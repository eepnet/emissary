// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! NTCP2 Noise handshake implementation for initiator (Alice)
//!
//! https://geti2p.net/spec/ntcp2#overview
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.

use crate::{
    crypto::{
        aes::cbc::Aes, base64_encode, chachapoly::ChaChaPoly, hmac::Hmac, noise::NoiseContext,
        siphash::SipHash, EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    runtime::Runtime,
    transport::ntcp2::{
        message::MessageBlock,
        options::{InitiatorOptions, ResponderOptions},
        session::{KeyContext, MAX_CLOCK_SKEW},
    },
    Error,
};

use bytes::{BufMut, Bytes, BytesMut};
use rand_core::RngCore;
use zeroize::Zeroize;

use alloc::{boxed::Box, vec::Vec};
use core::{fmt, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::initiator";

/// Initiator state.
enum InitiatorState {
    /// Initiator has sent `SessionCreated` message to remote
    /// and is waitint to hear a response.
    SessionRequested {
        /// Ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// AES IV.
        iv: [u8; 16],

        /// Local router info.
        local_info: Bytes,

        /// Static private key.
        local_static_key: StaticPrivateKey,

        /// Noise context.
        noise_ctx: NoiseContext,

        /// Router hash.
        router_hash: Vec<u8>,
    },

    /// Responder has accepted the session request and is waiting for initiator to confirm the
    /// session
    SessionCreated {
        /// Local router info.
        local_info: Bytes,

        /// Static private key.
        local_static_key: StaticPrivateKey,

        /// Noise context.
        noise_ctx: NoiseContext,

        /// Remote key.
        remote_key: Vec<u8>,

        // Responder's public key.
        responder_public: Box<StaticPublicKey>,

        /// Router hash.
        router_hash: Vec<u8>,
    },

    /// Initiator state has been poisoned.
    Poisoned,
}

impl fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionRequested { .. } =>
                f.debug_struct("SessionRequested").finish_non_exhaustive(),
            Self::SessionCreated { .. } => f.debug_struct("SessionCreated").finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("Poisoned").finish(),
        }
    }
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self::Poisoned
    }
}

/// Noise handshake initiator
pub struct Initiator {
    /// Initiator state.
    state: InitiatorState,
}

impl Initiator {
    /// Create new [`Handshaker`] for initiator.
    ///
    /// Implements KDF from [1], creates a `SessionRequest` message and returns that message
    /// together with an [`Initiator`] object which allows the call to drive progress on the
    /// opening connection.
    ///
    /// [1]: <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1>
    pub fn new<R: Runtime>(
        mut noise_ctx: NoiseContext,
        local_info: Bytes,
        local_static_key: StaticPrivateKey,
        remote_static_key: &StaticPublicKey,
        router_hash: Vec<u8>,
        remote_iv: [u8; 16],
        net_id: u8,
    ) -> crate::Result<(Self, BytesMut)> {
        tracing::trace!(
            target: LOG_TARGET,
            router = ?base64_encode(&router_hash),
            "initiate new connection"
        );

        // generate ephemeral key pair and apply MixHash(epub)
        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public();

        // MixHash(rs), MixHash(e.pubkey)
        noise_ctx.mix_hash(remote_static_key).mix_hash(&pk);

        // MixKey(DH())
        let mut local_key = noise_ctx.mix_key(&sk, remote_static_key);

        // encrypt X
        let mut aes = Aes::new_encryptor(&router_hash, &remote_iv);
        let encrypted_x = aes.encrypt(pk);

        // create `SessionRequest` message
        let mut out = BytesMut::with_capacity(96);
        let padding = {
            let mut padding = [0u8; 32];
            R::rng().fill_bytes(&mut padding);

            padding
        };

        let mut options = InitiatorOptions {
            network_id: net_id,
            version: 2u8,
            padding_length: 32u16,
            timestamp: R::time_since_epoch().as_secs() as u32,
            m3_p2_len: local_info.len() as u16 + 20u16,
        }
        .serialize()
        .to_vec();

        ChaChaPoly::new(&local_key).encrypt_with_ad_new(noise_ctx.state(), &mut options)?;
        local_key.zeroize();

        out.put_slice(&encrypted_x);
        out.put_slice(&options);
        out.put_slice(&padding);

        // MixHash(encrypted payload), MixHash(padding)
        noise_ctx.mix_hash(&out[32..64]).mix_hash(&out[64..96]);

        Ok((
            Self {
                state: InitiatorState::SessionRequested {
                    ephemeral_key: sk,
                    iv: aes.iv(),
                    local_info,
                    local_static_key,
                    noise_ctx,
                    router_hash,
                },
            },
            out,
        ))
    }

    /// Register `SessionCreated` message from responder (Bob).
    ///
    /// Decrypt `Y` and perform KDF for messages 2 and 3 part 1
    ///
    /// <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1>
    pub fn register_session_created<R: Runtime>(&mut self, bytes: &[u8]) -> crate::Result<usize> {
        let InitiatorState::SessionRequested {
            ephemeral_key,
            iv,
            local_info,
            local_static_key,
            mut noise_ctx,
            router_hash,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            router = ?base64_encode(&router_hash),
            "session created"
        );

        // decrypt `Y`
        let mut aes = Aes::new_decryptor(&router_hash, &iv);
        let y = aes.decrypt(&bytes[..32]);

        // MixHash(e.pubkey)
        noise_ctx.mix_hash(&y);

        // MixKey(DH())
        let responder_public = StaticPublicKey::from_bytes(&y).ok_or(Error::InvalidData)?;
        let remote_key = noise_ctx.mix_key(&ephemeral_key, &responder_public);

        // decrypt the chacha20poly1305 frame with generated remote key, deserialize
        // `ResponderOptions` and validate timestamp
        let padding = {
            let mut options = bytes[32..64].to_vec();
            ChaChaPoly::new(&remote_key).decrypt_with_ad(noise_ctx.state(), &mut options)?;

            // check clock skew
            let options = ResponderOptions::parse(&options).ok_or(Error::InvalidData)?;
            let now = R::time_since_epoch();
            let remote_time = Duration::from_secs(options.timestamp as u64);
            let future = remote_time.saturating_sub(now);
            let past = now.saturating_sub(remote_time);

            if past > MAX_CLOCK_SKEW || future > MAX_CLOCK_SKEW {
                tracing::warn!(
                    target: LOG_TARGET,
                    our_time = ?now,
                    ?remote_time,
                    ?past,
                    ?future,
                    "excessive clock skew",
                );
                return Err(Error::InvalidData);
            }

            options.padding_length as usize
        };

        // MixHash(ciphertext)
        //
        // https://geti2p.net/spec/ntcp2#encryption-for-for-handshake-message-3-part-1-using-message-2-kdf
        noise_ctx.mix_hash(&bytes[32..64]);

        self.state = InitiatorState::SessionCreated {
            local_info,
            local_static_key,
            noise_ctx,
            remote_key: remote_key.to_vec(),
            responder_public: Box::new(responder_public),
            router_hash,
        };

        Ok(padding)
    }

    /// Finalize session.
    ///
    /// Include `padding` bytes to current state, perform Diffie-Hellman key exchange
    /// between responder's public key and local private key, create `SessionConfirmed`
    /// message which contains local public key & router info and finally derive keys
    /// for the data phase.
    ///
    /// <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase>
    pub fn finalize(&mut self, padding: &[u8]) -> crate::Result<(KeyContext, BytesMut)> {
        let InitiatorState::SessionCreated {
            local_info,
            local_static_key,
            mut noise_ctx,
            remote_key,
            responder_public,
            router_hash,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            router = ?base64_encode(&router_hash),
            "confirm session"
        );

        // MixHash(padding)
        noise_ctx.mix_hash(padding);

        // encrypt local public key
        let mut s_p_bytes = local_static_key.public().to_vec();
        let mut cipher = ChaChaPoly::with_nonce(&remote_key, 1);
        cipher.encrypt_with_ad_new(noise_ctx.state(), &mut s_p_bytes)?;

        // MixHash(ciphertext)
        noise_ctx.mix_hash(&s_p_bytes);

        // perform diffie-hellman key exchange and derive keys for data phase
        let (key_context, message) = {
            // MixKey(DH())
            let mut k = noise_ctx.mix_key(&local_static_key, &*responder_public);

            // h from message 3 part 1 is used as the associated data
            // for the AEAD in message 3 part 2
            let mut message = MessageBlock::new_router_info(&local_info);
            ChaChaPoly::with_nonce(&k, 0).encrypt_with_ad_new(noise_ctx.state(), &mut message)?;

            // MixHash(ciphertext)
            noise_ctx.mix_hash(&message);

            // create `SessionConfirmed` message
            let mut out = BytesMut::with_capacity(local_info.len() + 20 + 48);
            out.put_slice(&s_p_bytes);
            out.put_slice(&message);

            // create send and receive keys
            let temp_key = Hmac::new(noise_ctx.chaining_key()).update([]).finalize();
            let send_key = Hmac::new(&temp_key).update([0x01]).finalize();
            let receive_key = Hmac::new(&temp_key).update(&send_key).update([0x02]).finalize();

            // siphash context for (de)obfuscating message sizes
            let sip = SipHash::new_initiator(&temp_key, noise_ctx.state());

            k.zeroize();

            (KeyContext::new(send_key, receive_key, sip), out)
        };

        Ok((key_context, message))
    }
}
