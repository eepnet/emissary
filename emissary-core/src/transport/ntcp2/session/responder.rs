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

//! NTCP2 Noise handshake implementation for responder (Bob)
//!
//! https://geti2p.net/spec/ntcp2#overview
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.

use crate::{
    crypto::{
        aes::cbc::Aes, chachapoly::ChaChaPoly, hmac::Hmac, noise::NoiseContext, siphash::SipHash,
        EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    primitives::RouterInfo,
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
const LOG_TARGET: &str = "emissary::ntcp2::responder";

/// Responder state.
#[derive(Default)]
enum ResponderState {
    /// Responder has received `SessionRequest` message from remote peer,
    /// has initialized NTCP2 session state and is waiting to read padding bytes
    SessionRequested {
        /// Initator's ephemeral public key.
        ephemeral_key: Box<StaticPublicKey>,

        /// AES IV.
        iv: [u8; 16],

        /// Local router hash.
        local_router_hash: Vec<u8>,

        /// Message 3 part 2 length.
        m3_p2_len: usize,

        /// Noise context.
        noise_ctx: NoiseContext,
    },

    /// Responder has read the padding bytes and
    /// has accepted the session by creatin `SessionCreated` message.
    SessionCreated {
        /// Ephemeral public.
        ephemeral_private: EphemeralPrivateKey,

        /// Local key.
        local_key: [u8; 32],

        /// Noise context.
        noise_ctx: NoiseContext,
    },

    /// Responder state has been poisoned.
    #[default]
    Poisoned,
}

impl fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionRequested { .. } =>
                f.debug_struct("SessionRequested").finish_non_exhaustive(),
            Self::SessionCreated { .. } => f.debug_struct("SessionCreated").finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("Poisoned").finish(),
        }
    }
}

/// Noise handshake initiator
pub struct Responder {
    /// Responder state.
    state: ResponderState,
}

impl Responder {
    /// Create new [`Handshaker`] for responder.
    ///
    /// Decrypt and parse the `SessionCreated` message received from remote.
    ///
    /// If the session is accepted (no decryption errors, valid options),
    /// [`Responder::new()`] returns the amount of padding bytes that need
    /// to be read from the socket in order for the session to make progress.
    ///
    /// <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1>
    pub fn new<R: Runtime>(
        mut noise_ctx: NoiseContext,
        local_router_hash: Vec<u8>,
        local_static_key: StaticPrivateKey,
        iv: [u8; 16],
        message: Vec<u8>,
        net_id: u8,
    ) -> crate::Result<(Self, usize)> {
        tracing::trace!(
            target: LOG_TARGET,
            "accept new connection"
        );

        // decrypt X
        let mut aes = Aes::new_decryptor(&local_router_hash, &iv);
        let x = aes.decrypt(&message[..32]);

        // MixHash(e.pubkey)
        noise_ctx.mix_hash(&x);

        // MixKey(DH())
        let ephemeral_key = StaticPublicKey::from_bytes(&x).ok_or(Error::InvalidData)?;
        let mut remote_key = noise_ctx.mix_key(&local_static_key, &ephemeral_key);

        // decrypt initiator options
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        let mut options = message[32..].to_vec();
        ChaChaPoly::new(&remote_key).decrypt_with_ad(noise_ctx.state(), &mut options)?;
        remote_key.zeroize();

        // MixHash(encrypted payload)
        noise_ctx.mix_hash(&message[32..64]);

        let options = InitiatorOptions::parse(&options).ok_or(Error::InvalidData)?;
        if options.network_id != net_id {
            tracing::warn!(
                target: LOG_TARGET,
                local_net_id = ?net_id,
                remote_net_id = ?options.network_id,
                "network id mismatch",
            );
            return Err(Error::InvalidData);
        }

        // check clock skew
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

        if options.version != 2 {
            tracing::warn!(
                target: LOG_TARGET,
                local_version = 2,
                remote_version = ?options.version,
                "ntcp2 version mismatch",
            );
            return Err(Error::InvalidData);
        }

        let padding_len = options.padding_length as usize;
        let m3_p2_len = options.m3_p2_len as usize;

        tracing::trace!(
            target: LOG_TARGET,
            ?padding_len,
            ?m3_p2_len,
            "ntcp2 session accepted",
        );

        Ok((
            Self {
                state: ResponderState::SessionRequested {
                    ephemeral_key: Box::new(ephemeral_key),
                    iv: aes.iv(),
                    local_router_hash,
                    m3_p2_len,
                    noise_ctx,
                },
            },
            padding_len,
        ))
    }

    /// Register padding to `Responder`.
    ///
    /// `SessionRequest` message is variable-length and doesn't reveal how much
    /// padding the message contains so processing of the `SessionCreate` is split
    /// into two functions:
    ///
    /// - [`Responder::new()`]
    /// - [`Responder::create_session()`]
    ///
    /// If the session is accepted, `SessionCreated` message is returned which the
    /// caller must send to remote peer in order for the session to make progress.
    pub fn create_session<R: Runtime>(
        &mut self,
        padding: Vec<u8>,
    ) -> crate::Result<(BytesMut, usize)> {
        let ResponderState::SessionRequested {
            local_router_hash,
            iv,
            ephemeral_key,
            m3_p2_len,
            mut noise_ctx,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            padding_len = ?padding.len(),
            "create session",
        );

        // MixHash(padding)
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        noise_ctx.mix_hash(&padding);

        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public();

        // MixHash(epub)
        noise_ctx.mix_hash(&pk);

        // MixKey(DH())
        let local_key = noise_ctx.mix_key(&sk, &*ephemeral_key);

        // encrypt `Y`
        let mut aes = Aes::new_encryptor(&local_router_hash, &iv);
        let ciphertext = aes.encrypt(pk);

        // encrypt options and construct `SessionCreated message`
        let mut options = ResponderOptions {
            padding_length: 32u16,
            timestamp: R::time_since_epoch().as_secs() as u32,
        }
        .serialize()
        .to_vec();

        ChaChaPoly::new(&local_key).encrypt_with_ad_new(noise_ctx.state(), &mut options)?;
        let message = {
            let mut padding = [0u8; 32];
            R::rng().fill_bytes(&mut padding);

            let mut message = BytesMut::with_capacity(96);
            message.put_slice(&ciphertext);
            message.put_slice(&options);
            message.put_slice(&padding);

            message
        };

        // https://geti2p.net/spec/ntcp2#encryption-for-for-handshake-message-3-part-1-using-message-2-kdf
        noise_ctx.mix_hash(&message[32..64]).mix_hash(&message[64..]);

        self.state = ResponderState::SessionCreated {
            ephemeral_private: sk,
            local_key,
            noise_ctx,
        };

        Ok((message, 48 + m3_p2_len))
    }

    /// Finalize handshake.
    ///
    /// `SessionConfirmed` has been received from the remote peer and the session can be finalize.
    ///
    /// This entails decrypting remote's public key, performing Diffie-Hellman key exchange on that
    /// public key and local private key, deriving ChaCha20Poly1305 keys for the data phase
    /// and generating SipHash keys for (de)obfuscation of payload lengths.
    ///
    /// <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-3-part-2>
    /// <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase>
    pub fn finalize(&mut self, message: Vec<u8>) -> crate::Result<(KeyContext, RouterInfo, Bytes)> {
        let ResponderState::SessionCreated {
            ephemeral_private,
            mut local_key,
            mut noise_ctx,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            message_len = ?message.len(),
            "finalize ntcp2 handshake",
        );

        // decrypt remote's static public key
        let mut initiator_public = message[..48].to_vec();
        let mut cipher = ChaChaPoly::with_nonce(&local_key, 1u64);
        local_key.zeroize();

        cipher
            .decrypt_with_ad(noise_ctx.state(), &mut initiator_public)
            .inspect_err(|error| {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to decrypt remote's public key"
                );
            })?;

        // MixHash(ciphertext)
        noise_ctx.mix_hash(&message[..48]);

        // perform diffie-hellman key exchange and derive keys for data phase
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase
        let initiator_public =
            StaticPublicKey::from_bytes(&initiator_public[..32]).ok_or(Error::InvalidData)?;

        // MixKey(DH())
        let mut k = noise_ctx.mix_key(&ephemeral_private, &initiator_public);

        // decrypt remote's router info and parse it into `RouterInfo`
        let (router_info, serialized) = {
            let mut router_info = message[48..].to_vec();
            ChaChaPoly::with_nonce(&k, 0)
                .decrypt_with_ad(noise_ctx.state(), &mut router_info)
                .inspect_err(|error| {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to decrypt remote's router info"
                    );
                })?;
            k.zeroize();

            // MixHash(ciphertext)
            noise_ctx.mix_hash(&message[48..]);

            match MessageBlock::parse(&router_info) {
                Ok(MessageBlock::RouterInfo { router_info, .. }) => RouterInfo::parse(router_info)
                    .map(|parsed| (parsed, Bytes::from(router_info.to_vec())))
                    .map_err(|error| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to parse remote router info",
                        );

                        Error::InvalidData
                    }),
                Ok(message) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?message,
                        "received an unexpected ntcp2 message block",
                    );
                    Err(Error::InvalidData)
                }
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?message,
                        ?error,
                        "received a malformed ntcp2 message block",
                    );
                    Err(Error::InvalidData)
                }
            }
        }?;

        // create send and receive keys
        let temp_key = Hmac::new(noise_ctx.chaining_key()).update([]).finalize();
        let send_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let recv_key = Hmac::new(&temp_key).update(&send_key).update([0x02]).finalize();

        // siphash context for (de)obfuscating message sizes
        let sip = SipHash::new_responder(&temp_key, noise_ctx.state());

        Ok((
            KeyContext::new(recv_key, send_key, sip),
            router_info,
            serialized,
        ))
    }
}
