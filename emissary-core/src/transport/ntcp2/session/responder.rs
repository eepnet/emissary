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
//! <https://geti2p.net/spec/ntcp2#overview>
//! <https://i2p.net/en/docs/specs/ntcp2-hybrid/>

use crate::{
    crypto::{
        aes::cbc::Aes, chachapoly::ChaChaPoly, hmac::Hmac, noise::NoiseContext, siphash::SipHash,
        EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    error::Ntcp2Error,
    primitives::RouterInfo,
    runtime::Runtime,
    transport::{
        ntcp2::{
            message::MessageBlock,
            options::{InitiatorOptions, ResponderOptions},
            session::{EncryptionContext, InboundState, KeyContext, MAX_CLOCK_SKEW},
        },
        EncryptionKind,
    },
};

use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;
use zeroize::Zeroize;

use alloc::{boxed::Box, vec, vec::Vec};
use core::{fmt, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::responder";

/// Poly1305 MAC size.
const POLY1305_MAC_SIZE: usize = 16usize;

/// Size of `SessionRequest`.
///
/// Includes the payload and a Poly1305 MAC.
const SESSION_REQUEST_SIZE: usize = 32usize;

/// Responder state.
#[derive(Default)]
enum ResponderState {
    /// Public key if initiator has been read and the session has been classified
    /// as either x25519 or ML-KEM-512/768/1024.
    PublicKeyRead {
        /// AES IV.
        aes_iv: [u8; 16],

        /// Encryption context.
        encryption_ctx: EncryptionContext,

        /// Remote's ephemeral key (X).
        ephemeral_key: StaticPublicKey,

        /// Local router hash.
        local_router_hash: Vec<u8>,

        /// Network ID.
        net_id: u8,

        /// Local static key.
        static_key: StaticPrivateKey,
    },

    /// Responder has received `SessionRequest` message from remote peer,
    /// has initialized NTCP2 session state and is waiting to read padding bytes
    SessionRequested {
        /// Encapsulation key.
        ///
        /// `None` if x25519 is used.
        encapsulation_key: Option<Vec<u8>>,

        /// Encryption context.
        encryption_ctx: EncryptionContext,

        /// Initator's ephemeral public key.
        ephemeral_key: Box<StaticPublicKey>,

        /// AES IV.
        iv: [u8; 16],

        /// Local router hash.
        local_router_hash: Vec<u8>,

        /// Message 3 part 2 length.
        m3_p2_len: usize,
    },

    /// Responder has read the padding bytes and
    /// has accepted the session by creatin `SessionCreated` message.
    SessionCreated {
        /// Encryption context.
        encryption_ctx: EncryptionContext,

        /// Ephemeral public.
        ephemeral_private: EphemeralPrivateKey,

        /// Local key.
        local_key: [u8; 32],
    },

    /// Responder state has been poisoned.
    #[default]
    Poisoned,
}

impl fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyRead { .. } =>
                f.debug_struct("ResponderState::PublicKeyRead").finish_non_exhaustive(),
            Self::SessionRequested { .. } =>
                f.debug_struct("ResponderState::SessionRequested").finish_non_exhaustive(),
            Self::SessionCreated { .. } =>
                f.debug_struct("ResponderState::SessionCreated").finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("ResponderState::Poisoned").finish(),
        }
    }
}

/// Noise handshake initiator
pub struct Responder {
    /// Responder state.
    state: ResponderState,
}

impl Responder {
    /// Create new `Responder`.
    ///
    /// Decrypts the remote public key which indicates whether this is an x25519 or an ML-KEK
    /// connections and returns a `Responder` object and the number of bytes that must be read from
    /// the stream for `SessionRequest`.
    pub fn new(
        inbound_state: InboundState,
        static_key: StaticPrivateKey,
        local_router_hash: Vec<u8>,
        iv: [u8; 16],
        net_id: u8,
        message: Vec<u8>,
    ) -> Result<(Self, usize), Ntcp2Error> {
        // decrypt X
        let mut aes = Aes::new_decryptor(&local_router_hash, &iv);
        let mut x = aes.decrypt(&message[..32]);

        // high MSB in public key indicates that this connection is PQ
        let (size, encryption_ctx) = match (x[31] & 0x80) == 0x80 {
            false => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "accept inbound connection over x25519",
                );

                (
                    SESSION_REQUEST_SIZE,
                    EncryptionContext::X25519(NoiseContext::new(
                        inbound_state.x25519.0,
                        inbound_state.x25519.1,
                    )),
                )
            }
            true => {
                // set MSB to low to make the public key valid
                x[31] &= 0x7f;

                let encryption_ctx = EncryptionContext::try_from(inbound_state).map_err(|()| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "inbound connection over PQ but it's disabled, rejecting",
                    );
                    Ntcp2Error::InvalidState
                })?;

                tracing::trace!(
                    target: LOG_TARGET,
                    kind = %encryption_ctx,
                    "accept inbound connection over ml-kem",
                );

                (
                    encryption_ctx.encapsulation_key_size()
                        + POLY1305_MAC_SIZE
                        + SESSION_REQUEST_SIZE,
                    encryption_ctx,
                )
            }
        };

        Ok((
            Self {
                state: ResponderState::PublicKeyRead {
                    aes_iv: aes.iv(),
                    encryption_ctx,
                    ephemeral_key: StaticPublicKey::try_from_bytes(&x)
                        .ok_or(Ntcp2Error::InvalidData)?,
                    local_router_hash,
                    static_key,
                    net_id,
                },
            },
            size,
        ))
    }

    /// Create new [`Handshaker`] for responder.
    ///
    /// Decrypt and parse the `SessionCreated` message received from remote.
    ///
    /// If the session is accepted (no decryption errors, valid options),
    /// [`Responder::new()`] returns the amount of padding bytes that need
    /// to be read from the socket in order for the session to make progress.
    ///
    /// <https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1>
    pub fn handle_session_request<R: Runtime>(
        &mut self,
        message: Vec<u8>,
    ) -> Result<usize, Ntcp2Error> {
        let ResponderState::PublicKeyRead {
            aes_iv,
            ephemeral_key,
            mut encryption_ctx,
            local_router_hash,
            net_id,
            static_key,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Ntcp2Error::InvalidState);
        };

        // MixHash(e.pubkey)
        encryption_ctx.noise_ctx().mix_hash(ephemeral_key.to_vec());

        // MixKey(DH()), es
        let mut remote_key = encryption_ctx.noise_ctx().mix_key(&static_key, &ephemeral_key);

        // e1
        //
        // https://i2p.net/en/docs/specs/ntcp2-hybrid/#bob-kdf-for-message-1
        let (nonce, offset, encap_key) = match &mut encryption_ctx {
            EncryptionContext::X25519(_) => (0u64, 0usize, None),
            kind => {
                let encap_size = kind.encapsulation_key_size() + POLY1305_MAC_SIZE;

                if message.len() < encap_size {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %kind,
                        size = message.len(),
                        expected = ?encap_size,
                        "SessionRequest is too short for ml-kem",
                    );
                    return Err(Ntcp2Error::InvalidData);
                }

                let mut encap_key = message[..encap_size].to_vec();

                ChaChaPoly::new(&remote_key)
                    .decrypt_with_ad(kind.noise_ctx().state(), &mut encap_key)
                    .map_err(|_| Ntcp2Error::Chacha)?;
                kind.noise_ctx().mix_hash(&message[..encap_size]);

                (1u64, encap_size, Some(encap_key))
            }
        };

        if message.len() < offset + SESSION_REQUEST_SIZE {
            tracing::warn!(
                target: LOG_TARGET,
                size  = ?message.len(),
                expected = offset + SESSION_REQUEST_SIZE,
                "SessionRequest is too short",
            );
            return Err(Ntcp2Error::InvalidData);
        }

        // decrypt initiator options
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        let mut options = message[offset..].to_vec();
        ChaChaPoly::with_nonce(&remote_key, nonce)
            .decrypt_with_ad(encryption_ctx.noise_ctx().state(), &mut options)
            .map_err(|_| Ntcp2Error::Chacha)?;
        remote_key.zeroize();

        // MixHash(encrypted payload)
        encryption_ctx
            .noise_ctx()
            .mix_hash(&message[offset..offset + SESSION_REQUEST_SIZE]);

        let options = InitiatorOptions::parse(&options).ok_or(Ntcp2Error::InvalidOptions)?;
        if options.network_id != net_id {
            tracing::warn!(
                target: LOG_TARGET,
                local_net_id = ?net_id,
                remote_net_id = ?options.network_id,
                "network id mismatch",
            );
            return Err(Ntcp2Error::NetworkMismatch);
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
            return Err(Ntcp2Error::ClockSkew);
        }

        if options.version != 2 {
            tracing::warn!(
                target: LOG_TARGET,
                local_version = 2,
                remote_version = ?options.version,
                "ntcp2 version mismatch",
            );
            return Err(Ntcp2Error::InvalidVersion);
        }

        let padding_len = options.padding_length as usize;
        let m3_p2_len = options.m3_p2_len as usize;

        tracing::trace!(
            target: LOG_TARGET,
            ?padding_len,
            ?m3_p2_len,
            "ntcp2 session accepted",
        );

        self.state = ResponderState::SessionRequested {
            encapsulation_key: encap_key,
            encryption_ctx,
            ephemeral_key: Box::new(ephemeral_key),
            iv: aes_iv,
            local_router_hash,
            m3_p2_len,
        };

        Ok(padding_len)
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
    ) -> Result<(BytesMut, usize), Ntcp2Error> {
        let ResponderState::SessionRequested {
            encapsulation_key,
            ephemeral_key,
            iv,
            local_router_hash,
            m3_p2_len,
            mut encryption_ctx,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Ntcp2Error::InvalidState);
        };

        tracing::trace!(
            target: LOG_TARGET,
            padding_len = ?padding.len(),
            "create session",
        );

        // MixHash(padding)
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-2-and-message-3-part-1
        encryption_ctx.noise_ctx().mix_hash(&padding);

        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public();

        // MixHash(epub)
        encryption_ctx.noise_ctx().mix_hash(&pk);

        // MixKey(DH()), ee
        let local_key = encryption_ctx.noise_ctx().mix_key(&sk, &*ephemeral_key);

        // encrypt `Y`
        let mut aes = Aes::new_encryptor(&local_router_hash, &iv);
        let ciphertext = aes.encrypt(pk);

        // ekem1
        //
        // https://i2p.net/en/docs/specs/ntcp2-hybrid/#bob-kdf-for-message-2
        let (local_key, kem_ciphertext) = match &mut encryption_ctx {
            EncryptionContext::X25519(_) => (local_key, None),
            kind => {
                // `encapsulation_key` must exist since this is an ml-kem connection
                let (mut ciphertext, shared_key) = kind
                    .encapsulate::<R>(encapsulation_key.expect("to exist").as_slice())
                    .ok_or(Ntcp2Error::InvalidData)?;

                ChaChaPoly::new(&local_key)
                    .encrypt_with_ad_new(kind.noise_ctx().state(), &mut ciphertext)
                    .map_err(|_| Ntcp2Error::Chacha)?;

                // MixHash(ciphertext)
                kind.noise_ctx().mix_hash(&ciphertext);

                // MixKey(kem_shared_key)
                let local_key = kind.noise_ctx().mix_key_from_shared_secret(&shared_key);

                (local_key, Some(ciphertext))
            }
        };

        let padding = {
            let mut padding = vec![0u8; (R::rng().next_u32() % 16 + 8) as usize];
            R::rng().fill_bytes(&mut padding);

            padding
        };

        // encrypt options and construct `SessionCreated message`
        let mut options = ResponderOptions {
            padding_length: padding.len() as u16,
            timestamp: R::time_since_epoch().as_secs() as u32,
        }
        .serialize()
        .to_vec();

        ChaChaPoly::new(&local_key)
            .encrypt_with_ad_new(encryption_ctx.noise_ctx().state(), &mut options)
            .map_err(|_| Ntcp2Error::Chacha)?;

        let (message, offset) = {
            let mut message = BytesMut::with_capacity(96);
            message.put_slice(&ciphertext);
            if let Some(kem_ciphertext) = kem_ciphertext {
                message.put_slice(&kem_ciphertext);
            }
            let offset = message.len();
            message.put_slice(&options);
            message.put_slice(&padding);

            (message, offset)
        };

        // https://geti2p.net/spec/ntcp2#encryption-for-for-handshake-message-3-part-1-using-message-2-kdf
        encryption_ctx
            .noise_ctx()
            .mix_hash(&message[offset..offset + 32])
            .mix_hash(&message[offset + 32..]);

        self.state = ResponderState::SessionCreated {
            ephemeral_private: sk,
            local_key,
            encryption_ctx,
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
    pub fn finalize<R: Runtime>(
        &mut self,
        message: Vec<u8>,
    ) -> Result<(KeyContext, RouterInfo, Bytes, EncryptionKind), Ntcp2Error> {
        let ResponderState::SessionCreated {
            ephemeral_private,
            mut encryption_ctx,
            mut local_key,
        } = core::mem::take(&mut self.state)
        else {
            return Err(Ntcp2Error::InvalidState);
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
            .decrypt_with_ad(encryption_ctx.noise_ctx().state(), &mut initiator_public)
            .inspect_err(|error| {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to decrypt remote's public key"
                );
            })
            .map_err(|_| Ntcp2Error::Chacha)?;

        // MixHash(ciphertext)
        encryption_ctx.noise_ctx().mix_hash(&message[..48]);

        // perform diffie-hellman key exchange and derive keys for data phase
        //
        // https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-data-phase
        let initiator_public = StaticPublicKey::try_from_bytes(&initiator_public[..32])
            .ok_or(Ntcp2Error::InvalidData)?;

        // MixKey(DH())
        let mut k = encryption_ctx.noise_ctx().mix_key(&ephemeral_private, &initiator_public);

        // decrypt remote's router info and parse it into `RouterInfo`
        let (router_info, serialized) = {
            let mut router_info = message[48..].to_vec();
            ChaChaPoly::with_nonce(&k, 0)
                .decrypt_with_ad(encryption_ctx.noise_ctx().state(), &mut router_info)
                .inspect_err(|error| {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to decrypt remote's router info"
                    );
                })
                .map_err(|_| Ntcp2Error::Chacha)?;
            k.zeroize();

            // MixHash(ciphertext)
            encryption_ctx.noise_ctx().mix_hash(&message[48..]);

            match MessageBlock::parse(&router_info) {
                Ok(MessageBlock::RouterInfo { router_info, .. }) =>
                    RouterInfo::parse::<R>(router_info)
                        .map(|parsed| (parsed, Bytes::from(router_info.to_vec())))
                        .map_err(|error| {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to parse remote router info",
                            );

                            Ntcp2Error::InvalidRouterInfo
                        }),
                Ok(message) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?message,
                        "received an unexpected ntcp2 message block",
                    );
                    Err(Ntcp2Error::UnexpectedMessage)
                }
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?message,
                        ?error,
                        "received a malformed ntcp2 message block",
                    );
                    Err(Ntcp2Error::InvalidData)
                }
            }
        }?;

        // create send and receive keys
        let temp_key = Hmac::new(encryption_ctx.noise_ctx().chaining_key()).update([]).finalize();
        let send_key = Hmac::new(&temp_key).update([0x01]).finalize();
        let recv_key = Hmac::new(&temp_key).update(&send_key).update([0x02]).finalize();

        // siphash context for (de)obfuscating message sizes
        let sip = SipHash::new_responder(&temp_key, encryption_ctx.noise_ctx().state());

        Ok((
            KeyContext::new(recv_key, send_key, sip),
            router_info,
            serialized,
            match encryption_ctx {
                EncryptionContext::X25519(_) => EncryptionKind::X25519,
                EncryptionContext::MlKem512X25519(_) => EncryptionKind::MlKem512X25519,
                EncryptionContext::MlKem768X25519(_) => EncryptionKind::MlKem768X25519,
                EncryptionContext::MlKem1024X25519(_) => EncryptionKind::MlKem1024X25519,
            },
        ))
    }
}
