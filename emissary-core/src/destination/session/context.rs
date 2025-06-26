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

use crate::{
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, StaticPrivateKey, StaticPublicKey,
    },
    destination::session::{inbound::InboundSession, outbound::OutboundSession},
    error::SessionError,
    i2np::{
        database::store::{DatabaseStoreBuilder, DatabaseStoreKind},
        garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicMessageBuilder},
        MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{DestinationId, MessageId},
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, Randomized};
use rand_core::RngCore;
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Range, RangeFrom},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session::context";

/// Noise protocol name.
const PROTOCOL_NAME: &str = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";

/// Ephemeral public key offset in `NewSession` message.
const NS_EPHEMERAL_PUBKEY_OFFSET: Range<usize> = 4..36;

/// Static public key offset in `NewSession` message, including Poly1305 MAC.
const NS_STATIC_PUBKEY_OFFSET: Range<usize> = 36..84;

/// Payload section offset in `NewSession` message, including Poly1305 MAC.
const NS_PAYLOAD_OFFSET: RangeFrom<usize> = 84..;

/// Minimum size for `NewSession` message.
const NS_MINIMUM_SIZE: usize = 100usize;

/// Key context for an ECIES-X25519-AEAD-Ratchet session.
#[derive(Clone)]
pub struct KeyContext<R: Runtime> {
    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Outbound state.
    outbound_state: Bytes,

    /// Static private key of the session.
    private_key: StaticPrivateKey,

    /// Static public key of the session.
    public_key: StaticPublicKey,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> KeyContext<R> {
    /// Create new [`KeyContext`] from `StaticPrivateKey`.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn from_private_key(private_key: StaticPrivateKey) -> Self {
        let chaining_key = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();
        let public_key = private_key.public();

        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state = Sha256::new().update(&outbound_state).update(&public_key).finalize();

        Self {
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            outbound_state: Bytes::from(outbound_state),
            private_key,
            public_key,
            _runtime: Default::default(),
        }
    }

    /// Generate private key which can be Elligator2-encoded.
    //
    // TODO: move this into `src/crypto`
    pub fn generate_ephemeral_keypair() -> ([u8; 32], u8) {
        let mut rng = R::rng();
        let tweak = rng.next_u32() as u8;

        loop {
            let mut private = [0u8; 32];
            rng.fill_bytes(&mut private);

            if Randomized::to_representative(&private, tweak).into_option().is_some() {
                return (private, tweak);
            }
        }
    }

    /// Create new outbound session.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_outbound_session(
        &mut self,
        local: DestinationId,
        remote: DestinationId,
        remote_public_key: &StaticPublicKey,
        lease_set: Bytes,
        payload: &[u8],
    ) -> (OutboundSession<R>, Vec<u8>) {
        // create garlic message for establishing a new session
        //
        // the message consists of three parts
        //  * date time block
        //  * bundled leaseset
        //  * garlic clove for upper-level protocol data
        //
        // this garlic message is wrapped inside a `NewSession` message
        // and sent to remote
        let database_store = DatabaseStoreBuilder::new(
            Bytes::from(local.to_vec()),
            DatabaseStoreKind::LeaseSet2 {
                lease_set: lease_set.clone(),
            },
        )
        .build();

        let hash = remote.to_vec();
        let payload = GarlicMessageBuilder::default()
            .with_date_time(R::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::DatabaseStore,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                GarlicDeliveryInstructions::Local,
                &database_store,
            )
            .with_garlic_clove(
                MessageType::Data,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                GarlicDeliveryInstructions::Destination { hash: &hash },
                &{
                    let mut out = BytesMut::with_capacity(payload.len() + 4);

                    out.put_u32(payload.len() as u32);
                    out.put_slice(payload);

                    out.freeze().to_vec()
                },
            )
            .build();

        // generate new elligator2-encodable ephemeral keypair
        let (private_key, public_key, representative) = {
            let (private_key, tweak) = Self::generate_ephemeral_keypair();
            // conversion is expected to succeed since the key was generated by us
            let sk = StaticPrivateKey::from_bytes(&private_key).expect("to succeed");
            let public_key =
                StaticPublicKey::from(Randomized::mul_base_clamped(private_key).to_montgomery().0);

            // elligator2 conversion must succeed because `Self::generate_ephemeral_keypair()`
            // has ensured that the public key is encodable
            let representative =
                Randomized::to_representative(&private_key, tweak).expect("to succeed");

            (sk, public_key, representative)
        };

        let state = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update::<&[u8]>(remote_public_key.as_ref())
                .finalize();

            Sha256::new().update(&state).update(&public_key).finalize()
        };

        // derive keys for encrypting initiator's static key
        let (chaining_key, static_key_ciphertext) = {
            let mut shared = private_key.diffie_hellman(remote_public_key);
            let mut temp_key = Hmac::new(&self.chaining_key).update(&shared).finalize();
            let chaining_key = Hmac::new(&temp_key).update(b"").update([0x01]).finalize();
            let mut cipher_key =
                Hmac::new(&temp_key).update(&chaining_key).update(b"").update([0x02]).finalize();

            // encrypt initiator's static public key
            //
            // `encrypt_with_ad()` must succeed as it's called with valid parameters
            let mut static_key = {
                let mut out = BytesMut::with_capacity(32 + 16);
                out.put_slice(self.public_key.as_ref());

                out.freeze().to_vec()
            };

            ChaChaPoly::with_nonce(&cipher_key, 0u64)
                .encrypt_with_ad_new(&state, &mut static_key)
                .expect("to succeed");

            shared.zeroize();
            temp_key.zeroize();
            cipher_key.zeroize();

            (chaining_key, static_key)
        };

        // state for payload section
        let state = Sha256::new().update(&state).update(&static_key_ciphertext).finalize();

        // encrypt payload section
        let (chaining_key, payload_ciphertext) = {
            let mut shared = self.private_key.diffie_hellman(remote_public_key);
            let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
            let chaining_key = Hmac::new(&temp_key).update(b"").update([0x01]).finalize();
            let mut cipher_key =
                Hmac::new(&temp_key).update(&chaining_key).update(b"").update([0x02]).finalize();

            // create buffer with 16 extra bytes for poly1305 auth tag
            let mut payload = {
                let mut out = BytesMut::with_capacity(payload.len() + 16);
                out.put_slice(&payload);

                out.freeze().to_vec()
            };

            // `encrypt_with_ad()` must succeed as it's called with valid parameters
            ChaChaPoly::with_nonce(&cipher_key, 0u64)
                .encrypt_with_ad_new(&state, &mut payload)
                .expect("to succeed");

            shared.zeroize();
            temp_key.zeroize();
            cipher_key.zeroize();

            (chaining_key, payload)
        };

        // state for new session reply kdf
        let state =
            Bytes::from(Sha256::new().update(&state).update(&payload_ciphertext).finalize());

        let payload = {
            let mut out = BytesMut::with_capacity(
                representative
                    .len()
                    .saturating_add(static_key_ciphertext.len())
                    .saturating_add(payload_ciphertext.len()),
            );
            out.put_slice(&representative);
            out.put_slice(&static_key_ciphertext);
            out.put_slice(&payload_ciphertext);

            out.freeze().to_vec()
        };

        (
            OutboundSession::new(
                remote,
                state,
                self.private_key.clone(),
                private_key,
                chaining_key,
            ),
            payload,
        )
    }

    /// Create inbound session from serialized `NewSession` message.
    ///
    /// https://geti2p.net/spec/ecies#f-kdfs-for-new-session-message
    pub fn create_inbound_session(
        &self,
        message: Vec<u8>,
    ) -> Result<(InboundSession<R>, Vec<u8>), SessionError> {
        if message.len() < NS_MINIMUM_SIZE {
            tracing::warn!(
                target: LOG_TARGET,
                message_len = ?message.len(),
                "`NewSession` message is too short",
            );

            return Err(SessionError::Malformed);
        }

        // extract and decode elligator2-encoded public key
        let public_key = {
            // conversion must succeed as `message` has been ensured to be long enough
            // to hold the elligator2-encoded ephemeral public key
            let representative =
                TryInto::<[u8; 32]>::try_into(message[NS_EPHEMERAL_PUBKEY_OFFSET].to_vec())
                    .expect("to succeed");

            let new_pubkey = Randomized::from_representative(&representative)
                .into_option()
                .ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?representative,
                        "failed to elligator2-decode public key",
                    );

                    SessionError::Malformed
                })?
                .to_montgomery();

            StaticPublicKey::from(new_pubkey.0)
        };

        // calculate new state based on remote's ephemeral public key
        let state = Sha256::new().update(&self.inbound_state).update(&public_key).finalize();

        // generate chaining key and cipher key for decrypting remote's public key
        let (chaining_key, mut cipher_key) = {
            let mut shared = self.private_key.diffie_hellman(&public_key);
            let mut temp_key = Hmac::new(&self.chaining_key).update(&shared).finalize();
            let chaining_key = Hmac::new(&temp_key).update(b"").update([0x01]).finalize();
            let cipher_key =
                Hmac::new(&temp_key).update(&chaining_key).update(b"").update([0x02]).finalize();

            shared.zeroize();
            temp_key.zeroize();

            (chaining_key, cipher_key)
        };

        // decrypt remote's static key and calculate new state
        let (static_key, state) = {
            let mut static_key = message[NS_STATIC_PUBKEY_OFFSET].to_vec();
            ChaChaPoly::with_nonce(&cipher_key, 0u64)
                .decrypt_with_ad(&state, &mut static_key)
                .inspect_err(|error| {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed decrypt static key section",
                    );
                })?;

            cipher_key.zeroize();

            (
                StaticPublicKey::from_bytes(&static_key).expect("to succeed"),
                Sha256::new()
                    .update(&state)
                    .update(&message[NS_STATIC_PUBKEY_OFFSET])
                    .finalize(),
            )
        };

        // decrypt payload section
        let (chaining_key, payload) = {
            let mut shared = self.private_key.diffie_hellman(&static_key);
            let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
            let chaining_key = Hmac::new(&temp_key).update(b"").update([0x01]).finalize();
            let mut cipher_key =
                Hmac::new(&temp_key).update(&chaining_key).update(b"").update([0x02]).finalize();

            let mut payload = message[NS_PAYLOAD_OFFSET].to_vec();
            ChaChaPoly::with_nonce(&cipher_key, 0u64)
                .decrypt_with_ad(&state, &mut payload)
                .inspect_err(|error| {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed decrypt payload section",
                    );
                })?;

            shared.zeroize();
            temp_key.zeroize();
            cipher_key.zeroize();

            (chaining_key, payload)
        };

        Ok((
            InboundSession::new(
                static_key,
                public_key,
                chaining_key,
                Sha256::new().update(&state).update(&message[NS_PAYLOAD_OFFSET]).finalize(),
            ),
            payload,
        ))
    }
}
