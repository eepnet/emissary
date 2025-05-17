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

//! Inbound ECIES-X25519-AEAD-Ratchet session implementation.

use crate::{
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, StaticPrivateKey, StaticPublicKey,
    },
    destination::session::{
        tag_set::{TagSet, TagSetEntry},
        KeyContext, NUM_TAGS_TO_GENERATE,
    },
    error::SessionError,
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use curve25519_elligator2::{MapToPointVariant, Randomized};
use hashbrown::HashMap;
use zeroize::Zeroize;

use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData, mem};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session::inbound";

/// State of the inbound session.
enum InboundSessionState {
    /// Inbound session is awaiting `NewSesionReply` to be sent.
    ///
    /// `SessionManager` waits for a while for the upper protocol layer to process the payload
    /// received in `NewSession` message in case the upper layer reply generates a reply for the
    /// received message.
    ///
    /// If no reply is received within a certain time window, `NewSessionReply` is sent without
    /// payload.
    AwaitingNewSessionReplyTransmit {
        /// Chaining key.
        chaining_key: Vec<u8>,

        /// State for `NewSessionReply` KDF.
        state: Vec<u8>,

        /// Ephemeral public key of remote destination.
        remote_ephemeral_public_key: StaticPublicKey,

        /// Static public key of remote destination.
        remote_static_public_key: StaticPublicKey,
    },

    /// `NewSessionReply` has been sent.
    ///
    /// [`InboundSession`] is waiting for `ExistingSession` message to be received before the
    /// session is considered active.
    NewSessionReplySent {
        /// Generated tag sets.
        tag_sets: HashMap<usize, (TagSet, TagSet)>,

        /// Garlic tag -> `tag_sets` index mappings.
        tag_set_mappings: HashMap<u64, usize>,

        /// `NewSessionReply` tag set.
        nsr_tag_set: Box<TagSet>,

        /// Ephemeral public key of remote destination.
        remote_ephemeral_public_key: StaticPublicKey,

        /// Static public key of remote destination.
        remote_static_public_key: StaticPublicKey,

        /// State from NS.
        ///
        /// Used if multiple NSR messages are sent.
        state: Vec<u8>,

        /// Chaining key from NS.
        ///
        /// Used if multiple NSR messages are sent.
        chaining_key: Vec<u8>,
    },

    /// Inbound session state has been poisoned.
    Poisoned,
}

impl fmt::Debug for InboundSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingNewSessionReplyTransmit { .. } => f
                .debug_struct("InboundSessionState::AwaitingNewSessionReplyTransmit ")
                .finish_non_exhaustive(),
            Self::NewSessionReplySent { .. } => f
                .debug_struct("InboundSessionState::NewSessionReplySent ")
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("InboundSessionState::Poisoned ").finish_non_exhaustive(),
        }
    }
}

/// Inbound session.
pub struct InboundSession<R: Runtime> {
    /// State of the inbound session.
    state: InboundSessionState,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> InboundSession<R> {
    /// Create new [`InboundSession`].
    pub fn new(
        remote_static_public_key: StaticPublicKey,
        remote_ephemeral_public_key: StaticPublicKey,
        chaining_key: Vec<u8>,
        state: Vec<u8>,
    ) -> Self {
        Self {
            state: InboundSessionState::AwaitingNewSessionReplyTransmit {
                chaining_key,
                remote_static_public_key,
                remote_ephemeral_public_key,
                state,
            },
            _runtime: Default::default(),
        }
    }

    /// Create NSR message.
    pub fn create_new_session_reply(
        &mut self,
        mut payload: Vec<u8>,
        ratchet_threshold: u16,
    ) -> Result<(Vec<u8>, Vec<TagSetEntry>), SessionError> {
        match mem::replace(&mut self.state, InboundSessionState::Poisoned) {
            InboundSessionState::AwaitingNewSessionReplyTransmit {
                chaining_key: ns_chaining_key,
                remote_ephemeral_public_key,
                remote_static_public_key,
                state: ns_state,
            } => {
                // generate new elligator2-encodable ephemeral keypair
                let (ephemeral_private_key, ephemeral_public_key, representative) = {
                    let (ephemeral_private_key, tweak) =
                        KeyContext::<R>::generate_ephemeral_keypair();
                    let sk = StaticPrivateKey::from_bytes(&ephemeral_private_key)
                        .ok_or(SessionError::InvalidKey)?;
                    let ephemeral_public_key = StaticPublicKey::from(
                        Randomized::mul_base_clamped(ephemeral_private_key).to_montgomery().0,
                    );

                    // conversion must succeed as `KeyContext::generate_ephemeral_keypair()`
                    // has ensured that the public key is encodable
                    let representative =
                        Randomized::to_representative(&ephemeral_private_key, tweak)
                            .expect("to succeed");

                    (sk, ephemeral_public_key, representative)
                };

                // create garlic tag for the `NewSessionReply` message
                let (nsr_tag_set, garlic_tag) = {
                    let temp_key = Hmac::new(&ns_chaining_key).update([]).finalize();
                    let tagset_key =
                        Hmac::new(&temp_key).update(b"SessionReplyTags").update([0x01]).finalize();
                    let mut nsr_tag_set =
                        TagSet::new(&ns_chaining_key, tagset_key, ratchet_threshold);

                    // `next_entry()` must succeed as `nsr_tag_set` is a fresh `TagSet`
                    let garlic_tag = nsr_tag_set.next_entry().expect("to succeed").tag;

                    (nsr_tag_set, garlic_tag)
                };

                tracing::trace!(
                    target: LOG_TARGET,
                    ?garlic_tag,
                    "garlic tag for NSR",
                );

                // calculate keys from shared secrets derived from ee & es
                let (chaining_key, keydata) = {
                    // ephemeral-ephemeral
                    let mut shared =
                        ephemeral_private_key.diffie_hellman(&remote_ephemeral_public_key);
                    let mut temp_key = Hmac::new(&ns_chaining_key).update(&shared).finalize();
                    let mut chaining_key =
                        Hmac::new(&temp_key).update(b"").update([0x01]).finalize();

                    // static-ephemeral
                    shared = ephemeral_private_key.diffie_hellman(&remote_static_public_key);
                    temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    chaining_key = Hmac::new(&temp_key).update(b"").update([0x01]).finalize();
                    let keydata = Hmac::new(&temp_key)
                        .update(&chaining_key)
                        .update(b"")
                        .update([0x02])
                        .finalize();

                    shared.zeroize();
                    temp_key.zeroize();

                    (chaining_key, keydata)
                };

                // calculate new state encrypting the empty key section
                let state = {
                    let state =
                        Sha256::new().update(&ns_state).update(garlic_tag.to_le_bytes()).finalize();

                    Sha256::new()
                        .update(&state)
                        .update::<&[u8]>(ephemeral_public_key.as_ref())
                        .finalize()
                };
                let mac = ChaChaPoly::new(&keydata).encrypt_with_ad(&state, &mut [])?;

                // include `mac` into state for payload section's encryption
                let state = Sha256::new().update(&state).update(&mac).finalize();

                // split key into send and receive keys
                let temp_key = Hmac::new(&chaining_key).update([]).finalize();
                let recv_key = Hmac::new(&temp_key).update([0x01]).finalize();
                let send_key = Hmac::new(&temp_key).update(&recv_key).update([0x02]).finalize();

                // initialize send and receive tag sets
                let send_tag_set = TagSet::new(&chaining_key, &send_key, ratchet_threshold);
                let mut recv_tag_set = TagSet::new(chaining_key, recv_key, ratchet_threshold);

                // decode payload of the `NewSessionReply` message
                let temp_key = Hmac::new(&send_key).update([]).finalize();
                let payload_key =
                    Hmac::new(&temp_key).update(b"AttachPayloadKDF").update([0x01]).finalize();

                ChaChaPoly::new(&payload_key).encrypt_with_ad_new(&state, &mut payload)?;

                let payload = {
                    let mut out = BytesMut::with_capacity(
                        representative
                            .len()
                            .saturating_add(8) // garlic tag
                            .saturating_add(mac.len())
                            .saturating_add(payload.len()),
                    );
                    out.put_slice(&garlic_tag.to_le_bytes());
                    out.put_slice(&representative);
                    out.put_slice(&mac);
                    out.put_slice(&payload);

                    out.freeze().to_vec()
                };

                // generate garlic tag/session key pairs for reception
                //
                // `next_entry()` must succeed as this is a fresh `TagSet` and
                // `NUM_TAGS_TO_GENERATE` is smaller than the maximum tag count
                // in a `Tagset`
                let (tag_set_mappings, tags): (HashMap<_, _>, Vec<_>) = (0..NUM_TAGS_TO_GENERATE)
                    .map(|_| {
                        let entry = recv_tag_set.next_entry().expect("to succeed");

                        ((entry.tag, 0usize), entry)
                    })
                    .unzip();

                self.state = InboundSessionState::NewSessionReplySent {
                    tag_sets: HashMap::from_iter([(0usize, (send_tag_set, recv_tag_set))]),
                    tag_set_mappings,
                    nsr_tag_set: Box::new(nsr_tag_set),
                    remote_ephemeral_public_key,
                    remote_static_public_key,
                    state: ns_state,
                    chaining_key: ns_chaining_key,
                };

                Ok((payload, tags))
            }
            InboundSessionState::NewSessionReplySent {
                mut tag_sets,
                mut tag_set_mappings,
                mut nsr_tag_set,
                remote_ephemeral_public_key,
                remote_static_public_key,
                state: ns_state,
                chaining_key: ns_chaining_key,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "send another NSR",
                );

                // generate new elligator2-encodable ephemeral keypair
                let (ephemeral_private_key, ephemeral_public_key, representative) = {
                    let (ephemeral_private_key, tweak) =
                        KeyContext::<R>::generate_ephemeral_keypair();
                    let sk = StaticPrivateKey::from_bytes(&ephemeral_private_key)
                        .ok_or(SessionError::InvalidKey)?;
                    let ephemeral_public_key = StaticPublicKey::from(
                        Randomized::mul_base_clamped(ephemeral_private_key).to_montgomery().0,
                    );

                    // conversion must succeed as `KeyContext::generate_ephemeral_keypair()`
                    // has ensured that the public key is encodable
                    let representative =
                        Randomized::to_representative(&ephemeral_private_key, tweak)
                            .expect("to succeed");

                    (sk, ephemeral_public_key, representative)
                };

                // garlic tag generation is expected to succeed as the number of sent NSR messages
                // should never exceed the total number of tags in the NSR tag set
                let garlic_tag = nsr_tag_set.next_entry().expect("to succeed").tag;

                tracing::trace!(
                    target: LOG_TARGET,
                    ?garlic_tag,
                    "garlic tag for NSR",
                );

                // calculate keys from shared secrets derived from ee & es
                let (chaining_key, keydata) = {
                    // ephemeral-ephemeral
                    let mut shared =
                        ephemeral_private_key.diffie_hellman(&remote_ephemeral_public_key);
                    let mut temp_key = Hmac::new(&ns_chaining_key).update(&shared).finalize();
                    let mut chaining_key =
                        Hmac::new(&temp_key).update(b"").update([0x01]).finalize();

                    // static-ephemeral
                    shared = ephemeral_private_key.diffie_hellman(&remote_static_public_key);
                    temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    chaining_key = Hmac::new(&temp_key).update(b"").update([0x01]).finalize();
                    let keydata = Hmac::new(&temp_key)
                        .update(&chaining_key)
                        .update(b"")
                        .update([0x02])
                        .finalize();

                    shared.zeroize();
                    temp_key.zeroize();

                    (chaining_key, keydata)
                };

                // calculate new state encrypting the empty key section
                let state = {
                    let state =
                        Sha256::new().update(&ns_state).update(garlic_tag.to_le_bytes()).finalize();

                    Sha256::new()
                        .update(&state)
                        .update::<&[u8]>(ephemeral_public_key.as_ref())
                        .finalize()
                };
                let mac = ChaChaPoly::new(&keydata).encrypt_with_ad(&state, &mut [])?;

                // include `mac` into state for payload section's encryption
                let state = Sha256::new().update(&state).update(&mac).finalize();

                // split key into send and receive keys
                let temp_key = Hmac::new(&chaining_key).update([]).finalize();
                let recv_key = Hmac::new(&temp_key).update([0x01]).finalize();
                let send_key = Hmac::new(&temp_key).update(&recv_key).update([0x02]).finalize();

                // initialize send and receive tag sets
                let send_tag_set = TagSet::new(&chaining_key, &send_key, ratchet_threshold);
                let mut recv_tag_set = TagSet::new(chaining_key, recv_key, ratchet_threshold);

                // decode payload of the `NewSessionReply` message
                let temp_key = Hmac::new(&send_key).update([]).finalize();
                let payload_key =
                    Hmac::new(&temp_key).update(b"AttachPayloadKDF").update([0x01]).finalize();

                ChaChaPoly::new(&payload_key).encrypt_with_ad_new(&state, &mut payload)?;

                let payload = {
                    let mut out = BytesMut::with_capacity(
                        representative
                            .len()
                            .saturating_add(8) // garlic tag
                            .saturating_add(mac.len())
                            .saturating_add(payload.len()),
                    );
                    out.put_slice(&garlic_tag.to_le_bytes());
                    out.put_slice(&representative);
                    out.put_slice(&mac);
                    out.put_slice(&payload);

                    out.freeze().to_vec()
                };

                // generate garlic tag/session key pairs for reception
                //
                // `next_entry()` must succeed as this is a fresh `TagSet` and
                // `NUM_TAGS_TO_GENERATE` is smaller than the maximum tag count
                // in a `Tagset`
                let tags = (0..NUM_TAGS_TO_GENERATE)
                    .map(|_| recv_tag_set.next_entry().expect("to succeed"))
                    .collect::<Vec<_>>();

                // associated the garlic tags of `tags` with this send/receive tag set pair
                // of this NSR message
                //
                // when an ES is received, the correct tag set pair is fetched from the context by
                // mapping the received garlic tag to an index in `tag_set_mappings`
                tags.iter().for_each(|entry| {
                    tag_set_mappings.insert(entry.tag, tag_sets.len());
                });
                tag_sets.insert(tag_sets.len(), (send_tag_set, recv_tag_set));

                self.state = InboundSessionState::NewSessionReplySent {
                    tag_sets,
                    tag_set_mappings,
                    nsr_tag_set,
                    remote_ephemeral_public_key,
                    remote_static_public_key,
                    state: ns_state,
                    chaining_key: ns_chaining_key,
                };

                Ok((payload, tags))
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for NSR",
                );
                debug_assert!(false);
                Err(SessionError::InvalidState)
            }
        }
    }

    /// Handle `ExistingSession` message.
    ///
    /// Decrypt `message` using `session_key` and return the decrypted payload and the inner state
    /// of `InboundSession`, allowing the caller to create a new `Session` object which contains
    /// both send and receive `TagSet`s.
    pub fn handle_existing_session(
        &mut self,
        garlic_tag: u64,
        tag_set_entry: TagSetEntry,
        payload: Vec<u8>,
    ) -> Result<(Vec<u8>, TagSet, TagSet), SessionError> {
        let InboundSessionState::NewSessionReplySent {
            mut tag_sets,
            tag_set_mappings,
            ..
        } = mem::replace(&mut self.state, InboundSessionState::Poisoned)
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "invalid state for ES",
            );
            debug_assert!(false);
            return Err(SessionError::InvalidState);
        };

        // try to associate `garlic_tag` with one of the generated send/receive tag set pairs
        //
        // this is necessary because multiple NSR messages may have been sent and remote destination
        // responds to one of them and the response must be associated with the correct tag set pair
        // so that remote is able to decrypt our messages
        let tag_set_index = tag_set_mappings.get(&garlic_tag).ok_or(SessionError::UnknownTag)?;
        let (send_tag_set, recv_tag_set) =
            tag_sets.remove(tag_set_index).ok_or(SessionError::UnknownTag)?;

        let mut payload = payload[12..].to_vec();

        ChaChaPoly::with_nonce(&tag_set_entry.key, tag_set_entry.tag_index as u64)
            .decrypt_with_ad(&tag_set_entry.tag.to_le_bytes(), &mut payload)?;

        Ok((payload, send_tag_set, recv_tag_set))
    }
}
