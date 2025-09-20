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
    crypto::{hmac::Hmac, StaticPrivateKey, StaticPublicKey},
    destination::session::LOG_TARGET,
    error::SessionError,
    i2np::garlic::{NextKeyBuilder, NextKeyKind},
    runtime::Runtime,
};

use bytes::{Bytes, BytesMut};
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{fmt, mem};

/// Maximum number of tags that can be generated from a [`TagSet`]:
///
/// "The maximum number of messages before the DH must ratchet is 65535." [1]
///
/// [1]: https://geti2p.net/spec/ecies#new-session-tags-and-comparison-to-signal
#[allow(unused)]
const MAX_TAGS: usize = 65535;

/// Maximum key ID.
///
/// The session must be terminated after this.
const MAX_KEY_ID: u16 = 32767;

/// Key state of [`TagSet`].
///
/// https://geti2p.net/spec/ecies#dh-ratchet-message-flow
enum KeyState {
    /// Initial sessions keys have not been exchanged
    Uninitialized,

    /// Awaiting for a requested reverse key to be received from remote destination.
    ///
    /// Once the reverse key is received, DH is performed between the reverse key and
    /// `private_key` and the [`TagSet`] does a DH ratchet.
    AwaitingReverseKey {
        /// Send key ID.
        send_key_id: u16,

        /// Receive key ID.
        recv_key_id: u16,

        /// Local private key.
        private_key: StaticPrivateKey,
    },

    /// New local key has been created and a `NextKey` block with that key has been sent to remote
    /// destination *without* request to send their reverse key back, causing the remote
    /// destination to reuse their previous key.
    ///
    /// Once the `NextKey` confirmation has been received, a DH ratchet is performed.
    AwaitingReverseKeyConfirmation {
        /// Send key ID.
        send_key_id: u16,

        /// Receive key ID.
        recv_key_id: u16,

        /// Local private key.
        private_key: StaticPrivateKey,

        /// Remote public key.
        public_key: StaticPublicKey,
    },

    /// Key state is active and a new `NextKey` request can be sent if the tag count threshold for
    /// the [`TagSet`] has been crossed.
    Active {
        /// Send key ID.
        send_key_id: u16,

        /// Receive key ID.
        recv_key_id: u16,

        /// Local private key.
        private_key: StaticPrivateKey,

        /// Remote public key.
        public_key: StaticPublicKey,
    },

    /// Key state is is poisoned due to invalid state transition.
    Poisoned,
}

impl fmt::Debug for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => f.debug_struct("KeyState::Uninitialized").finish(),
            Self::AwaitingReverseKey {
                send_key_id,
                recv_key_id,
                ..
            } => f
                .debug_struct("KeyState::AwaitingReverseKey")
                .field("send_key_id", &send_key_id)
                .field("recv_key_id", &recv_key_id)
                .finish_non_exhaustive(),
            Self::AwaitingReverseKeyConfirmation {
                send_key_id,
                recv_key_id,
                ..
            } => f
                .debug_struct("KeyState::AwaitingReverseKeyConfirmation")
                .field("send_key_id", &send_key_id)
                .field("recv_key_id", &recv_key_id)
                .finish_non_exhaustive(),
            Self::Active {
                send_key_id,
                recv_key_id,
                ..
            } => f
                .debug_struct("KeyState::Active")
                .field("send_key_id", &send_key_id)
                .field("recv_key_id", &recv_key_id)
                .finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("KeyState::Poisoned").finish(),
        }
    }
}

/// Key context for a [`TagSet`].
struct KeyContext {
    /// Next root key.
    next_root_key: Bytes,

    /// Session key data.
    session_key_data: Bytes,

    /// Session key constant.
    session_tag_constant: Vec<u8>,

    /// Session tag key.
    #[allow(unused)]
    session_tag_key: Vec<u8>,

    /// Symmetric key.
    symmetric_key: Vec<u8>,
}

impl KeyContext {
    /// Create new [`KeyContext`] for a [`TagSet`].
    pub fn new(root_key: impl AsRef<[u8]>, tag_set_key: impl AsRef<[u8]>) -> Self {
        let temp_key = Hmac::new(root_key.as_ref()).update(tag_set_key.as_ref()).finalize();
        let next_root_key =
            Hmac::new(&temp_key).update(b"KDFDHRatchetStep").update([0x01]).finalize();
        let ratchet_key = Hmac::new(&temp_key)
            .update(&next_root_key)
            .update(b"KDFDHRatchetStep")
            .update([0x02])
            .finalize();

        let temp_key = Hmac::new(&ratchet_key).update([]).finalize();
        let session_tag_key =
            Hmac::new(&temp_key).update(b"TagAndKeyGenKeys").update([0x01]).finalize();
        let symmetric_key = Hmac::new(&temp_key)
            .update(&session_tag_key)
            .update(b"TagAndKeyGenKeys")
            .update([0x02])
            .finalize();

        let mut temp_key = Hmac::new(&session_tag_key).update([]).finalize();
        let session_key_data =
            Hmac::new(&temp_key).update(b"STInitialization").update([0x01]).finalize();
        let session_tag_constant = Hmac::new(&temp_key)
            .update(&session_key_data)
            .update(b"STInitialization")
            .update([0x02])
            .finalize();

        temp_key.zeroize();

        Self {
            next_root_key: Bytes::from(next_root_key),
            session_key_data: Bytes::from(session_key_data),
            session_tag_constant,
            session_tag_key,
            symmetric_key,
        }
    }
}

/// Session tag entry.
#[derive(Debug, PartialEq, Eq)]
pub struct TagSetEntry {
    /// Session key.
    pub key: Bytes,

    /// Session tag.
    pub tag: u64,

    /// Tag Index.
    pub tag_index: u16,

    /// Tag set ID.
    pub tag_set_id: u16,
}

/// Tag set.
///
/// https://geti2p.net/spec/ecies#sample-implementation
pub struct TagSet {
    /// Key context
    key_context: KeyContext,

    /// Key state, see [`KeyState`] for more details.
    key_state: KeyState,

    /// Receive key ID.
    ///
    /// `None` if new session keys haven't been exchanged.
    #[allow(unused)]
    recv_key_id: Option<u16>,

    /// Send key ID.
    ///
    /// `None` if new session keys haven't been exchanged.
    #[allow(unused)]
    send_key_id: Option<u16>,

    /// Next tag index.
    tag_index: u16,

    /// ID of the tag set.
    tag_set_id: u16,

    /// Number of tag set entries consumed per key before a DH ratchet is performed.
    ratchet_threshold: u16,
}

impl TagSet {
    /// Create new [`TagSet`].
    pub fn new(
        root_key: impl AsRef<[u8]>,
        tag_set_key: impl AsRef<[u8]>,
        ratchet_threshold: u16,
    ) -> Self {
        // We check if the tag_index > ratchet_threshold so ratchet_threshold
        // must be strictly less than u16 max
        debug_assert!(ratchet_threshold < u16::MAX);
        Self {
            key_state: KeyState::Uninitialized,
            key_context: KeyContext::new(root_key, tag_set_key),
            recv_key_id: None,
            send_key_id: None,
            tag_set_id: 0u16,
            tag_index: 0u16,
            ratchet_threshold,
        }
    }

    /// Get next [`TagSetEntry`].
    ///
    /// Returns `None` if all tags have been used.
    pub fn next_entry(&mut self) -> Option<TagSetEntry> {
        let tag_index = {
            let tag_index = self.tag_index;
            self.tag_index = self.tag_index.checked_add(1)?;

            tag_index
        };

        // ratchet next tag
        let garlic_tag = {
            let mut temp_key = Hmac::new(&self.key_context.session_key_data)
                .update(&self.key_context.session_tag_constant)
                .finalize();

            // store session key data for the next session tag ratchet
            self.key_context.session_key_data = Bytes::from(
                Hmac::new(&temp_key).update(b"SessionTagKeyGen").update([0x01]).finalize(),
            );

            let session_tag_key_data = Hmac::new(&temp_key)
                .update(&self.key_context.session_key_data)
                .update(b"SessionTagKeyGen")
                .update([0x02])
                .finalize();

            temp_key.zeroize();

            BytesMut::from(&session_tag_key_data[0..8]).freeze()
        };

        let symmetric_key = {
            let mut temp_key = Hmac::new(&self.key_context.symmetric_key).update([]).finalize();

            // store symmetric key for the next key ratchet
            self.key_context.symmetric_key =
                Hmac::new(&temp_key).update("SymmetricRatchet").update([0x01]).finalize();

            let symmetric_key = Hmac::new(&temp_key)
                .update(&self.key_context.symmetric_key)
                .update(b"SymmetricRatchet")
                .update([0x02])
                .finalize();

            temp_key.zeroize();

            BytesMut::from(&symmetric_key[..]).freeze()
        };

        Some(TagSetEntry {
            tag_index,
            tag_set_id: self.tag_set_id,
            key: symmetric_key,
            tag: u64::from_le_bytes(
                TryInto::<[u8; 8]>::try_into(garlic_tag.as_ref()).expect("to succeed"),
            ),
        })
    }

    /// Reinitialize [`TagSet`] by performing a DH ratchet
    ///
    /// Do DH key exchange between `private_key` and `public_key` to generate a new tag set key
    /// which is used, together with the previous root key to generate a new state for the
    /// [`TagSet`].
    ///
    /// Caller must ensure that `send_key_id` and `recv_key_id` are valid for this DH ratchet.
    fn reinitialize_tag_set(
        &mut self,
        private_key: StaticPrivateKey,
        public_key: StaticPublicKey,
        send_key_id: u16,
        recv_key_id: u16,
    ) {
        let tag_set_key = {
            let mut shared = private_key.diffie_hellman(&public_key);
            let mut temp_key = Hmac::new(&shared).update([]).finalize();
            let tagset_key =
                Hmac::new(&temp_key).update(b"XDHRatchetTagSet").update([0x01]).finalize();

            shared.zeroize();
            temp_key.zeroize();

            tagset_key
        };

        // perform a dh ratchet and reset `TagSet`'s state
        {
            self.key_context = KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

            // tag set id is calculated as `1 + send key id + receive key id`
            //
            // https://geti2p.net/spec/ecies#key-and-tag-set-ids
            self.tag_set_id = 1u16 + send_key_id + recv_key_id;
            self.key_state = KeyState::Active {
                send_key_id,
                recv_key_id,
                private_key,
                public_key: public_key.clone(),
            };

            // for the new tag set, tag numbers start again from zero
            // and progress towards `NUM_TAGS_TO_GENERATE`
            self.tag_index = 0u16;
        }
    }

    /// Attempt to generate new key for the next DH ratchet.
    ///
    /// If the [`TagSet`] still has enough tags, the function returns early and the session can keep
    /// using the [`Tagset`].
    ///
    /// https://geti2p.net/spec/ecies#dh-ratchet-message-flow
    pub fn try_generate_next_key<R: Runtime>(
        &mut self,
    ) -> Result<Option<NextKeyKind>, SessionError> {
        // more tags can be generated from the current dh ratchet
        if self.tag_index <= self.ratchet_threshold {
            return Ok(None);
        }

        match mem::replace(&mut self.key_state, KeyState::Poisoned) {
            KeyState::Uninitialized => {
                let private_key = StaticPrivateKey::random(R::rng());
                let public_key = private_key.public();

                self.key_state = KeyState::AwaitingReverseKey {
                    send_key_id: 0u16,
                    recv_key_id: 0u16,
                    private_key,
                };

                Ok(Some(
                    NextKeyBuilder::forward(0u16)
                        .with_public_key(public_key)
                        .with_request_reverse_key(true)
                        .build(),
                ))
            }
            KeyState::Active {
                send_key_id,
                recv_key_id,
                private_key: old_private_key,
                public_key: old_public_key,
            } => {
                // for even-numbered tag sets, send a new forward key to remote destination and do a
                // dh ratchet with the previous key received the from remote destination
                //
                // for odd-numbered tag sets, send a reverse key request to remote destination, wait
                // until a new key is received and once it's received, do a dh ratchet
                //
                // https://geti2p.net/spec/ecies#dh-ratchet-message-flow
                match !self.tag_set_id.is_multiple_of(2) {
                    true => {
                        let private_key = StaticPrivateKey::random(R::rng());
                        let public_key = private_key.public();

                        if send_key_id + 1 > MAX_KEY_ID {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?send_key_id,
                                "send key id is too large",
                            );
                            return Err(SessionError::SessionTerminated);
                        }

                        self.key_state = KeyState::AwaitingReverseKeyConfirmation {
                            send_key_id: send_key_id + 1,
                            recv_key_id,
                            private_key,
                            public_key: old_public_key,
                        };

                        Ok(Some(
                            NextKeyBuilder::forward(send_key_id + 1)
                                .with_public_key(public_key)
                                .build(),
                        ))
                    }
                    false => {
                        if recv_key_id + 1 > MAX_KEY_ID {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?send_key_id,
                                "receive key id is too large",
                            );
                            return Err(SessionError::SessionTerminated);
                        }

                        self.key_state = KeyState::AwaitingReverseKey {
                            send_key_id,
                            recv_key_id: recv_key_id + 1,
                            private_key: old_private_key,
                        };

                        Ok(Some(
                            NextKeyBuilder::forward(recv_key_id + 1)
                                .with_request_reverse_key(true)
                                .build(),
                        ))
                    }
                }
            }
            KeyState::AwaitingReverseKeyConfirmation {
                send_key_id,
                public_key,
                recv_key_id,
                private_key,
            } => {
                let next_key_block = NextKeyBuilder::forward(send_key_id)
                    .with_public_key(private_key.public())
                    .build();

                self.key_state = KeyState::AwaitingReverseKeyConfirmation {
                    send_key_id,
                    recv_key_id,
                    private_key,
                    public_key,
                };

                Ok(Some(next_key_block))
            }
            KeyState::AwaitingReverseKey {
                send_key_id,
                recv_key_id,
                private_key,
            } => {
                // for the first `NextKey` block (send and recv ids are 0) both our public
                // and a request for reverse key is sent
                //
                // otherwise only a request for reverse key is sent
                let next_key_block = if send_key_id == 0 && recv_key_id == 0 {
                    NextKeyBuilder::forward(0u16)
                        .with_public_key(private_key.public())
                        .with_request_reverse_key(true)
                        .build()
                } else {
                    NextKeyBuilder::forward(recv_key_id).with_request_reverse_key(true).build()
                };

                self.key_state = KeyState::AwaitingReverseKey {
                    send_key_id,
                    recv_key_id,
                    private_key,
                };

                Ok(Some(next_key_block))
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for tag set when generating next key",
                );
                debug_assert!(false);
                Err(SessionError::InvalidState)
            }
        }
    }

    /// Can `TagSet` ratchet using `kind`.
    ///
    /// See [`TagSet::handle_next_key()`] for more documentation on the combinations
    /// of `NextKeyKind` and `KeyState`.
    pub fn can_ratchet(&self, kind: &NextKeyKind) -> bool {
        match (&self.key_state, kind) {
            (
                KeyState::Uninitialized,
                NextKeyKind::ForwardKey {
                    key_id: 0u16,
                    public_key: Some(_),
                    reverse_key_requested: true,
                },
            ) => true,
            (
                KeyState::AwaitingReverseKey { .. },
                NextKeyKind::ReverseKey {
                    public_key: Some(_),
                    ..
                },
            ) => true,
            (
                KeyState::AwaitingReverseKeyConfirmation { .. },
                NextKeyKind::ReverseKey {
                    public_key: None, ..
                },
            ) => true,
            (
                KeyState::Active { send_key_id, .. },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: Some(_),
                    reverse_key_requested: false,
                },
            ) if send_key_id < key_id => key_id <= &MAX_KEY_ID,
            (
                KeyState::Active { recv_key_id, .. },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: None,
                    reverse_key_requested: true,
                },
            ) if recv_key_id < key_id => key_id <= &MAX_KEY_ID,
            _ => false,
        }
    }

    /// Handle `NextKey` block received from remote peer.
    pub fn handle_next_key<R: Runtime>(
        &mut self,
        kind: &NextKeyKind,
    ) -> Result<Option<NextKeyKind>, SessionError> {
        match (mem::replace(&mut self.key_state, KeyState::Poisoned), kind) {
            (
                KeyState::Uninitialized,
                NextKeyKind::ForwardKey {
                    key_id: 0u16,
                    public_key: Some(remote_public_key),
                    reverse_key_requested: true,
                },
            ) => {
                let private_key = StaticPrivateKey::random(R::rng());
                let public_key = private_key.public();

                self.reinitialize_tag_set(private_key, remote_public_key.clone(), 0u16, 0u16);

                Ok(Some(NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(public_key),
                }))
            }
            // requested reverse key has been received from remote
            //
            // this is the first dh ratchet done after the session has been initialized and the
            // dstinations have done a key exchange in both directions (sending a forward key and
            // receiving a reverse key)
            //
            // after this dh ratchet is performed, the destinations alternate between who creates
            // a new key and who reuses and old key
            (
                KeyState::AwaitingReverseKey {
                    send_key_id,
                    recv_key_id,
                    private_key,
                },
                NextKeyKind::ReverseKey {
                    public_key: Some(public_key),
                    ..
                },
            ) => {
                self.reinitialize_tag_set(
                    private_key,
                    public_key.clone(),
                    send_key_id,
                    recv_key_id,
                );

                Ok(None)
            }
            // `NextKey` confirmation has been received for the request
            //
            // local destination has sent a new key to remote destination without requesting a
            // reverse key, causing remote destination to reuse the old key
            (
                KeyState::AwaitingReverseKeyConfirmation {
                    send_key_id,
                    recv_key_id,
                    private_key,
                    public_key,
                },
                NextKeyKind::ReverseKey {
                    public_key: None, ..
                },
            ) => {
                self.reinitialize_tag_set(private_key, public_key, send_key_id, recv_key_id);

                Ok(None)
            }
            // active key state and remote destination has requested a dh ratchet
            //
            // this is the first kind where remote has sent their new public key without requesting
            // a reverse key, asking the local destination to use the previous key for the dh
            // ratchet
            //
            // the `NextKey` is replied only with a confirmation, without a reverse key
            (
                KeyState::Active {
                    recv_key_id,
                    private_key,
                    send_key_id,
                    ..
                },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: Some(remote_public_key),
                    reverse_key_requested: false,
                },
            ) if send_key_id < *key_id => {
                if key_id > &MAX_KEY_ID {
                    tracing::error!(
                        target: LOG_TARGET,
                        max_key_id = ?MAX_KEY_ID,
                        ?key_id,
                        "key id is too large",
                    );
                    debug_assert!(false);
                    return Err(SessionError::SessionTerminated);
                }

                self.reinitialize_tag_set(
                    private_key,
                    remote_public_key.clone(),
                    *key_id,
                    recv_key_id,
                );

                Ok(Some(NextKeyBuilder::reverse(recv_key_id).build()))
            }
            // active key state and remote destination has requested a dh ratchet
            //
            // this is the second kind where the remote destination is reusing their previous key
            // and is asking us to create a new key, send it to them and do a dh ratchet
            //
            // the `NextKey` is replied with the new public key used for the dh ratchet
            (
                KeyState::Active {
                    send_key_id,
                    recv_key_id,
                    public_key: remote_public_key,
                    ..
                },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: None,
                    reverse_key_requested: true,
                },
            ) if recv_key_id < *key_id => {
                if key_id > &MAX_KEY_ID {
                    tracing::error!(
                        target: LOG_TARGET,
                        max_key_id = ?MAX_KEY_ID,
                        ?key_id,
                        "key id is too large",
                    );
                    debug_assert!(false);
                    return Err(SessionError::SessionTerminated);
                }

                let private_key = StaticPrivateKey::random(R::rng());
                let public_key = private_key.public();

                self.reinitialize_tag_set(
                    private_key,
                    remote_public_key.clone(),
                    send_key_id,
                    *key_id,
                );

                Ok(Some(
                    NextKeyBuilder::reverse(*key_id).with_public_key(public_key).build(),
                ))
            }
            // unexpected `ReverseKey` since the state is `Active`
            //
            // this can happen if we requested a reverse key and remote sent it multiple times
            (
                state @ KeyState::Active {
                    send_key_id,
                    recv_key_id,
                    ..
                },
                NextKeyKind::ReverseKey { key_id, .. },
            ) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?send_key_id,
                    ?recv_key_id,
                    ?key_id,
                    "received unexpected `ReverseKey`, possibly duplicate",
                );
                self.key_state = state;

                Ok(None)
            }
            (
                KeyState::Active {
                    send_key_id,
                    recv_key_id,
                    public_key,
                    private_key,
                },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: remote_public_key,
                    reverse_key_requested,
                },
            ) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?send_key_id,
                    ?recv_key_id,
                    ?key_id,
                    remote_public_key = ?remote_public_key.is_some(),
                    ?reverse_key_requested,
                    "received unexpected `ForwardKey`, possibly duplicate",
                );

                let next_key = if *reverse_key_requested {
                    NextKeyKind::ReverseKey {
                        key_id: *key_id,
                        public_key: Some(private_key.public()),
                    }
                } else {
                    NextKeyBuilder::reverse(recv_key_id).build()
                };

                self.key_state = KeyState::Active {
                    send_key_id,
                    recv_key_id,
                    private_key,
                    public_key,
                };

                Ok(Some(next_key))
            }
            (state, kind) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    ?kind,
                    "invalid key state/next key kind combination",
                );
                debug_assert!(false);
                Err(SessionError::InvalidState)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    const TEST_THRESHOLD: u16 = 10;

    #[test]
    fn maximum_tags_generated() {
        let mut tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);
        let tags = (0..u16::MAX).map(|_| tag_set.next_entry().unwrap()).collect::<Vec<_>>();

        assert_eq!(tags.len(), MAX_TAGS);
    }

    #[test]
    fn full_dh_ratchet_cycle() {
        let mut send_tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);
        let mut recv_tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);

        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 0);
        assert_eq!(recv_tag_set.tag_set_id, 0);
        assert_eq!(send_tag_set.recv_key_id, None);
        assert_eq!(recv_tag_set.recv_key_id, None);
        assert_eq!(send_tag_set.send_key_id, None);
        assert_eq!(recv_tag_set.send_key_id, None);

        // generate tags until the first dh ratchet can be done
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 0u16,
                    public_key: Some(_),
                    reverse_key_requested: true,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(_),
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send and receive key ids are 0
        // * tag set id 1
        // * tag index is 0
        // * tag sets have each other's public keys stored
        //
        // send and receive key ids are 0
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 1);
        assert_eq!(recv_tag_set.tag_set_id, 1);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 0,
                recv_key_id: 0,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 0,
                recv_key_id: 0,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_vec(), r_pub.to_vec());
        assert_eq!(r_priv.public().to_vec(), s_pub.to_vec());

        // generate tags until the second dh ratchet can be done
        //
        // during this ratchet, owner of the send tag set sends their new key to remote
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 1u16,
                    public_key: Some(_),
                    reverse_key_requested: false,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: None,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send key id is 1
        // * receive key ids is 0
        // * tag set id 2
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 2);
        assert_eq!(recv_tag_set.tag_set_id, 2);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 0u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 0u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_vec(), r_pub.to_vec());
        assert_eq!(r_priv.public().to_vec(), s_pub.to_vec());

        // generate tags until the second dh ratchet can be done
        //
        // during this ratchet, owner of the send tag set requests a reverse key from remote
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 1u16,
                    public_key: None,
                    reverse_key_requested: true,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 1u16,
                    public_key: Some(_),
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send key id is 1
        // * receive key ids is 1
        // * tag set id 3
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 3);
        assert_eq!(recv_tag_set.tag_set_id, 3);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_vec(), r_pub.to_vec());
        assert_eq!(r_priv.public().to_vec(), s_pub.to_vec());

        // generate tags until the second dh ratchet can be done
        //
        // during this ratchet, the process cycles back to tag owner sending a key to remote
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 2u16,
                    public_key: Some(_),
                    reverse_key_requested: false,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 1u16,
                    public_key: None,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send key id is 1
        // * receive key ids is 1
        // * tag set id 3
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 4);
        assert_eq!(recv_tag_set.tag_set_id, 4);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 2u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 2u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_vec(), r_pub.to_vec());
        assert_eq!(r_priv.public().to_vec(), s_pub.to_vec());
    }

    #[test]
    fn duplicate_reverse_key() {
        let mut send_tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);
        let mut recv_tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);

        // generate tags until the first dh ratchet can be done
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            if send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().is_some() {
                break;
            }
        }

        // ensure that `send_tag_set` keeps generating `ForwardKey`
        for _ in 0..3 {
            let kind = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().unwrap();

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 0u16,
                    public_key: Some(_),
                    reverse_key_requested: true,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            match recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(_),
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }
        }

        let kind = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().unwrap();

        match &kind {
            NextKeyKind::ForwardKey {
                key_id: 0u16,
                public_key: Some(_),
                reverse_key_requested: true,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

        // handle `NextKey` block with `ReverseKey` twice
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());

        // generate tags until the second dh ratchet can be done
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            if send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().is_some() {
                break;
            }
        }

        // ensure that `send_tag_set` keeps generating `ForwardKey`
        for _ in 0..3 {
            let kind = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().unwrap();

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 1u16,
                    public_key: Some(_),
                    reverse_key_requested: false,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            match recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: None,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }
        }

        let kind = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().unwrap();

        match &kind {
            NextKeyKind::ForwardKey {
                key_id: 1u16,
                public_key: Some(_),
                reverse_key_requested: false,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

        // handle `NextKey` block with `ReverseKey` twice
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());

        // generate tags until the third dh ratchet can be done
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            if send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().is_some() {
                break;
            }
        }

        // ensure that `send_tag_set` keeps generating `ForwardKey`
        for _ in 0..3 {
            let kind = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().unwrap();

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 1u16,
                    public_key: None,
                    reverse_key_requested: true,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            match recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
                NextKeyKind::ReverseKey {
                    key_id: 1u16,
                    public_key: Some(_),
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }
        }

        let kind = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap().unwrap();

        match &kind {
            NextKeyKind::ForwardKey {
                key_id: 1u16,
                public_key: None,
                reverse_key_requested: true,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

        // handle `NextKey` block with `ReverseKey` twice
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
        assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());

        // generate some tags with the new tagset
        for _ in 0..100 {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());
        }
    }

    #[test]
    fn duplicate_forward_key() {
        let mut send_tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);
        let mut recv_tag_set = TagSet::new([1u8; 32], [2u8; 32], TEST_THRESHOLD);

        // generate tags until the first dh ratchet can be done
        let kind = loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            if let Some(kind) = recv_tag_set.try_generate_next_key::<MockRuntime>().unwrap() {
                break kind;
            }
        };

        match &kind {
            NextKeyKind::ForwardKey {
                key_id: 0u16,
                public_key: Some(_),
                reverse_key_requested: true,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        let prev_pubkey =
            match &send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(pubkey),
                } => {
                    assert!(recv_tag_set
                        .handle_next_key::<MockRuntime>(&NextKeyKind::ReverseKey {
                            key_id: 0u16,
                            public_key: Some(pubkey.clone())
                        })
                        .expect("to succeed")
                        .is_none());

                    pubkey.clone()
                }
                kind => panic!("invalid next key kind: {kind:?}"),
            };

        let prev_pubkey =
            match &send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(pubkey),
                } => {
                    assert_eq!(
                        AsRef::<[u8]>::as_ref(pubkey),
                        AsRef::<[u8]>::as_ref(&prev_pubkey)
                    );
                    pubkey.clone()
                }
                kind => panic!("invalid next key kind: {kind:?}"),
            };

        match &send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
            NextKeyKind::ReverseKey {
                key_id: 0u16,
                public_key: Some(pubkey),
            } => {
                assert_eq!(
                    AsRef::<[u8]>::as_ref(pubkey),
                    AsRef::<[u8]>::as_ref(&prev_pubkey)
                );
            }
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        // generate tags until the first dh ratchet can be done
        let kind = loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            if let Some(kind) = recv_tag_set.try_generate_next_key::<MockRuntime>().unwrap() {
                break kind;
            }
        };

        match &kind {
            NextKeyKind::ForwardKey {
                key_id: 1u16,
                public_key: Some(_),
                reverse_key_requested: false,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        match &send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
            NextKeyKind::ReverseKey {
                key_id: 0u16,
                public_key: None,
            } => {
                assert!(recv_tag_set
                    .handle_next_key::<MockRuntime>(&NextKeyKind::ReverseKey {
                        key_id: 0u16,
                        public_key: None,
                    })
                    .expect("to succeed")
                    .is_none());
            }
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        match &send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
            NextKeyKind::ReverseKey {
                key_id: 0u16,
                public_key: None,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        match &send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap() {
            NextKeyKind::ReverseKey {
                key_id: 0u16,
                public_key: None,
            } => {}
            kind => panic!("invalid next key kind: {kind:?}"),
        }

        // generate some tags to ensure all is ok
        for _ in 0..10 {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());
        }
    }
}
