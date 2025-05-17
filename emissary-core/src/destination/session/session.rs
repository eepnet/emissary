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
    crypto::{chachapoly::ChaChaPoly, StaticPublicKey},
    destination::session::{
        context::KeyContext,
        inbound::InboundSession,
        outbound::OutboundSession,
        tag_set::{TagSet, TagSetEntry},
        LOG_TARGET, NUM_TAGS_TO_GENERATE,
    },
    error::SessionError,
    i2np::{
        garlic::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicMessage, GarlicMessageBlock,
            GarlicMessageBuilder, NextKeyKind,
        },
        MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{DestinationId, MessageId},
    runtime::{Instant, Runtime},
};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::{fmt, mem, time::Duration};

/// Garlic message overheard.
///
/// 8 bytes for garlic tag and 16 bytes Poly1305 MAC.
const GARLIC_MESSAGE_OVERHEAD: usize = 24usize;

/// Maximum age for pending session.
const PENDING_SESSION_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// Maximum age for [`NsrContext`].
const NSR_CONTEXT_MAX_AGE: Duration = Duration::from_secs(3 * 60);

/// Maximum age for a tag that belonged to a previous tag set.
const PREV_TAG_MAX_AGE: Duration = Duration::from_secs(3 * 60);

/// Number of extra tags to generate from the old tag set when it's about to expire.
const NUM_EXTRA_TAGS_TO_GENERATE: usize = 128usize;

/// Event emitted by [`PendingSession`].
pub enum PendingSessionEvent<R: Runtime> {
    /// Send message to remote destination.
    SendMessage {
        /// Serialized message.
        message: Vec<u8>,
    },

    /// Return message decrypted message.
    ReturnMessage {
        /// Decrypted message.
        message: Vec<u8>,

        /// Tag set ID.
        tag_set_id: u16,

        /// Tag index.
        tag_index: u16,
    },

    /// Create new active `Session` and send `message` to remote destination.
    CreateSession {
        /// Serialized message.
        message: Vec<u8>,

        /// Session context.
        context: Box<SessionContext<R>>,

        /// Tag set ID.
        tag_set_id: u16,

        /// Tag index.
        tag_index: u16,
    },
}

/// State of the pending session.
enum PendingSessionState<R: Runtime> {
    /// Inbound session received from remote destination.
    InboundActive {
        /// Inbound session.
        inbound: InboundSession<R>,

        /// Garlic tags, global mapping for all active and pending sessions.
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

        /// Garlic tag -> session key mapping for inbound messages.
        tag_set_entries: HashMap<u64, TagSetEntry>,
    },

    /// Outbound session is awaiting the reception of an NSR message.
    AwaitingNsr {
        /// Outbound sessions.
        outbound: HashMap<usize, OutboundSession<R>>,

        /// Remote's static public key.
        remote_public_key: StaticPublicKey,

        /// Garlic tags, global mapping for all active and pending sessions.
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

        /// Garlic tag -> (session, session key) mapping for NSR message(s).
        nsr_tag_set_entries: HashMap<u64, (usize, TagSetEntry)>,

        /// Garlic tag -> session key mapping for ES messages.
        tag_set_entries: HashMap<u64, TagSetEntry>,
    },

    /// Outbound session is awaiting the destination to send its first message so the session can
    /// be converted into an active session.
    AwaitingEsTransmit {
        /// Outbound sessions.
        ///
        /// These sessions are considered inactive as an NSR has already been received for one of
        /// the session and send/receive tag sets have been generated for that session.
        outbound: HashMap<usize, OutboundSession<R>>,

        /// Send tag set.
        send_tag_set: Box<TagSet>,

        /// Receive tag set.
        recv_tag_set: Box<TagSet>,

        /// Remote's static public key.
        remote_public_key: StaticPublicKey,

        /// Garlic tags, global mapping for all active and pending sessions.
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

        /// Garlic tag -> (session, session key) mapping for NSR message(s).
        nsr_tag_set_entries: HashMap<u64, (usize, TagSetEntry)>,

        /// Garlic tag -> session key mapping for ES messages.
        tag_set_entries: HashMap<u64, TagSetEntry>,
    },

    /// State has been poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for PendingSessionState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InboundActive { .. } =>
                f.debug_struct("PendingSessionState::InboundActive").finish_non_exhaustive(),
            Self::AwaitingNsr { .. } =>
                f.debug_struct("PendingSessionState::AwaitingNsr").finish_non_exhaustive(),
            Self::AwaitingEsTransmit { .. } => f
                .debug_struct("PendingSessionState::AwaitingEsTransmit")
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("PendingSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
}

/// Pending ECIES-X25519-AEAD-Ratchet session.
pub struct PendingSession<R: Runtime> {
    /// When was the pending session created.
    created: R::Instant,

    /// Key context.
    key_context: KeyContext<R>,

    /// ID of the local destination.
    local: DestinationId,

    /// ID of the remote destination.
    remote: DestinationId,

    /// State of the session.
    state: PendingSessionState<R>,
}

impl<R: Runtime> PendingSession<R> {
    /// Create new [`Session`] from an [`InboundSession`].
    pub fn new_inbound(
        local: DestinationId,
        remote: DestinationId,
        inbound: InboundSession<R>,
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,
        key_context: KeyContext<R>,
    ) -> Self {
        Self {
            created: R::now(),
            key_context,
            local,
            remote,
            state: PendingSessionState::InboundActive {
                inbound,
                tag_set_entries: HashMap::new(),
                garlic_tags,
            },
        }
    }

    /// Create new [`Session`] from an [`OutboundSession`].
    pub fn new_outbound(
        local: DestinationId,
        remote: DestinationId,
        remote_public_key: StaticPublicKey,
        outbound: OutboundSession<R>,
        garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,
        key_context: KeyContext<R>,
        ratchet_threshold: u16,
    ) -> Self {
        // generate and store tag set entries for NSR
        let nsr_tag_set_entries = {
            let mut inner = garlic_tags.write();

            outbound
                .generate_new_session_reply_tags(ratchet_threshold)
                .map(|tag_set| {
                    inner.insert(tag_set.tag, remote.clone());
                    (tag_set.tag, (0usize, tag_set))
                })
                .collect()
        };

        Self {
            created: R::now(),
            key_context,
            local,
            remote,
            state: PendingSessionState::AwaitingNsr {
                outbound: HashMap::from_iter([(0usize, outbound)]),
                remote_public_key,
                garlic_tags,
                nsr_tag_set_entries,
                tag_set_entries: HashMap::new(),
            },
        }
    }

    /// Is the pending session expired.
    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > PENDING_SESSION_MAX_AGE
    }

    /// Advance the state of [`PendingSession`] with an outbound `message`.
    ///
    /// TODO: more documentation
    pub fn advance_outbound(
        &mut self,
        lease_set: Bytes,
        message: Vec<u8>,
        ratchet_threshold: u16,
    ) -> Result<PendingSessionEvent<R>, SessionError> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive {
                mut inbound,
                mut tag_set_entries,
                garlic_tags,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send NSR",
                );

                let hash = self.remote.to_vec();
                let message = GarlicMessageBuilder::default()
                    .with_garlic_clove(
                        MessageType::Data,
                        MessageId::from(R::rng().next_u32()),
                        R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        GarlicDeliveryInstructions::Destination { hash: &hash },
                        &{
                            let mut out = BytesMut::with_capacity(message.len() + 4);

                            out.put_u32(message.len() as u32);
                            out.put_slice(&message);
                            out
                        },
                    )
                    .build();

                // create `NewSessionReply` and garlic receive tags
                let (message, entries) =
                    inbound.create_new_session_reply(message, ratchet_threshold)?;

                // store receive garlic tags both in the global storage common for all destinations
                // so `SessionManager` can dispatch received messages to the correct `Session` and
                // also in the session's own `TagSetEntry` storage so the session has access to the
                // session key and associated context to decrypt the message
                {
                    let mut inner = garlic_tags.write();

                    entries.into_iter().for_each(|entry| {
                        inner.insert(entry.tag, self.remote.clone());
                        tag_set_entries.insert(entry.tag, entry);
                    })
                }

                self.state = PendingSessionState::InboundActive {
                    inbound,
                    tag_set_entries,
                    garlic_tags,
                };

                Ok(PendingSessionEvent::SendMessage { message })
            }
            PendingSessionState::AwaitingNsr {
                garlic_tags,
                mut outbound,
                mut nsr_tag_set_entries,
                remote_public_key,
                tag_set_entries,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "send another NS",
                );

                let (session, message) = self.key_context.create_outbound_session(
                    self.local.clone(),
                    self.remote.clone(),
                    &remote_public_key,
                    lease_set,
                    &message,
                );

                // generate and store tag set entries for `NewSessionReply`
                {
                    let mut inner = garlic_tags.write();

                    session.generate_new_session_reply_tags(ratchet_threshold).for_each(
                        |tag_set| {
                            inner.insert(tag_set.tag, self.remote.clone());
                            nsr_tag_set_entries.insert(tag_set.tag, (outbound.len(), tag_set));
                        },
                    );
                }
                outbound.insert(outbound.len(), session);

                self.state = PendingSessionState::AwaitingNsr {
                    outbound,
                    garlic_tags,
                    nsr_tag_set_entries,
                    remote_public_key,
                    tag_set_entries,
                };

                Ok(PendingSessionEvent::SendMessage { message })
            }
            PendingSessionState::AwaitingEsTransmit {
                outbound,
                mut send_tag_set,
                recv_tag_set,
                garlic_tags,
                nsr_tag_set_entries,
                tag_set_entries,
                ..
            } => {
                let TagSetEntry {
                    key,
                    tag,
                    tag_index,
                    tag_set_id,
                } = send_tag_set.next_entry().ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.local,
                        remote = %self.remote,
                        "`TagSet` ran out of tags",
                    );
                    debug_assert!(false);
                    SessionError::InvalidState
                })?;

                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    garlic_tag = ?tag,
                    "send first ES message",
                );

                let message = {
                    let mut out = BytesMut::with_capacity(message.len() + 4);

                    out.put_u32(message.len() as u32);
                    out.put_slice(&message);
                    out
                };
                let hash = self.remote.to_vec();
                let builder = GarlicMessageBuilder::default().with_garlic_clove(
                    MessageType::Data,
                    MessageId::from(R::rng().next_u32()),
                    R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    GarlicDeliveryInstructions::Destination { hash: &hash },
                    &message,
                );

                let mut message = builder.build();
                let mut out = BytesMut::with_capacity(message.len() + GARLIC_MESSAGE_OVERHEAD);

                ChaChaPoly::with_nonce(&key, tag_index as u64)
                    .encrypt_with_ad_new(&tag.to_le_bytes(), &mut message)?;

                out.put_u64_le(tag);
                out.put_slice(&message);

                Ok(PendingSessionEvent::CreateSession {
                    message: out.freeze().to_vec(),
                    context: Box::new(SessionContext {
                        garlic_tags,
                        local: self.local.clone(),
                        recv_tag_set: *recv_tag_set,
                        remote: self.remote.clone(),
                        send_tag_set: *send_tag_set,
                        tag_set_entries,
                        nsr_context: NsrContext::new(nsr_tag_set_entries, outbound),
                    }),
                    tag_set_id,
                    tag_index,
                })
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    ?state,
                    "invalid session state",
                );
                debug_assert!(false);
                Err(SessionError::InvalidState)
            }
        }
    }

    /// Advance the state of [`PendingSession`] with an inbound `message`.
    ///
    /// This is either a `NewSessionReply` for outbound sessions or a `ExistingSession`
    /// for inbound session.
    pub fn advance_inbound(
        &mut self,
        garlic_tag: u64,
        message: Vec<u8>,
        ratchet_threshold: u16,
    ) -> Result<PendingSessionEvent<R>, SessionError> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::InboundActive {
                mut inbound,
                mut tag_set_entries,
                garlic_tags,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "ES received",
                );

                let tag_set_entry = tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.local,
                        remote = %self.remote,
                        ?garlic_tag,
                        "`TagSetEntry` doesn't exist for ES",
                    );

                    debug_assert!(false);
                    SessionError::InvalidState
                })?;
                let tag_set_id = tag_set_entry.tag_set_id;
                let tag_index = tag_set_entry.tag_index;

                let (message, send_tag_set, recv_tag_set) =
                    inbound.handle_existing_session(garlic_tag, tag_set_entry, message)?;

                Ok(PendingSessionEvent::CreateSession {
                    message,
                    context: Box::new(SessionContext {
                        recv_tag_set,
                        send_tag_set,
                        tag_set_entries,
                        garlic_tags,
                        local: self.local.clone(),
                        remote: self.remote.clone(),
                        nsr_context: NsrContext::Inactive,
                    }),
                    tag_set_id,
                    tag_index,
                })
            }
            PendingSessionState::AwaitingNsr {
                garlic_tags,
                mut outbound,
                mut nsr_tag_set_entries,
                mut tag_set_entries,
                remote_public_key,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "NSR received"
                );

                let (session_idx, tag_set_entry) =
                    nsr_tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.local,
                            remote = %self.remote,
                            ?garlic_tag,
                            "`TagSetEntry` doesn't exist for NSR",
                        );

                        debug_assert!(false);
                        SessionError::InvalidState
                    })?;
                let tag_set_id = tag_set_entry.tag_set_id;
                let tag_index = tag_set_entry.tag_index;

                let (message, send_tag_set, mut recv_tag_set) = outbound
                    .get_mut(&session_idx)
                    .expect("to exist")
                    .handle_new_session_reply(tag_set_entry, message, ratchet_threshold)?;

                // generate tag set entries for inbound messages and store remote's id in the global
                // storage under the generated garlic tags and store the tag set entries themselves
                // inside the `Session`'s storage
                //
                // these tags are for ES messages and the session tracks NSR tags separately
                {
                    let mut inner = garlic_tags.write();

                    // `next_entry()` must succeed as `recv_tag_set` is a fresh `TagSet`
                    (0..NUM_TAGS_TO_GENERATE).for_each(|_| {
                        let entry = recv_tag_set.next_entry().expect("to succeed");

                        inner.insert(entry.tag, self.remote.clone());
                        tag_set_entries.insert(entry.tag, entry);
                    });
                };

                self.state = PendingSessionState::AwaitingEsTransmit {
                    outbound,
                    send_tag_set: Box::new(send_tag_set),
                    recv_tag_set: Box::new(recv_tag_set),
                    garlic_tags,
                    tag_set_entries,
                    remote_public_key,
                    nsr_tag_set_entries,
                };

                Ok(PendingSessionEvent::ReturnMessage {
                    tag_set_id,
                    tag_index,
                    message,
                })
            }
            PendingSessionState::AwaitingEsTransmit {
                mut outbound,
                send_tag_set,
                recv_tag_set,
                remote_public_key,
                garlic_tags,
                mut nsr_tag_set_entries,
                tag_set_entries,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "NSR received while waiting to send ES"
                );

                let (session_idx, tag_set_entry) =
                    nsr_tag_set_entries.remove(&garlic_tag).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.local,
                            remote = %self.remote,
                            ?garlic_tag,
                            "`TagSetEntry` doesn't exist for NSR",
                        );

                        debug_assert!(false);
                        SessionError::InvalidState
                    })?;
                let tag_set_id = tag_set_entry.tag_set_id;
                let tag_index = tag_set_entry.tag_index;

                let (message, _send_tag_set, mut _recv_tag_set) = outbound
                    .get_mut(&session_idx)
                    .expect("to exist")
                    .handle_new_session_reply(tag_set_entry, message, ratchet_threshold)?;

                self.state = PendingSessionState::AwaitingEsTransmit {
                    outbound,
                    send_tag_set,
                    recv_tag_set,
                    garlic_tags,
                    tag_set_entries,
                    remote_public_key,
                    nsr_tag_set_entries,
                };

                Ok(PendingSessionEvent::ReturnMessage {
                    tag_set_id,
                    tag_index,
                    message,
                })
            }
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "session state has been poisoned",
                );
                debug_assert!(false);
                Err(SessionError::InvalidState)
            }
        }
    }
}

/// NSR context.
///
/// Remote may send multiple NSR messages, some of which may be received after the local destination
/// has sent its first ES. In order to handle these late NSR messages gracefully, they're tracked
/// using a separate context which only handles NSR messages received into an active session. These
/// messages must be handled separately as ES and NSR messages are handled differently.
///
/// For sessions where the local destination was the inbound participant (Bob), NSR context is
/// always inactive. For sessions where the the local destination was the outbound participant
/// (Alice), the NSR context is configured to be active and it's converted into an inactive session
/// after the NSR tag set expires.
enum NsrContext<R: Runtime> {
    /// NSR context is inactive either because the tag set has expired or this context belongs to
    /// an inbound session which doesn't need it.
    Inactive,

    /// NSR context is active.
    Active {
        /// When was the context created.
        created: R::Instant,

        /// Garlic tag -> (session, session key) mapping for NSR message(s).
        tag_set_entries: HashMap<u64, (usize, TagSetEntry)>,

        /// Active sessions.
        sessions: HashMap<usize, OutboundSession<R>>,
    },
}

impl<R: Runtime> NsrContext<R> {
    /// Create new [`NsrContext`].
    pub fn new(
        tag_set_entries: HashMap<u64, (usize, TagSetEntry)>,
        sessions: HashMap<usize, OutboundSession<R>>,
    ) -> Self {
        Self::Active {
            created: R::now(),
            tag_set_entries,
            sessions,
        }
    }

    /// Attempt to decrypt `message` using an NSR tag set entry.
    ///
    /// Returns an error if the context is inactive or `garlic_tag` doesn't exist.
    fn decrypt(
        &mut self,
        garlic_tag: u64,
        message: Vec<u8>,
        ratchet_threshold: u16,
    ) -> Result<(u16, u16, Vec<u8>), SessionError> {
        let NsrContext::Active {
            tag_set_entries,
            sessions,
            ..
        } = self
        else {
            return Err(SessionError::UnknownTag);
        };

        let (session_idx, tag_set_entry) =
            tag_set_entries.remove(&garlic_tag).ok_or(SessionError::UnknownTag)?;
        let session = sessions.get_mut(&session_idx).ok_or(SessionError::UnknownTag)?;

        tracing::debug!(
            target: LOG_TARGET,
            ?garlic_tag,
            "late NSR message",
        );

        let tag_set_id = tag_set_entry.tag_set_id;
        let tag_index = tag_set_entry.tag_index;

        session
            .handle_new_session_reply(tag_set_entry, message, ratchet_threshold)
            .map(|(message, _, _)| (tag_set_id, tag_index, message))
    }

    /// Attempt to expire
    fn try_expire(&mut self) -> Option<impl Iterator<Item = u64>> {
        match self {
            Self::Inactive => None,
            Self::Active { created, .. } if created.elapsed() < NSR_CONTEXT_MAX_AGE => None,
            Self::Active {
                tag_set_entries, ..
            } => {
                let garlic_tags = tag_set_entries.keys().copied().collect::<Vec<_>>();
                *self = Self::Inactive;

                Some(garlic_tags.into_iter())
            }
        }
    }
}

/// Session context, passed into [`Session::new()`].
pub struct SessionContext<R: Runtime> {
    /// Garlic tags, global mapping for all active and pending sessions.
    garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

    /// ID of the local destination.
    local: DestinationId,

    /// `TagSet` for inbound messages.
    recv_tag_set: TagSet,

    /// ID of the remote destination.
    remote: DestinationId,

    /// `TagSet` for outbound messages.
    send_tag_set: TagSet,

    /// `TagSet` entries for inbound messages.
    tag_set_entries: HashMap<u64, TagSetEntry>,

    /// NSR context.
    ///
    /// Always `NsrContext::Inactive` for inbound sessions.
    ///
    /// For outbound context, converted to `NsrContext::Inactive` after the tag sets have been
    /// expired.
    nsr_context: NsrContext<R>,
}

/// Active ECIES-X25519-AEAD-Ratchet session.
pub struct Session<R: Runtime> {
    /// Tags that marked to expire.
    expiring: VecDeque<(R::Instant, HashSet<u64>)>,

    /// Garlic tags, global mapping for all active and pending sessions.
    garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

    /// ID of the local destination.
    local: DestinationId,

    /// NSR context.
    ///
    /// See [`NsrContext`] for more details.
    nsr_context: NsrContext<R>,

    /// Pending `NextKey` block, if any.
    ///
    /// Set to `Some(NextKeyKind)` if remote has sent a `NextKey` block that warrants a response.
    pending_next_key: Option<NextKeyKind>,

    /// `TagSet` for inbound messages.
    recv_tag_set: TagSet,

    /// ID of the remote destination.
    remote: DestinationId,

    /// `TagSet` for outbound messages.
    send_tag_set: TagSet,

    /// `TagSet` entries for inbound messages.
    tag_set_entries: HashMap<u64, TagSetEntry>,
}

impl<R: Runtime> Session<R> {
    /// Create new [`Session`].
    pub fn new(context: SessionContext<R>) -> Self {
        let SessionContext {
            garlic_tags,
            local,
            recv_tag_set,
            remote,
            send_tag_set,
            tag_set_entries,
            nsr_context,
        } = context;

        Self {
            expiring: VecDeque::new(),
            garlic_tags,
            local,
            nsr_context,
            pending_next_key: None,
            recv_tag_set,
            remote,
            send_tag_set,
            tag_set_entries,
        }
    }

    /// Returns true if there is a pending next key
    pub fn has_pending_next_key(&self) -> bool {
        self.pending_next_key.is_some()
    }

    /// Decrypt `message` using `garlic_tag` which identifies a `TagSetEntry`.
    ///
    /// Retuns the tag set ID and tag index of the decrypted message, along with the message itself.
    pub fn decrypt(
        &mut self,
        garlic_tag: u64,
        message: Vec<u8>,
        ratchet_threshold: u16,
    ) -> Result<(u16, u16, Vec<u8>), SessionError> {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            ?garlic_tag,
            len = ?message.len(),
            "received ES",
        );

        // try to find a tag set entry from the tag sets generated for this session
        //
        // if no entry is found, try to decrypt the message using one of the tags generated for NSR
        // messages in case this is a late and/or retransmitted NSR message received after an ES
        // message was sent
        //
        // if the tag is not found in either set, reject the message and return an error
        let Some(TagSetEntry {
            key,
            tag,
            tag_index,
            tag_set_id,
        }) = self.tag_set_entries.remove(&garlic_tag)
        else {
            return self.nsr_context.decrypt(garlic_tag, message, ratchet_threshold).map_err(
                |error| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.local,
                        remote = %self.remote,
                        ?garlic_tag,
                        ?error,
                        "`TagSetEntry` doesn't exist and failed to handle as NSR",
                    );

                    debug_assert!(false);
                    SessionError::InvalidState
                },
            );
        };

        // generate new tag for the used tag if there are tags left
        {
            match self.recv_tag_set.next_entry() {
                None => tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    "receive tag set ran out of tags",
                ),
                Some(entry) => {
                    self.garlic_tags.write().insert(entry.tag, self.remote.clone());
                    self.tag_set_entries.insert(entry.tag, entry);
                }
            }
        }

        let mut payload = message[12..].to_vec();
        let payload = ChaChaPoly::with_nonce(&key, tag_index as u64)
            .decrypt_with_ad(&tag.to_le_bytes(), &mut payload)
            .map(|_| payload)?;

        // parse `payload` into garlic message and check if it contains a `NextKey` block
        let message = GarlicMessage::parse(&payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                "malformed garlic message",
            );

            SessionError::Malformed
        })?;

        // handle `NextKey` blocks
        //
        // forward keys are handled by the receive tag set and reverse keys by the send tag set
        message.blocks.iter().try_for_each(|block| match block {
            GarlicMessageBlock::NextKey { kind } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    ?kind,
                    "handle `NextKey` block",
                );

                match **kind {
                    NextKeyKind::ForwardKey { .. } => {
                        // `recv_tag_set` can ratchet using `kind`, meaning this is the first
                        // occurrence of an expected `NextKey` block
                        //
                        // whether the ratchet can be performed must be checked before performing it
                        // because the tags of the previouis tag set are set to expire and a new set
                        // of tags is generated from the fresh tag set
                        //
                        // if this check is not performed and a duplicate `NextKey` block is
                        // received, tags from the current tag set are marked as expiring which is
                        // not what we want
                        self.pending_next_key = if self.recv_tag_set.can_ratchet(kind) {
                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.local,
                                remote = %self.remote,
                                ?kind,
                                "ratchet receive tag set",
                            );

                            {
                                // generate some extra tags from the old tag set in case the ratchet
                                // takes long time to perform (due to missed packets)
                                let mut inner = self.garlic_tags.write();

                                for _ in 0..NUM_EXTRA_TAGS_TO_GENERATE {
                                    if let Some(entry) = self.recv_tag_set.next_entry() {
                                        inner.insert(entry.tag, self.remote.clone());
                                        self.tag_set_entries.insert(entry.tag, entry);
                                    }
                                }

                                // collect all tags of the current tag set into a separate storage
                                // from which they're easy to expire once the tag set they belonged
                                // to expires
                                let expiring_tags =
                                    self.tag_set_entries.keys().copied().collect::<HashSet<_>>();
                                self.expiring.push_back((R::now(), expiring_tags));
                            }

                            // handle `NextKey` block which does a DH ratchet and creates a new
                            // `TagSet`, replacing the old one
                            let next_key = self.recv_tag_set.handle_next_key::<R>(kind)?;

                            // generate tag set entries for the new tag set
                            //
                            // associate `self.remote` with the new tags in the global tag storage
                            // and store the `TagSetEntry` objects into
                            // `Session`'s own storage
                            {
                                let mut inner = self.garlic_tags.write();

                                // `next_entry()` must succeed as `recv_tag_set` is a fresh `TagSet`
                                (0..NUM_TAGS_TO_GENERATE).for_each(|_| {
                                    let entry = self.recv_tag_set.next_entry().expect("to succeed");

                                    inner.insert(entry.tag, self.remote.clone());
                                    self.tag_set_entries.insert(entry.tag, entry);
                                });
                            }

                            next_key
                        } else {
                            // duplicate `ForwardKey` was received
                            //
                            // return `NextKey` block which is sent when the next ES is sent to
                            // remote but don't modify the active tags since they've already been
                            // modified by the first `NextKey` block
                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.local,
                                remote = %self.remote,
                                ?kind,
                                "receive tag set already ratcheted",
                            );
                            self.recv_tag_set.handle_next_key::<R>(kind)?
                        };
                    }
                    NextKeyKind::ReverseKey { .. } => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.local,
                            remote = %self.remote,
                            ?kind,
                            "handle reverse key",
                        );

                        self.pending_next_key = self.send_tag_set.handle_next_key::<R>(kind)?;
                    }
                }

                Ok::<_, SessionError>(())
            }
            _ => Ok::<_, SessionError>(()),
        })?;

        Ok((tag_set_id, tag_index, payload))
    }

    /// Encrypt `message`.
    pub fn encrypt(
        &mut self,
        mut message_builder: GarlicMessageBuilder,
    ) -> Result<(u16, u16, Vec<u8>), SessionError> {
        let TagSetEntry {
            key,
            tag,
            tag_index,
            tag_set_id,
        } = self.send_tag_set.next_entry().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                "`TagSet` ran out of tags",
            );
            debug_assert!(false);
            SessionError::InvalidState
        })?;

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            garlic_tag = ?tag,
            "send ES",
        );

        // check if a dh ratchet should be performed because enought tags have been generated from
        // the active `TagSet`
        //
        // `TagSet` keeps track of the ratchet states and if a dh ratchet should be performed, it
        // returns the appropriate `NextKeyKind` which needs to added to into the garlic message
        message_builder = match self.send_tag_set.try_generate_next_key::<R>()? {
            Some(kind) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    ?kind,
                    "send forward `NextKey` block",
                );

                message_builder.with_next_key(kind)
            }
            None => message_builder,
        };

        // add any potential pending next key block for receive tag set
        message_builder = match self.pending_next_key.take() {
            Some(kind) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    ?kind,
                    "send reverse `NextKey` block",
                );

                message_builder.with_next_key(kind)
            }
            None => message_builder,
        };

        let mut message = message_builder.build();
        let mut out = BytesMut::with_capacity(message.len() + GARLIC_MESSAGE_OVERHEAD);

        ChaChaPoly::with_nonce(&key, tag_index as u64)
            .encrypt_with_ad_new(&tag.to_le_bytes(), &mut message)?;

        out.put_u64_le(tag);
        out.put_slice(&message);

        Ok((tag_set_id, tag_index, out.freeze().to_vec()))
    }

    /// Do periodic maintenance for the session.
    pub fn maintain(&mut self) {
        if let Some(tags) = self.nsr_context.try_expire() {
            let mut inner = self.garlic_tags.write();

            tags.for_each(|tag| {
                inner.remove(&tag);
            });
        }

        loop {
            let Some((created, _)) = self.expiring.front() else {
                break;
            };

            if created.elapsed() < PREV_TAG_MAX_AGE {
                break;
            }

            // entry must exist since it was just checked to exist
            let (_, tags) = self.expiring.pop_front().expect("to exist");

            // remove all expired tags from both the global and local storage
            {
                let mut inner = self.garlic_tags.write();

                tags.into_iter().for_each(|tag| {
                    inner.remove(&tag);
                    self.tag_set_entries.remove(&tag);
                });
            }
        }
    }

    /// Destroy session and return all active and expiring garlic tags.
    pub fn destroy(self) {
        tracing::info!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            "destroy session",
        );
        let mut inner = self.garlic_tags.write();

        self.tag_set_entries.keys().for_each(|tag| {
            inner.remove(tag);
        });
    }
}
