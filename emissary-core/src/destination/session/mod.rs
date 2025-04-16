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

//! ECIES-X25519-AEAD-Ratchet implementation.
//!
//! https://geti2p.net/spec/ecies

use crate::{
    crypto::{StaticPrivateKey, StaticPublicKey},
    destination::session::{
        context::KeyContext,
        session::{PendingSession, PendingSessionEvent, Session},
    },
    error::SessionError,
    i2np::{
        database::store::{
            DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload,
        },
        garlic::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicClove, GarlicMessage,
            GarlicMessageBlock, GarlicMessageBuilder, OwnedDeliveryInstructions,
        },
        Message, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{DestinationId, MessageId},
    runtime::{Instant, JoinSet, Runtime},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{FutureExt, Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

mod context;
mod inbound;
mod outbound;
mod session;
mod tag_set;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session";

/// Number of garlic tags to generate.
const NUM_TAGS_TO_GENERATE: usize = 4096;

/// Number of tag set entries consumed per key before a DH ratchet is performed.
const SESSION_DH_RATCHET_THRESHOLD: usize = 20_000usize;

/// How long is upper-layer protocol data awaited before a [`DatabaseStore`] message is sent to
/// remote to update remote destination's `NetDb` with our new lease set.
const LEASE_SET_PUBLISH_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// ES send tag set timeout.
///
/// If no messages has been sent within the last 8 minutes, the send tag set is considered inactive.
///
/// If the receive tag set is also considered inactive, the active session is removed
const ES_SEND_TAGSET_TIMEOUT: Duration = Duration::from_secs(8 * 60);

/// ES receive tag set timeout.
///
/// If no messages has been received within the last 10 minutes, the receive tag set is considered
/// inactive.
///
/// If the send tag set is also considered inactive, the active session is removed
const ES_RECEIVE_TAGSET_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Session manager maintenance interval.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// Interval to respond to ACK and NextKey requests if no other traffic is transmitted
// TODO: NS and NSR messages should have a "HIGH_PRIORITY_RESPONSE_INTERVAL" with a shorter
// interval to respond within. ref: https://geti2p.net/spec/ecies#protocol-layer-responses
const LOW_PRIORITY_RESPONSE_INTERVAL: Duration = Duration::from_secs(1);

/// Active session with remote destination.
struct ActiveSession<R: Runtime> {
    /// Pending ACK requests received from remote.
    inbound_ack_requests: HashSet<(u16, u16)>,

    /// Time when the last ES was received.
    last_received: R::Instant,

    /// Time when the last ES was sent.
    last_sent: R::Instant,

    /// Lease set that must be sent to remote, if any.
    lease_set: Option<Bytes>,

    /// Pending ACK requests sent by us.
    outbound_ack_requests: HashSet<(u16, u16)>,

    /// Session.
    session: Session<R>,
}

impl<R: Runtime> ActiveSession<R> {
    pub fn new(session: Session<R>) -> Self {
        Self {
            inbound_ack_requests: HashSet::new(),
            last_received: R::now(),
            last_sent: R::now(),
            lease_set: None,
            outbound_ack_requests: HashSet::new(),
            session,
        }
    }

    /// Insert new outbound ACK request for (`tag_set_id`, `tag_index`) tuple.
    pub fn insert_outbound_ack_request(&mut self, tag_set_id: u16, tag_index: u16) {
        self.outbound_ack_requests.insert((tag_set_id, tag_index));
    }
}

/// Events emitted by the [`SessionManager`].
pub enum SessionManagerEvent {
    /// Send scheduled message to remote destination.
    ///
    /// This event is emitted only if [`SessionManager`] needs to transmit information to remote
    /// destination and there has been no upper-level protocol activity to use for bundling that
    /// information.
    SendMessage {
        /// ID of the remote destination.
        destination_id: DestinationId,

        /// Serialized garlic message.
        message: Vec<u8>,
    },

    /// Session has been terminated, either forcibly due to a protocol error or because it was
    /// requested by either the local or remote destination.
    SessionTerminated {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },
}

/// Session manager for a `Destination`.
///
/// Handles both inbound and outbound sessions.
pub struct SessionManager<R: Runtime> {
    /// Active sessions.
    active: HashMap<DestinationId, ActiveSession<R>>,

    /// Destination ID.
    destination_id: DestinationId,

    /// Mapping from garlic tags to session keys.
    garlic_tags: Arc<RwLock<HashMap<u64, DestinationId>>>,

    /// Key context.
    key_context: KeyContext<R>,

    /// Currently active, serialized `LeaseSet2` of the local destination.
    lease_set: Bytes,

    /// Lease set publish timers.
    ///
    /// TODO: more documentain
    lease_set_publish_timers: R::JoinSet<DestinationId>,

    /// Response timers to handle protocol layer responses if there is no
    /// other message traffic
    protocol_response_timers: R::JoinSet<DestinationId>,

    /// Maintenance timer.
    maintenance_timer: R::Timer,

    /// Pending sessions.
    pending: HashMap<DestinationId, PendingSession<R>>,

    /// Pending events.
    pending_events: VecDeque<SessionManagerEvent>,

    /// Known remote destinations and their public keys.
    remote_destinations: HashMap<DestinationId, StaticPublicKey>,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    pub fn new(
        destination_id: DestinationId,
        private_key: StaticPrivateKey,
        lease_set: Bytes,
    ) -> Self {
        Self {
            active: HashMap::new(),
            destination_id,
            garlic_tags: Default::default(),
            key_context: KeyContext::from_private_key(private_key),
            lease_set,
            lease_set_publish_timers: R::join_set(),
            protocol_response_timers: R::join_set(),
            maintenance_timer: R::timer(MAINTENANCE_INTERVAL),
            pending_events: VecDeque::new(),
            pending: HashMap::new(),
            remote_destinations: HashMap::new(),
            waker: None,
        }
    }

    /// Set new `LeaseSet2` for the local destination.
    ///
    /// The lease set is also set as pending for all active session and a [`DatabaseStore`] will be
    /// sent to remote destinations until they acknowledge it.
    ///
    /// A timer is also started for each session and if no upper-level protocol activity happens for
    /// [`LEASE_SET_PUBLISH_WAIT_TIMEOUT`], meaning `lease_set` cannot be bundled with that data,
    /// the [`DatabaseStore`] is sent separately.
    pub fn register_lease_set(&mut self, lease_set: Bytes) {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            num_session = ?self.active.len(),
            "local lease set updated"
        );

        self.lease_set = lease_set.clone();
        self.active.iter_mut().for_each(|(destination_id, session)| {
            session.lease_set = Some(lease_set.clone());

            let destination_id = destination_id.clone();
            self.lease_set_publish_timers.push(async move {
                R::delay(LEASE_SET_PUBLISH_WAIT_TIMEOUT).await;

                destination_id
            });
        });

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Add remote destination to [`SessionManager`].
    ///
    /// Public key of the remote destination is fetched from its `LeaseSet2`.
    ///
    /// Calling `SessionManager::encrypt()` presupposes that the public key of remote destination
    /// has been added to [`SessionManager`], otherwise the call will fail.
    pub fn add_remote_destination(
        &mut self,
        destination_id: DestinationId,
        public_key: StaticPublicKey,
    ) {
        self.remote_destinations.insert(destination_id, public_key);
    }

    /// Remove session for `destination_id` from active sessions.
    fn remove_session(&mut self, destination_id: &DestinationId) {
        tracing::debug!(
            target: LOG_TARGET,
            ?destination_id,
            "remove active session",
        );

        if let Some(session) = self.active.remove(destination_id) {
            session.session.destroy();

            self.pending_events.push_back(SessionManagerEvent::SessionTerminated {
                destination_id: destination_id.clone(),
            });
        }
    }

    /// Creates an empty garlic message if there are inbound ACK requests.
    fn explicit_protocol_response_message(
        &mut self,
        destination_id: &DestinationId,
    ) -> Option<Vec<u8>> {
        let session = self.active.get_mut(destination_id)?;

        // explicit protool response messages sent only if there are pending ack requests
        if session.inbound_ack_requests.is_empty() {
            return None;
        }

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            "send explicit protocol response message",
        );

        let builder = GarlicMessageBuilder::default();

        session
            .session
            .encrypt(builder)
            .map(|(_tag_set_id, _tag_index, message)| {
                let mut out = BytesMut::with_capacity(message.len() + 4);

                out.put_u32(message.len() as u32);
                out.put_slice(&message);
                out.freeze().to_vec()
            })
            .ok()
    }

    /// Attempt to publish local lease set to remote destination.
    fn publish_local_lease_set(&mut self, destination_id: &DestinationId) -> Option<Vec<u8>> {
        let session = self.active.get_mut(destination_id)?;

        // explicity database store needs to be sent only if there are no acks pending
        if !session.outbound_ack_requests.is_empty() || session.lease_set.is_none() {
            return None;
        }

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            "send explicit database store for local lease set",
        );

        let database_store = DatabaseStoreBuilder::new(
            Bytes::from(self.destination_id.to_vec()),
            DatabaseStoreKind::LeaseSet2 {
                lease_set: self.lease_set.clone(),
            },
        )
        .build();

        let builder = GarlicMessageBuilder::default()
            .with_garlic_clove(
                MessageType::DatabaseStore,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                GarlicDeliveryInstructions::Local,
                &database_store,
            )
            .with_ack_request();

        // save the `(tag_set_id, tag_index)` into `ActiveSession` so that inbound
        // ack can be associated with an ack request sent in this message
        session
            .session
            .encrypt(builder)
            .map(|(tag_set_id, tag_index, message)| {
                session.insert_outbound_ack_request(tag_set_id, tag_index);

                let mut out = BytesMut::with_capacity(message.len() + 4);

                out.put_u32(message.len() as u32);
                out.put_slice(&message);
                out.freeze().to_vec()
            })
            .ok()
    }

    /// Encrypt `message` destined to `destination_id`.
    ///
    /// Caller must ensure that `message` is a serialized I2CP payload ([`GzipPayload`]).
    ///
    /// [`SessionManager::encrypt()`] wraps `message` in I2NP Data [1] payload and wraps that in a
    /// garlic clove which then gets encrypted into a `NewSession`, `NewSessionReply` or
    /// `ExistingSession` message, based on the session's state.
    ///
    /// [1]: https://geti2p.net/spec/i2np#data
    pub fn encrypt(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        match self.active.get_mut(destination_id) {
            Some(session) => {
                // TODO: ugly
                let hash = destination_id.to_vec();
                let message = {
                    let mut out = BytesMut::with_capacity(message.len() + 4);

                    out.put_u32(message.len() as u32);
                    out.put_slice(&message);
                    out
                };
                let mut builder = GarlicMessageBuilder::default().with_garlic_clove(
                    MessageType::Data,
                    MessageId::from(R::rng().next_u32()),
                    R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    GarlicDeliveryInstructions::Destination { hash: &hash },
                    &message,
                );

                // send acks for all inbound ack requests
                if !session.inbound_ack_requests.is_empty() {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        remote = %destination_id,
                        acks = ?session.inbound_ack_requests,
                        "add pending acks",
                    );

                    let acks = mem::replace(&mut session.inbound_ack_requests, HashSet::new());
                    builder = builder.with_ack(acks.into_iter().collect());
                }

                match &session.lease_set {
                    None => session
                        .session
                        .encrypt(builder)
                        .map(|(_, _, message)| {
                            let mut out = BytesMut::with_capacity(message.len() + 4);

                            out.put_u32(message.len() as u32);
                            out.put_slice(&message);
                            out.freeze().to_vec()
                        })
                        .map_err(|error| {
                            if let SessionError::SessionTerminated = error {
                                self.remove_session(destination_id);
                            }

                            error
                        }),
                    Some(lease_set) => {
                        let database_store = DatabaseStoreBuilder::new(
                            Bytes::from(self.destination_id.to_vec()),
                            DatabaseStoreKind::LeaseSet2 {
                                lease_set: lease_set.clone(),
                            },
                        )
                        .build();

                        let builder = builder
                            .with_garlic_clove(
                                MessageType::DatabaseStore,
                                MessageId::from(R::rng().next_u32()),
                                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                                GarlicDeliveryInstructions::Local,
                                &database_store,
                            )
                            .with_ack_request();

                        // save the `(tag_set_id, tag_index)` into `ActiveSession` so that inbound
                        // ack can be associated with an ack request sent in this message
                        session
                            .session
                            .encrypt(builder)
                            .map(|(tag_set_id, tag_index, message)| {
                                session.insert_outbound_ack_request(tag_set_id, tag_index);
                                session.last_sent = R::now();

                                let mut out = BytesMut::with_capacity(message.len() + 4);

                                out.put_u32(message.len() as u32);
                                out.put_slice(&message);
                                out.freeze().to_vec()
                            })
                            .map_err(|error| {
                                if let SessionError::SessionTerminated = error {
                                    self.remove_session(destination_id);
                                }

                                error
                            })
                    }
                }
            }
            // no active session for `destination_id`, check if pending session exists
            None => match self.pending.get_mut(destination_id) {
                Some(session) => {
                    match session.advance_outbound(self.lease_set.clone(), message)? {
                        PendingSessionEvent::SendMessage { message } => Ok({
                            let mut out = BytesMut::with_capacity(message.len() + 4);

                            out.put_u32(message.len() as u32);
                            out.put_slice(&message);
                            out.freeze().to_vec()
                        }),
                        PendingSessionEvent::CreateSession {
                            message, context, ..
                        } => {
                            tracing::info!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "new session started",
                            );

                            self.pending.remove(destination_id);
                            self.active.insert(
                                destination_id.clone(),
                                ActiveSession::new(Session::new(context)),
                            );

                            let mut out = BytesMut::with_capacity(message.len() + 4);

                            out.put_u32(message.len() as u32);
                            out.put_slice(&message);
                            Ok(out.freeze().to_vec())
                        }
                        PendingSessionEvent::ReturnMessage { .. } => unreachable!(),
                    }
                }
                // no pending nor active session for `destination_id`, create new outbound session
                None => {
                    // public key of the destination should exist since the caller (`Destination`)
                    // should've queried the lease set of the remote destination when sending the
                    // first message to them
                    let public_key =
                        self.remote_destinations.get(destination_id).ok_or_else(|| {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "public key for remote destination doesn't exist",
                            );

                            debug_assert!(false);
                            SessionError::InvalidState
                        })?;

                    // wrap the garlic message inside a `NewSession` message
                    // and create a pending outbound session
                    let (session, payload) = self.key_context.create_outbound_session(
                        self.destination_id.clone(),
                        destination_id.clone(),
                        public_key,
                        self.lease_set.clone(),
                        &message,
                    );

                    self.pending.insert(
                        destination_id.clone(),
                        PendingSession::new_outbound(
                            self.destination_id.clone(),
                            destination_id.clone(),
                            public_key.clone(),
                            session,
                            Arc::clone(&self.garlic_tags),
                            self.key_context.clone(),
                        ),
                    );

                    Ok({
                        let mut out = BytesMut::with_capacity(payload.len() + 4);

                        out.put_u32(payload.len() as u32);
                        out.put_slice(&payload);
                        out.freeze().to_vec()
                    })
                }
            },
        }
    }

    /// Decrypt `message`.
    ///
    /// `message` could be one of three types of messages:
    ///  * `NewSession` - session request from a remote destination
    ///  * `NewSessionReply` - reply for a session request initiated by us
    ///  * `ExistingSession` - message belonging to an existing session
    ///
    /// All messages kinds can be received from any remote destination, the only common factor
    /// between them is that the recipient is `Destination` this `SessionManager` is bound to.
    ///
    /// [`SessionManager::decrypt()`] assumes that the caller has validated `message` to be a garlic
    /// message of appropriate length, containing at least the message length and a garlic tag.
    ///
    /// On success, returns a serialized garlic clove set.
    pub fn decrypt(
        &mut self,
        message: Message,
    ) -> Result<impl Iterator<Item = GarlicClove>, SessionError> {
        // extract garlic tag and attempt to find session key for the tag
        //
        // if no key is found, `message` is assumed to be `NewSession`
        let garlic_tag = GarlicMessage::garlic_tag(&message);
        let session = { self.garlic_tags.write().remove(&garlic_tag) };

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            message_id = ?message.message_id,
            ?garlic_tag,
            "garlic message",
        );

        let (tag_set_id, tag_index, destination_id, payload) = match session {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?garlic_tag,
                    "session key not found, assume new session",
                );

                // parse `NewSession` and attempt to create an inbound session
                //
                // the returned session is either a bound or an unbound inbound session
                //
                // if it's a bound session, the parsed garlic clove set must include a `LeaseSet2`
                // so a reply can be sent to the remote destination and if `LeaseSet2` is not
                // bundled, the inbound session is rejected
                let (session, payload) =
                    self.key_context.create_inbound_session(message.payload)?;

                // attempt to parse `payload` into clove set
                let clove_set = GarlicMessage::parse(&payload).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        id = %self.destination_id,
                        "failed to parse NS payload into a clove set",
                    );

                    SessionError::Malformed
                })?;

                // TODO: verify `DateTime`

                // locate `DatabaseStore` i2np message from the clove set
                let Some(GarlicMessageBlock::GarlicClove { message_body, .. }) =
                    clove_set.blocks.iter().find(|clove| {
                        core::matches!(
                            clove,
                            GarlicMessageBlock::GarlicClove {
                                message_type: MessageType::DatabaseStore,
                                ..
                            }
                        )
                    })
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        id = %self.destination_id,
                        "clove set doesn't contain `DatabaseStore`, cannot reply",
                    );

                    return Err(SessionError::Malformed);
                };

                // attempt to parse the `DatabaseStore` as `LeaseSet2`
                let Some(DatabaseStore {
                    key,
                    payload: DatabaseStorePayload::LeaseSet2 { lease_set },
                    ..
                }) = DatabaseStore::<R>::parse(message_body)
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        id = %self.destination_id,
                        "`DatabaseStore` is not a valid `LeaseSet2` store, cannot reply",
                    );

                    return Err(SessionError::Malformed);
                };
                let destination_id = lease_set.header.destination.id();
                let key = DestinationId::from(key);

                if key != destination_id {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?destination_id,
                        ?key,
                        "key/lease set id mismatch for database store",
                    );
                    return Err(SessionError::InvalidKey);
                }

                match self.pending.get_mut(&destination_id) {
                    None => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            "inbound session created",
                        );

                        self.pending.insert(
                            destination_id.clone(),
                            PendingSession::new_inbound(
                                self.destination_id.clone(),
                                destination_id.clone(),
                                session,
                                Arc::clone(&self.garlic_tags),
                                self.key_context.clone(),
                            ),
                        );
                    }
                    Some(_) => tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        remote = %destination_id,
                        "inbound session already exists",
                    ),
                }

                // this is the first message of the session so both tag set id and tag index are 0
                (0u16, 0u16, destination_id, payload)
            }
            Some(destination_id) => match self.active.get_mut(&destination_id) {
                Some(session) => session
                    .session
                    .decrypt(garlic_tag, message.payload)
                    .map(|(tag_set_id, tag_index, message)| {
                        session.last_received = R::now();

                        (tag_set_id, tag_index, destination_id.clone(), message)
                    })
                    .map_err(|error| match error {
                        SessionError::SessionTerminated => {
                            self.remove_session(&destination_id);
                            SessionError::SessionTerminated
                        }
                        error => error,
                    })?,
                None => match self.pending.get_mut(&destination_id) {
                    Some(session) => match session.advance_inbound(garlic_tag, message.payload)? {
                        PendingSessionEvent::SendMessage { .. } => unreachable!(),
                        PendingSessionEvent::CreateSession {
                            message,
                            context,
                            tag_set_id,
                            tag_index,
                        } => {
                            tracing::info!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "new session started",
                            );

                            self.pending.remove(&destination_id);
                            self.active.insert(
                                destination_id.clone(),
                                ActiveSession::new(Session::new(context)),
                            );

                            (tag_set_id, tag_index, destination_id, message)
                        }
                        PendingSessionEvent::ReturnMessage {
                            tag_set_id,
                            tag_index,
                            message,
                        } => (tag_set_id, tag_index, destination_id, message),
                    },
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            ?garlic_tag,
                            "destination for garlic tag doesn't exist",
                        );
                        debug_assert!(false);
                        return Err(SessionError::InvalidState);
                    }
                },
            },
        };

        // parse garlic cloves from the decrypted messages and return them to the caller
        //
        // TODO: optimize, ideally this should return references
        let cloves = GarlicMessage::parse(&payload)
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    id = %self.destination_id,
                    "failed to parse NS payload into a clove set",
                );

                SessionError::Malformed
            })?
            .blocks
            .into_iter()
            .filter_map(|block| match block {
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => Some(GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions: OwnedDeliveryInstructions::from(&delivery_instructions),
                    message_body: message_body.to_vec(),
                }),
                GarlicMessageBlock::AckRequest => match self.active.get_mut(&destination_id) {
                    Some(session) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            ?tag_set_id,
                            ?tag_index,
                            "ack request received",
                        );
                        session.inbound_ack_requests.insert((tag_set_id, tag_index));

                        let destination_id = destination_id.clone();
                        self.protocol_response_timers.push(async move {
                            R::delay(LOW_PRIORITY_RESPONSE_INTERVAL).await;

                            destination_id
                        });
                        None
                    }
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            "ack request for non-active session",
                        );
                        debug_assert!(false);
                        None
                    }
                },
                GarlicMessageBlock::Ack { acks } => match self.active.get_mut(&destination_id) {
                    Some(session) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            ?acks,
                            "ack received",
                        );

                        // check if if an ack for an outbound ack request was received
                        //
                        // if so, the lease set can be reset from the session's context
                        if acks
                            .into_iter()
                            .filter(|(tag_set_id, tag_index)| {
                                session.outbound_ack_requests.remove(&(*tag_set_id, *tag_index))
                            })
                            .count()
                            > 0
                        {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "local lease set store acked",
                            );
                            session.lease_set = None;
                        }

                        None
                    }
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            "ack request for non-active session",
                        );
                        debug_assert!(false);
                        None
                    }
                },
                msg_type => {
                    tracing::trace!(
                        local = %self.destination_id,
                        remote = %destination_id,
                        ?msg_type,
                        "unhandled message type",
                    );
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(cloves.into_iter())
    }

    /// Perform periodic maintenance of active and pending sessions.
    ///
    /// Removes all pending sessions that have expired and all active sessions which haven't had
    /// activity within the last 10 minutes, and calls `Session::maintain()` for each active session
    /// which removes expired tags of the active session.
    fn maintain(&mut self) {
        self.pending
            .iter()
            .filter_map(|(key, session)| session.is_expired().then_some(key.clone()))
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|remote| {
                tracing::info!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    %remote,
                    "purging expired pending session",
                );
                self.pending.remove(&remote);
            });

        self.active
            .iter()
            .filter_map(|(destination_id, session)| {
                (session.last_received.elapsed() > ES_RECEIVE_TAGSET_TIMEOUT
                    && session.last_sent.elapsed() > ES_SEND_TAGSET_TIMEOUT)
                    .then_some(destination_id.clone())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|remote| {
                tracing::info!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    %remote,
                    "removing inactive session",
                );

                // session must exist since it was deemed inactive
                self.active.remove(&remote).expect("to exist").session.destroy();
            });

        self.active.values_mut().for_each(|session| session.session.maintain());
    }
}

impl<R: Runtime> Stream for SessionManager<R> {
    type Item = SessionManagerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(Some(event));
        }

        loop {
            match self.lease_set_publish_timers.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(destination_id)) => {
                    match self.publish_local_lease_set(&destination_id) {
                        None => continue,
                        Some(message) =>
                            return Poll::Ready(Some(SessionManagerEvent::SendMessage {
                                destination_id,
                                message,
                            })),
                    }
                }
            }
        }

        loop {
            match self.protocol_response_timers.poll_next_unpin(cx) {
                Poll::Pending | Poll::Ready(None) => break,
                Poll::Ready(Some(destination_id)) => {
                    match self.explicit_protocol_response_message(&destination_id) {
                        None => continue,
                        Some(message) =>
                            return Poll::Ready(Some(SessionManagerEvent::SendMessage {
                                destination_id,
                                message,
                            })),
                    }
                }
            }
        }

        if self.maintenance_timer.poll_unpin(cx).is_ready() {
            self.maintain();

            // create new timer and poll it so it'll get registered into the executor
            self.maintenance_timer = R::timer(MAINTENANCE_INTERVAL);
            let _ = self.maintenance_timer.poll_unpin(cx);
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{Lease, LeaseSet2, LeaseSet2Header, RouterId, TunnelId},
        runtime::mock::MockRuntime,
    };
    use core::time::Duration;
    use rand::thread_rng;

    /// Decrypt `message` using `session` and verify the inbound `Data` message
    /// inside the garlic message matches `diff`
    macro_rules! decrypt_and_verify {
        ($session:expr, $message:expr, $diff:expr) => {
            let mut message = $session
                .decrypt(Message {
                    payload: $message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], $diff);
        };
    }

    #[tokio::test]
    async fn new_inbound_session() {
        let private_key = StaticPrivateKey::random(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::random();
        let (leaseset, signing_key) = LeaseSet2::random();
        let leaseset = Bytes::from(leaseset.serialize(&signing_key));
        let mut session =
            SessionManager::<MockRuntime>::new(destination_id.clone(), private_key, leaseset);

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(destination_id.clone(), public_key);
        let message = outbound_session.encrypt(&destination_id, vec![1, 2, 3, 4]).unwrap();

        let mut cloves = session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        // verify message is valid
        {
            let Some(GarlicClove { message_body, .. }) =
                cloves.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        // verify pending inbound session exists for the destination
        assert!(session.pending.contains_key(&outbound_destination_id));
        let message = Message {
            payload: session.encrypt(&outbound_destination_id, vec![1, 2, 3, 4]).unwrap(),
            ..Default::default()
        };

        {
            let mut message = outbound_session.decrypt(message).unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        let message = {
            let message = outbound_session.encrypt(&destination_id, vec![5, 6, 7, 8]).unwrap();

            Message {
                payload: message,
                ..Default::default()
            }
        };

        assert_eq!(
            session
                .decrypt(message)
                .unwrap()
                .find(|clove| std::matches!(clove.message_type, MessageType::Data))
                .unwrap()
                .message_body,
            [0, 0, 0, 4, 5, 6, 7, 8]
        );

        assert!(session.active.contains_key(&outbound_destination_id));
        assert!(outbound_session.active.contains_key(&destination_id));
    }

    #[tokio::test]
    async fn messages_out_of_order() {
        let private_key = StaticPrivateKey::random(thread_rng());
        let public_key = private_key.public();
        let destination_id = DestinationId::random();
        let (leaseset, signing_key) = LeaseSet2::random();
        let leaseset = Bytes::from(leaseset.serialize(&signing_key));
        let mut session =
            SessionManager::<MockRuntime>::new(destination_id.clone(), private_key, leaseset);

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(destination_id.clone(), public_key);
        let message = outbound_session.encrypt(&destination_id, vec![1, 2, 3, 4]).unwrap();

        let mut payload = session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        // verify message is valid
        {
            let Some(GarlicClove { message_body, .. }) =
                payload.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);
        }

        // verify pending inbound session exists for the destination
        assert!(session.pending.contains_key(&outbound_destination_id));

        let message = Message {
            payload: session.encrypt(&outbound_destination_id, vec![1, 2, 3, 4]).unwrap(),
            ..Default::default()
        };

        let mut message = outbound_session.decrypt(message).unwrap();
        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

        let message = {
            let message = outbound_session.encrypt(&destination_id, vec![5, 6, 7, 8]).unwrap();

            Message {
                payload: message,
                ..Default::default()
            }
        };

        // verify pending inbound session still exists for the destination
        assert!(session.pending.contains_key(&outbound_destination_id));

        // verify message is valid
        {
            let mut message = session.decrypt(message).unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // verify that the inbound session is now considered active
        assert!(session.active.contains_key(&outbound_destination_id));
        assert!(session.pending.is_empty());

        // generate three messages and send them in reverse order
        let messages = (0..3)
            .map(|i| {
                let message = outbound_session.encrypt(&destination_id, vec![i as u8; 4]).unwrap();

                Message {
                    payload: message,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        messages.into_iter().enumerate().rev().for_each(|(i, message)| {
            let mut message = session.decrypt(message).unwrap();
            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };

            assert_eq!(&message_body[4..], &vec![i as u8; 4]);
        });

        // send message from the inbound session
        let message = Message {
            payload: session.encrypt(&outbound_destination_id, vec![1, 3, 3, 7]).unwrap(),
            ..Default::default()
        };

        let mut message = outbound_session.decrypt(message).unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 3, 3, 7]);
    }

    #[tokio::test]
    async fn new_outbound_session() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create `NewSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 3, 3, 7]);

        // finalize inbound session by sending an `ExistingSession` message
        let message = inbound_session.encrypt(&outbound_destination_id, vec![1, 3, 3, 8]).unwrap();

        // handle `ExistingSession` message
        let mut message = outbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(&message_body[4..], &vec![1, 3, 3, 8]);
    }

    #[tokio::test]
    async fn two_simultaneous_inbound_sessions() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create first outbound `SessionManager`
        let outbound1_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound1_leaseset, outbound1_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound1_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound1_destination_id,
            )
        };
        let mut outbound1_session = SessionManager::<MockRuntime>::new(
            outbound1_destination_id.clone(),
            outbound1_private_key,
            outbound1_leaseset,
        );
        outbound1_session
            .add_remote_destination(inbound_destination_id.clone(), inbound_public_key.clone());

        // create second outbound `SessionManager`
        let outbound2_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound2_leaseset, outbound2_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound2_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound2_destination_id,
            )
        };
        let mut outbound2_session = SessionManager::<MockRuntime>::new(
            outbound2_destination_id.clone(),
            outbound2_private_key,
            outbound2_leaseset,
        );
        outbound2_session
            .add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize first outbound session and create `NewSession` message
        let message = outbound1_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let outbound1_nsr = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound1_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // initialize second outbound session and create `NewSession` message
        let message = outbound2_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let outbound2_nsr = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound2_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound for the first session
        {
            let mut message = outbound1_session
                .decrypt(Message {
                    payload: outbound1_nsr,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // handle `NewSessionReply` and finalize outbound for the first session
        {
            let mut message = outbound2_session
                .decrypt(Message {
                    payload: outbound2_nsr,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(&message_body[4..], &vec![5, 6, 7, 8]);
        }

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound1_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // // send `ExistingSession` from inbound session
        // finalize inbound session by sending an `ExistingSession` message
        let message = inbound_session.encrypt(&outbound1_destination_id, vec![1, 3, 3, 8]).unwrap();

        // handle `ExistingSession` message
        let mut message = outbound1_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 8]);

        // verify there's one pending inbound session
        assert_eq!(inbound_session.active.len(), 1);
        assert_eq!(inbound_session.pending.len(), 1);
        assert_eq!(outbound1_session.active.len(), 1);
        assert_eq!(outbound1_session.pending.len(), 0);
        assert_eq!(outbound2_session.active.len(), 0);
        assert_eq!(outbound2_session.pending.len(), 1);

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound2_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // send `ExistingSession` from inbound session
        // finalize inbound session by sending an `ExistingSession` message
        let message = inbound_session.encrypt(&outbound2_destination_id, vec![1, 3, 3, 9]).unwrap();

        // handle `ExistingSession` message
        let mut message = outbound2_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 9]);

        // verify there's one pending inbound session
        assert_eq!(inbound_session.active.len(), 2);
        assert_eq!(inbound_session.pending.len(), 0);
        assert_eq!(outbound1_session.active.len(), 1);
        assert_eq!(outbound1_session.pending.len(), 0);
        assert_eq!(outbound2_session.active.len(), 1);
        assert_eq!(outbound2_session.pending.len(), 0);
    }

    #[tokio::test]
    async fn two_simultaneous_outbound_sessions() {
        // create first inbound `SessionManager`
        let inbound1_private_key = StaticPrivateKey::random(thread_rng());
        let inbound1_public_key = inbound1_private_key.public();
        let (inbound1_leaseset, inbound1_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound1_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound1_destination_id,
            )
        };
        let mut inbound1_session = SessionManager::<MockRuntime>::new(
            inbound1_destination_id.clone(),
            inbound1_private_key,
            inbound1_leaseset,
        );

        // create second inbound `SessionManager`
        let inbound2_private_key = StaticPrivateKey::random(thread_rng());
        let inbound2_public_key = inbound2_private_key.public();
        let (inbound2_leaseset, inbound2_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound2_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound2_destination_id,
            )
        };
        let mut inbound2_session = SessionManager::<MockRuntime>::new(
            inbound2_destination_id.clone(),
            inbound2_private_key,
            inbound2_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session
            .add_remote_destination(inbound1_destination_id.clone(), inbound1_public_key);
        outbound_session
            .add_remote_destination(inbound2_destination_id.clone(), inbound2_public_key);

        // initialize first outbound session and create `NewSession` message
        let ns1 = outbound_session.encrypt(&inbound1_destination_id, vec![1, 1, 1, 1]).unwrap();

        // initialize second outbound session and create `NewSession` message
        let ns2 = outbound_session.encrypt(&inbound2_destination_id, vec![2, 2, 2, 2]).unwrap();

        // handle `NewSession` message, initialize the first inbound session
        // and create `NewSessionReply` message
        let nsr1 = {
            let mut message = inbound1_session
                .decrypt(Message {
                    payload: ns1,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 1, 1, 1]);

            // create response to `NewSession`
            inbound1_session.encrypt(&outbound_destination_id, vec![3, 3, 3, 3]).unwrap()
        };

        // handle `NewSession` message, initialize the first inbound session
        // and create `NewSessionReply` message
        let nsr2 = {
            let mut message = inbound2_session
                .decrypt(Message {
                    payload: ns2,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [2, 2, 2, 2]);

            // create response to `NewSession`
            inbound2_session.encrypt(&outbound_destination_id, vec![4, 4, 4, 4]).unwrap()
        };

        // handle `NewSessionReply` from first inbound session and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: nsr1,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [3, 3, 3, 3]);
        }

        // handle `NewSessionReply` from second session and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: nsr2,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [4, 4, 4, 4]);
        }

        assert_eq!(inbound1_session.active.len(), 0);
        assert_eq!(inbound1_session.pending.len(), 1);
        assert_eq!(inbound2_session.active.len(), 0);
        assert_eq!(inbound2_session.pending.len(), 1);
        assert_eq!(outbound_session.active.len(), 0);
        assert_eq!(outbound_session.pending.len(), 2);

        // finalize first inbound session by sending an `ExistingSession` message
        let es1 = outbound_session.encrypt(&inbound1_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound1_session
            .decrypt(Message {
                payload: es1,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        assert_eq!(inbound1_session.active.len(), 1);
        assert_eq!(inbound1_session.pending.len(), 0);
        assert_eq!(inbound2_session.active.len(), 0);
        assert_eq!(inbound2_session.pending.len(), 1);
        assert_eq!(outbound_session.active.len(), 1);
        assert_eq!(outbound_session.pending.len(), 1);

        // finalize second inbound session by sending an `ExistingSession` message
        let es2 = outbound_session.encrypt(&inbound2_destination_id, vec![1, 3, 3, 8]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound2_session
            .decrypt(Message {
                payload: es2,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 8]);

        assert_eq!(inbound1_session.active.len(), 1);
        assert_eq!(inbound1_session.pending.len(), 0);
        assert_eq!(inbound2_session.active.len(), 1);
        assert_eq!(inbound2_session.pending.len(), 0);
        assert_eq!(outbound_session.active.len(), 2);
        assert_eq!(outbound_session.pending.len(), 0);
    }

    #[tokio::test]
    async fn tags_are_autogenerated() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create `NewSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        }

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // send twice as many messages as there were initial tags
        // and verify that all messages are decrypted correctly
        for i in 0..NUM_TAGS_TO_GENERATE * 2 {
            // send `ExistingSession` from inbound session
            // finalize inbound session by sending an `ExistingSession` message
            let message =
                inbound_session.encrypt(&outbound_destination_id, vec![i as u8; 4]).unwrap();

            // handle `ExistingSession` message
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [i as u8; 4]);
        }
    }

    #[tokio::test]
    async fn dh_ratchet() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (outbound_leaseset, outbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key,
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create `NewSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        }

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // run the dh ratchet five times to exercise all state transitions
        for _ in 0..5 {
            // send twice as many messages as there were initial tags
            // and verify that all messages are decrypted correctly
            let mut responded_to_nextkey = false;

            for i in 0..SESSION_DH_RATCHET_THRESHOLD + 5 {
                // send `ExistingSession` from inbound session
                // finalize inbound session by sending an `ExistingSession` message
                let message =
                    inbound_session.encrypt(&outbound_destination_id, vec![i as u8; 4]).unwrap();

                // handle `ExistingSession` message
                let mut message = outbound_session
                    .decrypt(Message {
                        payload: message,
                        ..Default::default()
                    })
                    .unwrap();

                let Some(GarlicClove { message_body, .. }) =
                    message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
                else {
                    panic!("message not found");
                };
                assert_eq!(message_body[4..], [i as u8; 4]);

                if i > SESSION_DH_RATCHET_THRESHOLD && !responded_to_nextkey {
                    let message =
                        outbound_session.encrypt(&inbound_destination_id, vec![4]).unwrap();

                    let _message = inbound_session
                        .decrypt(Message {
                            payload: message,
                            ..Default::default()
                        })
                        .unwrap();

                    responded_to_nextkey = true;
                }
            }
        }
    }

    #[tokio::test]
    async fn local_lease_set_bundled_with_data() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            outbound_destination,
            outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create `NewSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        }

        // send random data over the active session
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // verify that there are no pending lease set publishes
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_none());
        assert_eq!(outbound_session.lease_set_publish_timers.len(), 0);

        // create new lease set for `outbound_session`
        let gateway_router = RouterId::random();
        let gateway_tunnel = TunnelId::random();

        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: outbound_destination.clone(),
                    expires: (MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60))
                        .as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![outbound_private_key.public()],
                leases: vec![Lease {
                    router_id: gateway_router.clone(),
                    tunnel_id: gateway_tunnel,
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                }],
            }
            .serialize(&outbound_signing_key),
        );
        outbound_session.register_lease_set(lease_set);

        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_some());
        assert_eq!(outbound_session.lease_set_publish_timers.len(), 1);

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![4, 4, 4, 4]).unwrap();

        // verify there is an outbound ack request for `outbound_session`
        assert!(!outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .outbound_ack_requests
            .is_empty());

        // verify that the lease set is still active since an ack hasn't been received
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_some());

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [4, 4, 4, 4]);

        // verify there is an inbound ack request for `inbound_session`
        assert!(!inbound_session
            .active
            .get(&outbound_destination_id)
            .unwrap()
            .inbound_ack_requests
            .is_empty());

        // send random data to `outbound_session`
        let message = inbound_session.encrypt(&outbound_destination_id, vec![5, 5, 5, 5]).unwrap();

        // verify that there are no longer inbound ack requests since it was sent in `message`
        assert!(inbound_session
            .active
            .get(&outbound_destination_id)
            .unwrap()
            .inbound_ack_requests
            .is_empty());

        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 5, 5, 5]);
        }

        // verify that the lease set publish is no longer pending since an ack was received
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .outbound_ack_requests
            .is_empty());
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_none());
    }

    #[tokio::test]
    async fn local_lease_set_publish_timer_expires() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            outbound_destination,
            outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create `NewSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 2, 3, 4]).unwrap();

        // handle `NewSession` message, initialize inbound session
        // and create `NewSessionReply` message
        let message = {
            let mut message = inbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [1, 2, 3, 4]);

            // create response to `NewSession`
            inbound_session.encrypt(&outbound_destination_id, vec![5, 6, 7, 8]).unwrap()
        };

        // handle `NewSessionReply` and finalize outbound session
        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 6, 7, 8]);
        }

        // finalize inbound session by sending an `ExistingSession` message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 3, 3, 7]).unwrap();

        // handle `ExistingSession` message
        let mut message = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap();

        let Some(GarlicClove { message_body, .. }) =
            message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
        else {
            panic!("message not found");
        };
        assert_eq!(message_body[4..], [1, 3, 3, 7]);

        // verify that there are no pending lease set publishes
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_none());
        assert_eq!(outbound_session.lease_set_publish_timers.len(), 0);

        // create new lease set for `outbound_session`
        let gateway_router = RouterId::random();
        let gateway_tunnel = TunnelId::random();

        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: outbound_destination.clone(),
                    expires: (MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60))
                        .as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![outbound_private_key.public()],
                leases: vec![Lease {
                    router_id: gateway_router.clone(),
                    tunnel_id: gateway_tunnel,
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                }],
            }
            .serialize(&outbound_signing_key),
        );
        outbound_session.register_lease_set(lease_set);

        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_some());
        assert_eq!(outbound_session.lease_set_publish_timers.len(), 1);

        // wait until the publish timer times out
        let message = match tokio::time::timeout(Duration::from_secs(10), outbound_session.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SessionManagerEvent::SendMessage {
                destination_id,
                message,
            } => {
                assert_eq!(destination_id, inbound_destination_id);
                message
            }
            _ => panic!(""),
        };

        // verify there is an outbound ack request for `outbound_session`
        assert!(!outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .outbound_ack_requests
            .is_empty());

        // verify that the lease set is still active since an ack hasn't been received
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_some());

        // handle `ExistingSession` message
        let messages = inbound_session
            .decrypt(Message {
                payload: message,
                ..Default::default()
            })
            .unwrap()
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_type, MessageType::DatabaseStore);

        // verify there is an inbound ack request for `inbound_session`
        assert!(!inbound_session
            .active
            .get(&outbound_destination_id)
            .unwrap()
            .inbound_ack_requests
            .is_empty());

        // send random data to `outbound_session`
        let message = inbound_session.encrypt(&outbound_destination_id, vec![5, 5, 5, 5]).unwrap();

        // verify that there are no longer inbound ack requests since it was sent in `message`
        assert!(inbound_session
            .active
            .get(&outbound_destination_id)
            .unwrap()
            .inbound_ack_requests
            .is_empty());

        {
            let mut message = outbound_session
                .decrypt(Message {
                    payload: message,
                    ..Default::default()
                })
                .unwrap();

            let Some(GarlicClove { message_body, .. }) =
                message.find(|clove| std::matches!(clove.message_type, MessageType::Data))
            else {
                panic!("message not found");
            };
            assert_eq!(message_body[4..], [5, 5, 5, 5]);
        }

        // verify that the lease set publish is no longer pending since an ack was received
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .outbound_ack_requests
            .is_empty());
        assert!(outbound_session
            .active
            .get(&inbound_destination_id)
            .unwrap()
            .lease_set
            .is_none());
    }

    #[tokio::test]
    async fn multiple_new_session_messages() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            _outbound_destination,
            _outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create three `NewSession` messages
        let messages = [
            outbound_session.encrypt(&inbound_destination_id, vec![1, 1, 1, 1]).unwrap(),
            outbound_session.encrypt(&inbound_destination_id, vec![2, 2, 2, 2]).unwrap(),
            outbound_session.encrypt(&inbound_destination_id, vec![3, 3, 3, 3]).unwrap(),
        ];

        // process inbound messages
        for (i, payload) in messages.into_iter().enumerate() {
            decrypt_and_verify!(&mut inbound_session, payload, vec![(i + 1) as u8; 4]);
        }

        // send `NewSessionReply` to remote
        let message = inbound_session.encrypt(&outbound_destination_id, vec![4, 4, 4, 4]).unwrap();

        // handle `NewSessionReply` for the second `NewSession` message
        decrypt_and_verify!(&mut outbound_session, message, vec![4u8; 4]);

        // exchange few messages between the session to confirm they both work
        for i in 5..=10 {
            // send message from outbound to inbound
            let message =
                outbound_session.encrypt(&inbound_destination_id, vec![i as u8; 4]).unwrap();
            decrypt_and_verify!(&mut inbound_session, message, vec![i as u8; 4]);

            // send message from inbound to outbound
            let message = inbound_session
                .encrypt(&outbound_destination_id, vec![(i + 1) as u8; 4])
                .unwrap();
            decrypt_and_verify!(&mut outbound_session, message, vec![(i + 1) as u8; 4]);
        }
    }

    #[tokio::test]
    async fn multiple_new_session_reply_messages() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            _outbound_destination,
            _outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // initialize outbound session and create three NS messages
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1, 1, 1, 1]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![1u8; 4]);

        // create multiple NSR messages
        let messages = [
            inbound_session.encrypt(&outbound_destination_id, vec![2, 2, 2, 2]).unwrap(),
            inbound_session.encrypt(&outbound_destination_id, vec![3, 3, 3, 3]).unwrap(),
            inbound_session.encrypt(&outbound_destination_id, vec![4, 4, 4, 4]).unwrap(),
        ];

        // handle NSR messages
        for (i, message) in messages.into_iter().enumerate() {
            decrypt_and_verify!(&mut outbound_session, message, vec![(i + 2) as u8; 4]);
        }

        // exchange few messages between the session to confirm they both work
        for i in 5..=10 {
            // send message from outbound to inbound
            let message =
                outbound_session.encrypt(&inbound_destination_id, vec![i as u8; 4]).unwrap();
            decrypt_and_verify!(&mut inbound_session, message, vec![i as u8; 4]);

            // send message from inbound to outbound
            let message = inbound_session
                .encrypt(&outbound_destination_id, vec![(i + 1) as u8; 4])
                .unwrap();
            decrypt_and_verify!(&mut outbound_session, message, vec![(i + 1) as u8; 4]);
        }
    }

    #[tokio::test]
    async fn multiple_new_session_and_new_session_reply_messages() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            _outbound_destination,
            _outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // send multiple NS messages
        let messages = [
            outbound_session.encrypt(&inbound_destination_id, vec![1, 1, 1, 1]).unwrap(),
            outbound_session.encrypt(&inbound_destination_id, vec![2, 2, 2, 2]).unwrap(),
        ];

        // handle NS messages
        for (i, message) in messages.into_iter().enumerate() {
            decrypt_and_verify!(&mut inbound_session, message, vec![(i + 1) as u8; 4]);
        }

        // send multiple NSR messages as response to received NS messaages
        let messages = [
            inbound_session.encrypt(&outbound_destination_id, vec![3, 3, 3, 3]).unwrap(),
            inbound_session.encrypt(&outbound_destination_id, vec![4, 4, 4, 4]).unwrap(),
            inbound_session.encrypt(&outbound_destination_id, vec![5, 5, 5, 5]).unwrap(),
        ];

        // handle NSR messages
        for (i, message) in messages.into_iter().enumerate() {
            decrypt_and_verify!(&mut outbound_session, message, vec![(i + 3) as u8; 4]);
        }

        // exchange few messages between the session to confirm they both work
        for i in 5..=10 {
            // send message from outbound to inbound
            let message =
                outbound_session.encrypt(&inbound_destination_id, vec![i as u8; 4]).unwrap();
            decrypt_and_verify!(&mut inbound_session, message, vec![i as u8; 4]);

            // send message from inbound to outbound
            let message = inbound_session
                .encrypt(&outbound_destination_id, vec![(i + 1) as u8; 4])
                .unwrap();
            decrypt_and_verify!(&mut outbound_session, message, vec![(i + 1) as u8; 4]);
        }
    }

    #[tokio::test]
    async fn new_session_retried() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            _outbound_destination,
            _outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // send and handle NS message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![1u8; 4]);

        // send NSR but drop it
        let _ = inbound_session.encrypt(&outbound_destination_id, vec![2u8; 4]).unwrap();

        // send another NS because the NSR was lost
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![1u8; 4]);

        // send NSR as reply to the new NS
        let message = inbound_session.encrypt(&outbound_destination_id, vec![2u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![2u8; 4]);

        // send ES message to bob, finalizing the session
        let message = outbound_session.encrypt(&inbound_destination_id, vec![3u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![3u8; 4]);

        // send ES message to alice
        let message = inbound_session.encrypt(&outbound_destination_id, vec![5u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![5u8; 4]);
    }

    #[tokio::test]
    async fn new_session_reply_retried() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            _outbound_destination,
            _outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // send and handle NS message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![1u8; 4]);

        // send and handle NSR message
        let message = inbound_session.encrypt(&outbound_destination_id, vec![2u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![2u8; 4]);

        // send ES message which is never received by bob
        //
        // this converts the outbound session to active
        let _message = outbound_session.encrypt(&inbound_destination_id, vec![3u8; 4]).unwrap();

        // send another NSR because bob assumes it was dropped
        let message = inbound_session.encrypt(&outbound_destination_id, vec![3u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![3u8; 4]);

        // send ES message to bob, finalizing the session
        let message = outbound_session.encrypt(&inbound_destination_id, vec![4u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![4u8; 4]);

        // send ES message to alice
        let message = inbound_session.encrypt(&outbound_destination_id, vec![5u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![5u8; 4]);
    }

    #[tokio::test]
    async fn lease_set_bundled_in_ns_retries() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            _outbound_destination,
            _outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // send NS and verify it contains a `DatabaseStore` clove
        let mut message = inbound_session
            .decrypt(Message {
                payload: outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap(),
                ..Default::default()
            })
            .unwrap();
        assert!(message
            .find(|clove| std::matches!(clove.message_type, MessageType::DatabaseStore))
            .is_some());

        // send another NS and verify it also contains a `DatabaseStore` clove
        let mut message = inbound_session
            .decrypt(Message {
                payload: outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap(),
                ..Default::default()
            })
            .unwrap();
        assert!(message
            .find(|clove| std::matches!(clove.message_type, MessageType::DatabaseStore))
            .is_some());
    }

    #[tokio::test]
    async fn test_explicit_protocol_response() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            outbound_destination,
            outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // send and handle NS message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![1u8; 4]);

        // send NSR as reply to the new NS
        let message = inbound_session.encrypt(&outbound_destination_id, vec![2u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![2u8; 4]);

        // send ES message to bob, finalizing the session
        let message = outbound_session.encrypt(&inbound_destination_id, vec![3u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![3u8; 4]);

        // send ES message to alice
        let message = inbound_session.encrypt(&outbound_destination_id, vec![5u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![5u8; 4]);

        assert!(inbound_session
            .active
            .get(&outbound_destination_id)
            .expect("to exist")
            .inbound_ack_requests
            .is_empty());

        // create new lease set for `outbound_session`
        let gateway_router = RouterId::random();
        let gateway_tunnel = TunnelId::random();

        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: outbound_destination.clone(),
                    expires: (MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60))
                        .as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![outbound_private_key.public()],
                leases: vec![Lease {
                    router_id: gateway_router.clone(),
                    tunnel_id: gateway_tunnel,
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                }],
            }
            .serialize(&outbound_signing_key),
        );
        outbound_session.register_lease_set(lease_set);
        let ls_message = outbound_session.publish_local_lease_set(&inbound_destination_id).unwrap();
        let message =
            outbound_session.encrypt(&inbound_destination_id, ls_message.clone()).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, ls_message);

        // Assert we have an incoming ack request
        assert!(!inbound_session
            .active
            .get(&outbound_destination_id)
            .expect("to exist")
            .inbound_ack_requests
            .is_empty());

        // Assert we have outgoing pending ack request
        assert!(!outbound_session
            .active
            .get(&inbound_destination_id)
            .expect("to exist")
            .outbound_ack_requests
            .is_empty());

        // assert that nothing is ready immediately
        assert!(
            tokio::time::timeout(Duration::from_millis(100), inbound_session.next())
                .await
                .err()
                .is_some()
        );

        let ack_message =
            match tokio::time::timeout(LOW_PRIORITY_RESPONSE_INTERVAL, inbound_session.next())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                SessionManagerEvent::SendMessage {
                    destination_id,
                    message,
                } => {
                    assert_eq!(destination_id, outbound_destination_id);
                    message
                }
                _ => panic!(""),
            };

        let message =
            inbound_session.encrypt(&outbound_destination_id, ack_message.clone()).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, ack_message);

        // Assert we no longer have an inbound ack request
        assert!(inbound_session
            .active
            .get(&outbound_destination_id)
            .expect("to exist")
            .inbound_ack_requests
            .is_empty());

        // assert that nothing else is ready
        assert!(tokio::time::timeout(
            LOW_PRIORITY_RESPONSE_INTERVAL + LOW_PRIORITY_RESPONSE_INTERVAL,
            inbound_session.next()
        )
        .await
        .err()
        .is_some());
    }

    #[tokio::test]
    async fn test_explicit_protocol_response_canceled() {
        // create inbound `SessionManager`
        let inbound_private_key = StaticPrivateKey::random(thread_rng());
        let inbound_public_key = inbound_private_key.public();
        let (inbound_leaseset, inbound_destination_id) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let inbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                inbound_destination_id,
            )
        };
        let mut inbound_session = SessionManager::<MockRuntime>::new(
            inbound_destination_id.clone(),
            inbound_private_key,
            inbound_leaseset,
        );

        // create outbound `SessionManager`
        let outbound_private_key = StaticPrivateKey::random(thread_rng());
        let (
            outbound_leaseset,
            outbound_destination_id,
            outbound_destination,
            outbound_signing_key,
        ) = {
            let (leaseset, signing_key) = LeaseSet2::random();
            let destination = leaseset.header.destination.clone();
            let outbound_destination_id = leaseset.header.destination.id();

            (
                Bytes::from(leaseset.serialize(&signing_key)),
                outbound_destination_id,
                destination,
                signing_key,
            )
        };
        let mut outbound_session = SessionManager::<MockRuntime>::new(
            outbound_destination_id.clone(),
            outbound_private_key.clone(),
            outbound_leaseset,
        );
        outbound_session.add_remote_destination(inbound_destination_id.clone(), inbound_public_key);

        // send and handle NS message
        let message = outbound_session.encrypt(&inbound_destination_id, vec![1u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![1u8; 4]);

        // send NSR as reply to the new NS
        let message = inbound_session.encrypt(&outbound_destination_id, vec![2u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![2u8; 4]);

        // send ES message to bob, finalizing the session
        let message = outbound_session.encrypt(&inbound_destination_id, vec![3u8; 4]).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, vec![3u8; 4]);

        // send ES message to alice
        let message = inbound_session.encrypt(&outbound_destination_id, vec![5u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![5u8; 4]);

        assert!(inbound_session
            .active
            .get(&outbound_destination_id)
            .expect("to exist")
            .inbound_ack_requests
            .is_empty());

        // create new lease set for `outbound_session`
        let gateway_router = RouterId::random();
        let gateway_tunnel = TunnelId::random();

        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: outbound_destination.clone(),
                    expires: (MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60))
                        .as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![outbound_private_key.public()],
                leases: vec![Lease {
                    router_id: gateway_router.clone(),
                    tunnel_id: gateway_tunnel,
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                }],
            }
            .serialize(&outbound_signing_key),
        );
        outbound_session.register_lease_set(lease_set);
        let ls_message = outbound_session.publish_local_lease_set(&inbound_destination_id).unwrap();
        let message =
            outbound_session.encrypt(&inbound_destination_id, ls_message.clone()).unwrap();
        decrypt_and_verify!(&mut inbound_session, message, ls_message);

        // Assert we have an incoming ack request
        assert!(!inbound_session
            .active
            .get(&outbound_destination_id)
            .expect("to exist")
            .inbound_ack_requests
            .is_empty());

        // Assert we have outgoing pending ack request
        assert!(!outbound_session
            .active
            .get(&inbound_destination_id)
            .expect("to exist")
            .outbound_ack_requests
            .is_empty());

        // Upper-level activity
        let message = inbound_session.encrypt(&outbound_destination_id, vec![1u8; 4]).unwrap();
        decrypt_and_verify!(&mut outbound_session, message, vec![1u8; 4]);

        // Assert we no longer have an inbound ack request
        assert!(inbound_session
            .active
            .get(&outbound_destination_id)
            .expect("to exist")
            .inbound_ack_requests
            .is_empty());

        // assert that nothing else is ready
        assert!(tokio::time::timeout(
            LOW_PRIORITY_RESPONSE_INTERVAL + LOW_PRIORITY_RESPONSE_INTERVAL,
            inbound_session.next()
        )
        .await
        .err()
        .is_some());
    }
}
