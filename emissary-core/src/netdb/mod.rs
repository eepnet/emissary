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
    crypto::{base32_encode, base64_encode, StaticPublicKey},
    error::{Error, QueryError},
    i2np::{
        database::{
            lookup::{DatabaseLookup, LookupType, ReplyType},
            search_reply::DatabaseSearchReply,
            store::{
                DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload,
                ReplyType as StoreReplyType,
            },
        },
        delivery_status::DeliveryStatus,
        tunnel::gateway::TunnelGateway,
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::{handle::NetDbActionRecycle, metrics::*, query::*},
    primitives::{LeaseSet2, RouterId, RouterInfo},
    profile::Bucket,
    router::context::RouterContext,
    runtime::{Counter, Gauge, JoinSet, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transport::TransportService,
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::{Bytes, BytesMut};
use futures::{FutureExt, StreamExt};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc;

use alloc::{vec, vec::Vec};
use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub use dht::Dht;
pub use handle::NetDbHandle;

#[cfg(test)]
pub use handle::NetDbAction;
#[cfg(not(test))]
use handle::NetDbAction;

mod bucket;
mod dht;
mod handle;
mod metrics;
mod query;
mod routing_table;
mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb";

/// Timeout for an invididual `DatatabaseLookupMessage`.
const QUERY_TIMEOUT: Duration = Duration::from_millis(1600);

/// [`NetDb`] maintenance interval.
const NETDB_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

/// Number of router hashes to include into [`DatabaseSearchReply`].
const SEARCH_REPLY_NUM_ROUTERS: usize = 5usize;

/// What is considered high amount of routers.
const HIGH_ROUTER_COUNT: usize = 2500usize;

/// How often should router exploration be performed if the known peer count is low.
const EXPLORATION_INTERVAL_LOW_ROUTER_COUNT: usize = 55usize;

/// How often should router exploration be performed if the known peer count is high
const EXPLORATION_INTERVAL_HIGH_ROUTER_COUNT: usize = 170usize;

/// Message kind.
#[derive(Clone)]
enum MessageKind {
    /// Expiring message, e.g., flooded [`DatabaseStore`] for a [`LeaseSet2`] or [`RouterInfo`].
    Expiring {
        /// Serialized I2NP message.
        message: Vec<u8>,

        /// When does the payload of the message expires.
        expires: Duration,
    },

    /// Non-expiring message, e.g, router exploration.
    NonExpiring {
        /// Serialized I2NP message.
        message: Vec<u8>,
    },
}

impl MessageKind {
    /// Convert [`MessageKind`] into serialized I2NP message.
    pub fn into_inner(self) -> Vec<u8> {
        match self {
            Self::Expiring { message, .. } => message,
            Self::NonExpiring { message } => message,
        }
    }
}

/// Routere state.
enum RouterState {
    /// Router is connected.
    Connected,

    /// Router is being dialed.
    Dialing {
        /// Pending messages.
        pending_messages: Vec<MessageKind>,
    },
}

impl fmt::Debug for RouterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => f.debug_struct("RouterState::Connected").finish(),
            Self::Dialing { pending_messages } => f
                .debug_struct("RouterState::Dialing")
                .field("num_pending", &pending_messages.len())
                .finish(),
        }
    }
}

/// Network database (NetDB).
pub struct NetDb<R: Runtime> {
    /// Active queries.
    active: HashMap<Bytes, QueryKind<R>>,

    /// Exploratory tunnel pool handle.
    exploratory_pool_handle: TunnelPoolHandle,

    /// Router exploration timer.
    ///
    /// `None` if the router is run as floodfill.
    exploration_timer: Option<R::Timer>,

    /// Has the router been configured to act as a floodfill router.
    floodfill: bool,

    /// DHT of floodfills.
    floodfill_dht: Dht<R>,

    /// RX channel for receiving queries from other subsystems.
    handle_rx: mpsc::Receiver<NetDbAction, NetDbActionRecycle>,

    /// Serialized [`LeasSet2`]s received via `DatabaseStore` messages.
    ///
    /// This contains entries only if `floodfill` is true.
    lease_sets: HashMap<Bytes, (Bytes, Duration)>,

    /// `NetDb` maintenance timer.
    maintenance_timer: R::Timer,

    /// Message builder
    message_builder: NetDbMessageBuilder<R>,

    /// RX channel for receiving NetDb-related messages from [`TunnelManager`].
    netdb_msg_rx: mpsc::Receiver<Message>,

    /// TX channels of client destinations awaiting ready signal from [`NetDb`]
    pending_ready_awaits: Vec<oneshot::Sender<()>>,

    /// Query timers.
    query_timers: R::JoinSet<Bytes>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// DHT of non-floodfill routers.
    ///
    /// Available only if the router is acting as a floodfill router.
    ///
    /// Used to answer router exploration queries.
    router_dht: Option<Dht<R>>,

    /// Serialized [`RouterInfo`]s received via `DatabaseStore` messages.
    ///
    /// This contains entries only if `floodfill` is true.
    router_infos: HashMap<Bytes, (Bytes, Duration)>,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService<R>,
}

impl<R: Runtime> NetDb<R> {
    /// Create new [`NetDb`].
    pub fn new(
        router_ctx: RouterContext<R>,
        floodfill: bool,
        service: TransportService<R>,
        exploratory_pool_handle: TunnelPoolHandle,
        netdb_msg_rx: mpsc::Receiver<Message>,
    ) -> (Self, NetDbHandle) {
        let floodfills = router_ctx
            .profile_storage()
            .get_router_ids(Bucket::Any, |_, info, _| info.is_floodfill())
            .into_iter()
            .collect::<HashSet<_>>();

        let router_dht = floodfill.then(|| {
            Dht::new(
                router_ctx.router_id().clone(),
                router_ctx
                    .profile_storage()
                    .get_router_ids(Bucket::Any, |_, info, _| !info.is_floodfill())
                    .into_iter()
                    .collect::<HashSet<_>>(),
                router_ctx.clone(),
                false,
            )
        });

        router_ctx.metrics_handle().counter(NUM_FLOODFILLS).increment(floodfills.len());

        tracing::info!(
            target: LOG_TARGET,
            num_floodfills = ?floodfills.len(),
            ?floodfill,
            "starting netdb",
        );

        let (handle_tx, handle_rx) = mpsc::with_recycle(64, NetDbActionRecycle::default());

        (
            Self {
                active: HashMap::new(),
                exploratory_pool_handle,
                exploration_timer: if !floodfill {
                    let variance = R::rng().next_u64() as usize;

                    Some(R::timer(Duration::from_secs(
                        if router_ctx.profile_storage().num_routers() >= HIGH_ROUTER_COUNT {
                            ((EXPLORATION_INTERVAL_LOW_ROUTER_COUNT
                                + (variance % EXPLORATION_INTERVAL_LOW_ROUTER_COUNT))
                                / 2) as u64
                        } else {
                            (EXPLORATION_INTERVAL_HIGH_ROUTER_COUNT
                                + (variance % EXPLORATION_INTERVAL_HIGH_ROUTER_COUNT))
                                as u64
                        },
                    )))
                } else {
                    None
                },
                floodfill,
                floodfill_dht: Dht::new(
                    router_ctx.router_id().clone(),
                    floodfills.clone(),
                    router_ctx.clone(),
                    true,
                ),
                handle_rx,
                lease_sets: HashMap::new(),
                maintenance_timer: R::timer(Duration::from_secs(5)),
                message_builder: NetDbMessageBuilder::new(router_ctx.clone()),
                netdb_msg_rx,
                pending_ready_awaits: Vec::new(),
                query_timers: R::join_set(),
                router_ctx: router_ctx.clone(),
                router_dht,
                router_infos: HashMap::new(),
                routers: HashMap::new(),
                service,
            },
            NetDbHandle::new(handle_tx),
        )
    }

    /// Collect `NetDb`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Handle established connection to `router`.
    fn on_connection_established(&mut self, router_id: RouterId) {
        let is_floodfill = self.router_ctx.profile_storage().is_floodfill(&router_id);

        // send any pending messages to the connected router
        //
        // if the message was of the expiring kind (flooding) and the payload inside the i2np
        // message has expired, the message is skipped
        if let Some(RouterState::Dialing { pending_messages }) = self.routers.remove(&router_id) {
            let now = R::time_since_epoch();

            tracing::trace!(
                target: LOG_TARGET,
                floodfill = %router_id,
                num_pending = ?pending_messages.len(),
                "router with pending messages connected",
            );

            pending_messages.into_iter().for_each(|message| {
                let message = match message {
                    MessageKind::NonExpiring { message } => Some(message),
                    MessageKind::Expiring { message, expires } if expires > now => Some(message),
                    MessageKind::Expiring { expires, .. } => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?expires,
                            "message has expired, will not send",
                        );
                        None
                    }
                };

                if let Some(message) = message {
                    if let Err((error, _)) = self.service.send(&router_id, message) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?error,
                            "failed to send message",
                        );
                    }
                }
            });
        }

        if is_floodfill {
            self.floodfill_dht.add_router(router_id.clone());
            self.router_ctx.metrics_handle().gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
        } else {
            self.router_dht.as_mut().map(|dht| dht.add_router(router_id.clone()));
        }

        self.routers.insert(router_id, RouterState::Connected);
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router_id: RouterId) {
        self.routers.remove(&router_id);
    }

    // Handle connection failure to `router_id`.
    fn on_connection_failure(&mut self, router_id: RouterId) {
        if let Some(RouterState::Dialing { pending_messages }) = self.routers.remove(&router_id) {
            tracing::trace!(
                target: LOG_TARGET,
                %router_id,
                num_pending_messages = ?pending_messages.len(),
                "failed to establish connection",
            );
        }
    }

    /// Flood `message` to `routers`.
    fn send_message(&mut self, routers: &[RouterId], message: MessageKind) {
        routers.iter().for_each(|router_id| match self.routers.get_mut(router_id) {
            None => match self.service.connect(router_id) {
                Err(error) => tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    ?error,
                    "failed to connect to router",
                ),
                Ok(()) => {
                    self.routers.insert(
                        router_id.clone(),
                        RouterState::Dialing {
                            pending_messages: vec![message.clone()],
                        },
                    );
                }
            },
            Some(RouterState::Dialing { pending_messages }) => {
                pending_messages.push(message.clone());
            }
            Some(RouterState::Connected) => {
                if let Err((error, _)) = self.service.send(router_id, message.clone().into_inner())
                {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send message to router",
                    );
                }
            }
        });
    }

    /// Handle [`DatabaseStore`] for [`RouterInfo`] if the local router is run as a floodfill.
    fn on_router_info_store(
        &mut self,
        key: Bytes,
        reply: StoreReplyType,
        message: &[u8],
        router_info: RouterInfo,
    ) {
        let router_id = router_info.identity.id();

        if router_info.net_id() != self.router_ctx.net_id() {
            tracing::warn!(
                target: LOG_TARGET,
                local_net_id = ?self.router_ctx.net_id(),
                remote_net_id = ?router_info.net_id(),
                "invalid network id, ignoring router info store",
            );
            return;
        }

        if &router_id == self.router_ctx.router_id() {
            tracing::debug!(
                target: LOG_TARGET,
                "local router id, ignoring router info store",
            );
            return;
        }

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            "router info store",
        );
        let expires =
            Duration::from_millis(*router_info.published.date()) + Duration::from_secs(60 * 60);

        if expires < R::time_since_epoch() {
            tracing::debug!(
                target: LOG_TARGET,
                ?expires,
                "stale router info, ignoring",
            );
            return;
        }

        // add router to profile storage and floodfill dht (if they're a floodfill)
        // and check if we are a floodfill
        //
        // if we are not, exit early as non-floodfill don't flood router infos
        //
        // if we are a floodfill and flooding was requested, send the received
        // router info to three closest floodfills
        let published = *router_info.published.date();

        if router_info.is_floodfill() {
            self.floodfill_dht.add_router(router_id.clone());
        }

        // store both the new router info and its serialized form to profile storage
        //
        // the latter is used when a backup of profile storage is made to disk
        let raw_router_info = DatabaseStore::<R>::extract_raw_router_info(message);
        self.router_ctx
            .profile_storage()
            .discover_router(router_info, raw_router_info.clone());

        if !self.floodfill {
            return;
        }

        // parse the router info set from the database store and store it
        // in the set of router infos we keep track of
        self.router_infos.insert(
            key.clone(),
            (raw_router_info.clone(), Duration::from_millis(published)),
        );
        self.router_dht.as_mut().map(|dht| dht.add_router(router_id.clone()));

        match reply {
            StoreReplyType::None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "reply type is `None`, don't flood the router info",
                );
                return;
            }
            StoreReplyType::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::standard()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &TunnelGateway {
                            tunnel_id,
                            payload: &message,
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
            StoreReplyType::Router {
                reply_token,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
        }

        let floodfills = self.floodfill_dht.closest(&key, 3usize).collect::<Vec<_>>();
        if floodfills.is_empty() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "cannot flood router info, no floodfills",
            );
            return;
        }

        let message = DatabaseStoreBuilder::new(
            key,
            DatabaseStoreKind::RouterInfo {
                router_info: raw_router_info,
            },
        )
        .build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        self.send_message(&floodfills, MessageKind::Expiring { message, expires });
    }

    /// Handle [`DatabaseStore`] for [`LeasetSet2`] if the local router is run as a floodfill.
    fn on_lease_set_store(
        &mut self,
        key: Bytes,
        reply: StoreReplyType,
        message: &[u8],
        lease_set: LeaseSet2,
    ) {
        let destination_id = lease_set.header.destination.id();

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            "lease set store",
        );

        if lease_set.is_expired::<R>() {
            tracing::warn!(
                target: LOG_TARGET,
                %destination_id,
                expired = ?lease_set.header.expires,
                "received an expired lease set, ignoring",
            );
            return;
        }

        // parse the raw lease set from the database store, store it in the set of leases we keep
        // track of and flood it to three floodfills closest to `key`
        let raw_lease_set = DatabaseStore::<R>::extract_raw_lease_set(message);
        let expires = lease_set.expires();

        self.lease_sets.insert(key.clone(), (raw_lease_set.clone(), expires));

        match reply {
            StoreReplyType::None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "reply type is `None`, don't flood the router info",
                );
                return;
            }
            StoreReplyType::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::standard()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &TunnelGateway {
                            tunnel_id,
                            payload: &message,
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
            StoreReplyType::Router {
                reply_token,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
        }

        let floodfills = self.floodfill_dht.closest(&key, 3usize).collect::<Vec<_>>();
        if floodfills.is_empty() {
            tracing::debug!(
                target: LOG_TARGET,
                %destination_id,
                "cannot flood lease set, no floodfills",
            );
            return;
        }

        let message = DatabaseStoreBuilder::new(
            key,
            DatabaseStoreKind::LeaseSet2 {
                lease_set: raw_lease_set,
            },
        )
        .build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        self.send_message(&floodfills, MessageKind::Expiring { message, expires });
    }

    /// Handle [`DatabaseLookup`] for a [`LeaseSet2`].
    ///
    /// If lease set under `key` is not found in local storage, a [`DatabaseSearchReply`] message
    /// with floodfills closest to `key`, ignoring floodfills listed in `ignore`, is sent the sender
    /// either directly or via an exploratory tunnel.
    fn on_lease_set_lookup(
        &mut self,
        key: Bytes,
        reply_type: ReplyType,
        ignore: HashSet<RouterId>,
    ) {
        let (message_type, message) = match self.lease_sets.get(&key) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "lease set not found from local storage",
                );

                // get floodfills closest to `key`, ignoring floodfills listed in `ignore`
                //
                // the reply list is limited to 16 floodfills
                let routers = self
                    .floodfill_dht
                    .closest_with_ignore(&key, SEARCH_REPLY_NUM_ROUTERS, &ignore)
                    .collect::<Vec<_>>();

                (
                    MessageType::DatabaseSearchReply,
                    DatabaseSearchReply {
                        from: self.router_ctx.router_id().to_vec(),
                        key,
                        routers,
                    }
                    .serialize(),
                )
            }
            Some((lease_set, _)) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "lease set found from local storage",
                );

                (
                    MessageType::DatabaseStore,
                    DatabaseStoreBuilder::new(
                        key,
                        DatabaseStoreKind::LeaseSet2 {
                            lease_set: lease_set.clone(),
                        },
                    )
                    .build(),
                )
            }
        };

        match reply_type {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => {
                let message = MessageBuilder::standard()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err(error) = self
                    .exploratory_pool_handle
                    .send_message(message)
                    .tunnel_delivery(router_id.clone(), tunnel_id)
                    .try_send()
                {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        %tunnel_id,
                        ?error,
                        "failed to send database lookup reply to tunnel",
                    );
                }
            }
            ReplyType::Router { router_id } => {
                let message = MessageBuilder::short()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err((error, _)) = self.service.send(&router_id, message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send database lookup reply to router",
                    );
                }
            }
        }
    }

    /// Handle [`DatabaseLookup`] for a [`RouterInfo`].
    ///
    /// If router info under `key` is not found in local storage, a [`DatabaseSearchReply`] message
    /// with floodfills closest to `key`, ignoring floodfills listed in `ignore`, is sent the sender
    /// either directly or via an exploratory tunnel.
    fn on_router_info_lookup(
        &mut self,
        key: Bytes,
        reply_type: ReplyType,
        ignore: HashSet<RouterId>,
    ) {
        let (message_type, message) = match self.router_infos.get(&key) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "router info not found from local storage",
                );

                // get floodfills closest to `key`, ignoring floodfills listed in `ignore`
                //
                // the reply list is limited to 16 floodfills
                let routers = self
                    .floodfill_dht
                    .closest_with_ignore(&key, SEARCH_REPLY_NUM_ROUTERS, &ignore)
                    .collect::<Vec<_>>();

                (
                    MessageType::DatabaseSearchReply,
                    DatabaseSearchReply {
                        from: self.router_ctx.router_id().to_vec(),
                        key,
                        routers,
                    }
                    .serialize(),
                )
            }
            Some((router_info, _)) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "router info found from local storage",
                );

                (
                    MessageType::DatabaseStore,
                    DatabaseStoreBuilder::new(
                        key,
                        DatabaseStoreKind::RouterInfo {
                            router_info: router_info.clone(),
                        },
                    )
                    .build(),
                )
            }
        };

        match reply_type {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => {
                let message = MessageBuilder::standard()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err(error) = self
                    .exploratory_pool_handle
                    .send_message(message)
                    .tunnel_delivery(router_id.clone(), tunnel_id)
                    .try_send()
                {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        %tunnel_id,
                        ?error,
                        "failed to send database lookup reply to tunnel",
                    );
                }
            }
            ReplyType::Router { router_id } => {
                let message = MessageBuilder::short()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err((error, _)) = self.service.send(&router_id, message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send database lookup reply to router",
                    );
                }
            }
        }
    }

    /// Handle router exploration lookup.
    fn on_router_exploration(
        &mut self,
        key: Bytes,
        reply_type: ReplyType,
        ignore: HashSet<RouterId>,
    ) {
        let Some(dht) = self.router_dht.as_mut() else {
            tracing::warn!(
                target: LOG_TARGET,
                "ignore router exploration, not a floodfill",
            );
            return;
        };

        let routers = dht
            .closest_with_ignore(&key, SEARCH_REPLY_NUM_ROUTERS, &ignore)
            .collect::<Vec<_>>();

        tracing::trace!(
            target: LOG_TARGET,
            num_routers = ?routers.len(),
            "send router exploration reply",
        );

        let message = Message {
            message_type: MessageType::DatabaseSearchReply,
            message_id: R::rng().next_u32(),
            expiration: R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: DatabaseSearchReply {
                from: self.router_ctx.router_id().to_vec(),
                key: key.clone(),
                routers,
            }
            .serialize()
            .to_vec(),
        };

        let (router_id, message) = match reply_type {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => (
                router_id,
                MessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_payload(
                        &TunnelGateway {
                            tunnel_id,
                            payload: &message.serialize_standard(),
                        }
                        .serialize(),
                    )
                    .build(),
            ),
            ReplyType::Router { router_id } => (router_id, message.serialize_short()),
        };

        self.send_message(&[router_id], MessageKind::NonExpiring { message });
    }

    /// Handle `DatabaaseStore` message.
    fn on_database_store(
        &mut self,
        message: Message,
        sender: Option<RouterId>,
    ) -> crate::Result<()> {
        let DatabaseStore {
            key,
            payload,
            reply,
            ..
        } = DatabaseStore::<R>::parse(&message.payload).ok_or_else(|| {
            tracing::debug!(
                target: LOG_TARGET,
                "malformed database store received",
            );
            Error::InvalidData
        })?;

        match self.active.remove(&key) {
            None => match payload {
                DatabaseStorePayload::RouterInfo { router_info } => {
                    self.on_router_info_store(key, reply, &message.payload, router_info);
                }
                DatabaseStorePayload::LeaseSet2 { lease_set } if self.floodfill => {
                    self.on_lease_set_store(key, reply, &message.payload, lease_set);
                }
                DatabaseStorePayload::LeaseSet2 { lease_set } => tracing::trace!(
                    target: LOG_TARGET,
                    destination_id = %lease_set.header.destination.id(),
                    "ignoring lease set database store",
                ),
            },
            Some(kind) => match (payload, kind) {
                (DatabaseStorePayload::LeaseSet2 { lease_set }, QueryKind::LeaseSet { query }) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        destination_id = %lease_set.header.destination.id(),
                        "lease set query reply received",
                    );
                    query.complete(Ok(lease_set));
                }
                (DatabaseStorePayload::RouterInfo { router_info }, QueryKind::Router) => {
                    let router_id = router_info.identity.id();

                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        "router info query reply received",
                    );

                    if router_info.net_id() != self.router_ctx.net_id() {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local_net_id = ?self.router_ctx.net_id(),
                            remote_net_id = ?router_info.net_id(),
                            "invalid network id, ignoring router info query reply",
                        );
                        return Ok(());
                    }

                    if &router_id == self.router_ctx.router_id() {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "local router id, ignoring router info query reply",
                        );
                        return Ok(());
                    }

                    if router_info.is_floodfill() {
                        self.floodfill_dht.add_router(router_id.clone());
                    }
                    self.router_dht.as_mut().map(|dht| dht.add_router(router_id));

                    // if the router info was received directly from the floodfill, i.e., not
                    // through tunnel, adjust the floodfill score
                    //
                    // this makes it less likely to be evicted from the dht
                    if let Some(router_id) = sender {
                        self.floodfill_dht.register_lookup_success(&router_id);
                    }

                    // store both the new router info and its serialized form to profile storage
                    //
                    // the latter is used when a backup of profile storage is made to disk
                    let raw_router_info =
                        DatabaseStore::<R>::extract_raw_router_info(&message.payload);
                    self.router_ctx
                        .profile_storage()
                        .discover_router(router_info, raw_router_info.clone());
                }
                (
                    DatabaseStorePayload::RouterInfo { router_info },
                    QueryKind::RouterInfo { query },
                ) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        router_id = %router_info.identity.id(),
                        "router info found",
                    );

                    // store both the new router info and its serialized form to profile storage
                    //
                    // the latter is used when a backup of profile storage is made to disk
                    let raw_router_info =
                        DatabaseStore::<R>::extract_raw_router_info(&message.payload);
                    let router_id = router_info.identity.id();

                    // if the router info was received directly from the floodfill, i.e., not
                    // through tunnel, adjust the floodfill score
                    //
                    // this makes it less likely to be evicted from the dht
                    if let Some(router_id) = sender {
                        self.floodfill_dht.register_lookup_success(&router_id);
                    }

                    if self
                        .router_ctx
                        .profile_storage()
                        .discover_router(router_info, raw_router_info.clone())
                    {
                        query.complete(Ok(()));
                    } else {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            "router info found but it couldn't be accepted to profile storage",
                        );
                        query.complete(Err(QueryError::Malformed));
                    }
                }
                (payload, query) => tracing::warn!(
                    target: LOG_TARGET,
                    %payload,
                    ?query,
                    "unhandled database store kind",
                ),
            },
        }

        Ok(())
    }

    /// Handle `DatabaseSearchReply` message.
    fn on_database_search_reply(
        &mut self,
        message: Message,
        sender: Option<RouterId>,
    ) -> crate::Result<()> {
        // if the value was received directly from the floodfill, i.e., not
        // through tunnel, adjust the floodfill score
        if let Some(router_id) = sender {
            self.floodfill_dht.register_lookup_failure(&router_id);
        }

        let DatabaseSearchReply {
            key,
            mut routers,
            from,
        } = DatabaseSearchReply::parse(&message.payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                "malformed database search reply",
            );
            Error::InvalidData
        })?;
        let router_id = RouterId::from(from);

        match self.active.remove(&key) {
            None => {}
            Some(QueryKind::Exploration) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    num_routers = ?routers.len(),
                    "router exploration succeeded, send database lookups",
                );

                routers.retain(|router| {
                    router != self.router_ctx.router_id()
                        && !self.router_ctx.profile_storage().contains(router)
                });
                routers.into_iter().for_each(|lookup_key| {
                    let key = Bytes::from(lookup_key.to_vec());

                    match self.message_builder.create_router_info_query(key.clone()) {
                        Ok((message, outbound_tunnel)) => match self
                            .exploratory_pool_handle
                            .send_message(message)
                            .router_delivery(router_id.clone())
                            .via_outbound_tunnel(outbound_tunnel)
                            .try_send()
                        {
                            Ok(()) => {
                                self.active.insert(key.clone(), QueryKind::Router);
                                self.query_timers.push(async move {
                                    R::delay(QUERY_TIMEOUT).await;
                                    key
                                });
                            }
                            Err(error) => tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to send database lookup message for router info",
                            ),
                        },
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to database lookup message for router info",
                        ),
                    }
                });
            }
            Some(QueryKind::LeaseSet { mut query }) => {
                let unknown =
                    query.handle_search_reply(&routers, self.router_ctx.profile_storage());

                tracing::trace!(
                    target: LOG_TARGET,
                    key = base32_encode(&key),
                    num_queried = ?query.queried.len(),
                    ?unknown,
                    "received `DatabaseSearchReply` for lease set query",
                );

                // send lookup messages for the found routers
                unknown.iter().for_each(|lookup_router_id| {
                    let key = Bytes::from(lookup_router_id.to_vec());

                    match self.message_builder.create_router_info_query(key.clone()) {
                        Ok((message, outbound_tunnel)) => match self
                            .exploratory_pool_handle
                            .send_message(message)
                            .router_delivery(router_id.clone())
                            .via_outbound_tunnel(outbound_tunnel)
                            .try_send()
                        {
                            Ok(()) => {
                                self.active.insert(key.clone(), QueryKind::Router);
                                self.query_timers.push(async move {
                                    R::delay(QUERY_TIMEOUT).await;
                                    key
                                });
                            }
                            Err(error) => tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to send database lookup message for router info",
                            ),
                        },
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to database lookup message for router info",
                        ),
                    }
                });

                self.active.insert(key.clone(), QueryKind::LeaseSet { query });
            }
            Some(QueryKind::RouterInfo { mut query }) => {
                let unknown =
                    query.handle_search_reply(&routers, self.router_ctx.profile_storage());

                tracing::trace!(
                    target: LOG_TARGET,
                    key = %RouterId::from(&key),
                    num_queried = ?query.queried.len(),
                    ?unknown,
                    "received `DatabaseSearchReply` for router info query",
                );

                // send lookup messages for the found routers
                unknown.iter().for_each(|lookup_router_id| {
                    let key = Bytes::from(lookup_router_id.to_vec());

                    match self.message_builder.create_router_info_query(key.clone()) {
                        Ok((message, outbound_tunnel)) => match self
                            .exploratory_pool_handle
                            .send_message(message)
                            .router_delivery(router_id.clone())
                            .via_outbound_tunnel(outbound_tunnel)
                            .try_send()
                        {
                            Ok(()) => {
                                self.active.insert(key.clone(), QueryKind::Router);
                                self.query_timers.push(async move {
                                    R::delay(QUERY_TIMEOUT).await;
                                    key
                                });
                            }
                            Err(error) => tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to send database lookup message for router info",
                            ),
                        },
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to database lookup message for router info",
                        ),
                    }
                });

                self.active.insert(key.clone(), QueryKind::RouterInfo { query });
            }
            Some(QueryKind::Router) => tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                key = ?base64_encode(key),
                "router info lookup failed",
            ),
        }

        Ok(())
    }

    /// Handle I2NP message.
    ///
    /// `sender` is the [`RouterId`] if the message was received directly from the sender.
    fn on_message(&mut self, message: Message, sender: Option<RouterId>) -> crate::Result<()> {
        self.router_ctx.metrics_handle().counter(NUM_NETDB_MESSAGES).increment(1);

        match message.message_type {
            MessageType::DatabaseStore => return self.on_database_store(message, sender),
            MessageType::DatabaseLookup if self.floodfill => {
                self.router_ctx.metrics_handle().counter(NUM_QUERIES).increment(1);

                let DatabaseLookup {
                    ignore,
                    key,
                    lookup,
                    reply,
                } = DatabaseLookup::parse(&message.payload).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "malformed database lookup received",
                    );
                    Error::InvalidData
                })?;

                match lookup {
                    LookupType::LeaseSet => self.on_lease_set_lookup(key, reply, ignore),
                    LookupType::Router => self.on_router_info_lookup(key, reply, ignore),
                    LookupType::Exploration => self.on_router_exploration(key, reply, ignore),
                    kind => tracing::warn!(
                        target: LOG_TARGET,
                        ?kind,
                        "unsupported lookup kind",
                    ),
                }
            }
            MessageType::DatabaseLookup => tracing::debug!(
                target: LOG_TARGET,
                "ignoring database lookup, not a floodfill",
            ),
            MessageType::DatabaseSearchReply =>
                return self.on_database_search_reply(message, sender),
            MessageType::DeliveryStatus => {}
            message_type => tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "unsupported message",
            ),
        }

        Ok(())
    }

    /// Query `LeaseSet2` under `key` from `NetDb` and return result to caller via `tx`.
    ///
    /// Starts at most 3 queries in parallel and the first one that succeeds is sent to the
    /// destination. The query is considered failed if `DatabaseSearchReply` is received from all
    /// three floodfill routers or if the query timer expires.
    fn query_lease_set(&mut self, key: Bytes, tx: oneshot::Sender<Result<LeaseSet2, QueryError>>) {
        match self.active.get_mut(&key) {
            Some(QueryKind::LeaseSet { query }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    key = base32_encode(&key),
                    "lease set query already in progress, adding subscriber",
                );

                query.add_subscriber(tx);
                return;
            }
            Some(kind) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    key = ?key.to_vec(),
                    "unable to handle lease set query, different kind of query alreayd in progress",
                );
                return;
            }
            None => {}
        }

        let mut ignored = HashSet::<RouterId>::new();

        let (floodfill, floodfill_public_key) = loop {
            let Some(floodfill) =
                self.floodfill_dht.closest_with_ignore(&key, 1usize, &ignored).next()
            else {
                tracing::warn!(
                    target: LOG_TARGET,
                    "cannot query lease set, no floodfills",
                );
                let _ = tx.send(Err(QueryError::NoFloodfills));
                return;
            };

            let reader = self.router_ctx.profile_storage().reader();

            match reader.router_info(&floodfill) {
                Some(router_info) => {
                    break (floodfill, router_info.identity.static_key().clone());
                }
                None => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        key = ?base32_encode(&key),
                        %floodfill,
                        "cannot send lease set query, floodfill router info doesn't exist",
                    );
                    ignored.insert(floodfill);
                }
            }
        };

        tracing::debug!(
            target: LOG_TARGET,
            key = ?base32_encode(&key),
            %floodfill,
            "query lease set",
        );

        match self.message_builder.create_lease_set_query(key.clone(), floodfill_public_key) {
            Ok((message, outbound_tunnel)) => match self
                .exploratory_pool_handle
                .send_message(message)
                .router_delivery(floodfill.clone())
                .via_outbound_tunnel(outbound_tunnel)
                .try_send()
            {
                Ok(()) => {
                    // store leaseset query into active queries and start timer for the query
                    self.active.insert(
                        key.clone(),
                        QueryKind::LeaseSet {
                            query: Query::new(key.clone(), tx, floodfill),
                        },
                    );
                    self.query_timers.push(async move {
                        R::delay(QUERY_TIMEOUT).await;
                        key
                    });
                }
                Err(_) => {
                    let _ = tx.send(Err(QueryError::RetryFailure));
                }
            },
            Err(error) => {
                let _ = tx.send(Err(error));
            }
        }
    }

    /// Query `RouterInfo` under `router_id` from `NetDb` and return result to caller via `tx`.
    ///
    /// Starts at most 3 queries in parallel and the first one that succeeds is sent to the
    /// caller. The query is considered failed if `DatabaseSearchReply` is received from all
    /// three floodfill routers or if the query timer expires.
    fn query_router_info(
        &mut self,
        router_id: RouterId,
        tx: oneshot::Sender<Result<(), QueryError>>,
    ) {
        let key = Bytes::from(router_id.to_vec());

        match self.active.get_mut(&key) {
            Some(QueryKind::RouterInfo { query }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    key = %router_id,
                    "router info query already in progress, adding subscriber",
                );

                query.add_subscriber(tx);
                return;
            }
            Some(kind) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    key = %router_id,
                    "unable to handle router info query, different kind of query already in progress",
                );
                return;
            }
            None => {}
        }

        let Some(floodfill) = self.floodfill_dht.closest(&key, 1usize).next() else {
            tracing::warn!(
                target: LOG_TARGET,
                "cannot query leaseset, no floodfills",
            );
            let _ = tx.send(Err(QueryError::NoFloodfills));
            return;
        };

        tracing::debug!(
            target: LOG_TARGET,
            %router_id,
            %floodfill,
            "query router info",
        );

        match self.message_builder.create_router_info_query(key.clone()) {
            Ok((message, outbound_tunnel)) => match self
                .exploratory_pool_handle
                .send_message(message)
                .router_delivery(floodfill.clone())
                .via_outbound_tunnel(outbound_tunnel)
                .try_send()
            {
                Ok(()) => {
                    // store router info query into active queries and start timer for it
                    self.active.insert(
                        key.clone(),
                        QueryKind::RouterInfo {
                            query: Query::new(key.clone(), tx, floodfill),
                        },
                    );
                    self.query_timers.push(async move {
                        R::delay(QUERY_TIMEOUT).await;
                        key
                    });
                }
                Err(_) => {
                    let _ = tx.send(Err(QueryError::RetryFailure));
                }
            },
            Err(error) => {
                let _ = tx.send(Err(error));
            }
        }
    }

    /// Get `RouterId`'s of the floodfills closest to `key`.
    fn get_closest_floodfills(
        &mut self,
        key: Bytes,
        tx: oneshot::Sender<Vec<(RouterId, StaticPublicKey)>>,
    ) {
        let floodfills = self
            .floodfill_dht
            .closest(&key, 10usize)
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|router_id| {
                self.router_ctx
                    .profile_storage()
                    .get(&router_id)
                    .map(|router_info| (router_id, router_info.identity.static_key().clone()))
            })
            .collect::<Vec<_>>();

        if floodfills.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                key = ?base32_encode(&key),
                "no floodfills available",
            );

            return drop(tx);
        }

        let _ = tx.send(floodfills);
    }

    /// Publish `router_info` under `router_id` in `NetDb`.
    fn publish_router_info(&mut self, router_id: RouterId, router_info: Bytes) {
        let key = Bytes::from(router_id.to_vec());

        let floodfills = self.floodfill_dht.closest(&key, 3usize).collect::<Vec<_>>();
        if floodfills.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                "cannot send router info, no floodfills",
            );
            return;
        }

        // gzip-compress the serialized router info, as required by the spec
        //
        // call is expected to succeed as the router info is created by us
        let serialized_router_info =
            Bytes::from(R::gzip_compress(router_info).expect("to succeed"));

        let reply_token = R::rng().next_u32();
        let message = DatabaseStoreBuilder::new(
            key,
            DatabaseStoreKind::RouterInfo {
                router_info: serialized_router_info,
            },
        )
        .with_reply_type(StoreReplyType::Router {
            reply_token,
            router_id: self.router_ctx.router_id().clone(),
        })
        .build();

        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        tracing::info!(
            target: LOG_TARGET,
            %router_id,
            ?floodfills,
            %reply_token,
            "publish router info",
        );

        self.send_message(&floodfills, MessageKind::NonExpiring { message });
    }

    /// Perform general maintenance of [`NetDb`].
    fn maintain_netdb(&mut self) {
        // prune expired lease sets
        {
            let now = R::time_since_epoch();
            let num_pruned = self
                .lease_sets
                .iter()
                .filter_map(|(key, (_, expires))| (expires < &now).then_some(key.clone()))
                .collect::<Vec<_>>()
                .into_iter()
                .fold(0usize, |count, key| {
                    self.lease_sets.remove(&key);
                    count + 1
                });

            if num_pruned > 0 {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?num_pruned,
                    "pruned expired lease sets",
                );
            }
        }
    }

    /// Perform router exploration.
    fn explore_routers(&mut self) {
        let key = {
            let mut key = BytesMut::zeroed(32);
            R::rng().fill_bytes(&mut key);

            key.freeze()
        };

        let Some(floodfill) = self.floodfill_dht.closest(&key, 1usize).next() else {
            tracing::debug!(
                target: LOG_TARGET,
                "cannot perform router exploration, no floodfills",
            );
            return;
        };

        tracing::trace!(
            target: LOG_TARGET,
            %floodfill,
            "send router exploration query",
        );

        let Ok((message, outbound_tunnel)) =
            self.message_builder.create_router_exploration(key.clone())
        else {
            tracing::debug!(
                target: LOG_TARGET,
                "cannot perform router exploration, no inbound/outbound tunnels",
            );
            return;
        };

        match self
            .exploratory_pool_handle
            .send_message(message)
            .router_delivery(floodfill)
            .via_outbound_tunnel(outbound_tunnel)
            .try_send()
        {
            Ok(()) => {
                self.active.insert(key.clone(), QueryKind::Exploration);
                self.query_timers.push(async move {
                    R::delay(QUERY_TIMEOUT).await;
                    key
                });
            }
            Err(error) => tracing::debug!(
                target: LOG_TARGET,
                ?error,
                "failed to send router exploration query",
            ),
        }
    }

    /// Handle timeout for `query`.
    fn handle_timeout(&mut self, key: Bytes, query: QueryKind<R>) {
        match query {
            QueryKind::LeaseSet { mut query } => {
                if let Some(floodfill) = query.selected.take() {
                    self.floodfill_dht.register_lookup_timeout(&floodfill);
                }

                let (floodfill, public_key) = loop {
                    // attempt to select next floodfill if none is found or the query has expired,
                    // send failure to caller
                    let floodfill = match query
                        .handle_timeout(&self.floodfill_dht, self.router_ctx.profile_storage())
                    {
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                key = %base32_encode(&key),
                                ?error,
                                "lease set query timed out",
                            );
                            query.complete(Err(error));
                            return;
                        }
                        Ok(floodfill) => floodfill,
                    };

                    let reader = self.router_ctx.profile_storage().reader();

                    match reader.router_info(&floodfill) {
                        Some(router_info) =>
                            break (floodfill, router_info.identity.static_key().clone()),
                        None => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                key = ?base32_encode(&key),
                                %floodfill,
                                "cannot send lease set query, floodfill router info doesn't exist",
                            );
                            query.queried.insert(floodfill);
                        }
                    }
                };

                tracing::debug!(
                    target: LOG_TARGET,
                    key = ?base32_encode(&key),
                    %floodfill,
                    "send lease set query",
                );

                match self.message_builder.create_lease_set_query(key.clone(), public_key) {
                    Ok((message, outbound_tunnel)) => match self
                        .exploratory_pool_handle
                        .send_message(message)
                        .router_delivery(floodfill.clone())
                        .via_outbound_tunnel(outbound_tunnel)
                        .try_send()
                    {
                        Ok(()) => {
                            query.queried.insert(floodfill.clone());
                            query.selected = Some(floodfill);

                            self.active.insert(key.clone(), QueryKind::LeaseSet { query });
                            self.query_timers.push(async move {
                                R::delay(QUERY_TIMEOUT).await;
                                key
                            });
                        }
                        Err(_) => {
                            query.complete(Err(QueryError::RetryFailure));
                        }
                    },
                    Err(error) => {
                        query.complete(Err(error));
                    }
                }
            }
            QueryKind::RouterInfo { mut query } => {
                if let Some(floodfill) = query.selected.take() {
                    self.floodfill_dht.register_lookup_timeout(&floodfill);
                }

                // attempt to select next floodfill if none is found or the query has expired,
                // send failure to caller
                let floodfill = match query
                    .handle_timeout(&self.floodfill_dht, self.router_ctx.profile_storage())
                {
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            key = %base32_encode(&key),
                            ?error,
                            "router info query timed out",
                        );
                        query.complete(Err(error));
                        return;
                    }
                    Ok(floodfill) => floodfill,
                };

                tracing::debug!(
                    target: LOG_TARGET,
                    key = ?base32_encode(&key),
                    %floodfill,
                    "send router info query",
                );

                match self.message_builder.create_router_info_query(key.clone()) {
                    Ok((message, outbound_tunnel)) => match self
                        .exploratory_pool_handle
                        .send_message(message)
                        .router_delivery(floodfill.clone())
                        .via_outbound_tunnel(outbound_tunnel)
                        .try_send()
                    {
                        Ok(()) => {
                            query.queried.insert(floodfill.clone());
                            query.selected = Some(floodfill);
                        }
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to send database lookup message for router info",
                        ),
                    },
                    Err(error) => tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to create database lookup message for router info",
                    ),
                }

                self.active.insert(key.clone(), QueryKind::RouterInfo { query });
                self.query_timers.push(async move {
                    R::delay(QUERY_TIMEOUT).await;
                    key
                });
            }
            kind => tracing::debug!(
                target: LOG_TARGET,
                ?kind,
                "query timed out",
            ),
        }
    }
}

impl<R: Runtime> Future for NetDb<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|(router_id, message)| {
                        if let Err(error) = self.on_message(message, Some(router_id)) {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to handle message",
                            );
                        }
                    }),
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router })) =>
                    self.on_connection_failure(router),
                Poll::Ready(Some(SubsystemEvent::Dummy)) => {}
            }
        }

        loop {
            match self.netdb_msg_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) =>
                    if let Err(error) = self.on_message(message, None) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to handle message",
                        );
                    },
            }
        }

        // events from the exploratory pool are not interesting to `NetDb`
        loop {
            match self.exploratory_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                    self.message_builder.outbound_tunnels.add_tunnel(tunnel_id);

                    if self.message_builder.inbound_tunnels.len() > 0
                        && !self.pending_ready_awaits.is_empty()
                    {
                        mem::take(&mut self.pending_ready_awaits).into_iter().for_each(|tx| {
                            let _ = tx.send(());
                        });
                    }
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                    self.message_builder
                        .outbound_tunnels
                        .remove_tunnel(|tunnel| tunnel != &tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { lease, .. })) => {
                    self.message_builder.inbound_tunnels.add_tunnel(lease);

                    if self.message_builder.outbound_tunnels.len() > 0
                        && !self.pending_ready_awaits.is_empty()
                    {
                        mem::take(&mut self.pending_ready_awaits).into_iter().for_each(|tx| {
                            let _ = tx.send(());
                        });
                    }
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                    self.message_builder
                        .inbound_tunnels
                        .remove_tunnel(|lease| lease.tunnel_id != tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) => {
                    let _ = self.on_message(message, None);
                }
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => return Poll::Ready(()),
                Poll::Ready(Some(_)) => {}
            }
        }

        loop {
            match self.handle_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(NetDbAction::QueryLeaseSet2 { key, tx })) =>
                    self.query_lease_set(key, tx),
                Poll::Ready(Some(NetDbAction::GetClosestFloodfills { key, tx })) =>
                    self.get_closest_floodfills(key, tx),
                Poll::Ready(Some(NetDbAction::QueryRouterInfo { router_id, tx })) =>
                    self.query_router_info(router_id, tx),
                Poll::Ready(Some(NetDbAction::PublishRouterInfo {
                    router_id,
                    router_info,
                })) => self.publish_router_info(router_id, router_info),
                Poll::Ready(Some(NetDbAction::WaitUntilReady { tx })) => {
                    // if there's at least one inbound and one outbound tunnel,
                    // netdb is considered ready
                    if self.message_builder.inbound_tunnels.len() > 0
                        && self.message_builder.outbound_tunnels.len() > 0
                    {
                        let _ = tx.send(());
                    } else {
                        self.pending_ready_awaits.push(tx);
                    }
                }
                Poll::Ready(Some(NetDbAction::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.query_timers.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(key)) =>
                    if let Some(query) = self.active.remove(&key) {
                        self.handle_timeout(key, query);
                    },
            }
        }

        if self.maintenance_timer.poll_unpin(cx).is_ready() {
            self.maintain_netdb();

            // reset timer and register it into the executor
            self.maintenance_timer = R::timer(NETDB_MAINTENANCE_INTERVAL);
            let _ = self.maintenance_timer.poll_unpin(cx);
        }

        if let Some(ref mut timer) = self.exploration_timer {
            if timer.poll_unpin(cx).is_ready() {
                self.explore_routers();

                // create new timer and register it into the executor
                self.exploration_timer = Some({
                    let variance = R::rng().next_u64() as usize;

                    R::timer(Duration::from_secs(
                        if self.router_ctx.profile_storage().num_routers() >= HIGH_ROUTER_COUNT {
                            ((EXPLORATION_INTERVAL_LOW_ROUTER_COUNT
                                + (variance % EXPLORATION_INTERVAL_LOW_ROUTER_COUNT))
                                / 2) as u64
                        } else {
                            (EXPLORATION_INTERVAL_HIGH_ROUTER_COUNT
                                + (variance % EXPLORATION_INTERVAL_HIGH_ROUTER_COUNT))
                                as u64
                        },
                    ))
                });
                let _ = self.exploration_timer.as_mut().expect("to exist").poll_unpin(cx);
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{SigningPrivateKey, StaticPrivateKey},
        events::EventManager,
        i2np::database::lookup::DatabaseLookupBuilder,
        primitives::{
            Capabilities, Date, Destination, DestinationId, Lease, LeaseSet2Header, Mapping,
            RouterAddress, RouterIdentity, RouterInfo, RouterInfoBuilder, Str, TransportKind,
            TunnelId,
        },
        runtime::mock::MockRuntime,
        subsystem::{InnerSubsystemEvent, SubsystemCommand},
        transport::ProtocolCommand,
        tunnel::TunnelMessage,
    };
    use std::collections::VecDeque;
    use thingbuf::mpsc::channel;

    #[tokio::test]
    async fn lease_set_store_to_floodfill() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let reply_router = RouterId::random();
        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set })
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: reply_router.clone(),
            })
            .build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert_eq!(netdb.lease_sets.len(), 1);
        match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router_id } => {
                assert_eq!(router_id, reply_router);
            }
            _ => panic!("invalid event"),
        }
        assert!((0..3).all(|_| match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router_id } => {
                assert!(floodfills.remove(&router_id));
                true
            }
            _ => false,
        }));
        assert_eq!(netdb.routers.len(), 4);
        assert!(netdb
            .routers
            .values()
            .all(|state| std::matches!(state, RouterState::Dialing { .. })));
    }

    #[tokio::test]
    async fn lease_set_store_to_non_floodfill() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            false,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set })
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert!(netdb.lease_sets.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn expired_lease_set_store() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: (Duration::from_secs(60)).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: (MockRuntime::time_since_epoch()
                                - Duration::from_secs(5 * 60))
                            .as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set })
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert!(netdb.lease_sets.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn expired_lease_sets_are_pruned() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key1, expired_lease_set1) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: Duration::from_secs(10).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let (key2, expired_lease_set2) = {
            let sgk = SigningPrivateKey::from_bytes(&[2u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: Duration::from_secs(5).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let (key3, valid_lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[3u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: (MockRuntime::time_since_epoch() - Duration::from_secs(60))
                                .as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        // store first lease set that is about to expire
        {
            let reply_router = RouterId::random();
            let message = DatabaseStoreBuilder::new(
                key1,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: expired_lease_set1,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: reply_router.clone(),
            })
            .build();

            assert!(netdb.lease_sets.is_empty());
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 1);
            assert_eq!(netdb.routers.len(), 4);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!((0..3).all(|_| match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert!(floodfills.remove(&router_id));
                    true
                }
                _ => false,
            }));
            assert!(netdb.routers.values().all(|state| match state {
                RouterState::Dialing { pending_messages } => {
                    assert_eq!(pending_messages.len(), 1);
                    true
                }
                _ => false,
            }));
        }

        // store second expiring lease set and verify floodfills are pending
        {
            let reply_router = RouterId::random();
            let message = DatabaseStoreBuilder::new(
                key2,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: expired_lease_set2,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: reply_router.clone(),
            })
            .build();

            assert_eq!(netdb.lease_sets.len(), 1);
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 2);
            assert_eq!(netdb.routers.len(), 5);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.router_ctx.profile_storage().is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 2);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }

                    true
                }
                _ => false,
            }));
        }

        // store non-expiring lease set and verify floodfills are pending
        {
            let reply_router = RouterId::random();
            let message = DatabaseStoreBuilder::new(
                key3,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: valid_lease_set,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: reply_router.clone(),
            })
            .build();

            assert_eq!(netdb.lease_sets.len(), 2);
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 3);
            assert_eq!(netdb.routers.len(), 6);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.router_ctx.profile_storage().is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 3);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }
                    true
                }
                _ => false,
            }));
        }

        // poll netdb until it does its maintenance
        tokio::time::timeout(Duration::from_secs(35), &mut netdb).await.unwrap_err();

        // verify two of the lease sets are pruned
        assert_eq!(netdb.lease_sets.len(), 1);
    }

    #[tokio::test]
    async fn router_info_store_to_floodfill() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    + Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let reply_router = RouterId::random();
        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info })
            .with_reply_type(StoreReplyType::Router {
                reply_token: MockRuntime::rng().next_u32(),
                router_id: reply_router.clone(),
            })
            .build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert_eq!(netdb.router_infos.len(), 1);
        match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router_id } => {
                assert_eq!(router_id, reply_router);
            }
            _ => panic!("invalid event"),
        }
        assert!((0..3).all(|_| match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router_id } => {
                assert!(floodfills.remove(&router_id));
                true
            }
            _ => false,
        }));
        assert_eq!(netdb.routers.len(), 4);
        assert!(netdb
            .routers
            .values()
            .all(|state| std::matches!(state, RouterState::Dialing { .. })));
    }

    #[tokio::test]
    async fn stale_router_info_not_stored_nor_flooded() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    - Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info }).build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert!(netdb.router_infos.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn lease_set_query() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, lease_set, expires) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };
            let lease_set = Bytes::from(
                LeaseSet2 {
                    header: LeaseSet2Header {
                        destination,
                        expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                        is_unpublished: false,
                        offline_signature: None,
                        published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                    },
                    public_keys: vec![sk.public()],
                    leases: vec![lease1.clone(), lease2.clone()],
                }
                .serialize(&sgk),
            );
            let expires = LeaseSet2::parse(&lease_set).unwrap().expires();

            (Bytes::from(id.to_vec()), lease_set, expires)
        };

        netdb.lease_sets.insert(key.clone(), (lease_set, expires));

        let tunnel_id = TunnelId::random();
        let router_id = RouterId::random();

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::LeaseSet)
            .with_reply_type(ReplyType::Tunnel {
                tunnel_id,
                router_id: router_id.clone(),
            })
            .build();

        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseLookup,
                    ..Default::default()
                },
                None
            )
            .is_ok());

        match tm_rx.try_recv().unwrap() {
            TunnelMessage::TunnelDeliveryViaRoute {
                router_id: gateway,
                tunnel_id: dst_tunnel_id,
                message,
                ..
            } => {
                assert_eq!(gateway, router_id);
                assert_eq!(dst_tunnel_id, tunnel_id);

                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseStore);

                match DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap().payload {
                    DatabaseStorePayload::LeaseSet2 { lease_set } => {
                        assert_eq!(key, Bytes::from(lease_set.header.destination.id().to_vec()));
                    }
                    _ => panic!("invalid payload type"),
                }
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn lease_set_query_value_not_found() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<Vec<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let key = Bytes::from(DestinationId::random().to_vec());
        let tunnel_id = TunnelId::random();
        let router_id = RouterId::random();

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::LeaseSet)
            .with_reply_type(ReplyType::Tunnel {
                tunnel_id,
                router_id: router_id.clone(),
            })
            .with_ignored_routers(vec![floodfills[0].clone(), floodfills[1].clone()])
            .build();

        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseLookup,
                    ..Default::default()
                },
                None
            )
            .is_ok());

        match tm_rx.try_recv().unwrap() {
            TunnelMessage::TunnelDeliveryViaRoute {
                router_id: gateway,
                tunnel_id: dst_tunnel_id,
                message,
                ..
            } => {
                assert_eq!(gateway, router_id);
                assert_eq!(dst_tunnel_id, tunnel_id);

                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseSearchReply);

                let message = DatabaseSearchReply::parse(&message.payload).unwrap();

                assert_eq!(message.routers.len(), 1);
                assert_eq!(message.routers[0], floodfills[2]);
                assert_eq!(message.from, netdb.router_ctx.router_id().to_vec());
                assert_eq!(message.key, key);
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn router_info_query() {
        let (mut service, _rx, tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // register new router into `service`
        let router_id = RouterId::random();
        let (conn_tx, conn_rx) = channel(16);
        tx.send(InnerSubsystemEvent::ConnectionEstablished {
            router: router_id.clone(),
            tx: conn_tx,
        })
        .await
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), service.next()).await;

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    - Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };
        netdb.router_infos.insert(key.clone(), (router_info, Duration::from_secs(10)));

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Router)
            .with_reply_type(ReplyType::Router {
                router_id: router_id.clone(),
            })
            .build();

        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseLookup,
                    ..Default::default()
                },
                None
            )
            .is_ok());

        assert!(tm_rx.try_recv().is_err());

        match conn_rx.try_recv().unwrap() {
            SubsystemCommand::SendMessage { message } => {
                let message = Message::parse_short(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseStore);

                match DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap().payload {
                    DatabaseStorePayload::RouterInfo { router_info } => {
                        assert_eq!(key, Bytes::from(router_info.identity.id().to_vec()));
                    }
                    _ => panic!("invalid payload type"),
                }
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn router_info_query_value_not_found() {
        let (mut service, _rx, tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // register new router into `service`
        let router_id = RouterId::random();
        let (conn_tx, conn_rx) = channel(16);
        tx.send(InnerSubsystemEvent::ConnectionEstablished {
            router: router_id.clone(),
            tx: conn_tx,
        })
        .await
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), service.next()).await;

        // add few floodfills to router storage
        let floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<Vec<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let key = Bytes::from(RouterId::random().to_vec());
        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Router)
            .with_reply_type(ReplyType::Router {
                router_id: router_id.clone(),
            })
            .with_ignored_routers(vec![floodfills[0].clone(), floodfills[2].clone()])
            .build();

        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseLookup,
                    ..Default::default()
                },
                None
            )
            .is_ok());

        assert!(tm_rx.try_recv().is_err());

        match conn_rx.try_recv().unwrap() {
            SubsystemCommand::SendMessage { message } => {
                let message = Message::parse_short(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseSearchReply);

                let message = DatabaseSearchReply::parse(&message.payload).unwrap();

                assert_eq!(message.routers.len(), 1);
                assert_eq!(message.routers[0], floodfills[1]);
                assert_eq!(message.from, netdb.router_ctx.router_id().to_vec());
                assert_eq!(message.key, key);
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn pending_messages_sent_when_floodfill_connects() {
        let (service, _rx, tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                serialized.clone(),
                static_key,
                signing_key.clone(),
                2u8,
                event_handle.clone(),
            ),
            false,
            service,
            tp_handle,
            msg_rx,
        );

        // publish local router info
        handle.publish_router_info(router_info.identity.id(), serialized);

        // wait until netdb processes the publish request
        tokio::time::timeout(Duration::from_secs(5), &mut netdb).await.unwrap_err();

        let selected_floodfill = netdb
            .routers
            .iter()
            .find(|(_, state)| match state {
                RouterState::Dialing { pending_messages } if pending_messages.len() == 1 => true,
                _ => false,
            })
            .unwrap()
            .0;

        // register the selected floodfill into netdb
        let (conn_tx, conn_rx) = channel(16);
        tx.send(InnerSubsystemEvent::ConnectionEstablished {
            router: selected_floodfill.clone(),
            tx: conn_tx,
        })
        .await
        .unwrap();

        let future = async {
            loop {
                tokio::select! {
                    _ = &mut netdb => {}
                    event = conn_rx.recv() => match event.unwrap() {
                        SubsystemCommand::SendMessage { message } => break message,
                        _ => panic!("invalid command"),
                    }
                }
            }
        };

        let message = tokio::time::timeout(Duration::from_secs(2), future).await.unwrap();
        let message = Message::parse_short(&message).unwrap();

        assert_eq!(message.message_type, MessageType::DatabaseStore);
        assert!(DatabaseStore::<MockRuntime>::parse(&message.payload).is_some());
    }

    #[tokio::test]
    async fn expired_pending_lease_sets_not_flooded() {
        let (service, rx, tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key1, expired_lease_set1) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: Duration::from_secs(5).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let (key2, valid_lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[2u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: (MockRuntime::time_since_epoch() - Duration::from_secs(60))
                                .as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        // store first lease set that is about to expire
        let reply_router = RouterId::random();
        {
            let message = DatabaseStoreBuilder::new(
                key1,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: expired_lease_set1,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: reply_router.clone(),
            })
            .build();

            assert!(netdb.lease_sets.is_empty());
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 1);
            assert_eq!(netdb.routers.len(), 4);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!((0..3).all(|_| match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert!(floodfills.remove(&router_id));
                    true
                }
                _ => false,
            }));
            assert!(netdb.routers.values().all(|state| match state {
                RouterState::Dialing { pending_messages } => {
                    assert_eq!(pending_messages.len(), 1);
                    true
                }
                _ => false,
            }));
        }

        // store second expiring lease set and verify floodfills are pending
        {
            let reply_router = RouterId::random();
            let message = DatabaseStoreBuilder::new(
                key2.clone(),
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: valid_lease_set,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: reply_router.clone(),
            })
            .build();

            assert_eq!(netdb.lease_sets.len(), 1);
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 2);
            assert_eq!(netdb.routers.len(), 5);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.router_ctx.profile_storage().is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 2);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }
                    true
                }
                _ => false,
            }));
        }

        // wait for 10 seconds so the first lease set expires
        tokio::time::sleep(Duration::from_secs(10)).await;

        // register all floodfills to netdb and spawn it int the background
        let channels = floodfills
            .iter()
            .map(|router_id| {
                let (conn_tx, conn_rx) = channel(16);
                tx.try_send(InnerSubsystemEvent::ConnectionEstablished {
                    router: router_id.clone(),
                    tx: conn_tx,
                })
                .unwrap();

                conn_rx
            })
            .collect::<Vec<_>>();
        tokio::spawn(netdb);

        // verify that all floodfillls receive one lease set store, for the still valid lease set
        for channel in channels {
            match tokio::time::timeout(Duration::from_secs(1), channel.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                SubsystemCommand::SendMessage { message } => {
                    let message = Message::parse_short(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::DatabaseStore);

                    let DatabaseStore { key, payload, .. } =
                        DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                    assert_eq!(key, key2);
                    assert!(std::matches!(
                        payload,
                        DatabaseStorePayload::LeaseSet2 { .. }
                    ));
                }
                _ => panic!("invalid event"),
            }

            // verify there are no other messages pending
            match tokio::time::timeout(Duration::from_secs(1), channel.recv()).await {
                Err(_) => {}
                _ => panic!("expected timeout"),
            }
        }
    }

    #[tokio::test]
    async fn expired_pending_router_infos_not_flooded() {
        let (service, rx, tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();

                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key1, expiring_router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch() + Duration::from_secs(5))
                                    .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let (key2, valid_router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    + Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        // store first lease set that is about to expire
        let reply_router = RouterId::random();
        {
            let message = DatabaseStoreBuilder::new(
                key1,
                DatabaseStoreKind::RouterInfo {
                    router_info: expiring_router_info,
                },
            )
            .with_reply_type(StoreReplyType::Router {
                reply_token: MockRuntime::rng().next_u32(),
                router_id: reply_router.clone(),
            })
            .build();

            assert!(netdb.lease_sets.is_empty());
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.router_infos.len(), 1);
            assert_eq!(netdb.routers.len(), 4);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!((0..3).all(|_| match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert!(floodfills.remove(&router_id));
                    true
                }
                _ => false,
            }));
            assert!(netdb.routers.values().all(|state| match state {
                RouterState::Dialing { pending_messages } => {
                    assert_eq!(pending_messages.len(), 1);
                    true
                }
                _ => false,
            }));
        }

        // store second expiring lease set and verify floodfills are pending
        let reply_router = RouterId::random();
        {
            let message = DatabaseStoreBuilder::new(
                key2.clone(),
                DatabaseStoreKind::RouterInfo {
                    router_info: valid_router_info,
                },
            )
            .with_reply_type(StoreReplyType::Router {
                reply_token: MockRuntime::rng().next_u32(),
                router_id: reply_router.clone(),
            })
            .build();

            assert_eq!(netdb.router_infos.len(), 1);
            assert!(netdb
                .on_message(
                    Message {
                        payload: message.to_vec(),
                        message_type: MessageType::DatabaseStore,
                        ..Default::default()
                    },
                    None
                )
                .is_ok());
            assert_eq!(netdb.router_infos.len(), 2);
            assert_eq!(netdb.routers.len(), 5);
            match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router_id } => {
                    assert_eq!(router_id, reply_router);
                }
                _ => panic!("invalid event"),
            }
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.router_ctx.profile_storage().is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 2);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }
                    true
                }
                _ => false,
            }));
        }

        // wait for 10 seconds so the first lease set expires
        tokio::time::sleep(Duration::from_secs(10)).await;

        // register all floodfills to netdb and spawn it int the background
        let channels = floodfills
            .iter()
            .map(|router_id| {
                let (conn_tx, conn_rx) = channel(16);
                tx.try_send(InnerSubsystemEvent::ConnectionEstablished {
                    router: router_id.clone(),
                    tx: conn_tx,
                })
                .unwrap();

                conn_rx
            })
            .collect::<Vec<_>>();
        tokio::spawn(netdb);

        // verify that all floodfillls receive one lease set store, for the still valid lease set
        for channel in channels {
            match tokio::time::timeout(Duration::from_secs(1), channel.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                SubsystemCommand::SendMessage { message } => {
                    let message = Message::parse_short(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::DatabaseStore);

                    let DatabaseStore { key, payload, .. } =
                        DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                    assert_eq!(key, key2);
                    assert!(std::matches!(
                        payload,
                        DatabaseStorePayload::RouterInfo { .. }
                    ));
                }
                _ => panic!("invalid event"),
            }

            // verify there are no other messages pending
            match tokio::time::timeout(Duration::from_secs(1), channel.recv()).await {
                Err(_) => {}
                _ => panic!("expected timeout"),
            }
        }
    }

    #[tokio::test]
    async fn router_info_with_different_network_id_ignored() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch() - Duration::from_secs(60))
                                    .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("99")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 99,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info }).build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert!(netdb.router_infos.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn lease_set_store_with_zero_reply_token() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                            is_unpublished: false,
                            offline_signature: None,
                            published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set }).build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert_eq!(netdb.lease_sets.len(), 1);
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn router_info_store_with_zero_reply_token() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    + Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: Mapping::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info }).build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(
                Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                },
                None
            )
            .is_ok());
        assert_eq!(netdb.router_infos.len(), 1);
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn recursive_lease_set_query_with_duplicate_floodfills() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<VecDeque<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        netdb
            .message_builder
            .inbound_tunnels
            .add_tunnel(LeaseSet2::random().0.leases[0].clone());
        netdb.message_builder.outbound_tunnels.add_tunnel(TunnelId::random());

        let (lease_set, _signing_key) = LeaseSet2::random();
        let key = Bytes::from(lease_set.header.destination.id().to_vec());
        let (res_tx, mut res_rx) = oneshot::channel();

        // destination asks netdb to query a lease set
        //
        // netdb sends the query to three floodfills
        netdb.query_lease_set(key.clone(), res_tx);
        match netdb.active.get(&key) {
            Some(QueryKind::LeaseSet { query }) => {
                assert_eq!(query.queried.len(), 1);
            }
            _ => panic!("invalid state"),
        }
        assert!(std::matches!(
            tm_rx.try_recv().unwrap(),
            TunnelMessage::RouterDeliveryViaRoute { .. }
        ));

        // create database search reply indicating the lease set was not found
        let closest = (0..3).map(|_| RouterId::random()).collect::<Vec<_>>();

        netdb
            .on_message(
                Message {
                    message_type: MessageType::DatabaseSearchReply,
                    message_id: MockRuntime::rng().next_u32(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: DatabaseSearchReply {
                        from: floodfills.pop_front().unwrap().to_vec(),
                        key: key.clone(),
                        routers: closest.clone(),
                    }
                    .serialize()
                    .to_vec(),
                },
                None,
            )
            .unwrap();
        match netdb.active.get(&key) {
            Some(QueryKind::LeaseSet { query }) => {
                assert_eq!(query.queried.len(), 1);
                assert_eq!(query.pending.len(), 3);
            }
            _ => panic!("invalid state"),
        }

        // ensure there are 4 queries, one for the leaset and three for the closest floodfills
        assert_eq!(netdb.active.len(), 4);
        assert!(
            netdb.active.iter().filter(|(k, _)| k != &&key).all(|(k, kind)| std::matches!(
                kind,
                QueryKind::Router,
            ) && closest
                .contains(&RouterId::from(k.as_ref())))
        );

        // create second database search reply indicating the lease set was not found
        netdb
            .on_message(
                Message {
                    message_type: MessageType::DatabaseSearchReply,
                    message_id: MockRuntime::rng().next_u32(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: DatabaseSearchReply {
                        from: floodfills.pop_front().unwrap().to_vec(),
                        key: key.clone(),
                        routers: closest.clone(),
                    }
                    .serialize()
                    .to_vec(),
                },
                None,
            )
            .unwrap();
        match netdb.active.get(&key) {
            Some(QueryKind::LeaseSet { query }) => {
                // 1 queried floodfill + 3 pending router lookups
                assert_eq!(query.queried.len(), 1);
                assert_eq!(query.pending.len(), 3);
            }
            _ => panic!("invalid state"),
        }

        // ensure there are 7 queries, one for the leaset and 6 for the recursive queries
        assert_eq!(netdb.active.len(), 4);
        assert!(
            netdb.active.iter().filter(|(k, _)| k != &&key).all(|(k, kind)| std::matches!(
                kind,
                QueryKind::Router,
            ) && closest
                .contains(&RouterId::from(k.as_ref())))
        );

        netdb
            .on_message(
                Message {
                    message_type: MessageType::DatabaseSearchReply,
                    message_id: MockRuntime::rng().next_u32(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: DatabaseSearchReply {
                        from: floodfills.pop_front().unwrap().to_vec(),
                        key: key.clone(),
                        routers: closest.clone(),
                    }
                    .serialize()
                    .to_vec(),
                },
                None,
            )
            .unwrap();

        assert!(res_rx.try_recv().unwrap().is_none());
        assert!(netdb.active.get(&key).is_some());
        assert_eq!(netdb.active.len(), 4);
        assert!(
            netdb.active.iter().filter(|(k, _)| k != &&key).all(|(k, kind)| std::matches!(
                kind,
                QueryKind::Router
            ) && closest
                .contains(&RouterId::from(k.as_ref())))
        );
    }

    #[tokio::test]
    async fn local_router_info_store() {
        let (service, rx, subsys_tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                serialized.clone(),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        // publish local router info and poll netdb so the request is handled
        handle.publish_router_info(router_info.identity.id(), serialized.clone());
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut netdb).await.is_err());

        // verify all floodfills are being dialed
        assert!(netdb.routers.iter().all(|(id, state)| match state {
            RouterState::Dialing { pending_messages } if pending_messages.len() == 1 => {
                floodfills.contains(id)
            }
            _ => false,
        }));
        assert!((0..3).all(|_| match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router_id } => floodfills.contains(&router_id),
            _ => false,
        }));

        // register floodfills
        let receivers = floodfills
            .iter()
            .map(|router_id| {
                let (tx, rx) = channel(64);

                subsys_tx
                    .try_send(InnerSubsystemEvent::ConnectionEstablished {
                        router: router_id.clone(),
                        tx,
                    })
                    .unwrap();
                rx
            })
            .collect::<Vec<_>>();

        // poll netdb so the pending messages get sent to floodfills
        // and verify all floodfills get a database store message for the local router info
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut netdb).await.is_err());
        assert!(
            receivers.into_iter().all(|rx| match rx.try_recv().unwrap() {
                SubsystemCommand::SendMessage { message } => {
                    let message = Message::parse_short(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::DatabaseStore);

                    let store = DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                    match store.payload {
                        DatabaseStorePayload::RouterInfo { .. } => {
                            let raw_router_info =
                                DatabaseStore::<MockRuntime>::extract_raw_router_info(
                                    &message.payload,
                                );
                            let decompressed =
                                MockRuntime::gzip_decompress(&raw_router_info).unwrap();

                            assert_eq!(&decompressed, &serialized);

                            true
                        }
                        DatabaseStorePayload::LeaseSet2 { .. } => false,
                    }
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn router_exploration_works() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let floodfills = (0..3)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            false,
            service,
            tp_handle,
            msg_rx,
        );

        netdb
            .message_builder
            .inbound_tunnels
            .add_tunnel(LeaseSet2::random().0.leases[0].clone());
        netdb.message_builder.outbound_tunnels.add_tunnel(TunnelId::random());

        // set shorter timeout for exploration and wait until netdb sends exploration request
        netdb.exploration_timer = Some(Box::pin(tokio::time::sleep(Duration::from_secs(1))));
        tokio::time::timeout(Duration::from_secs(3), &mut netdb).await.unwrap_err();

        match tm_rx.try_recv().unwrap() {
            TunnelMessage::RouterDeliveryViaRoute {
                router_id, message, ..
            } => {
                assert!(floodfills.contains(&router_id));
                let Message {
                    payload,
                    message_type,
                    ..
                } = Message::parse_standard(&message).unwrap();

                assert_eq!(message_type, MessageType::DatabaseLookup);
                assert_eq!(
                    DatabaseLookup::parse(&payload).unwrap().lookup,
                    LookupType::Exploration
                );
            }
            _ => panic!("invalid message received"),
        }
    }

    #[tokio::test]
    async fn duplicate_lease_set_query() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..5)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        netdb
            .message_builder
            .inbound_tunnels
            .add_tunnel(LeaseSet2::random().0.leases[0].clone());
        netdb.message_builder.outbound_tunnels.add_tunnel(TunnelId::random());

        // query random lease set and verify that a query has started
        let remote = Bytes::from(DestinationId::random().to_vec());
        let mut rx1 = handle.query_lease_set(remote.clone()).unwrap();

        // wait until the query has been started
        tokio::time::timeout(Duration::from_secs(2), &mut netdb).await.unwrap_err();
        assert!(netdb.active.contains_key(&remote));
        assert!(rx1.try_recv().unwrap().is_none());

        // send another query for the same lease set and verify the first query is still active
        let mut rx2 = handle.query_lease_set(remote.clone()).unwrap();

        // register new query to netdb
        tokio::time::timeout(Duration::from_secs(2), &mut netdb).await.unwrap_err();

        assert!(rx1.try_recv().unwrap().is_none());
        assert!(rx2.try_recv().unwrap().is_none());

        // poll netdb until the query times out
        tokio::time::timeout(Duration::from_secs(15), &mut netdb).await.unwrap_err();

        match rx1.try_recv() {
            Ok(Some(Err(QueryError::NoFloodfills))) => {}
            _ => panic!("invalid value"),
        }

        match rx2.try_recv() {
            Ok(Some(Err(QueryError::NoFloodfills))) => {}
            _ => panic!("invalid value"),
        }
    }

    #[tokio::test]
    async fn duplicate_router_info_query() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..5)
            .map(|_| {
                let info = RouterInfoBuilder::default().as_floodfill().build().0;
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_msg_tx, msg_rx) = channel(64);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut netdb, handle) = NetDb::<MockRuntime>::new(
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            service,
            tp_handle,
            msg_rx,
        );

        netdb
            .message_builder
            .inbound_tunnels
            .add_tunnel(LeaseSet2::random().0.leases[0].clone());
        netdb.message_builder.outbound_tunnels.add_tunnel(TunnelId::random());

        // query random router info and verify that a query has started
        let remote = RouterId::random();
        let remote_key = Bytes::from(remote.to_vec());
        let mut rx1 = handle.try_query_router_info(remote.clone()).unwrap();

        // wait until the query has been started
        tokio::time::timeout(Duration::from_secs(2), &mut netdb).await.unwrap_err();
        assert!(netdb.active.contains_key(&remote_key));
        assert!(rx1.try_recv().unwrap().is_none());

        // send another query for the same router info and verify the first query is still active
        let mut rx2 = handle.try_query_router_info(remote.clone()).unwrap();

        // register new query to netdb
        tokio::time::timeout(Duration::from_secs(2), &mut netdb).await.unwrap_err();

        assert!(rx1.try_recv().unwrap().is_none());
        assert!(rx2.try_recv().unwrap().is_none());

        // poll netdb until the query times out
        tokio::time::timeout(Duration::from_secs(15), &mut netdb).await.unwrap_err();

        match rx1.try_recv() {
            Ok(Some(Err(QueryError::NoFloodfills))) => {}
            _ => panic!("invalid value"),
        }

        match rx2.try_recv() {
            Ok(Some(Err(QueryError::NoFloodfills))) => {}
            _ => panic!("invalid value"),
        }
    }
}
