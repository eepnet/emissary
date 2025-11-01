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

//! Tunnel pool context.

use crate::{
    error::{ChannelError, RoutingError},
    i2np::{Message, MessageType},
    primitives::{Lease, MessageId, RouterId, TunnelId},
    tunnel::pool::{TunnelPoolConfig, TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::Bytes;
use futures::Stream;
use futures_channel::oneshot;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec::Vec};
use core::{
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::context";

/// Channel size for the client -> pool channel size.
///
/// The size of this channel needs to be large because it's shared by all of the outbound tunnels of
/// the tunnel pool for outbound messages.
const TUNNEL_CHANNEL_SIZE: usize = 4096usize;

/// Message listeners.
///
/// The two additional mappings (garlic <-> `MessageId`) are used associate encrypted/unecrypted
/// outbound tunnel build responses with correct message listener.
#[derive(Default)]
struct MessageListeners {
    /// Message listeners.
    listeners: HashMap<MessageId, oneshot::Sender<Message>>,

    /// Garlic tag -> `MessageId` mappings.
    garlic_tags: HashMap<Bytes, MessageId>,

    /// `MessageId` -> garlic tag mappings.
    message_ids: HashMap<MessageId, Bytes>,
}

/// Tunnel pool handle.
#[derive(Clone)]
pub struct TunnelPoolContextHandle {
    /// Message listeners.
    listeners: Arc<RwLock<MessageListeners>>,

    /// TX channel for sending messages to the subscriber of the tunnel pool.
    event_tx: mpsc::Sender<TunnelPoolEvent>,

    /// TX channel for sending messages via one of the pool's outbound tunnels to remote routers.
    tx: mpsc::Sender<TunnelMessage, TunnelMessageRecycle>,
}

impl TunnelPoolContextHandle {
    /// Send `message` to `router_id` via an outbound tunnel identified by `gateway` and inform
    /// the caller via `feedback` if dialing the router succeeded.
    pub fn send_to_router_with_feedback(
        &self,
        gateway: TunnelId,
        router_id: RouterId,
        message: Vec<u8>,
        feedback_tx: oneshot::Sender<()>,
    ) -> Result<(), ChannelError> {
        self.tx
            .try_send(TunnelMessage::RouterDelivery {
                gateway,
                router_id,
                message,
                feedback_tx: Some(feedback_tx),
            })
            .map_err(From::from)
    }

    /// Send `message `via one of the tunnel pool's outbound tunnels to remote tunnel identified by
    /// (`gateway`, `tunnel_id`) tuple.
    #[allow(unused)]
    pub fn send_to_tunnel(
        &self,
        gateway: RouterId,
        tunnel_id: TunnelId,
        message: Vec<u8>,
    ) -> Result<(), ChannelError> {
        self.tx
            .try_send(TunnelMessage::TunnelDelivery {
                gateway,
                tunnel_id,
                message,
            })
            .map_err(From::from)
    }

    /// Route `message` received into an inbound tunnel of the tunnel pool.
    ///
    /// Message is routed to an existing listener if one exists for the message and if there are no
    /// installed listeners, the message is routed to `TunnelPool` for further processing.
    ///
    /// If the message is a garlic clove and the [`TunnelPoolContextHandle`] belongs to a client
    /// session the clove is forwarded to the session without routing through [`TunnelPool`].
    pub fn route_message(&self, message: Message) -> Result<(), RoutingError> {
        let mut inner = self.listeners.write();
        let message_id = MessageId::from(message.message_id);

        // if the message is a garlic message, try to associate the garlic message with a pending
        // tunnel build
        //
        // if the message is an unecrypted tunnel build reply, remove garlic tag <-> message id
        // association context
        let message_id = match message.message_type {
            MessageType::Garlic => {
                let garlic_tag = Bytes::from(message.payload[4..12].to_vec());

                match inner.garlic_tags.remove(&garlic_tag) {
                    Some(message_id) => {
                        let _value = inner.message_ids.remove(&message_id);
                        debug_assert!(_value == Some(garlic_tag));

                        message_id
                    }
                    None => match inner.listeners.remove(&message_id) {
                        Some(listener) =>
                            return listener.send(message).map_err(RoutingError::ChannelClosed),
                        None =>
                            return self
                                .event_tx
                                .try_send(TunnelPoolEvent::Message { message })
                                .map_err(|error| {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        ?message_id,
                                        ?error,
                                        "failed to route garlic message to client destination",
                                    );

                                    match error {
                                        mpsc::errors::TrySendError::Full(
                                            TunnelPoolEvent::Message { message },
                                        ) => RoutingError::ChannelFull(message),
                                        mpsc::errors::TrySendError::Closed(
                                            TunnelPoolEvent::Message { message },
                                        ) => RoutingError::ChannelClosed(message),
                                        _ => unreachable!(),
                                    }
                                }),
                    },
                }
            }
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => {
                return self.event_tx.try_send(TunnelPoolEvent::Message { message }).map_err(
                    |error| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?message_id,
                            ?error,
                            "failed to route netdb message",
                        );

                        match error {
                            mpsc::errors::TrySendError::Full(TunnelPoolEvent::Message {
                                message,
                            }) => RoutingError::ChannelFull(message),
                            mpsc::errors::TrySendError::Closed(TunnelPoolEvent::Message {
                                message,
                            }) => RoutingError::ChannelClosed(message),
                            _ => unreachable!(),
                        }
                    },
                );
            }
            MessageType::OutboundTunnelBuildReply => {
                inner
                    .message_ids
                    .remove(&message_id)
                    .map(|garlic_tag| inner.garlic_tags.remove(&garlic_tag));

                message_id
            }
            _ => message_id,
        };

        match inner.listeners.remove(&message_id) {
            Some(listener) => listener.send(message).map_err(RoutingError::ChannelClosed),
            // TODO: is this necessary?
            None =>
                self.tx
                    .try_send(TunnelMessage::Inbound { message })
                    .map_err(|error| match error {
                        mpsc::errors::TrySendError::Full(TunnelMessage::Inbound { message }) =>
                            RoutingError::ChannelFull(message),
                        mpsc::errors::TrySendError::Closed(TunnelMessage::Inbound { message }) =>
                            RoutingError::ChannelClosed(message),
                        _ => unreachable!(),
                    }),
        }
    }

    /// Allocate new (MessageId, Receiver<Message>)` tuple for an inbound build response.
    pub fn add_listener(&self, rng: &mut impl RngCore) -> (MessageId, oneshot::Receiver<Message>) {
        let mut inner = self.listeners.write();
        let (tx, rx) = oneshot::channel();

        loop {
            let message_id = MessageId::from(rng.next_u32());

            if !inner.listeners.contains_key(&message_id) {
                inner.listeners.insert(message_id, tx);

                return (message_id, rx);
            }
        }
    }

    /// Associate `garlic_tag` with `message_id`.
    ///
    /// This is needed for outbound tunnel build responses which may be garlic encrypted, meaning
    /// the `MessageId` of the garlic message has a different `MessageId` than then one that has a
    /// listener installed for it.
    ///
    /// Since the router is free to either encrypt the message or not, `TunnelHandle` must be
    /// prepared to reply the tunnel build response in either form.
    pub fn add_garlic_listener(&self, message_id: MessageId, garlic_tag: Bytes) {
        let mut inner = self.listeners.write();

        debug_assert!(inner.listeners.contains_key(&message_id));

        inner.garlic_tags.insert(garlic_tag.clone(), message_id);
        inner.message_ids.insert(message_id, garlic_tag);
    }

    /// Remove listener for `message_id` from listeners.
    pub fn remove_listener(&self, message_id: &MessageId) {
        let mut inner = self.listeners.write();

        inner.listeners.remove(message_id);
        inner
            .message_ids
            .remove(message_id)
            .map(|garlic_tag| inner.garlic_tags.remove(&garlic_tag));
    }
}

#[derive(Debug, Default, Clone)]
pub struct TunnelMessageRecycle(());

impl thingbuf::Recycle<TunnelMessage> for TunnelMessageRecycle {
    fn new_element(&self) -> TunnelMessage {
        TunnelMessage::Dummy
    }

    fn recycle(&self, element: &mut TunnelMessage) {
        *element = TunnelMessage::Dummy
    }
}

#[derive(Default)]
pub enum TunnelMessage {
    /// I2NP message received into one of the pool's inbound tunnels
    ///
    /// This message needs to be routed internally to either one of the installed listeners or to
    /// the destination of the tunnel pool.
    Inbound {
        /// Message
        message: Message,
    },

    /// Send message to remote router via an outbound tunnel of the pool.
    RouterDelivery {
        /// Outbound gateway through which `message` should be sent.
        gateway: TunnelId,

        /// ID of the router to whom the message should be sent.
        router_id: RouterId,

        /// Serialize I2NP message.
        message: Vec<u8>,

        /// Feedback channel to inform the caller whether the router was dialed successfully.
        feedback_tx: Option<oneshot::Sender<()>>,
    },

    /// Send message to remote inbound tunnel via one of the outbound tunnels of the pool.
    TunnelDelivery {
        /// Outbound gateway through which `message` should be sent.
        gateway: RouterId,

        /// ID of the inbound tunnel gateway.
        tunnel_id: TunnelId,

        /// Serialize I2NP message.
        message: Vec<u8>,
    },

    /// Router delivery, potentially via a specified outbound tunnel.
    RouterDeliveryViaRoute {
        /// `RouterId` of the recipient.
        router_id: RouterId,

        /// Outbound tunnel over which the message should be sent, if specified.
        outbound_tunnel: Option<TunnelId>,

        /// Message.
        message: Vec<u8>,
    },

    /// Tunnel delivery.
    TunnelDeliveryViaRoute {
        /// ID of the IBGW router.
        router_id: RouterId,

        /// ID of the IBGW tunnel.
        tunnel_id: TunnelId,

        /// Outbound tunnel over which the message should be sent, if specified.
        outbound_tunnel: Option<TunnelId>,

        /// Message.
        message: Vec<u8>,
    },

    #[default]
    Dummy,
}

/// Tunnel pool context.
pub struct TunnelPoolContext {
    /// Message listeners.
    listeners: Arc<RwLock<MessageListeners>>,

    /// TX channel for sending messages to the subscriber of the tunnel pool.
    event_tx: mpsc::Sender<TunnelPoolEvent>,

    /// RX channel for receiving messages destined to remote routers.
    rx: mpsc::Receiver<TunnelMessage, TunnelMessageRecycle>,

    /// TX channel given to pool's inbound tunnels, allowing them to send received I2NP messages to
    /// [`TunnelPool`] for routing.
    tx: mpsc::Sender<TunnelMessage, TunnelMessageRecycle>,
}

impl TunnelPoolContext {
    /// Allocate new (`MessageId`, `oneshot::Receiver<Message>)` tuple for an inbound build
    /// response.
    pub fn add_listener(&self, rng: &mut impl RngCore) -> (MessageId, oneshot::Receiver<Message>) {
        let mut inner = self.listeners.write();
        let (tx, rx) = oneshot::channel();

        loop {
            let message_id = MessageId::from(rng.next_u32());

            if !inner.listeners.contains_key(&message_id) {
                inner.listeners.insert(message_id, tx);

                return (message_id, rx);
            }
        }
    }

    /// Remove listener for `message_id` from listeners.
    pub fn remove_listener(&self, message_id: &MessageId) {
        let mut inner = self.listeners.write();

        inner.listeners.remove(message_id);
        inner
            .message_ids
            .remove(message_id)
            .map(|garlic_tag| inner.garlic_tags.remove(&garlic_tag));
    }

    /// Allocate new [`TunnelPoolContextHandle`] for the context.
    pub fn context_handle(&self) -> TunnelPoolContextHandle {
        TunnelPoolContextHandle {
            listeners: Arc::clone(&self.listeners),
            event_tx: self.event_tx.clone(),
            tx: self.tx.clone(),
        }
    }

    /// Inform the tunnel pool creator that the tunnel pool has been shut down.
    pub fn register_tunnel_pool_shut_down(&self) -> Result<(), ChannelError> {
        self.event_tx.try_send(TunnelPoolEvent::TunnelPoolShutDown).map_err(From::from)
    }

    /// Inform the tunnel pool creator that an inbound tunnel has been built.
    ///
    /// `tunnel_id` refers to the IBGW of the newly built tunnel.
    pub fn register_inbound_tunnel_built(
        &self,
        tunnel_id: TunnelId,
        lease: Lease,
    ) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })
            .map_err(From::from)
    }

    /// Inform the tunnel pool creator that an outbound tunnel has been built.
    ///
    /// `tunnel_id` refers to the OBGW of the newly built tunnel.
    pub fn register_outbound_tunnel_built(&self, tunnel_id: TunnelId) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })
            .map_err(From::from)
    }

    /// Inform the tunnel pool creator that an inbound tunnel has expired.
    ///
    /// `tunnel_id` refers to the IBGW of the newly built tunnel.
    pub fn register_inbound_tunnel_expired(&self, tunnel_id: TunnelId) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })
            .map_err(From::from)
    }

    /// Inform the tunnel pool creator that an outbound tunnel has expired.
    ///
    /// `tunnel_id` refers to the OBGW of the newly built tunnel.
    pub fn register_outbound_tunnel_expired(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })
            .map_err(From::from)
    }

    /// Inform the tunnel pool creator that an inbound tunnel is about to expire.
    ///
    /// `tunnel_id` refers to the IBGW of the newly built tunnel.
    pub fn register_expiring_inbound_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(TunnelPoolEvent::InboundTunnelExpiring { tunnel_id })
            .map_err(From::from)
    }

    /// Inform the tunnel pool creator that an outbound tunnel is about to expire.
    ///
    /// `tunnel_id` refers to the OBGW of the newly built tunnel.
    pub fn register_expiring_outbound_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(TunnelPoolEvent::OutboundTunnelExpiring { tunnel_id })
            .map_err(From::from)
    }
}

impl Stream for TunnelPoolContext {
    type Item = TunnelMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// Tunnel pool build parameters.
///
/// Parameters that are needed to build a tunnel pool.
pub struct TunnelPoolBuildParameters {
    /// Tunnel pool configuration.
    pub config: TunnelPoolConfig,

    /// Tunnel pool context.
    ///
    /// Given to `TunnelPool` TODO
    pub context: TunnelPoolContext,

    /// Tunnel pool context handle.
    ///
    /// Given to tunnels of the pool for communicating with `TunnelPool`.
    pub context_handle: TunnelPoolContextHandle,

    /// One-shot RX channel that is used by the subscriber of the pool to shut down the pool.
    pub shutdown_rx: oneshot::Receiver<()>,

    /// Tunnel pool handle.
    ///
    /// Given to the creator/user of the tunnel pool.
    ///
    /// Exploratory tunnel pool handle is given to `NetDb` and "client pool handles"
    /// are given to destinations when they create a new tunnel pool.
    pub tunnel_pool_handle: TunnelPoolHandle,
}

impl TunnelPoolBuildParameters {
    /// Create new [`TunnelPoolBuildParameters`].
    pub fn new(config: TunnelPoolConfig) -> Self {
        let listeners = Arc::new(RwLock::new(MessageListeners::default()));
        let (tx, rx) = mpsc::with_recycle(TUNNEL_CHANNEL_SIZE, TunnelMessageRecycle::default());
        let (tunnel_pool_handle, event_tx, shutdown_rx) =
            TunnelPoolHandle::new(config.clone(), tx.clone());

        Self {
            config,
            context: TunnelPoolContext {
                listeners: Arc::clone(&listeners),
                event_tx: event_tx.clone(),
                rx,
                tx: tx.clone(),
            },
            context_handle: TunnelPoolContextHandle {
                listeners,
                event_tx,
                tx,
            },
            shutdown_rx,
            tunnel_pool_handle,
        }
    }
}
