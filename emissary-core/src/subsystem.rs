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
    crypto::{chachapoly::ChaChaPoly, EphemeralPublicKey},
    error::{ChannelError, RoutingError},
    i2np::{
        garlic::{
            DeliveryInstructions as CloveDeliveryInstructions, GarlicMessage, GarlicMessageBlock,
        },
        tunnel::{data::EncryptedTunnelData, gateway::TunnelGateway},
        Message, MessageBuilder, MessageType,
    },
    primitives::{MessageId, RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{DeliveryInstructions, NoiseContext},
};

use futures_channel::oneshot;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, errors::TrySendError, with_recycle, Receiver, Sender};
use zeroize::Zeroize;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::subsystem";

/// Subsystem event.
#[derive(Default, Debug, Clone)]
pub enum SubsystemEvent {
    /// Connection established.
    ConnectionEstablished {
        /// Router ID.
        router_id: RouterId,

        /// TX channel for sending messages to router.
        tx: Sender<OutboundMessage, OutboundMessageRecycle>,
    },

    /// Connection closed.
    ConnectionClosed {
        /// Router ID.
        router_id: RouterId,
    },

    /// Connection failure.
    ConnectionFailure {
        /// Router ID.
        router_id: RouterId,
    },

    /// One or more I2NP messages.
    Message {
        /// Raw, unparsed I2NP messages
        messages: Vec<(RouterId, Message)>,
    },

    #[default]
    Dummy,
}

/// Subsystem events that are relevant to NetDb.
#[derive(Default, Debug, Clone)]
pub enum NetDbEvent {
    /// Connection established.
    ConnectionEstablished {
        /// Router ID.
        router_id: RouterId,
    },

    /// One or more I2NP messages.
    Message {
        /// Raw, unparsed I2NP messages
        messages: Vec<(RouterId, Message)>,
    },

    #[default]
    Dummy,
}

/// Recycling strategy for [`SubsystemManagerEvent`].
#[derive(Debug, Default, Clone)]
pub struct SubsystemManagerEventRecycle(());

impl thingbuf::Recycle<SubsystemManagerEvent> for SubsystemManagerEventRecycle {
    fn new_element(&self) -> SubsystemManagerEvent {
        SubsystemManagerEvent::Dummy
    }

    fn recycle(&self, element: &mut SubsystemManagerEvent) {
        *element = SubsystemManagerEvent::Dummy;
    }
}

/// Outbound message.
#[derive(Debug, Default)]
pub enum OutboundMessage {
    /// Single I2NP message.
    Message(Message),

    /// One or more I2NP messages.
    #[allow(unused)]
    Messages(Vec<Message>),

    /// Single I2NP message with feedback.
    ///
    /// If sending the message fails, the channel is dropped.
    MessageWithFeedback(Message, oneshot::Sender<()>),

    /// Dummy event.
    #[default]
    Dummy,
}

#[derive(Default, Debug, Clone)]
pub struct OutboundMessageRecycle(());

impl thingbuf::Recycle<OutboundMessage> for OutboundMessageRecycle {
    fn new_element(&self) -> OutboundMessage {
        OutboundMessage::Dummy
    }

    fn recycle(&self, element: &mut OutboundMessage) {
        *element = OutboundMessage::Dummy;
    }
}

/// Subsystem event.
#[derive(Debug, Default)]
pub enum SubsystemManagerEvent {
    /// Send message to router.
    Message {
        /// ID of the remote router.
        router_id: RouterId,

        /// One or more I2NP messages.
        message: OutboundMessage,
    },

    #[default]
    Dummy,
}

#[derive(Debug, Clone)]
pub struct SubsystemHandle {
    /// TX channel for sending events to [`SubsystemManager`].
    event_tx: Sender<SubsystemManagerEvent, SubsystemManagerEventRecycle>,

    /// Installed message listeners.    
    ///
    /// These are used by local tunnel build tasks to capture specific
    /// build-related messages.
    listeners: Arc<RwLock<HashMap<MessageId, oneshot::Sender<Message>>>>,

    /// Should the router throttle itself.
    #[allow(unused)]
    throttle: Arc<AtomicBool>,

    /// Active tunnels.
    tunnels: Arc<RwLock<HashMap<TunnelId, Sender<Message>>>>,
}

impl SubsystemHandle {
    /// Should the subsystem throttle itself.
    ///
    /// True if the router is close to its maximum bandwidth usage.
    #[allow(unused)]
    pub fn should_throttle(&self) -> bool {
        self.throttle.load(Ordering::Relaxed)
    }

    /// Send message to router.
    pub fn send(&self, router_id: &RouterId, message: Message) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(SubsystemManagerEvent::Message {
                router_id: router_id.clone(),
                message: OutboundMessage::Message(message),
            })
            .map_err(From::from)
    }

    /// Send one or more messages to router.
    #[allow(unused)]
    pub fn send_many(
        &self,
        router_id: &RouterId,
        messages: Vec<Message>,
    ) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(SubsystemManagerEvent::Message {
                router_id: router_id.clone(),
                message: OutboundMessage::Messages(messages),
            })
            .map_err(From::from)
    }

    /// Send message to router with feedback.
    ///
    /// If the message was successfully sent, `()` is sent over `feedback_tx` and if there was
    /// an error with sending the message, e.g., connection failure or the message was dropped,
    /// the channel is dropped.
    pub fn send_with_feedback(
        &self,
        router_id: &RouterId,
        message: Message,
        feedback_tx: oneshot::Sender<()>,
    ) -> Result<(), ChannelError> {
        self.event_tx
            .try_send(SubsystemManagerEvent::Message {
                router_id: router_id.clone(),
                message: OutboundMessage::MessageWithFeedback(message, feedback_tx),
            })
            .map_err(From::from)
    }

    /// Register listener into `SubsystemManager`'s routing table and return the unique
    /// message ID and the receive half of the registered channel.
    pub fn insert_listener(
        &self,
        rng: &mut impl RngCore,
    ) -> (MessageId, oneshot::Receiver<Message>) {
        let (tx, rx) = oneshot::channel();
        let mut listeners = self.listeners.write();

        loop {
            let message_id = MessageId::from(rng.next_u32());

            if !listeners.contains_key(&message_id) {
                listeners.insert(message_id, tx);
                return (message_id, rx);
            }
        }
    }

    /// Register tunnel into `SubsystemManager`'s routing table and return the unique
    /// tunnel ID and the channel the IBGW will use to receive messages.
    pub fn insert_tunnel<const SIZE: usize>(
        &self,
        rng: &mut impl RngCore,
    ) -> (TunnelId, Receiver<Message>) {
        let (tx, rx) = channel(SIZE);
        let mut tunnels = self.tunnels.write();

        loop {
            let tunnel_id = TunnelId::from(rng.next_u32());

            if !tunnels.contains_key(&tunnel_id) {
                tunnels.insert(tunnel_id, tx);
                return (tunnel_id, rx);
            }
        }
    }

    /// Unregister tunnel identified by  `tunnel_id` from routing table.
    pub fn remove_tunnel(&self, tunnel_id: &TunnelId) {
        self.tunnels.write().remove(tunnel_id);
    }

    /// Remove listener identified by `message_id` from routing table.
    pub fn remove_listener(&self, message_id: &MessageId) {
        self.listeners.write().remove(message_id);
    }

    /// Attempt to register tunnel with `tunnel_id` and return `Ok(receiver)` if `tunnel_id`
    /// is not taken.
    ///
    /// If `Err(RoutingError)` is returned, the tunnel is not added to routing table.
    pub fn try_insert_tunnel<const SIZE: usize>(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<Receiver<Message>, RoutingError> {
        let mut tunnels = self.tunnels.write();

        match tunnels.contains_key(&tunnel_id) {
            true => Err(RoutingError::TunnelExists(tunnel_id)),
            false => {
                let (tx, rx) = channel(SIZE);
                tunnels.insert(tunnel_id, tx);

                Ok(rx)
            }
        }
    }

    #[cfg(test)]
    pub fn new() -> (
        Self,
        Receiver<SubsystemManagerEvent, SubsystemManagerEventRecycle>,
    ) {
        let (event_tx, event_rx) = with_recycle(100, SubsystemManagerEventRecycle::default());

        (
            Self {
                event_tx,
                listeners: Default::default(),
                throttle: Default::default(),
                tunnels: Default::default(),
            },
            event_rx,
        )
    }
}

/// Router state.
enum RouterState {
    /// Router is being dialed.
    Dialing {
        /// Pending messages.
        pending: Vec<OutboundMessage>,
    },

    /// Router is connected.
    Connected {
        /// TX channel for sending message to router.
        tx: Sender<OutboundMessage, OutboundMessageRecycle>,
    },
}

/// Subsystem manager context.
pub struct SubsystemManagerContext<R: Runtime> {
    /// RX channel for receiving dial requests from `SubsystemManager`.
    pub dial_rx: Receiver<RouterId>,

    /// Handle for interacting with subsystem manager.
    pub handle: SubsystemHandle,

    /// Subsystem manager.
    pub manager: SubsystemManager<R>,

    /// RX channel passed to `NetDb`.
    ///
    /// Allows `SubsystemManager` to route messages to `NetDb`.
    pub netdb_rx: Receiver<NetDbEvent>,

    /// RX channel passed to `TransitTunnelManager`.
    ///
    /// Allows `SubsystemManager` to route messages to `TransitTunnelManager`.
    pub transit_rx: Receiver<Vec<(RouterId, Message)>>,

    /// TX channel given to all transports, allowing them to send events to `SubsystemManager`.
    pub transport_tx: Sender<SubsystemEvent>,
}

/// Subsystem manager.
pub struct SubsystemManager<R: Runtime> {
    /// TX channel for sending dialing requests to `TransportManager`.
    dial_tx: Sender<RouterId>,

    /// RX channel for receiving events from other subsystems.
    ///
    /// This includes tunnel build and expiration events and outbound messages.
    event_rx: Receiver<SubsystemManagerEvent, SubsystemManagerEventRecycle>,

    /// Installed message listeners.    
    ///
    /// These are used by local tunnel build tasks to capture specific
    /// build-related messages.
    listeners: Arc<RwLock<HashMap<MessageId, oneshot::Sender<Message>>>>,

    /// Maximum amount of transit traffic, in bytes.
    #[allow(unused)]
    max_transit: usize,

    /// TX channel for routing messages to `NetDb`.
    netdb_tx: Sender<NetDbEvent>,

    /// Noise context.
    noise: NoiseContext,

    /// Measured outbound traffic, in bytes.
    #[allow(unused)]
    outbound: usize,

    /// Local router ID.
    router_id: RouterId,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Should the router thorttle itself.
    #[allow(unused)]
    throttle: Arc<AtomicBool>,

    /// TX channel for routing messages to `TransitTunnelManager`
    transit_tx: Sender<Vec<(RouterId, Message)>>,

    /// RX channel for receiving transport-related events.
    transport_rx: Receiver<SubsystemEvent>,

    /// Active tunnels.
    tunnels: Arc<RwLock<HashMap<TunnelId, Sender<Message>>>>,

    /// Runtime.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> SubsystemManager<R> {
    /// Create new [`SubsystemManager`].
    pub fn new(
        limit: usize,
        share: f32,
        router_id: RouterId,
        noise: NoiseContext,
    ) -> SubsystemManagerContext<R> {
        assert!(share <= 1.0);

        let (event_tx, event_rx) = with_recycle(8192, SubsystemManagerEventRecycle::default());
        let (transit_tx, transit_rx) = channel(256);
        let (netdb_tx, netdb_rx) = channel(256);
        let (dial_tx, dial_rx) = channel(256);
        let (transport_tx, transport_rx) = channel(256);
        let throttle = Arc::new(AtomicBool::new(false));
        let listeners = Arc::new(RwLock::new(HashMap::new()));
        let tunnels = Arc::new(RwLock::new(HashMap::new()));

        SubsystemManagerContext {
            netdb_rx,
            transit_rx,
            transport_tx,
            dial_rx,
            manager: Self {
                dial_tx,
                event_rx,
                listeners: Arc::clone(&listeners),
                max_transit: (limit as f32 * share) as usize,
                netdb_tx,
                noise,
                outbound: limit,
                router_id,
                routers: HashMap::new(),
                throttle: Arc::clone(&throttle),
                transit_tx,
                transport_rx,
                tunnels: Arc::clone(&tunnels),
                _runtime: Default::default(),
            },
            handle: SubsystemHandle {
                event_tx,
                listeners,
                throttle,
                tunnels,
            },
        }
    }

    /// Handle outbound `message` to router identified by `router_id`.
    ///
    /// If router is connected, send `message` directly to router.
    ///
    /// If router is being dialed, queue message until the connection is resolved.
    ///
    /// If router doens't exist, dial the router by sending a message to `TransportManager`
    /// and queue the pending `message`. If connection succeeds, all pending messages are sent
    /// in order to the remote router. If the connection fails, all pending messages are dropped.
    fn on_outbound_message(&mut self, router_id: RouterId, message: OutboundMessage) {
        if router_id == self.router_id {
            return match message {
                OutboundMessage::Message(message) =>
                    self.on_inbound_message(vec![(router_id, message)]),
                OutboundMessage::Messages(messages) => self.on_inbound_message(
                    messages.into_iter().map(|message| (router_id.clone(), message)).collect(),
                ),
                OutboundMessage::MessageWithFeedback(message, feedback_tx) => {
                    self.on_inbound_message(vec![(router_id, message)]);
                    let _ = feedback_tx.send(());
                }
                OutboundMessage::Dummy => unreachable!(),
            };
        }

        match self.routers.get_mut(&router_id) {
            Some(RouterState::Dialing { pending }) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    num_pending = ?pending.len(),
                    "router is being dialed, queue message",
                );
                pending.push(message);
            }
            Some(RouterState::Connected { tx }) =>
                if let Err(error) = tx.try_send(message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send message to router",
                    );
                },
            None => match self.dial_tx.try_send(router_id.clone()) {
                Ok(()) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "started dialing router",
                    );
                    self.routers.insert(
                        router_id,
                        RouterState::Dialing {
                            pending: vec![message],
                        },
                    );
                }
                Err(error) => tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    ?error,
                    "failed to send dial request to transport manager",
                ),
            },
        }
    }

    /// Handle inbound `messages`.
    ///
    /// The message is handled differently based on its type:
    ///  - `TunnelData`/`TunnelGateway`: send to local IBGW/transit tunnel
    ///  - NetDb-related messages: send to NetDb
    ///  - garlic messages: decrypt and send to tunnel pool/transit tunnel/NetDb
    fn on_inbound_message(&mut self, messages: Vec<(RouterId, Message)>) {
        let mut netdb = Vec::<(RouterId, Message)>::new();
        let mut transit = Vec::<(RouterId, Message)>::new();
        let mut tunnels = HashMap::<TunnelId, Vec<Message>>::new();

        for (router_id, message) in messages {
            match message.message_type {
                MessageType::DatabaseStore
                | MessageType::DatabaseLookup
                | MessageType::DatabaseSearchReply
                | MessageType::DeliveryStatus => {
                    netdb.push((router_id, message));
                }
                MessageType::Garlic =>
                    if let Some(messages) = self.on_garlic_message(message) {
                        let mut inbound = vec![];
                        let mut outbound = vec![];

                        for message in messages {
                            match message {
                                DeliveryInstructions::Local { message } => {
                                    inbound.push((router_id.clone(), message));
                                }
                                DeliveryInstructions::Router { router, message }
                                | DeliveryInstructions::Tunnel {
                                    router, message, ..
                                } => {
                                    outbound.push((router, OutboundMessage::Message(message)));
                                }
                                DeliveryInstructions::Destination => {}
                            }
                        }

                        self.on_inbound_message(inbound);
                        outbound.into_iter().for_each(|(router_id, message)| {
                            self.on_outbound_message(router_id, message);
                        });
                    },
                MessageType::TunnelData => {
                    if let Some(tunnel_id) = EncryptedTunnelData::parse(&message.payload)
                        .map(|message| message.tunnel_id())
                    {
                        tunnels.entry(tunnel_id).or_default().push(message);
                    }
                }
                MessageType::TunnelGateway => {
                    if let Some(tunnel_id) =
                        TunnelGateway::parse(&message.payload).map(|message| message.tunnel_id)
                    {
                        tunnels.entry(tunnel_id).or_default().push(message);
                    }
                }
                MessageType::VariableTunnelBuild
                | MessageType::ShortTunnelBuild
                | MessageType::OutboundTunnelBuildReply
                | MessageType::TunnelBuild => {
                    if let Ok(Some(message)) = self.route_tunnel_build_message(message) {
                        transit.push((router_id.clone(), message));
                    }
                }
                MessageType::VariableTunnelBuildReply
                | MessageType::Data
                | MessageType::TunnelBuildReply => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        message_type = ?message.message_type,
                        "unhandled message type",
                    );
                }
            }
        }

        if !netdb.is_empty() {
            if let Err(error) = self.netdb_tx.try_send(NetDbEvent::Message { messages: netdb }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to send i2np messages to netdb",
                );
            }
        }

        if !transit.is_empty() {
            if let Err(error) = self.transit_tx.try_send(transit) {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to send i2np messages to transit tunnel manager",
                );
            }
        }

        if !tunnels.is_empty() {
            let inner = self.tunnels.read();

            for (tunnel_id, messages) in tunnels {
                let Some(tunnel) = inner.get(&tunnel_id) else {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "tunnel doesn't exist",
                    );
                    continue;
                };

                for message in messages {
                    if let Err(TrySendError::Closed(_)) = tunnel.try_send(message) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %tunnel_id,
                            "tunnel exist in the routing table but is closed",
                        );
                        debug_assert!(false);
                    }
                }
            }
        }
    }

    /// Attempt to route message to an installed listener, if the listener exists.
    ///
    /// If no listener exists, the message is routed to `TransitTunnelManager`.
    fn route_tunnel_build_message(
        &self,
        message: Message,
    ) -> Result<Option<Message>, RoutingError> {
        let mut listeners = self.listeners.write();

        match listeners.remove(&MessageId::from(message.message_id)) {
            Some(listener) => listener.send(message).map(|_| None).map_err(|message| {
                tracing::warn!(
                    target: LOG_TARGET,
                    message_id = %message.message_id,
                    "listener exist in the routing table but is closed",
                );
                debug_assert!(false);

                RoutingError::ChannelClosed(message)
            }),
            None => {
                drop(listeners);
                Ok(Some(message))
            }
        }
    }

    /// Handle garlic message.
    fn on_garlic_message(&self, message: Message) -> Option<Vec<DeliveryInstructions>> {
        let Message {
            message_id,
            expiration,
            payload,
            ..
        } = message;

        tracing::trace!(
            target: LOG_TARGET,
            ?message_id,
            ?expiration,
            "garlic message",
        );

        if payload.len() < 36 {
            tracing::warn!(
                target: LOG_TARGET,
                ?message_id,
                ?expiration,
                "garlic message is too short",
            );
            return None;
        }

        // derive cipher key and associated data and decrypt the garlic message
        let message = {
            let (mut cipher_key, associated_data) = self
                .noise
                .derive_inbound_garlic_key(EphemeralPublicKey::from_bytes(&payload[4..36])?);

            let mut message = payload[36..].to_vec();
            ChaChaPoly::new(&cipher_key)
                .decrypt_with_ad(&associated_data, &mut message)
                .ok()?;
            cipher_key.zeroize();

            message
        };

        let Ok(message) = GarlicMessage::parse(&message) else {
            return None;
        };

        Some(
            message
                .blocks
                .into_iter()
                .filter_map(|block| match block {
                    GarlicMessageBlock::GarlicClove {
                        message_type,
                        message_id,
                        expiration,
                        delivery_instructions,
                        message_body,
                    } => {
                        if expiration < R::time_since_epoch() {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?message_id,
                                ?message_type,
                                ?delivery_instructions,
                                "dropping expired i2np message",
                            );
                            return None;
                        }

                        match delivery_instructions {
                            CloveDeliveryInstructions::Local => Some(DeliveryInstructions::Local {
                                message: Message {
                                    message_type,
                                    message_id: *message_id,
                                    expiration,
                                    payload: message_body.to_vec(),
                                },
                            }),
                            CloveDeliveryInstructions::Router { hash } =>
                                Some(DeliveryInstructions::Router {
                                    router: RouterId::from(hash),
                                    message: Message {
                                        message_type,
                                        message_id: *message_id,
                                        expiration,
                                        payload: message_body.to_vec(),
                                    },
                                }),
                            CloveDeliveryInstructions::Tunnel { hash, tunnel_id } => {
                                let message = MessageBuilder::standard()
                                    .with_message_type(message_type)
                                    .with_message_id(message_id)
                                    .with_expiration(expiration)
                                    .with_payload(message_body)
                                    .build();

                                let message = TunnelGateway {
                                    tunnel_id: tunnel_id.into(),
                                    payload: &message,
                                }
                                .serialize();

                                Some(DeliveryInstructions::Tunnel {
                                    tunnel: TunnelId::from(tunnel_id),
                                    router: RouterId::from(hash),
                                    message: Message {
                                        message_type: MessageType::TunnelGateway,
                                        message_id: R::rng().next_u32(),
                                        expiration,
                                        payload: message.to_vec(),
                                    },
                                })
                            }
                            CloveDeliveryInstructions::Destination { hash } => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?hash,
                                    "ignoring destination",
                                );
                                None
                            }
                        }
                    }
                    block => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?block,
                            "ignoring garlic block",
                        );
                        None
                    }
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl<R: Runtime> Future for SubsystemManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.event_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(event)) => match event {
                    SubsystemManagerEvent::Message { router_id, message } =>
                        self.on_outbound_message(router_id, message),
                    SubsystemManagerEvent::Dummy => unreachable!(),
                },
            }
        }

        loop {
            match self.transport_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(event)) => match event {
                    SubsystemEvent::ConnectionEstablished { router_id, tx } => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "connection opened",
                        );

                        // TODO: handle this more gracefully by buffering events
                        if let Err(error) =
                            self.netdb_tx.try_send(NetDbEvent::ConnectionEstablished {
                                router_id: router_id.clone(),
                            })
                        {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %router_id,
                                ?error,
                                "failed to inform netdb of the connection",
                            );
                            self.routers.remove(&router_id);
                            continue;
                        }

                        // send all pending messages to router
                        if let Some(RouterState::Dialing { pending }) =
                            self.routers.remove(&router_id)
                        {
                            for message in pending {
                                if let Err(error) = tx.try_send(message) {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        %router_id,
                                        ?error,
                                        "failed to send pending message",
                                    );
                                }
                            }
                        }

                        self.routers.insert(router_id, RouterState::Connected { tx });
                    }
                    SubsystemEvent::ConnectionClosed { router_id } => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "connection closed",
                        );
                        self.routers.remove(&router_id);
                    }
                    SubsystemEvent::ConnectionFailure { router_id } => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "connection failure",
                        );
                        self.routers.remove(&router_id);
                    }
                    SubsystemEvent::Message { messages } => self.on_inbound_message(messages),
                    SubsystemEvent::Dummy => unreachable!(),
                },
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};
    use futures::FutureExt;

    use crate::{
        crypto::{EphemeralPrivateKey, StaticPrivateKey, StaticPublicKey},
        i2np::{garlic::GarlicMessageBuilder, I2NP_MESSAGE_EXPIRATION},
        runtime::mock::MockRuntime,
    };

    use super::*;

    macro_rules! poll_manager {
        ($manager:ident) => {
            futures::future::poll_fn(|cx| match $manager.poll_unpin(cx) {
                Poll::Pending => return Poll::Ready(()),
                Poll::Ready(_) => panic!("ready"),
            })
            .await;
        };
    }

    #[test]
    fn no_bandwidth_shared() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext { manager, .. } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        assert_eq!(manager.outbound, 100 * 1024);
        assert_eq!(manager.max_transit, 0);
    }

    #[test]
    fn all_bandwidth_shared() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext { manager, .. } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            1.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        assert_eq!(manager.outbound, 100 * 1024);
        assert_eq!(manager.max_transit, 100 * 1024);
    }

    #[tokio::test]
    async fn inbound_router_connection_disconnection() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );
        let (msg_tx, _msg_rx) = with_recycle(16, OutboundMessageRecycle::default());

        let router = RouterId::random();
        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: router.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();

        // poll manager and verify the router has connected
        poll_manager!(manager);
        assert!(manager.routers.contains_key(&router));

        // disconnect router
        tx.send(SubsystemEvent::ConnectionClosed {
            router_id: router.clone(),
        })
        .await
        .unwrap();

        poll_manager!(manager);
        assert!(!manager.routers.contains_key(&router));
    }

    #[tokio::test]
    async fn dial_router() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            dial_rx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        let router_id = RouterId::random();
        handle.send(&router_id, Message::default()).unwrap();
        poll_manager!(manager);

        // verify the router is being dialed
        match manager.routers.get(&router_id) {
            Some(RouterState::Dialing { pending }) => {
                assert_eq!(pending.len(), 1);
            }
            _ => panic!("invalid state"),
        }

        assert_eq!(dial_rx.try_recv(), Ok(router_id.clone()));

        // register connected router
        let (msg_tx, msg_rx) = with_recycle(16, OutboundMessageRecycle::default());
        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: router_id.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the router is considered connected
        match manager.routers.get(&router_id) {
            Some(RouterState::Connected { .. }) => {}
            _ => panic!("invalid state"),
        }

        // verify the pending message is sent to router
        assert!(msg_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn dial_fails() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            dial_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );
        let (feedback_tx, feedback_rx) = oneshot::channel();

        let router_id = RouterId::random();
        handle.send(&router_id, Message::default()).unwrap();
        handle.send_with_feedback(&router_id, Message::default(), feedback_tx).unwrap();
        poll_manager!(manager);

        // verify the router is being dialed
        match manager.routers.get(&router_id) {
            Some(RouterState::Dialing { pending }) => {
                assert_eq!(pending.len(), 2);
            }
            _ => panic!("invalid state"),
        }

        assert_eq!(dial_rx.try_recv(), Ok(router_id.clone()));

        // register connected router
        tx.send(SubsystemEvent::ConnectionFailure {
            router_id: router_id.clone(),
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the router is considered connected
        match manager.routers.get(&router_id) {
            None => {}
            _ => panic!("invalid state"),
        }

        // verify the feedback channel indicates that dial failed
        assert!(feedback_rx.await.is_err());
    }

    #[tokio::test]
    async fn dial_fails_with_feedback() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            dial_rx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        let router_id = RouterId::random();
        let (feedback_tx, feedback_rx) = oneshot::channel();
        handle.send_with_feedback(&router_id, Message::default(), feedback_tx).unwrap();
        poll_manager!(manager);

        // verify the router is being dialed
        match manager.routers.get(&router_id) {
            Some(RouterState::Dialing { pending }) => {
                assert_eq!(pending.len(), 1);
            }
            _ => panic!("invalid state"),
        }

        assert_eq!(dial_rx.try_recv(), Ok(router_id.clone()));

        // register connected router
        tx.send(SubsystemEvent::ConnectionFailure {
            router_id: router_id.clone(),
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the router is considered connected
        match manager.routers.get(&router_id) {
            None => {}
            _ => panic!("invalid state"),
        }

        assert!(feedback_rx.await.is_err());
    }

    #[tokio::test]
    async fn send_message_to_router() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );
        let router_id = RouterId::random();

        // register connected router
        let (msg_tx, msg_rx) = with_recycle(16, OutboundMessageRecycle::default());
        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: router_id.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the router is considered connected
        match manager.routers.get(&router_id) {
            Some(RouterState::Connected { .. }) => {}
            _ => panic!("invalid state"),
        }

        // send normal message
        handle
            .send(
                &router_id,
                Message {
                    message_id: 1337u32,
                    ..Default::default()
                },
            )
            .unwrap();

        // send multiple message
        handle
            .send_many(
                &router_id,
                vec![
                    Message {
                        message_id: 1338u32,
                        ..Default::default()
                    },
                    Message {
                        message_id: 1339u32,
                        ..Default::default()
                    },
                    Message {
                        message_id: 1340u32,
                        ..Default::default()
                    },
                ],
            )
            .unwrap();

        // send message with feedback
        let (feedback_tx, feedback_rx) = oneshot::channel();
        handle
            .send_with_feedback(
                &router_id,
                Message {
                    message_id: 1341u32,
                    ..Default::default()
                },
                feedback_tx,
            )
            .unwrap();

        // poll manager so the messages are processed
        poll_manager!(manager);

        // process first normal message
        {
            match msg_rx.try_recv().unwrap() {
                OutboundMessage::Message(message) => assert_eq!(message.message_id, 1337),
                _ => panic!("invalid message type"),
            }
        }

        // process multiple messages
        {
            match msg_rx.try_recv().unwrap() {
                OutboundMessage::Messages(messages) => assert!((1338u32..=1340)
                    .zip(messages.into_iter())
                    .all(|(id, message)| { message.message_id == id })),
                _ => panic!("invalid message type"),
            }
        }

        // process third message (with feedback)
        {
            match msg_rx.try_recv().unwrap() {
                OutboundMessage::MessageWithFeedback(message, feedback) => {
                    assert_eq!(message.message_id, 1341);
                    feedback.send(()).unwrap();
                }
                _ => panic!("invalid message type"),
            }
        }

        assert!(feedback_rx.await.is_ok());
    }

    #[tokio::test]
    async fn send_pending_messages_to_router() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            dial_rx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );
        let router_id = RouterId::random();

        // send normal message
        handle
            .send(
                &router_id,
                Message {
                    message_id: 1337u32,
                    ..Default::default()
                },
            )
            .unwrap();

        // send multiple message
        handle
            .send_many(
                &router_id,
                vec![
                    Message {
                        message_id: 1338u32,
                        ..Default::default()
                    },
                    Message {
                        message_id: 1339u32,
                        ..Default::default()
                    },
                    Message {
                        message_id: 1340u32,
                        ..Default::default()
                    },
                ],
            )
            .unwrap();

        // send message with feedback
        let (feedback_tx, feedback_rx) = oneshot::channel();
        handle
            .send_with_feedback(
                &router_id,
                Message {
                    message_id: 1341u32,
                    ..Default::default()
                },
                feedback_tx,
            )
            .unwrap();

        // poll manager so the messages are processed
        poll_manager!(manager);

        // verify the router is being dialed
        match manager.routers.get(&router_id) {
            Some(RouterState::Dialing { pending }) => assert_eq!(pending.len(), 3),
            _ => panic!("invalid state"),
        }
        assert_eq!(dial_rx.try_recv().unwrap(), router_id.clone());

        // register router connection to manager
        let (msg_tx, msg_rx) = with_recycle(16, OutboundMessageRecycle::default());
        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: router_id.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // process first normal message
        {
            match msg_rx.try_recv().unwrap() {
                OutboundMessage::Message(message) => assert_eq!(message.message_id, 1337),
                _ => panic!("invalid message type"),
            }
        }

        // process multiple messages
        {
            match msg_rx.try_recv().unwrap() {
                OutboundMessage::Messages(messages) => assert!((1338u32..=1340)
                    .zip(messages.into_iter())
                    .all(|(id, message)| { message.message_id == id })),
                _ => panic!("invalid message type"),
            }
        }

        // process third message (with feedback)
        {
            match msg_rx.try_recv().unwrap() {
                OutboundMessage::MessageWithFeedback(message, feedback) => {
                    assert_eq!(message.message_id, 1341);
                    feedback.send(()).unwrap();
                }
                _ => panic!("invalid message type"),
            }
        }

        assert!(feedback_rx.await.is_ok());
    }

    #[tokio::test]
    async fn install_listener_through_handle() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: _tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );
        let handle_clone = handle.clone();

        assert!(manager.listeners.read().is_empty());
        assert!(handle.listeners.read().is_empty());
        assert!(handle_clone.listeners.read().is_empty());

        let (message_id, _rx) = handle.insert_listener(&mut rand_core::OsRng);

        assert!(manager.listeners.read().contains_key(&message_id));
        assert!(handle.listeners.read().contains_key(&message_id));
        assert!(handle_clone.listeners.read().contains_key(&message_id));
    }

    #[tokio::test]
    async fn no_active_listener_variable_tunnel_build() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // create mock `VariableTunnelBuildMessage`
        let message = Message {
            message_type: MessageType::VariableTunnelBuild,
            ..Default::default()
        };

        // send and process message
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        let message = transit_rx.try_recv().unwrap();
        assert_eq!(message[0].1.message_type, MessageType::VariableTunnelBuild);
    }

    #[tokio::test]
    async fn no_listener_short_tunnel_build() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // create mock `ShortTunnelBuild`
        let message = Message {
            message_type: MessageType::ShortTunnelBuild,
            ..Default::default()
        };

        // send and process message
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        let message = transit_rx.try_recv().unwrap();
        assert_eq!(message[0].1.message_type, MessageType::ShortTunnelBuild);
    }

    #[tokio::test]
    async fn no_listener_outbound_tunnel_build_reply() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // create mock `OutboundTunnelBuildReply`
        let message = Message {
            message_type: MessageType::OutboundTunnelBuildReply,
            ..Default::default()
        };

        // send and process message
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        let message = transit_rx.try_recv().unwrap();
        assert_eq!(
            message[0].1.message_type,
            MessageType::OutboundTunnelBuildReply
        );
    }

    #[tokio::test]
    async fn active_listener_short_tunnel_build() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // register listener through handle
        let (message_id, rx) = handle.insert_listener(&mut rand_core::OsRng);

        // create mock `ShortTunnelBuid`
        let message = Message {
            message_type: MessageType::ShortTunnelBuild,
            message_id: *message_id,
            ..Default::default()
        };

        // send and process message
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the message is not routed to transit tunnel manager
        assert!(transit_rx.try_recv().is_err());

        // verify the registered listener receives the message
        let message = rx.await.unwrap();
        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        assert_eq!(message.message_id, *message_id);
    }

    #[tokio::test]
    async fn active_listener_outbound_tunnel_build_reply() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // register listener through handle
        let (message_id, rx) = handle.insert_listener(&mut rand_core::OsRng);

        // create mock `OutboundTunnelBuildReply`
        let message = Message {
            message_type: MessageType::OutboundTunnelBuildReply,
            message_id: *message_id,
            ..Default::default()
        };

        // send and process message
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the message is not routed to transit tunnel manager
        assert!(transit_rx.try_recv().is_err());

        // verify the registered listener receives the message
        let message = rx.await.unwrap();
        assert_eq!(message.message_type, MessageType::OutboundTunnelBuildReply);
        assert_eq!(message.message_id, *message_id);
    }

    #[tokio::test]
    async fn register_tunnel_through_handle() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: _tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // register tunnel through handle
        let (tunnel_id, _rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);

        assert!(handle.tunnels.read().contains_key(&tunnel_id));
        assert!(manager.tunnels.read().contains_key(&tunnel_id));

        // unregister tunnel and verify it doens't exist
        handle.remove_tunnel(&tunnel_id);

        assert!(!handle.tunnels.read().contains_key(&tunnel_id));
        assert!(!manager.tunnels.read().contains_key(&tunnel_id));
    }

    #[tokio::test]
    async fn route_tunnel_data() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // register tunnel through handle
        let (tunnel_id, rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);

        // create mock tunnel data message
        let message = {
            let mut data = BytesMut::with_capacity(4 + 16 + 1008);
            data.put_u32(*tunnel_id);
            data.put_slice(&[0xaa; 16]);
            data.put_slice(&[0xbb; 1008]);

            Message {
                message_type: MessageType::TunnelData,
                payload: data.to_vec(),
                ..Default::default()
            }
        };

        // send message and poll manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the tunnel has been received by the active tunnel
        let message = rx.try_recv().unwrap();

        let message = EncryptedTunnelData::parse(&message.payload).unwrap();
        assert_eq!(message.tunnel_id(), tunnel_id);
        assert_eq!(message.iv(), &[0xaa; 16]);
        assert_eq!(message.ciphertext(), &[0xbb; 1008]);
    }

    #[tokio::test]
    async fn route_tunnel_gateway() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // register tunnel through handle
        let (tunnel_id, rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);

        // create mock tunnel data message
        let message = {
            let mut data = BytesMut::with_capacity(4 + 2 + 512);
            data.put_u32(*tunnel_id);
            data.put_u16(512);
            data.put_slice(&[0xaa; 512]);

            Message {
                message_type: MessageType::TunnelGateway,
                payload: data.to_vec(),
                ..Default::default()
            }
        };

        // send message and poll manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the tunnel has been received by the active tunnel
        let message = rx.try_recv().unwrap();

        let message = TunnelGateway::parse(&message.payload).unwrap();
        assert_eq!(message.tunnel_id, tunnel_id);
        assert_eq!(message.payload, &[0xaa; 512]);
    }

    #[tokio::test]
    async fn route_tunnel_data_of_non_existent_tunnel() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // generate id for a non-existent tunnel
        let tunnel_id = TunnelId::random();

        // create mock tunnel data message
        let message = {
            let mut data = BytesMut::with_capacity(4 + 16 + 1008);
            data.put_u32(*tunnel_id);
            data.put_slice(&[0xaa; 16]);
            data.put_slice(&[0xbb; 1008]);

            Message {
                message_type: MessageType::TunnelData,
                payload: data.to_vec(),
                ..Default::default()
            }
        };

        // send message and poll manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the message is not routed to transit tunnel manager or netdb
        assert!(netdb_rx.try_recv().is_err());
        assert!(transit_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn route_tunnel_gateway_of_non_existent_tunnel() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // generate id for the non-existent tunnel
        let tunnel_id = TunnelId::random();

        // create mock tunnel data message
        let message = {
            let mut data = BytesMut::with_capacity(4 + 2 + 512);
            data.put_u32(*tunnel_id);
            data.put_u16(512);
            data.put_slice(&[0xaa; 512]);

            Message {
                message_type: MessageType::TunnelGateway,
                payload: data.to_vec(),
                ..Default::default()
            }
        };

        // send message and poll manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the message is not routed to transit tunnel manager or netdb
        assert!(netdb_rx.try_recv().is_err());
        assert!(transit_rx.try_recv().is_err());
    }

    #[tokio::test]
    #[should_panic]
    async fn route_message_to_closed_tunnel() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        // register tunnel through handle
        let (tunnel_id, rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);
        drop(rx);

        // create mock tunnel data message
        let message = {
            let mut data = BytesMut::with_capacity(4 + 16 + 1008);
            data.put_u32(*tunnel_id);
            data.put_slice(&[0xaa; 16]);
            data.put_slice(&[0xbb; 1008]);

            Message {
                message_type: MessageType::TunnelData,
                payload: data.to_vec(),
                ..Default::default()
            }
        };

        // send message and poll manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);
    }

    fn make_garlic_message_with_noise_context(
        noise: &NoiseContext,
        remote_key: StaticPublicKey,
        cloves: Vec<(MessageType, MessageId, CloveDeliveryInstructions, &[u8])>,
    ) -> Message {
        let mut message = GarlicMessageBuilder::default()
            .with_date_time(MockRuntime::time_since_epoch().as_secs() as u32);

        for (msg_type, msg_id, delivery, payload) in cloves {
            message = message.with_garlic_clove(
                msg_type,
                msg_id,
                MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                delivery,
                payload,
            );
        }

        let mut message = message.build();
        let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

        // derive outbound garlic context
        let ephemeral_secret = EphemeralPrivateKey::random(rand::thread_rng());
        let ephemeral_public = ephemeral_secret.public();
        let (local_key, local_state) =
            noise.derive_outbound_garlic_key(remote_key, ephemeral_secret);

        ChaChaPoly::new(&local_key)
            .encrypt_with_ad_new(&local_state, &mut message)
            .unwrap();

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        Message {
            message_type: MessageType::Garlic,
            message_id: MockRuntime::rng().next_u32(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: out.to_vec(),
        }
    }

    fn make_garlic_message(
        remote_key: StaticPublicKey,
        cloves: Vec<(MessageType, MessageId, CloveDeliveryInstructions, &[u8])>,
    ) -> Message {
        let key = StaticPrivateKey::random(rand::thread_rng());
        let router_id = Bytes::from(RouterId::random().to_vec());
        let noise = NoiseContext::new(key, router_id);

        make_garlic_message_with_noise_context(&noise, remote_key, cloves)
    }

    #[tokio::test]
    async fn outbound_garlic_message_triggers_a_dial() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            dial_rx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // create short tunnel build request which gets routed to transit tunnel manager
        let remote_router = RouterId::random();
        let serialized = remote_router.to_vec();
        let message = make_garlic_message(
            private_key.public(),
            vec![(
                MessageType::ShortTunnelBuild,
                MessageId::random(),
                CloveDeliveryInstructions::Router { hash: &serialized },
                &vec![1, 1, 1, 1],
            )],
        );

        // send the garlic message and poll the manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        match manager.routers.get(&remote_router) {
            Some(RouterState::Dialing { pending }) => {
                assert_eq!(pending.len(), 1)
            }
            _ => panic!("invalid state"),
        }

        assert_eq!(dial_rx.try_recv().unwrap(), remote_router);
    }

    #[tokio::test]
    async fn outbound_garlic_message_pending_dial() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            dial_rx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // create short tunnel build request which gets routed to transit tunnel manager
        let remote_router = RouterId::random();
        let serialized = remote_router.to_vec();
        let message = make_garlic_message(
            private_key.public(),
            vec![(
                MessageType::ShortTunnelBuild,
                MessageId::random(),
                CloveDeliveryInstructions::Router { hash: &serialized },
                &vec![1, 1, 1, 1],
            )],
        );

        // send the garlic message and poll the manager
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        match manager.routers.get(&remote_router) {
            Some(RouterState::Dialing { pending }) => {
                assert_eq!(pending.len(), 1)
            }
            _ => panic!("invalid state"),
        }
        assert_eq!(dial_rx.try_recv().unwrap(), remote_router);

        // receive another garlic message for the pending router
        let message = make_garlic_message(
            private_key.public(),
            vec![(
                MessageType::VariableTunnelBuild,
                MessageId::random(),
                CloveDeliveryInstructions::Router { hash: &serialized },
                &vec![2, 2, 2, 2],
            )],
        );

        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        match manager.routers.get(&remote_router) {
            Some(RouterState::Dialing { pending }) => {
                assert_eq!(pending.len(), 2)
            }
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn outbound_garlic_message_for_tunnel() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // register remote router as connected
        let (msg_tx, msg_rx) = with_recycle(16, OutboundMessageRecycle::default());
        let remote_router = RouterId::random();
        let serialized = remote_router.to_vec();

        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: remote_router.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // send garlic message for tunnel
        let tunnel_id = TunnelId::random();
        let message = make_garlic_message(
            private_key.public(),
            vec![(
                MessageType::TunnelData,
                MessageId::random(),
                CloveDeliveryInstructions::Tunnel {
                    hash: &serialized,
                    tunnel_id: *tunnel_id,
                },
                &vec![2, 2, 2, 2],
            )],
        );
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the transport receives the message
        let message = msg_rx.try_recv().unwrap();
        match message {
            OutboundMessage::Message(message) => {
                assert_eq!(message.message_type, MessageType::TunnelGateway);

                let inner = TunnelGateway::parse(&message.payload).unwrap();
                assert_eq!(inner.tunnel_id, tunnel_id);

                let inner = Message::parse_standard(&inner.payload).unwrap();
                assert_eq!(inner.message_type, MessageType::TunnelData);
                assert_eq!(inner.payload, vec![2, 2, 2, 2]);
            }
            _ => panic!("invalid type"),
        }
    }

    #[tokio::test]
    async fn outbound_garlic_message_for_router() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // register remote router as connected
        let (msg_tx, msg_rx) = with_recycle(16, OutboundMessageRecycle::default());
        let remote_router = RouterId::random();
        let serialized = remote_router.to_vec();

        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: remote_router.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // send garlic message for tunnel
        let message = make_garlic_message(
            private_key.public(),
            vec![(
                MessageType::ShortTunnelBuild,
                MessageId::random(),
                CloveDeliveryInstructions::Router { hash: &serialized },
                &vec![3, 3, 3, 3],
            )],
        );
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the transport receives the message
        let message = msg_rx.try_recv().unwrap();
        match message {
            OutboundMessage::Message(message) => {
                assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
                assert_eq!(message.payload, vec![3, 3, 3, 3]);
            }
            _ => panic!("invalid type"),
        }
    }

    #[tokio::test]
    async fn multiple_inbound_cloves() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx,
            mut manager,
            handle,
            transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // send garlic message for tunnel
        //  - one for netdb
        //  - one for transit tunnel manager
        //  - one for an active tunnel
        //  - one for an active listener
        let (message_id, mut listener_rx) = handle.insert_listener(&mut rand_core::OsRng);
        let (tunnel_id, tunnel_rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);
        let message = {
            let mut data = BytesMut::with_capacity(4 + 16 + 1008);
            data.put_u32(*tunnel_id);
            data.put_slice(&[0xaa; 16]);
            data.put_slice(&[0xbb; 1008]);

            data.to_vec()
        };

        let message = make_garlic_message(
            private_key.public(),
            vec![
                (
                    MessageType::DatabaseStore,
                    MessageId::random(),
                    CloveDeliveryInstructions::Local,
                    &vec![1, 1, 1, 1],
                ),
                (
                    MessageType::ShortTunnelBuild,
                    message_id,
                    CloveDeliveryInstructions::Local,
                    &vec![1, 1, 1, 1],
                ),
                (
                    MessageType::VariableTunnelBuild,
                    MessageId::random(),
                    CloveDeliveryInstructions::Local,
                    &vec![1, 1, 1, 1],
                ),
                (
                    MessageType::TunnelData,
                    MessageId::random(),
                    CloveDeliveryInstructions::Local,
                    &message,
                ),
            ],
        );
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify netdb receives the database store
        {
            match netdb_rx.try_recv().unwrap() {
                NetDbEvent::Message { messages } => {
                    assert_eq!(
                        messages[0].clone().1.message_type,
                        MessageType::DatabaseStore
                    );
                }
                _ => panic!("invalid event"),
            }
        }

        // verify transit tunnel receives the variable tunnel build request
        {
            let message = transit_rx.try_recv().unwrap();
            assert_eq!(
                message[0].clone().1.message_type,
                MessageType::VariableTunnelBuild
            );
        }

        // verify the active tunnel receives the tunnel data message
        {
            let message = tunnel_rx.try_recv().unwrap();
            assert_eq!(message.message_type, MessageType::TunnelData);
        }

        // verify the active listener receives the short tunnel build message
        {
            let message = listener_rx.try_recv().unwrap().unwrap();
            assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        }
    }

    #[tokio::test]
    async fn inbound_and_outbound_cloves() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            dial_rx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // register remote router as connected
        let (msg_tx, msg_rx) = with_recycle(16, OutboundMessageRecycle::default());
        let connected_router = RouterId::random();
        let unconnected_router = RouterId::random();
        let serialized_connected = connected_router.to_vec();
        let serialized_unconnected = unconnected_router.to_vec();

        tx.send(SubsystemEvent::ConnectionEstablished {
            router_id: connected_router.clone(),
            tx: msg_tx,
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // ignore connection established event
        assert!(netdb_rx.try_recv().is_ok());

        // send multiple cloves
        //  - one for an active local tunnel
        //  - one for netdb
        //  - tunnel delivery for connected router
        //  - router delivery for an unconnected router
        let (tunnel_id, tunnel_rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);
        let remote_tunnel_id = TunnelId::random();
        let message = {
            let mut data = BytesMut::with_capacity(4 + 16 + 1008);
            data.put_u32(*tunnel_id);
            data.put_slice(&[0xaa; 16]);
            data.put_slice(&[0xbb; 1008]);

            data.to_vec()
        };

        let message = make_garlic_message(
            private_key.public(),
            vec![
                (
                    MessageType::DatabaseStore,
                    MessageId::random(),
                    CloveDeliveryInstructions::Local,
                    &vec![1, 1, 1, 1],
                ),
                (
                    MessageType::TunnelData,
                    MessageId::random(),
                    CloveDeliveryInstructions::Local,
                    &message,
                ),
                (
                    MessageType::ShortTunnelBuild,
                    MessageId::random(),
                    CloveDeliveryInstructions::Router {
                        hash: &serialized_unconnected,
                    },
                    &vec![3, 3, 3, 3],
                ),
                (
                    MessageType::TunnelData,
                    MessageId::random(),
                    CloveDeliveryInstructions::Tunnel {
                        hash: &serialized_connected,
                        tunnel_id: *remote_tunnel_id,
                    },
                    &vec![2, 2, 2, 2],
                ),
            ],
        );
        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify the connected router receives the tunnel data message
        {
            // verify the transport receives the message
            let message = msg_rx.try_recv().unwrap();
            match message {
                OutboundMessage::Message(message) => {
                    assert_eq!(message.message_type, MessageType::TunnelGateway);

                    let inner = TunnelGateway::parse(&message.payload).unwrap();
                    assert_eq!(inner.tunnel_id, remote_tunnel_id);

                    let inner = Message::parse_standard(&inner.payload).unwrap();
                    assert_eq!(inner.message_type, MessageType::TunnelData);
                    assert_eq!(inner.payload, vec![2, 2, 2, 2]);
                }
                _ => panic!("invalid type"),
            }
        }

        // verify the unconnected router is being dialed
        {
            assert_eq!(dial_rx.try_recv().unwrap(), unconnected_router);

            match manager.routers.get(&unconnected_router) {
                Some(RouterState::Dialing { pending }) => {
                    assert_eq!(pending.len(), 1);
                }
                _ => panic!("invalid state"),
            }
        }

        // verify netdb receives the database store
        {
            match netdb_rx.try_recv().unwrap() {
                NetDbEvent::Message { messages } => {
                    assert_eq!(
                        messages[0].clone().1.message_type,
                        MessageType::DatabaseStore
                    );
                }
                _ => panic!("invalid event"),
            }
        }

        // verify the active tunnel receives the tunnel data message
        {
            let message = tunnel_rx.try_recv().unwrap();
            assert_eq!(message.message_type, MessageType::TunnelData);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn recursive_inbound_garlic_message() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx,
            mut manager,
            handle: _handle,
            transit_rx: _transit_rx,
            transport_tx: tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key.clone(), Bytes::from(router_id.to_vec())),
        );

        // create noise context
        let noise = NoiseContext::new(
            StaticPrivateKey::random(rand::thread_rng()),
            Bytes::from(RouterId::random().to_vec()),
        );

        // create recursive garlic message where the inner message wraps a database store
        // and the outer wraps the inner garlic message
        let message = make_garlic_message_with_noise_context(
            &noise,
            private_key.public(),
            vec![(
                MessageType::DatabaseStore,
                1337.into(),
                CloveDeliveryInstructions::Local,
                &vec![1, 1, 1, 1],
            )],
        )
        .serialize_short();
        let message = make_garlic_message_with_noise_context(
            &noise,
            private_key.public(),
            vec![(
                MessageType::Garlic,
                1338.into(),
                CloveDeliveryInstructions::Local,
                &message,
            )],
        );

        tx.send(SubsystemEvent::Message {
            messages: vec![(RouterId::random(), message)],
        })
        .await
        .unwrap();
        poll_manager!(manager);

        // verify netdb receives the database store
        {
            match netdb_rx.try_recv().unwrap() {
                NetDbEvent::Message { messages } => {
                    assert_eq!(
                        messages[0].clone().1.message_type,
                        MessageType::DatabaseStore
                    );
                }
                _ => panic!("invalid event"),
            }
        }
    }

    #[tokio::test]
    async fn route_message_locally() {
        let private_key = StaticPrivateKey::random(rand_core::OsRng);
        let router_id = RouterId::random();
        let SubsystemManagerContext {
            netdb_rx: _netdb_rx,
            mut manager,
            handle,
            transit_rx: _transit_rx,
            transport_tx: _tx,
            ..
        } = SubsystemManager::<MockRuntime>::new(
            100 * 1024,
            0.,
            router_id.clone(),
            NoiseContext::new(private_key, Bytes::from(router_id.to_vec())),
        );

        let (tunnel_id, tunnel_rx) = handle.insert_tunnel::<16>(&mut rand_core::OsRng);
        let message = {
            let mut data = BytesMut::with_capacity(4 + 16 + 1008);
            data.put_u32(*tunnel_id);
            data.put_slice(&[0xaa; 16]);
            data.put_slice(&[0xbb; 1008]);

            data.to_vec()
        };

        // route message to self
        //
        // this can happen, when e.g., OBEP and IBGW are the same router
        handle
            .send(
                &router_id,
                Message {
                    message_type: MessageType::TunnelData,
                    payload: message,
                    ..Default::default()
                },
            )
            .unwrap();
        poll_manager!(manager);

        let message = tunnel_rx.try_recv().unwrap();
        let message = EncryptedTunnelData::parse(&message.payload).unwrap();
        assert_eq!(message.iv(), &[0xaa; 16]);
        assert_eq!(message.ciphertext(), &[0xbb; 1008]);
    }
}
