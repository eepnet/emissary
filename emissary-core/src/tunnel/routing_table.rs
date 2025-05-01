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
    error::{RouteKind, RoutingError},
    i2np::{
        tunnel::{data::EncryptedTunnelData, gateway::TunnelGateway},
        Message, MessageType,
    },
    primitives::{MessageId, RouterId, TunnelId},
};

use futures_channel::oneshot;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{self, errors::TrySendError};

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec::Vec};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::routing-table";

#[derive(Debug, Default, Clone)]
pub struct RoutingKindRecycle(());

impl thingbuf::Recycle<RoutingKind> for RoutingKindRecycle {
    fn new_element(&self) -> RoutingKind {
        RoutingKind::default()
    }

    fn recycle(&self, element: &mut RoutingKind) {
        *element = RoutingKind::default()
    }
}

/// Routing kind.
#[derive(Debug)]
pub enum RoutingKind {
    /// Message needs to be send to an external router.
    External {
        /// Router ID.
        router_id: RouterId,

        /// Serialize I2NP essage.
        message: Vec<u8>,
    },

    /// Message needs to be sent to an external router and the sender must be informed
    /// if the message was sent successfully.
    ExternalWithFeedback {
        /// Router ID.
        router_id: RouterId,

        /// Serialize I2NP essage.
        message: Vec<u8>,

        /// TX channel for informing the sender if the message was sent successfully.
        tx: oneshot::Sender<()>,
    },

    /// Message needs to be routed internally either back to the tunnel subsystem or to [`NetDb`].
    Internal {
        /// I2NP message.
        message: Message,
    },
}

impl Default for RoutingKind {
    fn default() -> Self {
        Self::Internal {
            message: Message::default(),
        }
    }
}

/// Routing table.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Listeners for specific message.
    listeners: Arc<RwLock<HashMap<MessageId, oneshot::Sender<Message>>>>,

    /// TX channel for sending outbound messages to `TunnelManager`.
    /// TX channel for sending message routing instructions.
    ///
    /// See [`RoutingKind`] for more details.
    manager: mpsc::Sender<RoutingKind, RoutingKindRecycle>,

    /// Local router ID.
    router_hash: RouterId,

    /// TX channel for sending inbound messages to `TransitTunnelManager`.
    transit: mpsc::Sender<Message>,

    /// Active tunnels.
    tunnels: Arc<RwLock<HashMap<TunnelId, mpsc::Sender<Message>>>>,
}

impl RoutingTable {
    /// Create new [`RoutingTable`].
    pub fn new(
        router_hash: RouterId,
        manager: mpsc::Sender<RoutingKind, RoutingKindRecycle>,
        transit: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            transit,
            manager,
            router_hash,
            listeners: Default::default(),
            tunnels: Default::default(),
        }
    }

    /// Try to add transit tunnel into [`RoutingTable`].
    ///
    /// This function returns if the tunnel already exists in the routing table.
    pub fn try_add_tunnel<const SIZE: usize>(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<mpsc::Receiver<Message>, RoutingError> {
        let mut tunnels = self.tunnels.write();

        match tunnels.contains_key(&tunnel_id) {
            true => Err(RoutingError::TunnelExists(tunnel_id)),
            false => {
                let (tx, rx) = mpsc::channel(SIZE);
                tunnels.insert(tunnel_id, tx);

                Ok(rx)
            }
        }
    }

    /// Insert `sender` into [`RoutingTable`] and allocate it a random [`TunnelId`] which is
    /// returned to the caller.
    //
    /// TODO: add tests
    pub fn insert_tunnel<const SIZE: usize>(
        &self,
        rng: &mut impl RngCore,
    ) -> (TunnelId, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(SIZE);
        let mut tunnels = self.tunnels.write();

        loop {
            let tunnel_id = TunnelId::from(rng.next_u32());

            if !tunnels.contains_key(&tunnel_id) {
                tunnels.insert(tunnel_id, tx);
                return (tunnel_id, rx);
            }
        }
    }

    /// Remove tunnel from [`RoutingTable`].
    pub fn remove_tunnel(&self, tunnel_id: &TunnelId) {
        self.tunnels.write().remove(tunnel_id);
    }

    /// Insert `sender` into [`RoutingTable`] and allocate it a random [`MessageId`] which is
    /// returned to the caller.
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

    /// Remove listener from [`RoutingTable`].
    pub fn remove_listener(&self, message_id: &MessageId) {
        self.listeners.write().remove(message_id);
    }

    /// Attempt to route tunnel message to correct subsystem.
    ///
    /// Different from [`RoutingTable::route_listener_message()`] in that an error is returned if
    /// route (tunnel) is not found for `message`.
    fn route_tunnel_message(&self, message: Message) -> Result<(), RoutingError> {
        let tunnel_id = match message.message_type {
            MessageType::TunnelData => {
                let Some(tunnel_data) = EncryptedTunnelData::parse(&message.payload) else {
                    return Err(RoutingError::FailedToParseRoute(message));
                };

                tunnel_data.tunnel_id()
            }
            MessageType::TunnelGateway => {
                let Some(tunnel_gateway) = TunnelGateway::parse(&message.payload) else {
                    return Err(RoutingError::FailedToParseRoute(message));
                };

                tunnel_gateway.tunnel_id
            }
            _ => unreachable!(),
        };
        let tunnels = self.tunnels.read();

        let Some(sender) = tunnels.get(&tunnel_id) else {
            return Err(RoutingError::RouteNotFound(
                message,
                RouteKind::Tunnel(tunnel_id),
            ));
        };

        match sender.try_send(message).map_err(From::from) {
            error @ Err(RoutingError::ChannelClosed(_)) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %tunnel_id,
                    "tunnel exist in the routing table but is closed",
                );
                debug_assert!(false);

                error
            }
            result => result,
        }
    }

    /// Attempt to route message to an installed listener, if the listener exists.
    ///
    /// If no listener exists, the message is routed to `TransitTunnelManager`.
    fn route_listener_message(&self, message: Message) -> Result<(), RoutingError> {
        let mut listeners = self.listeners.write();

        match listeners.remove(&MessageId::from(message.message_id)) {
            Some(listener) => listener.send(message).map_err(|message| {
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

                self.transit.try_send(message).map_err(From::from)
            }
        }
    }

    /// Route `message` into correct subsystem.
    pub fn route_message(&self, message: Message) -> Result<(), RoutingError> {
        match message.message_type {
            MessageType::TunnelData | MessageType::TunnelGateway =>
                self.route_tunnel_message(message),
            _ => self.route_listener_message(message),
        }
    }

    /// Send `message` to router identified by `router_id`.
    ///
    /// `router_id` could point to local router which causes `message` to be routed locally.
    //
    // TODO(optimization): take deserialized message and serialize it only if it's for remote
    pub fn send_message(&self, router_id: RouterId, message: Vec<u8>) -> Result<(), RoutingError> {
        match router_id == self.router_hash {
            true => {
                // parsing must succeed since this message was created by us
                let message = Message::parse_short(&message).expect("valid message");

                match message.message_type {
                    MessageType::TunnelData
                    | MessageType::TunnelGateway
                    | MessageType::ShortTunnelBuild
                    | MessageType::VariableTunnelBuild => self.route_message(message),
                    message_type => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?message_type,
                            "received non-tunnel message, route to `TunnelManager`",
                        );

                        self.manager.try_send(RoutingKind::Internal { message }).map_err(|error| {
                            match error {
                                TrySendError::Full(RoutingKind::Internal { message }) =>
                                    RoutingError::ChannelFull(message),
                                TrySendError::Closed(RoutingKind::Internal { message }) =>
                                    RoutingError::ChannelClosed(message),
                                _ => unreachable!(),
                            }
                        })
                    }
                }
            }
            false => self.manager.try_send(RoutingKind::External { router_id, message }).map_err(
                |error| match error {
                    TrySendError::Full(RoutingKind::External { message, .. }) =>
                        RoutingError::ChannelFull(
                            Message::parse_short(&message).expect("valid message"),
                        ),
                    TrySendError::Closed(RoutingKind::External { message, .. }) =>
                        RoutingError::ChannelClosed(
                            Message::parse_short(&message).expect("valid message"),
                        ),
                    _ => unreachable!(),
                },
            ),
        }
    }

    /// Send `message` to router identified by `router_id` and use a TX to inform the caller whether
    /// the message was sent successfully.
    ///
    /// `router_id` could point to local router which causes `message` to be routed locally.
    pub fn send_message_with_feedback(
        &self,
        router_id: RouterId,
        message: Vec<u8>,
        tx: oneshot::Sender<()>,
    ) -> Result<(), RoutingError> {
        match router_id == self.router_hash {
            true => {
                // parsing must succeed since this message was created by us
                let message = Message::parse_short(&message).expect("valid message");

                // internally routed messages are always delivered correctly
                let _ = tx.send(());

                match message.message_type {
                    MessageType::TunnelData
                    | MessageType::TunnelGateway
                    | MessageType::ShortTunnelBuild
                    | MessageType::VariableTunnelBuild => self.route_message(message),
                    message_type => {
                        tracing::info!(
                            target: LOG_TARGET,
                            ?message_type,
                            "received non-tunnel message, route to `TunnelManager`",
                        );

                        self.manager.try_send(RoutingKind::Internal { message }).map_err(|error| {
                            match error {
                                TrySendError::Full(RoutingKind::Internal { message }) =>
                                    RoutingError::ChannelFull(message),
                                TrySendError::Closed(RoutingKind::Internal { message }) =>
                                    RoutingError::ChannelClosed(message),
                                _ => unreachable!(),
                            }
                        })
                    }
                }
            }
            false => self
                .manager
                .try_send(RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                })
                .map_err(|error| match error {
                    TrySendError::Full(RoutingKind::ExternalWithFeedback { message, .. }) =>
                        RoutingError::ChannelFull(
                            Message::parse_short(&message).expect("valid message"),
                        ),
                    TrySendError::Closed(RoutingKind::ExternalWithFeedback { message, .. }) =>
                        RoutingError::ChannelClosed(
                            Message::parse_short(&message).expect("valid message"),
                        ),
                    _ => unreachable!(),
                }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::{tunnel::data::TunnelDataBuilder, MessageBuilder},
        runtime::{mock::MockRuntime, Runtime},
    };
    use mpsc::with_recycle;
    use rand_core::RngCore;
    use thingbuf::mpsc::channel;

    #[test]
    fn tunnel_doesnt_exist() {
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        let message = {
            let message = TunnelDataBuilder::new(TunnelId::from(MockRuntime::rng().next_u32()))
                .with_local_delivery(&vec![1, 3, 3, 7])
                .build::<MockRuntime>(&[0u8; 1028])
                .next()
                .unwrap();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelData)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch())
                .with_payload(&message)
                .build();

            Message::parse_short(&message).unwrap()
        };

        match routing_table.route_message(message).unwrap_err() {
            RoutingError::RouteNotFound(_, _) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[test]
    fn tunnel_exists() {
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add tunnel into routing table
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let tunnel_rx = routing_table.try_add_tunnel::<2>(tunnel_id).unwrap();

        let message = {
            let message = TunnelDataBuilder::new(TunnelId::from(tunnel_id))
                .with_local_delivery(&vec![1, 3, 3, 7])
                .build::<MockRuntime>(&[0u8; 1028])
                .next()
                .unwrap();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelData)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch())
                .with_payload(&message)
                .build();

            Message::parse_short(&message).unwrap()
        };

        assert!(routing_table.route_message(message).is_ok());
        assert!(tunnel_rx.try_recv().is_ok());
    }

    #[test]
    fn listener_doesnt_exist() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        let message = {
            let message = MessageBuilder::short()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch())
                .with_payload(&vec![1, 2, 3, 4, 5])
                .build();

            Message::parse_short(&message).unwrap()
        };

        assert!(routing_table.route_message(message).is_ok());
        assert!(transit_rx.try_recv().is_ok());
    }

    #[test]
    fn listener_exists() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add listener for message into routing table
        let (message_id, mut listener_rx) = routing_table.insert_listener(&mut MockRuntime::rng());

        let message = {
            let message = MessageBuilder::short()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(message_id)
                .with_expiration(MockRuntime::time_since_epoch())
                .with_payload(&vec![1, 2, 3, 4, 5])
                .build();

            Message::parse_short(&message).unwrap()
        };

        assert!(routing_table.route_message(message).is_ok());
        assert!(listener_rx.try_recv().is_ok());
        assert!(transit_rx.try_recv().is_err());
    }

    #[test]
    #[should_panic]
    fn channel_closed() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add listener for message into routing table
        let (message_id, listener_rx) = routing_table.insert_listener(&mut MockRuntime::rng());

        let message = {
            let message = MessageBuilder::short()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(message_id)
                .with_expiration(MockRuntime::time_since_epoch())
                .with_payload(&vec![1, 2, 3, 4, 5])
                .build();

            Message::parse_short(&message).unwrap()
        };
        drop(listener_rx);

        match routing_table.route_message(message).unwrap_err() {
            RoutingError::ChannelClosed(_) => {}
            error => panic!("invalid error: {error:?}"),
        }
        assert!(transit_rx.try_recv().is_err());
    }

    #[test]
    fn channel_full() {
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add tunnel into routing table
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let tunnel_rx = routing_table.try_add_tunnel::<2>(tunnel_id).unwrap();

        // fill the tunnel channel with messages
        for _ in 0..2 {
            let message = {
                let message = TunnelDataBuilder::new(TunnelId::from(tunnel_id))
                    .with_local_delivery(&vec![1, 3, 3, 7])
                    .build::<MockRuntime>(&[0u8; 1028])
                    .next()
                    .unwrap();

                let message = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(MockRuntime::rng().next_u32())
                    .with_expiration(MockRuntime::time_since_epoch())
                    .with_payload(&message)
                    .build();

                Message::parse_short(&message).unwrap()
            };

            assert!(routing_table.route_message(message).is_ok());
        }

        // try to send one more message
        let message = {
            let message = TunnelDataBuilder::new(TunnelId::from(tunnel_id))
                .with_local_delivery(&vec![1, 3, 3, 7])
                .build::<MockRuntime>(&[0u8; 1028])
                .next()
                .unwrap();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelData)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch())
                .with_payload(&message)
                .build();

            Message::parse_short(&message).unwrap()
        };

        match routing_table.route_message(message).unwrap_err() {
            RoutingError::ChannelFull(_) => {}
            error => panic!("invalid error: {error:?}"),
        }

        for _ in 0..2 {
            assert!(tunnel_rx.try_recv().is_ok());
        }
    }

    #[test]
    fn send_message_to_remote() {
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add listener for message into routing table
        let (message_id, _listener_rx) = routing_table.insert_listener(&mut MockRuntime::rng());

        let message = MessageBuilder::short()
            .with_message_type(MessageType::ShortTunnelBuild)
            .with_message_id(message_id)
            .with_expiration(MockRuntime::time_since_epoch())
            .with_payload(&vec![1, 2, 3, 4, 5])
            .build();

        assert!(routing_table.send_message(RouterId::from(vec![1, 3, 3, 7]), message).is_ok());
        assert!(manager_rx.try_recv().is_ok());
    }

    #[test]
    fn route_message_locally() {
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::ShortTunnelBuild)
            .with_message_id(MessageId::from(MockRuntime::rng().next_u32()))
            .with_expiration(MockRuntime::time_since_epoch())
            .with_payload(&vec![1, 2, 3, 4, 5])
            .build();

        assert!(routing_table.send_message(RouterId::from(vec![1, 2, 3, 4]), message).is_ok());
        assert!(transit_rx.try_recv().is_ok());
    }

    #[test]
    fn tunnel_already_exists() {
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(RouterId::from(vec![1, 2, 3, 4]), manager_tx, transit_tx);

        // add tunnel into routing table
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let _ = routing_table.try_add_tunnel::<2>(tunnel_id).unwrap();

        // try to add another transit tunnel with same id in the routing table
        // and verify that the call fails
        match routing_table.try_add_tunnel::<2>(tunnel_id).unwrap_err() {
            RoutingError::TunnelExists(duplicate_tunnel) => {
                assert_eq!(duplicate_tunnel, tunnel_id);
            }
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn route_internal() {
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let router_id = RouterId::from(vec![1, 2, 3, 4]);
        let routing_table = RoutingTable::new(router_id.clone(), manager_tx, transit_tx);

        let message_id = MockRuntime::rng().next_u32();
        let message = MessageBuilder::short()
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(message_id)
            .with_expiration(MockRuntime::time_since_epoch())
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        routing_table.send_message(router_id, message).unwrap();

        match manager_rx.try_recv().unwrap() {
            RoutingKind::Internal { message } => {
                assert_eq!(message.message_id, message_id);
                assert_eq!(message.message_type, MessageType::DatabaseLookup);
            }
            _ => panic!("invalid routing kind"),
        }
    }
}
