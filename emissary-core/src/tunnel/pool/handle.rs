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
    error::ChannelError,
    i2np::Message,
    primitives::{Lease, RouterId, TunnelId},
    tunnel::pool::{context::TunnelMessageRecycle, TunnelMessage, TunnelPoolConfig},
};

use futures::Stream;
use futures_channel::oneshot;
use thingbuf::mpsc;

use alloc::vec::Vec;
use core::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

/// Events emitted by a `TunnelPool`.
#[derive(Default, Debug, Clone)]
pub enum TunnelPoolEvent {
    /// Tunnel pool has been shut down.
    TunnelPoolShutDown,

    /// Inbound tunnel has been built.
    InboundTunnelBuilt {
        /// Tunnel ID.
        tunnel_id: TunnelId,

        /// `Lease2` of the inbound tunnel.
        lease: Lease,
    },

    /// Outbound tunnel has been built.
    OutboundTunnelBuilt {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Inbound tunnel has been expired.
    InboundTunnelExpired {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Outbound tunnel has been expired.
    OutboundTunnelExpired {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Inbound tunnel is about to expire.
    #[allow(unused)]
    InboundTunnelExpiring {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Outbound tunnel is about to expire.
    #[allow(unused)]
    OutboundTunnelExpiring {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Message received into one of the inbound tunnels.
    Message {
        /// Received I2NP message.
        message: Message,
    },

    /// Dummy event.
    #[default]
    Dummy,
}

impl fmt::Display for TunnelPoolEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TunnelPoolShutDown => write!(f, "TunnelPoolEvent::TunnelPoolShutDown"),
            Self::InboundTunnelBuilt { .. } => write!(f, "TunnelPoolEvent::InboundTunnelBuilt"),
            Self::OutboundTunnelBuilt { .. } => write!(f, "TunnelPoolEvent::OutboundTunnelBuilt"),
            Self::InboundTunnelExpired { .. } => write!(f, "TunnelPoolEvent::InboundTunnelExpired"),
            Self::OutboundTunnelExpired { .. } =>
                write!(f, "TunnelPoolEvent::OutboundTunnelExpired"),
            Self::InboundTunnelExpiring { .. } =>
                write!(f, "TunnelPoolEvent::InboundTunnelExpiring"),
            Self::OutboundTunnelExpiring { .. } =>
                write!(f, "TunnelPoolEvent::OutboundTunnelExpiring"),
            Self::Message { .. } => write!(f, "TunnelPoolEvent::Message"),
            Self::Dummy => write!(f, "TunnelPoolEvent::Dummy"),
        }
    }
}

/// Tunnel message sender.
#[derive(Clone)]
pub struct TunnelMessageSender(mpsc::Sender<TunnelMessage, TunnelMessageRecycle>);

impl TunnelMessageSender {
    /// Create [`TunnelSender`] with `message`.
    ///
    /// [`TunnelSender`] allows the sender to construct a tunnel message of correct kind
    /// (router/tunnel delivery) and send it either in blocking or non-blocking manner.
    pub fn send_message(&self, message: Vec<u8>) -> TunnelSender<'_> {
        TunnelSender {
            kind: None,
            message,
            outbound_tunnel: None,
            tx: &self.0,
        }
    }
}

/// Delivery kind.
enum DeliveryKind {
    /// Tunnel delivery.
    TunnelDelivery {
        /// ID of the IBGW tunenl.
        tunnel_id: TunnelId,

        /// ID of the IBGW router.
        router_id: RouterId,
    },

    /// Router delivery.
    RouterDelivery {
        /// ID of the router.
        router_id: RouterId,
    },
}

/// Tunnel sender builder for a single message.
pub struct TunnelSender<'a> {
    /// Delivery kind.
    kind: Option<DeliveryKind>,

    /// Message.
    message: Vec<u8>,

    /// Outbound tunnel over which the message should be sent, if specified.
    ///
    /// If not specified, a random tunnel of the pool is used for delivery.
    outbound_tunnel: Option<TunnelId>,

    /// TX channel for sending the message.
    tx: &'a mpsc::Sender<TunnelMessage, TunnelMessageRecycle>,
}

impl TunnelSender<'_> {
    /// Send message to router identified by `router_id`.
    pub fn router_delivery(mut self, router_id: RouterId) -> Self {
        self.kind = Some(DeliveryKind::RouterDelivery { router_id });
        self
    }

    /// Send message to tunnel identified by (`router_id`, `tunnel_id`) tuple (IBGW).
    pub fn tunnel_delivery(mut self, router_id: RouterId, tunnel_id: TunnelId) -> Self {
        self.kind = Some(DeliveryKind::TunnelDelivery {
            tunnel_id,
            router_id,
        });
        self
    }

    /// Specify the ID of the outbound tunnel over which the messages should be sent.
    ///
    /// If not specified, a random outbound tunnel is selected for delivery.
    pub fn via_outbound_tunnel(mut self, tunnel_id: TunnelId) -> Self {
        self.outbound_tunnel = Some(tunnel_id);
        self
    }

    /// Attempt to send message to tunnel pool for delivery and return and error if the channel is
    /// full or closed.
    pub fn try_send(self) -> Result<(), ChannelError> {
        let message = match self.kind.expect("to exist") {
            DeliveryKind::TunnelDelivery {
                tunnel_id,
                router_id,
            } => TunnelMessage::TunnelDeliveryViaRoute {
                router_id,
                tunnel_id,
                outbound_tunnel: self.outbound_tunnel,
                message: self.message,
            },
            DeliveryKind::RouterDelivery { router_id } => TunnelMessage::RouterDeliveryViaRoute {
                router_id,
                outbound_tunnel: self.outbound_tunnel,
                message: self.message,
            },
        };

        self.tx.try_send(message).map_err(From::from)
    }

    /// Attempt to send message to tunnel pool for delivery and return and error if the channel is
    /// closed
    ///
    /// The function blocks until there's enough capacity in the channel to send the message.
    #[allow(unused)]
    pub async fn send(self) -> Result<(), ChannelError> {
        let message = match self.kind.expect("to exist") {
            DeliveryKind::TunnelDelivery {
                tunnel_id,
                router_id,
            } => TunnelMessage::TunnelDeliveryViaRoute {
                router_id,
                tunnel_id,
                outbound_tunnel: self.outbound_tunnel,
                message: self.message,
            },
            DeliveryKind::RouterDelivery { router_id } => TunnelMessage::RouterDeliveryViaRoute {
                router_id,
                outbound_tunnel: self.outbound_tunnel,
                message: self.message,
            },
        };

        self.tx.send(message).await.map_err(|_| ChannelError::Closed)
    }
}

/// Tunnel pool handle.
///
/// Allows `Destination`s to communicate with their `TunnelPool`.
pub struct TunnelPoolHandle {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// RX channel for receiving events from `TunnelPool`.
    event_rx: mpsc::Receiver<TunnelPoolEvent>,

    /// Implementation of [`TunnelSender`].
    sender: TunnelMessageSender,

    /// TX channel for sending a shutdown command to `TunnelPool`.
    #[allow(unused)]
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TunnelPoolHandle {
    /// Create new [`TunnelPoolHandle`].
    pub(super) fn new(
        config: TunnelPoolConfig,
        message_tx: mpsc::Sender<TunnelMessage, TunnelMessageRecycle>,
    ) -> (Self, mpsc::Sender<TunnelPoolEvent>, oneshot::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (event_tx, event_rx) = mpsc::channel(64);

        (
            Self {
                config,
                event_rx,
                sender: TunnelMessageSender(message_tx),
                shutdown_tx: Some(shutdown_tx),
            },
            event_tx,
            shutdown_rx,
        )
    }

    /// Send shutdown signal to `TunnelPool`.
    ///
    /// [`TunnelPoolEvent::TunnelPoolShutDown`] is emitted before `TunnelPool` is shut down.
    pub fn shutdown(&mut self) {
        self.shutdown_tx.take().map(|tx| tx.send(()));
    }

    /// Get reference to [`TunnelPoolConfig`] of the tunnel pool.
    pub fn config(&self) -> &TunnelPoolConfig {
        &self.config
    }

    /// Create [`TunnelSender`] with `message`.
    ///
    /// Note that this function doesn't send the message but creates a sender which the caller
    /// can use to construct a message with correct delivery style.
    pub fn send_message(&self, message: Vec<u8>) -> TunnelSender<'_> {
        self.sender.send_message(message)
    }

    /// Get a copy of [`TunnelMessageSender`].
    pub fn sender(&self) -> TunnelMessageSender {
        self.sender.clone()
    }

    /// Create new [`TunnelPoolHandle`] for testing.
    #[cfg(test)]
    pub fn create() -> (
        Self,
        mpsc::Receiver<TunnelMessage, TunnelMessageRecycle>,
        mpsc::Sender<TunnelPoolEvent>,
        oneshot::Receiver<()>,
    ) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (event_tx, event_rx) = mpsc::channel(64);
        let (message_tx, message_rx) = mpsc::with_recycle(64, TunnelMessageRecycle::default());

        (
            Self {
                config: Default::default(),
                event_rx,
                sender: TunnelMessageSender(message_tx),
                shutdown_tx: Some(shutdown_tx),
            },
            message_rx,
            event_tx,
            shutdown_rx,
        )
    }

    #[cfg(test)]
    /// Create new [`TunnelPoolHandle`] from `config`
    pub fn from_config(
        config: TunnelPoolConfig,
    ) -> (
        Self,
        mpsc::Receiver<TunnelMessage, TunnelMessageRecycle>,
        mpsc::Sender<TunnelPoolEvent>,
        oneshot::Receiver<()>,
    ) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (event_tx, event_rx) = mpsc::channel(64);
        let (message_tx, message_rx) = mpsc::with_recycle(64, TunnelMessageRecycle::default());

        (
            Self {
                config,
                event_rx,
                sender: TunnelMessageSender(message_tx),
                shutdown_tx: Some(shutdown_tx),
            },
            message_rx,
            event_tx,
            shutdown_rx,
        )
    }
}

impl Stream for TunnelPoolHandle {
    type Item = TunnelPoolEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.event_rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_to_router_via_any() {
        let (tx, rx) = mpsc::with_recycle(64, TunnelMessageRecycle::default());
        let sender = TunnelMessageSender(tx);

        let remote = RouterId::random();

        sender
            .send_message(vec![1, 3, 3, 7])
            .router_delivery(remote.clone())
            .send()
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            TunnelMessage::RouterDeliveryViaRoute {
                router_id,
                outbound_tunnel,
                message,
            } => {
                assert_eq!(router_id, remote);
                assert_eq!(message, vec![1, 3, 3, 7]);
                assert!(outbound_tunnel.is_none());
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn send_to_tunnel_via_any() {
        let (tx, rx) = mpsc::with_recycle(64, TunnelMessageRecycle::default());
        let sender = TunnelMessageSender(tx);

        let remote_router = RouterId::random();
        let remote_tunnel = TunnelId::random();

        sender
            .send_message(vec![1, 3, 3, 7])
            .tunnel_delivery(remote_router.clone(), remote_tunnel)
            .send()
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            TunnelMessage::TunnelDeliveryViaRoute {
                router_id,
                tunnel_id,
                outbound_tunnel,
                message,
            } => {
                assert_eq!(router_id, remote_router);
                assert_eq!(tunnel_id, remote_tunnel);
                assert_eq!(message, vec![1, 3, 3, 7]);
                assert!(outbound_tunnel.is_none());
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn send_to_router_via_route() {
        let (tx, rx) = mpsc::with_recycle(64, TunnelMessageRecycle::default());
        let sender = TunnelMessageSender(tx);

        let remote = RouterId::random();
        let obgw = TunnelId::random();

        sender
            .send_message(vec![1, 3, 3, 7])
            .router_delivery(remote.clone())
            .via_outbound_tunnel(obgw)
            .send()
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            TunnelMessage::RouterDeliveryViaRoute {
                router_id,
                outbound_tunnel,
                message,
            } => {
                assert_eq!(router_id, remote);
                assert_eq!(message, vec![1, 3, 3, 7]);
                assert_eq!(outbound_tunnel, Some(obgw));
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn send_to_tunnel_via_route() {
        let (tx, rx) = mpsc::with_recycle(64, TunnelMessageRecycle::default());
        let sender = TunnelMessageSender(tx);

        let remote_router = RouterId::random();
        let remote_tunnel = TunnelId::random();
        let obgw = TunnelId::random();

        sender
            .send_message(vec![1, 3, 3, 7])
            .tunnel_delivery(remote_router.clone(), remote_tunnel)
            .via_outbound_tunnel(obgw)
            .send()
            .await
            .unwrap();

        match rx.recv().await.unwrap() {
            TunnelMessage::TunnelDeliveryViaRoute {
                router_id,
                tunnel_id,
                outbound_tunnel,
                message,
            } => {
                assert_eq!(router_id, remote_router);
                assert_eq!(tunnel_id, remote_tunnel);
                assert_eq!(message, vec![1, 3, 3, 7]);
                assert_eq!(outbound_tunnel, Some(obgw));
            }
            _ => panic!("invalid message"),
        }
    }
}
