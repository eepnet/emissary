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
    i2np::{tunnel::gateway::TunnelGateway, Message},
    primitives::TunnelId,
    runtime::Runtime,
    tunnel::{pool::TUNNEL_BUILD_EXPIRATION, routing_table::RoutingTable},
};

use futures::FutureExt;
use futures_channel::oneshot;
use thingbuf::mpsc;

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file:
const LOG_TARGET: &str = "emissary::tunnel::pool::zero-hop";

/// Fake 0-hop inbound tunnel.
///
/// These tunnels are used to receive one `TunnelGateway` message which contains a tunnel build
/// response which it routes back to the installed listener (if it exists), after which the tunnel
/// gets destructed.
pub struct ZeroHopInboundTunnel<R: Runtime> {
    /// Expiration timer.
    expiration_timer: R::Timer,

    /// RX channel for receiving a message.
    message_rx: mpsc::Receiver<Message>,

    /// TX channel for sending reply to the listener.
    reply_tx: Option<oneshot::Sender<Message>>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,
}

impl<R: Runtime> ZeroHopInboundTunnel<R> {
    /// Create new [`ZeroHopInboundTunnel`].
    pub fn new(routing_table: RoutingTable) -> (TunnelId, Self, oneshot::Receiver<Message>) {
        let (tunnel_id, message_rx) = routing_table.insert_tunnel::<1>(&mut R::rng());
        let (tx, rx) = oneshot::channel();

        (
            tunnel_id,
            Self {
                expiration_timer: R::timer(TUNNEL_BUILD_EXPIRATION),
                message_rx,
                reply_tx: Some(tx),
                routing_table,
                tunnel_id,
            },
            rx,
        )
    }

    /// Handle receive I2NP message, presumably containing a tunnel build response.
    fn on_message(&mut self, message: Message) {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            message_type = ?message.message_type,
            "handle message",
        );

        let Some(TunnelGateway { payload, .. }) = TunnelGateway::parse(&message.payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                message_type = ?message.message_type,
                "invalid message, expected `TunnelGateway`",
            );
            return;
        };

        match Message::parse_standard(payload) {
            Ok(message) => {
                self.reply_tx.take().map(|tx| tx.send(message));
            }
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    message_type = ?message.message_type,
                    ?error,
                    "invalid message, expected standard i2np message",
                );
            }
        }
    }
}

impl<R: Runtime> Future for ZeroHopInboundTunnel<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.message_rx.poll_recv(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    zero_hop_tunnel = %self.tunnel_id,
                    "channel closed while waiting for build response",
                );

                self.routing_table.remove_tunnel(&self.tunnel_id);
                return Poll::Ready(());
            }
            Poll::Ready(Some(message)) => {
                self.on_message(message);
                self.routing_table.remove_tunnel(&self.tunnel_id);
                return Poll::Ready(());
            }
        }

        if self.expiration_timer.poll_unpin(cx).is_ready() {
            tracing::trace!(
                target: LOG_TARGET,
                zero_hop_tunnel = %self.tunnel_id,
                "zero-hop tunnel expired before reply",
            );

            self.routing_table.remove_tunnel(&self.tunnel_id);
            return Poll::Ready(());
        }

        Poll::Pending
    }
}
