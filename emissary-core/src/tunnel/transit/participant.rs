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
    events::EventHandle,
    i2np::{tunnel::data::EncryptedTunnelData, Message, MessageType},
    primitives::{RouterId, TunnelId},
    runtime::{Counter, Gauge, Instant, MetricsHandle, Runtime},
    subsystem::SubsystemHandle,
    tunnel::{
        metrics::{
            NUM_DROPPED_MESSAGES, NUM_PARTICIPANTS, NUM_ROUTED_MESSAGES, NUM_TERMINATED,
            NUM_TRANSIT_TUNNELS, TOTAL_TRANSIT_TUNNELS,
        },
        noise::TunnelKeys,
        transit::{TransitTunnel, TERMINATION_TIMEOUT, TRANSIT_TUNNEL_EXPIRATION},
    },
};

use bytes::{BufMut, BytesMut};
use futures::FutureExt;
use rand_core::RngCore;
use thingbuf::mpsc::Receiver;

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::participant";

/// Tunnel participant.
///
/// Only accepts and handles `TunnelData` messages,
/// all other message types are rejected as invalid.
pub struct Participant<R: Runtime> {
    /// Event handle.
    event_handle: EventHandle<R>,

    /// Tunnel expiration timer.
    expiration_timer: R::Timer,

    /// Used inbound bandwidth.
    inbound_bandwidth: usize,

    /// RX channel for receiving messages.
    message_rx: Receiver<Message>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Next router ID.
    next_router: RouterId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Used inbound bandwidth.
    outbound_bandwidth: usize,

    // When was the tunnel started.
    started: Option<R::Instant>,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Total bandwidth.
    total_bandwidth: usize,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel keys.
    tunnel_keys: TunnelKeys,
}

impl<R: Runtime> Participant<R> {
    /// Handle tunnel data.
    ///
    /// Return `RouterId` of the next hop and the message that needs to be forwarded
    /// to them on success.
    fn handle_tunnel_data(
        &mut self,
        tunnel_data: &EncryptedTunnelData,
    ) -> crate::Result<(RouterId, Message)> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            "participant tunnel data",
        );

        // decrypt record and create new `TunnelData` message
        let (ciphertext, iv) = self.tunnel_keys.decrypt_record(tunnel_data);

        // tunnel id + iv key + tunnel data payload length
        let mut out = BytesMut::with_capacity(4 + 16 + ciphertext.len());

        out.put_u32(self.next_tunnel_id.into());
        out.put_slice(&iv);
        out.put_slice(&ciphertext);

        let message = Message {
            message_type: MessageType::TunnelData,
            message_id: R::rng().next_u32(),
            expiration: R::time_since_epoch() + Duration::from_secs(8),
            payload: out.to_vec(),
        };

        Ok((self.next_router.clone(), message))
    }
}

impl<R: Runtime> TransitTunnel<R> for Participant<R> {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        subsystem_handle: SubsystemHandle,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
        event_handle: EventHandle<R>,
    ) -> Self {
        metrics_handle.gauge(NUM_PARTICIPANTS).increment(1);
        metrics_handle.gauge(NUM_TRANSIT_TUNNELS).increment(1);
        metrics_handle.counter(TOTAL_TRANSIT_TUNNELS).increment(1);

        Participant {
            event_handle,
            expiration_timer: R::timer(TRANSIT_TUNNEL_EXPIRATION),
            inbound_bandwidth: 0usize,
            message_rx,
            metrics_handle,
            next_router,
            next_tunnel_id,
            outbound_bandwidth: 0usize,
            started: Some(R::now()),
            subsystem_handle,
            total_bandwidth: 0usize,
            tunnel_id,
            tunnel_keys,
        }
    }
}

impl<R: Runtime> Future for Participant<R> {
    type Output = TunnelId;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "message channel closed",
                    );
                    self.metrics_handle.gauge(NUM_PARTICIPANTS).decrement(1);
                    return Poll::Ready(self.tunnel_id);
                }
                Some(message) => {
                    self.inbound_bandwidth += message.serialized_len_short();
                    self.total_bandwidth += message.serialized_len_short();

                    let MessageType::TunnelData = message.message_type else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            message_type = ?message.message_type,
                            "unsupported message",
                        );
                        self.metrics_handle.counter(NUM_DROPPED_MESSAGES).increment(1);
                        continue;
                    };

                    let Some(message) = EncryptedTunnelData::parse(&message.payload) else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "failed to parse TunnelData message",
                        );
                        self.metrics_handle.counter(NUM_DROPPED_MESSAGES).increment(1);
                        continue;
                    };

                    match self.handle_tunnel_data(&message) {
                        Ok((router, message)) => {
                            self.outbound_bandwidth += message.serialized_len_short();
                            self.total_bandwidth += message.serialized_len_short();

                            match self.subsystem_handle.send(&router, message) {
                                Ok(()) => {
                                    self.metrics_handle.counter(NUM_ROUTED_MESSAGES).increment(1);
                                }
                                Err(error) => {
                                    tracing::error!(
                                        target: LOG_TARGET,
                                        tunnel_id = %self.tunnel_id,
                                        ?error,
                                        "failed to send message",
                                    );
                                    self.metrics_handle.counter(NUM_DROPPED_MESSAGES).increment(1);
                                }
                            }
                        }
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                tunnel_id = %self.tunnel_id,
                                ?error,
                                "failed to parse TunnelData message",
                            );
                            self.metrics_handle.counter(NUM_DROPPED_MESSAGES).increment(1);
                        }
                    }
                }
            }
        }

        // terminate participant if it hasn't had any activity 2 minutes after starting
        if let Some(ref started) = self.started {
            if started.elapsed() > TERMINATION_TIMEOUT {
                self.started = None;

                if self.total_bandwidth == 0 {
                    tracing::debug!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "shutting down tunnel after 2 minutes of inactivity",
                    );
                    self.metrics_handle.gauge(NUM_PARTICIPANTS).decrement(1);
                    self.metrics_handle.gauge(NUM_TRANSIT_TUNNELS).decrement(1);
                    self.metrics_handle.counter(NUM_TERMINATED).increment(1);

                    return Poll::Ready(self.tunnel_id);
                }
            }
        }

        if self.event_handle.poll_unpin(cx).is_ready() {
            self.event_handle.transit_inbound_bandwidth(self.inbound_bandwidth);
            self.event_handle.transit_outbound_bandwidth(self.outbound_bandwidth);
            self.inbound_bandwidth = 0;
            self.outbound_bandwidth = 0;
        }

        if self.expiration_timer.poll_unpin(cx).is_ready() {
            self.metrics_handle.gauge(NUM_PARTICIPANTS).decrement(1);
            self.metrics_handle.gauge(NUM_TRANSIT_TUNNELS).decrement(1);

            return Poll::Ready(self.tunnel_id);
        }

        Poll::Pending
    }
}
