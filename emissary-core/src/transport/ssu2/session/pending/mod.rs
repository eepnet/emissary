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
    primitives::RouterId,
    runtime::{Instant, Runtime},
    transport::ssu2::session::active::Ssu2SessionContext,
};

use bytes::BytesMut;
use futures::FutureExt;

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub mod inbound;
pub mod outbound;

/// Maximum allowed clock skew.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Status returned by [`PendingSession`] to [`Ssu2Socket`].
pub enum PendingSsu2SessionStatus<R: Runtime> {
    /// New session has been opened.
    ///
    /// Session info is forwaded to [`Ssu2Socket`] and to [`TransportManager`] for validation and
    /// if the session is accepted, a new future is started for the session.
    NewInboundSession {
        /// Context for the active session.
        context: Ssu2SessionContext,

        /// Destination connection ID.
        dst_id: u64,

        /// ACK for `SessionConfirmed`.
        pkt: BytesMut,

        /// When was the handshake started.
        started: R::Instant,

        /// Socket address of the remote router.
        target: SocketAddr,

        /// Key for decrypting the header of a `SessionConfirmed` message
        ///
        /// Only used by inbound connections which have been rejected by
        /// `TransportManager` and are now trying to terminate the connection.
        k_header_2: [u8; 32],
    },

    /// New outbound session.
    NewOutboundSession {
        /// Context for the active session.
        context: Ssu2SessionContext,

        /// Source connection ID.
        src_id: u64,

        /// When was the handshake started.
        started: R::Instant,
    },

    /// Pending session terminated due to fatal error, e.g., decryption error.
    SessionTerminated {
        /// Address of remote peer.
        address: Option<SocketAddr>,

        /// Connection ID.
        ///
        /// Either destination or source connection ID, depending on whether the session
        /// was inbound or outbound.
        connection_id: u64,

        /// ID of the remote router.
        ///
        /// `None` if the session was inbound.
        router_id: Option<RouterId>,

        /// When was the handshake started.
        started: R::Instant,
    },

    /// Pending session terminated due to timeout.
    Timeout {
        /// Connection ID.
        ///
        /// Either destination or source connection ID, depending on whether the session
        /// was inbound or outbound.
        connection_id: u64,

        /// ID of the remote router.
        ///
        /// `None` if the session was inbound.
        router_id: Option<RouterId>,

        /// When was the handshake started.
        started: R::Instant,
    },

    /// [`SSu2Socket`] has been closed.
    SocketClosed {
        /// When was the handshake started.
        started: R::Instant,
    },
}

impl<R: Runtime> fmt::Debug for PendingSsu2SessionStatus<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PendingSsu2SessionStatus::NewInboundSession {
                dst_id,
                target,
                started,
                ..
            } => f
                .debug_struct("PendingSsu2SessionStatus::NewInboundSession")
                .field("dst_id", &dst_id)
                .field("target", &target)
                .field("started", &started)
                .finish_non_exhaustive(),
            PendingSsu2SessionStatus::NewOutboundSession {
                src_id, started, ..
            } => f
                .debug_struct("PendingSsu2SessionStatus::NewOutboundSession")
                .field("src_id", &src_id)
                .field("started", &started)
                .finish_non_exhaustive(),
            PendingSsu2SessionStatus::SessionTerminated {
                address,
                connection_id,
                router_id,
                started,
                ..
            } => f
                .debug_struct("PendingSsu2SessionStatus::SessionTerminated")
                .field("address", &address)
                .field("connection_id", &connection_id)
                .field("router_id", &router_id)
                .field("started", &started)
                .finish_non_exhaustive(),
            PendingSsu2SessionStatus::Timeout {
                connection_id,
                router_id,
                started,
            } => f
                .debug_struct("PendingSsu2SessionStatus::Timeout")
                .field("connection_id", &connection_id)
                .field("router_id", &router_id)
                .field("started", &started)
                .finish_non_exhaustive(),
            PendingSsu2SessionStatus::SocketClosed { started } => f
                .debug_struct("PendingSsu2SessionStatus::SocketClosed")
                .field("started", &started)
                .finish(),
        }
    }
}

impl<R: Runtime> PendingSsu2SessionStatus<R> {
    /// Return duration of the handshake in milliseconds.
    pub fn duration(&self) -> f64 {
        match self {
            Self::NewInboundSession { started, .. } => started.elapsed().as_millis() as f64,
            Self::NewOutboundSession { started, .. } => started.elapsed().as_millis() as f64,
            Self::SessionTerminated { started, .. } => started.elapsed().as_millis() as f64,
            Self::Timeout { started, .. } => started.elapsed().as_millis() as f64,
            Self::SocketClosed { started, .. } => started.elapsed().as_millis() as f64,
        }
    }
}

/// Events emitted by [`PacketRetransmitter`].
pub enum PacketRetransmitterEvent {
    /// Retransmit packet to remote router.
    Retransmit {
        /// Packet that needs to be retransmitted.
        pkt: Vec<u8>,
    },

    /// Operation has timed out.
    Timeout,
}

/// Packet retransmitter.
pub struct PacketRetransmitter<R: Runtime> {
    /// Packet that should be retransmitted if a timeout occurs.
    pkt: Vec<u8>,

    /// Timeouts for packet retransmission.
    timeouts: VecDeque<Duration>,

    /// Timer for triggering retransmit/timeout.
    timer: R::Timer,
}

impl<R: Runtime> PacketRetransmitter<R> {
    /// Create inactive [`PacketRetransmitter`].
    ///
    /// Used by a pending inbound session when a `Retry` message has been sent but no message has
    /// been received as a response.
    ///
    /// `timeout` specifies how long a new `TokenRequest`/`SessionRequest` is awaited before the
    /// inbound session is destroyed.
    pub fn inactive(timeout: Duration) -> Self {
        Self {
            pkt: Vec::new(),
            timeouts: VecDeque::new(),
            timer: R::timer(timeout),
        }
    }

    /// Create new [`PacketRetransmitter`] for `TokenRequest`.
    ///
    /// First retransmit happens 3 seconds after the packet is sent for the first time and no
    /// response has been heard. The second retransmit happens 6 seconds after the first retransmit
    /// and `TokenRequest` timeouts 6 seconds after the second retransmit.
    ///
    /// <https://geti2p.net/spec/ssu2#token-request>
    pub fn token_request(pkt: Vec<u8>) -> Self {
        Self {
            pkt,
            timeouts: VecDeque::from_iter([Duration::from_secs(6), Duration::from_secs(6)]),
            timer: R::timer(Duration::from_secs(3)),
        }
    }

    /// Create new [`PacketRetransmitter`] for `SessionRequest`.
    ///
    /// First retransmit happens 1.25 seconds after `SessionRequest` was sent for the first
    /// time. After that, the packet is retransmitted twice, first after awaiting 2.5 seconds after
    /// the first transmit and 5 seconds after the second retransmit. If no response is heard after
    /// 6.25 seconds after the last retransmit, `SessionRequest` timeouts.
    ///
    /// <https://geti2p.net/spec/ssu2#session-request>
    pub fn session_request(pkt: Vec<u8>) -> Self {
        Self {
            pkt,
            timeouts: VecDeque::from_iter([
                Duration::from_millis(2500),
                Duration::from_millis(5000),
                Duration::from_millis(6250),
            ]),
            timer: R::timer(Duration::from_millis(1250)),
        }
    }

    /// Create new [`PacketRetransmitter`] for `SessionCreated`.
    ///
    /// First retransmit happens happens 1 second after `SessionCreated` was sent for the first
    /// time. After that, the packet is retransmitted twice, first after awaiting 2 seconds after
    /// the first transmit and 4 seconds after the second retransmit. If no response is after 5
    /// seconds after the last retransmit, `SessionCreated` timeouts.
    ///
    /// <https://geti2p.net/spec/ssu2#session-created>
    pub fn session_created(pkt: Vec<u8>) -> Self {
        Self {
            pkt,
            timeouts: VecDeque::from_iter([
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(5),
            ]),
            timer: R::timer(Duration::from_secs(1)),
        }
    }

    /// Create new [`PacketRetransmitter`] for `SessionConfirmed`.
    ///
    /// First retransmit happens 1.25 seconds after `SessionConfirmed` was sent for the first
    /// time. After that, the packet is retransmitted twice, first after awaiting 2.5 seconds after
    /// the first transmit and 5 seconds after the second retransmit. If no response is heard after
    /// 6.25 seconds after the last retransmit, `SessionConfirmed` timeouts.
    ///
    /// Response to a `SessionConfirmed` is `Data` packet and the outbound pending session is not
    /// reported to [`Ssu2Socket`] until a `Data` packet is received from responder (Bob).
    ///
    /// <https://geti2p.net/spec/ssu2#session-confirmed>
    pub fn session_confirmed(pkt: Vec<u8>) -> Self {
        Self {
            pkt,
            timeouts: VecDeque::from_iter([
                Duration::from_millis(2500),
                Duration::from_millis(5000),
                Duration::from_millis(6250),
            ]),
            timer: R::timer(Duration::from_millis(1250)),
        }
    }
}

impl<R: Runtime> Future for PacketRetransmitter<R> {
    type Output = PacketRetransmitterEvent;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        futures::ready!(self.timer.poll_unpin(cx));

        match self.timeouts.pop_front() {
            Some(timeout) => {
                self.timer = R::timer(timeout);
                let _ = self.timer.poll_unpin(cx);

                Poll::Ready(PacketRetransmitterEvent::Retransmit {
                    pkt: self.pkt.clone(),
                })
            }
            None => Poll::Ready(PacketRetransmitterEvent::Timeout),
        }
    }
}
