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
    crypto::{sha256::Sha256, StaticPrivateKey},
    error::{ChannelError, Ssu2Error},
    primitives::{RouterId, RouterInfo, TransportKind},
    router::context::RouterContext,
    runtime::{Counter, Gauge, Histogram, JoinSet, MetricsHandle, Runtime, UdpSocket},
    subsystem::SubsystemEvent,
    transport::{
        ssu2::{
            message::{HeaderKind, HeaderReader},
            metrics::*,
            peer_test::{PeerTestManager, PeerTestManagerEvent},
            session::{
                active::{Ssu2Session, Ssu2SessionContext},
                pending::{
                    inbound::{InboundSsu2Context, InboundSsu2Session},
                    outbound::{OutboundSsu2Context, OutboundSsu2Session},
                    PendingSsu2SessionStatus,
                },
                terminating::{TerminatingSsu2Session, TerminationContext},
            },
            Packet,
        },
        Direction, TerminationReason, TransportEvent,
    },
};

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, errors::TrySendError, Sender};

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    fmt, mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::socket";

/// Protocol name.
const PROTOCOL_NAME: &str = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

/// SSU2 session channel size.
///
/// This is the channel from [`Ssu2Socket`] to a pending/active SSU2 session.
const CHANNEL_SIZE: usize = 256usize;

/// Maximum datagram size.
const DATAGRAM_MAX_SIZE: usize = 0xfff;

/// Pending session kind.
enum PendingSessionKind {
    /// Pending inbound session.
    Inbound {
        /// Initial `Data` packet that ACKs `SessionConfirmed`.
        pkt: BytesMut,

        /// Socket address of the remote router.
        address: SocketAddr,

        /// Session context.
        context: Ssu2SessionContext,

        /// Destination connection ID.
        ///
        /// This is the connection ID selected by the remote router and is used to remove pending
        /// session context in case it's rejected by the `TransportManager`.
        dst_id: u64,

        /// Key for decrypting the header of `SessionConfirmed` message.
        k_header_2: [u8; 32],
    },

    /// Pending outbound session.
    Outbound {
        // Socket address of the remote router.
        address: SocketAddr,

        /// Session context.
        context: Ssu2SessionContext,

        /// Source connection ID.
        ///
        /// This is the connection ID selected by us which the remote router uses to send us
        /// messages and it will be used to remove the session context in case the connection
        /// is rejected.
        src_id: u64,
    },
}

impl fmt::Debug for PendingSessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PendingSessionKind::Inbound {
                address,
                context,
                dst_id,
                ..
            } => f
                .debug_struct("PendingSessionKind::Inbound")
                .field("address", &address)
                .field("dst_id", &dst_id)
                .field("src_id", &context.dst_id)
                .finish_non_exhaustive(),
            PendingSessionKind::Outbound {
                address,
                context,
                src_id,
            } => f
                .debug_struct("PendingSessionKind::Outbound")
                .field("address", &address)
                .field("dst_id", &context.dst_id)
                .field("src_id", &src_id)
                .finish_non_exhaustive(),
        }
    }
}

/// Write state.
enum WriteState {
    /// Get next packet.
    GetPacket,

    /// Send packet.
    SendPacket {
        /// Packet.
        pkt: BytesMut,

        /// Target.
        target: SocketAddr,
    },

    /// Poisoned.
    Poisoned,
}

/// SSU2 socket.
pub struct Ssu2Socket<R: Runtime> {
    /// Active sessions.
    ///
    /// The session returns a `(RouterId, destination connection ID)` tuple when it exits.
    active_sessions: R::JoinSet<TerminationContext<R>>,

    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Introduction key.
    intro_key: [u8; 32],

    /// Outbound state.
    outbound_state: Bytes,

    /// Peer test manager.
    peer_test_manager: PeerTestManager<R>,

    /// Pending outbound sessions.
    ///
    /// Remote routers' intro keys indexed by their socket addresses.
    pending_outbound: HashMap<SocketAddr, [u8; 32]>,

    /// Pending outbound packets.
    pending_pkts: VecDeque<(BytesMut, SocketAddr)>,

    /// Pending SSU2 sessions.
    pending_sessions: R::JoinSet<PendingSsu2SessionStatus<R>>,

    /// Datagram read buffer.
    read_buffer: Vec<u8>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// SSU2 sessions.
    sessions: HashMap<u64, Sender<Packet>>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Terminating sessions.
    terminating_session: R::JoinSet<(RouterId, u64)>,

    /// TX channel for sending events to `SubsystemManager`.
    #[allow(unused)]
    transport_tx: Sender<SubsystemEvent>,

    /// Unvalidated sessions.
    unvalidated_sessions: HashMap<RouterId, PendingSessionKind>,

    /// Waker.
    waker: Option<Waker>,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Ssu2Socket<R> {
    /// Create new [`Ssu2Socket`].
    pub fn new(
        socket: R::UdpSocket,
        static_key: StaticPrivateKey,
        intro_key: [u8; 32],
        transport_tx: Sender<SubsystemEvent>,
        router_ctx: RouterContext<R>,
    ) -> Self {
        let state = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();
        let chaining_key = state.clone();
        let outbound_state = Sha256::new().update(&state).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(static_key.public().to_vec())
            .finalize();

        // TODO: pass intro key
        let peer_test_manager = PeerTestManager::new(intro_key, socket.clone(), router_ctx.clone());

        Self {
            active_sessions: R::join_set(),
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            intro_key,
            outbound_state: Bytes::from(outbound_state),
            peer_test_manager,
            pending_outbound: HashMap::new(),
            pending_pkts: VecDeque::new(),
            pending_sessions: R::join_set(),
            read_buffer: vec![0u8; DATAGRAM_MAX_SIZE],
            router_ctx,
            sessions: HashMap::new(),
            socket,
            static_key,
            terminating_session: R::join_set(),
            transport_tx,
            unvalidated_sessions: HashMap::new(),
            waker: None,
            write_state: WriteState::GetPacket,
        }
    }

    /// Handle packet.
    //
    // TODO: needs as lot of refactoring
    // TODO: explain what happens here
    fn handle_packet(
        &mut self,
        mut datagram: Vec<u8>,
        address: SocketAddr,
    ) -> Result<(), Ssu2Error> {
        let mut reader = HeaderReader::new(self.intro_key, &mut datagram)?;
        let connection_id = reader.dst_id();

        if let Some(tx) = self.sessions.get_mut(&connection_id) {
            match tx.try_send(Packet {
                pkt: datagram,
                address,
            }) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Closed(_)) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?connection_id,
                        ?address,
                        "session did not exit cleanly",
                    );
                    debug_assert!(false);

                    return Err(Ssu2Error::Channel(ChannelError::Closed));
                }
                Err(_) => {
                    self.router_ctx.metrics_handle().counter(NUM_DROPS_CHANNEL_FULL).increment(1);
                    return Err(Ssu2Error::Channel(ChannelError::Full));
                }
            }
        }

        match reader.parse(self.intro_key) {
            Ok(HeaderKind::TokenRequest {
                net_id,
                pkt_num,
                src_id,
            }) => {
                if net_id != self.router_ctx.net_id() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        our_net_id = ?self.router_ctx.net_id(),
                        their_net_id = ?net_id,
                        "network id mismatch",
                    );
                    return Err(Ssu2Error::NetworkMismatch);
                }

                let (tx, rx) = channel(CHANNEL_SIZE);
                let session = InboundSsu2Session::<R>::new(InboundSsu2Context {
                    address,
                    chaining_key: self.chaining_key.clone(),
                    dst_id: connection_id,
                    intro_key: self.intro_key,
                    net_id: self.router_ctx.net_id(),
                    pkt: datagram,
                    pkt_num,
                    rx,
                    socket: self.socket.clone(),
                    src_id,
                    state: self.inbound_state.clone(),
                    static_key: self.static_key.clone(),
                })?;

                self.sessions.insert(connection_id, tx);
                self.pending_sessions.push(session.run());
                self.router_ctx.metrics_handle().counter(NUM_INBOUND_SSU2).increment(1);

                Ok(())
            }
            Ok(HeaderKind::PeerTest {
                net_id,
                pkt_num,
                src_id,
            }) => {
                if net_id != self.router_ctx.net_id() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        our_net_id = ?self.router_ctx.net_id(),
                        their_net_id = ?net_id,
                        "network id mismatch",
                    );
                    return Err(Ssu2Error::NetworkMismatch);
                }

                self.peer_test_manager
                    .handle_peer_test(src_id, pkt_num, datagram, address)
                    .inspect_err(|error| {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?src_id,
                            ?error,
                            "failed to handle out-of-session peer test message",
                        );
                    })
            }
            _ => match self.pending_outbound.get(&address) {
                Some(intro_key) =>
                    match self.sessions.get_mut(&reader.reset_key(*intro_key).dst_id()) {
                        Some(tx) => tx
                            .try_send(Packet {
                                pkt: datagram,
                                address,
                            })
                            .map_err(From::from),
                        None => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?address,
                                "pending connection found but no associated session",
                            );
                            Ok(())
                        }
                    },
                None => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        message_type = ?datagram.get(12),
                        "unrecognized message type",
                    );
                    Err(Ssu2Error::Malformed)
                }
            },
        }
    }

    pub fn connect(&mut self, router_info: RouterInfo) {
        // must succeed since `TransportManager` has ensured `router_info` contains
        // a valid and reachable ssu2 router address
        let router_id = router_info.identity.id();
        let intro_key = router_info.ssu2_intro_key().expect("to succeed");
        let static_key = router_info.ssu2_static_key().expect("to succeed");
        let verifying_key = router_info.identity.signing_key().clone();
        let address = router_info
            .addresses
            .get(&TransportKind::Ssu2)
            .expect("to exist")
            .socket_address
            .expect("to exist");

        let router_info = self.router_ctx.router_info();
        let state = Sha256::new().update(&self.outbound_state).update(&static_key).finalize();
        let transport_tx = self.transport_tx.clone();
        let src_id = R::rng().next_u64();
        let dst_id = R::rng().next_u64();

        tracing::debug!(
            target: LOG_TARGET,
            %router_id,
            ?src_id,
            ?dst_id,
            ?address,
            "establish outbound session",
        );

        let (tx, rx) = channel(CHANNEL_SIZE);
        self.sessions.insert(src_id, tx);
        self.pending_outbound.insert(address, intro_key);
        self.router_ctx.metrics_handle().counter(NUM_OUTBOUND_SSU2).increment(1);

        self.pending_sessions.push(
            OutboundSsu2Session::<R>::new(OutboundSsu2Context {
                address,
                chaining_key: self.chaining_key.clone(),
                dst_id,
                local_intro_key: self.intro_key,
                local_static_key: self.static_key.clone(),
                net_id: self.router_ctx.net_id(),
                remote_intro_key: intro_key,
                router_id,
                router_info,
                rx,
                verifying_key,
                socket: self.socket.clone(),
                src_id,
                state,
                static_key,
                transport_tx,
            })
            .run(),
        );

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Accept inbound/outbound connection to `router_id`.
    ///
    /// Remove any state associated with a pending connection and spawn the event loop of the
    /// connection in a separate task. The channel that was used during negotiation is kept in
    /// `self.sessions` and removed only when the session is destroyed.
    pub fn accept(&mut self, router_id: &RouterId) {
        let Some(kind) = self.unvalidated_sessions.remove(router_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                "non-existent unvalidated session accepted",
            );
            debug_assert!(false);
            return;
        };

        let context = match kind {
            PendingSessionKind::Inbound {
                pkt,
                address,
                context,
                ..
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "inbound session accepted",
                );

                // TODO: retransmissiosn?
                self.pending_pkts.push_back((pkt, address));
                context
            }
            PendingSessionKind::Outbound {
                address, context, ..
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "outbound session accepted",
                );

                self.pending_outbound.remove(&address);
                context
            }
        };

        // get handle to peer test manager.
        let handle = self.peer_test_manager.handle();

        // register session to `PeerTestManager`
        self.peer_test_manager.add_session(&context.router_id, handle.cmd_tx());

        self.active_sessions.push(
            Ssu2Session::<R>::new(
                context,
                self.socket.clone(),
                self.transport_tx.clone(),
                self.router_ctx.clone(),
                handle,
            )
            .run(),
        );
        self.router_ctx.metrics_handle().gauge(NUM_CONNECTIONS).increment(1);

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Reject inbound/outbound connection to `router_id`.
    pub fn reject(&mut self, router_id: &RouterId) {
        let Some(kind) = self.unvalidated_sessions.remove(router_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                "non-existent unvalidated session rejected",
            );
            debug_assert!(false);
            return;
        };

        match kind {
            PendingSessionKind::Inbound {
                context,
                k_header_2,
                ..
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "inbound session rejected, send termination",
                );

                let Ssu2SessionContext {
                    address,
                    dst_id,
                    intro_key,
                    pkt_rx,
                    recv_key_ctx,
                    router_id,
                    send_key_ctx,
                    ..
                } = context;

                self.terminating_session.push(TerminatingSsu2Session::<R>::new(
                    TerminationContext {
                        address,
                        dst_id,
                        intro_key,
                        k_session_confirmed: Some(k_header_2),
                        next_pkt_num: 0,
                        reason: TerminationReason::ConnectionLimits,
                        recv_key_ctx,
                        router_id,
                        rx: pkt_rx,
                        send_key_ctx,
                        socket: self.socket.clone(),
                    },
                ))
            }
            PendingSessionKind::Outbound {
                address,
                context,
                src_id,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "outbound session rejected, send termination",
                );

                self.pending_outbound.remove(&address);
                self.sessions.remove(&src_id);
            }
        }

        // TODO: send termination?
    }
}

impl<R: Runtime> Stream for Ssu2Socket<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        loop {
            match Pin::new(&mut this.socket).poll_recv_from(cx, &mut this.read_buffer) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "socket closed",
                    );
                    return Poll::Ready(None);
                }
                Poll::Ready(Some((nread, from))) => {
                    this.router_ctx.metrics_handle().counter(INBOUND_BANDWIDTH).increment(nread);
                    this.router_ctx.metrics_handle().counter(INBOUND_PKT_COUNT).increment(1);
                    this.router_ctx
                        .metrics_handle()
                        .histogram(INBOUND_PKT_SIZES)
                        .record(nread as f64);

                    match this.handle_packet(this.read_buffer[..nread].to_vec(), from) {
                        Err(Ssu2Error::Channel(ChannelError::Full)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "cannot process packet, channel is full",
                            );
                            this.router_ctx
                                .metrics_handle()
                                .counter(NUM_DROPPED_DATAGRAMS)
                                .increment(1);
                        }
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?from,
                            ?error,
                            "failed to handle packet",
                        ),
                        Ok(()) => {}
                    }
                }
            }
        }

        match this.active_sessions.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(termination_ctx)) => {
                let router_id = termination_ctx.router_id.clone();
                let reason = termination_ctx.reason;

                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = %termination_ctx.dst_id,
                    ?reason,
                    "terminate active ssu2 session",
                );

                this.peer_test_manager.remove_session(&router_id);
                this.terminating_session.push(TerminatingSsu2Session::<R>::new(termination_ctx));
                this.router_ctx.metrics_handle().gauge(NUM_CONNECTIONS).decrement(1);

                return Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id, reason }));
            }
        }

        loop {
            match this.terminating_session.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some((router_id, connection_id))) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        %connection_id,
                        "active ssu2 session terminated",
                    );

                    // TODO: correct connection id for inbound?
                    this.sessions.remove(&connection_id);
                }
            }
        }

        loop {
            match this.pending_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(status)) => {
                    this.router_ctx
                        .metrics_handle()
                        .histogram(HANDSHAKE_DURATION)
                        .record(status.duration());

                    match &status {
                        PendingSsu2SessionStatus::NewInboundSession { .. }
                        | PendingSsu2SessionStatus::NewOutboundSession { .. } => this
                            .router_ctx
                            .metrics_handle()
                            .counter(NUM_HANDSHAKE_SUCCESSES)
                            .increment(1),
                        _ => this
                            .router_ctx
                            .metrics_handle()
                            .counter(NUM_HANDSHAKE_FAILURES)
                            .increment(1),
                    }

                    match status {
                        PendingSsu2SessionStatus::NewInboundSession {
                            context,
                            dst_id,
                            pkt,
                            target,
                            k_header_2,
                            router_info,
                            serialized,
                            ..
                        } => {
                            let router_id = context.router_id.clone();

                            // add router to router storage so we can later on use it for outbound
                            // connections
                            this.router_ctx
                                .profile_storage()
                                .discover_router(*router_info, serialized);

                            match this.unvalidated_sessions.get(&router_id) {
                                None => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        %router_id,
                                        connection_id = ?context.dst_id,
                                        "inbound session negotiated",
                                    );

                                    this.unvalidated_sessions.insert(
                                        router_id.clone(),
                                        PendingSessionKind::Inbound {
                                            pkt,
                                            address: target,
                                            context,
                                            dst_id,
                                            k_header_2,
                                        },
                                    );

                                    return Poll::Ready(Some(
                                        TransportEvent::ConnectionEstablished {
                                            direction: Direction::Inbound,
                                            router_id,
                                        },
                                    ));
                                }
                                Some(kind) => tracing::warn!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    connection_id = ?context.dst_id,
                                    ?kind,
                                    "inbound session negotiated but already pending, rejecting",
                                ),
                            }
                        }
                        PendingSsu2SessionStatus::NewOutboundSession {
                            context,
                            src_id,
                            started: _,
                            external_address,
                        } => {
                            let router_id = context.router_id.clone();

                            tracing::trace!(
                                target: LOG_TARGET,
                                %router_id,
                                connection_id = ?context.dst_id,
                                "outbound session negotiated",
                            );

                            if let Some(kind) = this.unvalidated_sessions.insert(
                                router_id.clone(),
                                PendingSessionKind::Outbound {
                                    address: context.address,
                                    context,
                                    src_id,
                                },
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    ?kind,
                                    "unvalidated session already exists",
                                );
                                debug_assert!(false);
                            }

                            // report external address to `PeerTestManager` so it can be used
                            // for status detection and active peer tests
                            if let Some(address) = external_address {
                                this.peer_test_manager.add_external_address(address);
                            }

                            return Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                                direction: Direction::Outbound,
                                router_id,
                            }));
                        }
                        PendingSsu2SessionStatus::SessionTerminated {
                            address,
                            connection_id,
                            router_id,
                            ..
                        } => match router_id {
                            None => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?connection_id,
                                    "pending inbound session terminated",
                                );
                                debug_assert!(false);
                            }
                            Some(router_id) => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    ?connection_id,
                                    "pending outbound session terminated",
                                );
                                let _channel = this.sessions.remove(&connection_id);
                                debug_assert!(_channel.is_some());

                                match address {
                                    Some(address) => {
                                        let _key = this.pending_outbound.remove(&address);
                                        debug_assert!(_key.is_some());
                                    }
                                    None => {
                                        tracing::warn!(
                                            target: LOG_TARGET,
                                            %router_id,
                                            %connection_id,
                                            "address doens't exist for a terminated outbound connection",
                                        );
                                        debug_assert!(false);
                                    }
                                }

                                return Poll::Ready(Some(TransportEvent::ConnectionFailure {
                                    router_id,
                                }));
                            }
                        },
                        PendingSsu2SessionStatus::Timeout {
                            connection_id,
                            router_id,
                            started: _,
                        } => match router_id {
                            None => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?connection_id,
                                    "pending inbound session timed out",
                                );
                            }
                            Some(router_id) => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    ?connection_id,
                                    "pending outbound session timed out",
                                );
                                return Poll::Ready(Some(TransportEvent::ConnectionFailure {
                                    router_id,
                                }));
                            }
                        },
                        PendingSsu2SessionStatus::SocketClosed { .. } => return Poll::Ready(None),
                    }
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetPacket => match this.pending_pkts.pop_front() {
                    None => {
                        this.write_state = WriteState::GetPacket;
                        break;
                    }
                    Some((pkt, target)) => {
                        this.write_state = WriteState::SendPacket { pkt, target };
                    }
                },
                WriteState::SendPacket { pkt, target } => match Pin::new(&mut this.socket)
                    .poll_send_to(cx, &pkt, target)
                {
                    Poll::Ready(Some(nwritten)) => {
                        this.router_ctx
                            .metrics_handle()
                            .counter(OUTBOUND_BANDWIDTH)
                            .increment(nwritten);
                        this.router_ctx.metrics_handle().counter(OUTBOUND_PKT_COUNT).increment(1);

                        this.write_state = WriteState::GetPacket;
                    }
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Pending => {
                        this.write_state = WriteState::SendPacket { pkt, target };
                        break;
                    }
                },
                WriteState::Poisoned => unreachable!(),
            }
        }

        match this.peer_test_manager.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(PeerTestManagerEvent::FirewallStatus { status })) =>
                return Poll::Ready(Some(TransportEvent::FirewallStatus { status })),
            Poll::Ready(Some(PeerTestManagerEvent::ExternalAddress { .. })) => {}
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        crypto::SigningPublicKey,
        events::EventManager,
        i2np::{Message, MessageType, I2NP_MESSAGE_EXPIRATION},
        primitives::RouterInfoBuilder,
        profile::ProfileStorage,
        runtime::{mock::MockRuntime, UdpSocket},
        subsystem::OutboundMessage,
        transport::ssu2::session::KeyContext,
    };

    #[tokio::test]
    async fn session_terminated() {
        let storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let router_ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage,
            router_info.identity.id(),
            Bytes::from(router_info.serialize(&signing_key)),
            static_key.clone(),
            signing_key,
            2u8,
            event_handle.clone(),
        );
        let (transport_tx, transport_rx) = channel(128);
        let mut socket = Ssu2Socket::<MockRuntime>::new(
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            static_key,
            [0xaa; 32],
            transport_tx,
            router_ctx,
        );
        let udp_socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut recv_socket =
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();

        let (_pkt_tx, pkt_rx) = channel(128);
        let context = Ssu2SessionContext {
            address: recv_socket.local_address().unwrap(),
            dst_id: 1337u64,
            intro_key: [0xbb; 32],
            pkt_rx,
            recv_key_ctx: KeyContext {
                k_data: [0xcc; 32],
                k_header_2: [0xdd; 32],
            },
            router_id: RouterId::random(),
            send_key_ctx: KeyContext {
                k_data: [0xee; 32],
                k_header_2: [0xff; 32],
            },
            verifying_key: SigningPublicKey::from_bytes(&[0x22; 32]).unwrap(),
        };
        let handle = socket.peer_test_manager.handle();
        socket.active_sessions.push(
            Ssu2Session::<MockRuntime>::new(
                context,
                udp_socket,
                socket.transport_tx.clone(),
                socket.router_ctx.clone(),
                handle,
            )
            .run(),
        );

        let tx = tokio::select! {
            event = socket.next() => {
                panic!("did not expect event {event:?}")
            }
            event = transport_rx.recv() => match event.unwrap() {
                SubsystemEvent::ConnectionEstablished { tx, .. } => tx,
                event => panic!("unexpected event: {event:?}"),
            }
        };

        // send outbound message to the active session
        tx.send(OutboundMessage::Message(Message {
            message_type: MessageType::DatabaseStore,
            message_id: 1337,
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: vec![0; 512],
        }))
        .await
        .unwrap();

        // verify the message is received by `Ssu2Socket`
        let mut buffer = vec![0u8; 0xffff];
        let _ = tokio::time::timeout(Duration::from_secs(5), recv_socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();

        let mut subsys_notified = false;
        let mut transport_manager_notified = false;

        let future = async {
            while !subsys_notified || !transport_manager_notified {
                tokio::select! {
                    event = transport_rx.recv() => match event.unwrap() {
                        SubsystemEvent::ConnectionClosed { .. } => {
                            subsys_notified = true;
                        }
                        _ => {}
                    },
                    event = socket.next() => match event.unwrap() {
                        TransportEvent::ConnectionClosed { .. } => {
                            transport_manager_notified = true
                        }
                        _ => {}
                    }
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(15), future).await {
            Err(_) => panic!("subsystem manager or transport manager was not notified in time"),
            Ok(_) => {}
        }
    }
}
