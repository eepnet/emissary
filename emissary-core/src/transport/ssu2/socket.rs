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
    error::Ssu2Error,
    primitives::{RouterId, RouterInfo, TransportKind},
    router::context::RouterContext,
    runtime::{JoinSet, Runtime, UdpSocket},
    subsystem::SubsystemHandle,
    transport::{
        ssu2::{
            message::{HeaderKind, HeaderReader},
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
        Direction, TransportEvent,
    },
};

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::socket";

/// Protocol name.
const PROTOCOL_NAME: &str = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Read buffer length.
const READ_BUFFER_LEN: usize = 2048usize;

/// SSU2 session channel size.
///
/// This is the channel from [`Ssu2Socket`] to a pending/active SSU2 session.
const CHANNEL_SIZE: usize = 256usize;

/// SSU2 packet channel size.
///
/// Used to receive datagrams from active sessions.
const PKT_CHANNEL_SIZE: usize = 8192usize;

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
    active_sessions: R::JoinSet<TerminationContext>,

    /// Receive buffer.
    buffer: Vec<u8>,

    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Introduction key.
    intro_key: [u8; 32],

    /// Outbound state.
    outbound_state: Bytes,

    /// Pending outbound sessions.
    ///
    /// Remote routers' intro keys indexed by their socket addresses.
    pending_outbound: HashMap<SocketAddr, [u8; 32]>,

    /// Pending outbound packets.
    pending_pkts: VecDeque<(BytesMut, SocketAddr)>,

    /// Pending SSU2 sessions.
    pending_sessions: R::JoinSet<PendingSsu2SessionStatus>,

    /// RX channel for receiving packets from active sessions.
    pkt_rx: Receiver<Packet>,

    /// TX channel given to active sessions.
    pkt_tx: Sender<Packet>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// SSU2 sessions.
    sessions: HashMap<u64, Sender<Packet>>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Terminating sessions.
    terminating_session: R::JoinSet<(RouterId, u64)>,

    /// Unvalidated sessions.
    unvalidated_sessions: HashMap<RouterId, Ssu2SessionContext>,

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
        subsystem_handle: SubsystemHandle,
        router_ctx: RouterContext<R>,
    ) -> Self {
        let state = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize();
        let chaining_key = state.clone();
        let outbound_state = Sha256::new().update(&state).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(static_key.public().to_vec())
            .finalize();

        // create channel pair which is used to exchange outbound packets
        // with active sessions and `Ssu2Socket`
        //
        // TODO: implement `Clone` for `R::UdpSocket`
        let (pkt_tx, pkt_rx) = channel(PKT_CHANNEL_SIZE);

        Self {
            active_sessions: R::join_set(),
            buffer: vec![0u8; READ_BUFFER_LEN],
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            intro_key,
            outbound_state: Bytes::from(outbound_state),
            pending_outbound: HashMap::new(),
            pending_pkts: VecDeque::new(),
            pending_sessions: R::join_set(),
            pkt_rx,
            pkt_tx,
            router_ctx,
            sessions: HashMap::new(),
            socket,
            static_key,
            subsystem_handle,
            terminating_session: R::join_set(),
            unvalidated_sessions: HashMap::new(),
            waker: None,
            write_state: WriteState::GetPacket,
        }
    }

    /// Handle packet.
    //
    // TODO: needs as lot of refactoring
    // TODO: explain what happens here
    fn handle_packet(&mut self, nread: usize, address: SocketAddr) -> Result<(), Ssu2Error> {
        let mut reader = HeaderReader::new(self.intro_key, &mut self.buffer[..nread])?;
        let connection_id = reader.dst_id();

        if let Some(tx) = self.sessions.get_mut(&connection_id) {
            return tx
                .try_send(Packet {
                    pkt: self.buffer[..nread].to_vec(),
                    address,
                })
                .map_err(From::from);
        }

        match reader.parse(self.intro_key) {
            Ok(HeaderKind::TokenRequest {
                net_id: _,
                pkt_num,
                src_id,
            }) => {
                // TODO: validate net id
                let (tx, rx) = channel(CHANNEL_SIZE);
                let session = InboundSsu2Session::<R>::new(InboundSsu2Context {
                    address,
                    chaining_key: self.chaining_key.clone(),
                    dst_id: connection_id,
                    intro_key: self.intro_key,
                    net_id: self.router_ctx.net_id(),
                    pkt_num,
                    pkt: self.buffer[..nread].to_vec(),
                    pkt_tx: self.pkt_tx.clone(),
                    rx,
                    src_id,
                    state: self.inbound_state.clone(),
                    static_key: self.static_key.clone(),
                })?;

                self.sessions.insert(connection_id, tx);
                self.pending_sessions.push(session);

                Ok(())
            }
            Ok(kind) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    "unable to handle message",
                );
                Ok(())
            }
            Err(_) => match self.pending_outbound.get(&address) {
                Some(intro_key) =>
                    match self.sessions.get_mut(&reader.reset_key(*intro_key).dst_id()) {
                        Some(tx) => tx
                            .try_send(Packet {
                                pkt: self.buffer[..nread].to_vec(),
                                address,
                            })
                            .map_err(From::from),
                        None => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?address,
                                "pending connection found but no associated session",
                            );
                            debug_assert!(false);
                            Ok(())
                        }
                    },
                None => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        message_type = ?self.buffer[12],
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
        let address = router_info
            .addresses
            .get(&TransportKind::Ssu2)
            .expect("to exist")
            .socket_address
            .expect("to exist");

        let router_info = self.router_ctx.router_info();
        let state = Sha256::new().update(&self.outbound_state).update(&static_key).finalize();
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
        self.pending_sessions.push(OutboundSsu2Session::<R>::new(OutboundSsu2Context {
            address,
            chaining_key: self.chaining_key.clone(),
            dst_id,
            intro_key,
            local_static_key: self.static_key.clone(),
            net_id: self.router_ctx.net_id(),
            pkt_tx: self.pkt_tx.clone(),
            router_id,
            router_info,
            rx,
            src_id,
            state,
            static_key,
        }));

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    pub fn accept(&mut self, router_id: &RouterId) {
        let Some(context) = self.unvalidated_sessions.remove(router_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                "non-existent unvalidated session accepted",
            );
            debug_assert!(false);
            return;
        };

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            "session accepted",
        );

        self.active_sessions.push(
            Ssu2Session::<R>::new(context, self.pkt_tx.clone(), self.subsystem_handle.clone())
                .run(),
        );

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    pub fn reject(&mut self, router_id: &RouterId) {
        match self.unvalidated_sessions.remove(router_id) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    "non-existent unvalidated session rejected",
                );
                debug_assert!(false);
            }
            Some(_) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "session rejected",
                );
                // TODO: send termination
            }
        }
    }
}

impl<R: Runtime> Stream for Ssu2Socket<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        loop {
            match Pin::new(&mut this.socket).poll_recv_from(cx, this.buffer.as_mut()) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "socket closed",
                    );
                    return Poll::Ready(None);
                }
                Poll::Ready(Some((nread, from))) => {
                    if let Err(error) = this.handle_packet(nread, from) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?from,
                            ?error,
                            "failed to handle packet",
                        );
                    }
                }
            }
        }

        loop {
            match this.active_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(termination_ctx)) => {
                    this.terminating_session
                        .push(TerminatingSsu2Session::<R>::new(termination_ctx));
                    // // TODO: remove channel
                    // return Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id, reason
                    // }));
                }
            }
        }

        loop {
            match this.pending_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(PendingSsu2SessionStatus::NewInboundSession {
                    context,
                    pkt,
                    target,
                })) => {
                    let router_id = context.router_id.clone();

                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        "inbound session negotiated",
                    );

                    this.pending_pkts.push_back((pkt, target));
                    this.unvalidated_sessions.insert(router_id.clone(), context);

                    return Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        direction: Direction::Inbound,
                        router_id,
                    }));
                }
                Poll::Ready(Some(PendingSsu2SessionStatus::NewOutboundSession { context })) => {
                    let router_id = context.router_id.clone();

                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        "outbound session negotiated",
                    );

                    this.unvalidated_sessions.insert(router_id.clone(), context);

                    return Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        direction: Direction::Outbound,
                        router_id,
                    }));
                }
                Poll::Ready(Some(PendingSsu2SessionStatus::SessionTermianted {
                    connection_id,
                    router_id,
                })) => match router_id {
                    None => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?connection_id,
                            "pending inbound session terminated",
                        );
                    }
                    Some(router_id) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?connection_id,
                            "pending outbound session terminated",
                        );
                        return Poll::Ready(Some(TransportEvent::ConnectionFailure { router_id }));
                    }
                },
                Poll::Ready(Some(PendingSsu2SessionStatus::Timeout {
                    connection_id,
                    router_id,
                })) => match router_id {
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
                        return Poll::Ready(Some(TransportEvent::ConnectionFailure { router_id }));
                    }
                },
                Poll::Ready(Some(PendingSsu2SessionStatus::SocketClosed)) =>
                    return Poll::Ready(None),
            }
        }

        loop {
            match this.pkt_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                // TODO: useless conversion from vec to bytesmut
                Poll::Ready(Some(Packet { pkt, address })) =>
                    this.pending_pkts.push_back((BytesMut::from(&pkt[..]), address)),
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
                WriteState::SendPacket { pkt, target } =>
                    match Pin::new(&mut this.socket).poll_send_to(cx, &pkt, target) {
                        Poll::Ready(Some(_)) => {
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

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
