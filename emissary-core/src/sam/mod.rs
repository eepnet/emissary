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

//! SAMV3 server implementation.
//!
//! https://geti2p.net/en/docs/api/samv3

use crate::{
    crypto::base32_decode,
    error::{ChannelError, ConnectionError, Error},
    events::EventHandle,
    netdb::NetDbHandle,
    primitives::{DestinationId, Str},
    profile::ProfileStorage,
    runtime::{AddressBook, JoinSet, Runtime, TcpListener, UdpSocket},
    sam::{
        parser::{Datagram, HostKind},
        pending::{
            connection::{ConnectionKind, PendingSamConnection},
            session::{PendingSamSession, SamSessionContext},
        },
        session::{SamSession, SamSessionCommand, SamSessionCommandRecycle},
        socket::SamSocket,
    },
    tunnel::{TunnelManagerHandle, TunnelPoolConfig},
};

use futures::{future::Either, Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{channel, with_recycle, Receiver, Sender};

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    future::Future,
    mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

mod parser;
mod pending;
mod protocol;
mod session;
mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam";

/// SAMv3 command channel size.
const COMMAND_CHANNEL_SIZE: usize = 256;

/// Session context.
///
/// Holds either pending or active sessions.
pub struct SessionContext<R: Runtime, T: 'static + Send + Unpin> {
    /// Sesison futures.
    futures: R::JoinSet<T>,

    /// TX channels for the session.
    senders: HashMap<Arc<str>, Sender<SamSessionCommand<R>, SamSessionCommandRecycle>>,
}

impl<R: Runtime, T: 'static + Send + Unpin> SessionContext<R, T> {
    /// Create new [`SessionContext`].
    fn new() -> Self {
        Self {
            senders: HashMap::new(),
            futures: R::join_set(),
        }
    }

    /// Returns `true` if [`SessionContext`] contains a session identified by `key`.
    fn contains_key(&self, key: &Arc<str>) -> bool {
        self.senders.contains_key(key)
    }

    /// Remove the command channel from [`SessionContext`] for `key` if it exists
    fn remove(
        &mut self,
        key: &Arc<str>,
    ) -> Option<Sender<SamSessionCommand<R>, SamSessionCommandRecycle>> {
        self.senders.remove(key)
    }

    /// Insert new session identified by `session_id` in the [`SessionContext`].
    fn insert(
        &mut self,
        session_id: Arc<str>,
        tx: Sender<SamSessionCommand<R>, SamSessionCommandRecycle>,
        future: impl Future<Output = T> + 'static + Send,
    ) {
        self.senders.insert(session_id, tx);
        self.futures.push(future);
    }
}

impl<R: Runtime> SessionContext<R, Arc<str>> {
    /// Send `command` to an active sesison identified by `session_id`.
    fn send_command(
        &self,
        session_id: &Arc<str>,
        command: SamSessionCommand<R>,
    ) -> Result<(), ChannelError> {
        self.senders
            .get(session_id)
            .ok_or(ChannelError::DoesntExist)?
            .try_send(command)
            .map_err(From::from)
    }
}

impl<R: Runtime, T: 'static + Send + Unpin> Stream for SessionContext<R, T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.futures.poll_next_unpin(cx)
    }
}

/// Datagram write state.
enum DatagramWriterState {
    /// Get next message from the datagram channel.
    GetMessage,

    /// Write current message to socket.
    WriteMessage {
        /// Client address.
        target: SocketAddr,

        /// Datagram.
        datagram: Vec<u8>,
    },
}

/// SAMv3 server.
pub struct SamServer<R: Runtime> {
    /// Active destinations.
    active_destinations: HashSet<DestinationId>,

    /// Active SAMV3 sessions.
    active_sessions: SessionContext<R, Arc<str>>,

    /// Address book.
    address_book: Option<Arc<dyn AddressBook>>,

    /// RX channel for receiving datagrams that should be to clients.
    datagram_rx: Receiver<(u16, Vec<u8>)>,

    /// TX channel given to active sessions they can use to send datagrams to clients.
    datagram_tx: Sender<(u16, Vec<u8>)>,

    /// Datagra writer state.
    datagram_writer_state: DatagramWriterState,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// Pending host lookups.
    host_lookups: R::JoinSet<(
        Arc<str>,
        SamSocket<R>,
        Option<(DestinationId, HashMap<String, String>)>,
    )>,

    /// TCP listener.
    listener: R::TcpListener,

    /// Metrics handle.
    #[allow(unused)]
    metrics: R::MetricsHandle,

    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Pending inbound SAMv3 connections.
    ///
    /// Inbound connections which are in the state of being handshaked and reading a command from
    /// the client. After the command has been read, `SamServer` validates it against the current
    /// state, ensuring, e.g., that the it's not a duplicate `SESSION CREATE` request.
    pending_inbound_connections: R::JoinSet<crate::Result<ConnectionKind<R>>>,

    /// Pending SAMv3 sessions that are in the process of building a tunnel pool.
    pending_sessions: SessionContext<R, crate::Result<SamSessionContext<R>>>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// Datagram read buffer.
    read_buffer: Vec<u8>,

    /// Session ID to `DestinationId` mappings.
    session_id_destinations: HashMap<Arc<str>, DestinationId>,

    /// SAMv3 datagram socket.
    socket: R::UdpSocket,

    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> SamServer<R> {
    /// Create new [`SamServer`]
    pub async fn new(
        tcp_port: u16,
        udp_port: u16,
        host: String,
        netdb_handle: NetDbHandle,
        tunnel_manager_handle: TunnelManagerHandle,
        metrics: R::MetricsHandle,
        address_book: Option<Arc<dyn AddressBook>>,
        event_handle: EventHandle<R>,
        profile_storage: ProfileStorage<R>,
    ) -> crate::Result<Self> {
        let listener = R::TcpListener::bind(SocketAddr::new(
            host.parse::<IpAddr>().expect("valid address"),
            tcp_port,
        ))
        .await
        .ok_or(Error::Connection(ConnectionError::BindFailure))?;

        let socket = R::UdpSocket::bind(SocketAddr::new(
            host.parse::<IpAddr>().expect("valid address"),
            udp_port,
        ))
        .await
        .ok_or(Error::Connection(ConnectionError::BindFailure))?;

        tracing::info!(
            target: LOG_TARGET,
            %host,
            tcp_port = ?listener.local_address().map(|address| address.port()),
            udp_port = ?socket.local_address().map(|address| address.port()),
            "starting sam server",
        );

        let (datagram_tx, datagram_rx) = channel(1024);

        Ok(Self {
            active_destinations: HashSet::new(),
            active_sessions: SessionContext::new(),
            address_book,
            datagram_rx,
            datagram_tx,
            datagram_writer_state: DatagramWriterState::GetMessage,
            event_handle,
            host_lookups: R::join_set(),
            listener,
            metrics,
            netdb_handle,
            pending_inbound_connections: R::join_set(),
            pending_sessions: SessionContext::new(),
            profile_storage,
            read_buffer: vec![0u8; 0xfff],
            session_id_destinations: HashMap::new(),
            socket,
            tunnel_manager_handle,
        })
    }

    /// Get address of the SAMv3 TCP listener.
    pub fn tcp_local_address(&self) -> Option<SocketAddr> {
        self.listener.local_address()
    }

    /// Get address of the SAMv3 UDP socket.
    pub fn udp_local_address(&self) -> Option<SocketAddr> {
        self.socket.local_address()
    }
}

impl<R: Runtime> Future for SamServer<R> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::into_inner(self);

        loop {
            match this.listener.poll_accept(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((stream, _))) => {
                    this.pending_inbound_connections.push(PendingSamConnection::new(stream));
                }
            }
        }

        loop {
            match Pin::new(&mut this.socket).poll_recv_from(cx, &mut this.read_buffer) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((nread, _))) => {
                    let Some(Datagram {
                        session_id,
                        destination,
                        datagram,
                    }) = Datagram::parse(&this.read_buffer[..nread])
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "malformed datagram",
                        );
                        continue;
                    };

                    if let Err(error) = this.active_sessions.send_command(
                        &session_id,
                        SamSessionCommand::SendDatagram {
                            destination,
                            datagram,
                        },
                    ) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            ?error,
                            "failed to send datagram to active session",
                        );
                    }
                }
            }
        }

        loop {
            match mem::replace(
                &mut this.datagram_writer_state,
                DatagramWriterState::GetMessage,
            ) {
                DatagramWriterState::GetMessage => match this.datagram_rx.poll_recv(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Ready(Some((port, datagram))) => {
                        this.datagram_writer_state = DatagramWriterState::WriteMessage {
                            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                            datagram,
                        };
                    }
                },
                DatagramWriterState::WriteMessage { target, datagram } => {
                    match Pin::new(&mut this.socket).poll_send_to(cx, &datagram, target) {
                        Poll::Pending => {
                            this.datagram_writer_state =
                                DatagramWriterState::WriteMessage { target, datagram };
                            break;
                        }
                        Poll::Ready(Some(_)) => {
                            this.datagram_writer_state = DatagramWriterState::GetMessage;
                        }
                        Poll::Ready(None) => tracing::warn!(
                            target: LOG_TARGET,
                            "failed to write to socket",
                        ),
                    }
                }
            }
        }

        loop {
            match this.pending_inbound_connections.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(Ok(kind))) => match kind {
                    ConnectionKind::Session {
                        mut socket,
                        version,
                        session_id,
                        destination,
                        session_kind,
                        options,
                    } => {
                        // client send a `SESSION CREATE` message with an id that is already
                        // in use by either an active or a pending session
                        //
                        // reject connection by closing the socket
                        if this.active_sessions.contains_key(&session_id)
                            || this.pending_sessions.contains_key(&session_id)
                        {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %session_id,
                                "duplicate session id",
                            );

                            R::spawn(async move {
                                let _ = socket
                                    .send_message_blocking(
                                        b"SESSION STATUS RESULT=DUPLICATE_ID".to_vec(),
                                    )
                                    .await;
                            });
                            continue;
                        }

                        // ensure this is not a duplicate session for the same destination
                        let destination_id = destination.destination.id();

                        if this.active_destinations.contains(&destination_id) {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %destination_id,
                                "duplicate destination",
                            );

                            R::spawn(async move {
                                let _ = socket
                                    .send_message_blocking(
                                        b"SESSION STATUS RESULT=DUPLICATE_DEST".to_vec(),
                                    )
                                    .await;
                            });
                            continue;
                        }

                        tracing::info!(
                            target: LOG_TARGET,
                            ?session_id,
                            %destination_id,
                            ?version,
                            "start constructing new session",
                        );

                        // send request to `TunnelManager` to start creating a tunnel pool and get
                        // back a future which returns a `TunnelPoolHandle` when the tunnel pool has
                        // been constructed
                        //
                        // the constructed pool is not ready for immediate use and must be polled
                        // until the desired amount of inbound/outbound tunnels have been built at
                        // which point an active samv3 session can be constructed
                        let tunnel_pool_future =
                            match this.tunnel_manager_handle.create_tunnel_pool(TunnelPoolConfig {
                                name: Str::from(Arc::clone(&session_id)),
                                ..Default::default()
                            }) {
                                Ok(tunnel_pool_future) => tunnel_pool_future,
                                Err(error) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %session_id,
                                        ?error,
                                        "failed to create tunnel pool for session",
                                    );
                                    continue;
                                }
                            };

                        let (tx, rx) =
                            with_recycle(COMMAND_CHANNEL_SIZE, SamSessionCommandRecycle::default());
                        let netdb_handle = this.netdb_handle.clone();

                        this.pending_sessions.insert(
                            Arc::clone(&session_id),
                            tx,
                            PendingSamSession::new(
                                socket,
                                destination,
                                Arc::clone(&session_id),
                                session_kind,
                                options,
                                rx,
                                this.datagram_tx.clone(),
                                Box::pin(tunnel_pool_future),
                                netdb_handle,
                                this.address_book.clone(),
                                this.event_handle.clone(),
                                this.profile_storage.clone(),
                            )
                            .run(),
                        );
                        this.active_destinations.insert(destination_id.clone());
                        this.session_id_destinations.insert(session_id, destination_id);
                    }
                    ConnectionKind::Stream {
                        session_id,
                        socket,
                        host,
                        options,
                        ..
                    } => match host {
                        HostKind::Destination { destination } => {
                            if let Err(error) = this.active_sessions.send_command(
                                &session_id,
                                SamSessionCommand::Connect {
                                    socket,
                                    destination_id: destination.id(),
                                    options,
                                },
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %session_id,
                                    ?error,
                                    "failed to send `STREAM CONNECT` to active session",
                                )
                            }
                        }
                        HostKind::B32Host { destination_id } => {
                            if let Err(error) = this.active_sessions.send_command(
                                &session_id,
                                SamSessionCommand::Connect {
                                    socket,
                                    destination_id,
                                    options,
                                },
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %session_id,
                                    ?error,
                                    "failed to send `STREAM CONNECT` to active session",
                                )
                            }
                        }
                        HostKind::Host { host } => match &this.address_book {
                            None => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %session_id,
                                    %host,
                                    "host lookup requested but address book not specified",
                                );
                                debug_assert!(false);
                            }
                            Some(address_book) => {
                                tracing::trace!(
                                    target: LOG_TARGET,
                                    %session_id,
                                    %host,
                                    "resolve host",
                                );

                                match address_book.resolve_b32(host) {
                                    Either::Left(destination) =>
                                        match base32_decode(&destination) {
                                            None => {
                                                tracing::error!(
                                                    target: LOG_TARGET,
                                                    "failed to base32-decode destination id from a host lookup",
                                                );
                                                debug_assert!(false);
                                            }
                                            Some(destination) => {
                                                let destination_id =
                                                    DestinationId::from(destination);

                                                tracing::trace!(
                                                    target: LOG_TARGET,
                                                    %destination_id,
                                                    "destination id found from the cache",
                                                );

                                                if let Err(error) =
                                                    this.active_sessions.send_command(
                                                        &session_id,
                                                        SamSessionCommand::Connect {
                                                            socket,
                                                            destination_id,
                                                            options,
                                                        },
                                                    )
                                                {
                                                    tracing::warn!(
                                                        target: LOG_TARGET,
                                                        %session_id,
                                                        ?error,
                                                        "failed to send `STREAM CONNECT` to active session",
                                                    )
                                                }
                                            }
                                        },
                                    Either::Right(future) => {
                                        this.host_lookups.push(async move {
                                            let result = future.await.and_then(base32_decode).map(
                                                |destination| {
                                                    (DestinationId::from(destination), options)
                                                },
                                            );

                                            (session_id, socket, result)
                                        });
                                    }
                                }
                            }
                        },
                    },
                    ConnectionKind::Accept {
                        session_id,
                        socket,
                        options,
                        ..
                    } => {
                        if let Err(error) = this.active_sessions.send_command(
                            &session_id,
                            SamSessionCommand::Accept { socket, options },
                        ) {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %session_id,
                                ?error,
                                "failed to send `STREAM ACCEPT` to active session",
                            )
                        }
                    }
                    ConnectionKind::Forward {
                        session_id,
                        socket,
                        port,
                        options,
                        ..
                    } => {
                        if let Err(error) = this.active_sessions.send_command(
                            &session_id,
                            SamSessionCommand::Forward {
                                socket,
                                port,
                                options,
                            },
                        ) {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %session_id,
                                ?error,
                                "failed to send `STREAM FORWARD` to active session",
                            )
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => tracing::trace!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to accept samv3 client connection",
                ),
            }
        }

        loop {
            match this.pending_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(Ok(context))) =>
                    match this.pending_sessions.remove(&context.session_id) {
                        Some(tx) => {
                            this.active_sessions.insert(
                                Arc::clone(&context.session_id),
                                tx,
                                SamSession::new(context),
                            );
                        }
                        None => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                session_id = %context.session_id,
                                "pending session doesn't exist"
                            );
                            debug_assert!(false);

                            if let Some(destination_id) =
                                this.session_id_destinations.remove(&context.session_id)
                            {
                                this.active_destinations.remove(&destination_id);
                            }
                        }
                    },
                Poll::Ready(Some(Err(error))) => tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to create tunnel pool for session",
                ),
            }
        }

        loop {
            match this.active_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(session_id)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        %session_id,
                        "session terminated",
                    );
                    this.active_sessions.remove(&session_id);

                    if let Some(destination_id) = this.session_id_destinations.remove(&session_id) {
                        this.active_destinations.remove(&destination_id);
                    }
                }
            }
        }

        loop {
            match this.host_lookups.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((session_id, mut socket, None))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?session_id,
                        "failed to resolve host",
                    );

                    R::spawn(async move {
                        let _ = socket
                            .send_message_blocking(
                                "STREAM STATUS RESULT=I2P_ERROR\n".to_string().as_bytes().to_vec(),
                            )
                            .await;
                    });
                }
                Poll::Ready(Some((session_id, socket, Some((destination_id, options))))) =>
                    if let Err(error) = this.active_sessions.send_command(
                        &session_id,
                        SamSessionCommand::Connect {
                            socket,
                            destination_id,
                            options,
                        },
                    ) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %session_id,
                            ?error,
                            "failed to send `STREAM CONNECT` to active session",
                        )
                    },
            }
        }

        Poll::Pending
    }
}
