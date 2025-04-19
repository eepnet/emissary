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

//! Pending I2CP client session.
//!
//! IC2P client session is considered pending until the client has sent a `CreateSession` message
//! and a tunnel pool with at least one inbound tunnel has been built for the session.
//!
//! After these two conditions have been met, the pending session is destroyed and a new active
//! session is created from the pending context.

use crate::{
    crypto::StaticPrivateKey,
    i2cp::{
        message::{
            BandwidthLimits, Message, RequestVariableLeaseSet, SessionId, SessionStatus,
            SessionStatusKind, SetDate,
        },
        socket::I2cpSocket,
    },
    primitives::{Date, DestinationId, Lease, Mapping, Str, TunnelId},
    profile::ProfileStorage,
    runtime::{AddressBook, Runtime},
    tunnel::{TunnelManagerHandle, TunnelPoolConfig, TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};

use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::pending-session";

/// I2CP client session context.
pub struct I2cpSessionContext<R: Runtime> {
    /// Address book.
    pub address_book: Option<Arc<dyn AddressBook>>,

    /// Destination ID.
    pub destination_id: DestinationId,

    /// Active inbound tunnels and their leases.
    pub inbound: HashMap<TunnelId, Lease>,

    /// Serialized [`LeaseSet2`].
    pub leaseset: Bytes,

    /// Session options.
    pub options: Mapping,

    /// Active outbound tunnels.
    pub outbound: HashSet<TunnelId>,

    /// Private keys of the destination.
    pub private_keys: Vec<StaticPrivateKey>,

    /// Profile storage.
    pub profile_storage: ProfileStorage<R>,

    /// Session ID.
    pub session_id: u16,

    /// I2CP socket.
    pub socket: I2cpSocket<R>,

    /// Tunnel pool handle.
    pub tunnel_pool_handle: TunnelPoolHandle,
}

/// State of the pending I2CP client session.
enum PendingSessionState<R: Runtime> {
    /// I2CP session doesn't have an active tunnel pool
    /// and is waiting for the client to send `CreateSession` message.
    Inactive {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,
    },

    /// The tunnel pool itself is being built.
    BuildingPool {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,

        /// Session options.
        options: Mapping,

        /// Tunnel pool build future.
        ///
        /// Resolves to a `TunnelPoolHandle` once the pool has been built.
        tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,
    },

    /// Tunnels of the tunnel pool are being built.
    ///
    /// As soon as one inbound and one outbound tunnel has been built, the client is sent
    /// `RequestVariableLeaseSet` message which instructs it to create a [`LeaseSet2`] for the
    /// inbound tunnel(s) and send private key(s) of the `Destination`.
    BuildingTunnels {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,

        /// Session options.
        options: Mapping,

        /// Handle to the built tunnel pool.
        handle: TunnelPoolHandle,

        /// Active inbound tunnels and their leases.
        inbound: HashMap<TunnelId, Lease>,

        /// Active outbound tunnels.
        outbound: HashSet<TunnelId>,
    },

    /// Awaiting to receive a lease set for client destination and an associated private key(s).
    ///
    /// After these are received, the pending I2CP session is destroyed and the `I2cpServer`
    /// is returned [`I2cpSessionContext`] which allows it to create an active I2CP session.
    AwaitingLeaseSet {
        /// Session ID.
        session_id: u16,

        /// I2CP socket.
        socket: I2cpSocket<R>,

        /// Session options.
        options: Mapping,

        /// Handle to the built tunnel pool.
        handle: TunnelPoolHandle,

        /// Active inbound tunnels and their leases.
        inbound: HashMap<TunnelId, Lease>,

        /// Active outbound tunnels.
        outbound: HashSet<TunnelId>,
    },

    /// Tunnel pool state is poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for PendingSessionState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inactive { session_id, .. } => f
                .debug_struct("PendingSessionState::Inactive")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::BuildingPool { session_id, .. } => f
                .debug_struct("PendingSessionState::BuildingPool")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::BuildingTunnels { session_id, .. } => f
                .debug_struct("PendingSessionState::BuildingTunnels")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::AwaitingLeaseSet { session_id, .. } => f
                .debug_struct("PendingSessionState::AwaitingLeaseSet")
                .field("session_id", &session_id)
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("PendingSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
}

impl<R: Runtime> PendingSessionState<R> {
    /// Get mutable reference to session's `I2cpSocket`.
    ///
    /// Panics if called after the session has been poisoned.
    fn socket(&mut self) -> &mut I2cpSocket<R> {
        match self {
            Self::Inactive { socket, .. } => socket,
            Self::BuildingPool { socket, .. } => socket,
            Self::BuildingTunnels { socket, .. } => socket,
            Self::AwaitingLeaseSet { socket, .. } => socket,
            Self::Poisoned => unreachable!(),
        }
    }

    /// Get session ID of the pending session.
    ///
    /// Panics if called after the session has been poisoned.
    fn session_id(&self) -> u16 {
        match self {
            Self::Inactive { session_id, .. } => *session_id,
            Self::BuildingPool { session_id, .. } => *session_id,
            Self::BuildingTunnels { session_id, .. } => *session_id,
            Self::AwaitingLeaseSet { session_id, .. } => *session_id,
            Self::Poisoned => unreachable!(),
        }
    }
}

/// Pending I2CP client session.
pub struct PendingI2cpSession<R: Runtime> {
    /// Address book.
    address_book: Option<Arc<dyn AddressBook>>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// State of the pending session.
    state: PendingSessionState<R>,

    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> PendingI2cpSession<R> {
    /// Create new [`I2cpSession`] from `stream`.
    pub fn new(
        session_id: u16,
        socket: I2cpSocket<R>,
        tunnel_manager_handle: TunnelManagerHandle,
        address_book: Option<Arc<dyn AddressBook>>,
        profile_storage: ProfileStorage<R>,
    ) -> Self {
        Self {
            address_book,
            profile_storage,
            state: PendingSessionState::Inactive { session_id, socket },
            tunnel_manager_handle,
        }
    }

    /// Handle I2CP message received from the client.
    fn on_message(&mut self, message: Message) -> Option<I2cpSessionContext<R>> {
        match message {
            Message::GetDate { version, options } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.state.session_id(),
                    %version,
                    ?options,
                    "get date, send set date",
                );

                self.state.socket().send_message(SetDate::new(
                    Date::new(R::time_since_epoch().as_millis() as u64),
                    Str::from_str("0.9.63").expect("to succeed"),
                ));
            }
            Message::GetBandwidthLimits => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.state.session_id(),
                    "handle bandwidth limit request",
                );

                self.state.socket().send_message(BandwidthLimits::new());
            }
            Message::DestroySession { session_id } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.state.session_id(),
                    destroyed_session_id = ?session_id,
                    "destroy session",
                );

                self.state
                    .socket()
                    .send_message(SessionStatus::new(session_id, SessionStatusKind::Destroyed));
            }
            Message::CreateSession {
                destination,
                date,
                mut options,
            } => match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                PendingSessionState::Inactive {
                    session_id,
                    mut socket,
                } => {
                    tracing::info!(
                        target: LOG_TARGET,
                        ?session_id,
                        destination = %destination.id(),
                        ?date,
                        num_options = ?options.len(),
                        "create session",
                    );

                    // create tunnel pool config
                    //
                    // emissary uses `inbound.nick` to name the tunnel pool config and in case it's
                    // not set check if `outbound.nick` is set and if so, use that for the tunnel
                    // pool's name
                    //
                    // if neither is set, use the destination short hash as the tunnel pool's name
                    let tunnel_pool_config = {
                        match options.get(&Str::from("inbound.nickname")) {
                            Some(_) => TunnelPoolConfig::from(&options),
                            None => {
                                let name =
                                    options.get(&Str::from("outbound.nickname")).map_or_else(
                                        || Str::from(destination.id().to_string()),
                                        |name| name.clone(),
                                    );
                                options.insert(Str::from("inbound.nickname"), name);

                                TunnelPoolConfig::from(&options)
                            }
                        }
                    };

                    // attempt to create tunnel pool for the session
                    //
                    // if channel towards `TunnelManager` is clogged, don't respond to the client,
                    // allowing them to retry `CreateSession` later when the channel has available
                    // capacity
                    //
                    // response from `TunnelManagerHandle::create_tunnel_pool()` is a future which
                    // the session must poll until a `TunnelPoolHandle` is received. Reception of
                    // the handle doesn't mean the tunnel is ready for use and the handle must be
                    // polled further until an inbound tunnel is built
                    match self.tunnel_manager_handle.create_tunnel_pool(tunnel_pool_config) {
                        Ok(future) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                ?session_id,
                                "tunnel pool build started",
                            );

                            socket.send_message(SessionStatus::new(
                                SessionId::Session(session_id),
                                SessionStatusKind::Created,
                            ));
                            self.state = PendingSessionState::BuildingPool {
                                session_id,
                                socket,
                                options,
                                tunnel_pool_future: Box::pin(future),
                            };
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?session_id,
                                ?error,
                                "failed to build tunnel pool",
                            );

                            self.state = PendingSessionState::Inactive { session_id, socket };
                        }
                    }
                }
                state => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?state,
                        "`CreateSession` received but tunnel pool is already pending",
                    );

                    self.state = state;
                }
            },
            Message::CreateLeaseSet2 {
                key,
                leaseset,
                private_keys,
                ..
            } => match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                PendingSessionState::AwaitingLeaseSet {
                    session_id,
                    socket,
                    options,
                    handle,
                    inbound,
                    outbound,
                } => {
                    // the lease set is returned to the active session constructor which publishes
                    // it to netdb
                    return Some(I2cpSessionContext {
                        address_book: self.address_book.clone(),
                        destination_id: DestinationId::from(key),
                        inbound,
                        leaseset,
                        options,
                        outbound,
                        private_keys,
                        profile_storage: self.profile_storage.clone(),
                        session_id,
                        socket,
                        tunnel_pool_handle: handle,
                    });
                }
                state => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?state,
                        "`CreateLeaseSet2` received but not awaiting lease set",
                    );
                    debug_assert!(false);

                    self.state = state;
                }
            },
            _ => {}
        }

        None
    }
}

impl<R: Runtime> Future for PendingI2cpSession<R> {
    type Output = Option<I2cpSessionContext<R>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.state.socket().poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(message)) =>
                    if let Some(context) = self.on_message(message) {
                        return Poll::Ready(Some(context));
                    },
            }
        }

        loop {
            match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                state @ PendingSessionState::Inactive { .. } => {
                    self.state = state;
                    break;
                }
                PendingSessionState::BuildingPool {
                    session_id,
                    socket,
                    options,
                    mut tunnel_pool_future,
                } => match tunnel_pool_future.poll_unpin(cx) {
                    Poll::Ready(handle) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            "tunnel pool for the session has been built",
                        );

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound: HashMap::new(),
                            outbound: HashSet::new(),
                        };
                    }
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingPool {
                            session_id,
                            socket,
                            options,
                            tunnel_pool_future,
                        };
                        break;
                    }
                },
                PendingSessionState::BuildingTunnels {
                    session_id,
                    mut socket,
                    options,
                    mut handle,
                    mut inbound,
                    mut outbound,
                } => match handle.poll_next_unpin(cx) {
                    Poll::Pending => {
                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "inbound tunnel built for pending session",
                        );
                        inbound.insert(tunnel_id, lease);

                        // wait until all tunnels have been built
                        if inbound.len() != handle.config().num_inbound
                            || outbound.len() != handle.config().num_outbound
                        {
                            self.state = PendingSessionState::BuildingTunnels {
                                session_id,
                                socket,
                                options,
                                handle,
                                inbound,
                                outbound,
                            };
                            continue;
                        }

                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            "send leaseset request to client",
                        );

                        socket.send_message(RequestVariableLeaseSet::new(
                            session_id,
                            inbound.values().cloned().collect::<Vec<_>>(),
                        ));

                        self.state = PendingSessionState::AwaitingLeaseSet {
                            inbound,
                            options,
                            outbound,
                            session_id,
                            socket,
                            handle,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "outbound tunnel built for pending session",
                        );
                        outbound.insert(tunnel_id);

                        // wait until all tunnels have been built
                        if inbound.len() != handle.config().num_inbound
                            || outbound.len() != handle.config().num_outbound
                        {
                            self.state = PendingSessionState::BuildingTunnels {
                                session_id,
                                socket,
                                options,
                                handle,
                                inbound,
                                outbound,
                            };
                            continue;
                        }

                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            "send leaseset request to client",
                        );

                        socket.send_message(RequestVariableLeaseSet::new(
                            session_id,
                            inbound.values().cloned().collect::<Vec<_>>(),
                        ));

                        self.state = PendingSessionState::AwaitingLeaseSet {
                            inbound,
                            options,
                            outbound,
                            session_id,
                            socket,
                            handle,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "inbound tunnel expired for pending session",
                        );
                        inbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            %tunnel_id,
                            "outbound tunnel expired for pending session",
                        );
                        outbound.remove(&tunnel_id);

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                    Poll::Ready(Some(event)) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?session_id,
                            ?event,
                            "unexpected event",
                        );

                        self.state = PendingSessionState::BuildingTunnels {
                            session_id,
                            socket,
                            options,
                            handle,
                            inbound,
                            outbound,
                        };
                    }
                },
                state @ PendingSessionState::AwaitingLeaseSet { .. } => {
                    self.state = state;
                    break;
                }
                PendingSessionState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "pending i2cp session tunnel pool state is poisoned",
                    );
                    debug_assert!(false);

                    return Poll::Ready(None);
                }
            }
        }

        Poll::Pending
    }
}
