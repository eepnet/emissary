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
    error::QueryError,
    primitives::{DestinationId, Lease, TunnelId},
    runtime::Runtime,
};

use futures::{future::FutureExt, Stream};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc;

use alloc::{vec, vec::Vec};
use core::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::routing-path";

/// Outbound tunnel expiration.
const OUTBOUND_TUNNEL_EXPIRATION: Duration = Duration::from_secs(30);

/// Inbound tunnel minimum age.
const INBOUND_TUNNEL_MIN_AGE: Duration = Duration::from_secs(30);

/// Maximum number of lease set queries before remote is considered unreachable.
const MAX_LEASE_SET_QUERIES: usize = 3usize;

/// Recycling strategy for [`NetDbAction`].
#[derive(Default, Clone, Debug)]
pub struct RoutingPathCommandRecycle(());

impl thingbuf::Recycle<RoutingPathCommand> for RoutingPathCommandRecycle {
    fn new_element(&self) -> RoutingPathCommand {
        RoutingPathCommand::Dummy
    }

    fn recycle(&self, element: &mut RoutingPathCommand) {
        *element = RoutingPathCommand::Dummy;
    }
}

/// Commands send to [`RoutingPathManager`] from [`RoutingPathHandle`]s and
/// [`PendingRoutingPathHandle`]s.
#[derive(Default)]
enum RoutingPathCommand {
    /// Get [`RoutingPathHandle`] bound to `destination_id`'s inbound tunnel events.
    GetHandle {
        /// Destination ID.
        destination_id: DestinationId,

        /// Oneshot channel for sending context for [`RoutingPathHandle`].
        tx: oneshot::Sender<(
            mpsc::Receiver<RoutingPathEvent>,
            mpsc::Sender<RoutingPathCommand, RoutingPathCommandRecycle>,
            Vec<(TunnelId, Duration)>,
            HashSet<TunnelId>,
            Vec<(TunnelId, Duration)>,
        )>,
    },

    /// Request remote lease set.
    RequestLeaseSet {
        /// Destination ID.
        destination_id: DestinationId,

        /// TX channel for receiving the result.
        tx: oneshot::Sender<Result<(), QueryError>>,
    },

    #[default]
    Dummy,
}

impl fmt::Debug for RoutingPathCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetHandle { destination_id, .. } => f
                .debug_struct("RoutingPathCommand::GetHandle")
                .field("destination_id", &format_args!("{destination_id}"))
                .finish(),
            Self::RequestLeaseSet { destination_id, .. } => f
                .debug_struct("RoutingPathCommand::RequestLeaseSet")
                .field("destination_id", &format_args!("{destination_id}"))
                .finish_non_exhaustive(),
            Self::Dummy => unreachable!(),
        }
    }
}

/// Routing path used to send a message to remote destination.
#[derive(Clone)]
pub struct RoutingPath {
    /// ID of the remote destination.
    pub destination_id: DestinationId,

    /// ID of the remote destination's inbound tunnel, i.e., ID of the remote's IBGW.
    pub inbound: TunnelId,

    /// ID of the local outbound tunnel used to send the message, i.e., ID of OBGW.
    pub outbound: TunnelId,
}

impl Default for RoutingPath {
    fn default() -> Self {
        Self {
            destination_id: DestinationId::from([0u8; 32]),
            inbound: TunnelId::from(0),
            outbound: TunnelId::from(0),
        }
    }
}

impl fmt::Display for RoutingPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RoutingPath(dest={} ibgw={} obgw={})",
            self.destination_id, self.inbound, self.outbound
        )
    }
}

/// Evens sent by [`RoutingPathManager`] to [`RoutingPathHandle`]s.
#[derive(Default, Clone)]
enum RoutingPathEvent {
    /// Remote destination has built one or more inbound tunnels.
    InboundTunnelBuilt {
        /// ID of the built tunnel and when the tunnel expires.
        tunnels: Vec<(TunnelId, Duration)>,
    },

    /// Outbound tunnel has been built.
    OutboundTunnelBuilt {
        /// ID of the built tunnel.
        tunnel_id: TunnelId,
    },

    /// Outbound tunnel is about to expire.
    OutboundTunnelExpiring {
        /// ID of the built tunnel.
        tunnel_id: TunnelId,

        /// When is the tunnel considered expired, time since UNIX epoch.
        expires: Duration,
    },

    /// Outbound tunnel has expired.
    OutboundTunnelExpired {
        /// ID of the built tunnel.
        tunnel_id: TunnelId,
    },

    #[default]
    Dummy,
}

impl fmt::Debug for RoutingPathEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InboundTunnelBuilt { tunnels } => f
                .debug_struct("RoutingPathEvent::InboundTunnelBuilt")
                .field("num_tunnels", &tunnels.len())
                .finish(),
            Self::OutboundTunnelBuilt { tunnel_id } => f
                .debug_struct("RoutingPathEvent::OutboundTunnelBuilt")
                .field("tunnel_id", &tunnel_id)
                .finish(),
            Self::OutboundTunnelExpiring { tunnel_id, expires } => f
                .debug_struct("RoutingPathEvent::OutboundTunnelExpiring")
                .field("tunnel_id", &tunnel_id)
                .field("expires", &expires)
                .finish(),
            Self::OutboundTunnelExpired { tunnel_id } => f
                .debug_struct("RoutingPathEvent::OutboundTunnelExpired")
                .field("tunnel_id", &tunnel_id)
                .finish(),
            Self::Dummy => unreachable!(),
        }
    }
}

/// Routing path manager.
pub struct RoutingPathManager<R> {
    /// RX channel for receiving commands.
    cmd_rx: mpsc::Receiver<RoutingPathCommand, RoutingPathCommandRecycle>,

    /// TX channel for sending commands to [`RoutingPathManager`].
    cmd_tx: mpsc::Sender<RoutingPathCommand, RoutingPathCommandRecycle>,

    /// Local destination ID.
    destination_id: DestinationId,

    /// Expiring outbound tunnels.
    ///
    /// Expiring outbound tunnels are depriotitized which is why they're tracked separately.
    expiring_outbound_tunnels: Vec<(TunnelId, Duration)>,

    /// Inbound tunnels of remote destination
    inbound_tunnels: HashMap<DestinationId, Vec<Lease>>,

    /// Outbound tunnels.
    outbound_tunnels: HashSet<TunnelId>,

    /// Pending lease set queries.
    pending_queries: HashMap<DestinationId, Vec<oneshot::Sender<Result<(), QueryError>>>>,

    /// Subscribers to routing path events.
    ///
    /// These are the TX channels of all objects that are interested in routing path events
    /// such as active streams and datagram sessions.
    subscribers: HashMap<DestinationId, Vec<mpsc::Sender<RoutingPathEvent>>>,

    /// Marker for `Runtime`
    _runtime: PhantomData<R>,
}

impl<R: Runtime> RoutingPathManager<R> {
    /// Create new [`RoutingPathManager`] from currently active inbound and outbound tunnels.
    pub fn new(destination_id: DestinationId, outbound_tunnels: Vec<TunnelId>) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::with_recycle(512, RoutingPathCommandRecycle::default());

        Self {
            cmd_rx,
            cmd_tx,
            destination_id,
            expiring_outbound_tunnels: Vec::new(),
            inbound_tunnels: HashMap::new(),
            outbound_tunnels: outbound_tunnels.into_iter().collect(),
            pending_queries: HashMap::new(),
            subscribers: HashMap::new(),
            _runtime: Default::default(),
        }
    }

    /// Acquire [`RoutingPathHandle`].
    pub fn handle(&mut self, destination_id: DestinationId) -> RoutingPathHandle<R> {
        let (tx, rx) = mpsc::channel(128);

        match self.subscribers.get_mut(&destination_id) {
            Some(subscribers) => {
                subscribers.push(tx);
            }
            None => {
                self.subscribers.insert(destination_id.clone(), vec![tx]);
            }
        }
        let inbound_tunnels =
            self.inbound_tunnels.get(&destination_id).map_or_else(Vec::new, |tunnels| {
                tunnels.iter().map(|lease| (lease.tunnel_id, lease.expires)).collect()
            });

        RoutingPathHandle::new(
            destination_id,
            rx,
            self.cmd_tx.clone(),
            inbound_tunnels,
            self.outbound_tunnels.clone(),
            self.expiring_outbound_tunnels.clone(),
        )
    }

    /// Get pending routing path handle.
    ///
    /// The returned handle is not bound to any `DestinationId` but allows the owner to acquire a
    /// [`RoutingPathHandle`] bound to a specific destination once the destination ID is resolved.
    ///
    /// This is used by protocols that accept inbound connection and thus don't know which
    /// `DestinationId` they should subscribe to at the time of creating the handle.
    ///
    /// Once the `DestinationId` is resolved, [`PendingRoutingPathHandle::bind()`] is called with
    /// remote's `DestinationId` which sends a command to [`RoutingPathManager`] which creates a new
    /// handle subscribing to that destination's inbound tunnel events and sends that to the owner
    /// of the [`PendingRoutingPathHandle`].
    pub fn pending_handle(&self) -> PendingRoutingPathHandle {
        PendingRoutingPathHandle::new(self.cmd_tx.clone())
    }

    /// Register a new local outbound tunnel.
    pub fn register_outbound_tunnel_built(&mut self, tunnel_id: TunnelId) {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?tunnel_id,
            "outbound tunnel built",
        );
        self.outbound_tunnels.insert(tunnel_id);

        self.subscribers.values_mut().for_each(|subscribers| {
            subscribers.retain(|tx| {
                match tx.try_send(RoutingPathEvent::OutboundTunnelBuilt { tunnel_id }) {
                    Ok(_) => true,
                    Err(mpsc::errors::TrySendError::Full(_)) => true,
                    Err(mpsc::errors::TrySendError::Closed(_)) => false,
                    Err(_) => true,
                }
            });
        });
    }

    /// Register that a local outbound tunnel is about to expire.
    pub fn register_outbound_tunnel_expiring(&mut self, tunnel_id: TunnelId) {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?tunnel_id,
            "outbound tunnel about to expire",
        );
        let expires = R::time_since_epoch() + 3 * OUTBOUND_TUNNEL_EXPIRATION;

        self.expiring_outbound_tunnels.push((tunnel_id, expires));
        self.outbound_tunnels.remove(&tunnel_id);

        self.subscribers.values_mut().for_each(|subscribers| {
            subscribers.retain(|tx| {
                match tx.try_send(RoutingPathEvent::OutboundTunnelExpiring { tunnel_id, expires }) {
                    Ok(_) => true,
                    Err(mpsc::errors::TrySendError::Full(_)) => true,
                    Err(mpsc::errors::TrySendError::Closed(_)) => false,
                    Err(_) => true,
                }
            })
        });
    }

    /// Register that a local outbound tunnel has expired.
    pub fn register_outbound_tunnel_expired(&mut self, tunnel_id: TunnelId) {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?tunnel_id,
            "outbound tunnel expired",
        );
        self.expiring_outbound_tunnels.retain(|(tunnel, _)| tunnel != &tunnel_id);

        self.subscribers.values_mut().for_each(|subscribers| {
            subscribers.retain(|tx| {
                match tx.try_send(RoutingPathEvent::OutboundTunnelExpired { tunnel_id }) {
                    Ok(_) => true,
                    Err(mpsc::errors::TrySendError::Full(_)) => true,
                    Err(mpsc::errors::TrySendError::Closed(_)) => false,
                    Err(_) => true,
                }
            });
        });
    }

    /// Register potential new leases for `destination_id`.
    ///
    /// All lease set stores and query results get reported to [`RoutingPathManager`] because lease
    /// sets can be learned through either remote-initiated `DatabaseStore`s or lease set queries
    /// initiated by one of the higher-level protocols or directly by routing path.
    ///
    /// Each routing path keeps track of many times it has requested remote lease set and if the
    /// number of consecutive failures is more than [`MAX_LEASE_SET_QUERIES`], the routing path
    /// signals the protocol that remote destination is unreachable and the protocol closes.
    ///
    /// Lease sets learned through `DatabaseStore` messages are always passed in as `Ok(LeaseSet2)`
    /// whereas query results are passed in as either `Ok(LeaseSet2)` or `Err(QueryError)`,
    /// depending on whether the query succeeded.
    ///
    /// If the query was not initiated by any of the active [`RoutingPathHandle`]s, the error is
    /// ignored.
    pub fn register_leases(
        &mut self,
        destination_id: &DestinationId,
        lease_set: Result<Vec<Lease>, QueryError>,
    ) {
        let leases = match (self.pending_queries.remove(destination_id), lease_set) {
            (None, Err(_)) => return, // nobody is interested in the query failure
            (Some(channels), Err(error)) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %destination_id,
                    ?error,
                    num_subscribers = ?channels.len(),
                    "lease set query failed",
                );

                return channels.into_iter().for_each(|tx| {
                    let _ = tx.send(Err(error));
                });
            }
            (Some(channels), Ok(leases)) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %destination_id,
                    num_subscribers = ?channels.len(),
                    "lease set query succeeded",
                );

                channels.into_iter().for_each(|tx| {
                    let _ = tx.send(Ok(()));
                });

                leases
            }
            (None, Ok(leases)) => leases,
        };

        let current_leases = match self.inbound_tunnels.get_mut(destination_id) {
            Some(leases) => leases,
            None => {
                self.inbound_tunnels
                    .insert(destination_id.clone(), Vec::with_capacity(leases.len()));
                self.inbound_tunnels.get_mut(destination_id).expect("to exist")
            }
        };

        for Lease {
            router_id,
            tunnel_id,
            ..
        } in &leases
        {
            tracing::trace!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %destination_id,
                ibgw_router_id = %router_id,
                ibgw_tunnel_id = %tunnel_id,
                "register new lease"
            );
        }

        // extend the current set of `destination_id`'s leases and prune all expired leases
        current_leases.extend(leases.clone());
        current_leases.retain(|lease| lease.expires > R::time_since_epoch());

        if let Some(subscribers) = self.subscribers.get_mut(destination_id) {
            subscribers.retain(|tx| {
                match tx.try_send(RoutingPathEvent::InboundTunnelBuilt {
                    tunnels: leases.iter().map(|lease| (lease.tunnel_id, lease.expires)).collect(),
                }) {
                    Ok(_) => true,
                    Err(mpsc::errors::TrySendError::Full(_)) => true,
                    Err(mpsc::errors::TrySendError::Closed(_)) => false,
                    Err(_) => true,
                }
            });
        }
    }
}

impl<R: Unpin> Stream for RoutingPathManager<R> {
    type Item = DestinationId;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match futures::ready!(self.cmd_rx.poll_recv(cx)) {
                None => return Poll::Ready(None),
                Some(RoutingPathCommand::GetHandle { destination_id, tx }) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %destination_id,
                        "bind routing path handle to destination",
                    );

                    let (event_tx, event_rx) = mpsc::channel(128);

                    match self.subscribers.get_mut(&destination_id) {
                        Some(subscribers) => {
                            subscribers.push(event_tx);
                        }
                        None => {
                            self.subscribers.insert(destination_id.clone(), vec![event_tx]);
                        }
                    }
                    let inbound_tunnels = self.inbound_tunnels.get(&destination_id).map_or_else(
                        Vec::new,
                        |tunnels| {
                            tunnels.iter().map(|lease| (lease.tunnel_id, lease.expires)).collect()
                        },
                    );

                    if let Err(error) = tx.send((
                        event_rx,
                        self.cmd_tx.clone(),
                        inbound_tunnels,
                        self.outbound_tunnels.clone(),
                        self.expiring_outbound_tunnels.clone(),
                    )) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %destination_id,
                            ?error,
                            "failed to send context for routing path handle"
                        );
                    }
                }
                Some(RoutingPathCommand::RequestLeaseSet { destination_id, tx }) => {
                    match self.pending_queries.get_mut(&destination_id) {
                        Some(channels) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                %destination_id,
                                "lease set query already in progress",
                            );
                            channels.push(tx);
                        }
                        None => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %destination_id,
                                "starting lease set query",
                            );
                            self.pending_queries.insert(destination_id.clone(), vec![tx]);

                            return Poll::Ready(Some(destination_id));
                        }
                    }
                }
                Some(RoutingPathCommand::Dummy) => {}
            }
        }
    }
}

/// Pending [`RoutingPathHandle`], currently unbound to a `DestinationId`.
///
/// See [`RoutingPathManager::pending_handle()`] for more details.
#[derive(Clone)]
pub struct PendingRoutingPathHandle {
    /// TX channel for sending commands.
    tx: mpsc::Sender<RoutingPathCommand, RoutingPathCommandRecycle>,
}

impl PendingRoutingPathHandle {
    /// Create new [`HandleFuture`].
    fn new(tx: mpsc::Sender<RoutingPathCommand, RoutingPathCommandRecycle>) -> Self {
        Self { tx }
    }

    /// Attempt to bind [`PendingRoutingPathHandle`] to a `DestinationId`.
    ///
    /// Returns a future which must be awaited and which on success returns a [`RoutingPathHandle`]
    /// bound to `destination_id`'s inbound tunnel events.
    pub async fn bind<R: Runtime>(
        self,
        destination_id: DestinationId,
    ) -> Option<RoutingPathHandle<R>> {
        let (tx, rx) = oneshot::channel();

        self.tx
            .send(RoutingPathCommand::GetHandle {
                destination_id: destination_id.clone(),
                tx,
            })
            .await
            .ok()?;

        rx.await.ok().map(
            |(rx, cmd_tx, inbound_tunnels, outbound_tunnels, expiring_outbound_tunnels)| {
                RoutingPathHandle::<R>::new(
                    destination_id,
                    rx,
                    cmd_tx,
                    inbound_tunnels,
                    outbound_tunnels,
                    expiring_outbound_tunnels,
                )
            },
        )
    }

    /// Create [`PendingRoutingPathHandle`] for testing.
    ///
    /// The handle cannot be used for anything.
    #[cfg(test)]
    pub fn create() -> Self {
        let (tx, _rx) = mpsc::with_recycle(16, RoutingPathCommandRecycle::default());

        Self { tx }
    }
}

/// Tunnel kind.
#[derive(Debug)]
enum TunnelKind {
    /// Active outbound tunnels.
    Outbound {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Expiring outbound tunnel.
    ExpiringOutbound {
        /// Tunnel ID.
        tunnel_id: TunnelId,

        /// When does the tunnel expires.
        expires: Duration,
    },

    /// Failing outbound tunnel.
    FailingOutbound {
        /// Tunnel ID.
        tunnel_id: TunnelId,

        /// When does the tunnel expires.
        ///
        /// `Some` if the tunnel is also expiring.
        expires: Option<Duration>,
    },

    /// Active inbound tunnel.
    Inbound {
        /// Tunnel ID.
        tunnel_id: TunnelId,

        /// When does the tunnel expire.
        expires: Duration,
    },

    /// Failing inbound tunnel.
    FailingInbound {
        /// Tunnel ID.
        tunnel_id: TunnelId,

        /// When does the tunnel expire.
        expires: Duration,
    },
}

/// Remote lease set query status.
enum LeaseSetQueryStatus {
    /// Remote lease set is not being quried.
    Inactive {
        /// How many times the remote lease set has been queried.
        ///
        /// Resets if the lease set is found and if it's not found after
        /// [`MAX_LEASE_SET_QUERIES`] retries, [`RoutingPathHandle`] will exit, signaling to the
        /// owner of that handle that the remote destination is unreachable.
        num_retries: usize,
    },

    /// Remote lease set is actively being queried.
    Pending {
        /// How many times the remote lease set has been queried.
        ///
        /// Resets if the lease set is found and if it's not found after
        /// [`MAX_LEASE_SET_QUERIES`] retries, [`RoutingPathHandle`] will exit, signaling to the
        /// owner of that handle that the remote destination is unreachable.
        num_retries: usize,

        /// RX channel for receiving the query result.
        rx: oneshot::Receiver<Result<(), QueryError>>,
    },
}

/// Routing path handle.
pub struct RoutingPathHandle<R: Runtime> {
    /// TX channel for sending lease set requests to [`RoutingPathManager`].
    cmd_tx: mpsc::Sender<RoutingPathCommand, RoutingPathCommandRecycle>,

    /// ID of the remote destination.
    destination_id: DestinationId,

    /// RX channel for receiving [`RoutingPathEvent`]s.
    event_rx: mpsc::Receiver<RoutingPathEvent>,

    /// Inbound tunnel expiration timer.
    inbound_expiration_timer: Option<R::Timer>,

    /// Lease set query status.
    lease_set_query_status: LeaseSetQueryStatus,

    /// Selected routing path, if any.
    routing_path: Option<RoutingPath>,

    /// Tunnels.
    tunnels: HashMap<TunnelId, TunnelKind>,
}

impl<R: Runtime> RoutingPathHandle<R> {
    /// Create new [`RoutingPathHandle`].
    fn new(
        destination_id: DestinationId,
        event_rx: mpsc::Receiver<RoutingPathEvent>,
        cmd_tx: mpsc::Sender<RoutingPathCommand, RoutingPathCommandRecycle>,
        inbound_tunnels: Vec<(TunnelId, Duration)>,
        outbound_tunnels: HashSet<TunnelId>,
        expiring_outbound_tunnels: Vec<(TunnelId, Duration)>,
    ) -> Self {
        let tunnels = inbound_tunnels
            .into_iter()
            .map(|(tunnel_id, expires)| (tunnel_id, TunnelKind::Inbound { tunnel_id, expires }))
            .chain(
                outbound_tunnels
                    .into_iter()
                    .map(|tunnel_id| (tunnel_id, TunnelKind::Outbound { tunnel_id })),
            )
            .chain(
                expiring_outbound_tunnels.into_iter().map(|(tunnel_id, expires)| {
                    (
                        tunnel_id,
                        TunnelKind::ExpiringOutbound { tunnel_id, expires },
                    )
                }),
            )
            .collect::<HashMap<_, _>>();

        Self {
            cmd_tx,
            destination_id,
            event_rx,
            inbound_expiration_timer: None,
            lease_set_query_status: LeaseSetQueryStatus::Inactive {
                num_retries: 0usize,
            },
            routing_path: None,
            tunnels,
        }
    }

    /// Attempt to select an outbound tunnel for routing path.
    ///
    /// First look into active tunnels and if there aren't any, try to select a tunnel from the set
    /// of expiring tunnels, if there's any with long enough lifetime. If there are no good expiring
    /// tunnels, attempt to select a tunnel from the set of failing tunnels in hopes that the tunnel
    /// works now. If there are no tunnels, `None` is returned and the caller must try again later.
    fn select_outbound_tunnel(&self) -> Option<TunnelId> {
        let now = R::time_since_epoch();

        // TODO: upgrade to 2024 and collect into three vectors
        let available = self
            .tunnels
            .iter()
            .filter_map(|(tunnel_id, kind)| {
                core::matches!(kind, TunnelKind::Outbound { .. }).then_some(*tunnel_id)
            })
            .collect::<Vec<_>>();

        let (expiring, failing): (Vec<_>, Vec<_>) = self
            .tunnels
            .iter()
            .filter_map(|(_, kind)| match kind {
                TunnelKind::ExpiringOutbound { tunnel_id, expires }
                    if *expires > now + OUTBOUND_TUNNEL_EXPIRATION =>
                    Some((Some(*tunnel_id), None)),
                TunnelKind::FailingOutbound { tunnel_id, expires } => match expires {
                    Some(expires) if *expires > now + OUTBOUND_TUNNEL_EXPIRATION =>
                        Some((None, Some(*tunnel_id))),
                    None => Some((None, Some(*tunnel_id))),
                    _ => None,
                },
                _ => None,
            })
            .unzip();

        // first attempt to select an expiring tunnel
        let expiring = expiring.into_iter().flatten().collect::<Vec<_>>();
        let failing = failing.into_iter().flatten().collect::<Vec<_>>();

        tracing::trace!(
            target: LOG_TARGET,
            destination_id = %self.destination_id,
            num_available = ?available.len(),
            num_expiring = ?expiring.len(),
            num_failing = ?failing.len(),
            "attempt to select outbound tunnel",
        );

        if !available.is_empty() {
            return Some(available[(R::rng().next_u32() as usize) % available.len()]);
        }

        if !expiring.is_empty() {
            return Some(expiring[(R::rng().next_u32() as usize) % expiring.len()]);
        }

        // finally attempt to select a failing tunnel
        if !failing.is_empty() {
            return Some(failing[(R::rng().next_u32() as usize) % failing.len()]);
        }

        tracing::debug!(
            target: LOG_TARGET,
            destination_id = %self.destination_id,
            "no outbound tunnels",
        );

        None
    }

    /// Attempt to select an inbound tunnel for routing path.
    ///
    /// Select those inbound tunnels which won't expire for the next 30 seconds and from the set
    /// of non-expiring tunnels, select a random tunnel.
    fn select_inbound_tunnel(&mut self) -> Option<(TunnelId, Duration)> {
        let now = R::time_since_epoch();

        let (available, failing): (Vec<_>, Vec<_>) = self
            .tunnels
            .iter()
            .filter_map(|(_, kind)| match kind {
                TunnelKind::Inbound { tunnel_id, expires }
                    if *expires > now + INBOUND_TUNNEL_MIN_AGE =>
                    Some((Some((*tunnel_id, *expires)), None)),
                TunnelKind::FailingInbound { tunnel_id, expires }
                    if *expires > now + INBOUND_TUNNEL_MIN_AGE =>
                    Some((None, Some((*tunnel_id, *expires)))),
                _ => None,
            })
            .unzip();

        // first attempt select a random inbound tunnel
        let available = available.into_iter().flatten().collect::<Vec<_>>();
        let failing = failing.into_iter().flatten().collect::<Vec<_>>();

        tracing::trace!(
            target: LOG_TARGET,
            destination_id = %self.destination_id,
            num_available = ?available.len(),
            num_failing = ?failing.len(),
            "attempt to select inbound tunnel",
        );

        if !available.is_empty() {
            return Some(available[(R::rng().next_u32() as usize) % available.len()]);
        }

        if !failing.is_empty() {
            return Some(failing[(R::rng().next_u32() as usize) % failing.len()]);
        }

        match self.lease_set_query_status {
            LeaseSetQueryStatus::Inactive { num_retries } => {
                let (tx, rx) = oneshot::channel();

                match self.cmd_tx.try_send(RoutingPathCommand::RequestLeaseSet {
                    destination_id: self.destination_id.clone(),
                    tx,
                }) {
                    Ok(()) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            destination_id = %self.destination_id,
                            ?num_retries,
                            "no inbound tunnels, starting lease set query",
                        );
                        self.lease_set_query_status = LeaseSetQueryStatus::Pending {
                            num_retries: num_retries + 1,
                            rx,
                        };
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            destination_id = %self.destination_id,
                            ?num_retries,
                            ?error,
                            "no inbound tunnels and failed to start lease set query",
                        );
                    }
                }
            }
            LeaseSetQueryStatus::Pending { num_retries, .. } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    destination_id = %self.destination_id,
                    ?num_retries,
                    "no inbound tunnels but lease set is being queried",
                );
            }
        }

        None
    }

    /// Attempt to create routing path.
    ///
    /// Try selecting an inbound and an outbound tunnel from the available tunnels and if both
    /// tunnels are found, start an expiration timer for the inbound tunnel so a new routing path is
    /// created before the tunnel expires, create and return the new routing path.
    fn make_routing_path(&mut self) -> Option<RoutingPath> {
        let outbound = self.select_outbound_tunnel()?;
        let (inbound, expires) = self.select_inbound_tunnel()?;

        // `select_inbond_tunnel()` has ensured the tunnel doesn't expire in the next 30 seconds
        self.inbound_expiration_timer = Some(R::timer(
            expires - R::time_since_epoch() - INBOUND_TUNNEL_MIN_AGE,
        ));

        self.routing_path = Some(RoutingPath {
            inbound,
            outbound,
            destination_id: self.destination_id.clone(),
        });

        self.routing_path.clone()
    }

    /// Get a copy of the assigned routing path.
    ///
    /// A new routing path is created if one doesn't exist yet. A new routing path is created if the
    /// inbound tunnel used by the current routing path is expired or about to expire soon. A new
    /// routing path may be created if the outbound tunnel used by the current routing path is about
    /// to expire.
    ///
    /// While unlikely, `None` is returned if a routing path cannot be constructed if there are
    /// either no inbound or outbound tunnels.
    pub fn routing_path(&mut self) -> Option<RoutingPath> {
        match &self.routing_path {
            Some(routing_path) => Some(routing_path.clone()),
            None => self.make_routing_path(),
        }
    }

    /// Attempt to create new routing path, replacing the old one.
    ///
    /// Note that the same routing path may be created if there are no other tunnels available.
    ///
    /// Returns `None` if there are either no inbound or no outbound tunnels.
    pub fn recreate_routing_path(&mut self) -> Option<RoutingPath> {
        let Some(RoutingPath {
            inbound, outbound, ..
        }) = &self.routing_path
        else {
            return self.make_routing_path();
        };

        // owner of the handle has requested a new routing path to be created because the previous
        // inbound/outbound combination was faulty
        //
        // this may return the same routing path if there are no other tunnels available
        tracing::debug!(
            target: LOG_TARGET,
            destination_id = %self.destination_id,
            %inbound,
            %outbound,
            "marking routing path as failing",
        );

        // reset inbound expiration time in case a new routing path cannot be constructed
        self.inbound_expiration_timer = None;

        match self.tunnels.remove(inbound) {
            Some(
                TunnelKind::Inbound { tunnel_id, expires }
                | TunnelKind::FailingInbound { tunnel_id, expires },
            ) => {
                self.tunnels.insert(*inbound, TunnelKind::FailingInbound { tunnel_id, expires });
            }
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    destination_id = %self.destination_id,
                    %inbound,
                    ?kind,
                    "invalid tunnel kind for inbound tunnel",
                );
                debug_assert!(false);
            }
        }

        match self.tunnels.remove(outbound) {
            Some(TunnelKind::Outbound { tunnel_id }) => {
                self.tunnels.insert(
                    *outbound,
                    TunnelKind::FailingOutbound {
                        tunnel_id,
                        expires: None,
                    },
                );
            }
            Some(TunnelKind::ExpiringOutbound { tunnel_id, expires }) => {
                self.tunnels.insert(
                    *outbound,
                    TunnelKind::FailingOutbound {
                        tunnel_id,
                        expires: Some(expires),
                    },
                );
            }
            Some(TunnelKind::FailingOutbound { tunnel_id, expires }) => {
                self.tunnels.insert(
                    *outbound,
                    TunnelKind::FailingOutbound { tunnel_id, expires },
                );
            }
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    destination_id = %self.destination_id,
                    %outbound,
                    ?kind,
                    "invalid tunnel kind for outbound tunnel",
                );
                debug_assert!(false);
            }
        }

        self.make_routing_path()
    }
}

impl<R: Runtime> Future for RoutingPathHandle<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let LeaseSetQueryStatus::Pending {
            num_retries,
            ref mut rx,
        } = self.lease_set_query_status
        {
            match rx.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(Ok(()))) => {
                    self.lease_set_query_status = LeaseSetQueryStatus::Inactive { num_retries: 0 };
                }
                Poll::Ready(Ok(Err(error))) => {
                    if num_retries == MAX_LEASE_SET_QUERIES {
                        tracing::warn!(
                            target: LOG_TARGET,
                            destination_id = %self.destination_id,
                            ?num_retries,
                            ?error,
                            "failed to find remote lease set after multiple retries",
                        );
                        return Poll::Ready(());
                    }

                    self.lease_set_query_status = LeaseSetQueryStatus::Inactive { num_retries };
                }
                Poll::Ready(Err(_)) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        destination_id = %self.destination_id,
                        "lease set query channel closed",
                    );
                    debug_assert!(false);
                }
            }
        }

        if let Some(timer) = &mut self.inbound_expiration_timer {
            if timer.poll_unpin(cx).is_ready() {
                tracing::debug!(
                    target: LOG_TARGET,
                    destination_id = %self.destination_id,
                    "inbound tunnel of current routing about to expire, invalidate routing path",
                );

                self.routing_path = None;
                self.inbound_expiration_timer = None;
            }
        }

        loop {
            match futures::ready!(self.event_rx.poll_recv(cx)) {
                None => return Poll::Ready(()),
                Some(event) => match event {
                    RoutingPathEvent::InboundTunnelBuilt { tunnels } => {
                        // invalidate current routing path if it uses failing tunnel
                        if let Some(RoutingPath { inbound, .. }) = &self.routing_path {
                            if core::matches!(
                                self.tunnels.get(inbound),
                                Some(TunnelKind::FailingInbound { .. })
                            ) {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    destination_id = %self.destination_id,
                                    %inbound,
                                    "new inbound tunnel built, invalidate routing path",
                                );

                                self.routing_path = None;
                                self.inbound_expiration_timer = None;
                            }
                        }
                        let now = R::time_since_epoch();
                        let routing_path_inbound_tunnel =
                            self.routing_path.as_ref().map(|path| path.inbound);

                        tunnels.into_iter().for_each(|(tunnel_id, expires)| {
                            self.tunnels
                                .insert(tunnel_id, TunnelKind::Inbound { tunnel_id, expires });
                        });

                        self.tunnels.retain(|tunnel_id, kind| {
                            // don't remove tunnel currently used by the routing path
                            if let Some(inbound) = routing_path_inbound_tunnel {
                                if *tunnel_id == inbound {
                                    return true;
                                }
                            }

                            match kind {
                                TunnelKind::Inbound { expires, .. } => *expires > now,
                                TunnelKind::FailingInbound { expires, .. } => *expires > now,
                                _ => true,
                            }
                        })
                    }
                    RoutingPathEvent::OutboundTunnelBuilt { tunnel_id } => {
                        // invalidate current routing path if it uses expiring/failing tunnel
                        if let Some(RoutingPath { outbound, .. }) = &self.routing_path {
                            if core::matches!(
                                self.tunnels.get(outbound),
                                Some(
                                    TunnelKind::ExpiringOutbound { .. }
                                        | TunnelKind::FailingOutbound { .. }
                                )
                            ) {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    destination_id = %self.destination_id,
                                    %outbound,
                                    "new outbound tunnel built, invalidate routing path",
                                );

                                self.routing_path = None;
                                self.inbound_expiration_timer = None;
                            }
                        }

                        self.tunnels.insert(tunnel_id, TunnelKind::Outbound { tunnel_id });
                    }
                    RoutingPathEvent::OutboundTunnelExpiring { tunnel_id, expires } => {
                        self.tunnels.insert(
                            tunnel_id,
                            TunnelKind::ExpiringOutbound { tunnel_id, expires },
                        );

                        // invalidate current routing path if it depends on the expiring tunnel
                        if self
                            .routing_path
                            .as_ref()
                            .is_some_and(|routing_path| routing_path.outbound == tunnel_id)
                        {
                            tracing::trace!(
                                target: LOG_TARGET,
                                destination_id = %self.destination_id,
                                %tunnel_id,
                                "outbound tunnel about to expire, invalidate routing path",
                            );

                            self.routing_path = None;
                            self.inbound_expiration_timer = None;
                        }
                    }
                    RoutingPathEvent::OutboundTunnelExpired { tunnel_id } => {
                        self.tunnels.remove(&tunnel_id);

                        // invalidate current routing path if it depends on the expired tunnel
                        if self
                            .routing_path
                            .as_ref()
                            .is_some_and(|routing_path| routing_path.outbound == tunnel_id)
                        {
                            tracing::warn!(
                                target: LOG_TARGET,
                                destination_id = %self.destination_id,
                                %tunnel_id,
                                "outbound tunnel expired, invalidate routing path",
                            );

                            self.routing_path = None;
                            self.inbound_expiration_timer = None;
                        }
                    }
                    RoutingPathEvent::Dummy => {}
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{primitives::RouterId, runtime::mock::MockRuntime};
    use futures::StreamExt;

    #[tokio::test(start_paused = true)]
    async fn make_routing_path() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }
    }

    #[test]
    fn expiring_inbound_tunnel() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease {
            tunnel_id: TunnelId::random(),
            router_id: RouterId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path but since the only inbound tunnel is about to expire,
        // there is no way to make a routing path
        assert!(handle.routing_path().is_none());
    }

    #[tokio::test]
    async fn expiring_inbound_tunnel_invalidates_routing_path() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease {
            tunnel_id: TunnelId::random(),
            router_id: RouterId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(40),
        };

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        // wait until the inbound tunnel has expired and try to acquire routing path
        assert!(tokio::time::timeout(Duration::from_secs(15), &mut handle).await.is_err());
        assert!(handle.routing_path().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_outbound_tunnel_invalidates_routing_path() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            0
        );
        manager.register_outbound_tunnel_expiring(outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());

        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            1
        );
        manager.register_outbound_tunnel_expired(outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());

        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            0
        );
        assert!(handle.routing_path().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn failing_tunnels_reused() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
                assert!(core::matches!(
                    handle.tunnels.get(&outbound),
                    Some(TunnelKind::Outbound { .. })
                ));
                assert!(core::matches!(
                    handle.tunnels.get(&ib),
                    Some(TunnelKind::Inbound { .. })
                ));
            }
            None => panic!("expected to succeed"),
        }

        // recreate routing path, marking both inbound and outbound tunnels as failing
        match handle.recreate_routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
                assert!(core::matches!(
                    handle.tunnels.get(&outbound),
                    Some(TunnelKind::FailingOutbound { .. })
                ));
                assert!(core::matches!(
                    handle.tunnels.get(&ib),
                    Some(TunnelKind::FailingInbound { .. })
                ));
            }
            None => panic!("expected to succeed"),
        }

        // recreate routing path again, marking both inbound and outbound tunnels as failing
        match handle.recreate_routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
                assert!(core::matches!(
                    handle.tunnels.get(&outbound),
                    Some(TunnelKind::FailingOutbound { .. })
                ));
                assert!(core::matches!(
                    handle.tunnels.get(&ib),
                    Some(TunnelKind::FailingInbound { .. })
                ));
            }
            None => panic!("expected to succeed"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn new_outbound_tunnel_replaces_expiring_tunnel() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            0
        );
        manager.register_outbound_tunnel_expiring(outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            1
        );
        assert!(handle.routing_path().is_some());

        let new_outbound = TunnelId::random();
        manager.register_outbound_tunnel_built(new_outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            1
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            1
        );

        match handle.routing_path() {
            Some(RoutingPath {
                inbound, outbound, ..
            }) => {
                assert_eq!(outbound, new_outbound);
                assert_eq!(inbound, lease.tunnel_id);
            }
            None => panic!("expected routing path"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn new_outbound_tunnel_replaces_failing_tunnel() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        // recreate routing path and verify the tunnels are marked as failing
        match handle.recreate_routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);

                assert_eq!(handle.tunnels.len(), 2);
                assert!(core::matches!(
                    handle.tunnels.get(&outbound),
                    Some(TunnelKind::FailingOutbound { .. })
                ));
                assert!(core::matches!(
                    handle.tunnels.get(&ib),
                    Some(TunnelKind::FailingInbound { .. })
                ));
            }
            None => panic!("expected to succeed"),
        }

        let new_outbound = TunnelId::random();
        manager.register_outbound_tunnel_built(new_outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::FailingInbound { .. }))
                .count(),
            1
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::FailingOutbound { .. }))
                .count(),
            1
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            1
        );

        match handle.routing_path() {
            Some(RoutingPath {
                inbound, outbound, ..
            }) => {
                assert_eq!(outbound, new_outbound);
                assert_eq!(inbound, lease.tunnel_id);
            }
            None => panic!("expected routing path"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expiring_tunnel_is_used() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        // register new outbound tunnel and verify that routing path doesn't change
        let new_outbound = TunnelId::random();
        manager.register_outbound_tunnel_built(new_outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            2
        );

        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        manager.register_outbound_tunnel_expiring(outbound);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());
        assert!(handle.routing_path.is_none());
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            1
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::ExpiringOutbound { .. }))
                .count(),
            1
        );

        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, new_outbound);
            }
            None => panic!("expected to succeed"),
        }

        // new outbound tunnel is bad, recreate routing path
        //
        // verify that the expiring tunnel is used
        match handle.recreate_routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failing_inbound_tunnel_replaced() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        // recreate routing path and verify the tunnels are marked as failing
        match handle.recreate_routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);

                assert_eq!(handle.tunnels.len(), 2);
                assert!(core::matches!(
                    handle.tunnels.get(&outbound),
                    Some(TunnelKind::FailingOutbound { .. })
                ));
                assert!(core::matches!(
                    handle.tunnels.get(&ib),
                    Some(TunnelKind::FailingInbound { .. })
                ));
            }
            None => panic!("expected to succeed"),
        }

        let new_inbound = Lease::random();
        manager.register_leases(&remote, Ok(vec![new_inbound.clone()]));
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());
        assert!(handle.routing_path.is_none());
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::FailingInbound { .. }))
                .count(),
            1
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::FailingOutbound { .. }))
                .count(),
            1
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Inbound { .. }))
                .count(),
            1
        );

        match handle.routing_path() {
            Some(RoutingPath {
                inbound,
                outbound: ob,
                ..
            }) => {
                assert_eq!(ob, outbound);
                assert_eq!(inbound, new_inbound.tunnel_id);
            }
            None => panic!("expected routing path"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bind_to_destination() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease::random();

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());
        let pending_handle = manager.pending_handle();

        // try to get routing path and verify that it succeeds
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        // register more inbound and outbound tunnels.
        let outbound1 = TunnelId::random();
        let outbound2 = TunnelId::random();
        let inbound1 = Lease::random();
        let inbound2 = Lease::random();

        manager.register_outbound_tunnel_built(outbound1);
        manager.register_leases(&remote, Ok(vec![inbound1]));
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut handle).await.is_err());

        // verify that the routing path hasn't changed
        match handle.routing_path() {
            Some(RoutingPath {
                destination_id: dest,
                inbound: ib,
                outbound: ob,
            }) => {
                assert_eq!(dest, remote);
                assert_eq!(ib, lease.tunnel_id);
                assert_eq!(ob, outbound);
            }
            None => panic!("expected to succeed"),
        }

        // verify that there are now two inbound and two outbound tunnels
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Inbound { .. }))
                .count(),
            2
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            2
        );

        // spawn manager in the background so it can handle the bind request
        let remote_dest = remote.clone();
        tokio::spawn(async move {
            assert!(tokio::time::timeout(Duration::from_secs(5), manager.next()).await.is_err());

            // register two more tunnels and verify that both handles get the updates
            manager.register_outbound_tunnel_built(outbound2);
            manager.register_leases(&remote_dest, Ok(vec![inbound2]));

            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        // bind the pending handle to `remote` and verify it has the same tunnels
        let mut new_handle = pending_handle.bind::<MockRuntime>(remote.clone()).await.unwrap();
        assert!(new_handle.routing_path().is_some());
        assert_eq!(
            new_handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Inbound { .. }))
                .count(),
            2
        );
        assert_eq!(
            new_handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            2
        );

        let future = async {
            tokio::select! {
                _ = &mut handle => {}
                _ = &mut new_handle => {}
            }
        };
        assert!(tokio::time::timeout(Duration::from_secs(2), future).await.is_err());

        assert!(handle.routing_path().is_some());
        assert!(new_handle.routing_path().is_some());

        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Inbound { .. }))
                .count(),
            2
        );
        assert_eq!(
            handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            2
        );
        assert_eq!(
            new_handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Inbound { .. }))
                .count(),
            2
        );
        assert_eq!(
            new_handle
                .tunnels
                .iter()
                .filter(|(_, kind)| core::matches!(kind, TunnelKind::Outbound { .. }))
                .count(),
            2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lease_set_requested_through_routing_path() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease {
            tunnel_id: TunnelId::random(),
            router_id: RouterId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never().unwrap(), Some(remote.clone()));

        // try to create routing path and verify that lease set query is not issued
        // since one is already active
        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never(), None);
        assert!(std::matches!(
            handle.lease_set_query_status,
            LeaseSetQueryStatus::Pending { .. }
        ));

        // register query failure
        manager.register_leases(&remote, Err(QueryError::Timeout));
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Inactive { num_retries } => assert_eq!(num_retries, 1),
            _ => panic!("invalid status"),
        }

        // try to create routing path and verify it fails again and that new query is started
        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never().unwrap(), Some(remote.clone()));

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Pending { num_retries, .. } => assert_eq!(num_retries, 2),
            _ => panic!("invalid status"),
        }

        // register new inbound lease and verify routing path is created
        manager.register_leases(
            &remote,
            Ok(vec![Lease {
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(9 * 60),
            }]),
        );
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Inactive { num_retries } => assert_eq!(num_retries, 0),
            _ => panic!("invalid status"),
        }

        assert!(handle.make_routing_path().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn multiple_consecutive_lease_set_query_errors() {
        let remote = DestinationId::random();
        let outbound = TunnelId::random();
        let lease = Lease {
            tunnel_id: TunnelId::random(),
            router_id: RouterId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };

        let mut manager =
            RoutingPathManager::<MockRuntime>::new(DestinationId::random(), vec![outbound]);
        manager.register_leases(&remote, Ok(vec![lease.clone()]));

        let mut handle = manager.handle(remote.clone());

        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never().unwrap(), Some(remote.clone()));

        // try to create routing path and verify that lease set query is not issued
        // since one is already active
        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never(), None);
        assert!(std::matches!(
            handle.lease_set_query_status,
            LeaseSetQueryStatus::Pending { .. }
        ));

        // register query failure
        manager.register_leases(&remote, Err(QueryError::Timeout));
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Inactive { num_retries } => assert_eq!(num_retries, 1),
            _ => panic!("invalid status"),
        }

        // try to create routing path and verify it fails again and that new query is started
        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never().unwrap(), Some(remote.clone()));

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Pending { num_retries, .. } => assert_eq!(num_retries, 2),
            _ => panic!("invalid status"),
        }

        // register query failure
        manager.register_leases(&remote, Err(QueryError::Timeout));
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_err());

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Inactive { num_retries } => assert_eq!(num_retries, 2),
            _ => panic!("invalid status"),
        }

        // try to create routing path and verify it fails again and that new query is started
        assert!(handle.make_routing_path().is_none());
        assert_eq!(manager.next().now_or_never().unwrap(), Some(remote.clone()));

        match handle.lease_set_query_status {
            LeaseSetQueryStatus::Pending { num_retries, .. } => assert_eq!(num_retries, 3),
            _ => panic!("invalid status"),
        }

        // register final query failure
        manager.register_leases(&remote, Err(QueryError::Timeout));
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut handle).await.is_ok());
    }
}
