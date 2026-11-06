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
    crypto::base64_encode,
    error::{DialError, QueryError},
    events::EventHandle,
    netdb::NetDbHandle,
    primitives::{Date, Mapping, RouterAddress, RouterId, RouterInfo, Str, TransportKind},
    router::context::RouterContext,
    runtime::{Counter, Gauge, JoinSet, MetricType, MetricsHandle, Runtime},
    subsystem::{
        bandwidth::{Congestion, CongestionLevel},
        SubsystemEvent,
    },
    transport::{metrics::*, ntcp2::Ntcp2Context, ssu2::Ssu2Context},
    Ntcp2Config, Ssu2Config,
};

use bytes::Bytes;
use futures::{FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{errors::TrySendError, Receiver, Sender};

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod metrics;
mod ntcp2;
mod ssu2;
mod types;

pub use ntcp2::Ntcp2Transport;
pub use ssu2::Ssu2Transport;
pub use types::*;

#[cfg(feature = "fuzz")]
pub use {
    ntcp2::MessageBlock,
    ssu2::{Block, HeaderReader},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::transport-manager";

/// Local [`RouterInfo`] republish interval.
///
/// Local router info gets republished to `NetDb` every 15 minutes.
const ROUTER_INFO_REPUBLISH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Introducer expiration.
const INTRODUCER_EXPIRATION: Duration = Duration::from_secs(80 * 60);

/// Builder for [`TransportManager`].
pub struct TransportManagerBuilder<R: Runtime> {
    /// Allow local addresses.
    allow_local: bool,

    /// Router capability override.
    caps: Option<Str>,

    /// Router congestion.
    congestion: Congestion,

    /// RX channel for receiving dial requests.
    dial_rx: Receiver<RouterId>,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Handle to [`NetDb`].
    netdb_handle: Option<NetDbHandle>,

    /// NTCP2 config.
    ntcp2_config: Option<Ntcp2Config>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// SSU2 config.
    ssu2_config: Option<Ssu2Config>,

    /// Supported transports.
    supported_transports: HashSet<TransportKind>,

    /// Are transit tunnels disabled.
    transit_tunnels_disabled: bool,

    /// TX channel given to connections which they use to send inbound
    /// messages to `SubsystemManager` for processing.
    transport_tx: Sender<SubsystemEvent>,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,
}

impl<R: Runtime> TransportManagerBuilder<R> {
    /// Create new [`TransportManagerBuilder`].
    pub fn new(
        router_ctx: RouterContext<R>,
        local_router_info: RouterInfo,
        allow_local: bool,
        dial_rx: Receiver<RouterId>,
        transport_tx: Sender<SubsystemEvent>,
        congestion: Congestion,
    ) -> Self {
        Self {
            allow_local,
            caps: None,
            congestion,
            dial_rx,
            local_router_info,
            netdb_handle: None,
            ntcp2_config: None,
            router_ctx,
            ssu2_config: None,
            supported_transports: HashSet::new(),
            transit_tunnels_disabled: false,
            transports: Vec::with_capacity(2),
            transport_tx,
        }
    }

    /// Register NTCP2 as an active transport.
    pub fn register_ntcp2(&mut self, context: Ntcp2Context<R>) {
        self.supported_transports.extend(context.classify());
        self.ntcp2_config = Some(context.config());
        self.transports.push(Box::new(Ntcp2Transport::new(
            context,
            self.allow_local,
            self.router_ctx.clone(),
            self.transport_tx.clone(),
        )))
    }

    /// Register SSU2 as an active transport.
    pub fn register_ssu2(&mut self, context: Ssu2Context<R>) {
        self.supported_transports.extend(context.classify());
        self.ssu2_config = Some(context.config());
        self.transports.push(Box::new(Ssu2Transport::new(
            context,
            self.allow_local,
            self.router_ctx.clone(),
            self.transport_tx.clone(),
        )))
    }

    /// Register [`NetDbHandle`].
    pub fn register_netdb_handle(&mut self, netdb_handle: NetDbHandle) {
        self.netdb_handle = Some(netdb_handle);
    }

    /// Specify whether transit tunnels are disabled or not.
    pub fn with_transit_tunnels_disabled(&mut self, transit_tunnels_disabled: bool) -> &mut Self {
        self.transit_tunnels_disabled = transit_tunnels_disabled;
        self
    }

    /// Specify router capability override.
    pub fn with_capabilities(&mut self, caps: String) -> &mut Self {
        self.caps = Some(Str::from(caps));
        self
    }

    /// Build into [`TransportManager`].
    pub fn build(self) -> TransportManager<R> {
        TransportManager {
            caps: self.caps,
            congestion: self.congestion,
            dial_rx: self.dial_rx,
            event_handle: self.router_ctx.event_handle().clone(),
            ipv4_info: TransportInfo::default(),
            ipv6_info: TransportInfo::default(),
            local_router_info: self.local_router_info,
            netdb_handle: self.netdb_handle.expect("to exist"),
            ntcp2_config: self.ntcp2_config,
            pending_connections: HashMap::new(),
            pending_introducers: HashMap::new(),
            pending_queries: HashSet::new(),
            pending_query_futures: R::join_set(),
            poll_index: 0usize,
            router_ctx: self.router_ctx,
            // publish the router info 10 seconds after booting, otherwise republish it periodically
            // in intervals of `ROUTER_INFO_REPUBLISH_INTERVAL`
            router_info_republish_timer: R::timer(Duration::from_secs(10)),
            routers: HashMap::new(),
            ssu2_config: self.ssu2_config,
            supported_transports: self.supported_transports,
            transit_tunnels_disabled: self.transit_tunnels_disabled,
            transports: self.transports,
            terminated_transports: HashSet::new(),
            transport_tx: self.transport_tx.clone(),
        }
    }
}

/// Object representing the state of a pending connection that requires relay.
///
/// Each unreachable SSU2 connection that requires and has published introducers has an
/// `IntroducerConnection` which tracks the connection state while it's pending. If an introducer
/// for the router is already connected, the router is dialed immediately, without creating context.
///
/// `IntroducerConnection` tracks the overall state of all intrducers and it is destroyed when:
///
/// a) connection was established the one of the introducers, allowing the router to be dialed
/// b) local router failed to dial all of the introducers, making it impossible to ial the router
struct IntroducerConnection {
    /// `RouterInfo` of the router that needs relay.
    router_info: RouterInfo,

    /// Pending connections to introducers.
    ///
    /// All introducers are dialed in parallel and whichever of the connections succeeds
    /// first is selected as the relay.
    ///
    /// If all connections fail, the router cannot be dialed and a dial failure is reported.
    pending_connections: HashSet<RouterId>,

    /// Pending router info queries.
    ///
    /// If an introducer's router info is not known, it must queried from NetDb.
    ///
    /// If all introducer router info queries fail, dialing the router fails.
    pending_queries: HashSet<RouterId>,
}

/// Transport information for IPv4/IPv6.
struct TransportInfo<T> {
    /// External address, if known.
    external_address: Option<T>,

    /// Firewall status.
    firewall_status: FirewallStatus,

    /// Introducers.
    ///
    /// Linear scans are OK since there are only 1-3 introducers.
    introducers: Vec<(RouterId, u32, Duration)>,
}

impl<T> Default for TransportInfo<T> {
    fn default() -> Self {
        Self {
            external_address: None,
            firewall_status: FirewallStatus::Unknown,
            introducers: Vec::new(),
        }
    }
}

/// Transport manager.
///
/// Transport manager is responsible for connecting the higher-level subsystems
/// together with enabled, lower-level transports and polling for polling those
/// transports so that they can make progress.
pub struct TransportManager<R: Runtime> {
    /// Router capability override.
    caps: Option<Str>,

    /// Router congestion.
    congestion: Congestion,

    /// RX channel for receiving dial requests.
    dial_rx: Receiver<RouterId>,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// IPv4 transport info.
    ipv4_info: TransportInfo<Ipv4Addr>,

    /// IPv6 transport info.
    ipv6_info: TransportInfo<Ipv6Addr>,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// NTCP2 config.
    ntcp2_config: Option<Ntcp2Config>,

    /// Pending outbound connections.
    pending_connections: HashMap<RouterId, Vec<RouterId>>,

    /// Pending introducer connections.
    ///
    /// Indexed by the ID of the router that needs relay.
    pending_introducers: HashMap<RouterId, IntroducerConnection>,

    /// Pending queries.
    pending_queries: HashSet<RouterId>,

    /// Pending router info queries.
    pending_query_futures: R::JoinSet<(RouterId, Result<(), QueryError>)>,

    /// Poll index for transports.
    poll_index: usize,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Router info republish timer.
    router_info_republish_timer: R::Timer,

    /// Connected routers.
    ///
    /// The value indicates if the router is connected over IPv4.
    routers: HashMap<RouterId, bool>,

    /// SSU2 config.
    ssu2_config: Option<Ssu2Config>,

    /// Supported transports.
    supported_transports: HashSet<TransportKind>,

    /// Are transit tunnels disabled.
    transit_tunnels_disabled: bool,

    /// TX channel for sending transport-related events to `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,

    /// Indices in `transports` whose stream has terminated. Skipped by the poll loop; the
    /// manager keeps running as long as at least one transport is alive.
    terminated_transports: HashSet<usize>,
}

impl<R: Runtime> TransportManager<R> {
    /// Collect `TransportManager`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        let metrics = register_metrics(metrics);
        let metrics = Ntcp2Transport::<R>::metrics(metrics);

        Ssu2Transport::<R>::metrics(metrics)
    }

    /// Update local router's external addresses to `address`, if published.
    fn update_router_addresses(&mut self, address: IpAddr) {
        match &self.ntcp2_config {
            Some(Ntcp2Config {
                port,
                ipv4,
                ipv4_host,
                ipv6,
                ipv6_host,
                publish_ipv4,
                publish_ipv6,
                iv,
                ..
            }) => match address {
                // discovered address was ipv4, check if ntcp2 can be modified
                IpAddr::V4(host) => match (ipv4, ipv4_host, publish_ipv4) {
                    // ipv4 enabled and user didn't specify an external address for the router
                    (true, None, true) =>
                        if let Some(ntcp2) = self.local_router_info.ntcp2_ipv4_mut() {
                            tracing::trace!(
                                target: LOG_TARGET,
                                address = ?SocketAddr::new(address, *port),
                                "creating published ntcp2 ipv4 address",
                            );
                            ntcp2.into_reachable_ntcp2(*iv, *port, IpAddr::V4(host));
                        },

                    // ipv4 disabled for ntcp2, might be enabled for ssu2
                    (false, _, _) => tracing::trace!(
                        target: LOG_TARGET,
                        ?address,
                        "not updating external address for ntcp2, ipv4 disabled",
                    ),

                    // discovered address matches the address specified by the user
                    (true, Some(specified), _) if *specified == IpAddr::V4(host) => {}

                    // discovered address doesn't match the address specified by the user
                    //
                    // log a warning so the user may fix the address but don't update the address
                    (true, Some(specified), _) => tracing::warn!(
                        target: LOG_TARGET,
                        ?specified,
                        ?host,
                        "specified external address doesn't match discovered external address",
                    ),

                    // ntcp2 ipv4 is not published
                    (true, None, false) => tracing::trace!(
                        target: LOG_TARGET,
                        "ntcp2 ipv4 not published, router address not updated",
                    ),
                },
                IpAddr::V6(host) => match (ipv6, ipv6_host, publish_ipv6) {
                    // ipv6 enabled and user didn't specify an external address for the router
                    //
                    // update the host in `RouterAddress`
                    (true, None, true) =>
                        if let Some(ntcp2) = self.local_router_info.ntcp2_ipv6_mut() {
                            tracing::trace!(
                                target: LOG_TARGET,
                                address = ?SocketAddr::new(address, *port),
                                "creating published ntcp2 ipv6 address",
                            );
                            ntcp2.into_reachable_ntcp2(*iv, *port, IpAddr::V6(host));
                        },

                    // ipv6 disabled for ntcp2, might be enabled for ssu2
                    (false, _, _) => tracing::trace!(
                        target: LOG_TARGET,
                        ?address,
                        "not updating external address for ntcp2, ipv6 disabled",
                    ),

                    // discovered address matches the address specified by the user
                    (true, Some(specified), _) if *specified == IpAddr::V6(host) => {}

                    // discovered address doesn't match the address specified by the user
                    //
                    // log a warning so the user may fix the address but don't update the address
                    (true, Some(specified), _) => tracing::warn!(
                        target: LOG_TARGET,
                        ?specified,
                        ?host,
                        "specified external address doesn't match discovered external address",
                    ),

                    // ntcp2 ipv6 is not published
                    (true, None, false) => tracing::trace!(
                        target: LOG_TARGET,
                        "ntcp2 ipv6 not published, router address not updated",
                    ),
                },
            },
            _ => {}
        }

        match &self.ssu2_config {
            Some(Ssu2Config {
                port,
                ipv4,
                ipv4_host,
                ipv6,
                ipv6_host,
                publish_ipv4,
                publish_ipv6,
                ..
            }) => match address {
                // discovered address was ipv4, check if ssu2 can be modified
                IpAddr::V4(host) => match (ipv4, ipv4_host, publish_ipv4) {
                    // ipv4 enabled and user didn't specify an external address for the router
                    (true, None, true) =>
                        if let Some(ssu2) = self.local_router_info.ssu2_ipv4_mut() {
                            tracing::trace!(
                                target: LOG_TARGET,
                                address = ?SocketAddr::new(address, *port),
                                "creating published ssu2 ipv4 address",
                            );
                            ssu2.into_reachable_ssu2(*port, IpAddr::V4(host));
                        },

                    // ipv4 disabled for ssu2, might be enabled for ssu2
                    (false, _, _) => tracing::trace!(
                        target: LOG_TARGET,
                        ?address,
                        "not updating external address for ssu2, ipv4 disabled",
                    ),

                    // discovered address matches the address specified by the user
                    (true, Some(specified), _) if *specified == IpAddr::V4(host) => {}

                    // discovered address doesn't match the address specified by the user
                    //
                    // log a warning so the user may fix the address but don't update the address
                    (true, Some(specified), _) => tracing::warn!(
                        target: LOG_TARGET,
                        ?specified,
                        ?host,
                        "specified external address doesn't match discovered external address",
                    ),

                    // ssu2 ipv4 is not published
                    (true, None, false) => tracing::trace!(
                        target: LOG_TARGET,
                        "ssu2 ipv4 not published, router address not updated",
                    ),
                },
                IpAddr::V6(host) => match (ipv6, ipv6_host, publish_ipv6) {
                    // ipv6 enabled and user didn't specify an external address for the router
                    //
                    // update the host in `RouterAddress`
                    (true, None, true) =>
                        if let Some(ssu2) = self.local_router_info.ssu2_ipv6_mut() {
                            tracing::trace!(
                                target: LOG_TARGET,
                                address = ?SocketAddr::new(address, *port),
                                "creating published ssu2 ipv6 address",
                            );
                            ssu2.into_reachable_ssu2(*port, IpAddr::V6(host));
                        },

                    // ipv6 disabled for ssu2, might be enabled for ssu2
                    (false, _, _) => tracing::trace!(
                        target: LOG_TARGET,
                        ?address,
                        "not updating external address for ssu2, ipv6 disabled",
                    ),

                    // discovered address matches the address specified by the user
                    (true, Some(specified), _) if *specified == IpAddr::V6(host) => {}

                    // discovered address doesn't match the address specified by the user
                    //
                    // log a warning so the user may fix the address but don't update the address
                    (true, Some(specified), _) => tracing::warn!(
                        target: LOG_TARGET,
                        ?specified,
                        ?host,
                        "specified external address doesn't match discovered external address",
                    ),

                    // ssu2 ipv6 is not published
                    (true, None, false) => tracing::trace!(
                        target: LOG_TARGET,
                        "ssu2 ipv6 not published, router address not updated",
                    ),
                },
            },
            _ => tracing::trace!(
                target: LOG_TARGET,
                "ssu2 not active or unpublished, router address not updated",
            ),
        }
    }

    /// Add port-mapped, external address for the router.
    ///
    /// The address/port pair has been mapped either by NAT-PMP/UPnP and the router can consider
    /// itself to be unfirewalled over that address.
    pub fn add_port_mapped_address(&mut self, address: IpAddr) {
        match address {
            IpAddr::V4(_) => {
                self.ipv4_info.firewall_status = FirewallStatus::Ok;
            }
            IpAddr::V6(_) => {
                self.ipv6_info.firewall_status = FirewallStatus::Ok;
            }
        }

        self.add_external_address(address);
    }

    /// Add external address for the router.
    fn add_external_address(&mut self, address: IpAddr) {
        tracing::trace!(
            target: LOG_TARGET,
            ?address,
            "external address discovered",
        );

        let previous_address = match address {
            IpAddr::V4(address) => (self.ipv4_info.external_address != Some(address)).then(|| {
                let previous = self.ipv4_info.external_address;

                self.ipv4_info.external_address = Some(address);

                match self.ipv4_info.firewall_status {
                    FirewallStatus::Ok => self.update_router_addresses(IpAddr::V4(address)),
                    status => tracing::debug!(
                        target: LOG_TARGET,
                        ?status,
                        "incompatible firewall status, unable to update router ipv4 address",
                    ),
                }

                previous.map(IpAddr::V4)
            }),
            IpAddr::V6(address) => (self.ipv6_info.external_address != Some(address)).then(|| {
                let previous = self.ipv6_info.external_address;

                self.ipv6_info.external_address = Some(address);

                match self.ipv6_info.firewall_status {
                    FirewallStatus::Ok => self.update_router_addresses(IpAddr::V6(address)),
                    status => tracing::debug!(
                        target: LOG_TARGET,
                        ?status,
                        "incompatible firewall status, unable to update router ipv6 address",
                    ),
                }

                previous.map(IpAddr::V6)
            }),
        };

        if let Some(previous) = previous_address {
            tracing::info!(
                target: LOG_TARGET,
                old_address = ?previous,
                ?address,
                "external address discovered",
            );
        }
    }

    /// Report dial failure to `SubsystemManager`.
    ///
    /// Attempts to send the event in a non-blocking way and if the channel is clogged, informs
    /// `SubsystemManager` in the background.
    fn report_dial_failure(&self, router_id: RouterId) {
        match self.transport_tx.try_send(SubsystemEvent::ConnectionFailure { router_id }) {
            Ok(()) => {}
            Err(TrySendError::Full(event)) => {
                let transport_tx = self.transport_tx.clone();

                R::spawn(async move {
                    let _ = transport_tx.send(event).await;
                });
            }
            Err(error) => tracing::error!(
                target: LOG_TARGET,
                ?error,
                "failed to inform subsystem manager of a closed connection",
            ),
        }
    }

    /// Send `RouterInfo` query to NetDb for `router_id`.
    ///
    /// `clients` contain the list routers that are interested in the result of the query.
    fn send_router_info_query(&mut self, router_id: RouterId, clients: Vec<RouterId>) {
        match self.netdb_handle.try_query_router_info(router_id.clone()) {
            Err(error) => tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                ?error,
                "failed to send router info query",
            ),
            Ok(rx) => {
                self.pending_connections.insert(router_id.clone(), clients);
                self.pending_queries.insert(router_id.clone());
                self.pending_query_futures.push(async move {
                    match rx.await {
                        // `Err(_)` indicates that `NetDb` didn't finish the query and
                        // instead dropped the channel which shouldn't happen unless there
                        // is a bug in router info query logic
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                ?error,
                                "netdb didn't properly finish the router info lookup",
                            );

                            (router_id, Err(QueryError::Timeout))
                        }
                        Ok(Err(error)) => (router_id, Err(error)),
                        Ok(Ok(lease_set)) => (router_id, Ok(lease_set)),
                    }
                });
            }
        }
    }

    /// Attempt to dial `router_id`.
    ///
    /// If `router_id` is not found in local storage, send [`RouterInfo`] query for `router_id` to
    /// [`NetDb`] and if the [`RouterInfo`] is found, attempt to dial it.
    ///
    /// `clients` are IDs of the routers that are interested in knowing about the result of this
    /// connection attempt.
    fn on_dial_router(&mut self, router_id: RouterId, clients: Vec<RouterId>) {
        if &router_id == self.router_ctx.router_id() {
            tracing::error!(target: LOG_TARGET, "tried to dial self");
            debug_assert!(false);
            return;
        }

        // `SubsystemManager` might send an outbound connection request just before an inbound
        // connection has been accepted by the `TransportManager`
        //
        // ignore these requests
        if self.routers.contains_key(&router_id) {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router is already connected, ignoring dial request",
            );
            return;
        }

        match self.router_ctx.profile_storage().get(&router_id) {
            Some(router_info) => {
                // even though `TransportService` prevents dialing the same router from the same
                // subsystem twice, the notion of a "pending router", i.e., it being dialed, is not
                // shared between the subsystems
                //
                // this means that it's possible for `TransportManager` to receive two dial requests
                // for the same router, with the second request arriving while the first one is
                // still pending
                //
                // ensure that the router is not being dialed before dialing them
                if self.pending_connections.contains_key(&router_id) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "router is already being dialed",
                    );
                    return;
                }

                let Some(transport) = router_info.select_transport(&self.supported_transports)
                else {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        caps = %router_info.capabilities,
                        "cannot dial router, no compatible transport",
                    );

                    self.router_ctx
                        .metrics_handle()
                        .counter(NUM_DIAL_FAILURES)
                        .increment_with_label(1, "reason", "no-address");
                    return self.report_dial_failure(router_id);
                };

                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    %transport,
                    "start dialing router",
                );

                // if not ssu2, dial the router over ntcp2
                let RouterAddress::Ssu2 {
                    introducers,
                    socket_address,
                    ..
                } = transport
                else {
                    self.router_ctx.metrics_handle().counter(NUM_INITIATED).increment(1);
                    self.pending_connections.insert(router_id.clone(), clients);
                    self.transports[0].connect(router_info);
                    return;
                };

                // ssu2 is always the last transport
                //
                // if only ssu2 is active, index is 0
                // if both ntcp2 and ssu2 are active, index is 1
                let ssu2_index = self.transports.len() - 1;

                // if a socket address has been published, dial the router directly
                if socket_address.is_some() {
                    self.router_ctx.metrics_handle().counter(NUM_INITIATED).increment(1);
                    self.pending_connections.insert(router_id.clone(), clients);
                    self.transports[ssu2_index].connect(router_info);
                    return;
                }

                // if we're connected to one of the introducers, we can dial right away
                if let Some((introducer, relay_tag)) =
                    introducers.iter().find(|(router_id, _)| self.routers.contains_key(router_id))
                {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        %introducer,
                        ?relay_tag,
                        "already connected to an introducer, starting relayed connection",
                    );

                    self.router_ctx.metrics_handle().counter(NUM_INITIATED).increment(1);
                    self.pending_connections.insert(router_id.clone(), clients);
                    self.transports[ssu2_index].connect(router_info);
                    return;
                }

                // start dialing introducers in parallel
                let mut pending_connections = HashSet::new();
                let mut pending_queries = HashSet::new();

                for (introducer, relay_tag) in introducers {
                    // check if a connection to one of the introducers is already pending
                    //
                    // if so, store `router_id` into the pending context and when the dial
                    // resolves, either report dial failure (cannot connect to introducer) or
                    // start "dialing" the target router by contacting the introducer
                    if self.pending_connections.contains_key(introducer) {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            %introducer,
                            ?relay_tag,
                            "connection to introducer pending",
                        );

                        // entry must exist since it was just checked above
                        self.pending_connections
                            .get_mut(introducer)
                            .expect("to exist")
                            .push(router_id.clone());
                        pending_connections.insert(introducer.clone());

                        continue;
                    }

                    // check if the introducer's router info is available and if so, start dialing
                    {
                        let reader = self.router_ctx.profile_storage().reader();
                        match reader.router_info(introducer) {
                            None => {
                                // introducer router info not found, start nedb query
                            }
                            Some(introducer_router_info) => {
                                if !introducer_router_info.is_reachable_ssu2() {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %router_id,
                                        %introducer,
                                        ?relay_tag,
                                        "introducer is not reachable over ssu2",
                                    );
                                    continue;
                                }

                                // ensure we support the same transports as the introducer
                                if introducer_router_info
                                    .select_transport_with_filter(|address| match address {
                                        RouterAddress::Ntcp2 { .. } => false,
                                        address @ RouterAddress::Ssu2 { socket_address, .. } =>
                                            address.classify().is_some_and(|address| {
                                                self.supported_transports.contains(&address)
                                                    && socket_address.is_some()
                                            }),
                                    })
                                    .is_none()
                                {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %introducer,
                                        supported = ?self.supported_transports,
                                        "no compatible transport found for introducer",
                                    );
                                    continue;
                                }

                                tracing::trace!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    %introducer,
                                    ?relay_tag,
                                    "dialing introducer",
                                );

                                // dial introducer directly
                                //
                                // at this point it has already been verified that there is neither
                                // active or pending connection to the
                                // introducer and that they're reachable over
                                // ssu2
                                pending_connections.insert(introducer.clone());
                                self.router_ctx
                                    .metrics_handle()
                                    .counter(NUM_INITIATED)
                                    .increment(1);
                                self.pending_connections
                                    .insert(introducer.clone(), vec![router_id.clone()]);
                                self.transports[ssu2_index].connect(introducer_router_info.clone());

                                continue;
                            }
                        }
                    }

                    // the introducer is not connected, doens't have a pending connection and
                    // doesn't exist in router storage
                    //
                    // start a netdb lookup for their router info
                    if self.pending_queries.contains(introducer) {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            %introducer,
                            ?relay_tag,
                            "router info query pending for introducer",
                        );

                        pending_queries.insert(introducer.clone());
                    } else {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            %introducer,
                            ?relay_tag,
                            "start router info query for introducer",
                        );

                        pending_queries.insert(introducer.clone());
                        self.send_router_info_query(introducer.clone(), vec![router_id.clone()]);
                    }
                }

                if pending_connections.is_empty() && pending_queries.is_empty() {
                    tracing::debug!(
                        target: LOG_TARGET,
                        "unable to dial router, failed to dial and/or query all introducers",
                    );
                    return self.report_dial_failure(router_id);
                }

                self.pending_connections.insert(router_id.clone(), clients);
                self.pending_introducers.insert(
                    router_id.clone(),
                    IntroducerConnection {
                        router_info,
                        pending_connections,
                        pending_queries,
                    },
                );
            }
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "router info not found, send router info query to netdb",
                );

                if self.pending_queries.contains(&router_id) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "router info is already being queried",
                    );
                    return;
                }

                self.send_router_info_query(router_id, Vec::new());
            }
        }
    }

    /// Handle firewall status update received from SSU2.
    fn on_firewall_status(&mut self, status: FirewallStatus, ipv4: bool) {
        tracing::debug!(
            target: LOG_TARGET,
            ?status,
            ?ipv4,
            "firewall status update",
        );

        if ipv4 {
            self.ipv4_info.firewall_status = status;
            self.event_handle.set_ipv4_status(status);

            // the external address may have been discovered while the firewall status was still
            // unknown, in which case it was never published; publish it now that the router is
            // known to be reachable
            if status == FirewallStatus::Ok {
                if let Some(address) = self.ipv4_info.external_address {
                    self.update_router_addresses(IpAddr::V4(address));
                }
            }
        } else {
            self.ipv6_info.firewall_status = status;
            self.event_handle.set_ipv6_status(status);

            if status == FirewallStatus::Ok {
                if let Some(address) = self.ipv6_info.external_address {
                    self.update_router_addresses(IpAddr::V6(address));
                }
            }
        }
    }

    /// Handle new introducer.
    fn on_introducer_added(
        &mut self,
        router_id: RouterId,
        relay_tag: u32,
        expires: Duration,
        ipv4: bool,
    ) {
        tracing::debug!(
            target: LOG_TARGET,
            %router_id,
            ?relay_tag,
            ?expires,
            ?ipv4,
            "add new introducer",
        );

        if ipv4 {
            self.ipv4_info.introducers.push((router_id, relay_tag, expires));
        } else {
            self.ipv6_info.introducers.push((router_id, relay_tag, expires));
        }
    }

    /// Handle removed introducer.
    fn on_introducer_removed(&mut self, router_id: &RouterId, ipv4: bool) {
        tracing::debug!(
            target: LOG_TARGET,
            %router_id,
            ?ipv4,
            "remove introducer",
        );

        if ipv4 {
            self.ipv4_info.introducers.retain(|(r, _, _)| r != router_id);
        } else {
            self.ipv6_info.introducers.retain(|(r, _, _)| r != router_id);
        }
    }

    /// Attempt to publish our router info.
    fn publish_router_info(&mut self) {
        // current router capabilties
        let mut caps = Str::from(self.congestion.bandwidth());

        // reset publish time and serialize our new router info
        self.local_router_info.published = Date::new(R::time_since_epoch().as_millis() as u64);

        // publish `G`, i.e., rejecting all tunnels, if transit tunnels have been disabled
        if self.transit_tunnels_disabled {
            tracing::info!(
                target: LOG_TARGET,
                "transit tunnels disabled, publishing G",
            );

            caps += "G";
        }

        let update_introducers =
            |options: &mut Mapping, introducers: &[(RouterId, u32, Duration)]| {
                // remove old introducers
                for i in 0..3 {
                    options.remove(&Str::from(format!("iexp{i}")));
                    options.remove(&Str::from(format!("ih{i}")));
                    options.remove(&Str::from(format!("itag{i}")));
                }

                // add introducers to our router info, skipping any expired introducers
                let now = R::time_since_epoch();

                for (i, (router_id, relay_tag, expires)) in introducers.iter().enumerate() {
                    if expires > &(now + INTRODUCER_EXPIRATION) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?relay_tag,
                            expired = ?(*expires - now - INTRODUCER_EXPIRATION),
                            "skipping expired introducer"
                        );
                        continue;
                    }

                    options.insert(
                        Str::from(format!("iexp{i}")),
                        Str::from(expires.as_secs().to_string()),
                    );
                    options.insert(
                        Str::from(format!("ih{i}")),
                        Str::from(base64_encode(router_id.to_vec())),
                    );
                    options.insert(
                        Str::from(format!("itag{i}")),
                        Str::from(relay_tag.to_string()),
                    );
                }
            };

        // update ssu2's ipv4 address if we have any active introducers
        if let Some(RouterAddress::Ssu2 { options, .. }) = self.local_router_info.ssu2_ipv4_mut() {
            update_introducers(options, &self.ipv4_info.introducers);
        }

        // update ssu2's ipv6 address if we have any active introducers
        if let Some(RouterAddress::Ssu2 { options, .. }) = self.local_router_info.ssu2_ipv6_mut() {
            update_introducers(options, &self.ipv6_info.introducers);
        }

        match (
            self.ipv4_info.firewall_status,
            self.ipv6_info.firewall_status,
        ) {
            (FirewallStatus::Ok, _) => {
                tracing::info!(
                    target: LOG_TARGET,
                    "router is not firewalled over ipv4, publishing R",
                );
                caps += "R";
            }
            (_, FirewallStatus::Ok) => {
                tracing::info!(
                    target: LOG_TARGET,
                    "router is not firewalled over ipv6, publishing R",
                );
                caps += "R";
            }
            (FirewallStatus::Unknown, FirewallStatus::Unknown) => tracing::info!(
                target: LOG_TARGET,
                "firewall status unknown, not publishing reachability caps",
            ),
            (ipv4_status, ipv6_status) => {
                tracing::info!(
                    target: LOG_TARGET,
                    ?ipv4_status,
                    ?ipv6_status,
                    "router is firewalled, publishing U",
                );
                caps += "U";
            }
        }

        // update congestion caps
        match self.congestion.load() {
            CongestionLevel::Medium => {
                tracing::info!(LOG_TARGET, "medium congestion, publishing D");
                caps += "D";
            }
            CongestionLevel::High => {
                tracing::info!(LOG_TARGET, "high congestion, publishing E");
                caps += "E";
            }
            CongestionLevel::Low => {}
        }

        // use user-provided caps if they exist, otherwise use the derived acps
        let caps = self.caps.as_ref().map_or(caps, |caps| caps.clone());

        tracing::info!(
            target: LOG_TARGET,
            %caps,
            "publish local router info",
        );

        self.local_router_info.options.insert(Str::from("caps"), caps);

        let serialized =
            Bytes::from(self.local_router_info.serialize(self.router_ctx.signing_key()));

        // reset router info in router context so all subsystems are using the latest version of
        // it and publish it to netdb
        self.router_ctx.set_router_info(serialized.clone());
        self.netdb_handle
            .publish_router_info(self.router_ctx.router_id().clone(), serialized);
    }
}

impl<R: Runtime> Future for TransportManager<R> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::into_inner(self);
        let len = this.transports.len();

        if len > 0 && this.terminated_transports.len() >= len {
            return Poll::Ready(());
        }

        let start_index = this.poll_index;

        loop {
            let index = this.poll_index % len;
            this.poll_index += 1;

            if this.terminated_transports.contains(&index) {
                if this.poll_index == start_index + len {
                    break;
                }
                continue;
            }

            loop {
                match this.transports[index].poll_next_unpin(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) => {
                        tracing::error!(
                            target: LOG_TARGET,
                            %index,
                            total_transports = len,
                            "transport stream ended",
                        );
                        this.terminated_transports.insert(index);
                        if this.terminated_transports.len() >= len {
                            tracing::error!(
                                target: LOG_TARGET,
                                "all transports terminated, shutting down transport manager",
                            );
                            return Poll::Ready(());
                        }
                        break;
                    }
                    Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        address,
                        direction,
                        router_id,
                        encryption,
                    })) => match direction {
                        Direction::Inbound if this.pending_connections.contains_key(&router_id) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                "outbound connection pending, rejecting inbound connection",
                            );

                            this.router_ctx.metrics_handle().counter(NUM_REJECTED).increment(1);
                            this.transports[index].reject(&router_id);
                        }
                        Direction::Outbound
                            if !this.pending_connections.contains_key(&router_id) =>
                        {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                "pending connection doesn't exist for router, rejecting connection",
                            );

                            this.router_ctx.metrics_handle().counter(NUM_REJECTED).increment(1);
                            this.transports[index].reject(&router_id);
                        }
                        direction => {
                            if this.routers.contains_key(&router_id) {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    "router already connected, rejecting",
                                );

                                this.router_ctx.metrics_handle().counter(NUM_REJECTED).increment(1);
                                this.transports[index].reject(&router_id);
                                continue;
                            }

                            tracing::trace!(
                                target: LOG_TARGET,
                                %router_id,
                                ?direction,
                                %encryption,
                                "connection established",
                            );

                            this.transports[index].accept(&router_id);
                            this.routers.insert(router_id.clone(), address.is_ipv4());

                            // if this was a successful connection to an introducer with
                            // active client(s), start
                            // dialing each of the clients
                            //
                            // the routers can be dialed directly (without calling
                            // `on_dial_request()`) as they've already been validated and
                            // were only awaiting for an
                            // introducer connection
                            //
                            // `IntroducerConnection` may not exist if some other introducer
                            // connected first and thus removed the connection
                            if let Some(routers) = this.pending_connections.remove(&router_id) {
                                let ssu2_index = this.transports.len() - 1;

                                for client_router_id in routers {
                                    let Some(IntroducerConnection { router_info, .. }) =
                                        this.pending_introducers.remove(&client_router_id)
                                    else {
                                        tracing::trace!(
                                            target: LOG_TARGET,
                                            router_id = %client_router_id,
                                            introducer = %router_id,
                                            "context for client doesn't exist"
                                        );
                                        continue;
                                    };

                                    tracing::trace!(
                                        target: LOG_TARGET,
                                        router_id = %client_router_id,
                                        introducer = %router_id,
                                        "introducer connected, dialing router",
                                    );

                                    this.router_ctx
                                        .metrics_handle()
                                        .counter(NUM_INITIATED)
                                        .increment(1);
                                    this.transports[ssu2_index].connect(router_info);
                                }
                            }

                            this.router_ctx.profile_storage().dial_succeeded(&router_id);
                            this.router_ctx
                                .metrics_handle()
                                .gauge(NUM_ACTIVE_CONNECTIONS)
                                .increment(1);
                            this.router_ctx
                                .metrics_handle()
                                .counter(NUM_CONNECTIONS)
                                .increment_with_label(
                                    1,
                                    "kind",
                                    match (direction, encryption) {
                                        (Direction::Inbound, EncryptionKind::X25519) => "ib-x25519",
                                        (Direction::Inbound, EncryptionKind::MlKem512X25519) =>
                                            "ib-ml-kem-512",
                                        (Direction::Inbound, EncryptionKind::MlKem768X25519) =>
                                            "ib-ml-kem-768",
                                        (Direction::Inbound, EncryptionKind::MlKem1024X25519) =>
                                            "ib-ml-kem-1024",
                                        (Direction::Outbound, EncryptionKind::X25519) =>
                                            "ob-x25519",
                                        (Direction::Outbound, EncryptionKind::MlKem512X25519) =>
                                            "ob-ml-kem-512",
                                        (Direction::Outbound, EncryptionKind::MlKem768X25519) =>
                                            "ob-ml-kem-768",
                                        (Direction::Outbound, EncryptionKind::MlKem1024X25519) =>
                                            "ob-ml-kem-1024",
                                    },
                                );
                            this.router_ctx.metrics_handle().counter(NUM_ACCEPTED).increment(1);
                            this.router_ctx
                                .metrics_handle()
                                .counter(CONNECTIONS_OPENED)
                                .increment(1);
                            this.router_ctx
                                .metrics_handle()
                                .gauge(if address.is_ipv4() {
                                    NUM_IPV4
                                } else {
                                    NUM_IPV6
                                })
                                .increment(1);
                        }
                    },
                    Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id, reason })) => {
                        match reason {
                            TerminationReason::Banned => tracing::warn!(
                                target: LOG_TARGET,
                                %router_id,
                                ?reason,
                                "remote router banned us",
                            ),
                            TerminationReason::IdleTimeout => tracing::trace!(
                                target: LOG_TARGET,
                                %router_id,
                                ?reason,
                                "connection closed",
                            ),
                            reason => tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                ?reason,
                                "connection closed",
                            ),
                        }

                        match this.routers.remove(&router_id) {
                            None => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    "connection closed to unknown router",
                                );
                                debug_assert!(false);
                            }
                            Some(true) =>
                                this.router_ctx.metrics_handle().gauge(NUM_IPV4).decrement(1),
                            Some(false) =>
                                this.router_ctx.metrics_handle().gauge(NUM_IPV6).decrement(1),
                        }
                        this.router_ctx.profile_storage().connection_closed(&router_id);
                        this.router_ctx.metrics_handle().gauge(NUM_ACTIVE_CONNECTIONS).decrement(1);
                        this.router_ctx
                            .metrics_handle()
                            .counter(CONNECTIONS_CLOSED)
                            .increment_with_label(1, "reason", reason.into());
                    }
                    Poll::Ready(Some(TransportEvent::ConnectionFailure { router_id, reason })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            ?reason,
                            "failed to dial router",
                        );

                        this.router_ctx
                            .metrics_handle()
                            .counter(NUM_DIAL_FAILURES)
                            .increment_with_label(1, "reason", reason.into());
                        this.router_ctx.profile_storage().dial_failed(&router_id);

                        // if the router for which the dial failed was also a pending introducer,
                        // remove the introducer from each client's `IntroducerConnection` and
                        // if this was the last introducer (all others failed), send dial failure
                        // for the client router
                        if let Some(routers) = this.pending_connections.remove(&router_id) {
                            for client_router_id in routers {
                                let Some(IntroducerConnection {
                                    pending_connections,
                                    pending_queries,
                                    ..
                                }) = this.pending_introducers.get_mut(&client_router_id)
                                else {
                                    tracing::trace!(
                                        target: LOG_TARGET,
                                        router_id = %client_router_id,
                                        introducer = %router_id,
                                        "context for client doesn't exist"
                                    );
                                    continue;
                                };

                                tracing::trace!(
                                    target: LOG_TARGET,
                                    router_id = %client_router_id,
                                    introducer = %router_id,
                                    "failed to dial introducer",
                                );
                                pending_connections.remove(&router_id);

                                if pending_connections.is_empty() && pending_queries.is_empty() {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        router_id = %client_router_id,
                                        introducer = %router_id,
                                        "failed to dial all introducers, unable to dial router",
                                    );

                                    this.router_ctx
                                        .metrics_handle()
                                        .counter(NUM_DIAL_FAILURES)
                                        .increment_with_label(1, "reason", "no-introducers");
                                    this.router_ctx
                                        .metrics_handle()
                                        .counter(NUM_INTRODUCER_DIAL_FAILURES)
                                        .increment(1);
                                    this.pending_connections.remove(&client_router_id);
                                    this.pending_introducers.remove(&client_router_id);
                                    this.report_dial_failure(client_router_id);
                                }
                            }
                        }

                        // if `reason` is `RelayFailure`, it means that an outbound ssu2 session
                        // was never started for the router and dial failure must be reported
                        // manually to `SubsystemManager`
                        if let DialError::RelayFailure = reason {
                            this.report_dial_failure(router_id);
                        }
                    }
                    Poll::Ready(Some(TransportEvent::FirewallStatus { status, ipv4 })) => {
                        this.on_firewall_status(status, ipv4);
                    }
                    Poll::Ready(Some(TransportEvent::ExternalAddress { address })) => {
                        this.add_external_address(address.ip());
                    }
                    Poll::Ready(Some(TransportEvent::IntroducerAdded {
                        relay_tag,
                        router_id,
                        expires,
                        ipv4,
                    })) => this.on_introducer_added(router_id, relay_tag, expires, ipv4),
                    Poll::Ready(Some(TransportEvent::IntroducerRemoved { router_id, ipv4 })) =>
                        this.on_introducer_removed(&router_id, ipv4),
                }
            }

            if this.poll_index == start_index + len {
                break;
            }
        }

        loop {
            match this.pending_query_futures.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((router_id, Ok(())))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "router info query succeeded, dial pending router",
                    );
                    this.pending_queries.remove(&router_id);

                    let clients = match this.pending_connections.remove(&router_id) {
                        None => {
                            tracing::error!(
                                target: LOG_TARGET,
                                %router_id,
                                "router does not have dial context",
                            );
                            debug_assert!(false);
                            Vec::new()
                        }
                        Some(clients) => clients,
                    };

                    // remove pending query from all client connections
                    for client_router_id in &clients {
                        if let Some(IntroducerConnection {
                            pending_queries, ..
                        }) = this.pending_introducers.get_mut(client_router_id)
                        {
                            pending_queries.remove(&router_id);
                        };
                    }

                    this.router_ctx
                        .metrics_handle()
                        .counter(NUM_NETDB_QUERY_SUCCESSES)
                        .increment(1);

                    this.on_dial_router(router_id, clients);
                }
                Poll::Ready(Some((router_id, Err(error)))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "router info query failed",
                    );

                    this.router_ctx
                        .metrics_handle()
                        .counter(NUM_DIAL_FAILURES)
                        .increment_with_label(1, "reason", "ri-query-failed");
                    this.router_ctx.metrics_handle().counter(NUM_NETDB_QUERY_FAILURES).increment(1);
                    this.pending_queries.remove(&router_id);

                    // remove the pending query for the introducer from all client connections
                    //
                    // if this was the last pending query, report dial failures for the client
                    if let Some(routers) = this.pending_connections.remove(&router_id) {
                        for client_router_id in routers {
                            let Some(IntroducerConnection {
                                pending_connections,
                                pending_queries,
                                ..
                            }) = this.pending_introducers.get_mut(&client_router_id)
                            else {
                                tracing::trace!(
                                    target: LOG_TARGET,
                                    router_id = %client_router_id,
                                    introducer = %router_id,
                                    "context for client doesn't exist"
                                );
                                continue;
                            };

                            tracing::trace!(
                                target: LOG_TARGET,
                                router_id = %client_router_id,
                                introducer = %router_id,
                                "router info query failed for introducer",
                            );
                            pending_queries.remove(&router_id);

                            if pending_connections.is_empty() && pending_queries.is_empty() {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    router_id = %client_router_id,
                                    introducer = %router_id,
                                    "failed to dial all introducers, unable to dial router",
                                );

                                this.router_ctx
                                    .metrics_handle()
                                    .counter(NUM_DIAL_FAILURES)
                                    .increment_with_label(1, "reason", "no-introducers");
                                this.router_ctx
                                    .metrics_handle()
                                    .counter(NUM_INTRODUCER_DIAL_FAILURES)
                                    .increment(1);
                                this.pending_connections.remove(&client_router_id);
                                this.pending_introducers.remove(&client_router_id);
                                this.report_dial_failure(client_router_id);
                            }
                        }
                    }

                    this.report_dial_failure(router_id);
                }
            }
        }

        loop {
            match this.dial_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(router_id)) => this.on_dial_router(router_id, Vec::new()),
            }
        }

        if this.router_info_republish_timer.poll_unpin(cx).is_ready() {
            // reset timer and register it into the executor
            this.router_info_republish_timer = R::timer(ROUTER_INFO_REPUBLISH_INTERVAL);
            let _ = this.router_info_republish_timer.poll_unpin(cx);

            this.publish_router_info();
        }

        if this.event_handle.poll_unpin(cx).is_ready() {
            this.event_handle.num_connected_routers(this.routers.len());
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::DialError,
        events::EventManager,
        i2np::{Message, MessageType, I2NP_MESSAGE_EXPIRATION},
        netdb::{NetDbAction, NetDbActionRecycle},
        primitives::{Bandwidth, Capabilities, RouterInfoBuilder, Str},
        profile::ProfileStorage,
        router::context::builder::RouterContextBuilder,
        runtime::mock::MockRuntime,
        subsystem::OutboundMessage,
        timeout,
    };
    use futures::Stream;
    use std::collections::VecDeque;
    use thingbuf::mpsc::channel;
    use tokio::sync::mpsc;

    fn make_transport_manager(
        ntcp2: Option<Ntcp2Config>,
        ssu2: Option<Ssu2Config>,
    ) -> (
        TransportManagerBuilder<MockRuntime>,
        Sender<RouterId>,
        Receiver<SubsystemEvent>,
        Receiver<NetDbAction, NetDbActionRecycle>,
    ) {
        let (router_info, static_key, signing_key) = {
            let mut builder = RouterInfoBuilder::default();

            if let Some(ntcp2) = ntcp2 {
                builder = builder.with_ntcp2(ntcp2);
            }

            if let Some(ssu2) = ssu2 {
                builder = builder.with_ssu2(ssu2);
            }

            builder.build()
        };
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let (dial_tx, dial_rx) = channel(100);
        let (transport_tx, transport_rx) = channel(100);
        let (handle, netdb_rx) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&[], &[], None),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);

        (builder, dial_tx, transport_rx, netdb_rx)
    }

    #[tokio::test]
    async fn external_address_discovered_ntcp2_ipv4() {
        external_address_discovered_ntcp2(true).await
    }

    #[tokio::test]
    async fn external_address_discovered_ntcp2_ipv6() {
        external_address_discovered_ntcp2(false).await
    }

    async fn external_address_discovered_ntcp2(ipv4: bool) {
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            max_connections: None,
            port: 0,
            ipv4_host: ipv4.then_some("127.0.0.1".parse().unwrap()),
            ipv6_host: (!ipv4).then_some("::1".parse().unwrap()),
            ipv4,
            ipv6: !ipv4,
            publish_ipv4: true,
            publish_ipv6: true,
            ml_kem: None,
            disable_pq: false,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(Some(context.config()), None);
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        // ensure ntcp2 is published
        assert!(manager.ntcp2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                            && options.get(&Str::from("s")).is_some()
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                            && options.get(&Str::from("s")).is_some()
                    }
                }
                _ => false,
            })
        );

        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::1".parse().unwrap());
        }

        // verify that the address is still published and that host is the same
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                            && options.get(&Str::from("s")).is_some()
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                            && options.get(&Str::from("s")).is_some()
                    }
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn external_address_discovered_ntcp2_unpublished_ipv4() {
        external_address_discovered_ntcp2_unpublished(true).await;
    }

    #[tokio::test]
    async fn external_address_discovered_ntcp2_unpublished_ipv6() {
        external_address_discovered_ntcp2_unpublished(false).await;
    }

    async fn external_address_discovered_ntcp2_unpublished(ipv4: bool) {
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            max_connections: None,
            port: 0,
            ipv4_host: None,
            ipv6_host: None,
            ipv4,
            ipv6: !ipv4,
            ml_kem: None,
            disable_pq: false,
            publish_ipv4: false,
            publish_ipv6: false,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(Some(context.config()), None);
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        // ensure ntcp2 is unpublished
        assert!(manager.ntcp2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    options.get(&Str::from("host")).is_none()
                        && options.get(&Str::from("i")).is_none()
                }
                _ => false,
            })
        );

        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::1".parse().unwrap());
        }

        // verify that the address is still unpublished
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    options.get(&Str::from("host")).is_none()
                        && options.get(&Str::from("i")).is_none()
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn external_address_discovered_ssu2_ipv4() {
        external_address_discovered_ssu2(true).await;
    }

    #[tokio::test]
    async fn external_address_discovered_ssu2_ipv6() {
        external_address_discovered_ssu2(false).await;
    }

    async fn external_address_discovered_ssu2(ipv4: bool) {
        let ssu2 = Ssu2Config {
            max_connections: None,
            ml_kem: None,
            disable_pq: false,
            port: 0,
            ipv4_host: ipv4.then_some("127.0.0.1".parse().unwrap()),
            ipv6_host: (!ipv4).then_some("::1".parse().unwrap()),
            ipv4,
            ipv6: !ipv4,
            publish_ipv4: true,
            publish_ipv6: true,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
            ipv4_mtu: None,
            ipv6_mtu: None,
        };
        let context =
            Ssu2Transport::<MockRuntime>::initialize(Some(ssu2)).await.unwrap().0.unwrap();
        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(None, Some(context.config()));
        builder.register_ssu2(context);
        let mut manager = builder.build();

        // ensure ssu2 is published
        assert!(manager.ssu2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                    }
                }
                _ => false,
            })
        );

        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::1".parse().unwrap());
        }

        // verify that the address is still published and that host is the same
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                    }
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn external_address_discovered_ssu2_unpublished_ipv4() {
        external_address_discovered_ssu2_unpublished(true).await
    }

    #[tokio::test]
    async fn external_address_discovered_ssu2_unpublished_ipv6() {
        external_address_discovered_ssu2_unpublished(false).await
    }

    async fn external_address_discovered_ssu2_unpublished(ipv4: bool) {
        let context = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            max_connections: None,
            ml_kem: None,
            disable_pq: false,
            port: 0,
            ipv4_host: None,
            ipv6_host: None,
            ipv4,
            ipv6: !ipv4,
            publish_ipv4: false,
            publish_ipv6: false,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
            ipv4_mtu: None,
            ipv6_mtu: None,
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(None, Some(context.config()));
        builder.register_ssu2(context);
        let mut manager = builder.build();

        // ensure ssu2 is unpublished
        assert!(manager.ssu2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    options.get(&Str::from("host")).is_none()
                }
                _ => false,
            })
        );

        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::1".parse().unwrap());
        }

        // verify that the address is still unpublished
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    options.get(&Str::from("host")).is_none()
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn new_external_address_discovered_ipv4() {
        new_external_address_discovered(true).await
    }

    #[tokio::test]
    async fn new_external_address_discovered_ipv6() {
        new_external_address_discovered(false).await
    }

    async fn new_external_address_discovered(ipv4: bool) {
        let ssu2_context = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            max_connections: None,
            ml_kem: None,
            disable_pq: false,
            port: 0,
            ipv4_host: None,
            ipv6_host: None,
            ipv4,
            ipv6: !ipv4,
            publish_ipv4: true,
            publish_ipv6: true,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
            ipv4_mtu: None,
            ipv6_mtu: None,
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        let ntcp2_context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            max_connections: None,
            port: 0,
            ipv4_host: None,
            ipv6_host: None,
            ml_kem: None,
            disable_pq: false,
            publish_ipv4: true,
            publish_ipv6: true,
            key: [0u8; 32],
            iv: [0u8; 16],
            ipv4,
            ipv6: !ipv4,
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(Some(ntcp2_context.config()), Some(ssu2_context.config()));
        builder.register_ssu2(ssu2_context);
        builder.register_ntcp2(ntcp2_context);
        let mut manager = builder.build();

        // ensure ssu2 and ntcp2 is unpublished since no host was provided
        assert!(manager.ssu2_config.is_some());
        assert!(manager.ntcp2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    options.get(&Str::from("host")).is_none()
                }
                _ => false,
            })
        );
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    options.get(&Str::from("host")).is_none()
                        && options.get(&Str::from("i")).is_none()
                }
                _ => false,
            })
        );

        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::1".parse().unwrap());
        }

        // verify the addresses have been published
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                    }
                }
                _ => false,
            })
        );
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                            && options.get(&Str::from("i")).is_some()
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                            && options.get(&Str::from("i")).is_some()
                    }
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn discovered_address_doesnt_match_published_address_ntcp2_ipv4() {
        discovered_address_doesnt_match_published_address_ntcp2(true).await;
    }

    #[tokio::test]
    async fn discovered_address_doesnt_match_published_address_ntcp2_ipv6() {
        discovered_address_doesnt_match_published_address_ntcp2(false).await;
    }

    async fn discovered_address_doesnt_match_published_address_ntcp2(ipv4: bool) {
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            max_connections: None,
            port: 0,
            ipv4_host: ipv4.then_some("127.0.0.1".parse().unwrap()),
            ipv6_host: (!ipv4).then_some("::1".parse().unwrap()),
            ipv4,
            ipv6: !ipv4,
            ml_kem: None,
            disable_pq: false,
            publish_ipv4: true,
            publish_ipv6: true,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(Some(context.config()), None);
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        // ensure ntcp2 is published
        assert!(manager.ntcp2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                            && options.get(&Str::from("i")).is_some()
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                            && options.get(&Str::from("i")).is_some()
                    }
                }
                _ => false,
            })
        );

        // address doesn't match our current adress
        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.2".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::2".parse().unwrap());
        }

        // verify that the address is still published and that host is the same
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ntcp2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                            && options.get(&Str::from("i")).is_some()
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                            && options.get(&Str::from("i")).is_some()
                    }
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn discovered_address_doesnt_match_published_address_ssu2_ipv4() {
        discovered_address_doesnt_match_published_address_ssu2(true).await;
    }

    #[tokio::test]
    async fn discovered_address_doesnt_match_published_address_ssu2_ipv6() {
        discovered_address_doesnt_match_published_address_ssu2(false).await;
    }

    async fn discovered_address_doesnt_match_published_address_ssu2(ipv4: bool) {
        let context = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            max_connections: None,
            ml_kem: None,
            disable_pq: false,
            port: 0,
            ipv4_host: ipv4.then_some("127.0.0.1".parse().unwrap()),
            ipv6_host: (!ipv4).then_some("::1".parse().unwrap()),
            ipv4,
            ipv6: !ipv4,
            publish_ipv4: true,
            publish_ipv6: true,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
            ipv4_mtu: None,
            ipv6_mtu: None,
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx, _netdb_rx) =
            make_transport_manager(None, Some(context.config()));
        builder.register_ssu2(context);
        let mut manager = builder.build();

        // ensure ssu2 is unpublished
        assert!(manager.ssu2_config.is_some());
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                    }
                }
                _ => false,
            })
        );

        // address doesn't match our current adress
        if ipv4 {
            manager.ipv4_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("127.0.0.2".parse().unwrap());
        } else {
            manager.ipv6_info.firewall_status = FirewallStatus::Ok;
            manager.add_external_address("::2".parse().unwrap());
        }

        // verify that the address is still unpublished
        assert!(
            manager.local_router_info.addresses().any(|address| match address {
                RouterAddress::Ssu2 { options, .. } => {
                    if ipv4 {
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                    } else {
                        options.get(&Str::from("host")) == Some(&Str::from("::1"))
                    }
                }
                _ => false,
            })
        );
    }

    #[tokio::test]
    async fn inbound_connection_rejected_connection_already_exists() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let (handle, _) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&[], &[], None),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let (_dial_tx, dial_rx) = channel(100);
        let (transport_tx, _transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let mut manager = builder.build();

        #[derive(Clone, Default)]
        enum Command {
            Accept(RouterId),
            Reject(RouterId),
            #[default]
            Dummy,
        }

        pub struct MockTransport {
            events: VecDeque<TransportEvent>,
            tx: Sender<Command>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {
                todo!();
            }

            fn accept(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Accept(router_id.clone())).unwrap();
            }

            fn reject(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Reject(router_id.clone())).unwrap();
            }
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match self.events.pop_front() {
                    Some(event) => {
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Some(event));
                    }
                    None => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
        }

        let (tx, rx) = channel(64);
        let router_id1 = RouterId::random();

        manager.transports.push(Box::new(MockTransport {
            events: VecDeque::from_iter([
                TransportEvent::ConnectionEstablished {
                    address: "127.0.0.1:8888".parse().unwrap(),
                    encryption: EncryptionKind::X25519,
                    router_id: router_id1.clone(),
                    direction: Direction::Inbound,
                },
                TransportEvent::ConnectionEstablished {
                    address: "127.0.0.1:8888".parse().unwrap(),
                    encryption: EncryptionKind::X25519,
                    router_id: router_id1.clone(),
                    direction: Direction::Inbound,
                },
            ]),
            tx,
        }));
        tokio::spawn(manager);

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Accept(router_id) => {
                assert_eq!(router_id, router_id1);
            }
            _ => panic!("invalid command"),
        }

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Reject(router_id) => {
                assert_eq!(router_id, router_id1);
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn inbound_connection_rejected_outbound_pending() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (handle, _) = NetDbHandle::create();
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage.clone(),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let router = RouterInfoBuilder::default().build().0;
        let router_id = router.identity.id();
        storage.add_router(router);

        let (dial_tx, dial_rx) = channel(100);
        let (transport_tx, _transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let mut manager = builder.build();

        #[derive(Clone, Default)]
        enum Command {
            Connect(RouterInfo),
            Accept(RouterId),
            Reject(RouterId),
            #[default]
            Dummy,
        }

        pub struct MockTransport {
            tx: mpsc::Sender<Command>,
            event_rx: mpsc::Receiver<TransportEvent>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, info: RouterInfo) {
                self.tx.try_send(Command::Connect(info)).unwrap();
            }

            fn accept(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Accept(router_id.clone())).unwrap();
            }

            fn reject(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Reject(router_id.clone())).unwrap();
            }
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                self.event_rx.poll_recv(cx)
            }
        }

        let (tx, mut rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(64);

        manager.transports.push(Box::new(MockTransport { event_rx, tx }));
        manager.supported_transports.insert(TransportKind::Ntcp2V4);
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Connect(router_info) => {
                assert_eq!(router_info.identity.id(), router_id);
            }
            _ => panic!("invalid command"),
        }

        event_tx
            .send(TransportEvent::ConnectionEstablished {
                address: "127.0.0.1:8888".parse().unwrap(),
                encryption: EncryptionKind::X25519,
                router_id: router_id.clone(),
                direction: Direction::Inbound,
            })
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Reject(rid) => {
                assert_eq!(rid, router_id);
            }
            _ => panic!("invalid command"),
        }

        event_tx
            .send(TransportEvent::ConnectionFailure {
                router_id: router_id.clone(),
                reason: DialError::Timeout,
            })
            .await
            .unwrap();

        event_tx
            .send(TransportEvent::ConnectionEstablished {
                address: "127.0.0.1:8888".parse().unwrap(),
                encryption: EncryptionKind::X25519,
                router_id: router_id.clone(),
                direction: Direction::Inbound,
            })
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Accept(rid) => {
                assert_eq!(rid, router_id);
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_connection_rejected_while_netdb_lookup_pending() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (handle, netdb_rx) = NetDbHandle::create();
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage.clone(),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );
        let router_id = RouterId::random();

        let (dial_tx, dial_rx) = channel(100);
        let (transport_tx, _transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let mut manager = builder.build();

        #[derive(Clone, Default)]
        enum Command {
            Accept(RouterId),
            Reject(RouterId),
            #[default]
            Dummy,
        }

        pub struct MockTransport {
            tx: mpsc::Sender<Command>,
            event_rx: mpsc::Receiver<TransportEvent>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {
                todo!();
            }

            fn accept(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Accept(router_id.clone())).unwrap();
            }

            fn reject(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Reject(router_id.clone())).unwrap();
            }
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                self.event_rx.poll_recv(cx)
            }
        }

        let (tx, mut rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(64);

        manager.transports.push(Box::new(MockTransport { event_rx, tx }));
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        // since RI for `router_id` doesn't exist, it's looked up from netdb
        let query_result_tx = match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::QueryRouterInfo { router_id: rid, tx } => {
                assert_eq!(rid, router_id);
                tx
            }
            _ => panic!("invalid command"),
        };

        // try to add new inbound connection from the node that's being queried
        event_tx
            .send(TransportEvent::ConnectionEstablished {
                address: "127.0.0.1:8888".parse().unwrap(),
                encryption: EncryptionKind::X25519,
                router_id: router_id.clone(),
                direction: Direction::Inbound,
            })
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Reject(rid) => {
                assert_eq!(rid, router_id);
            }
            _ => panic!("invalid command"),
        }

        // RI not found
        query_result_tx.send(Err(QueryError::ValueNotFound)).unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;

        // add new inbound connection from the same node that was previously rejected
        event_tx
            .send(TransportEvent::ConnectionEstablished {
                address: "127.0.0.1:8888".parse().unwrap(),
                encryption: EncryptionKind::X25519,
                router_id: router_id.clone(),
                direction: Direction::Inbound,
            })
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            Command::Accept(rid) => {
                assert_eq!(rid, router_id);
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn transit_tunnels_disabled() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let (handle, _netdb_rx) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage.clone(),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            max_connections: None,
            port: 0,
            ipv4_host: Some("192.168.0.1".parse().unwrap()),
            ipv6_host: None,
            ml_kem: None,
            disable_pq: false,
            publish_ipv4: true,
            publish_ipv6: true,
            key: [0u8; 32],
            iv: [0u8; 16],
            ipv4: true,
            ipv6: false,
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (_dial_tx, dial_rx) = channel(100);
        let (transport_tx, _transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        builder.register_ntcp2(context);
        builder.with_transit_tunnels_disabled(true);

        let mut manager = builder.build();
        manager.router_info_republish_timer = MockRuntime::timer(Duration::from_secs(1));

        assert!(tokio::time::timeout(Duration::from_secs(3), &mut manager).await.is_err());

        // verify that the local router is no longer considered usable due to the `G` flag
        assert!(!Capabilities::parse(
            &manager.local_router_info.options.get(&Str::from("caps")).unwrap()
        )
        .unwrap()
        .is_usable());
    }

    #[tokio::test(start_paused = true)]
    async fn router_info_query_fails() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (handle, netdb_rx) = NetDbHandle::create();
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage.clone(),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );
        let router_id = RouterId::random();

        let (dial_tx, dial_rx) = channel(100);
        let (transport_tx, transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let mut manager = builder.build();

        #[derive(Clone, Default)]
        enum Command {
            #[allow(unused)]
            Accept(RouterId),
            #[allow(unused)]
            Reject(RouterId),
            #[default]
            Dummy,
        }

        pub struct MockTransport {
            tx: mpsc::Sender<Command>,
            event_rx: mpsc::Receiver<TransportEvent>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {
                todo!();
            }

            fn accept(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Accept(router_id.clone())).unwrap();
            }

            fn reject(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Reject(router_id.clone())).unwrap();
            }
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                self.event_rx.poll_recv(cx)
            }
        }

        let (tx, _rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(64);

        manager.transports.push(Box::new(MockTransport { event_rx, tx }));
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        // since RI for `router_id` doesn't exist, it's looked up from netdb
        let query_result_tx = match tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::QueryRouterInfo { router_id: rid, tx } => {
                assert_eq!(rid, router_id);
                tx
            }
            _ => panic!("invalid command"),
        };

        // RI not found, verify that nothing is reported
        query_result_tx.send(Err(QueryError::ValueNotFound)).unwrap();

        tokio::time::sleep(Duration::from_secs(2)).await;

        match tokio::time::timeout(Duration::from_secs(5), transport_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SubsystemEvent::ConnectionFailure { router_id: router } => {
                assert_eq!(router, router_id)
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn router_without_ntcp2_support_dialed() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let (remote_router_info, _, _) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: 888u16,
                ipv4_host: Some("127.0.0.1".parse().unwrap()),
                ipv6_host: None,
                ipv4: true,
                ipv6: false,
                publish_ipv4: true,
                publish_ipv6: true,
                static_key: [1u8; 32],
                intro_key: [2u8; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();
        let remote_router_id = remote_router_info.identity.id();
        storage.add_router(remote_router_info);

        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (handle, _netdb_rx) = NetDbHandle::create();
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage.clone(),
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let (dial_tx, dial_rx) = channel(100);
        let (transport_tx, transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            max_connections: None,
            port: 0,
            ipv4_host: Some("192.168.0.1".parse().unwrap()),
            ipv6_host: None,
            ml_kem: None,
            disable_pq: false,
            publish_ipv4: true,
            publish_ipv6: true,
            key: [0u8; 32],
            iv: [0u8; 16],
            ipv4: true,
            ipv6: false,
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        #[derive(Clone, Default)]
        enum Command {
            #[default]
            Dummy,
        }

        pub struct MockTransport {
            _tx: mpsc::Sender<Command>,
            event_rx: mpsc::Receiver<TransportEvent>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {}
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                self.event_rx.poll_recv(cx)
            }
        }

        let (_tx, _rx) = mpsc::channel(64);
        let (_event_tx, event_rx) = mpsc::channel(64);

        manager.transports.push(Box::new(MockTransport { event_rx, _tx }));
        tokio::spawn(manager);

        // attempt to connect to remote router but since they don't have an ntcp2 address,
        // the dial fails
        dial_tx.send(remote_router_id.clone()).await.unwrap();

        match tokio::time::timeout(Duration::from_secs(5), transport_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SubsystemEvent::ConnectionFailure { router_id: router } => {
                assert_eq!(router, remote_router_id)
            }
            _ => panic!("invalid event"),
        }

        // attempt to connect again and verify that a dial failure is reported
        //
        // this is a fix for a regression where the outbound connection was left in a pending state
        // and all subsequent dials to the remote peer timed out in in `TransitTunnelManager`
        // because the dial attempt didn't proceed as it was erroneously in the pending state
        dial_tx.send(remote_router_id.clone()).await.unwrap();

        match tokio::time::timeout(Duration::from_secs(5), transport_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SubsystemEvent::ConnectionFailure { router_id: router } => {
                assert_eq!(router, remote_router_id)
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn simultaneous_outbound_ssu2_connections() {
        let config1 = Ssu2Config {
            max_connections: None,
            ml_kem: None,
            disable_pq: false,
            port: 0,
            ipv4_host: Some("127.0.0.1".parse().unwrap()),
            ipv6_host: None,
            ipv4: true,
            ipv6: false,
            publish_ipv4: true,
            publish_ipv6: true,
            static_key: [0xaa; 32],
            intro_key: [0xbb; 32],
            ipv4_mtu: None,
            ipv6_mtu: None,
        };
        let (context1, address1, _) =
            Ssu2Transport::<MockRuntime>::initialize(Some(config1)).await.unwrap();
        let (router_info1, static_key1, signing_key1) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: address1.unwrap().ssu2_ipv4_address().port(),
                ipv4_host: Some("127.0.0.1".parse().unwrap()),
                ipv6_host: None,
                ipv4: true,
                ipv6: false,
                publish_ipv4: true,
                publish_ipv6: true,
                static_key: [0xaa; 32],
                intro_key: [0xbb; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();
        let serialized1 = Bytes::from(router_info1.serialize(&signing_key1));
        let storage1 = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let router_id1 = router_info1.identity.id();

        let config2 = Ssu2Config {
            max_connections: None,
            ml_kem: None,
            disable_pq: false,
            port: 0,
            ipv4_host: Some("127.0.0.1".parse().unwrap()),
            ipv6_host: None,
            ipv4: true,
            ipv6: false,
            publish_ipv4: true,
            publish_ipv6: true,
            static_key: [0xcc; 32],
            intro_key: [0xdd; 32],
            ipv4_mtu: None,
            ipv6_mtu: None,
        };
        let (context2, address2, _) =
            Ssu2Transport::<MockRuntime>::initialize(Some(config2)).await.unwrap();

        let (router_info2, static_key2, signing_key2) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: address2.unwrap().ssu2_ipv4_address().port(),
                ipv4_host: Some("127.0.0.1".parse().unwrap()),
                ipv6_host: None,
                ipv4: true,
                ipv6: false,
                publish_ipv4: true,
                publish_ipv6: true,
                static_key: [0xcc; 32],
                intro_key: [0xdd; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();
        let serialized2 = Bytes::from(router_info2.serialize(&signing_key2));
        let storage2 = ProfileStorage::<MockRuntime>::new(&[], &[], None);
        let router_id2 = router_info2.identity.id();

        storage1.add_router(router_info2.clone());
        storage2.add_router(router_info1.clone());

        let (_event_mgr1, _event_subscriber1, event_handle1) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (_event_mgr2, _event_subscriber2, event_handle2) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (handle1, _netdb_rx1) = NetDbHandle::create();
        let (handle2, _netdb_rx2) = NetDbHandle::create();

        let ctx1 = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage1.clone(),
            router_info1.identity.id(),
            serialized1.clone(),
            static_key1,
            signing_key1,
            2u8,
            event_handle1.clone(),
        );
        let ctx2 = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage2.clone(),
            router_info2.identity.id(),
            serialized2.clone(),
            static_key2,
            signing_key2,
            2u8,
            event_handle2.clone(),
        );

        let (dial_tx1, dial_rx1) = channel(100);
        let (transport_tx1, transport_rx1) = channel(100);
        let mut builder1 = TransportManagerBuilder::<MockRuntime>::new(
            ctx1,
            router_info1,
            true,
            dial_rx1,
            transport_tx1,
            Default::default(),
        );
        builder1.register_ssu2(context1.unwrap());
        builder1.register_netdb_handle(handle1);
        let transport1 = builder1.build();

        let (dial_tx2, dial_rx2) = channel(100);
        let (transport_tx2, transport_rx2) = channel(100);
        let mut builder2 = TransportManagerBuilder::<MockRuntime>::new(
            ctx2,
            router_info2,
            true,
            dial_rx2,
            transport_tx2,
            Default::default(),
        );
        builder2.register_ssu2(context2.unwrap());
        builder2.register_netdb_handle(handle2);
        let transport2 = builder2.build();

        tokio::spawn(transport1);
        tokio::spawn(transport2);

        dial_tx1.try_send(router_id2.clone()).unwrap();
        dial_tx2.try_send(router_id1.clone()).unwrap();

        match tokio::time::timeout(Duration::from_secs(5), transport_rx1.recv())
            .await
            .expect("no timeout")
            .unwrap()
        {
            SubsystemEvent::ConnectionFailure { router_id } => {
                assert_eq!(router_id, router_id2);
            }
            _ => panic!("invalid event"),
        }

        match tokio::time::timeout(Duration::from_secs(5), transport_rx2.recv())
            .await
            .expect("no timeout")
            .unwrap()
        {
            SubsystemEvent::ConnectionFailure { router_id } => {
                assert_eq!(router_id, router_id1);
            }
            _ => panic!("invalid event"),
        }

        dial_tx2.try_send(router_id1.clone()).unwrap();

        let conn_tx1 = match tokio::time::timeout(Duration::from_secs(5), transport_rx1.recv())
            .await
            .expect("no timeout")
            .unwrap()
        {
            SubsystemEvent::ConnectionEstablished { router_id, tx } => {
                assert_eq!(router_id, router_id2);
                tx
            }
            _ => panic!("invalid event"),
        };

        let conn_tx2 = match tokio::time::timeout(Duration::from_secs(5), transport_rx2.recv())
            .await
            .expect("no timeout")
            .unwrap()
        {
            SubsystemEvent::ConnectionEstablished { router_id, tx } => {
                assert_eq!(router_id, router_id1);
                tx
            }
            _ => panic!("invalid event"),
        };

        conn_tx2
            .try_send(OutboundMessage::Message(Message {
                message_type: MessageType::DatabaseStore,
                message_id: 1337u32,
                expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                payload: vec![1, 1, 1, 1],
            }))
            .unwrap();

        conn_tx1
            .try_send(OutboundMessage::Message(Message {
                message_type: MessageType::DatabaseStore,
                message_id: 1338u32,
                expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                payload: vec![2, 2, 2, 2],
            }))
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), transport_rx1.recv())
            .await
            .expect("no timeout")
            .unwrap()
        {
            SubsystemEvent::Message { messages } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, router_id2);
                assert_eq!(messages[0].1.message_type, MessageType::DatabaseStore);
                assert_eq!(messages[0].1.message_id, 1337u32);
                assert_eq!(messages[0].1.payload, vec![1, 1, 1, 1]);
            }
            _ => panic!("invalid event"),
        }

        match tokio::time::timeout(Duration::from_secs(5), transport_rx2.recv())
            .await
            .expect("no timeout")
            .unwrap()
        {
            SubsystemEvent::Message { messages } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, router_id1);
                assert_eq!(messages[0].1.message_type, MessageType::DatabaseStore);
                assert_eq!(messages[0].1.message_id, 1338u32);
                assert_eq!(messages[0].1.payload, vec![2, 2, 2, 2]);
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn dial_connected_router() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let (handle, netdb_rx) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (storage, remote_router_id) = {
            let (router_info, _static_key, _signing_key) = RouterInfoBuilder::default().build();
            let router_id = router_info.identity.id();
            let storage = ProfileStorage::<MockRuntime>::new(&[], &[], None);
            storage.add_router(router_info);

            (storage, router_id)
        };
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            storage,
            router_info.identity.id(),
            serialized.clone(),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let (dial_tx, dial_rx) = channel(100);
        let (transport_tx, _transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let mut manager = builder.build();

        #[derive(Clone, Default)]
        enum Command {
            Connect(RouterId),
            Accept(RouterId),
            #[default]
            Dummy,
        }

        pub struct MockTransport {
            events: VecDeque<TransportEvent>,
            tx: Sender<Command>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, info: RouterInfo) {
                self.tx.try_send(Command::Connect(info.identity.id())).unwrap();
            }

            fn accept(&mut self, router_id: &RouterId) {
                self.tx.try_send(Command::Accept(router_id.clone())).unwrap();
            }

            fn reject(&mut self, _: &RouterId) {
                unreachable!()
            }
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match self.events.pop_front() {
                    Some(event) => {
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Some(event));
                    }
                    None => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
        }

        // start mock transport with a single inbound event and send a dial request for that same
        // router over `dial_rx` to `TransportManager`
        let (tx, rx) = channel(64);

        manager.transports.push(Box::new(MockTransport {
            events: VecDeque::from_iter([TransportEvent::ConnectionEstablished {
                address: "127.0.0.1:8888".parse().unwrap(),
                encryption: EncryptionKind::X25519,
                router_id: remote_router_id.clone(),
                direction: Direction::Inbound,
            }]),
            tx,
        }));
        dial_tx.try_send(remote_router_id.clone()).unwrap();

        // verify that router doesn't exist in either connected or pending
        assert!(!manager.routers.contains_key(&remote_router_id));
        assert!(!manager.pending_connections.contains_key(&remote_router_id));

        futures::future::poll_fn(|cx| {
            let _ = manager.poll_unpin(cx);
            Poll::Ready(())
        })
        .await;

        // verify that `TransportManager` now has the router as a connected peer
        assert!(manager.routers.contains_key(&remote_router_id));
        assert!(!manager.pending_connections.contains_key(&remote_router_id));
        assert!(netdb_rx.try_recv().is_err());

        // verify the inbound connection is accepted
        match rx.try_recv().unwrap() {
            Command::Accept(router_id) => assert_eq!(router_id, remote_router_id),
            _ => panic!("invalid command"),
        }

        // verify that the dial request is ignored
        match rx.try_recv() {
            Err(_) => {}
            Ok(Command::Connect(router_id)) if router_id == remote_router_id =>
                panic!("connected router dialed"),
            _ => panic!("unexpected event"),
        }
    }

    #[tokio::test]
    async fn introducers_published() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: 888,
                ipv4_host: None,
                ipv6_host: None,
                ipv4: true,
                ipv6: false,
                publish_ipv4: false,
                publish_ipv6: false,
                static_key: [0x33; 32],
                intro_key: [0x34; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();

        let (handle, netdb_rx) = NetDbHandle::create();
        let ctx = RouterContextBuilder::default()
            .with_router_info(router_info.clone(), static_key, signing_key)
            .build();

        let (_dial_tx, dial_rx) = channel(100);
        let (transport_tx, _transport_rx) = channel(100);
        let mut builder = TransportManagerBuilder::<MockRuntime>::new(
            ctx,
            router_info,
            true,
            dial_rx,
            transport_tx,
            Default::default(),
        );
        builder.register_netdb_handle(handle);
        let mut manager = builder.build();

        pub struct MockTransport {
            events: tokio::sync::mpsc::Receiver<TransportEvent>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {}
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                Poll::Ready(futures::ready!(self.events.poll_recv(cx)))
            }
        }

        let (t_event_tx, t_event_rx) = tokio::sync::mpsc::channel(16);
        manager.transports.push(Box::new(MockTransport { events: t_event_rx }));

        // set lower timeout for publishing router info
        assert!(manager.ipv4_info.introducers.is_empty());
        manager.router_info_republish_timer =
            <MockRuntime as Runtime>::timer(Duration::from_secs(0));

        let router_info = tokio::select! {
            _ = &mut manager => panic!("manager exited"),
            event = netdb_rx.recv() => match event.unwrap() {
                NetDbAction::PublishRouterInfo { router_info, .. } => router_info,
                _ => panic!("invalid event"),
            },
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
        };

        let parsed = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
        assert_eq!(parsed.addresses.len(), 1);

        match &parsed.addresses[0] {
            RouterAddress::Ssu2 { options, .. } => {
                // verify address is not published
                assert!(options.get(&Str::from("port")).is_none());
                assert!(options.get(&Str::from("host")).is_none());

                // verify there are no introducers
                for i in 0..3 {
                    assert!(options.get(&Str::from(format!("iexp{i}"))).is_none());
                    assert!(options.get(&Str::from(format!("ih{i}"))).is_none());
                    assert!(options.get(&Str::from(format!("itag{i}"))).is_none());
                }
            }
            _ => panic!("no ssu2 address available"),
        }

        // register introducers
        let introducer1 = RouterId::random();
        let introducer2 = RouterId::random();
        let introducer3 = RouterId::random();

        t_event_tx
            .send(TransportEvent::IntroducerAdded {
                relay_tag: 1337,
                router_id: introducer1.clone(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80 * 60),
                ipv4: true,
            })
            .await
            .unwrap();
        t_event_tx
            .send(TransportEvent::IntroducerAdded {
                relay_tag: 1338,
                router_id: introducer2.clone(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80 * 60),
                ipv4: true,
            })
            .await
            .unwrap();

        // last introducer has expired
        t_event_tx
            .send(TransportEvent::IntroducerAdded {
                relay_tag: 1339,
                router_id: introducer3.clone(),
                expires: MockRuntime::time_since_epoch() - Duration::from_secs(1),
                ipv4: true,
            })
            .await
            .unwrap();

        // reset publish timer
        manager.router_info_republish_timer =
            <MockRuntime as Runtime>::timer(Duration::from_secs(0));

        let router_info = tokio::select! {
            _ = &mut manager => panic!("manager exited"),
            event = netdb_rx.recv() => match event.unwrap() {
                NetDbAction::PublishRouterInfo { router_info, .. } => router_info,
                _ => panic!("invalid event"),
            },
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
        };

        let parsed = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
        assert_eq!(parsed.addresses.len(), 1);

        match &parsed.addresses[0] {
            RouterAddress::Ssu2 {
                options,
                introducers,
                ..
            } => {
                // verify address is not published
                assert!(options.get(&Str::from("port")).is_none());
                assert!(options.get(&Str::from("host")).is_none());

                assert_eq!(introducers.len(), 2);
                assert_eq!(introducers[0].0, introducer1);
                assert_eq!(introducers[0].1, 1337);
                assert_eq!(introducers[1].0, introducer2);
                assert_eq!(introducers[1].1, 1338);

                // first introducer
                {
                    assert_eq!(
                        options.get(&Str::from(format!("itag0"))),
                        Some(&Str::from("1337")),
                    );
                    assert_eq!(
                        options.get(&Str::from(format!("ih0"))),
                        Some(&Str::from(base64_encode(introducer1.to_vec()))),
                    );
                }

                // second introducer
                {
                    assert_eq!(
                        options.get(&Str::from(format!("itag1"))),
                        Some(&Str::from("1338")),
                    );
                    assert_eq!(
                        options.get(&Str::from(format!("ih1"))),
                        Some(&Str::from(base64_encode(introducer2.to_vec()))),
                    );
                }
            }
            _ => panic!("no ssu2 address available"),
        }
    }

    #[derive(Default)]
    struct TestContextBuilder {
        ssu2: Option<Box<dyn Transport<Item = TransportEvent>>>,
        ntcp2: Option<Box<dyn Transport<Item = TransportEvent>>>,
        routers: Vec<RouterInfo>,
        transit_tunnels_disabled: bool,
        caps: Option<String>,
        ipv6: bool,
        both: bool,
        publish: bool,
    }

    impl TestContextBuilder {
        fn with_ssu2(mut self, ssu2: Box<dyn Transport<Item = TransportEvent>>) -> Self {
            self.ssu2 = Some(ssu2);
            self
        }

        fn with_ntcp2(mut self, ntcp2: Box<dyn Transport<Item = TransportEvent>>) -> Self {
            self.ntcp2 = Some(ntcp2);
            self
        }

        fn with_router(mut self, router_info: RouterInfo) -> Self {
            self.routers.push(router_info);
            self
        }

        fn with_transit_tunnels_disabled(mut self) -> Self {
            self.transit_tunnels_disabled = true;
            self
        }

        fn with_caps(mut self, caps: String) -> Self {
            self.caps = Some(caps);
            self
        }

        fn with_ipv6(mut self, ipv6: bool) -> Self {
            self.ipv6 = ipv6;
            self
        }

        fn with_publish(mut self) -> Self {
            self.publish = true;
            self
        }

        fn with_both(mut self) -> Self {
            self.both = true;
            self
        }

        fn build(
            self,
        ) -> (
            TransportManager<MockRuntime>,
            Receiver<NetDbAction, NetDbActionRecycle>,
            Sender<RouterId>,
            Receiver<SubsystemEvent>,
        ) {
            let mut builder = if self.ipv6 {
                RouterInfoBuilder::default().with_ipv6()
            } else {
                RouterInfoBuilder::default()
            };

            let ssu2_config = self.ssu2.is_some().then(|| Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: 8888,
                ipv4_host: None,
                ipv6_host: None,
                ipv6: self.both || self.ipv6,
                ipv4: self.both || !self.ipv6,
                publish_ipv4: self.publish,
                publish_ipv6: self.publish,
                static_key: [0x33; 32],
                intro_key: [0x34; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            });
            let ntcp2_config = self.ntcp2.is_some().then(|| Ntcp2Config {
                max_connections: None,
                port: 8889,
                ipv4_host: None,
                ipv6_host: None,
                ipv6: self.both || self.ipv6,
                ipv4: self.both || !self.ipv6,
                ml_kem: None,
                disable_pq: false,
                publish_ipv4: self.publish,
                publish_ipv6: self.publish,
                key: [0xaa; 32],
                iv: [0xbb; 16],
            });

            if let Some(ref ssu2) = ssu2_config {
                builder = builder.with_ssu2(ssu2.clone());
            }

            if let Some(ref ntcp2) = ntcp2_config {
                builder = builder.with_ntcp2(ntcp2.clone());
            }

            let (router_info, static_key, signing_key) = builder.build();

            let profile_storage = if self.routers.is_empty() {
                ProfileStorage::new(&[], &[], None)
            } else {
                let storage = ProfileStorage::new(&[], &[], None);

                for router in self.routers {
                    storage.add_router(router);
                }

                storage
            };

            let (handle, netdb_rx) = NetDbHandle::create();
            let ctx = RouterContextBuilder::default()
                .with_profile_storage(profile_storage)
                .with_router_info(router_info.clone(), static_key, signing_key)
                .build();

            let (dial_tx, dial_rx) = channel(100);
            let (transport_tx, transport_rx) = channel(100);
            let mut builder = TransportManagerBuilder::<MockRuntime>::new(
                ctx,
                router_info,
                true,
                dial_rx,
                transport_tx,
                Default::default(),
            );
            builder.register_netdb_handle(handle);

            if self.transit_tunnels_disabled {
                builder.with_transit_tunnels_disabled(true);
            }

            if let Some(ref caps) = self.caps {
                builder.with_capabilities(caps.clone());
            }

            let mut manager = builder.build();

            if let Some(ntcp2) = self.ntcp2 {
                manager.transports.push(ntcp2);
                manager.ntcp2_config = ntcp2_config;

                if self.both {
                    manager.supported_transports.insert(TransportKind::Ntcp2V6);
                    manager.supported_transports.insert(TransportKind::Ntcp2V4);
                } else if self.ipv6 {
                    manager.supported_transports.insert(TransportKind::Ntcp2V6);
                } else {
                    manager.supported_transports.insert(TransportKind::Ntcp2V4);
                }
            }

            if let Some(ssu2) = self.ssu2 {
                manager.transports.push(ssu2);
                manager.ssu2_config = ssu2_config;

                if self.both {
                    manager.supported_transports.insert(TransportKind::Ssu2V6);
                    manager.supported_transports.insert(TransportKind::Ssu2V4);
                } else if self.ipv6 {
                    manager.supported_transports.insert(TransportKind::Ssu2V6);
                } else {
                    manager.supported_transports.insert(TransportKind::Ssu2V4);
                }
            }

            (manager, netdb_rx, dial_tx, transport_rx)
        }
    }

    #[tokio::test]
    async fn dial_ntcp2_ipv4() {
        dial_ntcp2(true).await;
    }

    #[tokio::test]
    async fn dial_ntcp2_ipv6() {
        dial_ntcp2(false).await;
    }

    async fn dial_ntcp2(ipv4: bool) {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (router_info, ..) = RouterInfoBuilder::default()
            .with_ntcp2(Ntcp2Config {
                max_connections: None,
                port: 9999,
                ipv4_host: ipv4.then_some("127.0.0.1".parse().unwrap()),
                ipv6_host: (!ipv4).then_some("::1".parse().unwrap()),
                ipv4,
                ipv6: !ipv4,
                ml_kem: None,
                disable_pq: false,
                publish_ipv4: true,
                publish_ipv6: true,
                key: [0x11; 32],
                iv: [0x22; 16],
            })
            .build();
        let router_id = router_info.identity.id();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (manager, _netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ipv6(!ipv4)
            .with_ntcp2(Box::new(MockTransport { tx }))
            .build();
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        assert_eq!(timeout!(rx.recv()).await.unwrap().unwrap(), router_id);
    }

    #[tokio::test]
    async fn dial_ntcp2_ip_not_supported_ipv4() {
        dial_ntcp2_ip_not_supported(false, true).await;
    }

    #[tokio::test]
    async fn dial_ntcp2_ip_not_supported_ipv6() {
        dial_ntcp2_ip_not_supported(true, false).await;
    }

    async fn dial_ntcp2_ip_not_supported(local_ipv4: bool, remote_ipv4: bool) {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (router_info, ..) = RouterInfoBuilder::default()
            .with_ntcp2(Ntcp2Config {
                max_connections: None,
                port: 9999,
                ipv4_host: remote_ipv4.then_some("127.0.0.1".parse().unwrap()),
                ipv6_host: (!remote_ipv4).then_some("::1".parse().unwrap()),
                ipv4: remote_ipv4,
                ipv6: !remote_ipv4,
                ml_kem: None,
                disable_pq: false,
                publish_ipv4: true,
                publish_ipv6: true,
                key: [0x11; 32],
                iv: [0x22; 16],
            })
            .build();
        let router_id = router_info.identity.id();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ipv6(!local_ipv4)
            .with_ntcp2(Box::new(MockTransport { tx }))
            .build();
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dial_ssu2_ip_not_supported_ipv4() {
        dial_ssu2_ip_not_supported(false, true).await;
    }

    #[tokio::test]
    async fn dial_ssu2_ip_not_supported_ipv6() {
        dial_ssu2_ip_not_supported(true, false).await;
    }

    async fn dial_ssu2_ip_not_supported(local_ipv4: bool, remote_ipv4: bool) {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (router_info, ..) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: 9999,
                ipv4_host: remote_ipv4.then_some("127.0.0.1".parse().unwrap()),
                ipv6_host: (!remote_ipv4).then_some("::1".parse().unwrap()),
                ipv4: remote_ipv4,
                ipv6: !remote_ipv4,
                publish_ipv4: true,
                publish_ipv6: true,
                intro_key: [0x11; 32],
                static_key: [0x22; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();
        let router_id = router_info.identity.id();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ipv6(!local_ipv4)
            .with_ssu2(Box::new(MockTransport { tx }))
            .build();
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }

        assert!(rx.try_recv().is_err());
    }

    // attempt to dial router over ntcp2 but transport not enabled
    #[tokio::test]
    async fn dial_ntcp2_not_available() {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (router_info, ..) = RouterInfoBuilder::default()
            .with_ntcp2(Ntcp2Config {
                max_connections: None,
                port: 9999,
                ipv4_host: Some("127.0.0.1".parse().unwrap()),
                ipv6_host: None,
                publish_ipv4: true,
                publish_ipv6: true,
                ml_kem: None,
                disable_pq: false,
                key: [0x11; 32],
                iv: [0x22; 16],
                ipv4: true,
                ipv6: false,
            })
            .build();
        let router_id = router_info.identity.id();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { tx }))
            .build();
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dial_ssu2_ipv4() {
        dial_ssu2(true).await;
    }

    #[tokio::test]
    async fn dial_ssu2_ipv6() {
        dial_ssu2(false).await;
    }

    async fn dial_ssu2(ipv4: bool) {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (router_info, ..) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: 9999,
                ipv4_host: ipv4.then_some("127.0.0.1".parse().unwrap()),
                ipv6_host: (!ipv4).then_some("::1".parse().unwrap()),
                ipv4,
                ipv6: !ipv4,
                publish_ipv4: true,
                publish_ipv6: true,
                static_key: [0x11; 32],
                intro_key: [0x22; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();
        let router_id = router_info.identity.id();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (manager, _netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ipv6(!ipv4)
            .with_ssu2(Box::new(MockTransport { tx }))
            .build();
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        assert_eq!(timeout!(rx.recv()).await.unwrap().unwrap(), router_id);
    }

    // attempt to dial router over ssu2 but transport not enabled
    #[tokio::test]
    async fn dial_ssu2_not_available() {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (router_info, ..) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                max_connections: None,
                ml_kem: None,
                disable_pq: false,
                port: 9999,
                ipv4_host: Some("127.0.0.1".parse().unwrap()),
                ipv6_host: None,
                ipv4: true,
                ipv6: false,
                publish_ipv4: true,
                publish_ipv6: true,
                static_key: [0x11; 32],
                intro_key: [0x22; 32],
                ipv4_mtu: None,
                ipv6_mtu: None,
            })
            .build();
        let router_id = router_info.identity.id();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(MockTransport { tx }))
            .build();
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }

        assert!(rx.try_recv().is_err());
    }

    // attempt to dial router which doens't have a published address
    //
    // verify that since the router's introducer is already connected,
    // the router is also dialed immediately
    #[tokio::test]
    async fn dial_ssu2_connected_introducer() {
        pub struct MockTransport {
            tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let (mut manager, _netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_router(introducer)
            .with_ssu2(Box::new(MockTransport { tx }))
            .build();

        // mark introducer as connected router
        manager.routers.insert(introducer_router_id, true);
        tokio::spawn(manager);

        dial_tx.send(router_id.clone()).await.unwrap();

        assert_eq!(timeout!(rx.recv()).await.unwrap().unwrap(), router_id);
    }

    // introducer is already being dialed and then the dial fails
    //
    // report that a dial failure is also reported for the router that needed relay
    #[tokio::test]
    async fn dial_ssu2_introducer_pending_then_fails() {
        pub struct MockTransport {
            rx: tokio::sync::mpsc::Receiver<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {}
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionFailure {
                    router_id,
                    reason: DialError::Timeout,
                }))
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (mut manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_router(introducer)
            .with_ssu2(Box::new(MockTransport { rx }))
            .build();

        // mark introducer as pending
        manager.pending_connections.insert(introducer_router_id.clone(), Vec::new());

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // send dial failure for introducer
        tx.send(introducer_router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that both the introducer and the router are no longer considered pending
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(!manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&introducer_router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that dial failure is reported to subsystem manager for `router_id`
        //
        // dial failure for the introducer is reported by the transport (omitted for
        // `MockTransport`) so the channel only contains an event for the client
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
        assert!(subsys_rx.try_recv().is_err());
    }

    // introducer is already being dialed and then the dial succeeds
    //
    // verify that a dial is started for the router who needed relay
    #[tokio::test]
    async fn dial_ssu2_introducer_pending_then_succeeds() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<RouterId>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                    address: "127.0.0.1:8888".parse().unwrap(),
                    encryption: EncryptionKind::X25519,
                    direction: Direction::Outbound,
                    router_id,
                }))
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, _netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_router(introducer)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        // mark introducer as pending
        manager.pending_connections.insert(introducer_router_id.clone(), Vec::new());

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // send dial success for introducer
        event_tx.send(introducer_router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that the introducer is considered connected
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(manager.routers.contains_key(&introducer_router_id));

        // and that the router is considered pending
        assert!(manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that transport manager started to dial the router
        assert_eq!(timeout!(conn_rx.recv()).await.unwrap().unwrap(), router_id);
    }

    // introducer found in storage
    //
    // start dialing the router and once the connection fails,
    // verify that tha dial failure is reported for the router
    #[tokio::test]
    async fn dial_ssu2_introducer_found_in_storage_dial_fails() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<RouterId>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionFailure {
                    router_id,
                    reason: DialError::Timeout,
                }))
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_router(introducer)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // verify that the introducer is dialed
        assert_eq!(
            timeout!(conn_rx.recv()).await.unwrap().unwrap(),
            introducer_router_id
        );

        // send dial failure for introducer
        event_tx.send(introducer_router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that the introducer is no longer pending nor connected
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(!manager.routers.contains_key(&introducer_router_id));

        // and that the router is no longer pending
        assert!(!manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that subsystem manager is notified of the dial failure
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
        assert!(subsys_rx.try_recv().is_err());
    }

    // introducer found in storage
    //
    // start dialing the introducer and once the connection succeeds,
    // verify that tha dial failure is reported for the router
    #[tokio::test]
    async fn dial_ssu2_introducer_found_in_storage_dial_succeeds() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<RouterId>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                    address: "127.0.0.1:8888".parse().unwrap(),
                    encryption: EncryptionKind::X25519,
                    direction: Direction::Outbound,
                    router_id,
                }))
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, _netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_router(introducer)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // verify that the introducer is dialed
        assert_eq!(
            timeout!(conn_rx.recv()).await.unwrap().unwrap(),
            introducer_router_id
        );

        // send dial success for introducer
        event_tx.send(introducer_router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that the introducer is considered connected
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(manager.routers.contains_key(&introducer_router_id));

        // and that the router is considered pending
        assert!(manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that transport manager started to dial the router
        assert_eq!(timeout!(conn_rx.recv()).await.unwrap().unwrap(), router_id);
    }

    // introducer not found in storage and netdb query is started
    //
    // the query fails and since the router had only a single introducer,
    // the dial fails
    #[tokio::test]
    async fn dial_ssu2_introducer_router_info_query_fails() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<RouterId>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                    address: "127.0.0.1:8888".parse().unwrap(),
                    encryption: EncryptionKind::X25519,
                    direction: Direction::Outbound,
                    router_id,
                }))
            }
        }

        let (_introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (_event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, _conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_queries.contains(&introducer_router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // send query failure back
        match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
            NetDbAction::QueryRouterInfo {
                router_id: target,
                tx,
            } => {
                assert_eq!(target, introducer_router_id);
                tx.send(Err(QueryError::Timeout)).unwrap();
            }
            _ => panic!("unexpected netdb action"),
        }

        let future = {
            futures::future::poll_fn(|cx| loop {
                match manager.poll_unpin(cx) {
                    Poll::Pending => {
                        if !manager.pending_connections.contains_key(&introducer_router_id)
                            && !manager.pending_queries.contains(&introducer_router_id)
                        {
                            return Poll::Ready(());
                        } else {
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(_) => panic!("manager returned"),
                }
            })
        };
        let _: () = timeout!(future).await.unwrap();

        // verify that the introducer is no longer considered pending
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(!manager.pending_queries.contains(&introducer_router_id));

        // and that the router is not considered pending
        assert!(!manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that subsystem manager is notified of the client dial failure
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }

        // since the dial failure originated from transport and not from transport, subsystem
        // manager is notified of the introducer dial failure directly
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, introducer_router_id),
            _ => panic!("invalid event"),
        }
    }

    // introducer not found in storage and netdb query is started
    //
    // router info query succeeds but the subsequent dial of the introducer fails,
    // causing the dial for the original router to fail
    #[tokio::test]
    async fn dial_ssu2_introducer_router_info_query_succeeds_dial_fails() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<RouterId>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionFailure {
                    router_id,
                    reason: DialError::Timeout,
                }))
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        let profile_storage = manager.router_ctx.profile_storage().clone();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_queries.contains(&introducer_router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
            NetDbAction::QueryRouterInfo {
                router_id: target,
                tx,
            } => {
                assert_eq!(target, introducer_router_id);
                profile_storage.add_router(introducer);
                tx.send(Ok(())).unwrap();
            }
            _ => panic!("unexpected netdb action"),
        }

        let future = {
            futures::future::poll_fn(|cx| loop {
                match manager.poll_unpin(cx) {
                    Poll::Pending =>
                        if !manager.pending_queries.contains(&introducer_router_id) {
                            return Poll::Ready(());
                        } else {
                            return Poll::Pending;
                        },
                    Poll::Ready(_) => panic!("manager returned"),
                }
            })
        };
        let _: () = timeout!(future).await.unwrap();

        // verify that the introducer is still pending but no longer has a pending query
        assert!(manager.pending_connections.contains_key(&introducer_router_id));
        assert!(!manager.pending_queries.contains(&introducer_router_id));
        assert!(!manager.routers.contains_key(&introducer_router_id));

        // and that the original router is still pending
        assert!(manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that the introducer is dialed
        assert_eq!(
            timeout!(conn_rx.recv()).await.unwrap().unwrap(),
            introducer_router_id
        );

        // send dial failure for introducer
        event_tx.send(introducer_router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that subsystem manager is notified of the client dial failure
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
    }

    // introducer not found in storage and netdb query is started
    //
    // router info query succeeds and the subsequent dial of the introducer succeeds,
    // causing the client router to be dialed
    #[tokio::test]
    async fn dial_ssu2_introducer_router_info_query_succeeds_dial_succeeds() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<RouterId>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let router_id = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                    address: "127.0.0.1:8888".parse().unwrap(),
                    encryption: EncryptionKind::X25519,
                    direction: Direction::Outbound,
                    router_id,
                }))
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        let profile_storage = manager.router_ctx.profile_storage().clone();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_queries.contains(&introducer_router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
            NetDbAction::QueryRouterInfo {
                router_id: target,
                tx,
            } => {
                assert_eq!(target, introducer_router_id);
                profile_storage.add_router(introducer);
                tx.send(Ok(())).unwrap();
            }
            _ => panic!("unexpected netdb action"),
        }

        let future = {
            futures::future::poll_fn(|cx| loop {
                match manager.poll_unpin(cx) {
                    Poll::Pending =>
                        if !manager.pending_queries.contains(&introducer_router_id) {
                            return Poll::Ready(());
                        } else {
                            return Poll::Pending;
                        },
                    Poll::Ready(_) => panic!("manager returned"),
                }
            })
        };
        let _: () = timeout!(future).await.unwrap();

        // verify that the introducer is still pending but no longer has a pending query
        assert!(manager.pending_connections.contains_key(&introducer_router_id));
        assert!(!manager.pending_queries.contains(&introducer_router_id));
        assert!(!manager.routers.contains_key(&introducer_router_id));

        // and that the original router is still pending
        assert!(manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify that the introducer is dialed
        assert_eq!(
            timeout!(conn_rx.recv()).await.unwrap().unwrap(),
            introducer_router_id
        );

        // send dial success for introducer
        event_tx.send(introducer_router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that the router is dialed
        assert_eq!(timeout!(conn_rx.recv()).await.unwrap().unwrap(), router_id);
    }

    #[tokio::test]
    async fn dial_ssu2_introducer_all_dials_fail() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<Event>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        enum Event {
            Failure(RouterId),
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match futures::ready!(self.event_rx.poll_recv(cx)).unwrap() {
                    Event::Failure(router_id) =>
                        Poll::Ready(Some(TransportEvent::ConnectionFailure {
                            router_id,
                            reason: DialError::Timeout,
                        })),
                }
            }
        }

        let introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 9999,
                        ipv4_host: Some("127.0.0.1".parse().unwrap()),
                        ipv6_host: None,
                        ipv4: true,
                        ipv6: false,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i; 32],
                        intro_key: [0x22 + i; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let mut builder = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }));

        // add all introducers to profile storage
        for (_, introducer) in &introducers {
            builder = builder.with_router(introducer.clone());
        }

        let (mut manager, _netdb_rx, dial_tx, subsys_rx) = builder.build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify all introducers are dialed
        for _ in 0..3 {
            let introducer_router_id = conn_rx.try_recv().unwrap();
            assert!(introducers.contains_key(&introducer_router_id));
        }

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducers.keys().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // verify that all introducers are in the pending introducer context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager.pending_introducers.get(&router_id).unwrap().pending_queries.is_empty());

        // verify that the client router is pending
        assert!(manager.pending_connections.contains_key(&router_id));

        let mut introducers = introducers.into_iter().collect::<Vec<_>>();

        // send dial failures for the first two introducers
        for _ in 0..2 {
            let (introducer_router_id, _) = introducers.pop().unwrap();
            event_tx.send(Event::Failure(introducer_router_id.clone())).await.unwrap();
            futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("manager returned"),
            })
            .await;

            // verify that the introducer is no longer pending or part of `pending_introducers`
            assert!(!manager
                .pending_introducers
                .get(&router_id)
                .unwrap()
                .pending_connections
                .contains(&introducer_router_id));
            assert!(!manager.pending_connections.contains_key(&introducer_router_id));
            assert!(manager.pending_connections.contains_key(&router_id));
        }

        // send dial failure for the last introducer
        let (introducer_router_id, _) = introducers.pop().unwrap();
        event_tx.send(Event::Failure(introducer_router_id.clone())).await.unwrap();
        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;
        assert!(!manager.pending_introducers.contains_key(&router_id));
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(!manager.pending_connections.contains_key(&router_id));

        // verify dial failure is reported for the client router
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn dial_ssu2_introducer_all_dials_succeed() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<Event>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        enum Event {
            Success(RouterId),
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match futures::ready!(self.event_rx.poll_recv(cx)).unwrap() {
                    Event::Success(router_id) =>
                        Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                            address: "127.0.0.1:8888".parse().unwrap(),
                            encryption: EncryptionKind::X25519,
                            direction: Direction::Outbound,
                            router_id,
                        })),
                }
            }
        }

        let introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 9999,
                        ipv4_host: Some("127.0.0.1".parse().unwrap()),
                        ipv6_host: None,
                        ipv4: true,
                        ipv6: false,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i; 32],
                        intro_key: [0x22 + i; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let mut builder = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }));

        // add all introducers to profile storage
        for (_, introducer) in &introducers {
            builder = builder.with_router(introducer.clone());
        }

        let (mut manager, _netdb_rx, dial_tx, _subsys_rx) = builder.build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify all introducers are dialed
        for _ in 0..3 {
            let introducer_router_id = conn_rx.try_recv().unwrap();
            assert!(introducers.contains_key(&introducer_router_id));
        }

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducers.keys().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // verify that all introducers are in the pending introducer context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager.pending_introducers.get(&router_id).unwrap().pending_queries.is_empty());

        // verify that the client router is pending
        assert!(manager.pending_connections.contains_key(&router_id));

        let mut introducers = introducers.into_iter().collect::<Vec<_>>();

        // send dial success for the first introducer
        let (introducer_router_id, _) = introducers.pop().unwrap();
        event_tx.send(Event::Success(introducer_router_id.clone())).await.unwrap();
        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify pending introducer context no longer exist since the client router was dialed
        assert!(!manager.pending_introducers.contains_key(&router_id));
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(manager.routers.contains_key(&introducer_router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // verify the client router is dialed
        assert_eq!(conn_rx.try_recv().unwrap(), router_id);

        // send dial succeses for the remaining introducers
        for (introducer_router_id, _) in introducers {
            event_tx.send(Event::Success(introducer_router_id.clone())).await.unwrap();
            futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("manager returned"),
            })
            .await;

            // verify the pending introducer context is still missing
            assert!(!manager.pending_introducers.contains_key(&router_id));

            // and that the introducer is no considered connected
            assert!(!manager.pending_connections.contains_key(&introducer_router_id));
            assert!(manager.routers.contains_key(&introducer_router_id));

            // and connection for the client router is still pending
            assert!(manager.pending_connections.contains_key(&router_id));

            // and that no more dial requests are sent
            assert!(conn_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn dial_ssu2_introducer_one_dial_succeeds() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<Event>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        enum Event {
            Success(RouterId),
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match futures::ready!(self.event_rx.poll_recv(cx)).unwrap() {
                    Event::Success(router_id) =>
                        Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                            address: "127.0.0.1:8888".parse().unwrap(),
                            encryption: EncryptionKind::X25519,
                            direction: Direction::Outbound,
                            router_id,
                        })),
                }
            }
        }

        let introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 9999,
                        ipv4_host: Some("127.0.0.1".parse().unwrap()),
                        ipv6_host: None,
                        ipv4: true,
                        ipv6: false,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i; 32],
                        intro_key: [0x22 + i; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let mut builder = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }));

        // add all introducers to profile storage
        for (_, introducer) in &introducers {
            builder = builder.with_router(introducer.clone());
        }

        let (mut manager, _netdb_rx, dial_tx, _subsys_rx) = builder.build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify all introducers are dialed
        for _ in 0..3 {
            let introducer_router_id = conn_rx.try_recv().unwrap();
            assert!(introducers.contains_key(&introducer_router_id));
        }

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducers.keys().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // verify that all introducers are in the pending introducer context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager.pending_introducers.get(&router_id).unwrap().pending_queries.is_empty());

        // verify that the client router is pending
        assert!(manager.pending_connections.contains_key(&router_id));

        let mut introducers = introducers.into_iter().collect::<Vec<_>>();

        // send dial success for the first introducer
        let (introducer_router_id, _) = introducers.pop().unwrap();
        event_tx.send(Event::Success(introducer_router_id.clone())).await.unwrap();
        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify pending introducer context no longer exist since the client router was dialed
        assert!(!manager.pending_introducers.contains_key(&router_id));
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(manager.routers.contains_key(&introducer_router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // verify the client router is dialed
        assert_eq!(conn_rx.try_recv().unwrap(), router_id);

        // send dial succeses for the remaining introducers
        for (introducer_router_id, _) in introducers {
            event_tx.send(Event::Success(introducer_router_id.clone())).await.unwrap();
            futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("manager returned"),
            })
            .await;

            // verify the pending introducer context is still missing
            assert!(!manager.pending_introducers.contains_key(&router_id));

            // and that the introducer is no considered connected
            assert!(!manager.pending_connections.contains_key(&introducer_router_id));
            assert!(manager.routers.contains_key(&introducer_router_id));

            // and connection for the client router is still pending
            assert!(manager.pending_connections.contains_key(&router_id));

            // and that no more dial requests are sent
            assert!(conn_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn dial_ssu2_all_queries_fail() {
        pub struct MockTransport {
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        let mut introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 9999,
                        ipv4_host: Some("127.0.0.1".parse().unwrap()),
                        ipv6_host: None,
                        ipv4: true,
                        ipv6: false,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i; 32],
                        intro_key: [0x22 + i; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let (conn_tx, _conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { conn_tx }))
            .build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify all introducers are in the pending query context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_queries
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .is_empty());
        assert!(introducers.keys().all(|key| manager.pending_connections.contains_key(key)));
        assert!(introducers.keys().all(|key| manager.pending_queries.contains(key)));

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducers.keys().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // send router info query failure for the first two introducers
        for _ in 0..2 {
            let introducer = match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
                NetDbAction::QueryRouterInfo {
                    tx,
                    router_id: target,
                } => {
                    tx.send(Err(QueryError::Timeout)).unwrap();
                    target
                }
                _ => panic!("unexpected netdb action"),
            };

            let future = {
                futures::future::poll_fn(|cx| loop {
                    match manager.poll_unpin(cx) {
                        Poll::Pending =>
                            if !manager.pending_queries.contains(&introducer) {
                                return Poll::Ready(());
                            } else {
                                return Poll::Pending;
                            },
                        Poll::Ready(_) => panic!("manager returned"),
                    }
                })
            };
            let _: () = timeout!(future).await.unwrap();

            // verify the introducer is no longer tracked in any context
            assert!(!manager
                .pending_introducers
                .get(&router_id)
                .unwrap()
                .pending_queries
                .contains(&introducer));
            assert!(!manager
                .pending_introducers
                .get(&router_id)
                .unwrap()
                .pending_connections
                .contains(&introducer));
            assert!(!manager.pending_connections.contains_key(&introducer));
            assert!(!manager.pending_queries.contains(&introducer));

            // verify dial failure is reported to the subsystem manager
            match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
                SubsystemEvent::ConnectionFailure { router_id: remote } =>
                    assert_eq!(remote, introducer),
                _ => panic!("invalid event"),
            }
            introducers.remove(&introducer);
        }

        // send router info query failure for the last introducer
        let introducer = match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
            NetDbAction::QueryRouterInfo {
                tx,
                router_id: target,
            } => {
                tx.send(Err(QueryError::Timeout)).unwrap();
                target
            }
            _ => panic!("unexpected netdb action"),
        };

        let future = {
            futures::future::poll_fn(|cx| loop {
                match manager.poll_unpin(cx) {
                    Poll::Pending =>
                        if !manager.pending_queries.contains(&introducer) {
                            return Poll::Ready(());
                        } else {
                            return Poll::Pending;
                        },
                    Poll::Ready(_) => panic!("manager returned"),
                }
            })
        };
        let _: () = timeout!(future).await.unwrap();

        // verify that there is no pending context for the introducer or the router
        assert!(!manager.pending_introducers.contains_key(&router_id));
        assert!(!manager.pending_connections.contains_key(&introducer));
        assert!(!manager.pending_queries.contains(&introducer));
        assert!(!manager.pending_connections.contains_key(&router_id));
        assert!(!manager.pending_queries.contains(&router_id));

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert!(introducers.remove(&remote).is_some()),
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn dial_ssu2_all_queries_succeed_all_dials_fail() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<Event>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        enum Event {
            Failure(RouterId),
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match futures::ready!(self.event_rx.poll_recv(cx)).unwrap() {
                    Event::Failure(router_id) =>
                        Poll::Ready(Some(TransportEvent::ConnectionFailure {
                            router_id,
                            reason: DialError::Timeout,
                        })),
                }
            }
        }

        let introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 9999,
                        ipv4_host: Some("127.0.0.1".parse().unwrap()),
                        ipv6_host: None,
                        ipv4: true,
                        ipv6: false,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i; 32],
                        intro_key: [0x22 + i; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        let storage = manager.router_ctx.profile_storage().clone();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify all introducers are in the pending query context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_queries
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .is_empty());
        assert!(introducers.keys().all(|key| manager.pending_connections.contains_key(key)));
        assert!(introducers.keys().all(|key| manager.pending_queries.contains(key)));

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducers.keys().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // send query successes for all queries
        for _ in 0..3 {
            match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
                NetDbAction::QueryRouterInfo {
                    tx,
                    router_id: target,
                } => {
                    tx.send(Ok(())).unwrap();
                    storage.add_router(introducers.get(&target).unwrap().clone());
                }
                _ => panic!("unexpected netdb action"),
            }
        }

        let future = {
            futures::future::poll_fn(|cx| loop {
                match manager.poll_unpin(cx) {
                    Poll::Pending =>
                        if manager.pending_queries.is_empty() {
                            return Poll::Ready(());
                        } else {
                            return Poll::Pending;
                        },
                    Poll::Ready(_) => panic!("manager returned"),
                }
            })
        };
        let _: () = timeout!(future).await.unwrap();

        // verify that all introducers have transitioned to pending
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager.pending_introducers.get(&router_id).unwrap().pending_queries.is_empty());

        // send dial failures for each of the introducers
        for _ in 0..3 {
            let introducer = conn_rx.try_recv().unwrap();
            event_tx.send(Event::Failure(introducer)).await.unwrap();
        }

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that there is no pending context for the introducer or the router
        assert!(!manager.pending_introducers.contains_key(&router_id));
        assert!(!manager.pending_queries.contains(&router_id));
        assert!(manager.pending_connections.is_empty());

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn dial_ssu2_all_queries_succeed_all_dials_succeed() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<Event>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        enum Event {
            Success(RouterId),
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match futures::ready!(self.event_rx.poll_recv(cx)).unwrap() {
                    Event::Success(router_id) =>
                        Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                            address: "127.0.0.1:8888".parse().unwrap(),
                            encryption: EncryptionKind::X25519,
                            direction: Direction::Outbound,
                            router_id,
                        })),
                }
            }
        }

        let introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 9999,
                        ipv4_host: Some("127.0.0.1".parse().unwrap()),
                        ipv6_host: None,
                        ipv4: true,
                        ipv6: false,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i; 32],
                        intro_key: [0x22 + i; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, netdb_rx, dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        let storage = manager.router_ctx.profile_storage().clone();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify all introducers are in the pending query context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_queries
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .is_empty());
        assert!(introducers.keys().all(|key| manager.pending_connections.contains_key(key)));
        assert!(introducers.keys().all(|key| manager.pending_queries.contains(key)));

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducers.keys().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // send query successes for all queries
        for _ in 0..3 {
            match timeout!(netdb_rx.recv()).await.unwrap().unwrap() {
                NetDbAction::QueryRouterInfo {
                    tx,
                    router_id: target,
                } => {
                    tx.send(Ok(())).unwrap();
                    storage.add_router(introducers.get(&target).unwrap().clone());
                }
                _ => panic!("unexpected netdb action"),
            }
        }

        let future = {
            futures::future::poll_fn(|cx| loop {
                match manager.poll_unpin(cx) {
                    Poll::Pending =>
                        if manager.pending_queries.is_empty() {
                            return Poll::Ready(());
                        } else {
                            return Poll::Pending;
                        },
                    Poll::Ready(_) => panic!("manager returned"),
                }
            })
        };
        let _: () = timeout!(future).await.unwrap();

        // verify that all introducers have transitioned to pending
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .iter()
            .all(|key| introducers.contains_key(key)));
        assert!(manager.pending_introducers.get(&router_id).unwrap().pending_queries.is_empty());

        // send dial success for each of the introducers
        for _ in 0..3 {
            let introducer = conn_rx.try_recv().unwrap();
            event_tx.send(Event::Success(introducer)).await.unwrap();
        }

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        assert!(introducers.keys().all(|key| manager.routers.contains_key(key)));
        assert_eq!(manager.pending_connections.len(), 1);
        assert!(manager.pending_connections.contains_key(&router_id));
        assert!(manager.pending_introducers.is_empty());
        assert!(manager.pending_queries.is_empty());

        // verify the client router is dialed
        assert_eq!(conn_rx.try_recv().unwrap(), router_id);
    }

    struct NoopTransport {}

    impl Transport for NoopTransport {
        fn connect(&mut self, _: RouterInfo) {}
        fn accept(&mut self, _: &RouterId) {}
        fn reject(&mut self, _: &RouterId) {}
    }

    impl Stream for NoopTransport {
        type Item = TransportEvent;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn publish_router_info_transit_tunnels_disabled_reachable() {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_transit_tunnels_disabled()
            .build();

        manager.on_firewall_status(FirewallStatus::Ok, true);
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LGR"))
                );
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_transit_tunnels_disabled_unreachable() {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_transit_tunnels_disabled()
            .build();

        manager.on_firewall_status(FirewallStatus::SymmetricNat, true);
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LGU"))
                );
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_transit_tunnels_disabled_unknown_status() {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_transit_tunnels_disabled()
            .build();

        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LG"))
                );
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_unknown_firewall_status_ipv4() {
        publish_router_info_unknown_firewall_status(true).await
    }

    #[tokio::test]
    async fn publish_router_info_unknown_firewall_status_ipv6() {
        publish_router_info_unknown_firewall_status(false).await
    }

    async fn publish_router_info_unknown_firewall_status(ipv4: bool) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .build();

        // since firewall status is unknown so the address is not published
        if ipv4 {
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.add_external_address("::1".parse().unwrap());
        }
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("L"))
                );
                assert!(router_info.addresses.iter().all(|address| match address {
                    RouterAddress::Ntcp2 {
                        socket_address,
                        options,
                        ..
                    }
                    | RouterAddress::Ssu2 {
                        options,
                        socket_address,
                        ..
                    } =>
                        socket_address.is_none()
                            && options.get(&Str::from("host")).is_none()
                            && options.get(&Str::from("port")).is_none(),
                }));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_ok_after_external_address_discovery() {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .build();

        // external address is discovered before the firewall status is known so
        // the ntcp2 address is not published yet
        manager.add_external_address("127.0.0.1".parse().unwrap());

        // firewall status is later determined to be Ok which must publish the
        // previously-discovered ntcp2 address
        manager.on_firewall_status(FirewallStatus::Ok, true);
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LR"))
                );
                assert!(router_info.addresses.iter().any(|address| match address {
                    RouterAddress::Ntcp2 { options, .. } =>
                        options.get(&Str::from("host")) == Some(&Str::from("127.0.0.1"))
                            && options.get(&Str::from("port")).is_some()
                            && options.get(&Str::from("i")).is_some(),
                    _ => false,
                }));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_symnat_ipv4() {
        publish_router_info_symnat(true).await;
    }

    #[tokio::test]
    async fn publish_router_info_symnat_ipv6() {
        publish_router_info_symnat(false).await;
    }

    async fn publish_router_info_symnat(ipv4: bool) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .build();

        // since firewall status is symnat so the address is not published
        manager.on_firewall_status(FirewallStatus::SymmetricNat, ipv4);

        if ipv4 {
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.add_external_address("::1".parse().unwrap());
        }

        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LU"))
                );
                assert!(router_info.addresses.iter().all(|address| match address {
                    RouterAddress::Ntcp2 {
                        socket_address,
                        options,
                        ..
                    }
                    | RouterAddress::Ssu2 {
                        options,
                        socket_address,
                        ..
                    } =>
                        socket_address.is_none()
                            && options.get(&Str::from("host")).is_none()
                            && options.get(&Str::from("port")).is_none(),
                }));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_firewalled_ipv4() {
        publish_router_info_firewalled(true).await;
    }

    #[tokio::test]
    async fn publish_router_info_firewalled_ipv6() {
        publish_router_info_firewalled(false).await;
    }

    async fn publish_router_info_firewalled(ipv4: bool) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .build();

        // since firewall status is firewalled so the address is not published
        manager.on_firewall_status(FirewallStatus::Firewalled, ipv4);

        if ipv4 {
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.add_external_address("::1".parse().unwrap());
        }

        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LU"))
                );
                assert!(router_info.addresses.iter().all(|address| match address {
                    RouterAddress::Ntcp2 {
                        socket_address,
                        options,
                        ..
                    }
                    | RouterAddress::Ssu2 {
                        options,
                        socket_address,
                        ..
                    } =>
                        socket_address.is_none()
                            && options.get(&Str::from("host")).is_none()
                            && options.get(&Str::from("port")).is_none(),
                }));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_not_firewalled_ipv4() {
        publish_router_info_not_firewalled(true).await;
    }

    #[tokio::test]
    async fn publish_router_info_not_firewalled_ipv6() {
        publish_router_info_not_firewalled(false).await;
    }

    async fn publish_router_info_not_firewalled(ipv4: bool) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .with_ipv6(!ipv4)
            .build();

        // since firewall status is ok so the addresses are published
        manager.on_firewall_status(FirewallStatus::Ok, ipv4);

        if ipv4 {
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.add_external_address("::1".parse().unwrap());
        }

        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LR"))
                );

                assert!(router_info.addresses.iter().all(|address| match address {
                    RouterAddress::Ntcp2 {
                        socket_address,
                        options,
                        ..
                    }
                    | RouterAddress::Ssu2 {
                        options,
                        socket_address,
                        ..
                    } =>
                        socket_address.is_some()
                            && options.get(&Str::from("host")).is_some()
                            && options.get(&Str::from("port")).is_some(),
                }));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_overriden_capabilities() {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_transit_tunnels_disabled()
            .with_caps("XfR".to_string())
            .build();

        manager.on_firewall_status(FirewallStatus::SymmetricNat, true);
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();

                // caps should be `LGU` but they were overriden by user
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("XfR"))
                );
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn address_discovered_and_modified_ipv4() {
        address_discovered_and_modified(true).await;
    }

    #[tokio::test]
    async fn address_discovered_and_modified_ipv6() {
        address_discovered_and_modified(false).await;
    }

    async fn address_discovered_and_modified(ipv4: bool) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .with_both()
            .build();

        // since firewall status is ok so the addresses are published
        //
        // but only one of ipv4/ipv6 external address is added and the other
        // address will remain unpublished
        manager.on_firewall_status(FirewallStatus::Ok, ipv4);

        if ipv4 {
            manager.add_external_address("127.0.0.1".parse().unwrap());
        } else {
            manager.add_external_address("::1".parse().unwrap());
        }

        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                assert_eq!(
                    router_info.options.get(&Str::from("caps")),
                    Some(&Str::from("LR"))
                );

                // verify there's 1 published ipv4 address and 1 unpublished ipv6 address
                if ipv4 {
                    assert_eq!(
                        router_info
                            .addresses
                            .iter()
                            .filter(|address| match address {
                                RouterAddress::Ntcp2 { socket_address, .. } =>
                                    socket_address.map_or(false, |address| address.is_ipv4()),
                                RouterAddress::Ssu2 { .. } => unreachable!(),
                            })
                            .count(),
                        1
                    );
                    assert_eq!(
                        router_info
                            .addresses
                            .iter()
                            .filter(|address| match address {
                                RouterAddress::Ntcp2 { socket_address, .. } =>
                                    socket_address.map_or(false, |address| address.is_ipv6()),
                                RouterAddress::Ssu2 { .. } => unreachable!(),
                            })
                            .count(),
                        0
                    );
                } else {
                    // verify there's 1 published ipv6 address and 1 unpublished ipv4 address
                    assert_eq!(
                        router_info
                            .addresses
                            .iter()
                            .filter(|address| match address {
                                RouterAddress::Ntcp2 { socket_address, .. } =>
                                    socket_address.map_or(false, |address| address.is_ipv6()),
                                RouterAddress::Ssu2 { .. } => unreachable!(),
                            })
                            .count(),
                        1
                    );
                    assert_eq!(
                        router_info
                            .addresses
                            .iter()
                            .filter(|address| match address {
                                RouterAddress::Ntcp2 { socket_address, .. } =>
                                    socket_address.map_or(false, |address| address.is_ipv4()),
                                RouterAddress::Ssu2 { .. } => unreachable!(),
                            })
                            .count(),
                        0
                    );
                }

                assert!(router_info.addresses.iter().all(|address| match address {
                    RouterAddress::Ssu2 { .. } => unreachable!(),
                    RouterAddress::Ntcp2 {
                        socket_address,
                        options,
                        ..
                    } => {
                        if ipv4 {
                            match socket_address {
                                Some(address) =>
                                    address.is_ipv4()
                                        && options.get(&Str::from("host")).is_some()
                                        && options.get(&Str::from("port")).is_some(),
                                _ =>
                                    options.get(&Str::from("host")).is_none()
                                        && options.get(&Str::from("port")).is_none(),
                            }
                        } else {
                            match socket_address {
                                Some(address) =>
                                    address.is_ipv6()
                                        && options.get(&Str::from("host")).is_some()
                                        && options.get(&Str::from("port")).is_some(),
                                _ =>
                                    options.get(&Str::from("host")).is_none()
                                        && options.get(&Str::from("port")).is_none(),
                            }
                        }
                    }
                }));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn introducer_transport_mismatch_ipv4() {
        introducer_transport_mismatch(true).await
    }

    #[tokio::test]
    async fn introducer_transport_mismatch_ipv6() {
        introducer_transport_mismatch(false).await
    }

    async fn introducer_transport_mismatch(ipv4: bool) {
        pub struct MockTransport {}

        impl Transport for MockTransport {
            fn connect(&mut self, _: RouterInfo) {}
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        // introducers support only either ipv4 or ipv6
        let introducers = (0..3)
            .map(|i| {
                let (introducer, _, sigkey) = RouterInfoBuilder::default()
                    .with_ssu2(Ssu2Config {
                        max_connections: None,
                        ml_kem: None,
                        disable_pq: false,
                        port: 8888 + i,
                        ipv4_host: (!ipv4).then_some("127.0.0.1".parse().unwrap()),
                        ipv6_host: ipv4.then_some("::1".parse().unwrap()),
                        ipv4: !ipv4,
                        ipv6: ipv4,
                        publish_ipv4: true,
                        publish_ipv6: true,
                        static_key: [0x11 + i as u8; 32],
                        intro_key: [0x22 + i as u8; 32],
                        ipv4_mtu: None,
                        ipv6_mtu: None,
                    })
                    .build();

                (
                    introducer.identity.id(),
                    RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        // the router we're attempting to dial support both ipv4 and ipv6
        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: Some("::1".parse().unwrap()),
                    ipv4: true,
                    ipv6: true,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 {
                introducers: router_introducers,
                ..
            } =>
                for (i, (introducer_router_id, _)) in introducers.iter().enumerate() {
                    router_introducers.push((introducer_router_id.clone(), 1337 + i as u32));
                },
            _ => panic!("expected ssu2"),
        }

        let mut builder = TestContextBuilder::default()
            .with_router(router_info)
            .with_ipv6(!ipv4)
            .with_ssu2(Box::new(MockTransport {}));

        // add all introducers to profile storage
        for (_, introducer) in &introducers {
            builder = builder.with_router(introducer.clone());
        }

        let (mut manager, _netdb_rx, dial_tx, subsys_rx) = builder.build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn introducer_transport_mixed_ipv4() {
        introducer_transport_mixed(true).await
    }

    #[tokio::test]
    async fn introducer_transport_mixed_ipv6() {
        introducer_transport_mixed(false).await
    }

    async fn introducer_transport_mixed(ipv4: bool) {
        pub struct MockTransport {
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }

        // first introducer is over ipv4 and the second is over ipv6
        let ipv4_introducer = ipv4.then(|| {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                introducer.identity.id(),
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
            )
        });
        let ipv6_introducer = (!ipv4).then(|| {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: None,
                    ipv6_host: Some("::1".parse().unwrap()),
                    ipv4: false,
                    ipv6: true,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                introducer.identity.id(),
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
            )
        });

        // the router that's being dialed supports both ipv4 and ipv6
        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: true,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        let mut introducer_router_infos = vec![];

        if let Some((introducer, introducer_router_info)) = &ipv4_introducer {
            match router_info.addresses.get_mut(0).unwrap() {
                RouterAddress::Ssu2 {
                    introducers: router_introducers,
                    ..
                } => {
                    router_introducers.push((introducer.clone(), 1337));
                    introducer_router_infos.push(introducer_router_info.clone());
                }
                _ => panic!("expected ssu2"),
            }
        }

        if let Some((introducer, introducer_router_info)) = &ipv6_introducer {
            match router_info.addresses.get_mut(1).unwrap() {
                RouterAddress::Ssu2 {
                    introducers: router_introducers,
                    ..
                } => {
                    router_introducers.push((introducer.clone(), 1338));
                    introducer_router_infos.push(introducer_router_info.clone());
                }
                _ => panic!("expected ssu2"),
            }
        }

        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let mut builder = TestContextBuilder::default()
            .with_router(router_info)
            .with_ssu2(Box::new(MockTransport { conn_tx }));

        builder = match ipv4 {
            true => builder,
            false => builder.with_ipv6(true),
        };

        // add all introducers to profile storage
        for introducer in introducer_router_infos {
            builder = builder.with_router(introducer);
        }

        let (mut manager, _netdb_rx, dial_tx, _subsys_rx) = builder.build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        let introducer_ids = match ipv4 {
            // ipv4, only the first introducer is dialed
            true => {
                let introducer_router_id = conn_rx.try_recv().unwrap();
                assert_eq!(introducer_router_id, ipv4_introducer.unwrap().0);
                assert!(conn_rx.try_recv().is_err());

                vec![introducer_router_id]
            }

            // ipv6 only the second introducer is dialed
            false => {
                let introducer_router_id = conn_rx.try_recv().unwrap();
                assert_eq!(introducer_router_id, ipv6_introducer.unwrap().0);
                assert!(conn_rx.try_recv().is_err());

                vec![introducer_router_id]
            }
        };

        // verify that all introducers are being dialed and that the router
        // is tracked in their dial context
        assert!(introducer_ids.iter().all(|introducer_id| {
            match manager.pending_connections.get(introducer_id) {
                Some(routers) => routers.iter().any(|client| client == &router_id),
                None => false,
            }
        }));

        // verify that all introducers are in the pending introducer context
        assert!(manager
            .pending_introducers
            .get(&router_id)
            .unwrap()
            .pending_connections
            .iter()
            .all(|key| introducer_ids.contains(key)));
        assert!(manager.pending_introducers.get(&router_id).unwrap().pending_queries.is_empty());
    }

    #[tokio::test]
    async fn publish_router_info_low_congestion() {
        publish_router_info_with_congestion(CongestionLevel::Low).await;
    }

    #[tokio::test]
    async fn publish_router_info_medium_congestion() {
        publish_router_info_with_congestion(CongestionLevel::Medium).await;
    }

    #[tokio::test]
    async fn publish_router_info_high_congestion() {
        publish_router_info_with_congestion(CongestionLevel::High).await;
    }

    async fn publish_router_info_with_congestion(congestion: CongestionLevel) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .build();

        manager.on_firewall_status(FirewallStatus::Ok, true);
        manager.add_external_address("127.0.0.1".parse().unwrap());
        manager.congestion.store(congestion);
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();

                match congestion {
                    CongestionLevel::Low => assert_eq!(
                        router_info.options.get(&Str::from("caps")),
                        Some(&Str::from("LR"))
                    ),
                    CongestionLevel::Medium => assert_eq!(
                        router_info.options.get(&Str::from("caps")),
                        Some(&Str::from("LRD"))
                    ),
                    CongestionLevel::High => assert_eq!(
                        router_info.options.get(&Str::from("caps")),
                        Some(&Str::from("LRE"))
                    ),
                }
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn publish_router_info_class_k() {
        publish_router_info_with_bandwidth_class(Bandwidth::K).await;
    }

    #[tokio::test]
    async fn publish_router_info_class_l() {
        publish_router_info_with_bandwidth_class(Bandwidth::L).await;
    }

    #[tokio::test]
    async fn publish_router_info_class_m() {
        publish_router_info_with_bandwidth_class(Bandwidth::M).await;
    }

    #[tokio::test]
    async fn publish_router_info_class_n() {
        publish_router_info_with_bandwidth_class(Bandwidth::N).await;
    }

    #[tokio::test]
    async fn publish_router_info_class_o() {
        publish_router_info_with_bandwidth_class(Bandwidth::O).await;
    }

    #[tokio::test]
    async fn publish_router_info_class_p() {
        publish_router_info_with_bandwidth_class(Bandwidth::P).await;
    }

    #[tokio::test]
    async fn publish_router_info_class_x() {
        publish_router_info_with_bandwidth_class(Bandwidth::X).await;
    }

    async fn publish_router_info_with_bandwidth_class(bandwidth: Bandwidth) {
        let (router_info, ..) = RouterInfoBuilder::default().build();
        let (mut manager, netdb_rx, _dial_tx, _subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_ntcp2(Box::new(NoopTransport {}))
            .with_publish()
            .build();

        manager.on_firewall_status(FirewallStatus::Ok, true);
        manager.add_external_address("127.0.0.1".parse().unwrap());
        manager.congestion = Congestion::new(bandwidth);
        manager.publish_router_info();

        match netdb_rx.try_recv().unwrap() {
            NetDbAction::PublishRouterInfo { router_info, .. } => {
                let router_info = RouterInfo::parse::<MockRuntime>(&router_info).unwrap();
                let caps: Str = router_info.options.get(&Str::from("caps")).unwrap().clone();
                assert!((*caps).contains(&*Str::from(bandwidth)));
            }
            _ => panic!("unexpected action"),
        }
    }

    // dialing the introducer succeeds but then there's relay failure,
    // preventing a connection to the target router
    #[tokio::test]
    async fn dial_ssu2_introducer_client_dial_fails() {
        pub struct MockTransport {
            event_rx: tokio::sync::mpsc::Receiver<(RouterId, bool)>,
            conn_tx: tokio::sync::mpsc::Sender<RouterId>,
        }

        impl Transport for MockTransport {
            fn connect(&mut self, router_info: RouterInfo) {
                self.conn_tx.try_send(router_info.identity.id()).unwrap();
            }
            fn accept(&mut self, _: &RouterId) {}
            fn reject(&mut self, _: &RouterId) {}
        }

        impl Stream for MockTransport {
            type Item = TransportEvent;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let (router_id, success) = futures::ready!(self.event_rx.poll_recv(cx)).unwrap();

                if success {
                    Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        address: "127.0.0.1:8888".parse().unwrap(),
                        encryption: EncryptionKind::X25519,
                        direction: Direction::Outbound,
                        router_id,
                    }))
                } else {
                    Poll::Ready(Some(TransportEvent::ConnectionFailure {
                        router_id,
                        reason: DialError::RelayFailure,
                    }))
                }
            }
        }

        let (introducer, introducer_router_id) = {
            let (introducer, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 9999,
                    ipv4_host: Some("127.0.0.1".parse().unwrap()),
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: true,
                    publish_ipv6: true,
                    static_key: [0x11; 32],
                    intro_key: [0x22; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(introducer.serialize(&sigkey)).unwrap(),
                introducer.identity.id(),
            )
        };

        let (mut router_info, router_id) = {
            let (router_info, _, sigkey) = RouterInfoBuilder::default()
                .with_ssu2(Ssu2Config {
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                    port: 10000,
                    ipv4_host: None,
                    ipv6_host: None,
                    ipv4: true,
                    ipv6: false,
                    publish_ipv4: false,
                    publish_ipv6: false,
                    static_key: [0x33; 32],
                    intro_key: [0x44; 32],
                    ipv4_mtu: None,
                    ipv6_mtu: None,
                })
                .build();

            (
                RouterInfo::parse::<MockRuntime>(router_info.serialize(&sigkey)).unwrap(),
                router_info.identity.id(),
            )
        };

        // add introducer for `router_info`
        match router_info.addresses.get_mut(0).unwrap() {
            RouterAddress::Ssu2 { introducers, .. } => {
                introducers.push((introducer_router_id.clone(), 1337));
            }
            _ => panic!("expected ssu2"),
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(16);

        let (mut manager, _netdb_rx, dial_tx, subsys_rx) = TestContextBuilder::default()
            .with_router(router_info)
            .with_router(introducer)
            .with_ssu2(Box::new(MockTransport { event_rx, conn_tx }))
            .build();

        // send dial request for router that needs relay
        dial_tx.send(router_id.clone()).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that router is tracked in introducer's pending context
        //
        // also verify the router has a pending connection
        assert!(manager
            .pending_connections
            .get(&introducer_router_id)
            .unwrap()
            .iter()
            .any(|client| client == &router_id));
        assert!(manager.pending_connections.contains_key(&router_id));

        // verify that the introducer is dialed
        assert_eq!(
            timeout!(conn_rx.recv()).await.unwrap().unwrap(),
            introducer_router_id
        );

        // send dial success for introducer
        event_tx.send((introducer_router_id.clone(), true)).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that the introducer is no longer pending but connected
        assert!(!manager.pending_connections.contains_key(&introducer_router_id));
        assert!(manager.routers.contains_key(&introducer_router_id));

        // and that the router is still pending
        assert!(manager.pending_connections.contains_key(&router_id));
        assert!(!manager.routers.contains_key(&router_id));

        // verify the router is dialed now that the introducer is connected
        assert_eq!(timeout!(conn_rx.recv()).await.unwrap().unwrap(), router_id);

        // send dial failure for the router
        event_tx.send((router_id.clone(), false)).await.unwrap();

        futures::future::poll_fn(|cx| match manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("manager returned"),
        })
        .await;

        // verify that subsystem manager is notified of the dial failure
        match timeout!(subsys_rx.recv()).await.unwrap().unwrap() {
            SubsystemEvent::ConnectionFailure { router_id: remote } =>
                assert_eq!(remote, router_id),
            _ => panic!("invalid event"),
        }
        assert!(subsys_rx.try_recv().is_err());
    }
}
