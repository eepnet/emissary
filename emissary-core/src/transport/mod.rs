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
    events::EventHandle,
    netdb::NetDbHandle,
    primitives::{Date, RouterAddress, RouterId, RouterInfo, Str, TransportKind},
    router::context::RouterContext,
    runtime::{Counter, Gauge, JoinSet, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transport::{metrics::*, ntcp2::Ntcp2Context, ssu2::Ssu2Context},
    Ntcp2Config, Ssu2Config,
};

use bytes::Bytes;
use futures::{FutureExt, Stream, StreamExt};
use hashbrown::HashSet;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod metrics;
mod ntcp2;
mod ssu2;

pub use ntcp2::Ntcp2Transport;
pub use ssu2::Ssu2Transport;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::transport-manager";

/// Local [`RouterInfo`] republish interval.
///
/// Local router info gets republished to `NetDb` every 15 minutes.
const ROUTER_INFO_REPUBLISH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Termination reason.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum TerminationReason {
    /// Unspecified or normal termination.
    #[default]
    Unspecified,

    /// Termination block was received.
    TerminationReceived,

    /// Idle timeout.
    IdleTimeout,

    /// Socket was closed (NTCP2 only).
    IoError,

    /// Router is shutting down.
    RouterShutdown,

    /// AEAD failure.
    AeadFailure,

    /// Incompatible options,
    IncompatibleOptions,

    /// Unsupported signature kind.
    IncompatibleSignatureKind,

    /// Clock skew.
    ClockSkew,

    /// Padding violation.
    PaddinViolation,

    /// Payload format error.
    PayloadFormatError,

    /// AEAD framing error.
    AeadFramingError,

    /// NTCP2 handshake error.
    Ntcp2HandshakeError(u8),

    /// SSU2 handshake error.
    Ssu2HandshakeError(u8),

    /// Intra frame timeout.
    IntraFrameReadTimeout,

    /// Invalid router info.
    InvalidRouterInfo,

    /// Router has been banned.
    Banned,

    /// Timeout (SSU2 only)
    Timeout,

    /// Bad token (SSU2 only).
    BadToken,

    /// Connection limit reached (SSU2 only)
    ConnectionLimits,

    /// Incompatible version (SSU2 only)
    IncompatibleVersion,

    /// Wrong network ID (SSU2 only)
    WrongNetId,

    /// Replaced by new session (SSU2 only)
    ReplacedByNewSession,
}

impl TerminationReason {
    /// Get [`TerminationReason`] from an NTCP2 termination reason.
    pub fn ntcp2(value: u8) -> Self {
        match value {
            0 => TerminationReason::Unspecified,
            1 => TerminationReason::TerminationReceived,
            2 => TerminationReason::IdleTimeout,
            3 => TerminationReason::RouterShutdown,
            4 => TerminationReason::AeadFailure,
            5 => TerminationReason::IncompatibleOptions,
            6 => TerminationReason::IncompatibleSignatureKind,
            7 => TerminationReason::ClockSkew,
            8 => TerminationReason::PaddinViolation,
            9 => TerminationReason::AeadFramingError,
            10 => TerminationReason::PayloadFormatError,
            11 => TerminationReason::Ntcp2HandshakeError(1),
            12 => TerminationReason::Ntcp2HandshakeError(2),
            13 => TerminationReason::Ntcp2HandshakeError(3),
            14 => TerminationReason::IntraFrameReadTimeout,
            15 => TerminationReason::InvalidRouterInfo,
            16 => TerminationReason::InvalidRouterInfo,
            17 => TerminationReason::Banned,
            _ => TerminationReason::Unspecified,
        }
    }

    /// Get [`TerminationReason`] from an SSU2 termination reason.
    pub fn ssu2(value: u8) -> Self {
        match value {
            0 => TerminationReason::Unspecified,
            1 => TerminationReason::TerminationReceived,
            2 => TerminationReason::IdleTimeout,
            3 => TerminationReason::RouterShutdown,
            4 => TerminationReason::AeadFailure,
            5 => TerminationReason::IncompatibleOptions,
            6 => TerminationReason::IncompatibleSignatureKind,
            7 => TerminationReason::ClockSkew,
            8 => TerminationReason::PaddinViolation,
            9 => TerminationReason::AeadFramingError,
            10 => TerminationReason::PayloadFormatError,
            11 => TerminationReason::Ssu2HandshakeError(1),
            12 => TerminationReason::Ssu2HandshakeError(2),
            13 => TerminationReason::Ssu2HandshakeError(3),
            14 => TerminationReason::IntraFrameReadTimeout,
            15 => TerminationReason::InvalidRouterInfo,
            16 => TerminationReason::InvalidRouterInfo,
            17 => TerminationReason::Banned,
            18 => TerminationReason::BadToken,
            19 => TerminationReason::ConnectionLimits,
            20 => TerminationReason::IncompatibleVersion,
            21 => TerminationReason::WrongNetId,
            22 => TerminationReason::ReplacedByNewSession,
            _ => TerminationReason::Unspecified,
        }
    }
}

/// Direction of the connection.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// Inbound connection.
    Inbound,

    /// Outbound connection.
    Outbound,
}

/// Transport event.
#[derive(Debug)]
pub enum TransportEvent {
    /// Connection successfully established to router.
    ConnectionEstablished {
        /// Is this an outbound or an inbound connection.
        direction: Direction,

        /// ID of the connected router.
        router_id: RouterId,
    },

    /// Connection closed to router.
    ConnectionClosed {
        /// ID of the disconnected router.
        router_id: RouterId,

        /// Reason for the termination.
        reason: TerminationReason,
    },

    /// Failed to dial peer.
    ///
    /// The connection is considered failed if we failed to reach the router
    /// or if there was an error during handshaking.
    ConnectionFailure {
        /// ID of the remote router.
        router_id: RouterId,
    },
}

/// Transport interface.
pub trait Transport: Stream + Unpin + Send {
    /// Connect to `router`.
    fn connect(&mut self, router: RouterInfo);

    /// Accept connection and start its event loop.
    fn accept(&mut self, router: &RouterId);

    /// Reject connection.
    fn reject(&mut self, router: &RouterId);
}

/// Builder for [`TransportManager`].
pub struct TransportManagerBuilder<R: Runtime> {
    /// Allow local addresses.
    allow_local: bool,

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
    ) -> Self {
        Self {
            allow_local,
            dial_rx,
            local_router_info,
            netdb_handle: None,
            ntcp2_config: None,
            router_ctx,
            ssu2_config: None,
            transit_tunnels_disabled: false,
            transports: Vec::with_capacity(2),
            transport_tx,
        }
    }

    /// Register NTCP2 as an active transport.
    pub fn register_ntcp2(&mut self, context: Ntcp2Context<R>) {
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

    /// Build into [`TransportManager`].
    pub fn build(self) -> TransportManager<R> {
        TransportManager {
            dial_rx: self.dial_rx,
            transport_tx: self.transport_tx.clone(),
            event_handle: self.router_ctx.event_handle().clone(),
            external_address: None,
            local_router_info: self.local_router_info,
            netdb_handle: self.netdb_handle.expect("to exist"),
            ntcp2_config: self.ntcp2_config,
            pending_connections: HashSet::new(),
            pending_queries: HashSet::new(),
            pending_query_futures: R::join_set(),
            poll_index: 0usize,
            router_ctx: self.router_ctx,
            // publish the router info 10 seconds after booting, otherwise republish it periodically
            // in intervals of [`ROUTER_INFO_REPUBLISH_INTERVAL`]
            router_info_republish_timer: R::timer(Duration::from_secs(10)),
            routers: HashSet::new(),
            shutting_down: false,
            ssu2_config: self.ssu2_config,
            transit_tunnels_disabled: self.transit_tunnels_disabled,
            transports: self.transports,
        }
    }
}

/// Transport manager.
///
/// Transport manager is responsible for connecting the higher-level subsystems
/// together with enabled, lower-level transports and polling for polling those
/// transports so that they can make progress.
pub struct TransportManager<R: Runtime> {
    /// RX channel for receiving dial requests.
    dial_rx: Receiver<RouterId>,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// External address, if any.
    external_address: Option<Ipv4Addr>,

    /// Local router info.
    local_router_info: RouterInfo,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// NTCP2 config.
    ntcp2_config: Option<Ntcp2Config>,

    /// Pending outbound connections.
    pending_connections: HashSet<RouterId>,

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
    routers: HashSet<RouterId>,

    /// Is the router shutting down.
    shutting_down: bool,

    /// SSU2 config.
    ssu2_config: Option<Ssu2Config>,

    /// Are transit tunnels disabled.
    transit_tunnels_disabled: bool,

    /// TX channel for sending transport-related events to `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,

    /// Enabled transports.
    transports: Vec<Box<dyn Transport<Item = TransportEvent>>>,
}

impl<R: Runtime> TransportManager<R> {
    /// Collect `TransportManager`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        let metrics = register_metrics(metrics);
        let metrics = Ntcp2Transport::<R>::metrics(metrics);

        Ssu2Transport::<R>::metrics(metrics)
    }

    /// Mark the router as shutting down.
    ///
    /// This causes the next publish router info to have `G` capabilities.
    pub fn shutdown(&mut self) {
        self.shutting_down = true;
    }

    /// Add external address for the router.
    pub fn add_external_address(&mut self, address: Ipv4Addr) {
        tracing::info!(
            target: LOG_TARGET,
            ?address,
            "external address discovered",
        );

        match (self.external_address, address) {
            (None, address) => {
                tracing::info!(
                    target: LOG_TARGET,
                    ?address,
                    "external address discovered, publishing new router info",
                );

                self.external_address = Some(address);
            }
            (Some(old_address), new_address) if old_address != new_address => {
                tracing::info!(
                    target: LOG_TARGET,
                    ?old_address,
                    ?new_address,
                    "new external address discovered, publishing new router info",
                );

                self.external_address = Some(address);
            }
            _ => return,
        };

        match &self.ntcp2_config {
            Some(Ntcp2Config {
                port,
                host,
                publish: true,
                key,
                iv,
            }) => match (host, address) {
                (None, address) => {
                    self.local_router_info.addresses.insert(
                        TransportKind::Ntcp2,
                        RouterAddress::new_published_ntcp2(*key, *iv, *port, address),
                    );
                }
                (Some(published), address) if published == &address => {}
                (Some(published), address) => tracing::warn!(
                    target: LOG_TARGET,
                    ?published,
                    ?address,
                    "external address doesn't match published address, router address not updated",
                ),
            },
            _ => tracing::trace!(
                target: LOG_TARGET,
                "ntcp2 not active or unpublished, router address not updated",
            ),
        }

        match &self.ssu2_config {
            Some(Ssu2Config {
                port,
                host,
                publish: true,
                static_key,
                intro_key,
            }) => match (host, address) {
                (None, address) => {
                    self.local_router_info.addresses.insert(
                        TransportKind::Ssu2,
                        RouterAddress::new_published_ssu2(*static_key, *intro_key, *port, address),
                    );
                }
                (Some(published), address) if published == &address => {}
                (Some(published), address) => tracing::warn!(
                    target: LOG_TARGET,
                    ?published,
                    ?address,
                    "external address doesn't match published ssu2 address, router address not updated",
                ),
            },
            _ => tracing::trace!(
                target: LOG_TARGET,
                "ssu2 not active or unpublished, router address not updated",
            ),
        }
    }

    /// Attempt to dial `router_id`.
    ///
    /// If `router_id` is not found in local storage, send [`RouterInfo`] query for `router_id` to
    /// [`NetDb`] and if the [`RouterInfo`] is found, attempt to dial it.
    fn on_dial_router(&mut self, router_id: RouterId) {
        if &router_id == self.router_ctx.router_id() {
            tracing::error!(target: LOG_TARGET, "tried to dial self");
            debug_assert!(false);
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
                if !self.pending_connections.insert(router_id.clone()) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "router is already being dialed",
                    );
                    return;
                }

                // TODO: ssu2 support
                if self.ntcp2_config.is_some() && !router_info.is_reachable_ntcp2() {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        caps = %router_info.capabilities,
                        "cannot dial router, ntcp2 address is not reachable",
                    );
                    self.pending_connections.remove(&router_id);

                    // report connection failure to subsystems
                    let transport_tx = self.transport_tx.clone();

                    R::spawn(async move {
                        // subsystem manager never dies
                        transport_tx
                            .send(SubsystemEvent::ConnectionFailure { router_id })
                            .await
                            .expect("channel to stay open");
                    });

                    return;
                }

                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    "start dialing router",
                );

                // TODO: compare transport costs
                self.transports[0].connect(router_info);
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

                match self.netdb_handle.try_query_router_info(router_id.clone()) {
                    Err(error) => tracing::warn!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send router info query",
                    ),
                    Ok(rx) => {
                        self.pending_connections.insert(router_id.clone());
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
        }
    }
}

impl<R: Runtime> Future for TransportManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let len = self.transports.len();
        let start_index = self.poll_index;

        loop {
            let index = self.poll_index % len;
            self.poll_index += 1;

            loop {
                match self.transports[index].poll_next_unpin(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        direction,
                        router_id,
                    })) => match direction {
                        Direction::Inbound if self.pending_connections.contains(&router_id) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                "outbound connection pending, rejecting inbound connection",
                            );
                            self.transports[index].reject(&router_id);
                        }
                        Direction::Outbound if !self.pending_connections.contains(&router_id) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                "pending connection doesn't exist for router, rejecting connection",
                            );
                            self.transports[index].reject(&router_id);
                        }
                        direction => match self.routers.insert(router_id.clone()) {
                            true => {
                                tracing::trace!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    ?direction,
                                    "connection established",
                                );

                                self.transports[index].accept(&router_id);
                                self.pending_connections.remove(&router_id);
                                self.router_ctx
                                    .metrics_handle()
                                    .gauge(NUM_CONNECTIONS)
                                    .increment(1);
                                self.router_ctx.profile_storage().dial_succeeded(&router_id);
                            }
                            false => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    "router already connected, rejecting",
                                );
                                self.transports[index].reject(&router_id);
                            }
                        },
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

                        self.routers.remove(&router_id);
                        self.router_ctx.metrics_handle().gauge(NUM_CONNECTIONS).decrement(1);
                    }
                    Poll::Ready(Some(TransportEvent::ConnectionFailure { router_id })) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "failed to dial router",
                        );

                        self.router_ctx.metrics_handle().counter(NUM_DIAL_FAILURES).increment(1);
                        self.router_ctx.profile_storage().dial_failed(&router_id);
                        self.pending_connections.remove(&router_id);
                    }
                }
            }

            if self.poll_index == start_index + len {
                break;
            }
        }

        loop {
            match self.pending_query_futures.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((router_id, Ok(())))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "router info query succeeded, dial pending router",
                    );

                    self.pending_queries.remove(&router_id);
                    self.pending_connections.remove(&router_id);
                    self.on_dial_router(router_id);
                }
                Poll::Ready(Some((router_id, Err(error)))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "router info query failed",
                    );
                    self.pending_connections.remove(&router_id);
                    self.pending_queries.remove(&router_id);

                    // report connection failure to subsystems
                    let transport_tx = self.transport_tx.clone();

                    R::spawn(async move {
                        // subsystem manager never dies
                        transport_tx
                            .send(SubsystemEvent::ConnectionFailure { router_id })
                            .await
                            .expect("channel to stay open");
                    });
                }
            }
        }

        loop {
            match self.dial_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(router_id)) => self.on_dial_router(router_id),
            }
        }

        if self.router_info_republish_timer.poll_unpin(cx).is_ready() {
            // reset publish time and serialize our new router info
            self.local_router_info.published = Date::new(R::time_since_epoch().as_millis() as u64);

            // publish `G`, i.e., rejecting all tunnels if the router is shutting down
            // or if transit tunnels have been disabled
            if self.shutting_down || self.transit_tunnels_disabled {
                tracing::trace!(
                    target: LOG_TARGET,
                    shutting_down = ?self.shutting_down,
                    transit_tunnels_disabled = ?self.transit_tunnels_disabled,
                    "publishing router info with `G`",
                );

                self.local_router_info.options.insert(Str::from("caps"), Str::from("GR"));
            }

            let serialized =
                Bytes::from(self.local_router_info.serialize(self.router_ctx.signing_key()));

            // reset router info in router context so all subsystems are using the latest version of
            // it and publish it to netdb
            self.router_ctx.set_router_info(serialized.clone());
            self.netdb_handle
                .publish_router_info(self.router_ctx.router_id().clone(), serialized);

            // reset timer and register it into the executor
            self.router_info_republish_timer = R::timer(ROUTER_INFO_REPUBLISH_INTERVAL);
            let _ = self.router_info_republish_timer.poll_unpin(cx);
        }

        if self.event_handle.poll_unpin(cx).is_ready() {
            self.event_handle.num_connected_routers(self.routers.len());
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::{
        events::EventManager,
        i2np::{Message, MessageType, I2NP_MESSAGE_EXPIRATION},
        netdb::NetDbAction,
        primitives::{Capabilities, RouterInfoBuilder, Str},
        profile::ProfileStorage,
        runtime::mock::MockRuntime,
        subsystem::OutboundMessage,
    };
    use thingbuf::mpsc::channel;
    use tokio::sync::mpsc;

    fn make_transport_manager(
        ntcp2: Option<Ntcp2Config>,
        ssu2: Option<Ssu2Config>,
    ) -> (
        TransportManagerBuilder<MockRuntime>,
        Sender<RouterId>,
        Receiver<SubsystemEvent>,
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
        let (handle, _) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
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
        );
        builder.register_netdb_handle(handle);

        (builder, dial_tx, transport_rx)
    }

    #[tokio::test]
    async fn external_address_discovered_ntcp2() {
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            port: 0,
            host: Some("192.168.0.1".parse().unwrap()),
            publish: true,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(Some(context.config()), None);
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        // ensure ntcp2 is published
        assert!(manager.ntcp2_config.is_some());
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("s"))
            .is_some());

        manager.add_external_address("192.168.0.1".parse().unwrap());

        // verify that the address is still published and that host is the same
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("s"))
            .is_some());
    }

    #[tokio::test]
    async fn external_address_discovered_ntcp2_unpublished() {
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            port: 0,
            host: None,
            publish: false,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(Some(context.config()), None);
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        // ensure ntcp2 is unpublished
        assert!(manager.ntcp2_config.is_some());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("host"))
            .is_none());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("i"))
            .is_none());

        manager.add_external_address("192.168.0.1".parse().unwrap());

        // verify that the address is still unpublished
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("host"))
            .is_none());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("i"))
            .is_none());
    }

    #[tokio::test]
    async fn external_address_discovered_ssu2() {
        let ssu2 = Ssu2Config {
            port: 0,
            host: Some("192.168.0.1".parse().unwrap()),
            publish: true,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
        };
        let context =
            Ssu2Transport::<MockRuntime>::initialize(Some(ssu2)).await.unwrap().0.unwrap();
        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(None, Some(context.config()));
        builder.register_ssu2(context);
        let mut manager = builder.build();

        // ensure ssu2 is published
        assert!(manager.ssu2_config.is_some());
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );

        manager.add_external_address("192.168.0.1".parse().unwrap());

        // verify that the address is still published and that host is the same
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
    }

    #[tokio::test]
    async fn external_address_discovered_ssu2_unpublished() {
        let context = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0,
            host: None,
            publish: false,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(None, Some(context.config()));
        builder.register_ssu2(context);
        let mut manager = builder.build();

        // ensure ssu2 is unpublished
        assert!(manager.ssu2_config.is_some());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ssu2)
            .unwrap()
            .options
            .get(&Str::from("host"))
            .is_none());

        manager.add_external_address("192.168.0.1".parse().unwrap());

        // verify that the address is still unpublished
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ssu2)
            .unwrap()
            .options
            .get(&Str::from("host"))
            .is_none());
    }

    #[tokio::test]
    async fn new_external_address_discovered() {
        let ssu2_context = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0,
            host: None,
            publish: true,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        let ntcp2_context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            port: 0,
            host: None,
            publish: true,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(Some(ntcp2_context.config()), Some(ssu2_context.config()));
        builder.register_ssu2(ssu2_context);
        builder.register_ntcp2(ntcp2_context);
        let mut manager = builder.build();

        // ensure ssu2 and ntcp2 is unpublished since no host was provided
        assert!(manager.ssu2_config.is_some());
        assert!(manager.ntcp2_config.is_some());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ssu2)
            .unwrap()
            .options
            .get(&Str::from("host"))
            .is_none());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("host"))
            .is_none());
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("i"))
            .is_none());

        manager.add_external_address("192.168.0.1".parse().unwrap());

        // verify that the address is still unpublished
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("s"))
            .is_some());
    }

    #[tokio::test]
    async fn discovered_address_doesnt_match_published_address_ntcp2() {
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            port: 0,
            host: Some("192.168.0.1".parse().unwrap()),
            publish: true,
            key: [0u8; 32],
            iv: [0u8; 16],
        }))
        .await
        .unwrap()
        .0
        .unwrap();
        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(Some(context.config()), None);
        builder.register_ntcp2(context);
        let mut manager = builder.build();

        // ensure ntcp2 is published
        assert!(manager.ntcp2_config.is_some());
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("s"))
            .is_some());

        manager.add_external_address("192.168.1.1".parse().unwrap());

        // verify that the address is still published and that host is the same
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.0.1"))
        );
        assert!(manager
            .local_router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options
            .get(&Str::from("s"))
            .is_some());
    }

    #[tokio::test]
    async fn discovered_address_doesnt_match_published_address_ssu2() {
        let context = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0,
            host: Some("192.168.1.1".parse().unwrap()),
            publish: true,
            static_key: [0u8; 32],
            intro_key: [1u8; 32],
        }))
        .await
        .unwrap()
        .0
        .unwrap();

        let (mut builder, _dial_tx, _transport_rx) =
            make_transport_manager(None, Some(context.config()));
        builder.register_ssu2(context);
        let mut manager = builder.build();

        // ensure ssu2 is unpublished
        assert!(manager.ssu2_config.is_some());
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.1.1"))
        );

        manager.add_external_address("192.168.0.1".parse().unwrap());

        // verify that the address is still unpublished
        assert_eq!(
            manager
                .local_router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("192.168.1.1"))
        );
    }

    #[tokio::test]
    async fn inbound_connection_rejected_connection_already_exists() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let (handle, _) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&[], &[]),
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
                    router_id: router_id1.clone(),
                    direction: Direction::Inbound,
                },
                TransportEvent::ConnectionEstablished {
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
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
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
            })
            .await
            .unwrap();

        event_tx
            .send(TransportEvent::ConnectionEstablished {
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
    async fn inbound_connection_rejected_while_netdb_lookup_pending() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
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
    async fn router_shutting_down() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
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
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            port: 0,
            host: Some("192.168.0.1".parse().unwrap()),
            publish: true,
            key: [0u8; 32],
            iv: [0u8; 16],
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
        );
        builder.register_netdb_handle(handle);
        builder.register_ntcp2(context);

        let mut manager = builder.build();

        assert!(Capabilities::parse(
            &manager.local_router_info.options.get(&Str::from("caps")).unwrap()
        )
        .unwrap()
        .is_usable());

        // shutdown the manager, set RI republish timeout smaller and wait for RI to be published
        manager.shutdown();
        manager.router_info_republish_timer = MockRuntime::timer(Duration::from_secs(1));

        assert!(tokio::time::timeout(Duration::from_secs(3), &mut manager).await.is_err());

        // verify that the local router is no longer considered usable due to the `G` flag
        assert!(!Capabilities::parse(
            &manager.local_router_info.options.get(&Str::from("caps")).unwrap()
        )
        .unwrap()
        .is_usable());
    }

    #[tokio::test]
    async fn transit_tunnels_disabled() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (handle, _netdb_rx) = NetDbHandle::create();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
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
            port: 0,
            host: Some("192.168.0.1".parse().unwrap()),
            publish: true,
            key: [0u8; 32],
            iv: [0u8; 16],
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

    #[tokio::test]
    async fn router_info_query_fails() {
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let serialized = Bytes::from(router_info.serialize(&signing_key));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
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
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (remote_router_info, _, _) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                port: 888u16,
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,
                static_key: [1u8; 32],
                intro_key: [2u8; 32],
            })
            .build();
        let remote_router_id = remote_router_info.identity.id();
        storage.add_router(remote_router_info);

        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
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
        );
        builder.register_netdb_handle(handle);
        let context = Ntcp2Transport::<MockRuntime>::initialize(Some(Ntcp2Config {
            port: 0,
            host: Some("192.168.0.1".parse().unwrap()),
            publish: true,
            key: [0u8; 32],
            iv: [0u8; 16],
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
            port: 0,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xaa; 32],
            intro_key: [0xbb; 32],
        };
        let (context1, address1) =
            Ssu2Transport::<MockRuntime>::initialize(Some(config1)).await.unwrap();
        let (router_info1, static_key1, signing_key1) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                port: address1.unwrap().socket_address.unwrap().port(),
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,
                static_key: [0xaa; 32],
                intro_key: [0xbb; 32],
            })
            .build();
        let serialized1 = Bytes::from(router_info1.serialize(&signing_key1));
        let storage1 = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let router_id1 = router_info1.identity.id();

        let config2 = Ssu2Config {
            port: 0,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xcc; 32],
            intro_key: [0xdd; 32],
        };
        let (context2, address2) =
            Ssu2Transport::<MockRuntime>::initialize(Some(config2)).await.unwrap();

        let (router_info2, static_key2, signing_key2) = RouterInfoBuilder::default()
            .with_ssu2(Ssu2Config {
                port: address2.unwrap().socket_address.unwrap().port(),
                host: Some("127.0.0.1".parse().unwrap()),
                publish: true,
                static_key: [0xcc; 32],
                intro_key: [0xdd; 32],
            })
            .build();
        let serialized2 = Bytes::from(router_info2.serialize(&signing_key2));
        let storage2 = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let router_id2 = router_info2.identity.id();

        storage1.add_router(router_info2.clone());
        storage2.add_router(router_info1.clone());

        let (_event_mgr1, _event_subscriber1, event_handle1) = EventManager::new(None);
        let (_event_mgr2, _event_subscriber2, event_handle2) = EventManager::new(None);
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
}
