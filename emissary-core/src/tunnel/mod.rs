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
    bloom::BloomFilter,
    config::TransitConfig,
    error::Error,
    i2np::{tunnel::data::EncryptedTunnelData, Message, MessageType},
    primitives::RouterId,
    router::context::RouterContext,
    runtime::{Counter, MetricType, MetricsHandle, Runtime},
    shutdown::ShutdownHandle,
    subsystem::SubsystemEvent,
    transport::TransportService,
    tunnel::{
        handle::{CommandRecycle, TunnelManagerCommand},
        metrics::*,
        pool::{ClientSelector, ExploratorySelector, TunnelPool, TunnelPoolBuildParameters},
        routing_table::RoutingKind,
        transit::TransitTunnelManager,
    },
};

use futures::{FutureExt, StreamExt};
use futures_channel::oneshot;
use hashbrown::HashMap;
use thingbuf::mpsc::{channel, with_recycle, Receiver, Sender};

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod fragment;
mod garlic;
mod handle;
mod hop;
mod metrics;
mod noise;
mod pool;
mod routing_table;
mod transit;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub use pool::TunnelMessage;

pub use garlic::{DeliveryInstructions, GarlicHandler};
pub use handle::TunnelManagerHandle;
pub use noise::NoiseContext;
pub use pool::{TunnelMessageSender, TunnelPoolConfig, TunnelPoolEvent, TunnelPoolHandle};
pub use routing_table::{RoutingKindRecycle, RoutingTable};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel";

/// Default channel size.
const DEFAULT_CHANNEL_SIZE: usize = 512;

/// Tunnel expiration, 10 minutes.
const TUNNEL_EXPIRATION: Duration = Duration::from_secs(10 * 60);

/// Bloom filter decay interval.
const BLOOM_FILTER_DECAY_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Router state.
#[derive(Debug)]
pub enum RouterState {
    /// Router is connected.
    Connected,

    /// Router is being dialed.
    Dialing {
        /// Pending messages and potentially feedback channels for confirmation of delivery.
        pending_messages: Vec<(Vec<u8>, Option<oneshot::Sender<()>>)>,
    },
}

/// Tunnel manager.
pub struct TunnelManager<R: Runtime> {
    /// Bloom filter for incoming `TunnelData` messages.
    bloom_filter: BloomFilter,

    /// Bloom filter decay timer.
    bloom_filter_timer: R::Timer,

    /// RX channel for receiving tunneling-related commands from other subsystems.
    command_rx: Receiver<TunnelManagerCommand, CommandRecycle>,

    /// Exploratory tunnel/hop selector.
    exploratory_selector: ExploratorySelector<R>,

    /// Garlic message handler.
    garlic: GarlicHandler<R>,

    /// RX channel for receiving messages from other tunnel-related subsystems.
    message_rx: Receiver<RoutingKind, RoutingKindRecycle>,

    /// TX channel for forwarding messages to [`NetDb`].
    netdb_tx: Sender<Message>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Transport service.
    service: TransportService<R>,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    ///
    /// Returns a [`TunnelManager`] object, a [`TunnelManagerHandle`] which can be used to create
    /// new tunnel pools and a [`TunnelPoolHandle`] for the exploratory tunnel pool.
    pub fn new(
        service: TransportService<R>,
        router_ctx: RouterContext<R>,
        exploratory_config: TunnelPoolConfig,
        insecure_tunnels: bool,
        transit_config: Option<TransitConfig>,
        transit_shutdown_handle: ShutdownHandle,
    ) -> (
        Self,
        TunnelManagerHandle,
        TunnelPoolHandle,
        RoutingTable,
        Receiver<Message>,
    ) {
        tracing::info!(
            target: LOG_TARGET,
            ?insecure_tunnels,
            "starting tunnel manager",
        );

        let (routing_table, message_rx, transit_rx) = {
            let (message_tx, message_rx) =
                with_recycle(DEFAULT_CHANNEL_SIZE, RoutingKindRecycle::default());
            let (transit_tx, transit_rx) = channel(DEFAULT_CHANNEL_SIZE);
            let routing_table =
                RoutingTable::new(router_ctx.router_id().clone(), message_tx, transit_tx);

            (routing_table, message_rx, transit_rx)
        };

        // create `TransitTunnelManager` and run it in a separate task
        //
        // `TransitTunnelManager` communicates with `TunnelManager` via `RoutingTable`
        R::spawn(TransitTunnelManager::<R>::new(
            transit_config,
            router_ctx.clone(),
            routing_table.clone(),
            transit_rx,
            transit_shutdown_handle,
        ));

        // start exploratory tunnel pool
        //
        // `TunnelPool` communicates with `TunnelManager` via `RoutingTable`
        let (pool_handle, exploratory_selector) = {
            let build_parameters = TunnelPoolBuildParameters::new(exploratory_config);
            let selector = ExploratorySelector::new(
                router_ctx.profile_storage().clone(),
                build_parameters.context_handle.clone(),
                insecure_tunnels,
            );
            let (tunnel_pool, tunnel_pool_handle) = TunnelPool::<R, _>::new(
                build_parameters,
                selector.clone(),
                routing_table.clone(),
                router_ctx.clone(),
            );
            R::spawn(tunnel_pool);

            (tunnel_pool_handle, selector)
        };

        // create handle which other subsystems can use to create new tunnel pools
        let (manager_handle, command_rx) = TunnelManagerHandle::new();

        // create channel for forwarding netdb-related to netdb
        let (netdb_tx, netdb_rx) = channel(32);

        (
            Self {
                bloom_filter: BloomFilter::default(),
                bloom_filter_timer: R::timer(BLOOM_FILTER_DECAY_INTERVAL),
                command_rx,
                exploratory_selector,
                garlic: GarlicHandler::new(
                    router_ctx.noise().clone(),
                    router_ctx.metrics_handle().clone(),
                ),
                message_rx,
                netdb_tx,
                router_ctx,
                routers: HashMap::new(),
                routing_table: routing_table.clone(),
                service,
            },
            manager_handle,
            pool_handle,
            routing_table,
            netdb_rx,
        )
    }

    /// Collect tunnel-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Send `message` to router identified by `router_id`.
    ///
    /// If the router is not connected, its information is looked up from `ProfileStorage` and if it
    /// exists, it will be dialed and if the connection is established successfully, any pending
    /// messages will be sent to the router once the connection has been registered to
    /// [`TunnelManager`].
    ///
    /// If the connection fails to establish, [`TunnelManager`] is notified of it
    /// and any pending messages will be dropped.
    ///
    /// [`TransportService::send()`] returns an error if the channel is closed, meaning the
    /// the connection has been closed or if the channel is full at which point the message
    /// will just be dropped.
    ///
    /// `feedback` is an optional TX channel given by the message sender and it's used to signal to
    /// the message's sender whether the message was sent to remote router successfully.
    fn send_message(
        &mut self,
        router_id: &RouterId,
        message: Vec<u8>,
        feedback_tx: Option<oneshot::Sender<()>>,
    ) {
        match self.routers.get_mut(router_id) {
            Some(RouterState::Connected) => match self.service.send(router_id, message) {
                Ok(()) =>
                    if let Some(tx) = feedback_tx {
                        let _ = tx.send(());
                    },
                Err((error, _)) => tracing::error!(
                    target: LOG_TARGET,
                    %router_id,
                    ?error,
                    "failed to send message to router",
                ),
            },
            Some(RouterState::Dialing {
                ref mut pending_messages,
            }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "router is being dialed, buffer message",
                );

                pending_messages.push((message, feedback_tx));
            }
            None => match router_id == self.router_ctx.router_id() {
                true => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        message_type = ?MessageType::from_u8(message[2]),
                        message_len = ?message.len(),
                        "message incorrectly routed to self",
                    );
                    debug_assert!(false);
                }
                false => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "start dialing router",
                    );

                    if let Err(error) = self.service.connect(router_id) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?error,
                            "failed to dial router",
                        );
                    }

                    self.routers.insert(
                        router_id.clone(),
                        RouterState::Dialing {
                            pending_messages: vec![(message, feedback_tx)],
                        },
                    );
                }
            },
        }
    }

    /// Handle established connection to router identified by `router_id`.
    ///
    /// Store `router` into `routers` and send any pending messages to router identified by
    /// `router_id`.
    fn on_connection_established(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            Some(RouterState::Dialing { pending_messages }) if !pending_messages.is_empty() => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "router with pending messages connected",
                );

                for (message, feedback_tx) in pending_messages {
                    match self.service.send(&router_id, message) {
                        Ok(()) =>
                            if let Some(tx) = feedback_tx {
                                let _ = tx.send(());
                            },
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?error,
                            "failed to send message to router",
                        ),
                    }
                }
            }
            Some(RouterState::Dialing { .. }) | None => {}
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    ?state,
                    "invalid state for connected router",
                );
                debug_assert!(false);
            }
        }

        self.routers.insert(router_id, RouterState::Connected);
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router_id: &RouterId) {
        match self.routers.remove(router_id) {
            Some(RouterState::Dialing { pending_messages }) if !pending_messages.is_empty() => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "dial failure for router with pending messages",
                );
            }
            _ => {}
        }
    }

    /// Handle connection failure to `router_id`
    ///
    /// Remove `router_id` from `routers` and drop any pending messages to them.
    fn on_connection_failure(&mut self, router_id: &RouterId) {
        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            "failed to open connection to router",
        );
        self.routers.remove(router_id);
    }

    /// Handle garlic message.
    ///
    /// Decrypt the payload, return I2NP messages inside the garlic cloves
    /// and process them individually.
    fn on_garlic(&mut self, message: Message) -> crate::Result<()> {
        self.garlic.handle_message(message).map(|messages| {
            messages.for_each(|delivery_instructions| match delivery_instructions {
                DeliveryInstructions::Local { message } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        "garlic message for local delivery",
                    );

                    if let Err(error) = self.on_message(message) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to route tunnel message encapsulated within a garlic message",
                        );
                    }
                }
                DeliveryInstructions::Router { router, message } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        router_id = %router,
                        "garlic message for router delivery",
                    );

                    self.send_message(&router, message, None);
                }
                DeliveryInstructions::Tunnel {
                    router,
                    tunnel,
                    message,
                } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        router_id = %router,
                        tunnel_id = %tunnel,
                        "garlic message for tunnel delivery",
                    );

                    self.send_message(&router, message, None);
                }
                DeliveryInstructions::Destination => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "garlic message for destination",
                    );
                    debug_assert!(false);
                }
            })
        })
    }

    /// Create new [`TunnelPool`] for a client destination.
    ///
    /// Returns a [`TunnelPoolHandle`] for the tunnel pool that is sent over destination.
    fn on_create_tunnel_pool(&self, config: TunnelPoolConfig) -> TunnelPoolHandle {
        tracing::info!(
            target: LOG_TARGET,
            ?config,
            "create tunnel pool",
        );

        let build_parameters = TunnelPoolBuildParameters::new(config);
        let selector = ClientSelector::new(
            self.exploratory_selector.clone(),
            build_parameters.context_handle.clone(),
        );
        let (tunnel_pool, tunnel_pool_handle) = TunnelPool::<R, _>::new(
            build_parameters,
            selector,
            self.routing_table.clone(),
            self.router_ctx.clone(),
        );
        R::spawn(tunnel_pool);

        tunnel_pool_handle
    }

    /// Handle received message from one of the open connections.
    fn on_message(&mut self, message: Message) -> crate::Result<()> {
        self.router_ctx.metrics_handle().counter(NUM_TUNNEL_MESSAGES).increment(1);

        // feed tunnel data into a decaying bloom filter to ensure it's unique
        //
        // TODO: disabled for now, causes tunnel test failures with i2pd
        // if core::matches!(message.message_type, MessageType::TunnelData) {
        if false {
            let xor = EncryptedTunnelData::parse(&message.payload).ok_or(Error::InvalidData)?.xor();

            if !self.bloom_filter.insert(&xor) {
                tracing::trace!(
                    target: LOG_TARGET,
                    message_id = ?message.message_id,
                    "ignoring, duplicate tunnel data message",
                );
                return Err(Error::Duplicate);
            }
        }

        match message.message_type {
            MessageType::TunnelData
            | MessageType::TunnelGateway
            | MessageType::VariableTunnelBuild
            | MessageType::ShortTunnelBuild
            | MessageType::OutboundTunnelBuildReply
            | MessageType::TunnelBuild =>
                self.routing_table.route_message(message).map_err(From::from),
            MessageType::Garlic => self.on_garlic(message),
            MessageType::TunnelBuildReply
            | MessageType::Data
            | MessageType::VariableTunnelBuildReply => {
                tracing::warn!(
                    target: LOG_TARGET,
                    message_type = ?message.message_type,
                    "unsupported message type",
                );
                debug_assert!(false);

                Ok(())
            }
            MessageType::DeliveryStatus
            | MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => {
                if let Err(error) = self.netdb_tx.try_send(message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to forward message to netdb",
                    );
                }

                Ok(())
            }
        }
    }
}

impl<R: Runtime> Future for TunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(RoutingKind::External { router_id, message }) =>
                    self.send_message(&router_id, message, None),
                Some(RoutingKind::Internal { message }) => {
                    if let Err(error) = self.on_message(message) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to handle internal tunnel message",
                        );
                    }
                }
                Some(RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                }) => self.send_message(&router_id, message, Some(tx)),
            }
        }

        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(&router),
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|(_, message)| {
                        if let Err(error) = self.on_message(message) {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to handle external tunnel message",
                            );
                        }
                    }),
                Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router })) =>
                    self.on_connection_failure(&router),
                Poll::Ready(Some(SubsystemEvent::Dummy)) => unreachable!(),
                Poll::Ready(None) => return Poll::Ready(()),
            }
        }

        loop {
            match self.command_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(TunnelManagerCommand::CreateTunnelPool { config, tx })) => {
                    let _ = tx.send(self.on_create_tunnel_pool(config));
                }
                Poll::Ready(Some(TunnelManagerCommand::Dummy)) => unreachable!(),
            }
        }

        futures::ready!(self.bloom_filter_timer.poll_unpin(cx));

        // create new timer and register it into the executor
        {
            self.bloom_filter.decay();
            self.bloom_filter_timer = R::timer(BLOOM_FILTER_DECAY_INTERVAL);
            let _ = self.bloom_filter_timer.poll_unpin(cx);
        }

        Poll::Pending
    }
}
