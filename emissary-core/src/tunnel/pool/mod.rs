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
    crypto::{chachapoly::ChaChaPoly, EphemeralPrivateKey},
    error::{ChannelError, Error},
    events::EventHandle,
    i2np::{
        garlic::{DeliveryInstructions, GarlicMessageBuilder},
        MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{Lease, Mapping, MessageId, RouterId, Str, TunnelId},
    router::context::RouterContext,
    runtime::{Counter, Gauge, Histogram, Instant, JoinSet, MetricsHandle, Runtime},
    tunnel::{
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel, ReceiverKind,
            Tunnel, TunnelBuildParameters, TunnelInfo,
        },
        metrics::*,
        pool::{
            listener::TunnelBuildListener,
            selector::{HopSelector, TunnelSelector},
            timer::{TunnelKind, TunnelTimer, TunnelTimerEvent},
            zero_hop::ZeroHopInboundTunnel,
        },
        routing_table::RoutingTable,
        TUNNEL_EXPIRATION,
    },
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    future::{select, Either},
    FutureExt, StreamExt,
};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use listener::ReceiveKind;
use rand_core::RngCore;

use alloc::vec::Vec;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll},
    time::Duration,
};

pub use context::{
    TunnelMessage, TunnelPoolBuildParameters, TunnelPoolContext, TunnelPoolContextHandle,
};
pub use handle::{TunnelMessageSender, TunnelPoolEvent, TunnelPoolHandle};
pub use selector::{ClientSelector, ExploratorySelector};

#[cfg(test)]
pub use context::TunnelMessageRecycle;

mod context;
mod handle;
mod listener;
mod selector;
mod timer;
mod zero_hop;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pool";

/// Tunnel maintenance interval.
const TUNNEL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);

/// Tunnel build request expiration.
///
/// How long is a pending tunnel kept active before the request is considered failed.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(8);

/// Tunnel test expiration.
///
/// How long is the tunnel considered under testing until the test is considered a failure.
const TUNNEL_TEST_EXPIRATION: Duration = Duration::from_secs(8);

/// Tunnel channel size.
const TUNNEL_CHANNEL_SIZE: usize = 64usize;

/// Tunnel test interval.
///
/// How often tunnels of the pool are tested.
const TUNNEL_TEST_INTERVAL: Duration = Duration::from_secs(15);

/// Tunnel pool configuration.
#[derive(Debug, Clone)]
pub struct TunnelPoolConfig {
    /// Tunnel pool name.
    ///
    /// This is either set in I2CP options and if none is set,
    /// it's the short hash of the `Destination`.
    pub name: Str,

    /// How many inbound tunnels the pool should have.
    pub num_inbound: usize,

    /// How many hops should each inbound tunnel have.
    pub num_inbound_hops: usize,

    /// How many outbound tunnels the pool should have.
    pub num_outbound: usize,

    /// How many hops should each outbound tunnel have.
    pub num_outbound_hops: usize,
}

impl Default for TunnelPoolConfig {
    fn default() -> Self {
        Self {
            num_inbound: 3usize,
            num_inbound_hops: 2usize,
            num_outbound: 3usize,
            num_outbound_hops: 2usize,
            name: Str::from("exploratory"),
        }
    }
}

impl From<&Mapping> for TunnelPoolConfig {
    fn from(options: &Mapping) -> Self {
        let num_inbound = options
            .get(&Str::from("inbound.quantity"))
            .map_or(3usize, |value| value.parse::<usize>().unwrap_or(3usize));

        let num_inbound_hops = options
            .get(&Str::from("inbound.length"))
            .map_or(2usize, |value| value.parse::<usize>().unwrap_or(2usize));

        let num_outbound = options
            .get(&Str::from("outbound.quantity"))
            .map_or(3usize, |value| value.parse::<usize>().unwrap_or(3usize));

        let num_outbound_hops = options
            .get(&Str::from("outbound.length"))
            .map_or(2usize, |value| value.parse::<usize>().unwrap_or(2usize));

        let name = options
            .get(&Str::from("inbound.nickname"))
            .cloned()
            .unwrap_or(Str::from("unspecified"));

        Self {
            name,
            num_inbound,
            num_inbound_hops,
            num_outbound,
            num_outbound_hops,
        }
    }
}

/// Tunnel pool implementation.
///
/// Tunnel pool manages a set of inbound and outbound tunnels for a particular destination.
pub struct TunnelPool<R: Runtime, S: TunnelSelector + HopSelector> {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// Tunne pool context.
    context: TunnelPoolContext,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// Expiring inbound tunnels.
    expiring_inbound: HashSet<TunnelId>,

    /// Expiring outbound tunnels.
    expiring_outbound: HashSet<TunnelId>,

    /// Active inbound tunnels.
    ///
    /// After the inbound tunnel expires, it returns a `(TunnelId, TunnelId)` tuple where the first
    /// `TunnelId` is the ID of the inbound tunnel and second ID if the id of the gateway.
    inbound: R::JoinSet<(TunnelId, TunnelId)>,

    /// Inbound tunnels.
    ///
    /// Key is IBGW `TunnelId` and value is (IBEP `TunnelId`, IBGW `RouterId`) tuple.
    inbound_tunnels: HashMap<TunnelId, (TunnelId, RouterId)>,

    /// Last time a tunnel test was performed.
    last_tunnel_test: R::Instant,

    /// Tunnel maintenance timer.
    maintenance_timer: R::Timer,

    /// How many tunnel build failures, either timeouts or rejections, there has been.
    num_tunnel_build_failures: usize,

    /// How many tunnels have successfully been built.
    num_tunnels_built: usize,

    /// Active outbound tunnels.
    outbound: HashMap<TunnelId, OutboundTunnel<R>>,

    /// Pending inbound tunnels.
    pending_inbound: TunnelBuildListener<R, InboundTunnel<R>>,

    /// Pending outbound tunnels.
    pending_outbound: TunnelBuildListener<R, OutboundTunnel<R>>,

    /// Pending tunnel tests.
    pending_tests: R::JoinSet<(TunnelId, TunnelId, crate::Result<Duration>)>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel/hop selector for the tunnel pool.
    selector: S,

    /// RX channel for receiving a shutdown signal from the pool's owner.
    shutdown_rx: Option<oneshot::Receiver<()>>,

    /// Expiration timers for inbound/outbound tunnels.
    tunnel_timers: TunnelTimer<R>,
}

impl<R: Runtime, S: TunnelSelector + HopSelector> TunnelPool<R, S> {
    /// Create new [`TunnelPool`].
    pub fn new(
        build_parameters: TunnelPoolBuildParameters,
        selector: S,
        routing_table: RoutingTable,
        router_ctx: RouterContext<R>,
    ) -> (Self, TunnelPoolHandle) {
        let TunnelPoolBuildParameters {
            config,
            context,
            shutdown_rx,
            tunnel_pool_handle,
            ..
        } = build_parameters;

        tracing::debug!(
            target: LOG_TARGET,
            name = %config.name,
            num_inbound = ?config.num_inbound,
            num_inbound_hops = ?config.num_inbound_hops,
            num_outbound = ?config.num_outbound,
            num_outbound_hops = ?config.num_outbound_hops,
            "create tunnel pool",
        );

        (
            Self {
                config,
                context,
                event_handle: router_ctx.event_handle().clone(),
                expiring_inbound: HashSet::new(),
                expiring_outbound: HashSet::new(),
                inbound: R::join_set(),
                inbound_tunnels: HashMap::new(),
                last_tunnel_test: R::now(),
                maintenance_timer: R::timer(Duration::from_secs(0)),
                outbound: HashMap::new(),
                pending_inbound: TunnelBuildListener::new(
                    routing_table.clone(),
                    router_ctx.profile_storage().clone(),
                ),
                pending_outbound: TunnelBuildListener::new(
                    routing_table.clone(),
                    router_ctx.profile_storage().clone(),
                ),
                num_tunnel_build_failures: 0usize,
                num_tunnels_built: 0usize,
                router_ctx,
                pending_tests: R::join_set(),
                routing_table,
                selector,
                shutdown_rx: Some(shutdown_rx),
                tunnel_timers: TunnelTimer::new(),
            },
            tunnel_pool_handle,
        )
    }

    /// Calculate the number of outbound tunnels that need to be built.
    fn calculate_outbound_build_count(&self) -> usize {
        let max_tunnels = self.config.num_outbound + self.expiring_outbound.len();

        // fewer than requested amount of tunnels
        if self.outbound.len() + self.pending_outbound.len() < max_tunnels {
            return max_tunnels - self.outbound.len() - self.pending_outbound.len();
        }

        0usize
    }

    /// Calculate the number of inbound tunnels that need to be built.
    fn calculate_inbound_build_count(&self) -> usize {
        let max_tunnels = self.config.num_inbound + self.expiring_inbound.len();

        // fewer than requested amount of tunnels
        if self.inbound.len() + self.pending_inbound.len() < max_tunnels {
            return max_tunnels - self.inbound.len() - self.pending_inbound.len();
        }

        0usize
    }

    /// Maintain the tunnel pool.
    ///
    /// If the number of inbound/outbound is less than desired, build new tunnels.
    ///
    /// Each active tunnel gets tested once every 10 seconds by selecting a pair of random tunnels
    /// and sending a test message to the outbound tunnel and receiving the message back via the
    /// paired inbound tunnels.
    fn maintain_pool(&mut self) {
        tracing::trace!(
            target: LOG_TARGET,
            name = %self.config.name,
            num_outbound = ?self.outbound.len(),
            num_expiring_outbound = self.expiring_outbound.len(),
            num_inbound = ?self.inbound.len(),
            num_expiring_inbound = self.expiring_inbound.len(),
            "maintain tunnel pool",
        );

        for _ in 0..self.calculate_outbound_build_count() {
            // attempt to select hops for the outbound tunnel
            //
            // if there aren't enough available hops, the tunnel build is skipped
            let Some(hops) = self.selector.select_hops(self.config.num_outbound_hops) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    name = %self.config.name,
                    hops_required = ?self.config.num_outbound_hops,
                    "not enough routers for outbound tunnel build",
                );
                continue;
            };

            // allocate random tunnel id for the pending outbound tunnel
            //
            // this can just be a random id (with no regard for collisions)
            // as outbound tunnel messages are not routed through `RoutingTable`
            let tunnel_id = TunnelId::from(R::rng().next_u32());

            // build outbound tunnel
            //
            // the tunnel build reply is received either through an existing inbound tunnel
            // or through a fake 0-hop inbound tunnel if there are no available inbound tunnels
            match self.selector.select_inbound_tunnel() {
                // no inbound tunnels available
                //
                // create a fake 0-hop inbound tunnel and add listener for the tunnel build reply
                // in the routing table
                //
                // if the reply is received, it'll be routed via the routing table to the fake
                // inbound tunnel which routes it to inbound tunnel `TunnelListener` from which
                // it'll be received by the `TunnelPool`
                None => {
                    // the fake 0-hop tunnel routes the build response via `RoutingTable`
                    //
                    // `ZeroHopInboundTunnel::new()` also returns a `oneshot::Receiver<Message>`
                    // which is used to receive the build response, if it's received in time
                    let (gateway, zero_hop_tunnel, message_rx) =
                        ZeroHopInboundTunnel::<R>::new(self.routing_table.clone());

                    // allocate random message id for the build request
                    //
                    // since the reply is not routed through routing table,
                    // message id collisions are not a concern and this can just be a random number
                    let message_id = MessageId::from(R::rng().next_u32());

                    tracing::trace!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        %gateway,
                        %message_id,
                        num_hops = ?hops.len(),
                        "build outbound tunnel via 0-hop tunnel",
                    );

                    match PendingTunnel::<OutboundTunnel<R>>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            name: self.config.name.clone(),
                            noise: self.router_ctx.noise().clone(),
                            message_id,
                            tunnel_info: TunnelInfo::Outbound {
                                gateway,
                                tunnel_id,
                                router_id: self.router_ctx.noise().local_router_hash().clone(),
                            },
                            receiver: ReceiverKind::Outbound,
                        },
                    ) {
                        Ok((tunnel, router_id, message)) => {
                            // spawn the fake 0-hop inbound tunnel in the background if it exists
                            //
                            // it will exit after receiving its first message because
                            // the tunnel is only used for this particular build request
                            R::spawn(zero_hop_tunnel);

                            // add pending tunnel into outbound tunnel build listener and send
                            // tunnel build request to the first hop
                            //
                            // give tunnel listener a oneshot receiver which it must poll before
                            // waiting for tunnel build result to ensure that dialing the next hop
                            // succeeded
                            let (dial_tx, dial_rx) = oneshot::channel();

                            self.pending_outbound.add_pending_tunnel(
                                tunnel,
                                ReceiveKind::ZeroHop,
                                message_rx,
                                dial_rx,
                            );
                            self.router_ctx
                                .metrics_handle()
                                .gauge(NUM_PENDING_OUTBOUND_TUNNELS)
                                .increment(1);

                            if let Err(error) = self.routing_table.send_message_with_feedback(
                                router_id,
                                message.serialize_short(),
                                dial_tx,
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "failed to send outbound tunnel build message (0-hop)",
                                );
                                debug_assert!(false);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                name = %self.config.name,
                                %tunnel_id,
                                %message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );

                            self.routing_table.remove_tunnel(&gateway);
                            self.routing_table.remove_listener(&message_id);
                        }
                    }
                }
                // inbound tunnel available
                //
                // add message listener for selected tunnel's tunnel pool and send the build request
                //
                // once the tunnel build reply is received into the selected inbound tunnel (which
                // could be in a different pool), it'll be received by the selected tunnel's
                // `TunnelPool` which routes the message to the listener
                Some((gateway, router_id, handle)) => {
                    // if an inbound tunnel exists, the reply is routed through it and received
                    // by its `TunnelPool` which routes the message to the listener
                    let (message_id, message_rx) = handle.add_listener(&mut R::rng());

                    tracing::trace!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        %gateway,
                        %router_id,
                        %message_id,
                        num_hops = ?hops.len(),
                        "build outbound tunnel via existing inbound tunnel",
                    );

                    match PendingTunnel::<OutboundTunnel<R>>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            name: self.config.name.clone(),
                            noise: self.router_ctx.noise().clone(),
                            message_id,
                            tunnel_info: TunnelInfo::Outbound {
                                gateway,
                                router_id: Bytes::from(Into::<Vec<u8>>::into(router_id)),
                                tunnel_id,
                            },
                            receiver: ReceiverKind::Outbound,
                        },
                    ) {
                        Ok((tunnel, router_id, message)) => {
                            // listening for outbound tunnel build responses through an existing
                            // inbound tunnel is more complex than listening through a fake 0-hop
                            // inbound tunnel since the inbound tunnel is not expecting to receive
                            // just one message and because the selected OBEP has freedom to choose
                            // whether to garlic encrypt the tunnel build response or not
                            //
                            // if the response is not garlic encrypted, it'll be identified by the
                            // generated message id and if it is garlic encrypted, it'll be
                            // identified by the garlic tag which means that the inbound tunnel must
                            // have two listener types, one for the unecrypted response and one for
                            // the encrypted response
                            handle.add_garlic_listener(message_id, tunnel.garlic_tag());

                            // add pending tunnel into outbound tunnel build listener
                            // and send tunnel build request to the first hop
                            //
                            // give tunnel listener a oneshot receiver which it must poll before
                            // waiting for tunnel build result to ensure that dialing the next hop
                            // succeeded
                            let (dial_tx, dial_rx) = oneshot::channel();

                            self.pending_outbound.add_pending_tunnel(
                                tunnel,
                                ReceiveKind::Tunnel {
                                    handle: handle.clone(),
                                    message_id,
                                },
                                message_rx,
                                dial_rx,
                            );
                            self.router_ctx
                                .metrics_handle()
                                .gauge(NUM_PENDING_OUTBOUND_TUNNELS)
                                .increment(1);

                            if let Err(error) = self.routing_table.send_message_with_feedback(
                                router_id,
                                message.serialize_short(),
                                dial_tx,
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "failed to send outbound tunnel build message",
                                );
                                debug_assert!(false);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                name = %self.config.name,
                                %tunnel_id,
                                %message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );

                            handle.remove_listener(&message_id);
                        }
                    }
                }
            }
        }

        // build one or more inbound tunnels
        for _ in 0..self.calculate_inbound_build_count() {
            // tunnel that's used to deliver the tunnel build request message
            //
            // if it's `None`, a fake 0-hop outbound tunnel is used
            let send_tunnel_id = self.selector.select_outbound_tunnel();

            // select hops for the tunnel
            let Some(hops) = self.selector.select_hops(self.config.num_inbound_hops) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    name = %self.config.name,
                    hops_required = ?self.config.num_inbound_hops,
                    "not enough routers for inbound tunnel build",
                );
                continue;
            };

            // generate message id for the build request and optimistically insert
            // a listener tx channel for it in the routing table
            //
            // if the building the build request fails, the listener must be removed
            // from the routing table
            let (message_id, message_rx) = self.routing_table.insert_listener(&mut R::rng());

            // generate tunnel id for the inbound tunnel that's about to be built
            let (tunnel_id, tunnel_rx) =
                self.routing_table.insert_tunnel::<TUNNEL_CHANNEL_SIZE>(&mut R::rng());

            match PendingTunnel::<InboundTunnel<R>>::create_tunnel::<R>(TunnelBuildParameters {
                hops,
                name: self.config.name.clone(),
                noise: self.router_ctx.noise().clone(),
                message_id,
                tunnel_info: TunnelInfo::Inbound {
                    tunnel_id,
                    router_id: self.router_ctx.noise().local_router_hash().clone(),
                },
                receiver: ReceiverKind::Inbound {
                    message_rx: tunnel_rx,
                    handle: self.context.context_handle(),
                },
            }) {
                Ok((tunnel, router, message)) => {
                    // add pending tunnel into outbound tunnel build listener and send
                    // tunnel build request to the first hop
                    //
                    // give tunnel listener a oneshot receiver which it must poll before
                    // waiting for tunnel build result to ensure that dialing the next hop
                    // succeeded
                    let (dial_tx, dial_rx) = oneshot::channel();

                    self.pending_inbound.add_pending_tunnel(
                        tunnel,
                        ReceiveKind::RoutingTable { message_id },
                        message_rx,
                        dial_rx,
                    );
                    self.router_ctx
                        .metrics_handle()
                        .gauge(NUM_PENDING_INBOUND_TUNNELS)
                        .increment(1);

                    match send_tunnel_id {
                        None => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                name = %self.config.name,
                                %tunnel_id,
                                "no outbound tunnel available, send build request to router",
                            );

                            if let Err(error) = self.routing_table.send_message_with_feedback(
                                router,
                                message.serialize_short(),
                                dial_tx,
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "failed to send inbond tunnel build message",
                                );
                                debug_assert!(false);
                            }
                        }
                        Some((send_tunnel_id, handle)) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                name = %self.config.name,
                                %tunnel_id,
                                %send_tunnel_id,
                                "send tunnel build request to local outbound tunnel",
                            );

                            // the message is sent through a handle and not directly using the
                            // tunnel pool's outbound tunnels (`self.outboun`) because the tunnel
                            // build message might be for a client tunnel pool that is being created
                            // and thus doesn't have any available outbound tunnels meaning the TBM
                            // is sent via the exploratory pool
                            if let Err(error) = handle.send_to_router_with_feedback(
                                send_tunnel_id,
                                router,
                                message.serialize_standard(),
                                dial_tx,
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    name = %self.config.name,
                                    %tunnel_id,
                                    %send_tunnel_id,
                                    ?error,
                                    "failed to send message to outbound tunnel"
                                );
                            }
                            self.router_ctx.metrics_handle().histogram(NUM_FRAGMENTS).record(1f64);
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        %message_id,
                        ?error,
                        "failed to create outbound tunnel",
                    );

                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.routing_table.remove_listener(&message_id);
                    continue;
                }
            }
        }

        // test active tunnels
        //
        // for pairs of active inbound and outbound tunnels, send a test message through and
        // outbound tunnel and request the obep of that tunnel to route the message to the selected
        // inbound tunnel
        //
        // for each message, start a timer which expires after 8 seconds and if the response is
        // received into the selected inbound tunnel within the time limit, the tunnel is considered
        // operational
        //
        // perform test only if enough time has elapsed since the last time
        if self.last_tunnel_test.elapsed() < TUNNEL_TEST_INTERVAL {
            return;
        }
        self.last_tunnel_test = R::now();

        self.outbound
            .keys()
            .filter(|tunnel_id| !self.expiring_outbound.contains(*tunnel_id))
            .copied()
            .zip(
                self.inbound_tunnels.iter().filter_map(|(tunnel_id, router)| {
                    (!self.expiring_inbound.contains(tunnel_id)).then_some((*tunnel_id, router))
                }),
            )
            .for_each(|(outbound, (inbound, (_, router)))| {
                // allocate new message id and an RX channel for receiving the tunnel test message
                let (message_id, message_rx) = self.context.add_listener(&mut R::rng());

                tracing::trace!(
                    target: LOG_TARGET,
                    name = %self.config.name,
                    %outbound,
                    %inbound,
                    %router,
                    %message_id,
                    "test tunnel",
                );

                // create dummy test message and send it through the outbound tunnel
                // to the selected inbound tunnel's gateway
                let payload = {
                    let mut out = BytesMut::with_capacity(11 + 4);
                    out.put_u32(11);
                    out.put_slice(b"tunnel test".as_ref());

                    out
                };

                // wrap the message inside a garlic message destined to ourselves
                let message = {
                    let expiration = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                    let mut message = GarlicMessageBuilder::default()
                        .with_date_time(R::time_since_epoch().as_secs() as u32)
                        .with_garlic_clove(
                            MessageType::Data,
                            message_id,
                            expiration,
                            DeliveryInstructions::Local,
                            &MessageBuilder::standard()
                                .with_expiration(expiration)
                                .with_message_type(MessageType::Data)
                                .with_message_id(message_id)
                                .with_payload(&payload)
                                .build(),
                        )
                        .build();

                    let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
                    let ephemeral_public = ephemeral_secret.public();
                    let (key, tag) = self.router_ctx.noise().derive_outbound_garlic_key(
                        self.router_ctx.noise().local_public_key(),
                        ephemeral_secret,
                    );

                    // message length + poly13055 tg + ephemeral key + garlic message length
                    let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

                    // encryption must succeed since the parameters are managed by us
                    ChaChaPoly::new(&key)
                        .encrypt_with_ad_new(&tag, &mut message)
                        .expect("to succeed");

                    out.put_u32(message.len() as u32 + 32);
                    out.put_slice(&ephemeral_public.to_vec());
                    out.put_slice(&message);

                    MessageBuilder::standard()
                        .with_expiration(expiration)
                        .with_message_type(MessageType::Garlic)
                        .with_message_id(message_id)
                        .with_payload(&out)
                        .build()
                };

                // outbound tunnel must exist since it was jus iterated over
                let (router, mut messages) = self
                    .outbound
                    .get(&outbound)
                    .expect("outbound tunnel to exist")
                    .send_to_tunnel(router.clone(), inbound, message);

                // message must exist since it's a valid i2np message
                match self
                    .routing_table
                    .send_message(router, messages.next().expect("message to exist"))
                {
                    Ok(_) => self.pending_tests.push(async move {
                        let started = R::now();

                        match select(message_rx, pin!(R::delay(TUNNEL_TEST_EXPIRATION))).await {
                            Either::Right((_, _)) => (outbound, inbound, Err(Error::Timeout)),
                            Either::Left((Err(_), _)) =>
                                (outbound, inbound, Err(Error::Channel(ChannelError::Closed))),
                            Either::Left((Ok(_), _)) => (outbound, inbound, Ok(started.elapsed())),
                        }
                    }),
                    Err(error) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %outbound,
                            %inbound,
                            ?error,
                            "failed to send tunnel test message",
                        );

                        self.context.remove_listener(&message_id);
                    }
                }
                self.router_ctx.metrics_handle().histogram(NUM_FRAGMENTS).record(1f64);

                debug_assert!(messages.next().is_none());
            });
    }
}

impl<R: Runtime, S: TunnelSelector + HopSelector> Future for TunnelPool<R, S> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // counter for keeping track of how many tunnel builds failed
        //
        // it's used to check if `TunnelPool::maintain_pool()` should be called before its timer
        // expires so the pool doesn't unnecessarily wait for a timeout when it could be building a
        // tunnel instead
        let mut num_failed_builds = 0;

        // poll pending outbound tunnels
        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_outbound.poll_next_unpin(cx)
        {
            match event {
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        ?error,
                        "failed to build outbound tunnel",
                    );
                    num_failed_builds += 1;

                    self.router_ctx.metrics_handle().counter(NUM_BUILD_FAILURES).increment(1);
                    self.router_ctx
                        .metrics_handle()
                        .gauge(NUM_PENDING_OUTBOUND_TUNNELS)
                        .decrement(1);
                    self.num_tunnel_build_failures += 1;
                }
                Ok(tunnel) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        outbound_tunnel_id = %tunnel.tunnel_id(),
                        "outbound tunnel built",
                    );

                    self.selector.add_outbound_tunnel(tunnel_id, tunnel.hops());
                    self.outbound.insert(tunnel_id, tunnel);
                    self.tunnel_timers.add_outbound_tunnel(tunnel_id);
                    self.router_ctx
                        .metrics_handle()
                        .gauge(NUM_PENDING_OUTBOUND_TUNNELS)
                        .decrement(1);
                    self.router_ctx.metrics_handle().gauge(NUM_OUTBOUND_TUNNELS).increment(1);
                    self.router_ctx.metrics_handle().counter(NUM_BUILD_SUCCESSES).increment(1);
                    self.num_tunnels_built += 1;

                    // inform the owner of the tunnel pool that a new outbound tunnel has been built
                    if let Err(error) = self.context.register_outbound_tunnel_built(tunnel_id) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %tunnel_id,
                            ?error,
                            "failed to register new outbound tunnel to owner",
                        );
                    }
                }
            }
        }

        // poll pending inbound tunnels
        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_inbound.poll_next_unpin(cx) {
            match event {
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        ?error,
                        "failed to build inbound tunnel",
                    );
                    num_failed_builds += 1;

                    self.num_tunnel_build_failures += 1;
                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.router_ctx.metrics_handle().counter(NUM_BUILD_FAILURES).increment(1);
                    self.router_ctx
                        .metrics_handle()
                        .gauge(NUM_PENDING_INBOUND_TUNNELS)
                        .decrement(1);
                }
                Ok(tunnel) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        tunnel_id = %tunnel.tunnel_id(),
                        "inbound tunnel built",
                    );

                    // fetch the newly created inbound tunnel's gateway information
                    //
                    // in order for the inbound tunnel to be usable, it's gateway information must
                    // be stored in selector/routing table, as opposed to the endpoint information,
                    // because the gateway is used to receive messages
                    let (router_id, gateway_tunnel_id) = tunnel.gateway();
                    self.selector.add_inbound_tunnel(
                        gateway_tunnel_id,
                        router_id.clone(),
                        tunnel.hops(),
                    );
                    self.inbound_tunnels.insert(gateway_tunnel_id, (tunnel_id, router_id.clone()));
                    self.tunnel_timers.add_inbound_tunnel(gateway_tunnel_id);
                    self.num_tunnels_built += 1;

                    // inform the owner of the tunnel pool that a new inbound tunnel has been built
                    if let Err(error) = self.context.register_inbound_tunnel_built(
                        gateway_tunnel_id,
                        Lease {
                            router_id,
                            tunnel_id: gateway_tunnel_id,
                            expires: R::time_since_epoch() + TUNNEL_EXPIRATION,
                        },
                    ) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %gateway_tunnel_id,
                            ?error,
                            "failed to register new inbound tunnel to owner",
                        );
                    }

                    self.inbound.push(tunnel);
                    self.router_ctx.metrics_handle().gauge(NUM_INBOUND_TUNNELS).increment(1);
                    self.router_ctx
                        .metrics_handle()
                        .gauge(NUM_PENDING_INBOUND_TUNNELS)
                        .decrement(1);
                    self.router_ctx.metrics_handle().counter(NUM_BUILD_SUCCESSES).increment(1);
                }
            }
        }

        // poll event loops of inbound tunnels
        while let Poll::Ready(event) = self.inbound.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some((tunnel_id, gateway_tunnel_id)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        %gateway_tunnel_id,
                        "inbound tunnel expired",
                    );

                    self.expiring_inbound.remove(&gateway_tunnel_id);
                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.selector.remove_inbound_tunnel(&gateway_tunnel_id);
                    self.inbound_tunnels.remove(&gateway_tunnel_id);
                    self.router_ctx.metrics_handle().gauge(NUM_INBOUND_TUNNELS).decrement(1);

                    // inform the owner of the tunnel pool that an inbound tunnel has expired
                    if let Err(error) =
                        self.context.register_inbound_tunnel_expired(gateway_tunnel_id)
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %gateway_tunnel_id,
                            ?error,
                            "failed to register expired inbound tunnel to owner",
                        );
                    }
                }
            }
        }

        // poll tunnel message context
        //
        // tunnel message context receives two types of events:
        //  1) inbound tunnel events
        //  2) outbound tunnel events
        //
        // inbound tunnel events are received from the network and a route for them couldn't be
        // found from the `TunnelHandle`'s routing table which causes them to be routed to
        // `TunnelPool` for further processing
        //
        // outbound tunnel events are received from destinations/other tunnel pools that wish to
        // send message over one of this tunnel pool's outbound tunnels, e.g., when sending a tunnel
        // build request to remote
        while let Poll::Ready(event) = self.context.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(event) => match event {
                    TunnelMessage::Dummy => unreachable!(),
                    TunnelMessage::RouterDelivery {
                        gateway,
                        router_id,
                        message,
                        feedback_tx,
                    } => match self.outbound.get(&gateway) {
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %gateway,
                            "cannot send message, outbound tunnel doesn't exist",
                        ),
                        Some(tunnel) => {
                            let (router_id, messages) = tunnel.send_to_router(router_id, message);

                            let (_, count) = messages.into_iter().fold(
                                (feedback_tx, 0usize),
                                |(mut feedback_tx, count), message| {
                                    match feedback_tx.take() {
                                        Some(feedback_tx) => {
                                            if let Err(error) =
                                                self.routing_table.send_message_with_feedback(
                                                    router_id.clone(),
                                                    message,
                                                    feedback_tx,
                                                )
                                            {
                                                tracing::warn!(
                                                    target: LOG_TARGET,
                                                    name = %self.config.name,
                                                    %gateway,
                                                    ?error,
                                                    "failed to send tunnel message to router",
                                                );
                                            }
                                        }
                                        None => {
                                            if let Err(error) = self
                                                .routing_table
                                                .send_message(router_id.clone(), message)
                                            {
                                                tracing::warn!(
                                                    target: LOG_TARGET,
                                                    name = %self.config.name,
                                                    %gateway,
                                                    ?error,
                                                    "failed to send tunnel message to router",
                                                );
                                            }
                                        }
                                    }

                                    (None, count + 1)
                                },
                            );
                            self.router_ctx
                                .metrics_handle()
                                .histogram(NUM_FRAGMENTS)
                                .record(count as f64);
                        }
                    },
                    TunnelMessage::TunnelDelivery {
                        gateway,
                        tunnel_id,
                        message,
                    } => {
                        // TODO: needs to be fairer
                        let Some((outbound_gateway, tunnel)) = self.outbound.iter().next() else {
                            tracing::warn!(
                                target: LOG_TARGET,
                                name = %self.config.name,
                                "failed to send tunnel message, no outbound tunnel available",
                            );
                            continue;
                        };

                        tracing::trace!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %outbound_gateway,
                            "send tunnel message to remote destination",
                        );

                        let (router_id, messages) =
                            tunnel.send_to_tunnel(gateway.clone(), tunnel_id, message);

                        let count = messages.into_iter().fold(0usize, |count, message| {
                            if let Err(error) =
                                self.routing_table.send_message(router_id.clone(), message)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    name = %self.config.name,
                                    %gateway,
                                    ?error,
                                    "failed to send tunnel message to router",
                                );
                            }

                            count + 1
                        });
                        self.router_ctx
                            .metrics_handle()
                            .histogram(NUM_FRAGMENTS)
                            .record(count as f64);
                    }
                    TunnelMessage::RouterDeliveryViaRoute {
                        router_id,
                        outbound_tunnel,
                        message,
                    } => {
                        let (outbound_gateway, tunnel) = match outbound_tunnel {
                            None => match self.outbound.iter().next() {
                                Some((obgw_tunnel_id, tunnel)) => (*obgw_tunnel_id, tunnel),
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        name = %self.config.name,
                                        "failed to send tunnel message, no outbound tunnel available",
                                    );
                                    continue;
                                }
                            },
                            Some(obgw_tunnel_id) => match self.outbound.get(&obgw_tunnel_id) {
                                Some(tunnel) => (obgw_tunnel_id, tunnel),
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        ?obgw_tunnel_id,
                                        "outbound tunnel specified by routing path doesn't exist",
                                    );
                                    debug_assert!(false);

                                    let Some((outbound_gateway, tunnel)) =
                                        self.outbound.iter().next()
                                    else {
                                        tracing::warn!(
                                            target: LOG_TARGET,
                                            name = %self.config.name,
                                            "failed to send tunnel message, no outbound tunnel available",
                                        );
                                        continue;
                                    };

                                    (*outbound_gateway, tunnel)
                                }
                            },
                        };

                        let (router_id, messages) = tunnel.send_to_router(router_id, message);

                        let count = messages.into_iter().fold(0usize, |count, message| {
                            if let Err(error) =
                                self.routing_table.send_message(router_id.clone(), message)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    name = %self.config.name,
                                    %outbound_gateway,
                                    ?error,
                                    "failed to send tunnel message to router",
                                );
                            }

                            count + 1
                        });

                        self.router_ctx
                            .metrics_handle()
                            .histogram(NUM_FRAGMENTS)
                            .record(count as f64);
                    }
                    TunnelMessage::TunnelDeliveryViaRoute {
                        router_id: ibgw_router_id,
                        tunnel_id: ibgw_tunnel_id,
                        outbound_tunnel,
                        message,
                    } => {
                        let (outbound_gateway, tunnel) = match outbound_tunnel {
                            None => match self.outbound.iter().next() {
                                Some((obgw_tunnel_id, tunnel)) => (*obgw_tunnel_id, tunnel),
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        name = %self.config.name,
                                        "failed to send tunnel message, no outbound tunnel available",
                                    );
                                    continue;
                                }
                            },
                            Some(obgw_tunnel_id) => match self.outbound.get(&obgw_tunnel_id) {
                                Some(tunnel) => (obgw_tunnel_id, tunnel),
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        ?obgw_tunnel_id,
                                        "outbound tunnel specified by routing path doesn't exist",
                                    );
                                    debug_assert!(false);

                                    let Some((outbound_gateway, tunnel)) =
                                        self.outbound.iter().next()
                                    else {
                                        tracing::warn!(
                                            target: LOG_TARGET,
                                            name = %self.config.name,
                                            "failed to send tunnel message, no outbound tunnel available",
                                        );
                                        continue;
                                    };

                                    (*outbound_gateway, tunnel)
                                }
                            },
                        };

                        tracing::trace!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %outbound_gateway,
                            "send tunnel message to remote destination",
                        );

                        let (router_id, messages) =
                            tunnel.send_to_tunnel(ibgw_router_id.clone(), ibgw_tunnel_id, message);

                        let count = messages.into_iter().fold(0usize, |count, message| {
                            if let Err(error) =
                                self.routing_table.send_message(router_id.clone(), message)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    name = %self.config.name,
                                    %ibgw_router_id,
                                    %ibgw_tunnel_id,
                                    obgw_tunnel_id = %outbound_gateway,
                                    ?error,
                                    "failed to send tunnel message to router",
                                );
                            }

                            count + 1
                        });

                        self.router_ctx
                            .metrics_handle()
                            .histogram(NUM_FRAGMENTS)
                            .record(count as f64);
                    }
                    TunnelMessage::Inbound { message } => tracing::warn!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        message_type = ?message.message_type,
                        "unhandled message"
                    ),
                },
            }
        }

        // poll tunnel tests
        while let Poll::Ready(event) = self.pending_tests.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some((outbound, inbound, result)) => match result {
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %outbound,
                            %inbound,
                            ?error,
                            "tunnel test failed",
                        );

                        self.selector.register_tunnel_test_failure(&outbound, &inbound);
                        self.router_ctx.metrics_handle().counter(NUM_TEST_FAILURES).increment(1);
                    }
                    Ok(elapsed) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %outbound,
                            %inbound,
                            ?elapsed,
                            "tunnel test succeeded",
                        );

                        self.selector.register_tunnel_test_success(&outbound, &inbound);
                        self.router_ctx.metrics_handle().counter(NUM_TEST_SUCCESSES).increment(1);
                        self.router_ctx
                            .metrics_handle()
                            .histogram(TUNNEL_TEST_DURATIONS)
                            .record(elapsed.as_millis() as f64);
                    }
                },
            }
        }

        // poll tunnel timers
        //
        // both inbound and outbound tunnels emit `Rebuild` events which indicate that the tunnel is
        // about to expire and tunnel pool should build a replacement for the expiring tunnel
        //
        // as outbound tunnels do not have an asynchronous event loop but are instead stored in
        // tunnel pool, `TunnelTimer` also emits a `Destroy` event for them so tunnel pool knows
        // when to remove them from `outbound`
        //
        // inbound tunnels have their own event loops which track when the tunnel should be
        // destroyed and thus tunnel pool doesn't need an explicit signal from `TunnelTimer` for
        // inbound tunnel destruction
        while let Poll::Ready(event) = self.tunnel_timers.poll_next_unpin(cx) {
            match event {
                None => return Poll::Ready(()),
                Some(TunnelTimerEvent::Destroy { tunnel_id }) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        "outbound tunnel expired",
                    );
                    self.outbound.remove(&tunnel_id);
                    self.expiring_outbound.remove(&tunnel_id);
                    self.selector.remove_outbound_tunnel(&tunnel_id);

                    // inform the owner of the tunnel pool that an inbound tunnel has expired
                    if let Err(error) = self.context.register_outbound_tunnel_expired(tunnel_id) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %tunnel_id,
                            ?error,
                            "failed to register expired outbound tunnel to owner",
                        );
                    }
                }
                Some(TunnelTimerEvent::Rebuild {
                    kind: TunnelKind::Outbound { tunnel_id },
                }) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        "outbound tunnel is about to expire",
                    );
                    self.expiring_outbound.insert(tunnel_id);

                    if let Err(error) = self.context.register_expiring_outbound_tunnel(tunnel_id) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %tunnel_id,
                            ?error,
                            "failed to register expiring outbound tunnel to owner",
                        );
                    }
                }
                Some(TunnelTimerEvent::Rebuild {
                    kind: TunnelKind::Inbound { tunnel_id },
                }) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        name = %self.config.name,
                        %tunnel_id,
                        "inbound tunnel is about to expire",
                    );
                    self.expiring_inbound.insert(tunnel_id);

                    if let Err(error) = self.context.register_expiring_inbound_tunnel(tunnel_id) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.config.name,
                            %tunnel_id,
                            ?error,
                            "failed to register expiring inbound tunnel to owner",
                        );
                    }
                }
            }
        }

        // check if the pool owner has sent a shutdown signal to the tunnel pool
        //
        // currently `TunnelPool` doesn't do any graceful shutdown for its own tunnels
        // and instead shuts down immediately
        //
        // the client is informed that the pool is shut down before it's shutdown so
        // the destination can starts up its own shutdown process
        if let Some(rx) = &mut self.shutdown_rx {
            if rx.poll_unpin(cx).is_ready() {
                tracing::info!(
                    target: LOG_TARGET,
                    name = %self.config.name,
                    "tunnel pool shutting down",
                );

                self.inbound_tunnels.values().for_each(|(tunnel_id, _)| {
                    self.routing_table.remove_tunnel(tunnel_id);
                });

                if let Err(error) = self.context.register_tunnel_pool_shut_down() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to send shutdown confirmation to tunnel pool owner",
                    );
                }

                return Poll::Ready(());
            }
        }

        if self.event_handle.poll_unpin(cx).is_ready() {
            self.event_handle
                .tunnel_status(self.num_tunnels_built, self.num_tunnel_build_failures);

            // reset counters to zero as the cumulative success/failure tate is tracked by the event
            // system whereas each tunnel pool only  tracks the rate during each report period
            self.num_tunnels_built = 0;
            self.num_tunnel_build_failures = 0;
        }

        match self.maintenance_timer.poll_unpin(cx) {
            Poll::Ready(()) => {
                // create new timer and register it into the executor
                {
                    self.maintenance_timer = R::timer(TUNNEL_MAINTENANCE_INTERVAL);
                    let _ = self.maintenance_timer.poll_unpin(cx);
                }

                self.maintain_pool();
            }
            Poll::Pending if num_failed_builds > 0 => self.maintain_pool(),
            _ => {}
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::RoutingError,
        events::EventManager,
        i2np::Message,
        primitives::{RouterId, RouterInfoBuilder},
        profile::ProfileStorage,
        runtime::mock::MockRuntime,
        tunnel::{
            garlic::DeliveryInstructions as GarlicDeliveryInstructions,
            pool::selector::ClientSelector,
            routing_table::{RoutingKind, RoutingKindRecycle},
            tests::TestTransitTunnelManager,
        },
    };
    use thingbuf::mpsc;

    #[tokio::test]
    async fn build_outbound_exploratory_tunnel() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // route tunnel build response to the fake 0-hop inbound tunnel
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message).unwrap();

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn outbound_exploratory_build_request_expires() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (_router, _message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(TUNNEL_BUILD_EXPIRATION, &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));
    }

    #[tokio::test]
    async fn build_inbound_exploratory_tunnel() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);
        let message = match routers
            .get_mut(&router)
            .unwrap()
            .garlic()
            .handle_message(message)
            .unwrap()
            .next()
        {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // route tunnel build response to the tunnel build response listener
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message).unwrap();

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn inbound_exploratory_build_request_expires() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);
        let message = match routers
            .get_mut(&router)
            .unwrap()
            .garlic()
            .handle_message(message)
            .unwrap()
            .next()
        {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (_router, _message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(
            TUNNEL_BUILD_EXPIRATION + Duration::from_secs(1),
            &mut tunnel_pool
        )
        .await
        .is_err());
        assert_eq!(tunnel_pool.inbound.len(), 0);
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1))
    }

    #[tokio::test]
    async fn build_inbound_client_tunnel() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let exploratory_selector =
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false);
        let router_ctx = RouterContext::new(
            handle.clone(),
            profile_storage,
            router_info.identity.id(),
            Bytes::from(router_info.serialize(&signing_key)),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let (mut exploratory_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            exploratory_selector.clone(),
            routing_table.clone(),
            router_ctx.clone(),
        );

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // route tunnel build response to the fake 0-hop inbound tunnel
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.outbound.len(), 1);
        assert_eq!(exploratory_pool.pending_outbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));

        {
            let pool_config = TunnelPoolConfig {
                num_inbound: 1usize,
                num_inbound_hops: 3usize,
                num_outbound: 0usize,
                num_outbound_hops: 0usize,
                name: Str::from("client"),
            };
            let client_parameters = TunnelPoolBuildParameters::new(pool_config);
            let client_pool_handle = client_parameters.context_handle.clone();
            let client_selector =
                ClientSelector::new(exploratory_selector.clone(), client_pool_handle);

            let (mut client_pool, _client_handle) = TunnelPool::<MockRuntime, _>::new(
                client_parameters,
                client_selector,
                routing_table.clone(),
                router_ctx.clone(),
            );

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());

            // inbound tunnel build is garlic encrypted and exceeds the tunnel data limit
            // so it's split into two fragments
            let mut obep = Option::<RouterId>::None;

            while let Ok(RoutingKind::ExternalWithFeedback {
                router_id,
                message,
                tx,
            }) = manager_rx.try_recv()
            {
                tx.send(()).unwrap();

                // 1st hop (participant)
                let (router_id, message) = {
                    let message = Message::parse_short(&message).unwrap();
                    let mut router = routers.get_mut(&router_id).unwrap();

                    router.routing_table().route_message(message).unwrap();
                    assert!(
                        tokio::time::timeout(Duration::from_millis(250), &mut router)
                            .await
                            .is_err()
                    );

                    let RoutingKind::External { router_id, message } =
                        router.message_rx().try_recv().unwrap()
                    else {
                        panic!("invalid routing kind");
                    };
                    (router_id, message)
                };

                // 2nd hop (participant)
                let (router_id, message) = {
                    let message = Message::parse_short(&message).unwrap();
                    let mut router = routers.get_mut(&router_id).unwrap();

                    router.routing_table().route_message(message).unwrap();
                    assert!(
                        tokio::time::timeout(Duration::from_millis(250), &mut router)
                            .await
                            .is_err()
                    );

                    let RoutingKind::External { router_id, message } =
                        router.message_rx().try_recv().unwrap()
                    else {
                        panic!("invalid routing kind");
                    };
                    (router_id, message)
                };

                // 3rd hop (obep)
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();
                obep = Some(router_id);

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(250), &mut router).await.is_err()
                );
            }

            let router = routers.get_mut(&obep.unwrap()).unwrap();
            let RoutingKind::External { router_id, message } =
                router.message_rx().try_recv().unwrap()
            else {
                panic!("invalid routing kind");
            };

            // inbound build 1st hop (ibgw)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                assert_eq!(message.message_type, MessageType::Garlic);
                let message = match router.garlic().handle_message(message).unwrap().next() {
                    Some(GarlicDeliveryInstructions::Local { message }) => message,
                    _ => panic!("invalid delivery instructions"),
                };

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(250), &mut router).await.is_err()
                );

                let RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                } = router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                let _ = tx.send(());

                (router_id, message)
            };

            // inbound build 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(1), &mut router).await.is_err());

                let RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                } = router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                let _ = tx.send(());

                (router_id, message)
            };

            // inbound build 3rd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(250), &mut router).await.is_err()
                );

                let RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                } = router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                let _ = tx.send(());

                (router_id, message)
            };

            assert_eq!(&router_id, router_ctx.router_id());

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message).unwrap();

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());
        }

        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn build_outbound_client_tunnel() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);

        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let exploratory_selector =
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false);
        let router_ctx = RouterContext::new(
            handle.clone(),
            profile_storage,
            router_info.identity.id(),
            Bytes::from(router_info.serialize(&signing_key)),
            static_key,
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let (mut exploratory_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            exploratory_selector.clone(),
            routing_table.clone(),
            router_ctx.clone(),
        );

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);
        let message = match routers
            .get_mut(&router)
            .unwrap()
            .garlic()
            .handle_message(message)
            .unwrap()
            .next()
        {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // route tunnel build response to the tunnel build response listener
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut exploratory_pool)
                .await
                .is_err()
        );
        assert_eq!(exploratory_pool.inbound.len(), 1);
        assert_eq!(exploratory_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        {
            let pool_config = TunnelPoolConfig {
                num_inbound: 0usize,
                num_inbound_hops: 0usize,
                num_outbound: 1usize,
                num_outbound_hops: 3usize,
                name: Str::from("client"),
                ..Default::default()
            };
            let parameters = TunnelPoolBuildParameters::new(pool_config);
            let pool_handle = parameters.context_handle.clone();
            let client_selector = ClientSelector::new(exploratory_selector, pool_handle);

            let (mut client_pool, _client_handle) = TunnelPool::<MockRuntime, _>::new(
                parameters,
                client_selector,
                routing_table.clone(),
                router_ctx.clone(),
            );

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_err());

            let Ok(RoutingKind::ExternalWithFeedback {
                router_id,
                message,
                tx,
            }) = manager_rx.try_recv()
            else {
                panic!("invalid routing kind")
            };
            tx.send(()).unwrap();

            // outbound build 1st hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut router).await.is_err()
                );

                let RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                } = router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                let _ = tx.send(());

                (router_id, message)
            };

            // outbound build 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut router).await.is_err()
                );

                let RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                } = router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                let _ = tx.send(());

                (router_id, message)
            };

            // outbound build 3rd hop (obep)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut router).await.is_err()
                );

                let RoutingKind::ExternalWithFeedback {
                    router_id,
                    message,
                    tx,
                } = router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                let _ = tx.send(());

                (router_id, message)
            };

            // build reply 1st hop (ibgw)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut router).await.is_err()
                );

                let RoutingKind::External { router_id, message } =
                    router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                (router_id, message)
            };

            // build reply 2nd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut router).await.is_err()
                );

                let RoutingKind::External { router_id, message } =
                    router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                (router_id, message)
            };

            // build reply 3rd hop (participant)
            let (router_id, message) = {
                let message = Message::parse_short(&message).unwrap();
                let mut router = routers.get_mut(&router_id).unwrap();

                router.routing_table().route_message(message).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut router).await.is_err()
                );

                let RoutingKind::External { router_id, message } =
                    router.message_rx().try_recv().unwrap()
                else {
                    panic!("invalid routing kind");
                };
                (router_id, message)
            };
            assert_eq!(&router_id, router_ctx.router_id());

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message).unwrap();

            let future = async {
                tokio::select! {
                    _ = &mut client_pool => {}
                    _ = &mut exploratory_pool => {}
                }
            };

            assert!(tokio::time::timeout(Duration::from_secs(4), future).await.is_err());
        }

        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));
    }

    #[tokio::test]
    async fn exploratory_outbound_build_reply_received_late() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(Duration::from_secs(8), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));

        // route message to listener after timeout
        let message = Message::parse_short(&message).unwrap();
        match routing_table.route_message(message).unwrap_err() {
            RoutingError::RouteNotFound(_, _) => {}
            error => panic!("invalid error: {error:?}"),
        }

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));
    }

    #[tokio::test]
    async fn exploratory_inbound_build_reply_received_late() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);
        let message = match routers
            .get_mut(&router)
            .unwrap()
            .garlic()
            .handle_message(message)
            .unwrap()
            .next()
        {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(Duration::from_secs(10), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1));

        // route message to listener after timeout
        let message = Message::parse_short(&message).unwrap();
        let _ = routing_table.route_message(message);

        // verify it's routed to transit manager which'll reject it
        assert!(transit_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn exploratory_tunnel_test() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..20)
            .map(|_| {
                let transit = TestTransitTunnelManager::new(false);
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 2usize,
            num_outbound: 1usize,
            num_outbound_hops: 2usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let our_id = router_info.identity.id();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // build one inbound and one outbound tunnel
        for _ in 0..2 {
            let Ok(RoutingKind::ExternalWithFeedback {
                router_id: router,
                message,
                tx,
            }) = manager_rx.try_recv()
            else {
                panic!("invalid routing kind")
            };
            tx.send(()).unwrap();

            // 1st outbound hop
            let message = Message::parse_short(&message).unwrap();
            let message = match message.message_type {
                MessageType::Garlic => match routers
                    .get_mut(&router)
                    .unwrap()
                    .garlic()
                    .handle_message(message)
                    .unwrap()
                    .next()
                {
                    Some(GarlicDeliveryInstructions::Local { message }) => message,
                    _ => panic!("invalid delivery instructions"),
                },
                _ => message,
            };

            let (router, message, tx) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }

            // 2nd outbound hop
            let message = Message::parse_short(&message).unwrap();
            let (_router, message, tx) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message).unwrap();

            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut tunnel_pool)
                    .await
                    .is_err()
            );
        }

        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        assert!(tokio::time::timeout(Duration::from_secs(20), &mut tunnel_pool).await.is_err());
        let Ok(RoutingKind::External {
            router_id: router,
            message,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };

        // 1st outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());

        let RoutingKind::External {
            router_id: router,
            message,
        } = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };
        assert!(routers.get_mut(&router).unwrap().message_rx().try_recv().is_err());

        // 2nd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());
        let RoutingKind::External {
            router_id: router,
            message,
        } = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };

        // 1st inbound hop (ibgw)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());
        let RoutingKind::External {
            router_id: router,
            message,
        } = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };

        // 2nd inbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());
        let RoutingKind::External {
            router_id: router,
            message,
        } = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };

        // route response to local router and verify that tunnel test is considered succeeded
        assert_eq!(router, our_id);

        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(250), &mut tunnel_pool)
                .await
                .is_err()
        );

        assert_eq!(MockRuntime::get_counter_value(NUM_TEST_SUCCESSES), Some(1));
    }

    #[tokio::test]
    async fn exploratory_tunnel_test_expires() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 2usize,
            num_outbound: 1usize,
            num_outbound_hops: 2usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, _handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // build one inbound and one outbound tunnel
        for _ in 0..2 {
            let Ok(RoutingKind::ExternalWithFeedback {
                router_id: router,
                message,
                tx,
            }) = manager_rx.try_recv()
            else {
                panic!("invalid routing kind")
            };
            tx.send(()).unwrap();

            // 1st outbound hop
            let message = Message::parse_short(&message).unwrap();
            let message = match message.message_type {
                MessageType::Garlic => match routers
                    .get_mut(&router)
                    .unwrap()
                    .garlic()
                    .handle_message(message)
                    .unwrap()
                    .next()
                {
                    Some(GarlicDeliveryInstructions::Local { message }) => message,
                    _ => panic!("invalid delivery instructions"),
                },
                _ => message,
            };
            let (router, message, tx) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }

            // 2nd outbound hop
            let message = Message::parse_short(&message).unwrap();
            let (_router, message, tx) =
                routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }

            let message = Message::parse_short(&message).unwrap();
            routing_table.route_message(message).unwrap();

            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut tunnel_pool)
                    .await
                    .is_err()
            );
        }

        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_OUTBOUND_TUNNELS), Some(1));
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        assert!(tokio::time::timeout(Duration::from_secs(20), &mut tunnel_pool).await.is_err());
        let Ok(RoutingKind::External {
            router_id: router,
            message,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };

        // 1st outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());

        let RoutingKind::External {
            router_id: router,
            message,
        } = routers.get_mut(&router).unwrap().message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind")
        };
        assert!(routers.get_mut(&router).unwrap().message_rx().try_recv().is_err());

        // 2nd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        routers
            .get_mut(&router)
            .unwrap()
            .routing_table()
            .route_message(message)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(250),
            &mut routers.get_mut(&router).unwrap()
        )
        .await
        .is_err());

        // don't route the test message any further and verify the test timeouts
        assert!(tokio::time::timeout(Duration::from_secs(9), &mut tunnel_pool).await.is_err());
        assert_eq!(MockRuntime::get_counter_value(NUM_TEST_FAILURES), Some(1));
    }

    #[tokio::test]
    async fn inbound_tunnels_removed_from_routing_table() {
        // create 10 routers and add them to local `ProfileStorage`
        let mut routers = (0..10)
            .map(|i| {
                let transit = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });
                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let profile_storage = ProfileStorage::<MockRuntime>::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            ..Default::default()
        };
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let handle = MockRuntime::register_metrics(Vec::new(), None);
        let (manager_tx, manager_rx) = mpsc::with_recycle(64, RoutingKindRecycle::default());
        let (transit_tx, _transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(router_info.identity.id(), manager_tx, transit_tx);
        let parameters = TunnelPoolBuildParameters::new(pool_config);
        let pool_handle = parameters.context_handle.clone();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let (mut tunnel_pool, mut handle) = TunnelPool::<MockRuntime, _>::new(
            parameters,
            ExploratorySelector::new(profile_storage.clone(), pool_handle, false),
            routing_table.clone(),
            RouterContext::new(
                handle.clone(),
                profile_storage,
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);

        // 1st outbound hop (ibgw)
        let Ok(RoutingKind::ExternalWithFeedback {
            router_id: router,
            message,
            tx,
        }) = manager_rx.try_recv()
        else {
            panic!("invalid routing kind")
        };
        tx.send(()).unwrap();

        let message = Message::parse_short(&message).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);
        let message = match routers
            .get_mut(&router)
            .unwrap()
            .garlic()
            .handle_message(message)
            .unwrap()
            .next()
        {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (_router, message, tx) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }

        // route tunnel build response to the tunnel build response listener
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message).unwrap();

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert_eq!(MockRuntime::get_gauge_value(NUM_INBOUND_TUNNELS), Some(1));

        // verify the inbound tunnel exists in the routing table
        let tunnel_id = tunnel_pool.inbound_tunnels.values().next().unwrap().0;

        match routing_table.try_add_tunnel::<6>(tunnel_id) {
            Err(RoutingError::TunnelExists(value)) => {
                assert_eq!(value, tunnel_id);
            }
            _ => panic!("invalid status"),
        }

        // shut down the tunnel pool
        handle.shutdown();
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_ok());

        // try to add the tunnel again and ensure that it succeeds this time because the tunnel
        // pool's tunnels were removed from tunnel pool when it shut down
        match routing_table.try_add_tunnel::<6>(tunnel_id) {
            Ok(_) => {}
            _ => panic!("invalid status"),
        }
    }
}
