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
    config::TransitConfig,
    i2np::Message,
    primitives::RouterId,
    router::context::RouterContext,
    runtime::{MetricType, Runtime},
    shutdown::ShutdownHandle,
    subsystem::SubsystemHandle,
    tunnel::{
        handle::{CommandRecycle, TunnelManagerCommand},
        pool::{ClientSelector, ExploratorySelector, TunnelPool, TunnelPoolBuildParameters},
        transit::TransitTunnelManager,
    },
};

use thingbuf::mpsc::Receiver;

use alloc::vec::Vec;
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
mod transit;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub use garlic::GarlicHandler;
#[cfg(test)]
pub use pool::{TunnelMessage, TunnelMessageRecycle};

pub use garlic::DeliveryInstructions;
pub use handle::TunnelManagerHandle;
pub use noise::NoiseContext;
pub use pool::{TunnelMessageSender, TunnelPoolConfig, TunnelPoolEvent, TunnelPoolHandle};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel";

/// Tunnel expiration, 10 minutes.
const TUNNEL_EXPIRATION: Duration = Duration::from_secs(10 * 60);

/// Tunnel manager.
pub struct TunnelManager<R: Runtime> {
    /// RX channel for receiving tunneling-related commands from other subsystems.
    command_rx: Receiver<TunnelManagerCommand, CommandRecycle>,

    /// Exploratory tunnel/hop selector.
    exploratory_selector: ExploratorySelector<R>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Routing table.
    subsystem_handle: SubsystemHandle,
}

impl<R: Runtime> TunnelManager<R> {
    /// Create new [`TunnelManager`].
    ///
    /// Returns a [`TunnelManager`] object, a [`TunnelManagerHandle`] which can be used to create
    /// new tunnel pools and a [`TunnelPoolHandle`] for the exploratory tunnel pool.
    pub fn new(
        router_ctx: RouterContext<R>,
        exploratory_config: TunnelPoolConfig,
        insecure_tunnels: bool,
        transit_config: Option<TransitConfig>,
        transit_shutdown_handle: ShutdownHandle,
        subsystem_handle: SubsystemHandle,
        subsys_transit_rx: Receiver<Vec<(RouterId, Message)>>,
    ) -> (Self, TunnelManagerHandle, TunnelPoolHandle) {
        tracing::info!(
            target: LOG_TARGET,
            ?insecure_tunnels,
            "starting tunnel manager",
        );

        // create `TransitTunnelManager` and run it in a separate task
        //
        // `TransitTunnelManager` communicates with the network via `SubsystemHandle`
        R::spawn(TransitTunnelManager::<R>::new(
            transit_config,
            router_ctx.clone(),
            subsystem_handle.clone(),
            subsys_transit_rx,
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
                subsystem_handle.clone(),
                router_ctx.clone(),
            );
            R::spawn(tunnel_pool);

            (tunnel_pool_handle, selector)
        };

        // create handle which other subsystems can use to create new tunnel pools
        let (manager_handle, command_rx) = TunnelManagerHandle::new();

        (
            Self {
                command_rx,
                exploratory_selector,
                router_ctx,
                subsystem_handle,
            },
            manager_handle,
            pool_handle,
        )
    }

    /// Collect tunnel-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
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
            self.subsystem_handle.clone(),
            self.router_ctx.clone(),
        );
        R::spawn(tunnel_pool);

        tunnel_pool_handle
    }
}

impl<R: Runtime> Future for TunnelManager<R> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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

        Poll::Pending
    }
}
