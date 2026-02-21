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

use crate::runtime::Runtime;

#[cfg(feature = "events")]
use crate::runtime::{Counter, MetricType, MetricsHandle};

#[cfg(feature = "events")]
use futures::FutureExt;
#[cfg(feature = "events")]
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{string::String, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

#[cfg(feature = "events")]
use alloc::sync::Arc;
#[cfg(feature = "events")]
use core::{
    mem,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Default update interval.
#[cfg(feature = "events")]
const UPDATE_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(feature = "events")]
pub const TRANSIT_INBOUND_BANDWIDTH: &str = "transit_inbound_bandwidth_total";
#[cfg(feature = "events")]
pub const TRANSIT_OUTBOUND_BANDWIDTH: &str = "transit_outbound_bandwidth_total";
#[cfg(feature = "events")]
pub const TRANSPORT_INBOUND_BANDWIDTH: &str = "transport_inbound_bandwidth_total";
#[cfg(feature = "events")]
pub const TRANSPORT_OUTBOUND_BANDWIDTH: &str = "transport_outbound_bandwidth_total";

/// Events emitted by [`EventSubscriber`].
#[derive(Debug, Clone)]
#[cfg(feature = "events")]
enum SubsystemEvent {
    /// Client destination has been started.
    ClientDestinationStarted {
        /// Name of the destination.
        name: String,
    },

    /// Server destination has been started.
    ServerDestinationStarted {
        /// Name of the destination.
        name: String,

        /// Address of the destination.
        address: String,
    },
}

#[cfg(feature = "events")]
impl Default for SubsystemEvent {
    fn default() -> Self {
        Self::ClientDestinationStarted {
            name: String::new(),
        }
    }
}

/// Event handle.
#[cfg(feature = "events")]
pub struct EventHandle<R: Runtime> {
    /// TX channel for sending events to [`EventSubscriber`].
    event_tx: Sender<SubsystemEvent>,

    /// Cumulative inbound bandwidth used by all transports.
    inbound_bandwidth: Arc<AtomicUsize>,

    /// Cumulative outbound bandwidth used by all transports.
    outbound_bandwidth: Arc<AtomicUsize>,

    /// Number of connected routers.
    num_connected_routers: Arc<AtomicUsize>,

    /// Number of transit tunnels.
    num_transit_tunnels: Arc<AtomicUsize>,

    /// Number of tunnel build failures, either timeouts or rejections.
    num_tunnel_build_failures: Arc<AtomicUsize>,

    /// Number of successfully built tunnels.
    num_tunnels_built: Arc<AtomicUsize>,

    /// Cumulative inbound bandwidth used by all transit tunnels.
    transit_inbound_bandwidth: Arc<AtomicUsize>,

    /// Cumulative outbound bandwidth used by all transit tunnels.
    transit_outbound_bandwidth: Arc<AtomicUsize>,

    /// Update interval.
    update_interval: Duration,

    /// Event timer.
    timer: Option<R::Timer>,
}

#[cfg(feature = "events")]
impl<R: Runtime> Clone for EventHandle<R> {
    fn clone(&self) -> Self {
        EventHandle {
            event_tx: self.event_tx.clone(),
            inbound_bandwidth: Arc::clone(&self.inbound_bandwidth),
            outbound_bandwidth: Arc::clone(&self.outbound_bandwidth),
            num_connected_routers: Arc::clone(&self.num_connected_routers),
            num_transit_tunnels: Arc::clone(&self.num_transit_tunnels),
            num_tunnel_build_failures: Arc::clone(&self.num_tunnel_build_failures),
            num_tunnels_built: Arc::clone(&self.num_tunnels_built),
            transit_inbound_bandwidth: Arc::clone(&self.transit_inbound_bandwidth),
            transit_outbound_bandwidth: Arc::clone(&self.transit_outbound_bandwidth),
            update_interval: self.update_interval,
            timer: Some(R::timer(self.update_interval)),
        }
    }
}

/// Event handle.
#[cfg(not(feature = "events"))]
#[derive(Clone)]
pub(crate) struct EventHandle<R: Runtime> {
    /// Marker for `Runtime`.
    _marker: core::marker::PhantomData<R>,
}

impl<R: Runtime> EventHandle<R> {
    /// Update transit tunnel count.
    ///
    /// [`AtomicUsize::store()`] is used because the count is updated only by
    /// `TransitTunnelManager`.
    #[inline(always)]
    pub fn num_transit_tunnels(&self, _num_tunnels: usize) {
        #[cfg(feature = "events")]
        self.num_transit_tunnels.store(_num_tunnels, Ordering::Release);
    }

    /// Update inbound transit tunnel bandwidth.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each transit tunnel keeps track
    /// of its own bandwidth.
    pub fn transit_inbound_bandwidth(&self, _bandwidth: usize) {
        #[cfg(feature = "events")]
        self.transit_inbound_bandwidth.fetch_add(_bandwidth, Ordering::Release);
    }

    /// Update outbound transit tunnel bandwidth.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each transit tunnel keeps track
    /// of its own bandwidth.
    #[inline(always)]
    pub fn transit_outbound_bandwidth(&self, _bandwidth: usize) {
        #[cfg(feature = "events")]
        self.transit_outbound_bandwidth.fetch_add(_bandwidth, Ordering::Release);
    }

    /// Update inbound transport bandwidth.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each connection keeps track of its own
    /// bandwidth.
    #[inline(always)]
    pub fn transport_inbound_bandwidth(&self, _bandwidth: usize) {
        #[cfg(feature = "events")]
        self.inbound_bandwidth.fetch_add(_bandwidth, Ordering::Release);
    }

    /// Update outbound transport bandwidth.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each connection keeps track of its own
    /// bandwidth.
    #[inline(always)]
    pub fn transport_outbound_bandwidth(&self, _bandwidth: usize) {
        #[cfg(feature = "events")]
        self.outbound_bandwidth.fetch_add(_bandwidth, Ordering::Release);
    }

    /// Update connected router count.
    ///
    /// [`AtomicUsize::store()`] is used because the count is updated only by
    /// `TransportManager`.
    #[inline(always)]
    pub fn num_connected_routers(&self, _num_connected_routers: usize) {
        #[cfg(feature = "events")]
        self.num_connected_routers.store(_num_connected_routers, Ordering::Release);
    }

    /// Update tunnel build success/failure status.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each tunnel pool keeps track of its own
    /// tunnel build success/failure rate.
    #[inline(always)]
    pub fn tunnel_status(&self, _num_tunnels_built: usize, _num_tunnel_build_failures: usize) {
        #[cfg(feature = "events")]
        self.num_tunnels_built.fetch_add(_num_tunnels_built, Ordering::Release);
        #[cfg(feature = "events")]
        self.num_tunnel_build_failures
            .fetch_add(_num_tunnel_build_failures, Ordering::Release);
    }

    /// Notify the [`EventManager`] that a server destination was started.
    #[inline(always)]
    pub fn server_destination_started(&self, _name: String, _address: String) {
        #[cfg(feature = "events")]
        let _ = self.event_tx.try_send(SubsystemEvent::ServerDestinationStarted {
            name: _name,
            address: _address,
        });
    }

    /// Notify the [`EventManager`] that a client destination was started.
    #[inline(always)]
    pub fn client_destination_started(&self, _name: String) {
        #[cfg(feature = "events")]
        let _ = self.event_tx.try_send(SubsystemEvent::ClientDestinationStarted { name: _name });
    }

    /// Create new `EventHandle` for tests.
    #[cfg(test)]
    pub fn new_for_tests() -> Self {
        let (event_tx, _event_rx) = channel(16);

        Self {
            event_tx,
            inbound_bandwidth: Default::default(),
            outbound_bandwidth: Default::default(),
            num_connected_routers: Default::default(),
            num_transit_tunnels: Default::default(),
            num_tunnel_build_failures: Default::default(),
            num_tunnels_built: Default::default(),
            transit_inbound_bandwidth: Default::default(),
            transit_outbound_bandwidth: Default::default(),
            update_interval: UPDATE_INTERVAL,
            timer: None,
        }
    }
}

impl<R: Runtime> Future for EventHandle<R> {
    type Output = ();

    #[cfg(feature = "events")]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.timer {
            None => Poll::Pending,
            Some(timer) => {
                futures::ready!(timer.poll_unpin(cx));

                // create new timer and register it into the executor
                let mut timer = R::timer(self.update_interval);
                let _ = timer.poll_unpin(cx);
                self.timer = Some(timer);

                Poll::Ready(())
            }
        }
    }

    #[cfg(not(feature = "events"))]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

/// Client destination has been started.
#[derive(Debug, Clone, Default)]
pub struct ClientDestinationStarted {
    /// Name of the destination.
    pub name: String,
}

/// Server destination has been started.
#[derive(Debug, Clone, Default)]
pub struct ServerDestinationStarted {
    /// Name of the destination.
    pub name: String,

    /// Address of the destination.
    pub address: String,
}

/// Transit tunnel status.
#[derive(Debug, Clone, Default)]
pub struct TransitTunnelStatus {
    /// Number of transit tunnels.
    pub num_tunnels: usize,

    /// Cumulative inbound bandwith used by all transit tunnels.
    pub inbound_bandwidth: usize,

    /// Cumulative outbound bandwith used by all transit tunnels.
    pub outbound_bandwidth: usize,
}

/// Transport status.
#[derive(Debug, Clone, Default)]
pub struct TransportStatus {
    /// Number of connected routers.
    pub num_connected_routers: usize,

    /// Cumulative inbound bandwidth consumed by all transports.
    pub inbound_bandwidth: usize,

    /// Cumulative outbound bandwidth consumed by all transports.
    pub outbound_bandwidth: usize,
}

/// Tunnel status.
#[derive(Debug, Clone, Default)]
pub struct TunnelStatus {
    /// Number of tunnels built.
    pub num_tunnels_built: usize,

    /// Number of tunnel build failures.
    pub num_tunnel_build_failures: usize,
}

/// Events emitted by [`EventManager`].
#[derive(Debug, Clone, Default)]
pub enum Event {
    RouterStatus {
        /// Client destination status updates.
        client_destinations: Vec<String>,

        /// Server destination status updates.
        server_destinations: Vec<(String, String)>,

        /// Transit tunnel subsystem status.
        transit: TransitTunnelStatus,

        /// Transport subsystem status.
        transport: TransportStatus,

        /// Tunnel subsystem status.
        tunnel: TunnelStatus,
    },

    /// Router is shutting down.
    ShuttingDown,

    /// Router has shut down.
    #[default]
    ShutDown,
}

/// [`EventManager`] state.
#[cfg(feature = "events")]
enum State {
    /// [`EventManager`] and the router is active.
    Active,

    /// [`EventManager`] and the router is shutting down.
    ShuttingDown,

    /// [`EventManager`]  and the routerhas shut down.
    ShutDown,
}

/// Event manager.
#[cfg(feature = "events")]
pub struct EventManager<R: Runtime> {
    /// RX channel for receiving events from other subsystems.
    event_rx: Receiver<SubsystemEvent>,

    /// Event handle.
    handle: EventHandle<R>,

    /// Metrics handle
    metrics_handle: R::MetricsHandle,

    /// Pending client destinatin updates.
    pending_client_updates: Vec<String>,

    /// Pending server destination updates.
    pending_server_updates: Vec<(String, String)>,

    /// Event manager and router state.
    state: State,

    /// TX channel for sending router status updates to [`EventSubscriber`].
    status_tx: Sender<Event>,

    /// Update timer.
    timer: R::Timer,

    /// Inbound transit bandwdith.
    transit_inbound: usize,

    /// Outbound transit bandwdith.
    transit_outbound: usize,

    /// Inbound transport bandwdith.
    transport_inbound: usize,

    /// Outbound transport bandwdith.
    transport_outbound: usize,
}

/// Event manager.
#[cfg(not(feature = "events"))]
pub(crate) struct EventManager<R: Runtime> {
    _marker: core::marker::PhantomData<R>,
}

impl<R: Runtime> EventManager<R> {
    /// Create new [`EventManager`].
    #[cfg(feature = "events")]
    pub fn new(
        update_interval: Option<Duration>,
        metrics_handle: R::MetricsHandle,
    ) -> (Self, EventSubscriber, EventHandle<R>) {
        let (event_tx, event_rx) = channel(64);
        let (status_tx, status_rx) = channel(64);
        let update_interval = update_interval.unwrap_or(UPDATE_INTERVAL);
        let handle = EventHandle {
            event_tx,
            inbound_bandwidth: Default::default(),
            outbound_bandwidth: Default::default(),
            num_connected_routers: Default::default(),
            num_transit_tunnels: Default::default(),
            num_tunnel_build_failures: Default::default(),
            num_tunnels_built: Default::default(),
            transit_inbound_bandwidth: Default::default(),
            transit_outbound_bandwidth: Default::default(),
            update_interval,
            timer: None,
        };

        (
            Self {
                event_rx,
                state: State::Active,
                handle: EventHandle {
                    event_tx: handle.event_tx.clone(),
                    inbound_bandwidth: Arc::clone(&handle.inbound_bandwidth),
                    outbound_bandwidth: Arc::clone(&handle.outbound_bandwidth),
                    num_connected_routers: Arc::clone(&handle.num_connected_routers),
                    num_transit_tunnels: Arc::clone(&handle.num_transit_tunnels),
                    num_tunnel_build_failures: Arc::clone(&handle.num_tunnel_build_failures),
                    num_tunnels_built: Arc::clone(&handle.num_tunnels_built),
                    transit_inbound_bandwidth: Arc::clone(&handle.transit_inbound_bandwidth),
                    transit_outbound_bandwidth: Arc::clone(&handle.transit_outbound_bandwidth),
                    update_interval,
                    timer: None,
                },
                metrics_handle,
                pending_client_updates: Vec::new(),
                pending_server_updates: Vec::new(),
                status_tx,
                timer: R::timer(update_interval),
                transit_inbound: 0usize,
                transit_outbound: 0usize,
                transport_inbound: 0usize,
                transport_outbound: 0usize,
            },
            EventSubscriber { status_rx },
            handle,
        )
    }

    /// Collect `EventManager`-related metric counters, gauges and histograms.
    #[cfg(feature = "events")]
    pub fn metrics(mut metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics.push(MetricType::Counter {
            name: TRANSIT_INBOUND_BANDWIDTH,
            description: "how many bytes have transit tunnels received",
        });
        metrics.push(MetricType::Counter {
            name: TRANSIT_OUTBOUND_BANDWIDTH,
            description: "how many bytes have transit tunnels sent",
        });
        metrics.push(MetricType::Counter {
            name: TRANSPORT_INBOUND_BANDWIDTH,
            description: "how many bytes have transports received",
        });
        metrics.push(MetricType::Counter {
            name: TRANSPORT_OUTBOUND_BANDWIDTH,
            description: "how many bytes have transports sent",
        });

        metrics
    }

    /// Create new [`EventManager`].
    #[cfg(not(feature = "events"))]
    pub(crate) fn new(
        _update_interval: Option<Duration>,
    ) -> (Self, EventSubscriber, EventHandle<R>) {
        (
            Self {
                _marker: Default::default(),
            },
            EventSubscriber {},
            EventHandle {
                _marker: Default::default(),
            },
        )
    }

    /// Send shutdown signal to [`EventSubscriber`].
    pub(crate) fn shutdown(&mut self) {
        #[cfg(feature = "events")]
        match self.state {
            State::Active => {
                let _ = self.status_tx.try_send(Event::ShuttingDown);

                self.state = State::ShuttingDown;
            }
            State::ShuttingDown => {
                let _ = self.status_tx.try_send(Event::ShutDown);

                self.state = State::ShutDown;
            }
            State::ShutDown => {}
        }
    }
}

impl<R: Runtime> Future for EventManager<R> {
    type Output = ();

    #[cfg(feature = "events")]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.event_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(SubsystemEvent::ClientDestinationStarted { name })) => {
                    self.pending_client_updates.push(name);
                }
                Poll::Ready(Some(SubsystemEvent::ServerDestinationStarted { name, address })) => {
                    self.pending_server_updates.push((name, address));
                }
            }
        }

        if self.timer.poll_unpin(cx).is_ready() {
            let server_destinations = mem::take(&mut self.pending_server_updates);
            let client_destinations = mem::take(&mut self.pending_client_updates);

            let transit_outbound = self.handle.transit_outbound_bandwidth.load(Ordering::Acquire);
            let transit_inbound = self.handle.transit_inbound_bandwidth.load(Ordering::Acquire);
            let transport_outbound = self.handle.outbound_bandwidth.load(Ordering::Acquire);
            let transport_inbound = self.handle.inbound_bandwidth.load(Ordering::Acquire);

            {
                self.metrics_handle
                    .counter(TRANSIT_INBOUND_BANDWIDTH)
                    .increment(transit_inbound.saturating_sub(self.transit_inbound));
                self.transit_inbound = transit_inbound;
            }
            {
                self.metrics_handle
                    .counter(TRANSIT_OUTBOUND_BANDWIDTH)
                    .increment(transit_outbound.saturating_sub(self.transit_outbound));
                self.transit_outbound = transit_outbound;
            }
            {
                self.metrics_handle
                    .counter(TRANSPORT_INBOUND_BANDWIDTH)
                    .increment(transport_inbound.saturating_sub(self.transport_inbound));
                self.transport_inbound = transport_inbound;
            }
            {
                self.metrics_handle
                    .counter(TRANSPORT_OUTBOUND_BANDWIDTH)
                    .increment(transport_outbound.saturating_sub(self.transport_outbound));
                self.transport_outbound = transport_outbound;
            }

            let _ = self.status_tx.try_send(Event::RouterStatus {
                transit: TransitTunnelStatus {
                    num_tunnels: self.handle.num_transit_tunnels.load(Ordering::Acquire),
                    inbound_bandwidth: transit_inbound,
                    outbound_bandwidth: transit_outbound,
                },
                transport: TransportStatus {
                    num_connected_routers: self
                        .handle
                        .num_connected_routers
                        .load(Ordering::Acquire),
                    outbound_bandwidth: transport_outbound,
                    inbound_bandwidth: transport_inbound,
                },
                tunnel: TunnelStatus {
                    num_tunnels_built: self.handle.num_tunnels_built.load(Ordering::Acquire),
                    num_tunnel_build_failures: self
                        .handle
                        .num_tunnel_build_failures
                        .load(Ordering::Acquire),
                },
                server_destinations,
                client_destinations,
            });

            self.timer = R::timer(self.handle.update_interval);
            let _ = self.timer.poll_unpin(cx);
        }

        Poll::Pending
    }

    #[cfg(not(feature = "events"))]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

/// Event subscriber.
pub struct EventSubscriber {
    /// RX channel for receiving events.
    #[cfg(feature = "events")]
    status_rx: Receiver<Event>,
}

impl EventSubscriber {
    /// Attempt to get next [`Event`].
    #[cfg(feature = "events")]
    pub fn router_status(&mut self) -> Option<Event> {
        self.status_rx.try_recv().ok()
    }

    /// Attempt to get next [`Event`].
    #[cfg(not(feature = "events"))]
    pub fn router_status(&mut self) -> Option<Event> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test(start_paused = true)]
    async fn event_handle_timer_works() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_manager, _subscriber, handle) =
            EventManager::<MockRuntime>::new(Some(Duration::from_secs(1)), handle);

        // make a clone of the handle which initializes the event timer
        let mut new_handle = handle.clone();

        // ensure that the timer keeps firing
        for _ in 0..3 {
            assert!(tokio::time::timeout(Duration::from_secs(5), &mut new_handle).await.is_ok());
        }
    }
}
