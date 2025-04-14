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

use futures::FutureExt;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    mem,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
    time::Duration,
};

/// Default update interval.
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// Events emitted by [`EventSubscriber`].
#[derive(Debug, Clone)]
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

impl Default for SubsystemEvent {
    fn default() -> Self {
        Self::ClientDestinationStarted {
            name: String::new(),
        }
    }
}

/// Event handle.
pub(crate) struct EventHandle<R: Runtime> {
    /// TX channel for sending events to [`EventSubscriber`].
    event_tx: Sender<SubsystemEvent>,

    /// Cumulative bandwidth used by all transports.
    bandwidth: Arc<AtomicUsize>,

    /// Number of connected routers.
    num_connected_routers: Arc<AtomicUsize>,

    /// Number of transit tunnels.
    num_transit_tunnels: Arc<AtomicUsize>,

    /// Number of tunnel build failures, either timeouts or rejections.
    num_tunnel_build_failures: Arc<AtomicUsize>,

    /// Number of successfully built tunnels.
    num_tunnels_built: Arc<AtomicUsize>,

    /// Cumulative bandwidth used by all transit tunnels.
    transit_bandwidth: Arc<AtomicUsize>,

    /// Update interval.
    update_interval: Duration,

    /// Event timer.
    timer: Option<R::Delay>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Clone for EventHandle<R> {
    fn clone(&self) -> Self {
        EventHandle {
            event_tx: self.event_tx.clone(),
            bandwidth: Arc::clone(&self.bandwidth),
            num_connected_routers: Arc::clone(&self.num_connected_routers),
            num_transit_tunnels: Arc::clone(&self.num_transit_tunnels),
            num_tunnel_build_failures: Arc::clone(&self.num_tunnel_build_failures),
            num_tunnels_built: Arc::clone(&self.num_tunnels_built),
            transit_bandwidth: Arc::clone(&self.transit_bandwidth),
            update_interval: self.update_interval,
            timer: Some(R::delay(self.update_interval)),
            _runtime: Default::default(),
        }
    }
}

impl<R: Runtime> EventHandle<R> {
    /// Update transit tunnel count.
    ///
    /// [`AtomicUsize::store()`] is used because the count is updated only by
    /// `TransitTunnelManager`.
    pub(crate) fn num_transit_tunnels(&self, num_tunnels: usize) {
        self.num_transit_tunnels.store(num_tunnels, Ordering::Release);
    }

    /// Update transit tunnel bandwidth.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each transit tunnel keeps track
    /// of its own bandwidth.
    pub(crate) fn transit_tunnel_bandwidth(&self, bandwidth: usize) {
        self.transit_bandwidth.fetch_add(bandwidth, Ordering::Release);
    }

    /// Update transport bandwidth.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each connection keeps track of its own
    /// bandwidth.
    pub(crate) fn transport_bandwidth(&self, bandwidth: usize) {
        self.bandwidth.fetch_add(bandwidth, Ordering::Release);
    }

    /// Update connected router count.
    ///
    /// [`AtomicUsize::store()`] is used because the count is updated only by
    /// `TransportManager`.
    pub(crate) fn num_connected_routers(&self, num_connected_routers: usize) {
        self.num_connected_routers.store(num_connected_routers, Ordering::Release);
    }

    /// Update tunnel build success/failure status.
    ///
    /// [`AtomicUsize::fetch_add()`] is used because each tunnel pool keeps track of its own
    /// tunnel build success/failure rate.
    pub(crate) fn tunnel_status(&self, num_tunnels_built: usize, num_tunnel_build_failures: usize) {
        self.num_tunnels_built.fetch_add(num_tunnels_built, Ordering::Release);
        self.num_tunnel_build_failures
            .fetch_add(num_tunnel_build_failures, Ordering::Release);
    }

    // TODO:
    pub(crate) fn server_destination_started(&self, name: String, address: String) {
        let _ = self
            .event_tx
            .try_send(SubsystemEvent::ServerDestinationStarted { name, address });
    }

    // TODO:
    pub(crate) fn client_destination_started(&self, name: String) {
        let _ = self.event_tx.try_send(SubsystemEvent::ClientDestinationStarted { name });
    }
}

impl<R: Runtime> Future for EventHandle<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.timer {
            None => Poll::Pending,
            Some(timer) => {
                futures::ready!(timer.poll_unpin(cx));

                // create new timer and register it into the executor
                let mut timer = R::delay(self.update_interval);
                let _ = timer.poll_unpin(cx);
                self.timer = Some(timer);

                Poll::Ready(())
            }
        }
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

    /// Cumulative bandwith used by all transit tunnels.
    pub bandwidth: usize,
}

/// Transport status.
#[derive(Debug, Clone, Default)]
pub struct TransportStatus {
    /// Number of connected routers.
    pub num_connected_routers: usize,

    /// Cumulative bandwith consumed by all transports.
    pub bandwidth: usize,
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
enum State {
    /// [`EventManager`] and the router is active.
    Active,

    /// [`EventManager`] and the router is shutting down.
    ShuttingDown,

    /// [`EventManager`]  and the routerhas shut down.
    ShutDown,
}

/// Event manager.
pub(crate) struct EventManager<R: Runtime> {
    /// RX channel for receiving events from other subsystems.
    event_rx: Receiver<SubsystemEvent>,

    /// Event handle.
    handle: EventHandle<R>,

    /// Pending client destinatin updates.
    pending_client_updates: Vec<String>,

    /// Pending server destination updates.
    pending_server_updates: Vec<(String, String)>,

    /// Event manager and router state.
    state: State,

    /// TX channel for sending router status updates to [`EventSubscriber`].
    status_tx: Sender<Event>,

    /// Update timer.
    timer: R::Delay,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> EventManager<R> {
    /// Create new [`EventManager`].
    pub(crate) fn new(
        update_interval: Option<Duration>,
    ) -> (Self, EventSubscriber, EventHandle<R>) {
        let (event_tx, event_rx) = channel(64);
        let (status_tx, status_rx) = channel(64);
        let update_interval = update_interval.unwrap_or(UPDATE_INTERVAL);
        let handle = EventHandle {
            event_tx,
            bandwidth: Default::default(),
            num_connected_routers: Default::default(),
            num_transit_tunnels: Default::default(),
            num_tunnel_build_failures: Default::default(),
            num_tunnels_built: Default::default(),
            transit_bandwidth: Default::default(),
            update_interval,
            timer: None,
            _runtime: Default::default(),
        };

        (
            Self {
                event_rx,
                state: State::Active,
                handle: EventHandle {
                    event_tx: handle.event_tx.clone(),
                    bandwidth: Arc::clone(&handle.bandwidth),
                    num_connected_routers: Arc::clone(&handle.num_connected_routers),
                    num_transit_tunnels: Arc::clone(&handle.num_transit_tunnels),
                    num_tunnel_build_failures: Arc::clone(&handle.num_tunnel_build_failures),
                    num_tunnels_built: Arc::clone(&handle.num_tunnels_built),
                    transit_bandwidth: Arc::clone(&handle.transit_bandwidth),
                    update_interval,
                    timer: None,
                    _runtime: Default::default(),
                },
                pending_client_updates: Vec::new(),
                pending_server_updates: Vec::new(),
                status_tx,
                timer: R::delay(update_interval),
                _runtime: Default::default(),
            },
            EventSubscriber { status_rx },
            handle,
        )
    }

    /// Send shutdown signal to [`EventSubscriber`].
    pub(crate) fn shutdown(&mut self) {
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

            let _ = self.status_tx.try_send(Event::RouterStatus {
                transit: TransitTunnelStatus {
                    num_tunnels: self.handle.num_transit_tunnels.load(Ordering::Acquire),
                    bandwidth: self.handle.transit_bandwidth.load(Ordering::Acquire),
                },
                transport: TransportStatus {
                    num_connected_routers: self
                        .handle
                        .num_connected_routers
                        .load(Ordering::Acquire),
                    bandwidth: self.handle.bandwidth.load(Ordering::Acquire),
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

            self.timer = R::delay(self.handle.update_interval);
            let _ = self.timer.poll_unpin(cx);
        }

        Poll::Pending
    }
}

/// Event subscriber.
pub struct EventSubscriber {
    /// RX channel for receiving events.
    status_rx: Receiver<Event>,
}

impl EventSubscriber {
    /// Attempt to get next [`Event`].
    pub fn router_status(&mut self) -> Option<Event> {
        self.status_rx.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn event_handle_timer_works() {
        let (_manager, _subscriber, handle) =
            EventManager::<MockRuntime>::new(Some(Duration::from_secs(1)));

        // make a clone of the handle which initializes the event timer
        let mut new_handle = handle.clone();

        // ensure that the timer keeps firing
        for _ in 0..3 {
            assert!(tokio::time::timeout(Duration::from_secs(5), &mut new_handle).await.is_ok());
        }
    }
}
