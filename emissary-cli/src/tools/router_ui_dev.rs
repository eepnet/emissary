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

#![cfg(any(feature = "native-ui", feature = "web-ui"))]

use crate::ui;

use emissary_core::{
    events::{EventHandle, EventManager, TransitTunnelStatus, TransportStatus, TunnelStatus},
    runtime::Runtime,
};
use emissary_util::runtime::tokio::Runtime as TokioRuntime;
use rand::Rng;

use std::time::Duration;

struct RouterState {
    transit: TransitTunnelStatus,
    transport: TransportStatus,
    tunnel: TunnelStatus,
    handle: EventHandle<TokioRuntime>,
}

impl RouterState {
    fn new(handle: EventHandle<TokioRuntime>) -> Self {
        Self {
            handle,
            transit: TransitTunnelStatus {
                num_tunnels: 50,
                inbound_bandwidth: 10_000,
                outbound_bandwidth: 8_000,
            },
            transport: TransportStatus {
                num_connected_routers: 100,
                inbound_bandwidth: 15_000,
                outbound_bandwidth: 12_000,
            },
            tunnel: TunnelStatus {
                num_tunnels_built: 200,
                num_tunnel_build_failures: 5,
            },
        }
    }

    async fn run(mut self) {
        loop {
            {
                let mut rng = rand::thread_rng();

                let mut delta = |value: usize, max_change: i32| -> usize {
                    let change: i32 = rng.gen_range(-max_change..=max_change);
                    let new = value as i32 + change;
                    new.max(0) as usize
                };

                // transit updates
                {
                    self.transit.num_tunnels = delta(self.transit.num_tunnels, 3);
                    self.handle.num_transit_tunnels(self.transit.num_tunnels);

                    self.transit.inbound_bandwidth = delta(self.transit.inbound_bandwidth, 500);
                    self.handle.transit_inbound_bandwidth(self.transit.inbound_bandwidth);

                    self.transit.outbound_bandwidth = delta(self.transit.outbound_bandwidth, 500);
                    self.handle.transit_outbound_bandwidth(self.transit.outbound_bandwidth);
                }

                // transport updates
                {
                    self.transport.num_connected_routers =
                        delta(self.transport.num_connected_routers, 5);
                    self.handle.num_connected_routers(self.transport.num_connected_routers);

                    self.transport.inbound_bandwidth =
                        delta(self.transport.inbound_bandwidth, 1000);
                    self.handle.transport_inbound_bandwidth(self.transport.inbound_bandwidth);

                    self.transport.outbound_bandwidth =
                        delta(self.transport.outbound_bandwidth, 1000);
                    self.handle.transport_outbound_bandwidth(self.transport.outbound_bandwidth);
                }

                // tunnel updates
                {
                    self.tunnel.num_tunnels_built = delta(self.tunnel.num_tunnels_built, 2);
                    self.tunnel.num_tunnel_build_failures =
                        delta(self.tunnel.num_tunnel_build_failures, 1);

                    self.handle.tunnel_status(
                        self.tunnel.num_tunnels_built,
                        self.tunnel.num_tunnel_build_failures,
                    );
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

/// Start the router UI (either native or web) in development mode.
///
/// The actual router is not started and the router UI is fed mock data.
pub async fn run() {
    let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
    let metrics_handle = TokioRuntime::register_metrics(vec![], None);
    let (manager, subscriber, handle) = EventManager::<TokioRuntime>::new(None, metrics_handle);

    tokio::spawn(manager);
    tokio::spawn(RouterState::new(handle).run());

    #[cfg(feature = "native-ui")]
    {
        use crate::{cli::Arguments, config::Config};
        use emissary_core::primitives::RouterId;
        use emissary_util::storage::Storage;
        use tempfile::tempdir;

        let dir = tempdir().expect("to succeed");
        let base_path = dir.path().to_owned();
        let storage = Storage::new(Some(base_path.clone())).await.unwrap();
        let mut config = Config::parse(&Arguments::default(), &storage).await.unwrap();

        println!("confguration path = {}", base_path.display());

        let _ = ui::native::RouterUi::start(
            subscriber,
            config.config.take().unwrap(),
            base_path,
            None,
            RouterId::from(rand::thread_rng().gen::<[u8; 32]>()),
            shutdown_tx,
        );
    }

    #[cfg(feature = "web-ui")]
    {
        ui::web::RouterUi::new(subscriber, None, 1, shutdown_tx).run().await;
    }
}
