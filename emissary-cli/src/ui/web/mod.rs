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
    ui::{calculate_bandwidth, Status},
    LOG_TARGET,
};

use axum::{
    extract::{
        ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use emissary_core::events::{Event, EventSubscriber};
use futures::StreamExt;
use tokio::{
    net::TcpListener,
    sync::mpsc::Sender,
    time::{interval, Interval},
};

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Router console.
const ROUTER_CONSOLE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html"));

/// Default listening port for web UI.
const LISTEN_PORT: u16 = 7657;

/// Router state.
struct InnerRouterState {
    /// Cumulative bandwidth of all transports.
    bandwidth: usize,

    /// Active client destinations.
    client_destinations: Vec<String>,

    /// Total number of routers.
    num_routers: usize,

    /// Total number of transit tunnels.
    num_transit_tunnels: usize,

    /// How many tunnel builds have failed.
    num_tunnel_build_failures: usize,

    /// How many tunnels have been built.
    num_tunnels_built: usize,

    /// Active server destinations.
    server_destinations: Vec<(String, String)>,

    /// TX channel for sending a graceful shutdown signal to router.
    shutdown_tx: Sender<()>,

    /// Router status.
    status: Status,

    /// Cumulative bandwidth of all transit tunnels.
    transit_bandwidth: usize,

    /// Web UI update interval.
    update_interval: Duration,

    /// Uptime.
    uptime: Instant,
}

/// Router state.
#[derive(Clone)]
struct RouterState {
    /// Router state.
    state: Arc<Mutex<InnerRouterState>>,
}

/// Router UI.
pub struct RouterUi {
    /// Subscriber to events emitted by `emissary-core`.
    events: EventSubscriber,

    /// Listen port for the web UI.
    port: u16,

    /// TX channel for sending a graceful shutdown signal to router.
    _shutdown_tx: Sender<()>,

    /// Router state.
    state: RouterState,

    /// Interval for updating web UI.
    update_interval: Interval,
}

impl RouterUi {
    /// Create new [`RouterUi`].
    pub fn new(
        events: EventSubscriber,
        port: Option<u16>,
        refresh_interval: usize,
        shutdown_tx: Sender<()>,
    ) -> Self {
        let update_interval = if refresh_interval == 0 {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(refresh_interval as u64)
        };

        RouterUi {
            events,
            port: port.unwrap_or(LISTEN_PORT),
            _shutdown_tx: shutdown_tx.clone(),
            state: RouterState {
                state: Arc::new(Mutex::new(InnerRouterState {
                    bandwidth: 0usize,
                    client_destinations: Vec::new(),
                    num_routers: 0usize,
                    num_transit_tunnels: 0usize,
                    num_tunnel_build_failures: 0usize,
                    num_tunnels_built: 0usize,
                    server_destinations: Vec::new(),
                    shutdown_tx,
                    status: Status::Active,
                    transit_bandwidth: 0usize,
                    update_interval,
                    uptime: Instant::now(),
                })),
            },
            update_interval: interval(update_interval),
        }
    }

    /// Run the event loop of [`RouterUi`].
    pub async fn run(mut self) {
        let listener = match TcpListener::bind(format!("127.0.0.1:{}", self.port)).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    port = ?self.port,
                    ?error,
                    "failed to bind to router ui port",
                );
                return;
            }
        };

        let app = Router::new()
            .route("/", get(index))
            .route("/ws", get(ws_handler))
            .with_state(self.state.clone());

        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to serve web ui",
                );
            }
        });

        loop {
            tokio::select! {
                _ = self.update_interval.tick() => {
                    while let Some(event) = self.events.router_status() {
                        let Ok(mut inner) = self.state.state.lock() else {
                            return;
                        };

                        match event {
                            Event::RouterStatus {
                                client_destinations,
                                server_destinations,
                                transit,
                                transport,
                                tunnel,
                            } => {
                                inner.transit_bandwidth = transit.inbound_bandwidth + transit.outbound_bandwidth;
                                inner.num_transit_tunnels = transit.num_tunnels;
                                inner.bandwidth = transport.inbound_bandwidth + transport.outbound_bandwidth;
                                inner.num_routers = transport.num_connected_routers;
                                inner.server_destinations.extend(server_destinations);
                                inner.client_destinations.extend(client_destinations);
                                inner.num_tunnels_built = tunnel.num_tunnels_built;
                                inner.num_tunnel_build_failures = tunnel.num_tunnel_build_failures;
                            }
                            Event::ShuttingDown => match inner.status {
                                Status::Active => {
                                    inner.status = Status::ShuttingDown(Instant::now());
                                }
                                _ => {}
                            },
                            Event::ShutDown => {}
                        }
                    }
                }
            }
        }
    }
}

async fn index() -> impl IntoResponse {
    axum::response::Html(ROUTER_CONSOLE)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RouterState>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: RouterState) {
    let mut interval = {
        match state.state.lock() {
            Ok(inner) => interval(inner.update_interval),
            Err(_) => return,
        }
    };

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let update = {
                    let Ok(inner) = state.state.lock() else {
                        return;
                    };

                    let mut uptime = inner.uptime.elapsed().as_secs();
                    if uptime == 0 {
                        uptime = 1;
                    }

                    let status_text = format!("Status: {}", inner.status);
                    let uptime_text = format!(
                        "Uptime: {} h {} min {} s",
                        uptime / 60 / 60,
                        (uptime / 60) % 60,
                        uptime % 60,
                    );
                    let total_bandwidth_text = {
                        let (total, total_unit) = calculate_bandwidth(inner.bandwidth as f64);
                        let (per_second, per_second_unit) =
                            calculate_bandwidth(inner.bandwidth as f64 / uptime as f64);

                        format!(
                            "Total bandwidth: {:.2} {} ({:.2} {}/s)",
                            total, total_unit, per_second, per_second_unit,
                        )
                    };
                    let num_connected_text = format!("Number of connected routers: {}", inner.num_routers);
                    let tunnel_build_success_rate_text = {
                        if inner.num_tunnels_built == 0 && inner.num_tunnel_build_failures == 0 {
                            format!("Tunnel build success rate: 0%")
                        } else {
                            format!(
                                "Tunnel build success rate: {}%",
                                ((inner.num_tunnels_built as f64
                                    / ((inner.num_tunnels_built + inner.num_tunnel_build_failures) as f64))
                                    * 100f64) as usize
                            )
                        }
                    };
                    let num_transit_tunnels_text =
                        format!("Transit tunnels: {}", inner.num_transit_tunnels);
                    let transit_bandwidth_text = {
                        let (total, total_unit) = calculate_bandwidth(inner.transit_bandwidth as f64);
                        let (per_second, per_second_unit) =
                            calculate_bandwidth(inner.transit_bandwidth as f64 / uptime as f64);

                        format!(
                            "Transit bandwidth: {:.2} {} ({:.2} {}/s)",
                            total, total_unit, per_second, per_second_unit,
                        )
                    };

                    serde_json::json!({
                        "bandwidth": total_bandwidth_text,
                        "client_destinations": inner.client_destinations.clone(),
                        "num_routers": num_connected_text,
                        "num_transit_tunnels": num_transit_tunnels_text,
                        "tunnel_build_ratio": tunnel_build_success_rate_text,
                        "server_destinations": inner.server_destinations.clone(),
                        "status": status_text,
                        "transit_bandwidth": transit_bandwidth_text,
                        "uptime": uptime_text,
                    })
                };

                if socket.send(Message::Text(Utf8Bytes::from(update.to_string()))).await.is_err() {
                    return;
                }
            },
            message = socket.next() => match message {
                None => return,
                Some(message) => {
                    let Ok(message) = message else {
                        continue;
                    };
                    let Ok(text) = message.into_text() else {
                        continue;
                    };

                    if let Ok(json_msg) = serde_json::from_str::<serde_json::Value>(&text) {
                        if json_msg["type"] == "command" {
                            match json_msg["action"].as_str() {
                                Some("graceful_shutdown") => {
                                    if let Ok(inner) = state.state.lock() {
                                        let _ = inner.shutdown_tx.try_send(());
                                    };
                                }
                                Some("forceful_shutdown") => std::process::exit(0),
                                command => tracing::warn!(
                                    target: LOG_TARGET,
                                    ?command,
                                    "uknown command"
                                ),
                            }
                        }
                    }
                }
            }
        }
    }
}
