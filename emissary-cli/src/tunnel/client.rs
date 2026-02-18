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

use crate::config::ClientTunnelConfig;

use tokio::{net::TcpListener, task::JoinSet};
use yosemite::{style, Session, SessionOptions, StreamOptions};

use std::{future::Future, sync::Arc, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::client-tunnel";

/// Retry timeout.
const RETRY_TIMEOUT: Duration = Duration::from_secs(15);

/// Client tunnel manager.
pub struct ClientTunnelManager {
    /// Tunnel futures.
    futures: JoinSet<Arc<ClientTunnelConfig>>,

    /// SAMv3 server port of the router.
    sam_tcp_port: u16,

    /// Client tunnel configurations.
    tunnels: Vec<Arc<ClientTunnelConfig>>,
}

impl ClientTunnelManager {
    /// Create new [`ClientTunnelManager`].
    pub fn new(tunnels: Vec<ClientTunnelConfig>, sam_tcp_port: u16) -> Self {
        Self {
            futures: JoinSet::new(),
            sam_tcp_port,
            tunnels: tunnels.into_iter().map(Arc::from).collect(),
        }
    }

    /// Run the event loop of a client tunnel.
    async fn tunnel_event_loop(
        future: impl Future<Output = yosemite::Result<yosemite::Stream>>,
        tunnel: &Arc<ClientTunnelConfig>,
    ) -> crate::Result<()> {
        let listener = TcpListener::bind(format!(
            "{}:{}",
            tunnel.address.clone().unwrap_or(String::from("127.0.0.1")),
            tunnel.port
        ))
        .await?;

        let (mut tcp_stream, _) = listener.accept().await?;
        let mut i2p_stream = future.await?;

        tokio::io::copy_bidirectional(&mut i2p_stream, &mut tcp_stream).await?;

        Ok(())
    }

    /// Run the event loop of [`ClientTunnelManger`].
    ///
    /// If there are no client tunnels congigured, [`ClientTunnelManager`] exits immediately.
    pub async fn run(mut self) {
        if self.tunnels.is_empty() {
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            num_tunnels = ?self.tunnels.len(),
            "starting client tunnel manager",
        );

        let mut session = match Session::<style::Stream>::new(SessionOptions {
            publish: false,
            samv3_tcp_port: self.sam_tcp_port,
            nickname: "i2p-tunnel".to_string(),
            inbound_quantity: 4,
            outbound_quantity: 4,
            ..Default::default()
        })
        .await
        {
            Ok(session) => session,
            Err(error) => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to start client tunnel manager",
                );
                return;
            }
        };

        for tunnel in self.tunnels.iter().cloned() {
            let future = session.connect_detached_with_options(
                &tunnel.destination,
                StreamOptions {
                    dst_port: tunnel.destination_port.unwrap_or(0),
                    ..Default::default()
                },
            );

            self.futures.spawn(async move {
                match Self::tunnel_event_loop(future, &tunnel).await {
                    Ok(()) => tunnel,
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            name = %tunnel.name,
                            ?error,
                            "client tunnel exited with error",
                        );

                        tokio::time::sleep(RETRY_TIMEOUT).await;
                        tunnel
                    }
                }
            });
        }

        while let Some(result) = self.futures.join_next().await {
            match result {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "client tunnel panicked, unable to restart",
                    );
                    debug_assert!(false);
                }
                Ok(tunnel) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        name = %tunnel.name,
                        "tunnel returned, restart event loop"
                    );

                    let future = session.connect_detached_with_options(
                        &tunnel.destination,
                        StreamOptions {
                            dst_port: tunnel.destination_port.unwrap_or(0),
                            ..Default::default()
                        },
                    );

                    self.futures.spawn(async move {
                        match Self::tunnel_event_loop(future, &tunnel).await {
                            Ok(()) => tunnel,
                            Err(error) => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    name = %tunnel.name,
                                    ?error,
                                    "client tunnel exited with error",
                                );

                                tokio::time::sleep(RETRY_TIMEOUT).await;
                                tunnel
                            }
                        }
                    });
                }
            }
        }
    }
}
