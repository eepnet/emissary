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

use crate::port_mapper::{upnp, PortMapperConfig};

use futures::FutureExt;
use natpmp::{new_tokio_natpmp, NatpmpAsync, Protocol, Response};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

use std::net::Ipv4Addr;
use std::time::Duration;

/// Logging target for the file
const LOG_TARGET: &str = "emissary-util::port-mapper::nat-pmp";

/// Timeout for responses.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times the operations are retried before bailing out.
const NUM_RETRIES: usize = 3usize;

/// Port mapping lifetime in seconds.
///
/// How long is the lifetime of an NTCP2/SSU2 port mapping.
const PORT_MAPPING_LIFETIME: u32 = 60 * 60;

/// Address refresh timer.
///
/// How often is the check for an external address change done.
const ADDRESS_REFRESH_TIMER: Duration = Duration::from_secs(5 * 60);

/// NAT-PMP port mapper.
///
/// NAT-PMP is the default port forwarding protocol used by `emissary-cli`
/// and if it's not supported, UPnP is used as a fallback.
pub struct PortMapper {
    /// TX channel for sending external address discoveries.
    address_tx: mpsc::Sender<Ipv4Addr>,

    /// Port forwarding config.
    config: PortMapperConfig,

    /// NTCP2 port, if the transport was enabled.
    ntcp2_port: Option<u16>,

    /// RX channel for receiving a shutdown signal.
    shutdown_rx: oneshot::Receiver<oneshot::Sender<()>>,

    /// SSU2 port, if the transport was enabled.
    ssu2_port: Option<u16>,
}

impl PortMapper {
    /// Create new NAT-PMP [`PortMapper`].
    pub fn new(
        config: PortMapperConfig,
        ntcp2_port: Option<u16>,
        ssu2_port: Option<u16>,
        address_tx: mpsc::Sender<Ipv4Addr>,
        shutdown_rx: oneshot::Receiver<oneshot::Sender<()>>,
    ) -> Self {
        Self {
            address_tx,
            config,
            ntcp2_port,
            shutdown_rx,
            ssu2_port,
        }
    }

    /// If NAT-PMP initialization failed, attempt to use UPnP as a backup if it was enabled.
    ///
    /// If UPnP was not enabled, [`PortMapper`] will shutdown and no port forwarding/external
    /// address discovery is possible using either of these protocols.
    fn try_switch_to_upnp(self) {
        if !self.config.upnp {
            tracing::warn!(
                target: LOG_TARGET,
                "nat-pmp failed and upnp not enabled, shutting down port mapper",
            );
            return;
        }

        tracing::warn!(
            target: LOG_TARGET,
            "nat-pmp failed, switching to upnp",
        );

        tokio::spawn(
            upnp::PortMapper::new(
                self.config,
                self.ntcp2_port,
                self.ssu2_port,
                self.address_tx,
                self.shutdown_rx,
            )
            .run(),
        );
    }

    /// Attempt to map NTCP2 port with retries.
    async fn try_map_ntcp2(client: &NatpmpAsync<UdpSocket>, port: u16) -> Result<Response, ()> {
        for _ in 0..NUM_RETRIES {
            let result = tokio::time::timeout(RESPONSE_TIMEOUT, async {
                client
                    .send_port_mapping_request(Protocol::TCP, port, port, PORT_MAPPING_LIFETIME)
                    .await?;
                client.read_response_or_retry().await
            })
            .await;

            match result {
                Err(_) => tracing::debug!(target: LOG_TARGET, "map ntcp2 timeout"),
                Ok(Err(e)) => tracing::debug!(target: LOG_TARGET, ?e, "map ntcp2 failed"),
                Ok(Ok(resp)) => return Ok(resp),
            }
        }
        Err(())
    }

    /// Attempt to map SSU2 port with retries.
    async fn try_map_ssu2(client: &NatpmpAsync<UdpSocket>, port: u16) -> Result<Response, ()> {
        for _ in 0..NUM_RETRIES {
            let result = tokio::time::timeout(RESPONSE_TIMEOUT, async {
                client
                    .send_port_mapping_request(Protocol::UDP, port, port, PORT_MAPPING_LIFETIME)
                    .await?;
                client.read_response_or_retry().await
            })
            .await;

            match result {
                Err(_) => tracing::debug!(target: LOG_TARGET, "map ssu2 timeout"),
                Ok(Err(e)) => tracing::debug!(target: LOG_TARGET, ?e, "map ssu2 failed"),
                Ok(Ok(resp)) => return Ok(resp),
            }
        }
        Err(())
    }

    /// Attempt to fetch external address with retries.
    async fn try_get_external_address(client: &mut NatpmpAsync<UdpSocket>) -> Result<Ipv4Addr, ()> {
        for _ in 0..NUM_RETRIES {
            let result = tokio::time::timeout(RESPONSE_TIMEOUT, async {
                client.send_public_address_request().await?;
                client.read_response_or_retry().await
            })
            .await;

            match result {
                Err(_) => tracing::debug!(target: LOG_TARGET, "get external address timeout"),
                Ok(Err(e)) => tracing::debug!(target: LOG_TARGET, ?e, "get external address failed"),
                Ok(Ok(resp)) => {
                    if let Response::Gateway(response) = resp {
                        return Ok(*response.public_address());
                    } else {
                        tracing::warn!(target: LOG_TARGET, ?resp, "unexpected response");
                    }
                }
            }
        }
        Err(())
    }

    /// Run the event loop of NAT-PMP [`PortMapper`].
    pub async fn run(mut self) {
        // Initialize NAT-PMP client with retries.
        let mut client = None;
        for _ in 0..NUM_RETRIES {
            match tokio::time::timeout(RESPONSE_TIMEOUT, new_tokio_natpmp()).await {
                Err(_) => tracing::debug!(target: LOG_TARGET, "init timeout"),
                Ok(Err(e)) => tracing::debug!(target: LOG_TARGET, ?e, "init failed"),
                Ok(Ok(c)) => {
                    client = Some(c);
                    break;
                }
            }
        }
        let Some(mut client) = client else {
            return self.try_switch_to_upnp();
        };

        // Map NTCP2 port.
        if let Some(port) = self.ntcp2_port {
            match Self::try_map_ntcp2(&client, port).await {
                Ok(Response::TCP(_)) => tracing::debug!(target: LOG_TARGET, "ntcp2 port mapped"),
                Ok(other) => tracing::warn!(target: LOG_TARGET, ?other, "unexpected response"),
                Err(()) => return self.try_switch_to_upnp(),
            }
        }

        // Map SSU2 port.
        if let Some(port) = self.ssu2_port {
            match Self::try_map_ssu2(&client, port).await {
                Ok(Response::UDP(_)) => tracing::debug!(target: LOG_TARGET, "ssu2 port mapped"),
                Ok(other) => tracing::warn!(target: LOG_TARGET, ?other, "unexpected response"),
                Err(()) => return self.try_switch_to_upnp(),
            }
        }

        // Get initial external address.
        let mut external_address = match Self::try_get_external_address(&mut client).await {
            Ok(addr) => {
                let _ = self.address_tx.send(addr).await;
                addr
            }
            Err(()) => return self.try_switch_to_upnp(),
        };

        let mut external_address_timer = Box::pin(tokio::time::sleep(ADDRESS_REFRESH_TIMER));
        let mut port_mapping_timer = Box::pin(tokio::time::sleep(Duration::from_secs(
            (PORT_MAPPING_LIFETIME - 10) as u64,
        )));

        loop {
            tokio::select! {
                event = &mut self.shutdown_rx => match event {
                    Ok(tx) => {
                        tracing::info!(target: LOG_TARGET, "shutting down nat-pmp port manager");
                        let _ = tx.send(());
                        return;
                    }
                    Err(_) => return,
                },
                _ = &mut external_address_timer => {
                    if let Ok(addr) = Self::try_get_external_address(&mut client).await {
                        if addr != external_address {
                            tracing::info!(
                                target: LOG_TARGET,
                                new_address = ?addr,
                                previous_address = ?external_address,
                                "new external address discovered",
                            );
                            let _ = self.address_tx.send(addr).await;
                            external_address = addr;
                        }
                    }
                    external_address_timer = Box::pin(tokio::time::sleep(ADDRESS_REFRESH_TIMER));
                }
                _ = &mut port_mapping_timer => {
                    // Refresh NTCP2 mapping.
                    if let Some(port) = self.ntcp2_port {
                        if let Ok(Response::TCP(_)) = Self::try_map_ntcp2(&client, port).await {
                            tracing::debug!(target: LOG_TARGET, "ntcp2 port remapped");
                        }
                    }
                    // Refresh SSU2 mapping.
                    if let Some(port) = self.ssu2_port {
                        if let Ok(Response::UDP(_)) = Self::try_map_ssu2(&client, port).await {
                            tracing::debug!(target: LOG_TARGET, "ssu2 port remapped");
                        }
                    }
                    port_mapping_timer = Box::pin(tokio::time::sleep(Duration::from_secs(
                        (PORT_MAPPING_LIFETIME - 10) as u64,
                    )));
                }
            }
        }
    }
}
