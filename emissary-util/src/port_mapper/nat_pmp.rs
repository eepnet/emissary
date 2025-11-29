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

use std::{future::Future, net::Ipv4Addr, time::Duration};

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

    /// Attempt to execute `future` with with retries and timeout.
    ///
    /// If the future fails after `NUM_RETRIES` many retries, either due to error or timeout, the
    /// function returns `None` which the caller should consider as fatal failure.
    async fn with_retries_and_timeout<T>(
        mut future: impl Future<Output = natpmp::Result<T>> + Unpin,
    ) -> Result<T, ()> {
        for _ in 0..NUM_RETRIES {
            match tokio::time::timeout(RESPONSE_TIMEOUT, &mut future).await {
                Err(_) => tracing::debug!(
                    target: LOG_TARGET,
                    "operation timed out",
                ),
                Ok(Err(error)) => tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "operation failed",
                ),
                Ok(Ok(res)) => return Ok(res),
            }
        }

        Err(())
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

    /// Attempt to map NTCP2 port.
    ///
    /// Returns `Err(())` if the operation failed after multiple retries and `Ok(None)` if NTCP2 is
    /// disabled.
    async fn try_map_ntcp2(&self, client: &NatpmpAsync<UdpSocket>) -> Result<Option<Response>, ()> {
        let Some(ntcp2_port) = self.ntcp2_port else {
            return Ok(None);
        };

        tracing::trace!(
            target: LOG_TARGET,
            ?ntcp2_port,
            "map ntcp2 port",
        );

        Self::with_retries_and_timeout(
            async {
                client
                    .send_port_mapping_request(
                        Protocol::TCP,
                        ntcp2_port,
                        ntcp2_port,
                        PORT_MAPPING_LIFETIME,
                    )
                    .await?;
                client.read_response_or_retry().await
            }
            .boxed(),
        )
        .await
        .map(Some)
    }

    /// Attempt to map SSU2 port.
    ///
    /// Returns `Err(())` if the operation failed after multiple retries and `Ok(None)` if SSU2 is
    /// disabled.
    async fn try_map_ssu2(&self, client: &NatpmpAsync<UdpSocket>) -> Result<Option<Response>, ()> {
        let Some(ssu2_port) = self.ssu2_port else {
            return Ok(None);
        };

        tracing::trace!(
            target: LOG_TARGET,
            ?ssu2_port,
            "map ssu2 port",
        );

        Self::with_retries_and_timeout(
            async {
                client
                    .send_port_mapping_request(
                        Protocol::TCP,
                        ssu2_port,
                        ssu2_port,
                        PORT_MAPPING_LIFETIME,
                    )
                    .await?;
                client.read_response_or_retry().await
            }
            .boxed(),
        )
        .await
        .map(Some)
    }

    /// Attempt to fetch external address of the router.
    async fn try_get_external_address(
        client: &mut NatpmpAsync<UdpSocket>,
    ) -> Result<Option<Ipv4Addr>, ()> {
        Self::with_retries_and_timeout(
            async {
                client.send_public_address_request().await?;
                client.read_response_or_retry().await
            }
            .boxed(),
        )
        .await
        .map(|result| match result {
            Response::Gateway(response) => Some(*response.public_address()),
            response => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?response,
                    "ignoring unexpected response",
                );
                None
            }
        })
    }

    /// Run the event loop of NAT-PMP [`PortMapper`].
    pub async fn run(mut self) {
        let Ok(mut client) = Self::with_retries_and_timeout(new_tokio_natpmp().boxed()).await
        else {
            return self.try_switch_to_upnp();
        };

        match self.try_map_ntcp2(&client).await {
            Ok(None) => {}
            Err(()) => return self.try_switch_to_upnp(),
            Ok(Some(Response::TCP(_))) => tracing::debug!(
                target: LOG_TARGET,
                "ntcp2 port mapped",
            ),
            Ok(Some(response)) => tracing::warn!(
                target: LOG_TARGET,
                ?response,
                "ignoring unexpected response",
            ),
        }

        match self.try_map_ssu2(&client).await {
            Ok(None) => {}
            Err(()) => return self.try_switch_to_upnp(),
            Ok(Some(Response::TCP(_))) => tracing::debug!(
                target: LOG_TARGET,
                "ssu2 port mapped",
            ),
            Ok(Some(response)) => tracing::warn!(
                target: LOG_TARGET,
                ?response,
                "ignoring unexpected response",
            ),
        }

        let mut external_address = match Self::try_get_external_address(&mut client).await {
            Err(()) => return self.try_switch_to_upnp(),
            Ok(None) => return self.try_switch_to_upnp(),
            Ok(Some(address)) => {
                let _ = self.address_tx.send(address).await;
                address
            }
        };

        let mut external_address_timer = Box::pin(tokio::time::sleep(ADDRESS_REFRESH_TIMER));
        let mut port_mapping_timer = Box::pin(tokio::time::sleep(Duration::from_secs(
            (PORT_MAPPING_LIFETIME - 10) as u64,
        )));

        loop {
            tokio::select! {
                event = &mut self.shutdown_rx => match event {
                    Ok(tx) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            "shutting down nat-pmp port manager",
                        );

                        // nat-pmp doesn't need to unmap any ports since the mappings have
                        // expirations meaning the shutdown response can be sent immediately
                        let _ = tx.send(());
                        return;
                    }
                    Err(_) => return,
                },
                _ = &mut external_address_timer => {
                    if let Ok(Some(address)) = Self::try_get_external_address(&mut client).await {
                        if address != external_address {
                            tracing::info!(
                                target: LOG_TARGET,
                                new_address = ?address,
                                previous_address = ?external_address,
                                "new external address discovered",
                            );

                            let _ = self.address_tx.send(address).await;
                            external_address = address;
                        }
                    };

                    external_address_timer = Box::pin(tokio::time::sleep(ADDRESS_REFRESH_TIMER));
                }
                _ = &mut port_mapping_timer => {
                    match self.try_map_ntcp2(&client).await {
                        Ok(Some(Response::TCP(_))) => tracing::debug!(
                            target: LOG_TARGET,
                            "ntcp2 port remapped",
                        ),
                        Ok(Some(response)) => tracing::warn!(
                            target: LOG_TARGET,
                            ?response,
                            "ignoring unexpected response",
                        ),
                        _ => {}
                    }

                    match self.try_map_ssu2(&client).await {
                        Ok(Some(Response::TCP(_))) => tracing::debug!(
                            target: LOG_TARGET,
                            "ssu2 port remapped",
                        ),
                        Ok(Some(response)) => tracing::warn!(
                            target: LOG_TARGET,
                            ?response,
                            "ignoring unexpected response",
                        ),
                        _ => {}
                    }

                    port_mapping_timer = Box::pin(tokio::time::sleep(Duration::from_secs(
                        (PORT_MAPPING_LIFETIME - 10) as u64,
                    )));
                }
            }
        }
    }
}
