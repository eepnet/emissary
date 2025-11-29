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

use crate::port_mapper::PortMapperConfig;

use futures::FutureExt;
use igd_next::{
    aio::{
        tokio::{search_gateway, Tokio},
        Gateway,
    },
    PortMappingProtocol,
};
use tokio::sync::{mpsc, oneshot};

use std::{
    fmt::Debug,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

// TODO: update port mapping if there is new dhcp lease for different address?
// TODO: use `tokio::spawn_blocking()` for `netdev` calls

/// Logging target for the file
const LOG_TARGET: &str = "emissary-util::port-mapper::upnp";

/// Timeout for responses.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times the operations are retried before bailing out.
const NUM_RETRIES: usize = 3usize;

/// Address refresh timer.
///
/// How often is the check for an external/local address change check done.
const ADDRESS_REFRESH_TIMER: Duration = Duration::from_secs(5 * 60);

/// UPnP port mapper.
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
    /// Create new UPnP [`PortMapper`].
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
    async fn with_retries_and_timeout<T, E: Debug>(
        mut future: impl Future<Output = Result<T, E>> + Unpin,
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

    /// Attempt to map NTCP2 port.
    ///
    /// Returns `Err(())` if the operation failed after multiple retries and `Ok(None)` if NTCP2 is
    /// disabled.
    async fn try_map_ntcp2(
        &self,
        address: IpAddr,
        gateway: &Gateway<Tokio>,
    ) -> Result<Option<()>, ()> {
        let Some(ntcp2_port) = self.ntcp2_port else {
            return Ok(None);
        };
        let address = SocketAddr::new(address, ntcp2_port);

        tracing::trace!(
            target: LOG_TARGET,
            ?address,
            "map ntcp2 port",
        );

        Self::with_retries_and_timeout(
            async {
                gateway
                    .add_port(
                        PortMappingProtocol::TCP,
                        ntcp2_port,
                        address,
                        0,
                        &self.config.name,
                    )
                    .await
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
    async fn try_map_ssu2(
        &self,
        address: IpAddr,
        gateway: &Gateway<Tokio>,
    ) -> Result<Option<()>, ()> {
        let Some(ssu2_port) = self.ssu2_port else {
            return Ok(None);
        };
        let address = SocketAddr::new(address, ssu2_port);

        tracing::trace!(
            target: LOG_TARGET,
            ?address,
            "map ssu2 port",
        );

        Self::with_retries_and_timeout(
            async {
                gateway
                    .add_port(
                        PortMappingProtocol::UDP,
                        ssu2_port,
                        address,
                        0,
                        &self.config.name,
                    )
                    .await
            }
            .boxed(),
        )
        .await
        .map(Some)
    }

    /// Run the event loop of UPnP [`PortMapper`].
    pub async fn run(mut self) {
        let local_address = match netdev::interface::get_local_ipaddr() {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "failed to get router's local address",
                );
                return;
            }
            Some(address) => address,
        };

        let gateway = match search_gateway(Default::default()).await {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to find upnp gateway"
                );
                return;
            }
            Ok(gateway) => gateway,
        };

        match self.try_map_ntcp2(local_address, &gateway).await {
            Ok(None) => {}
            Err(()) => {}
            Ok(Some(())) => {}
        }

        match self.try_map_ssu2(local_address, &gateway).await {
            Ok(None) => {}
            Err(()) => {}
            Ok(Some(())) => {}
        }

        let mut external_address =
            match Self::with_retries_and_timeout(async { gateway.get_external_ip().await }.boxed())
                .await
            {
                Err(()) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "failed to fetch external address",
                    );
                    None
                }
                Ok(address) => match address {
                    IpAddr::V4(address) => {
                        let _ = self.address_tx.send(address).await;
                        Some(address)
                    }
                    IpAddr::V6(address) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?address,
                            "ignoring ipv6 external address",
                        );
                        None
                    }
                },
            };

        let mut address_timer = Box::pin(tokio::time::sleep(ADDRESS_REFRESH_TIMER));

        loop {
            tokio::select! {
                event = &mut self.shutdown_rx => match event {
                    Ok(tx) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            ssu2_active = ?self.ssu2_port.is_some(),
                            ntcp2_active = ?self.ntcp2_port.is_some(),
                            "shutting down upnp port manager",
                        );

                        if let Some(ssu2_port) = self.ssu2_port {
                            let _ = gateway
                                .remove_port(PortMappingProtocol::UDP, ssu2_port)
                                .await;
                        }

                        if let Some(ntcp2_port) = self.ntcp2_port {
                            let _ = gateway
                                .remove_port(PortMappingProtocol::TCP, ntcp2_port)
                                .await;
                        }

                        let _ = tx.send(());
                        return;
                    }
                    Err(_) => {
                        if let Some(ssu2_port) = self.ssu2_port {
                            let _ = gateway
                                .remove_port(PortMappingProtocol::UDP, ssu2_port)
                                .await;
                        }

                        if let Some(ntcp2_port) = self.ntcp2_port {
                            let _ = gateway
                                .remove_port(PortMappingProtocol::TCP, ntcp2_port)
                                .await;
                        }
                    }
                },
                _ = &mut address_timer => {
                    match Self::with_retries_and_timeout(async { gateway.get_external_ip().await }.boxed())
                        .await
                    {
                        Err(()) => tracing::warn!(
                            target: LOG_TARGET,
                            "failed to fetch external address",
                        ),
                        Ok(address) => match address {
                            IpAddr::V4(address) => {
                                if Some(address) != external_address {
                                    let _ = self.address_tx.send(address).await;
                                    external_address = Some(address);
                                }
                            }
                            IpAddr::V6(address) => tracing::warn!(
                                target: LOG_TARGET,
                                ?address,
                                "ignoring external ipv6 address",
                            ),
                        },
                    };
                }
            }
        }
    }
}
