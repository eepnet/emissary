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

use crate::config::PortForwardingConfig;

use futures::Stream;
use tokio::sync::{mpsc, oneshot};

use std::{
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
};

mod nat_pmp;
mod upnp;

/// Logging target for the file
const LOG_TARGET: &str = "emissary::port-mapper";

/// Port mapper.
///
/// `PortMapper`'s [`Stream`] implementation never returns `None` and if the underlying stream
/// encounters an error, `PortMapper` stops polling it and keeps returning `Poll::Pending`.
pub struct PortMapper {
    /// RX channel for receiving external address discoveries.
    address_rx: Option<mpsc::Receiver<Ipv4Addr>>,

    /// TX channel for sending shutdown signal to port mapper, whichever is active.
    ///
    /// The active port mapper is sent another oneshot channel which it'll use to signal that the
    /// port mappings, if any, have been removed and the router can be safely shut down.
    ///
    /// `None` if the shutdown signal has been sent.
    shutdown_tx: Option<oneshot::Sender<oneshot::Sender<()>>>,
}

impl PortMapper {
    /// Create new [`PortMapper`]
    pub fn new(
        config: Option<PortForwardingConfig>,
        ntcp2_port: Option<u16>,
        ssu2_port: Option<u16>,
    ) -> Self {
        let (address_tx, address_rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let config = match config {
            None
            | Some(PortForwardingConfig {
                upnp: false,
                nat_pmp: false,
                ..
            }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "port forwarding disabled",
                );

                // note that the other halfs of the address/shutdown channels are dropped since
                // neither protocol was enabled
                //
                // this causes [`PortMapper`] to return `Poll::Pending` from its [`Stream`]
                // implementation and [`Self::shutdown()`] will be no-op.
                return Self {
                    address_rx: Some(address_rx),
                    shutdown_tx: Some(shutdown_tx),
                };
            }
            Some(config) => config,
        };

        tracing::info!(
            target: LOG_TARGET,
            ?config,
            ?ntcp2_port,
            ?ssu2_port,
            "starting port mapper",
        );

        match config {
            PortForwardingConfig { nat_pmp: true, .. } => {
                tokio::spawn(
                    nat_pmp::PortMapper::new(
                        config,
                        ntcp2_port,
                        ssu2_port,
                        address_tx,
                        shutdown_rx,
                    )
                    .run(),
                );
            }
            PortForwardingConfig { nat_pmp: false, .. } => {
                tokio::spawn(
                    upnp::PortMapper::new(config, ntcp2_port, ssu2_port, address_tx, shutdown_rx)
                        .run(),
                );
            }
        }

        Self {
            address_rx: Some(address_rx),
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Shut down [`PortMapper`].
    ///
    /// If UPnP was used and there is a live port mapping, the UPnP port mapper is sent a shut down
    /// signal which causes it to remove the port mapping.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let (recv_tx, recv_rx) = oneshot::channel();

            // send shutdown signal to active port mapper and wait until response is received
            let _ = tx.send(recv_tx);
            let _ = recv_rx.await;
        }
    }
}

impl Stream for PortMapper {
    type Item = Ipv4Addr;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.address_rx.as_mut() {
            None => Poll::Pending,
            Some(rx) => match futures::ready!(rx.poll_recv(cx)) {
                None => {
                    self.address_rx = None;
                    Poll::Pending
                }
                Some(value) => Poll::Ready(Some(value)),
            },
        }
    }
}
