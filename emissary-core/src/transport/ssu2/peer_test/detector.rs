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

use crate::transport::FirewallStatus;

use futures::Stream;

use alloc::collections::VecDeque;
use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::peer-test::detector";

#[derive(Debug, Clone, Copy)]
pub enum DetectorEvent {
    /// External address of the router has changed.
    ExternalAddressChanged {
        /// New external address.
        address: SocketAddr,
    },

    /// Firewall status has changed.
    FirewallStatus {
        /// New firewall status.
        status: FirewallStatus,
    },
}

/// Firewall/external address detector.
pub struct Detector {
    /// Port where the SSU2 socket was bound to
    #[allow(unused)]
    bind_port: u16,

    /// Our external address.
    external_address: Option<SocketAddr>,

    /// Our firewall status.
    firewall_status: FirewallStatus,

    /// Pending events.
    pending_events: VecDeque<DetectorEvent>,
}

impl Detector {
    /// Create new `Detector`.
    pub fn new(bind_port: u16) -> Self {
        Self {
            bind_port,
            external_address: None,
            firewall_status: FirewallStatus::Unknown,
            pending_events: VecDeque::new(),
        }
    }

    /// Get router's external address.
    pub fn external_address(&self) -> Option<SocketAddr> {
        self.external_address
    }

    /// Register new external address to detector.
    pub fn register_external_address(&mut self, address: SocketAddr) {
        if self.external_address != Some(address) {
            tracing::info!(
                target: LOG_TARGET,
                ?address,
                "discovered external address",
            );
            self.pending_events.push_back(DetectorEvent::ExternalAddressChanged { address });
        }

        self.external_address = Some(address);
    }

    /// Register peer test result to `Detector`
    ///
    /// `message{4,5,7}` specifies whether the message was received or not.
    ///
    /// https://geti2p.net/spec/ssu2#results-state-machine
    pub fn register_peer_test_result(&mut self, message4: bool, message5: bool, message7: bool) {
        let previous_status = self.firewall_status;

        tracing::debug!(
            target: LOG_TARGET,
            status = ?previous_status,
            ?message4,
            ?message5,
            ?message7,
            "handle peer test result",
        );

        match (message4, message5, message7) {
            (false, false, false) => {
                self.firewall_status = FirewallStatus::Unknown;
            }
            (true, false, false) => {
                self.firewall_status = FirewallStatus::Firewall;
            }
            (false, true, false) => {
                self.firewall_status = FirewallStatus::Ok;
            }
            (true, true, false) => {
                self.firewall_status = FirewallStatus::Ok;
            }
            (true, false, true) => {
                self.firewall_status = FirewallStatus::Firewall;
            }
            (true, true, true) => {
                self.firewall_status = FirewallStatus::Ok;
            }
            (false, false, true) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "received message 7 without receiving message 5",
                );
                debug_assert!(false);
            }
            (false, true, true) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "received message 7 without receiving message 4",
                );
                debug_assert!(false);
            }
        }

        if self.firewall_status != previous_status {
            self.pending_events.push_back(DetectorEvent::FirewallStatus {
                status: self.firewall_status,
            });
        }
    }

    /// Get router's firewall status.
    #[cfg(test)]
    pub fn status(&self) -> FirewallStatus {
        self.firewall_status
    }
}

impl Stream for Detector {
    type Item = DetectorEvent;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.pending_events
            .pop_front()
            .map_or(Poll::Pending, |event| Poll::Ready(Some(event)))
    }
}
