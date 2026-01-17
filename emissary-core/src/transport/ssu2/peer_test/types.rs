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

use crate::primitives::{RouterId, RouterInfo};

use futures::Stream;
use thingbuf::mpsc::{channel, Receiver, Sender};

use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Peer test handle.
///
/// Given to active sessions, allowing them to interact with `PeerTestManager`.
pub struct PeerTestHandle {
    /// TX channel given to `PeerTestManager`.
    cmd_tx: Sender<PeerTestCommand>,

    /// RX channel for receiving peer test commands from `PeerTestManager`.
    cmd_rx: Receiver<PeerTestCommand>,

    /// TX channel for sending events to `PeerTestManager`.
    event_tx: Sender<PeerTestEvent, PeerTestEventRecycle>,
}

impl PeerTestHandle {
    /// Create new `PeerTestHandle` from `event_tx`.
    pub fn new(event_tx: Sender<PeerTestEvent, PeerTestEventRecycle>) -> Self {
        let (cmd_tx, cmd_rx) = channel(32);

        Self {
            cmd_tx,
            cmd_rx,
            event_tx,
        }
    }

    /// Get clone of command channel.
    pub fn cmd_tx(&self) -> Sender<PeerTestCommand> {
        self.cmd_tx.clone()
    }

    /// Send peer test message 1 (Alice -> Bob) to `PeerTestManager` for further processing.
    pub fn send_message_1(&self, router_id: RouterId, nonce: u32, address: SocketAddr) {
        let _ = self.event_tx.try_send(PeerTestEvent::Message1 {
            address,
            nonce,
            router_id,
            tx: self.cmd_tx.clone(),
        });
    }
}

impl Stream for PeerTestHandle {
    type Item = PeerTestCommand;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.cmd_rx.poll_recv(cx)
    }
}

/// Recycling strategy for [`NetDbAction`].
#[derive(Default, Clone)]
pub struct PeerTestEventRecycle(());

impl thingbuf::Recycle<PeerTestEvent> for PeerTestEventRecycle {
    fn new_element(&self) -> PeerTestEvent {
        PeerTestEvent::Dummy
    }

    fn recycle(&self, element: &mut PeerTestEvent) {
        *element = PeerTestEvent::Dummy;
    }
}

#[derive(Default)]
pub enum PeerTestEvent {
    /// Handle peer test message 1.
    Message1 {
        /// Socket address of Alice.
        address: SocketAddr,

        /// Test nonce.
        nonce: u32,

        /// Router ID of Alice.
        router_id: RouterId,

        /// TX channel for sending commands back to active session.
        tx: Sender<PeerTestCommand>,
    },

    #[default]
    Dummy,
}

/// Rejection reason.
#[derive(Debug, Copy, Clone)]
pub enum RejectionReason {
    /// Unspecified.
    Unspecified,

    /// No router available.
    NoRouterAvailable,

    /// Limit exceeded.
    LimitExceeded,

    /// Signature failure.
    SignatureFailure,

    /// Unsupported address.
    UnsupportedAddress,

    /// Alice is already connected.
    AlreadyConnected,

    /// Alice is banned.
    Banned,

    /// Alice is unknown.
    RouterUnknown,

    /// Unknown source and rejection.
    Unknown,
}

impl From<u8> for RejectionReason {
    fn from(value: u8) -> Self {
        match value {
            0 => unreachable!(),
            1 => Self::Unspecified,
            2 => Self::NoRouterAvailable,
            3 => Self::LimitExceeded,
            4 => Self::SignatureFailure,
            5 => Self::UnsupportedAddress,
            6..=63 => Self::Unspecified,
            64 => Self::Unspecified,
            65 => Self::UnsupportedAddress,
            66 => Self::LimitExceeded,
            67 => Self::SignatureFailure,
            68 => Self::AlreadyConnected,
            69 => Self::Banned,
            70 => Self::RouterUnknown,
            71..=127 => Self::Unspecified,
            128 => Self::Unknown,
            129..=255 => Self::Unspecified,
        }
    }
}

/// Peer test commands.
///
/// Sent by `PeerTestManager` to active connections.
#[derive(Debug, Default, Clone)]
pub enum PeerTestCommand {
    /// Peer test request was rejected by `PeerTestManager`.
    Reject {
        /// Test nonce.
        nonce: u32,

        /// Reason for rejection.
        reason: RejectionReason,
    },

    /// Send peer test request from Bob to Charlie.
    TestPeer {
        /// Socket address of Alice.
        address: SocketAddr,

        /// Test nonce.
        nonce: u32,

        /// Serialized router info of Alice.
        router_info: Vec<u8>,
    },

    #[default]
    Dummy,
}
