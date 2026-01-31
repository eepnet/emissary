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
use hashbrown::HashMap;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{boxed::Box, vec::Vec};
use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Peer test handle.
///
/// Given to active sessions, allowing them to interact with `PeerTestManager`.
pub struct PeerTestHandle {
    /// Message + signature for each peer test request received from Alice.
    alice_requests: HashMap<u32, (Vec<u8>, Vec<u8>)>,

    /// TX channel given to `PeerTestManager`.
    cmd_tx: Sender<PeerTestCommand>,

    /// RX channel for receiving peer test commands from `PeerTestManager`.
    cmd_rx: Receiver<PeerTestCommand>,

    /// TX channel for sending events to `PeerTestManager`.
    event_tx: Sender<PeerTestEvent, PeerTestEventRecycle>,

    /// Pending tests.
    pending_tests: HashMap<u32, Vec<u8>>,
}

impl PeerTestHandle {
    /// Create new `PeerTestHandle` from `event_tx`.
    pub fn new(event_tx: Sender<PeerTestEvent, PeerTestEventRecycle>) -> Self {
        let (cmd_tx, cmd_rx) = channel(32);

        Self {
            alice_requests: HashMap::new(),
            cmd_tx,
            cmd_rx,
            event_tx,
            pending_tests: HashMap::new(),
        }
    }

    /// Get clone of command channel.
    pub fn cmd_tx(&self) -> Sender<PeerTestCommand> {
        self.cmd_tx.clone()
    }

    /// Send peer test message 1 (Alice -> Bob) to `PeerTestManager` for further processing.
    pub fn handle_alice_request(
        &mut self,
        router_id: RouterId,
        nonce: u32,
        address: SocketAddr,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) {
        self.alice_requests.insert(nonce, (message.clone(), signature.clone()));

        let _ = self.event_tx.try_send(PeerTestEvent::AliceRequest {
            address,
            message,
            signature,
            nonce,
            router_id,
            tx: self.cmd_tx.clone(),
        });
    }

    /// Send peer test message 2 (Bob -> Charlie) to `PeerTestManager` for further processing.
    pub fn handle_bob_request(
        &mut self,
        router_id: RouterId,
        nonce: u32,
        address: SocketAddr,
        message: Vec<u8>,
        router_info: Option<Box<RouterInfo>>,
    ) {
        self.pending_tests.insert(nonce, message.clone());

        let _ = self.event_tx.try_send(PeerTestEvent::BobRequest {
            address,
            message,
            nonce,
            router_id,
            router_info,
            tx: self.cmd_tx.clone(),
        });
    }

    /// Relay Charlie's peer test response to Alice.
    pub fn handle_charlie_response(
        &mut self,
        nonce: u32,
        rejection: Option<RejectionReason>,
        message: Vec<u8>,
    ) {
        let _ = self.event_tx.try_send(PeerTestEvent::CharlieResponse {
            nonce,
            rejection,
            message,
        });
    }

    /// Relay peer test response from either Bob or Charlie to `PeerTestManager`.
    pub fn handle_peer_test_response(
        &self,
        nonce: u32,
        rejection: Option<RejectionReason>,
        router_hash: Vec<u8>,
        router_info: Option<Box<RouterInfo>>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let _ = self.event_tx.try_send(PeerTestEvent::PeerTestResponse {
            nonce,
            rejection,
            router_hash,
            router_info,
            message,
            signature,
        });
    }

    /// Attempt to take the stored message of Alice/Bob request peer test message.
    pub fn take_message(&mut self, nonce: &u32) -> Option<Vec<u8>> {
        self.pending_tests.remove(nonce)
    }

    /// Take message and siganture that were part of the peer test request received from Alice.
    pub fn take_alice_request(&mut self, nonce: &u32) -> Option<(Vec<u8>, Vec<u8>)> {
        self.alice_requests.remove(nonce)
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
    /// Handle peer test message 1, i.e., Alice requesting Bob.
    AliceRequest {
        /// Socket address of Alice.
        address: SocketAddr,

        /// Message received from Alice.
        message: Vec<u8>,

        /// Signature for `message`.
        signature: Vec<u8>,

        /// Test nonce.
        nonce: u32,

        /// Router ID of Alice.
        router_id: RouterId,

        /// TX channel for sending commands back to active session.
        tx: Sender<PeerTestCommand>,
    },

    /// Handle peer test message 2, i.e., Bob requesting Charlie.
    BobRequest {
        /// Socket address of Alice.
        address: SocketAddr,

        /// Message received from Alice.
        message: Vec<u8>,

        /// Test nonce.
        nonce: u32,

        /// Router ID of Alice.
        router_id: RouterId,

        /// Router info of Alice.
        ///
        /// `Some(_)` if the router info was received in a `RouterInfo` block.
        router_info: Option<Box<RouterInfo>>,

        /// TX channel for sending commands back to active session.
        tx: Sender<PeerTestCommand>,
    },

    /// Handle peer test response from Charlie.
    CharlieResponse {
        /// Test nonce.
        nonce: u32,

        /// Rejection reason.
        ///
        /// `None` if Charlie accepted peer test request.
        rejection: Option<RejectionReason>,

        /// Message + signature sent by Charlie.
        message: Vec<u8>,
    },

    /// Response to a peer test request, either from Bob or Charlie.
    PeerTestResponse {
        /// Test nonce,
        nonce: u32,

        /// Rejection reason from Bob/Charlie, if request was not accepted.
        ///
        /// `None` if requested was accepted.
        rejection: Option<RejectionReason>,

        /// Router hash.
        ///
        /// All zeros if Bob rejected the request.
        router_hash: Vec<u8>,

        /// Router info of Charlie, if it was sent in a `RouterInfo` block
        router_info: Option<Box<RouterInfo>>,

        /// Message sent by Charlie.
        message: Vec<u8>,

        /// Signature for `message`.
        signature: Vec<u8>,
    },

    #[default]
    Dummy,
}

/// Rejection reason.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

impl RejectionReason {
    /// Convert `RejectionReason` to a status code from Bob.
    pub fn as_bob(self) -> u8 {
        match self {
            Self::Unspecified => 1,
            Self::NoRouterAvailable => 2,
            Self::LimitExceeded => 3,
            Self::SignatureFailure => 4,
            Self::UnsupportedAddress => 5,
            Self::Unknown => 128,
            _ => 1,
        }
    }

    /// Convert `RejectionReason` to a status code from Charlie.
    pub fn as_charlie(self) -> u8 {
        match self {
            Self::Unspecified => 64,
            Self::UnsupportedAddress => 65,
            Self::LimitExceeded => 66,
            Self::SignatureFailure => 67,
            Self::AlreadyConnected => 68,
            Self::Banned => 69,
            Self::RouterUnknown => 70,
            Self::Unknown => 128,
            _ => 1,
        }
    }
}

/// Peer test commands.
///
/// Sent by `PeerTestManager` to active connections.
#[derive(Debug, Default, Clone)]
pub enum PeerTestCommand {
    /// Request Bob to participate in a peer test.
    RequestBob {
        /// Test nonce.
        nonce: u32,

        /// Message.
        message: Vec<u8>,

        /// Signature.
        signature: Vec<u8>,
    },

    /// Peer test request was rejected by `PeerTestManager`.
    Reject {
        /// Test nonce.
        nonce: u32,

        /// Reason for rejection.
        reason: RejectionReason,
    },

    /// Send peer test request from Bob to Charlie.
    RequestCharlie {
        /// Message received from Alice.
        message: Vec<u8>,

        /// Signature for `message`.
        signature: Vec<u8>,

        /// Test nonce.
        nonce: u32,

        /// Router ID of Alice.
        router_id: RouterId,

        /// Serialized router info of Alice.
        router_info: Vec<u8>,
    },

    /// Respond to Alice's request as Charlie.
    SendCharlieResponse {
        /// Test nonce.
        nonce: u32,

        /// Rejection reason.
        ///
        /// `None` if Charlie accepted the peer test request.
        rejection: Option<RejectionReason>,

        /// Router ID of Alice.
        router_id: RouterId,
    },

    /// Relay Charlie's response to Alice.
    RelayCharlieResponse {
        /// Test nonce,
        nonce: u32,

        /// Rejection reason.
        ///
        /// `None` if Charlie accepted the peer test request.
        rejection: Option<RejectionReason>,

        /// Charlie's router ID.
        router_id: RouterId,

        /// Message + signature received from Charlie.
        message: Vec<u8>,

        /// Charlie's router info.
        router_info: Vec<u8>,
    },

    #[default]
    Dummy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bob_rejection_codes() {
        assert_eq!(RejectionReason::Unspecified.as_bob(), 1);
        assert_eq!(RejectionReason::NoRouterAvailable.as_bob(), 2);
        assert_eq!(RejectionReason::LimitExceeded.as_bob(), 3);
        assert_eq!(RejectionReason::SignatureFailure.as_bob(), 4);
        assert_eq!(RejectionReason::UnsupportedAddress.as_bob(), 5);
        assert_eq!(RejectionReason::Unknown.as_bob(), 128);

        assert_eq!(RejectionReason::from(1u8), RejectionReason::Unspecified);
        assert_eq!(
            RejectionReason::from(2u8),
            RejectionReason::NoRouterAvailable
        );
        assert_eq!(RejectionReason::from(3u8), RejectionReason::LimitExceeded);
        assert_eq!(
            RejectionReason::from(4u8),
            RejectionReason::SignatureFailure
        );
        assert_eq!(
            RejectionReason::from(5u8),
            RejectionReason::UnsupportedAddress
        );
        assert_eq!(RejectionReason::from(128u8), RejectionReason::Unknown);

        for i in 6u8..=63u8 {
            assert_eq!(RejectionReason::from(i), RejectionReason::Unspecified);
        }
    }

    #[test]
    fn charlie_rejection_reason() {
        assert_eq!(RejectionReason::Unspecified.as_charlie(), 64);
        assert_eq!(RejectionReason::UnsupportedAddress.as_charlie(), 65);
        assert_eq!(RejectionReason::LimitExceeded.as_charlie(), 66);
        assert_eq!(RejectionReason::SignatureFailure.as_charlie(), 67);
        assert_eq!(RejectionReason::AlreadyConnected.as_charlie(), 68);
        assert_eq!(RejectionReason::Banned.as_charlie(), 69);
        assert_eq!(RejectionReason::RouterUnknown.as_charlie(), 70);
        assert_eq!(RejectionReason::Unknown.as_charlie(), 128);

        assert_eq!(RejectionReason::from(64), RejectionReason::Unspecified);
        assert_eq!(
            RejectionReason::from(65),
            RejectionReason::UnsupportedAddress
        );
        assert_eq!(RejectionReason::from(66), RejectionReason::LimitExceeded);
        assert_eq!(RejectionReason::from(67), RejectionReason::SignatureFailure);
        assert_eq!(RejectionReason::from(68), RejectionReason::AlreadyConnected);
        assert_eq!(RejectionReason::from(69), RejectionReason::Banned);
        assert_eq!(RejectionReason::from(70), RejectionReason::RouterUnknown);
        assert_eq!(RejectionReason::from(128), RejectionReason::Unknown);

        for i in 71u8..=127 {
            assert_eq!(RejectionReason::from(i), RejectionReason::Unspecified);
        }
    }
}
