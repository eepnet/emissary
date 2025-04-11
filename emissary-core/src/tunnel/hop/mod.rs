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
    crypto::StaticPublicKey,
    i2np::{HopRole, Message},
    primitives::{MessageId, RouterId, Str, TunnelId},
    tunnel::{
        noise::{NoiseContext, OutboundSession},
        pool::TunnelPoolContextHandle,
    },
};

use bytes::Bytes;
use hashbrown::HashSet;
use thingbuf::mpsc::Receiver;

use alloc::{collections::VecDeque, vec::Vec};
use core::{marker::PhantomData, num::NonZeroUsize};

pub mod inbound;
pub mod outbound;
pub mod pending;

/// Tunnel hop.
#[derive(Debug)]
pub struct TunnelHop {
    /// Key context.
    key_context: OutboundSession,

    /// Record index in the tunnel build record.
    record_idx: Option<usize>,

    /// Router ID.
    router: RouterId,

    /// Tunnel ID.
    tunnel_id: TunnelId,
}

impl TunnelHop {
    /// Get reference to hop's `OutboundSession`.
    #[cfg(test)]
    pub fn outbound_session(&self) -> &OutboundSession {
        &self.key_context
    }

    /// Get reference to [`TunnelHop`]'s `RouterId`.
    pub fn router_id(&self) -> &RouterId {
        &self.router
    }

    /// Set record index for the tunnel hop.
    pub fn set_record_index(&mut self, record_idx: usize) {
        self.record_idx = Some(record_idx);
    }

    /// Get record index.
    ///
    /// Panics if a record index has not been assigned for the tunnel hop.
    pub fn record_index(&self) -> usize {
        self.record_idx.expect("to exist")
    }
}

/// Tunnel direction.
#[derive(Debug)]
pub enum TunnelDirection {
    /// Inbound tunnel.
    Inbound,

    /// Outbound tunnel.
    Outbound,
}

/// Common interface for local tunnels (initiated by us).
pub trait Tunnel: Send {
    /// Create new [`Tunnel`].
    fn new(name: Str, tunnel_id: TunnelId, receiver: ReceiverKind, hops: Vec<TunnelHop>) -> Self;

    /// Get an iterator of hop roles for the tunnel participants.
    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole>;

    /// Get tunnel direction.
    fn direction() -> TunnelDirection;

    /// Get reference to tunnel ID.
    fn tunnel_id(&self) -> &TunnelId;

    /// Get `RouterId`s of tunnel hops.
    fn hops(&self) -> HashSet<RouterId>;
}

/// Tunnel builder.
pub struct TunnelBuilder<T: Tunnel> {
    /// Hops.
    hops: VecDeque<TunnelHop>,

    /// Name of the tunnel pool this tunnel belongs to.
    name: Str,

    /// Message receiver for the tunnel.
    receiver: ReceiverKind,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Marker for `Tunnel`
    _tunnel: PhantomData<T>,
}

impl<T: Tunnel> TunnelBuilder<T> {
    /// Create new [`TunnelBuilder`].
    pub fn new(name: Str, tunnel_id: TunnelId, receiver: ReceiverKind) -> Self {
        Self {
            hops: VecDeque::new(),
            name,
            receiver,
            tunnel_id,
            _tunnel: Default::default(),
        }
    }

    /// Push new hop into tunnel's hops.
    pub fn with_hop(mut self, hop: TunnelHop) -> Self {
        self.hops.push_back(hop);
        self
    }

    // Build new tunnel from provided hops.
    pub fn build(self) -> T {
        T::new(
            self.name,
            self.tunnel_id,
            self.receiver,
            self.hops.into_iter().rev().collect(),
        )
    }
}

/// Receiver type for the tunnel.
///
/// Messages to outbound tunnels (destined to network) are not routed through [`RoutingTable`] as
/// they must carry additional information (delivery instructions) and thus the receiver types must
/// be differentiated by the tunnel type.
//
// TODO: rewrite comment above
pub enum ReceiverKind {
    Outbound,

    /// Inbound tunnel.
    Inbound {
        /// RX channel for receiving messages from the network.
        message_rx: Receiver<Message>,

        /// Tunnel pool handle.
        handle: TunnelPoolContextHandle,
    },
}

impl ReceiverKind {
    /// Destruct [`ReceiverKind`] into an RX channel for an inbound tunnel.
    pub fn inbound(self) -> (Receiver<Message>, TunnelPoolContextHandle) {
        match self {
            Self::Inbound { message_rx, handle } => (message_rx, handle),
            _ => panic!("state mismatch"),
        }
    }
}

/// Tunnel information for tunnel builds.
#[derive(Debug)]
pub enum TunnelInfo {
    /// Outbound tunnel build.
    Outbound {
        /// ID of the tunnel that's used to receive the outbound tunnel build response.
        ///
        /// It's a tunnel ID of one of following kinds:
        ///  a) ID of an inbound tunnel from the same pool
        ///  b) ID of an inbound tunnel from the exploratory pool (client pools only)
        ///  c) ID of a fake 0-hop inbound tunnel (if no inbound tunnel exist)
        gateway: TunnelId,

        /// ID of the gateway router.
        router_id: Bytes,

        /// ID of the pending outbound tunnel.
        tunnel_id: TunnelId,
    },

    // Inbound tunnel build.
    Inbound {
        /// ID of the pending tunnel.
        tunnel_id: TunnelId,

        /// ID of the router where the reply should be sent.
        router_id: Bytes,
    },
}

impl TunnelInfo {
    /// Destruct [`TunnelInfo`] into reception `TunnelId` and the tunnel's actual `TunnelId`.
    ///
    /// For inbound tunnels the `TunnelId` is the same because the reply is not received
    /// via an inbound tunnel.
    pub fn destruct(self) -> (TunnelId, TunnelId, Bytes) {
        match self {
            Self::Outbound {
                gateway,
                tunnel_id,
                router_id,
            } => (gateway, tunnel_id, router_id),
            Self::Inbound {
                tunnel_id,
                router_id,
            } => (tunnel_id, tunnel_id, router_id),
        }
    }
}

/// Tunnel build parameters.
pub struct TunnelBuildParameters {
    /// Tunnel hops.
    pub hops: Vec<(Bytes, StaticPublicKey)>,

    /// Name of the tunnel pool.
    pub name: Str,

    /// Noise context.
    pub noise: NoiseContext,

    /// Message ID used in the build message.
    pub message_id: MessageId,

    /// Tunnel information.
    pub tunnel_info: TunnelInfo,

    /// Message receiver for the pending tunnel.
    ///
    /// See documentation of [`ReceiverKind`] for more details.
    pub receiver: ReceiverKind,
}
