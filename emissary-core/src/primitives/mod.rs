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

use core::{fmt, ops::Deref};

pub use capabilities::Capabilities;
pub use date::Date;
pub use destination::{Destination, DestinationId};
pub use datagram_flags::DatagramFlags;
pub use lease_set::{Lease, LeaseSet2, LeaseSet2Header};
pub use mapping::Mapping;
pub use offline_signature::OfflineSignature;
pub use router_address::{RouterAddress, TransportKind};
pub use router_identity::{RouterId, RouterIdentity};
pub use router_info::RouterInfo;
pub use string::Str;

#[cfg(test)]
pub use router_info::RouterInfoBuilder;

mod capabilities;
mod date;
mod destination;
mod datagram_flags;
mod lease_set;
mod mapping;
mod offline_signature;
mod router_address;
mod router_identity;
mod router_info;
mod string;

/// Logging target for the module.
const LOG_TARGET: &str = "emissary::primitives";

/// Tunnel ID.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelId(u32);

impl TunnelId {
    #[cfg(test)]
    pub fn random() -> TunnelId {
        use rand::RngCore;

        TunnelId::from(rand::thread_rng().next_u32())
    }
}

impl From<u32> for TunnelId {
    fn from(value: u32) -> Self {
        TunnelId(value)
    }
}

impl From<TunnelId> for u32 {
    fn from(value: TunnelId) -> Self {
        value.0
    }
}

impl Deref for TunnelId {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for TunnelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Message Id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(u32);

impl MessageId {
    #[cfg(test)]
    pub fn random() -> MessageId {
        use rand::RngCore;

        MessageId::from(rand::thread_rng().next_u32())
    }
}

impl From<u32> for MessageId {
    fn from(value: u32) -> Self {
        MessageId(value)
    }
}

impl From<MessageId> for u32 {
    fn from(value: MessageId) -> Self {
        value.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for MessageId {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
