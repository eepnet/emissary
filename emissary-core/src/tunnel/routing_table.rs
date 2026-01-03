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
    error::RoutingError,
    i2np::Message,
    primitives::{MessageId, RouterId, TunnelId},
    subsystem::SubsystemHandle,
};

use futures_channel::oneshot;
use rand_core::RngCore;
use thingbuf::mpsc;

/// Routing table.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub subsystem_handle: SubsystemHandle,
}

impl RoutingTable {
    /// Create new [`RoutingTable`].
    pub fn new(subsystem_handle: SubsystemHandle) -> Self {
        Self { subsystem_handle }
    }

    /// Try to add transit tunnel into [`RoutingTable`].
    ///
    /// This function returns if the tunnel already exists in the routing table.
    pub fn try_add_tunnel<const SIZE: usize>(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<mpsc::Receiver<Message>, RoutingError> {
        self.subsystem_handle.try_insert_tunnel::<SIZE>(tunnel_id)
    }

    /// Insert `sender` into [`RoutingTable`] and allocate it a random [`TunnelId`] which is
    /// returned to the caller.
    //
    /// TODO: add tests
    pub fn insert_tunnel<const SIZE: usize>(
        &self,
        rng: &mut impl RngCore,
    ) -> (TunnelId, mpsc::Receiver<Message>) {
        self.subsystem_handle.insert_tunnel::<SIZE>(rng)
    }

    /// Remove tunnel from [`RoutingTable`].
    pub fn remove_tunnel(&self, tunnel_id: &TunnelId) {
        self.subsystem_handle.remove_tunnel(tunnel_id);
    }

    /// Insert `sender` into [`RoutingTable`] and allocate it a random [`MessageId`] which is
    /// returned to the caller.
    pub fn insert_listener(
        &self,
        rng: &mut impl RngCore,
    ) -> (MessageId, oneshot::Receiver<Message>) {
        self.subsystem_handle.insert_listener(rng)
    }

    /// Remove listener from [`RoutingTable`].
    pub fn remove_listener(&self, message_id: &MessageId) {
        self.subsystem_handle.remove_listener(message_id);
        // self.listeners.write().remove(message_id);
    }

    /// Send `message` to router identified by `router_id`.
    ///
    /// `router_id` could point to local router which causes `message` to be routed locally.
    //
    // TODO(optimization): take deserialized message and serialize it only if it's for remote
    pub fn send_message(&self, router_id: RouterId, message: Message) -> Result<(), RoutingError> {
        // TODO: remove clone
        match self.subsystem_handle.send(&router_id, message.clone()) {
            Ok(()) => Ok(()),
            Err(_) => Err(RoutingError::ChannelFull(message)),
        }
    }

    /// Send `message` to router identified by `router_id` and use a TX to inform the caller whether
    /// the message was sent successfully.
    ///
    /// `router_id` could point to local router which causes `message` to be routed locally.
    pub fn send_message_with_feedback(
        &self,
        router_id: RouterId,
        message: Message,
        tx: oneshot::Sender<()>,
    ) -> Result<(), RoutingError> {
        // TODO: remove clone
        match self.subsystem_handle.send_with_feedback(&router_id, message.clone(), tx) {
            Ok(()) => Ok(()),
            Err(_) => Err(RoutingError::ChannelFull(message)),
        }
    }
}
