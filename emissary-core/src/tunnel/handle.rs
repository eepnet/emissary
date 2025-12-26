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

#![allow(unused)]

use crate::{
    error::ChannelError,
    tunnel::{TunnelPoolConfig, TunnelPoolHandle},
};

use futures_channel::oneshot;
use thingbuf::mpsc;

use core::future::Future;

/// Recycling strategy for [`TunnelManagerCommand`].
#[derive(Default, Clone)]
pub(super) struct CommandRecycle(());

impl thingbuf::Recycle<TunnelManagerCommand> for CommandRecycle {
    fn new_element(&self) -> TunnelManagerCommand {
        TunnelManagerCommand::Dummy
    }

    fn recycle(&self, element: &mut TunnelManagerCommand) {
        *element = TunnelManagerCommand::Dummy;
    }
}

/// Commands handled by the [`TunnelManager`].
#[derive(Default)]
pub(super) enum TunnelManagerCommand {
    /// Create new tunnel pool.
    CreateTunnelPool {
        /// Tunnel pool configuration.
        config: TunnelPoolConfig,

        /// TX channel for sending `TunnelPoolHandle` to caller.
        tx: oneshot::Sender<TunnelPoolHandle>,
    },

    /// Dummy event.
    #[default]
    Dummy,
}

/// Tunnel manager handle.
#[derive(Clone)]
pub struct TunnelManagerHandle {
    /// TX channel for sending commands to [`TunnelManager`].
    tx: mpsc::Sender<TunnelManagerCommand, CommandRecycle>,
}

impl TunnelManagerHandle {
    /// Create new [`TunnelManagerHandle`].
    pub(super) fn new() -> (Self, mpsc::Receiver<TunnelManagerCommand, CommandRecycle>) {
        let (tx, rx) = mpsc::with_recycle(64, CommandRecycle(()));

        (Self { tx }, rx)
    }

    /// Create new `TunnelPool` with `config`.
    ///
    /// On success, returns a future which the caller must poll to get a `TunnelPoolHandle`
    /// which is used to interact with the created `TunnelPool`.
    ///
    /// If the channel towards `TunnelManager` is full or closed, `ChannelError` is returned.
    pub fn create_tunnel_pool(
        &self,
        config: TunnelPoolConfig,
    ) -> Result<impl Future<Output = TunnelPoolHandle>, ChannelError> {
        let (tx, rx) = oneshot::channel();

        // waiting on the channel won't fail unless `TunnelManager` has shut down
        self.tx
            .try_send(TunnelManagerCommand::CreateTunnelPool { config, tx })
            .map(|_| async move { rx.await.expect("to succeed") })
            .map_err(From::from)
    }
}
