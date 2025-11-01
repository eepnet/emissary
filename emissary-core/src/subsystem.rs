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

use crate::{i2np::Message, primitives::RouterId};

use thingbuf::mpsc::Sender;

use alloc::vec::Vec;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::subsystem";

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum SubsystemKind {
    /// NetDB subsystem.
    NetDb,

    /// Tunneling subsystem.
    Tunnel,
}

#[derive(Default, Clone)]
pub enum SubsystemCommand {
    /// Send I2NP message to router.
    SendMessage {
        /// Serialized I2NP message.
        message: Vec<u8>,
    },

    #[default]
    Dummy,
}

/// Inner subsystem event.
#[derive(Default, Clone)]
pub enum InnerSubsystemEvent {
    /// Connection established.
    ConnectionEstablished {
        /// Router ID.
        router: RouterId,

        /// TX channel for sending commands to the transport.
        tx: Sender<SubsystemCommand>,
    },

    /// Connection closed.
    ConnectionClosed {
        /// Router ID.
        router: RouterId,
    },

    /// Connection failure.
    ConnectionFailure {
        /// Router ID.
        router: RouterId,
    },

    /// I2NP message.
    I2Np {
        /// Raw, unparsed I2NP messages
        messages: Vec<(RouterId, Message)>,
    },

    #[default]
    Dummy,
}

/// Subsystem event.
#[derive(Default, Debug, Clone)]
pub enum SubsystemEvent {
    /// Connection established.
    ConnectionEstablished {
        /// Router ID.
        router: RouterId,
    },

    /// Connection closed.
    ConnectionClosed {
        /// Router ID.
        router: RouterId,
    },

    /// Connection failure.
    ConnectionFailure {
        /// Router ID.
        router: RouterId,
    },

    /// I2NP message.
    I2Np {
        /// Raw, unparsed I2NP messages
        messages: Vec<(RouterId, Message)>,
    },

    #[default]
    Dummy,
}

#[derive(Clone)]
pub struct SubsystemHandle {
    subsystems: Vec<Sender<InnerSubsystemEvent>>,
}

impl SubsystemHandle {
    /// Create new [`SubsystemHandle`].
    pub fn new() -> Self {
        Self {
            subsystems: Vec::new(),
        }
    }

    // TODO: make private!
    pub fn register_subsystem(&mut self, event_tx: Sender<InnerSubsystemEvent>) {
        self.subsystems.push(event_tx);
    }

    // TODO: could definitely be better lol
    pub async fn report_connection_established(
        &mut self,
        router: RouterId,
        tx: Sender<SubsystemCommand>,
    ) {
        for subsystem in &mut self.subsystems {
            let _ = subsystem
                .send(InnerSubsystemEvent::ConnectionEstablished {
                    router: router.clone(),
                    tx: tx.clone(),
                })
                .await;
        }
    }

    pub async fn report_connection_failure(&mut self, router: RouterId) {
        for subsystem in &mut self.subsystems {
            let _ = subsystem
                .send(InnerSubsystemEvent::ConnectionFailure {
                    router: router.clone(),
                })
                .await;
        }
    }

    pub async fn report_connection_closed(&mut self, router: RouterId) {
        for subsystem in &mut self.subsystems {
            let _ = subsystem
                .send(InnerSubsystemEvent::ConnectionClosed {
                    router: router.clone(),
                })
                .await;
        }
    }

    // TODO: fix error
    pub fn dispatch_messages(
        &mut self,
        router_id: RouterId,
        messages: Vec<Message>,
    ) -> crate::Result<()> {
        let (tunnel_messages, netdb_messages): (Vec<_>, Vec<_>) = messages
            .into_iter()
            .map(|message| match message.destination() {
                SubsystemKind::NetDb => (None, Some((router_id.clone(), message))),
                SubsystemKind::Tunnel => (Some((router_id.clone(), message)), None),
            })
            .unzip();

        let tunnel_messages = tunnel_messages.into_iter().flatten().collect::<Vec<_>>();
        let netdb_messages = netdb_messages.into_iter().flatten().collect::<Vec<_>>();

        if !tunnel_messages.is_empty() {
            if let Err(error) = self.subsystems[0].try_send(InnerSubsystemEvent::I2Np {
                messages: tunnel_messages,
            }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    %error,
                    "failed to dispatch mesage to `TunnelManager`",
                );
            }
        }

        if !netdb_messages.is_empty() {
            if let Err(error) = self.subsystems[1].try_send(InnerSubsystemEvent::I2Np {
                messages: netdb_messages,
            }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    %error,
                    "failed to dispatch mesage to `NetDb`",
                );
            }
        }

        Ok(())
    }
}
