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

//! I2CP implementation.
//!
//! https://geti2p.net/en/docs/protocol/i2cp

use crate::{
    error::{ConnectionError, Error, I2cpError},
    i2cp::{
        pending::{I2cpSessionContext, PendingI2cpSession},
        session::I2cpSession,
        socket::I2cpSocket,
    },
    netdb::NetDbHandle,
    profile::ProfileStorage,
    runtime::{AddressBook, JoinSet, Runtime, TcpListener},
    tunnel::TunnelManagerHandle,
    util::AsyncReadExt,
};

use futures::StreamExt;

use alloc::{string::String, sync::Arc, vec};
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

mod message;
mod payload;
mod pending;
mod session;
mod socket;

pub use payload::{I2cpPayload, I2cpPayloadBuilder};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp";

/// I2CP protocol byte.
const I2CP_PROTOCOL_BYTE: u8 = 0x2a;

/// I2CP server
///
/// Listens to incoming I2CP streams and dispatches them to a separate event loop
/// after the I2CP protocol byte has been received.
pub struct I2cpServer<R: Runtime> {
    /// Address book,
    address_book: Option<Arc<dyn AddressBook>>,

    /// TCP listener.
    listener: R::TcpListener,

    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Next session ID.
    next_session_id: u16,

    /// Pending connections.
    pending_connections: R::JoinSet<crate::Result<R::TcpStream>>,

    /// Pending sessions.
    pending_session: R::JoinSet<Option<I2cpSessionContext<R>>>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// Handle to `TunnelManager`.
    tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> I2cpServer<R> {
    /// Create new [`I2cpServer`].
    pub async fn new(
        host: String,
        port: u16,
        netdb_handle: NetDbHandle,
        tunnel_manager_handle: TunnelManagerHandle,
        address_book: Option<Arc<dyn AddressBook>>,
        profile_storage: ProfileStorage<R>,
    ) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            ?port,
            "starting i2cp server",
        );

        let address = SocketAddr::new(host.parse::<IpAddr>().expect("valid address"), port);
        let listener = R::TcpListener::bind(address)
            .await
            .ok_or(Error::Connection(ConnectionError::BindFailure))?;

        Ok(Self {
            address_book,
            listener,
            netdb_handle,
            next_session_id: 1u16,
            pending_connections: R::join_set(),
            pending_session: R::join_set(),
            profile_storage,
            tunnel_manager_handle,
        })
    }

    /// Allocate next session ID.
    fn next_session_id(&mut self) -> u16 {
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        session_id
    }

    /// Get address of the I2CP listener.
    pub fn local_address(&self) -> Option<SocketAddr> {
        self.listener.local_address()
    }
}

impl<R: Runtime> Future for I2cpServer<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.listener.poll_accept(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        "ready `None` from i2cp server socket",
                    );

                    return Poll::Ready(());
                }
                Poll::Ready(Some((mut stream, _))) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        "incoming connection, read protocol byte",
                    );

                    // complete handshake for the i2cp client session in the background by polling
                    // the connection until the protocol byte is received and comparing it against
                    // the expected protocol byte
                    self.pending_connections.push(async move {
                        let mut protocol_byte = vec![0u8; 1];

                        stream.read_exact::<R>(&mut protocol_byte).await?;

                        if protocol_byte[0] != I2CP_PROTOCOL_BYTE {
                            return Err(Error::I2cp(I2cpError::InvalidProtocolByte(
                                protocol_byte[0],
                            )));
                        }

                        Ok(stream)
                    });
                }
            }
        }

        loop {
            match self.pending_connections.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        "read `None` from pending connections",
                    );
                    return Poll::Ready(());
                }
                Poll::Ready(Some(Err(error))) => tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to accept inbound i2cp connection",
                ),
                Poll::Ready(Some(Ok(stream))) => {
                    let session_id = self.next_session_id();
                    let tunnel_manager_handle = self.tunnel_manager_handle.clone();
                    let address_book = self.address_book.clone();
                    let profile_storage = self.profile_storage.clone();

                    tracing::trace!(
                        target: LOG_TARGET,
                        ?session_id,
                        "i2cp client session accepted",
                    );

                    self.pending_session.push(PendingI2cpSession::<R>::new(
                        session_id,
                        I2cpSocket::new(stream),
                        tunnel_manager_handle,
                        address_book,
                        profile_storage,
                    ));
                }
            }
        }

        loop {
            match self.pending_session.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(None)) => {}
                Poll::Ready(Some(Some(context))) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?context.session_id,
                        "start active i2cp connection",
                    );

                    R::spawn(I2cpSession::<R>::new(self.netdb_handle.clone(), context));
                }
            }
        }

        Poll::Pending
    }
}
