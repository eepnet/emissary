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
    error::Error,
    events::EventHandle,
    netdb::NetDbHandle,
    primitives::{Lease, TunnelId},
    profile::ProfileStorage,
    runtime::{AddressBook, Runtime},
    sam::{
        parser::{DestinationContext, SessionKind},
        session::{SamSessionCommand, SamSessionCommandRecycle},
        socket::SamSocket,
        SubSessionCommand,
    },
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use futures::{future::BoxFuture, StreamExt};
use hashbrown::{HashMap, HashSet};
use thingbuf::mpsc::{Receiver, Sender};

use alloc::{string::String, sync::Arc, vec::Vec};
use core::time::Duration;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::pending::session";

/// Retry duration.
const RETRY_DURATION: Duration = Duration::from_secs(5);

/// SAMv3 client session context.
pub struct SamSessionContext<R: Runtime> {
    /// Address book, if specified.
    pub address_book: Option<Arc<dyn AddressBook>>,

    /// TX channel which can be used to send datagrams to clients.
    pub datagram_tx: Sender<(u16, Vec<u8>)>,

    /// Destination context.
    pub destination: DestinationContext,

    /// Event handle.
    pub event_handle: EventHandle<R>,

    /// Active inbound tunnels and their leases.
    pub inbound: HashMap<TunnelId, Lease>,

    /// Handle to `NetDb`.
    pub netdb_handle: NetDbHandle,

    /// Session options.
    pub options: HashMap<String, String>,

    /// Active outbound tunnels.
    pub outbound: HashSet<TunnelId>,

    /// Profile storage.
    pub profile_storage: ProfileStorage<R>,

    /// RX channel for receiving commands to an active session.
    pub receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// Session ID.
    pub session_id: Arc<str>,

    /// Session kind.
    pub session_kind: SessionKind,

    /// SAMv3 socket.
    pub socket: SamSocket<R>,

    /// TX channel for sending sub-session commands.
    pub sub_session_tx: Option<Sender<SubSessionCommand>>,

    /// Tunnel pool handle.
    pub tunnel_pool_handle: TunnelPoolHandle,
}

/// Pending SAMv3 sessions.
///
/// Builds a tunnel pool and waits for one inbound and one outbound tunnel to be built before
/// returning to [`SamSessionContext`] to `SamServer`, allowing it to start a `Destination`
/// for the connected client.
pub struct PendingSamSession<R: Runtime> {
    /// Address book.
    address_book: Option<Arc<dyn AddressBook>>,

    /// TX channel which can be used to send datagrams to clients.
    datagram_tx: Sender<(u16, Vec<u8>)>,

    /// Destination context.
    destination: DestinationContext,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// Active inbound tunnels and their leases.
    inbound: HashMap<TunnelId, Lease>,

    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Session options.
    options: HashMap<String, String>,

    /// Active outbound tunnels.
    outbound: HashSet<TunnelId>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// RX channel for receiving commands to an active session.
    receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// ID of the client session.
    session_id: Arc<str>,

    /// Session kind.
    session_kind: SessionKind,

    /// SAMv3 socket associated with the session.
    socket: SamSocket<R>,

    /// TX channel for sending sub-session commands.
    sub_session_tx: Option<Sender<SubSessionCommand>>,

    /// Tunnel pool build future.
    ///
    /// Resolves to a `TunnelPoolHandle` once the pool has been built.
    tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,
}

impl<R: Runtime> PendingSamSession<R> {
    /// Create new [`PendingSamSession`].
    pub fn new(
        socket: SamSocket<R>,
        destination: DestinationContext,
        session_id: Arc<str>,
        session_kind: SessionKind,
        options: HashMap<String, String>,
        receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,
        datagram_tx: Sender<(u16, Vec<u8>)>,
        tunnel_pool_future: BoxFuture<'static, TunnelPoolHandle>,
        netdb_handle: NetDbHandle,
        address_book: Option<Arc<dyn AddressBook>>,
        event_handle: EventHandle<R>,
        profile_storage: ProfileStorage<R>,
        sub_session_tx: Option<Sender<SubSessionCommand>>,
    ) -> Self {
        Self {
            address_book,
            datagram_tx,
            destination,
            event_handle,
            inbound: HashMap::new(),
            netdb_handle,
            options,
            outbound: HashSet::new(),
            profile_storage,
            receiver,
            session_id,
            session_kind,
            socket,
            sub_session_tx,
            tunnel_pool_future,
        }
    }

    /// Run the event loop of [`PendingSamSession`].
    ///
    /// First the event loop waits until `NetDb` is ready, meaning it has at least one inbound and
    /// one outbound tunnel. After that a tunnel pool build request is sent to `TunnelManager` and
    /// after a tunnel pool handle is built, the event loop waits until at least one inbound and one
    /// outbound tunnel has been built for the tunnel pool before it returns [`SamSessionContext`].
    pub async fn run(mut self) -> crate::Result<SamSessionContext<R>> {
        loop {
            match self.netdb_handle.wait_until_ready() {
                Ok(rx) =>
                    if rx.await.is_ok() {
                        break;
                    },
                Err(_) => R::delay(RETRY_DURATION).await,
            }
        }

        let mut tunnel_pool_handle = self.tunnel_pool_future.await;

        tracing::trace!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            "tunnel pool for the session has been built",
        );

        loop {
            match tunnel_pool_handle.next().await.ok_or(Error::EssentialTaskClosed)? {
                TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        %tunnel_id,
                        "inbound tunnel built for pending session",
                    );
                    self.inbound.insert(tunnel_id, lease);

                    // `SESSION STATUS` shall not be sent until there is at least one inbound
                    // and outbound tunnel built
                    if !self.inbound.is_empty() && !self.outbound.is_empty() {
                        break;
                    }
                }
                TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        %tunnel_id,
                        "outbound tunnel built for pending session",
                    );
                    self.outbound.insert(tunnel_id);

                    // `SESSION STATUS` shall not be sent until there is at least one inbound
                    // and outbound tunnel built
                    if !self.inbound.is_empty() && !self.outbound.is_empty() {
                        break;
                    }
                }
                TunnelPoolEvent::InboundTunnelExpired { tunnel_id } => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        %tunnel_id,
                        "inbound tunnel expired for pending session",
                    );
                    self.inbound.remove(&tunnel_id);
                }
                TunnelPoolEvent::OutboundTunnelExpired { tunnel_id } => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        %tunnel_id,
                        "outbound tunnel expired for pending session",
                    );
                    self.outbound.remove(&tunnel_id);
                }
                _ => {}
            }
        }

        Ok(SamSessionContext {
            address_book: self.address_book,
            datagram_tx: self.datagram_tx,
            destination: self.destination,
            event_handle: self.event_handle,
            inbound: self.inbound,
            netdb_handle: self.netdb_handle,
            options: self.options,
            outbound: self.outbound,
            profile_storage: self.profile_storage,
            receiver: self.receiver,
            session_id: self.session_id,
            session_kind: self.session_kind,
            socket: self.socket,
            sub_session_tx: self.sub_session_tx,
            tunnel_pool_handle,
        })
    }
}
