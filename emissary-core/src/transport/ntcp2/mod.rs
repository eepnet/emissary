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
    config::Ntcp2Config,
    error::{ConnectionError, Error},
    primitives::{RouterAddress, RouterId, RouterInfo},
    router::context::RouterContext,
    runtime::{Counter, JoinSet, MetricType, MetricsHandle, Runtime, TcpListener},
    subsystem::SubsystemHandle,
    transport::{
        metrics::*,
        ntcp2::{
            listener::Ntcp2Listener,
            session::{Ntcp2Session, SessionManager},
        },
        TerminationReason, Transport, TransportEvent,
    },
};

use futures::{Stream, StreamExt};
use hashbrown::{hash_map::Entry, HashMap};

use alloc::{format, vec::Vec};
use core::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
};

mod listener;
mod message;
mod options;
mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2";

/// NTCP2 context.
pub struct Ntcp2Context<R: Runtime> {
    /// NTCP2 configuration.
    config: Ntcp2Config,

    /// NTCP2 listener.
    listener: R::TcpListener,

    /// Socket address.
    socket_address: SocketAddr,
}

impl<R: Runtime> Ntcp2Context<R> {
    /// Get the port where [`Ntcp2Listener`] is bound to.
    pub fn port(&self) -> u16 {
        self.socket_address.port()
    }

    /// Get copy of [`Ntcp2Config`].
    pub fn config(&self) -> Ntcp2Config {
        self.config.clone()
    }
}

/// NTCP2 transport.
pub struct Ntcp2Transport<R: Runtime> {
    /// NTCP2 connection listener.
    listener: Ntcp2Listener<R>,

    /// Open connections.
    open_connections: R::JoinSet<(RouterId, TerminationReason)>,

    /// Pending connections.
    ///
    /// Connections which have been established successfully
    /// but are waiting approval/rejection from the `TransportManager`.
    pending_connections: HashMap<RouterId, Ntcp2Session<R>>,

    /// Pending connections.
    ///
    /// `RouterId` is `None` for inbound sessions.
    pending_handshakes: R::JoinSet<Result<Ntcp2Session<R>, (Option<RouterId>, Error)>>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Session manager.
    session_manager: SessionManager<R>,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> Ntcp2Transport<R> {
    /// Create new [`Ntcp2Transport`].
    pub fn new(
        context: Ntcp2Context<R>,
        allow_local: bool,
        router_ctx: RouterContext<R>,
        subsystem_handle: SubsystemHandle,
    ) -> Self {
        let Ntcp2Context {
            config,
            listener,
            socket_address,
        } = context;

        let session_manager = SessionManager::new(
            config.key,
            config.iv,
            router_ctx.clone(),
            subsystem_handle,
            allow_local,
        );

        tracing::info!(
            target: LOG_TARGET,
            listen_address = ?socket_address,
            ?allow_local,
            "starting ntcp2",
        );

        Ntcp2Transport {
            listener: Ntcp2Listener::new(listener, allow_local),
            open_connections: R::join_set(),
            pending_connections: HashMap::new(),
            pending_handshakes: R::join_set(),
            router_ctx,
            session_manager,
            waker: None,
        }
    }

    /// Collect `Ntcp2Transport`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics
    }

    /// Initialize [`Ntcp2Transport`].
    ///
    /// If NTCP2 has been enabled, create a router address using the configuration that was provided
    /// and bind a TCP listener to the port that was specified.
    ///
    /// Returns a [`RouterAddress`] of the transport and an [`Ntcp2Context`] that needs to be passed
    /// to [`Ntcp2Transport::new()`] when constructing the transport.
    pub async fn initialize(
        config: Option<Ntcp2Config>,
    ) -> crate::Result<(Option<Ntcp2Context<R>>, Option<RouterAddress>)> {
        let Some(config) = config else {
            return Ok((None, None));
        };

        let listener =
            R::TcpListener::bind(format!("0.0.0.0:{}", config.port).parse().expect("to succeed"))
                .await
                .ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        port = %config.port,
                        "ntcp2 port in use, select another port for the transport",
                    );

                    Error::Connection(ConnectionError::BindFailure)
                })?;

        let socket_address = listener.local_address().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                "failed to get local address of the ntcp2 listener",
            );

            Error::Connection(ConnectionError::BindFailure)
        })?;

        let address = match (config.publish, config.host) {
            (true, Some(host)) => RouterAddress::new_published_ntcp2(
                config.key,
                config.iv,
                socket_address.port(),
                host,
            ),
            (true, None) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "ntcp2 requested to be published but no host provided",
                );
                RouterAddress::new_unpublished_ntcp2(config.key, socket_address.port())
            }
            (_, _) => RouterAddress::new_unpublished_ntcp2(config.key, socket_address.port()),
        };

        Ok((
            Some(Ntcp2Context {
                config,
                listener,
                socket_address,
            }),
            Some(address),
        ))
    }
}

impl<R: Runtime> Transport for Ntcp2Transport<R> {
    fn connect(&mut self, router: RouterInfo) {
        tracing::trace!(
            target: LOG_TARGET,
            router_id = %router.identity.id(),
            "negotiate ntcp2 session with router",
        );

        let future = self.session_manager.create_session(router);
        self.pending_handshakes.push(future);
        self.router_ctx.metrics_handle().counter(NUM_OUTBOUND).increment(1);

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    fn accept(&mut self, router_id: &RouterId) {
        match self.pending_connections.remove(router_id) {
            Some(session) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "ntcp2 session accepted, starting event loop",
                );

                self.open_connections.push(session.run());

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    "cannot accept non-existent ntcp2 session",
                );
                debug_assert!(false);
            }
        }
    }

    fn reject(&mut self, router_id: &RouterId) {
        match self.pending_connections.remove(router_id) {
            Some(connection) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "ntcp2 session rejected, closing connection",
                );
                self.router_ctx.metrics_handle().counter(NUM_REJECTED).increment(1);
                drop(connection);
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    "cannot reject non-existent ntcp2 session",
                );
                debug_assert!(false);
            }
        }
    }
}

impl<R: Runtime> Stream for Ntcp2Transport<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.open_connections.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some((router_id, reason))) =>
                return Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id, reason })),
        }

        loop {
            match self.listener.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(stream)) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        "inbound tcp connection, accept session",
                    );

                    let future = self.session_manager.accept_session(stream);
                    self.pending_handshakes.push(future);
                    self.router_ctx.metrics_handle().counter(NUM_INBOUND).increment(1);
                }
            }
        }

        loop {
            match self.pending_handshakes.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(Some(Ok(session))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        role = ?session.role(),
                        router = %session.router().identity.id(),
                        "ntcp2 connection opened",
                    );

                    // get router info from the session, store the session itself into
                    // `pending_connections` and inform `TransportManager` that new ntcp2 connection
                    // with `router` has been opened
                    //
                    // `TransportManager` will either accept or reject the session
                    let router_info = session.router();
                    let router_id = router_info.identity.id();
                    let direction = session.direction();

                    // multiple connections raced and got negotiated at the same time
                    //
                    // reject any connection to/from the same router if a connection is already
                    // under validation in `TransportManager`
                    match self.pending_connections.entry(router_id.clone()) {
                        Entry::Vacant(entry) => {
                            entry.insert(session);
                        }
                        Entry::Occupied(_) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                "pending connection already exist, rejecting new connection",
                            );
                            continue;
                        }
                    }

                    return Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                        direction,
                        router_id,
                    }));
                }
                Poll::Ready(Some(Err((router_id, error)))) => match router_id {
                    Some(router_id) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            ?error,
                            "failed to connect to router",
                        );
                        return Poll::Ready(Some(TransportEvent::ConnectionFailure { router_id }));
                    }
                    None => tracing::trace!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to accept inbound connection",
                    ),
                },
                Poll::Ready(None) => return Poll::Ready(None),
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{primitives::Str, runtime::mock::MockRuntime};

    #[tokio::test]
    async fn publish_ntcp() {
        let config = Some(Ntcp2Config {
            port: 0u16,
            host: Some("8.8.8.8".parse().unwrap()),
            publish: true,
            key: [0xaa; 32],
            iv: [0xbb; 16],
        });
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(config).await.unwrap();
        let port = context.as_ref().unwrap().socket_address.port().to_string();

        assert_eq!(
            address.as_ref().unwrap().options.get(&Str::from("host")),
            Some(&Str::from("8.8.8.8"))
        );
        assert_eq!(
            address.as_ref().unwrap().options.get(&Str::from("port")),
            Some(&Str::from(port))
        );
        assert!(address.as_ref().unwrap().options.get(&Str::from("i")).is_some());
        assert!(address.as_ref().unwrap().socket_address.is_some());
        assert!(context.is_some());
    }

    #[tokio::test]
    async fn dont_publish_ntcp() {
        let config = Some(Ntcp2Config {
            port: 0u16,
            host: None,
            publish: false,
            key: [0xaa; 32],
            iv: [0xbb; 16],
        });
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(config).await.unwrap();

        assert!(address.as_ref().unwrap().options.get(&Str::from("host")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("port")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("i")).is_none());
        assert!(address.as_ref().unwrap().socket_address.is_some());
        assert!(context.is_some());
    }

    #[tokio::test]
    async fn dont_publish_ntcp_host_specified() {
        let config = Some(Ntcp2Config {
            port: 0u16,
            host: Some("8.8.8.8".parse().unwrap()),
            publish: false,
            key: [0xaa; 32],
            iv: [0xbb; 16],
        });
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(config).await.unwrap();

        assert!(address.as_ref().unwrap().options.get(&Str::from("host")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("port")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("i")).is_none());
        assert!(address.as_ref().unwrap().socket_address.is_some());
        assert!(context.is_some());
    }

    #[tokio::test]
    async fn publish_ntcp_but_no_host() {
        let config = Some(Ntcp2Config {
            port: 0u16,
            host: None,
            publish: true,
            key: [0xaa; 32],
            iv: [0xbb; 16],
        });
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(config).await.unwrap();

        assert!(address.as_ref().unwrap().options.get(&Str::from("host")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("port")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("i")).is_none());
        assert!(address.as_ref().unwrap().socket_address.is_some());
        assert!(context.is_some());
    }

    #[tokio::test]
    async fn bind_to_random_port() {
        let config = Some(Ntcp2Config {
            port: 0u16,
            host: None,
            publish: true,
            key: [0xaa; 32],
            iv: [0xbb; 16],
        });
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(config).await.unwrap();

        assert!(address.as_ref().unwrap().options.get(&Str::from("host")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("port")).is_none());
        assert!(address.as_ref().unwrap().options.get(&Str::from("i")).is_none());
        assert!(address.as_ref().unwrap().socket_address.is_some());
        assert_ne!(
            address.as_ref().unwrap().socket_address.as_ref().unwrap().port(),
            0u16
        );
        assert!(context.is_some());
    }

    #[tokio::test]
    async fn publish_random_port() {
        let config = Some(Ntcp2Config {
            port: 0u16,
            host: Some("8.8.8.8".parse().unwrap()),
            publish: true,
            key: [0xaa; 32],
            iv: [0xbb; 16],
        });
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(config).await.unwrap();

        let published_port = address
            .as_ref()
            .unwrap()
            .options
            .get(&Str::from("port"))
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let socket_address_port = address.as_ref().unwrap().socket_address.as_ref().unwrap().port();

        assert!(address.as_ref().unwrap().options.get(&Str::from("host")).is_some());
        assert!(address.as_ref().unwrap().options.get(&Str::from("port")).is_some());
        assert!(address.as_ref().unwrap().options.get(&Str::from("i")).is_some());
        assert_eq!(published_port, socket_address_port);
        assert_ne!(published_port, 0u16);
        assert!(context.is_some());
    }

    #[tokio::test]
    async fn ntcp2_not_enabled() {
        let (context, address) = Ntcp2Transport::<MockRuntime>::initialize(None).await.unwrap();
        assert!(context.is_none());
        assert!(address.is_none());
    }
}
