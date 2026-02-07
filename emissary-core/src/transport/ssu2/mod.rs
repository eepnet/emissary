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
    config::Ssu2Config,
    crypto::StaticPrivateKey,
    error::{ConnectionError, Error},
    primitives::{RouterAddress, RouterId, RouterInfo},
    router::context::RouterContext,
    runtime::{MetricType, Runtime, UdpSocket},
    subsystem::SubsystemEvent,
    transport::{ssu2::socket::Ssu2Socket, Transport, TransportEvent},
};

use futures::{Stream, StreamExt};

use alloc::{format, vec::Vec};
use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use thingbuf::mpsc::Sender;

mod duplicate;
mod message;
mod metrics;
mod peer_test;
mod session;
mod socket;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2";

#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet.
    pub pkt: Vec<u8>,

    /// Socket address of the remote router.
    #[allow(unused)]
    pub address: SocketAddr,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            pkt: Default::default(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        }
    }
}

/// SSU2 context.
pub struct Ssu2Context<R: Runtime> {
    /// SSU configuration.
    config: Ssu2Config,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Socket address.
    socket_address: SocketAddr,
}

impl<R: Runtime> Ssu2Context<R> {
    /// Get the port where [`Ssu2Socket`] is bound to.
    pub fn port(&self) -> u16 {
        self.socket_address.port()
    }

    /// Get copy of [`Ssu2Config`].
    pub fn config(&self) -> Ssu2Config {
        self.config.clone()
    }
}

/// SSU2 transport.
pub struct Ssu2Transport<R: Runtime> {
    /// SSU2 server socket.
    socket: Ssu2Socket<R>,
}

impl<R: Runtime> Ssu2Transport<R> {
    /// Create new [`Ssu2Transport`].
    pub fn new(
        context: Ssu2Context<R>,
        allow_local: bool,
        router_ctx: RouterContext<R>,
        transport_tx: Sender<SubsystemEvent>,
    ) -> Self {
        let Ssu2Context {
            socket_address,
            socket,
            config,
        } = context;

        tracing::info!(
            target: LOG_TARGET,
            listen_address = ?socket_address,
            ?allow_local,
            "starting ssu2",
        );

        Self {
            socket: Ssu2Socket::<R>::new(
                socket,
                StaticPrivateKey::from(config.static_key),
                config.intro_key,
                transport_tx,
                router_ctx.clone(),
            ),
        }
    }

    /// Collect SSU2-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Initialize [`SsU2Transport`].
    ///
    /// If SSU2 has been enabled, create a router address using the configuration that was provided
    /// and bind a UDP socket to the port that was specified.
    ///
    /// Returns a [`RouterAddress`] of the transport and an [`SsU2Context`] that needs to be passed
    /// to [`SsU2Transport::new()`] when constructing the transport.
    pub async fn initialize(
        config: Option<Ssu2Config>,
    ) -> crate::Result<(Option<Ssu2Context<R>>, Option<RouterAddress>)> {
        let Some(config) = config else {
            return Ok((None, None));
        };

        tracing::warn!(
            target: LOG_TARGET,
            "ssu2 support is experimental and not recommend for general use",
        );

        let socket =
            R::UdpSocket::bind(format!("0.0.0.0:{}", config.port).parse().expect("to succeed"))
                .await
                .ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        port = %config.port,
                        "ssu2 port in use, select another port for the transport",
                    );

                    Error::Connection(ConnectionError::BindFailure)
                })?;

        let socket_address = socket.local_address().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                "failed to get local address of the ssu2 listener",
            );

            Error::Connection(ConnectionError::BindFailure)
        })?;

        let address = match (config.publish, config.host) {
            (true, Some(host)) => RouterAddress::new_published_ssu2(
                config.static_key,
                config.intro_key,
                socket_address.port(),
                host,
            ),
            (true, None) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "ssu2 requested to be published but no host provided",
                );
                RouterAddress::new_unpublished_ssu2(
                    config.static_key,
                    config.intro_key,
                    socket_address.port(),
                )
            }
            (_, _) => RouterAddress::new_unpublished_ssu2(
                config.static_key,
                config.intro_key,
                socket_address.port(),
            ),
        };

        Ok((
            Some(Ssu2Context {
                config,
                socket,
                socket_address,
            }),
            Some(address),
        ))
    }
}

impl<R: Runtime> Transport for Ssu2Transport<R> {
    fn connect(&mut self, router_info: RouterInfo) {
        self.socket.connect(router_info);
    }

    fn accept(&mut self, router_id: &RouterId) {
        self.socket.accept(router_id);
    }

    fn reject(&mut self, router_id: &RouterId) {
        self.socket.reject(router_id);
    }
}

impl<R: Runtime> Stream for Ssu2Transport<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.socket.poll_next_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::SigningPrivateKey, events::EventManager, profile::ProfileStorage,
        runtime::mock::MockRuntime, transport::FirewallStatus,
    };
    use bytes::Bytes;
    use std::time::Duration;
    use thingbuf::mpsc::channel;

    #[tokio::test]
    async fn connect_ssu2() {
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (ctx1, address1) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xaa; 32],
            intro_key: [0xbb; 32],
        }))
        .await
        .unwrap();
        let (ctx2, address2) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xcc; 32],
            intro_key: [0xdd; 32],
        }))
        .await
        .unwrap();

        let (static1, signing1) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let (static2, signing2) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let router_info1 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address1,
            &static1,
            &signing1,
            false,
        );
        let router_info2 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address2,
            &static2,
            &signing2,
            false,
        );
        let (event1_tx, _event1_rx) = channel(64);
        let (event2_tx, _event2_rx) = channel(64);

        let mut transport1 = Ssu2Transport::<MockRuntime>::new(
            ctx1.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                router_info1.identity.id(),
                Bytes::from(router_info1.serialize(&signing1)),
                static1,
                signing1,
                2u8,
                event_handle.clone(),
            ),
            event1_tx,
        );
        let mut transport2 = Ssu2Transport::<MockRuntime>::new(
            ctx2.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                router_info2.identity.id(),
                Bytes::from(router_info2.serialize(&signing2)),
                static2,
                signing2,
                2u8,
                event_handle.clone(),
            ),
            event2_tx,
        );
        tokio::spawn(async move {
            loop {
                match transport2.next().await.unwrap() {
                    TransportEvent::ConnectionEstablished { router_id, .. } =>
                        transport2.accept(&router_id),
                    _ => {}
                }
            }
        });

        transport1.connect(router_info2);
        let future = async move {
            loop {
                match transport1.next().await.unwrap() {
                    TransportEvent::ConnectionEstablished { router_id, .. } => {
                        transport1.accept(&router_id);
                        break;
                    }
                    _ => {}
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(15), future).await {
            Err(_) => panic!("timeout"),
            Ok(()) => {}
        }
    }

    #[tokio::test]
    async fn connect_ssu2_wrong_network() {
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (ctx1, address1) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xaa; 32],
            intro_key: [0xbb; 32],
        }))
        .await
        .unwrap();
        let (ctx2, address2) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xcc; 32],
            intro_key: [0xdd; 32],
        }))
        .await
        .unwrap();

        let (static1, signing1) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let (static2, signing2) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let router_info1 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address1,
            &static1,
            &signing1,
            false,
        );
        let router_info2 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address2,
            &static2,
            &signing2,
            false,
        );
        let (event1_tx, _event1_rx) = channel(64);
        let (event2_tx, _event2_rx) = channel(64);

        let mut transport1 = Ssu2Transport::<MockRuntime>::new(
            ctx1.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                router_info1.identity.id(),
                Bytes::from(router_info1.serialize(&signing1)),
                static1,
                signing1,
                2u8,
                event_handle.clone(),
            ),
            event1_tx,
        );
        let mut transport2 = Ssu2Transport::<MockRuntime>::new(
            ctx2.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                router_info2.identity.id(),
                Bytes::from(router_info2.serialize(&signing2)),
                static2,
                signing2,
                5u8, // wrong network
                event_handle.clone(),
            ),
            event2_tx,
        );
        tokio::spawn(async move { while let Some(_) = transport2.next().await {} });

        transport1.connect(router_info2);
        let future = async move {
            loop {
                match transport1.next().await.unwrap() {
                    TransportEvent::ConnectionFailure { .. } => break,
                    _ => {}
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(20), future).await {
            Err(_) => panic!("timeout"),
            Ok(()) => {}
        }
    }

    #[tokio::test]
    async fn peer_test_works() {
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (ctx1, address1) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xaa; 32],
            intro_key: [0xbb; 32],
        }))
        .await
        .unwrap();
        let (ctx2, address2) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xcc; 32],
            intro_key: [0xdd; 32],
        }))
        .await
        .unwrap();
        let (ctx3, address3) = Ssu2Transport::<MockRuntime>::initialize(Some(Ssu2Config {
            port: 0u16,
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
            static_key: [0xee; 32],
            intro_key: [0xff; 32],
        }))
        .await
        .unwrap();

        let (static1, signing1) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let (static2, signing2) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let (static3, signing3) = (
            StaticPrivateKey::random(MockRuntime::rng()),
            SigningPrivateKey::random(MockRuntime::rng()),
        );
        let router_info1 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address1.clone(),
            &static1,
            &signing1,
            false,
        );
        let router_info2 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address2.clone(),
            &static2,
            &signing2,
            false,
        );
        let router_info3 = RouterInfo::new::<MockRuntime>(
            &Default::default(),
            None,
            address3.clone(),
            &static3,
            &signing3,
            false,
        );
        let (event1_tx, _event1_rx) = channel(64);
        let (event2_tx, _event2_rx) = channel(64);
        let (event3_tx, _event3_rx) = channel(64);

        let serialized1 = Bytes::from(router_info1.serialize(&signing1));
        let serialized2 = Bytes::from(router_info2.serialize(&signing2));
        let serialized3 = Bytes::from(router_info3.serialize(&signing3));

        let storage1 = {
            let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
            storage.discover_router(router_info2.clone(), serialized2.clone());
            storage.discover_router(router_info3.clone(), serialized3.clone());

            storage
        };
        let storage2 = {
            let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
            storage.discover_router(router_info3.clone(), serialized3.clone());
            storage.discover_router(router_info1.clone(), serialized1.clone());

            storage
        };
        let storage3 = {
            let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
            storage.discover_router(router_info2.clone(), serialized2.clone());
            storage.discover_router(router_info1.clone(), serialized1.clone());

            storage
        };

        let mut transport1 = Ssu2Transport::<MockRuntime>::new(
            ctx1.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                storage1,
                router_info1.identity.id(),
                Bytes::from(router_info1.serialize(&signing1)),
                static1,
                signing1,
                5u8,
                event_handle.clone(),
            ),
            event1_tx,
        );
        let mut transport2 = Ssu2Transport::<MockRuntime>::new(
            ctx2.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                storage2,
                router_info2.identity.id(),
                Bytes::from(router_info2.serialize(&signing2)),
                static2,
                signing2,
                5u8,
                event_handle.clone(),
            ),
            event2_tx,
        );
        let mut transport3 = Ssu2Transport::<MockRuntime>::new(
            ctx3.unwrap(),
            true,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                storage3,
                router_info3.identity.id(),
                Bytes::from(router_info3.serialize(&signing3)),
                static3,
                signing3,
                5u8,
                event_handle.clone(),
            ),
            event3_tx,
        );

        // spawn the first router in the background
        tokio::spawn(async move {
            while let Some(event) = transport2.next().await {
                match event {
                    TransportEvent::ConnectionEstablished { router_id, .. } => {
                        transport2.accept(&router_id);
                    }
                    _ => {}
                }
            }
        });

        // connect the routers together and ensure connection works
        transport1.connect(router_info2.clone());
        let future = async {
            loop {
                match transport1.next().await.unwrap() {
                    TransportEvent::ConnectionEstablished { router_id, .. } => {
                        transport1.accept(&router_id);
                        break;
                    }
                    _ => {}
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(20), future).await {
            Err(_) => panic!("timeout"),
            Ok(()) => {}
        }

        // spawn the second router in the background
        tokio::spawn(async move {
            while let Some(event) = transport1.next().await {
                match event {
                    TransportEvent::ConnectionEstablished { router_id, .. } => {
                        transport1.accept(&router_id);
                    }
                    _ => {}
                }
            }
        });

        // connect the third router to router2 which also starts a peer test process
        transport3.connect(router_info2);
        let future = async {
            loop {
                match transport3.next().await.unwrap() {
                    TransportEvent::ConnectionEstablished { router_id, .. } => {
                        transport3.accept(&router_id);
                        break;
                    }
                    _ => {}
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(20), future).await {
            Err(_) => panic!("timeout"),
            Ok(()) => {}
        }

        let future = async move {
            loop {
                match transport3.next().await.unwrap() {
                    TransportEvent::FirewallStatus { status } => {
                        assert_eq!(status, FirewallStatus::Ok);
                        break;
                    }
                    _ => {}
                }
            }
        };
        match tokio::time::timeout(Duration::from_secs(20), future).await {
            Err(_) => panic!("timeout"),
            Ok(()) => {}
        }
    }
}
