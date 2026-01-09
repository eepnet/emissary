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
    crypto::{SigningPrivateKey, StaticPrivateKey, StaticPublicKey},
    events::EventManager,
    i2np::{tunnel::gateway, Message, MessageType},
    primitives::{Capabilities, MessageId, RouterId, RouterInfo, RouterInfoBuilder, Str, TunnelId},
    profile::ProfileStorage,
    router::context::RouterContext,
    runtime::{mock::MockRuntime, Runtime},
    shutdown::ShutdownContext,
    subsystem::{
        NetDbEvent, OutboundMessage, OutboundMessageRecycle, SubsystemEvent, SubsystemHandle,
        SubsystemManager, SubsystemManagerContext,
    },
    tunnel::{
        garlic::{DeliveryInstructions, GarlicHandler},
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel, ReceiverKind,
            TunnelBuildParameters, TunnelInfo,
        },
        noise::NoiseContext,
        pool::TunnelPoolBuildParameters,
        transit::TransitTunnelManager,
    },
    TransitConfig,
};

use bytes::Bytes;
use futures::FutureExt;
use futures_channel::oneshot;
use hashbrown::HashMap;
use rand_core::RngCore;
use thingbuf::mpsc::{channel, with_recycle, Receiver, Sender};

use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Make new router.
pub fn make_router(
    fast: bool,
) -> (
    Bytes,
    StaticPrivateKey,
    SigningPrivateKey,
    NoiseContext,
    RouterInfo,
) {
    let (mut router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
    if fast {
        router_info.capabilities = Capabilities::parse(&Str::from("XR")).expect("to succeed");
    }

    let router_hash: Vec<u8> = router_info.identity.id().into();
    let router_hash = Bytes::from(router_hash);

    (
        router_hash.clone(),
        static_key.clone(),
        signing_key,
        NoiseContext::new(static_key.clone(), router_hash),
        router_info,
    )
}

/// [`TransitTunnelManager`] for testing.
pub struct TestTransitTunnelManager {
    /// RX channel for receiving dial requests from `SubsystemManager`.
    _dial_rx: Receiver<RouterId>,

    /// RX channel passed to `NetDb`.
    ///
    /// Allows `SubsystemManager` to route messages to `NetDb`.
    _netdb_rx: Receiver<NetDbEvent>,

    /// Shutdown context.
    _shutdown_ctx: ShutdownContext<MockRuntime>,

    /// Garlic handler.
    garlic: GarlicHandler<MockRuntime>,

    /// Transit tunnel manager.
    manager: TransitTunnelManager<MockRuntime>,

    /// Static public key.
    public_key: StaticPublicKey,

    /// Router ID.
    router: RouterId,

    /// Router hash.
    router_hash: Bytes,

    /// Router info.
    router_info: RouterInfo,

    /// Connected routers.
    routers: HashMap<RouterId, Receiver<OutboundMessage, OutboundMessageRecycle>>,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// TX channel given to all transports, allowing them to send events to `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,
}

impl fmt::Debug for TestTransitTunnelManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestTransitTunnelManager")
            .field("router", &self.router)
            .finish_non_exhaustive()
    }
}

impl TestTransitTunnelManager {
    pub fn new(fast: bool) -> Self {
        let (router_hash, static_key, signing_key, noise, router_info) = make_router(fast);
        let public_key = static_key.public();
        let mut _shutdown_ctx = ShutdownContext::<MockRuntime>::new();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let SubsystemManagerContext {
            dial_rx,
            handle: subsystem_handle,
            manager,
            netdb_rx,
            transit_rx,
            transport_tx,
        } = SubsystemManager::<MockRuntime>::new(100, 0., router_info.identity.id(), noise.clone());

        // spawn subsystem manager in the background
        //
        // the manager needs to be active because tunnel tests use subsystem handle
        // to route internal and external messages
        tokio::spawn(manager);

        Self {
            garlic: GarlicHandler::new(noise.clone(), MockRuntime::register_metrics(vec![], None)),
            manager: TransitTunnelManager::<MockRuntime>::new(
                Some(TransitConfig {
                    max_tunnels: Some(5000),
                }),
                RouterContext::new(
                    MockRuntime::register_metrics(vec![], None),
                    ProfileStorage::new(&[], &[]),
                    router_info.identity.id(),
                    Bytes::from(router_info.serialize(&signing_key)),
                    static_key,
                    signing_key,
                    2u8,
                    event_handle.clone(),
                ),
                subsystem_handle.clone(),
                transit_rx,
                _shutdown_ctx.handle(),
            ),
            _dial_rx: dial_rx,
            _netdb_rx: netdb_rx,
            transport_tx,
            public_key,
            router_hash: router_hash.clone(),
            router_info,
            router: RouterId::from(router_hash),
            routers: HashMap::new(),
            subsystem_handle,
            _shutdown_ctx,
        }
    }

    /// Get copy of [`RouterInfo`].
    pub fn router_info(&self) -> RouterInfo {
        self.router_info.clone()
    }

    /// Get hash of the router.
    pub fn router_hash(&self) -> Bytes {
        self.router_hash.clone()
    }

    /// Get public key of the router.
    pub fn public_key(&self) -> StaticPublicKey {
        self.public_key.clone()
    }

    /// Get ID of the router.
    pub fn router(&self) -> RouterId {
        self.router.clone()
    }

    /// Get mutable reference to [`GarlicHandler`].
    pub fn garlic(&mut self) -> &mut GarlicHandler<MockRuntime> {
        &mut self.garlic
    }

    /// Handle short tunnel build.
    pub fn handle_short_tunnel_build(
        &mut self,
        message: Message,
    ) -> crate::Result<(RouterId, Message, Option<oneshot::Sender<()>>)> {
        self.manager.handle_short_tunnel_build(message)
    }

    /// Get message RX channel of a connected router.
    pub fn router_rx(
        &self,
        router_id: &RouterId,
    ) -> Option<&Receiver<OutboundMessage, OutboundMessageRecycle>> {
        self.routers.get(router_id)
    }

    pub fn subsystem_handle(&self) -> &SubsystemHandle {
        &self.subsystem_handle
    }

    /// Attempt to select message from one of the connection handlers.
    pub fn select_message(&self) -> Option<(RouterId, Message)> {
        for (router_id, rx) in &self.routers {
            match rx.try_recv() {
                Ok(OutboundMessage::Message(message)) => return Some((router_id.clone(), message)),
                Ok(OutboundMessage::MessageWithFeedback(message, tx)) => {
                    tx.send(()).unwrap();
                    return Some((router_id.clone(), message));
                }
                Ok(OutboundMessage::Messages(_)) => panic!("not supported"),
                Ok(OutboundMessage::Dummy) => {}
                Err(_) => {}
            }
        }

        None
    }

    /// Connect router.
    pub fn connect_router(&mut self, router_id: &RouterId) {
        let (tx, rx) = with_recycle(128, OutboundMessageRecycle::default());
        self.routers.insert(router_id.clone(), rx);
        self.transport_tx
            .try_send(SubsystemEvent::ConnectionEstablished {
                router_id: router_id.clone(),
                tx,
            })
            .unwrap();
    }
}

impl Future for TestTransitTunnelManager {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.manager.poll_unpin(cx)
    }
}

/// Connect all routers together.
pub fn connect_routers<'a>(routers: impl Iterator<Item = &'a mut TestTransitTunnelManager>) {
    let (routers, router_ids): (Vec<_>, Vec<_>) = routers
        .map(|router| {
            let router_id = router.router();

            (router, router_id)
        })
        .unzip();

    for router in routers {
        for remote_router in &router_ids {
            if remote_router == &router.router() {
                continue;
            }

            let (tx, rx) = with_recycle(128, OutboundMessageRecycle::default());
            router.routers.insert(remote_router.clone(), rx);
            router
                .transport_tx
                .try_send(SubsystemEvent::ConnectionEstablished {
                    router_id: remote_router.clone(),
                    tx,
                })
                .unwrap();
        }
    }
}

/// Build outbound tunnel.
pub fn build_outbound_tunnel(
    fast: bool,
    num_hops: usize,
) -> (
    Bytes,
    OutboundTunnel<MockRuntime>,
    Vec<TestTransitTunnelManager>,
) {
    let (hops, mut transit_managers): (
        Vec<(Bytes, StaticPublicKey)>,
        Vec<TestTransitTunnelManager>,
    ) = (0..num_hops)
        .map(|i| {
            let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

            (
                (manager.router_hash.clone(), manager.public_key.clone()),
                manager,
            )
        })
        .unzip();

    let (local_hash, _, _, local_noise, _) = make_router(fast);
    let message_id = MessageId::from(MockRuntime::rng().next_u32());
    let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
    let gateway = TunnelId::from(MockRuntime::rng().next_u32());

    let (pending_tunnel, _next_router, message) =
        PendingTunnel::<_, OutboundTunnel<MockRuntime>>::create_tunnel(TunnelBuildParameters {
            hops: hops.clone(),
            metrics_handle: MockRuntime::register_metrics(vec![], None),
            name: Str::from("tunnel-pool"),
            noise: local_noise,
            message_id,
            tunnel_info: TunnelInfo::Outbound {
                gateway,
                tunnel_id,
                router_id: local_hash.clone(),
            },
            receiver: ReceiverKind::Outbound,
        })
        .unwrap();

    let message = hops.iter().zip(transit_managers.iter_mut()).fold(
        message,
        |acc, ((_, _), transit_manager)| {
            let (_, message, tx) = transit_manager.handle_short_tunnel_build(acc).unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
            message
        },
    );
    let gateway::TunnelGateway { payload, .. } =
        gateway::TunnelGateway::parse(&message.payload).unwrap();

    let message = Message::parse_standard(&payload).unwrap();
    assert_eq!(message.message_type, MessageType::Garlic);
    let tunnel = pending_tunnel.try_build_tunnel(message).unwrap();

    (local_hash, tunnel, transit_managers)
}

/// Build inbound tunnel.
pub fn build_inbound_tunnel(
    fast: bool,
    num_hops: usize,
) -> (
    Bytes,
    InboundTunnel<MockRuntime>,
    Vec<TestTransitTunnelManager>,
) {
    let (hops, mut transit_managers): (
        Vec<(Bytes, StaticPublicKey)>,
        Vec<TestTransitTunnelManager>,
    ) = (0..num_hops)
        .map(|i| {
            let manager = TestTransitTunnelManager::new(if i % 2 == 0 { true } else { false });

            (
                (manager.router_hash.clone(), manager.public_key.clone()),
                manager,
            )
        })
        .unzip();

    let (local_hash, _, _, local_noise, _) = make_router(fast);
    let message_id = MessageId::from(MockRuntime::rng().next_u32());
    let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
    let (_tx, rx) = channel(64);
    let TunnelPoolBuildParameters {
        context_handle: handle,
        ..
    } = TunnelPoolBuildParameters::new(Default::default());

    let (pending_tunnel, next_router, message) =
        PendingTunnel::<_, InboundTunnel<MockRuntime>>::create_tunnel(TunnelBuildParameters {
            hops: hops.clone(),
            metrics_handle: MockRuntime::register_metrics(vec![], None),
            name: Str::from("tunnel-pool"),
            noise: local_noise,
            message_id,
            tunnel_info: TunnelInfo::Inbound {
                tunnel_id,
                router_id: local_hash.clone(),
            },
            receiver: ReceiverKind::Inbound {
                message_rx: rx,
                handle,
            },
        })
        .unwrap();

    let message = match transit_managers[0].garlic().handle_message(message).unwrap().next() {
        Some(DeliveryInstructions::Local { message }) => message,
        _ => panic!("invalid delivery instructions"),
    };

    assert_eq!(message.message_id, message_id.into());
    assert_eq!(next_router, RouterId::from(hops[0].0.to_vec()));
    assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
    assert_eq!(message.payload[1..].len() % 218, 0);

    let message = hops.iter().zip(transit_managers.iter_mut()).fold(
        message,
        |acc, ((_, _), transit_manager)| {
            let (_, message, tx) = transit_manager.handle_short_tunnel_build(acc).unwrap();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
            message
        },
    );

    let tunnel = pending_tunnel.try_build_tunnel(message).unwrap();

    (local_hash, tunnel, transit_managers)
}
