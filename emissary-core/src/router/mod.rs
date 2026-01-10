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
    config::{Config, I2cpConfig, MetricsConfig, SamConfig},
    crypto::{SigningPrivateKey, StaticPrivateKey},
    error::Error,
    events::{EventManager, EventSubscriber},
    i2cp::I2cpServer,
    netdb::NetDb,
    primitives::{RouterId, RouterInfo},
    profile::ProfileStorage,
    router::context::RouterContext,
    runtime::{AddressBook, Runtime, Storage},
    sam::SamServer,
    shutdown::ShutdownContext,
    subsystem::{SubsystemManager, SubsystemManagerContext},
    transport::{Ntcp2Transport, Ssu2Transport, TransportManager, TransportManagerBuilder},
    tunnel::{TunnelManager, TunnelManagerHandle},
};

use bytes::Bytes;
use futures::FutureExt;
use rand_core::RngCore;

use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub mod context;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::router";

/// Default network ID.
const NET_ID: u8 = 2u8;

/// How many times [`Router::shutdown()`] needs to be called until the router is shutdown
/// immediately, cancelling graceful shutdown.
const IMMEDIATE_SHUTDOWN_COUNT: usize = 2usize;

/// Profile storage backup interval.
///
/// How often is backup (stored to disk) taken of [`ProfileStorage`].
const PROFILE_STORAGE_BACKUP_INTERVAL: Duration = Duration::from_secs(15 * 60);
// const PROFILE_STORAGE_BACKUP_INTERVAL: Duration = Duration::from_secs(30);

/// Protocol address information.
#[derive(Debug, Default, Copy, Clone)]
pub struct ProtocolAddressInfo {
    /// NTCP2 port.
    pub ntcp2_port: Option<u16>,

    /// Socket address of the SAMv3 TCP listener.
    pub sam_tcp: Option<SocketAddr>,

    /// Socket address of the SAMv3 UDP socket.
    pub sam_udp: Option<SocketAddr>,

    /// SSU2 port.
    pub ssu2_port: Option<u16>,
}

/// Router builder.
#[derive(Default)]
pub struct RouterBuilder<R> {
    /// Object providing [`AddressBook`] service for [`Router`], if enabled.
    address_book: Option<Arc<dyn AddressBook>>,

    /// Router configuration.
    config: Config,

    /// Object providing storage access for [`Router`], if enabled.
    storage: Option<Arc<dyn Storage>>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> RouterBuilder<R> {
    /// Create new [`RouterBuilder`].
    pub fn new(config: Config) -> Self {
        Self {
            address_book: None,
            config,
            storage: None,
            _runtime: Default::default(),
        }
    }

    /// Provide [`AddressBook`] for [`Router`].
    pub fn with_address_book(mut self, address_book: Arc<dyn AddressBook>) -> Self {
        self.address_book = Some(address_book);
        self
    }

    /// Provide [`StorageHandle`] for [`Router`].
    pub fn with_storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Build [`Router`]
    pub async fn build(self) -> crate::Result<(Router<R>, EventSubscriber, Vec<u8>)> {
        Router::new(self.config, self.address_book, self.storage).await
    }
}

/// Router.
pub struct Router<R: Runtime> {
    /// Protocol address information.
    address_info: ProtocolAddressInfo,

    /// Event manager
    event_manager: EventManager<R>,

    /// Local router ID.
    router_id: RouterId,

    /// Shutdown context.
    shutdown_context: ShutdownContext<R>,

    /// Number of times shutdown has been requested.
    shutdown_count: usize,

    /// Transport manager
    ///
    /// Polls both NTCP2 and SSU2 transports.
    transport_manager: TransportManager<R>,

    /// Handle to [`TunnelManager`].
    _tunnel_manager_handle: TunnelManagerHandle,
}

impl<R: Runtime> Router<R> {
    /// Create new [`Router`] from `config` and pass `address_book` to [`SamServer`] and
    /// [`I2cpServer`] if address book support was enabled.
    pub async fn new(
        mut config: Config,
        address_book: Option<Arc<dyn AddressBook>>,
        storage: Option<Arc<dyn Storage>>,
    ) -> crate::Result<(Self, EventSubscriber, Vec<u8>)> {
        // attempt to initialize the ntcp2 transport from provided config
        //
        // this is done prior to constructing local router info in case ntcp2 config contained an
        // unspecified port, meaning the actual socket address of the transport is available only
        // after the listener has been created
        let (ntcp2_context, ntcp2_address) =
            Ntcp2Transport::<R>::initialize(config.ntcp2.take()).await?;

        // attempt to initialize the ssu2 transport from provided config
        let (ssu2_context, ssu2_address) =
            Ssu2Transport::<R>::initialize(config.ssu2.take()).await?;

        if ntcp2_context.is_none() && ssu2_context.is_none() {
            tracing::warn!(
                target: LOG_TARGET,
                "cannot start router, no active transport protocol",
            );
            return Err(Error::Custom("no transport".to_string()));
        }

        // create static/signing keypairs for the router
        //
        // if caller didn't supply keys, generate transient keypair
        let local_static_key = StaticPrivateKey::from(config.static_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            R::rng().fill_bytes(&mut key);
            key
        }));
        let local_signing_key = SigningPrivateKey::from(config.signing_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            R::rng().fill_bytes(&mut key);
            key
        }));

        let local_router_info = RouterInfo::new::<R>(
            &config,
            ntcp2_address,
            ssu2_address,
            &local_static_key,
            &local_signing_key,
            config.transit.is_none(),
        );
        let router_id = local_router_info.identity.id();
        let Config {
            i2cp_config,
            samv3_config,
            floodfill,
            net_id,
            exploratory,
            insecure_tunnels,
            routers,
            profiles,
            allow_local,
            metrics,
            transit,
            refresh_interval,
            ..
        } = config;

        let profile_storage = ProfileStorage::<R>::new(&routers, &profiles);
        let serialized_router_info = local_router_info.serialize(&local_signing_key);
        let local_router_id = local_router_info.identity.id();
        let mut address_info = ProtocolAddressInfo::default();

        // create router shutdown context and allocate handle `TransitTunnelManager`
        //
        // `TransitTunnelManager` can take up to 10 minutes to shut down, depending on the age
        // of the newest transit tunnel
        let mut shutdown_context = ShutdownContext::<R>::new();
        let transit_shutdown_handle = shutdown_context.handle();

        tracing::info!(
            target: LOG_TARGET,
            ?local_router_id,
            net_id = ?net_id.unwrap_or(NET_ID),
            "starting emissary",
        );

        // collect metrics from all subsystems, register them and acquire metrics handle
        //
        // if metrics are disabled, call `R::register_metrics()` with an empty vector which makes
        // the runtime not start the metrics server and return a handle which doesn't update any
        // metirics
        let metrics_handle = match metrics {
            None => R::register_metrics(Vec::new(), None),
            Some(MetricsConfig { port }) => {
                let metrics = TransportManager::<R>::metrics(Vec::new());
                let metrics = TunnelManager::<R>::metrics(metrics);
                let metrics = NetDb::<R>::metrics(metrics);
                #[cfg(feature = "events")]
                let metrics = EventManager::<R>::metrics(metrics);

                R::register_metrics(metrics, Some(port))
            }
        };

        // initialize the event system
        let (event_manager, event_subscriber, event_handle) = EventManager::<R>::new(
            refresh_interval.and_then(|refresh_interval| {
                if refresh_interval == 0 {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "invalid refresh interval, using default value"
                    );
                    return None;
                }

                Some(Duration::from_secs(refresh_interval as u64))
            }),
            #[cfg(feature = "events")]
            metrics_handle.clone(),
        );

        // create router context that is passed onto other subsystems and contains a collection
        // of common objects utilized by all of the subsystems
        let router_ctx = RouterContext::new(
            metrics_handle.clone(),
            profile_storage.clone(),
            local_router_id.clone(),
            Bytes::from(serialized_router_info.clone()),
            local_static_key.clone(),
            local_signing_key.clone(),
            net_id.unwrap_or(NET_ID),
            event_handle,
        );
        let sam_event_handle = router_ctx.event_handle().clone();

        // create subsystem manager
        let SubsystemManagerContext {
            netdb_rx,
            manager,
            handle,
            transit_rx,
            transport_tx,
            dial_rx,
        } = SubsystemManager::<R>::new(
            100,
            0.,
            router_ctx.router_id().clone(),
            router_ctx.noise().clone(),
        );

        // spawn subsystem manager in the background
        R::spawn(manager);

        // create transport manager builder and initialize & start enabled transports
        //
        // note: order of initialization is important
        let mut transport_manager_builder = TransportManagerBuilder::new(
            router_ctx.clone(),
            local_router_info,
            allow_local,
            dial_rx,
            transport_tx,
        );

        // specify if transit tunnels are disabled
        //
        // if they are, the router will always publish an RI with `G` flag
        transport_manager_builder.with_transit_tunnels_disabled(transit.is_none());

        // initialize and start tunnel manager
        //
        // acquire handle to exploratory tunnel pool which is given to `NetDb`
        let (tunnel_manager_handle, exploratory_pool_handle) = {
            let (tunnel_manager, tunnel_manager_handle, tunnel_pool_handle) =
                TunnelManager::<R>::new(
                    router_ctx.clone(),
                    exploratory.into(),
                    insecure_tunnels,
                    transit,
                    transit_shutdown_handle,
                    handle.clone(),
                    transit_rx,
                );
            R::spawn(tunnel_manager);

            (tunnel_manager_handle, tunnel_pool_handle)
        };

        // initialize and start netdb
        let netdb_handle = {
            let (netdb, netdb_handle) = NetDb::<R>::new(
                router_ctx,
                floodfill,
                exploratory_pool_handle,
                netdb_rx,
                handle,
            );
            R::spawn(netdb);

            netdb_handle
        };

        // pass netdb handle to transport manager builder
        //
        // transport manager uses netdb to query remote router infos and periodically publish local
        // router info when, e.g., it goes stale or a new external address is discovered
        transport_manager_builder.register_netdb_handle(netdb_handle.clone());

        // initialize i2cp server if it was enabled
        if let Some(I2cpConfig { host, port }) = i2cp_config {
            let i2cp_server = I2cpServer::<R>::new(
                host,
                port,
                netdb_handle.clone(),
                tunnel_manager_handle.clone(),
                address_book.clone(),
                profile_storage.clone(),
            )
            .await?;

            R::spawn(i2cp_server);
        }

        if let Some(SamConfig {
            tcp_port,
            udp_port,
            host,
        }) = samv3_config
        {
            let sam_server = SamServer::<R>::new(
                tcp_port,
                udp_port,
                host,
                netdb_handle.clone(),
                tunnel_manager_handle.clone(),
                metrics_handle,
                address_book,
                sam_event_handle,
                profile_storage.clone(),
            )
            .await?;

            address_info.sam_tcp = sam_server.tcp_local_address();
            address_info.sam_udp = sam_server.udp_local_address();

            R::spawn(sam_server)
        }

        // start profile storage task in the background if it was enabled
        //
        // all this task does is periodically backup router infos and profiles to disk
        if let Some(storage) = storage {
            R::spawn(async move {
                loop {
                    let _ = R::delay(PROFILE_STORAGE_BACKUP_INTERVAL).await;

                    let routers = profile_storage.backup();

                    if !routers.is_empty() {
                        tracing::info!(
                            target: LOG_TARGET,
                            num_routers = ?routers.len(),
                            "taking backup of profile storage",
                        );

                        storage.save_to_disk(routers);
                    }
                }
            });
        }

        if let Some(context) = ntcp2_context {
            address_info.ntcp2_port = Some(context.port());
            transport_manager_builder.register_ntcp2(context);
        }

        if let Some(context) = ssu2_context {
            address_info.ssu2_port = Some(context.port());
            transport_manager_builder.register_ssu2(context);
        }

        Ok((
            Self {
                address_info,
                event_manager,
                router_id,
                shutdown_context,
                shutdown_count: 0usize,
                transport_manager: transport_manager_builder.build(),
                _tunnel_manager_handle: tunnel_manager_handle,
            },
            event_subscriber,
            serialized_router_info,
        ))
    }

    /// Shut down the router.
    ///
    /// The first request to shutdown the router starts a graceful shutdown and TOOD
    pub fn shutdown(&mut self) {
        self.shutdown_count += 1;

        if self.shutdown_count == 1 {
            tracing::info!(
                target: LOG_TARGET,
                "starting graceful shutdown",
            );

            self.shutdown_context.shutdown();
            self.transport_manager.shutdown();
            self.event_manager.shutdown();
        } else {
            tracing::info!(
                target: LOG_TARGET,
                "shutting down router",
            );
        }
    }

    /// Get reference to [`ProtocolAddressInfo`].
    pub fn protocol_address_info(&self) -> &ProtocolAddressInfo {
        &self.address_info
    }

    /// Get local router ID.
    pub fn router_id(&self) -> &RouterId {
        &self.router_id
    }

    /// Add external address for [`Router`].
    ///
    /// This address will be added to the [`RouterInfo`] that is published in `NetDb`. If the user
    /// specified an address manually in the router configuration, `address` is ignored.
    ///
    /// If `address` differs from the address that was specified the router configuration,
    /// a warning is logged.
    pub fn add_external_address(&mut self, address: Ipv4Addr) {
        self.transport_manager.add_external_address(address);
    }
}

impl<R: Runtime> Future for Router<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.shutdown_count >= IMMEDIATE_SHUTDOWN_COUNT {
            return Poll::Ready(());
        }

        if self.shutdown_context.poll_unpin(cx).is_ready() {
            return Poll::Ready(());
        }

        if self.event_manager.poll_unpin(cx).is_ready() {
            tracing::warn!(
                target: LOG_TARGET,
                "event manager crashed",
            );
            return Poll::Ready(());
        }

        match self.transport_manager.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(()) => return Poll::Ready(()),
        }

        Poll::Pending
    }
}
