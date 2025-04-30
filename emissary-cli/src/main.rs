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

#![allow(clippy::crate_in_macro_def)]
#![allow(clippy::too_many_arguments)]

use crate::{
    address_book::AddressBookManager,
    cli::Arguments,
    config::{Config, ReseedConfig, RouterUiConfig},
    error::Error,
    port_mapper::PortMapper,
    proxy::http::HttpProxy,
    signal::SignalHandler,
    storage::RouterStorage,
    tunnel::{client::ClientTunnelManager, server::ServerTunnelManager},
};

use anyhow::anyhow;
use clap::Parser;
use emissary_core::{events::EventSubscriber, router::Router};
use emissary_util::{reseeder::Reseeder, runtime::tokio::Runtime, su3::ReseedRouterInfo};
use futures::{channel::oneshot, StreamExt};
use tokio::sync::mpsc::{channel, Receiver};

use std::{fs::File, io::Write, mem, sync::Arc};

mod address_book;
mod cli;
mod config;
mod error;
mod logger;
mod port_mapper;
mod proxy;
mod signal;
mod storage;
mod tunnel;
mod ui;

#[cfg(all(feature = "native-ui", feature = "web-ui"))]
compile_error!("native and web ui cannot be enabled at the same time");

/// Logging target for the file.
const LOG_TARGET: &str = "emissary";

/// Result type for the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Router context.
struct RouterContext {
    /// Router.
    router: Router<Runtime>,

    /// Event subscriber.
    ///
    /// Passed onto a router UI if it has been enabled.
    #[allow(unused)]
    events: EventSubscriber,

    /// Port mapper for NAT-PMP and UPnP.
    port_mapper: PortMapper,

    /// Signal handler for `SIGINT`.
    signal_handler: SignalHandler,

    /// Router UI config, if enabled.
    #[allow(unused)]
    router_ui_config: Option<RouterUiConfig>,
}

/// Setup router and related subsystems.
async fn setup_router() -> anyhow::Result<RouterContext> {
    let arguments = Arguments::parse();
    let signal_handler = SignalHandler::new();

    // initialize logger with any logging directive given as a cli argument
    let handle = init_logger!(arguments.log.clone());

    // parse router config and merge it with cli options
    let mut config = Config::parse(arguments.base_path.clone(), &arguments).map_err(|error| {
        tracing::warn!(
            target: LOG_TARGET,
            ?error,
            "invalid router config, pass `--overwrite-config` to create new config",
        );

        error
    })?;
    let storage = RouterStorage::new(config.base_path.clone());

    // reinitialize the logger with any directives given in the configuration file
    init_logger!(config.log.clone(), handle);

    // is the # of known routers less than reseed threshold or is reseed forced
    let should_reseed = config.reseed.as_ref().is_some_and(
        |ReseedConfig {
             reseed_threshold, ..
         }| reseed_threshold > &config.routers.len(),
    ) || arguments.reseed.force_reseed.unwrap_or(false);

    if should_reseed {
        tracing::info!(
            target: LOG_TARGET,
            num_routers = ?config.routers.len(),
            forced_reseed = ?arguments.reseed.force_reseed.unwrap_or(false),
            force_ipv4 = ?(!arguments.reseed.disable_force_ipv4.unwrap_or(false)),
            "reseed router"
        );

        match Reseeder::reseed(
            config.reseed.as_ref().and_then(|config| config.hosts.clone()),
            !arguments.reseed.disable_force_ipv4.unwrap_or(false),
        )
        .await
        {
            Ok(routers) => {
                tracing::info!(
                    target: LOG_TARGET,
                    num_routers = ?routers.len(),
                    "router reseeded",
                );

                routers.into_iter().for_each(|ReseedRouterInfo { name, router_info }| {
                    match name.strip_prefix("routerInfo-") {
                        Some(start) => {
                            if let Err(error) =
                                storage.store_router_info(start.to_string(), router_info.clone())
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "failed to store router info to disk",
                                );
                            }
                        }
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            ?name,
                            "malformed router info name, cannot store on disk",
                        ),
                    }

                    config.routers.push(router_info);
                });
            }
            Err(error) if config.routers.is_empty() => {
                tracing::error!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to reseed and no routers available",
                );
                return Err(anyhow!("no routers available"));
            }
            Err(error) => tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to reseed, trying to start router anyway",
            ),
        }
    }

    let path = config.base_path.clone();
    let http = config.http_proxy.take();
    let port_forwarding = config.port_forwarding.take();
    let client_tunnels = mem::take(&mut config.client_tunnels);
    let server_tunnels = mem::take(&mut config.server_tunnels);
    let router_ui_config = config.router_ui.clone();

    let (router, events, local_router_info, address_book_manager) =
        match config.address_book.take() {
            None => Router::<Runtime>::new(config.into(), None, Some(Arc::new(storage)))
                .await
                .map(|(router, event_subscriber, info)| (router, event_subscriber, info, None)),

            Some(address_book_config) => {
                // create address book, allocate address book handle and pass it to `Router`
                let address_book_manager =
                    AddressBookManager::new(config.base_path.clone(), address_book_config);
                let address_book_handle = address_book_manager.handle();

                Router::<Runtime>::new(
                    config.into(),
                    Some(address_book_handle),
                    Some(Arc::new(storage)),
                )
                .await
                .map(|(router, event_subscriber, info)| {
                    (router, event_subscriber, info, Some(address_book_manager))
                })
            }
        }
        .map_err(|error| anyhow!(error))?;

    // save newest router info to disk
    File::create(path.join("router.info"))?.write_all(&local_router_info)?;

    // if sam was enabled, start all enabled proxies, client tunnels and the address book
    if let Some(address) = router.protocol_address_info().sam_tcp {
        // start http proxy if it was enabled
        if let Some(config) = http {
            // start event loop of address book manager if address book was enabled
            //
            // address book depends on the http proxy as it downloads hosts.txt from inside i2p
            //
            // if address book is enabled, create oneshot channel pair, pass the receiver to address
            // book and sender to http proxy and once the http proxy is ready (its tunnel pool has
            // been built), it'll signal the address book that it can start download hosts file(s)
            let http_proxy_ready_tx = address_book_manager.map(|address_book_manager| {
                let (tx, rx) = oneshot::channel();
                tokio::spawn(address_book_manager.run(config.port, config.host.clone(), rx));

                tx
            });

            // start event loop of http proxy
            tokio::spawn(async move {
                match HttpProxy::new(config, address.port(), http_proxy_ready_tx).await {
                    Ok(proxy) => {
                        tokio::spawn(async move {
                            if let Err(error) = proxy.run().await {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "http proxy exited",
                                );
                            }
                        });
                    }
                    Err(error) => tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to start http proxy",
                    ),
                }
            });
        }

        // start client and server tunnels
        tokio::spawn(ClientTunnelManager::new(client_tunnels, address.port()).run());
        tokio::spawn(
            ServerTunnelManager::new(server_tunnels, address.port(), path.clone())
                .await
                .run(),
        );
    }

    // create port mapper from config and transport protocol info
    //
    // `PortMapper` can be polled for external address discoveries
    let port_mapper = PortMapper::new(
        port_forwarding,
        router.protocol_address_info().ntcp2_port,
        router.protocol_address_info().ssu2_port,
    );

    Ok(RouterContext {
        router,
        events,
        port_mapper,
        signal_handler,
        router_ui_config,
    })
}

/// Run the event loop of `emissary-cli`
///
/// Start a loop which polls:
///  * `SIGINT` signal handler
///  * `Router`'s event loop
///  * [`PortMapper`]'s event loop
///  * RX channel for receiving a shutdown signal from router UI
async fn router_event_loop(
    mut router: Router<Runtime>,
    mut port_mapper: PortMapper,
    mut handler: SignalHandler,
    mut shutdown_rx: Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = handler.next() => {
                port_mapper.shutdown().await;
                router.shutdown();
            }
            _ = shutdown_rx.recv() => {
                port_mapper.shutdown().await;
                router.shutdown();
            }
            address = port_mapper.next() => {
                // the value must exist since the stream never terminates
                router.add_external_address(address.expect("value"));
            },
            _ = &mut router => {
                tracing::info!(
                    target: LOG_TARGET,
                    "emissary shut down",
                );
                break;
            }
        }
    }
}

#[cfg(not(any(feature = "native-ui", feature = "web-ui")))]
fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (_tx, shutdown_rx) = channel(1);
    let RouterContext {
        port_mapper,
        router,
        signal_handler,
        ..
    } = runtime.block_on(setup_router())?;

    runtime.block_on(router_event_loop(
        router,
        port_mapper,
        signal_handler,
        shutdown_rx,
    ));

    Ok(())
}

#[cfg(feature = "web-ui")]
fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (shutdown_tx, shutdown_rx) = channel(1);
    let RouterContext {
        events,
        port_mapper,
        router,
        router_ui_config,
        signal_handler,
        ..
    } = runtime.block_on(setup_router())?;

    match router_ui_config {
        None => {
            runtime.block_on(router_event_loop(
                router,
                port_mapper,
                signal_handler,
                shutdown_rx,
            ));
        }
        Some(RouterUiConfig {
            refresh_interval,
            port,
            ..
        }) => {
            runtime.spawn(async move {
                ui::web::RouterUi::new(events, port, refresh_interval, shutdown_tx).run().await;
            });
            runtime.block_on(router_event_loop(
                router,
                port_mapper,
                signal_handler,
                shutdown_rx,
            ));
        }
    }

    Ok(())
}

#[cfg(feature = "native-ui")]
fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (shutdown_tx, shutdown_rx) = channel(1);
    let RouterContext {
        router,
        port_mapper,
        signal_handler,
        events,
        router_ui_config,
    } = runtime.block_on(setup_router())?;

    match router_ui_config {
        None => {
            runtime.block_on(router_event_loop(
                router,
                port_mapper,
                signal_handler,
                shutdown_rx,
            ));

            Ok(())
        }
        Some(RouterUiConfig {
            theme,
            refresh_interval,
            ..
        }) => {
            std::thread::spawn(move || {
                runtime.block_on(router_event_loop(
                    router,
                    port_mapper,
                    signal_handler,
                    shutdown_rx,
                ));
                std::process::exit(0);
            });

            ui::native::RouterUi::start(events, theme, refresh_interval, shutdown_tx)
        }
    }
}
