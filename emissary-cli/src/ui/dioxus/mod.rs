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
    address_book::AddressBookHandle,
    config::{AddressBookConfig, EmissaryConfig, Theme},
    ui::dioxus::{
        style::global_css,
        types::{
            AddressBook, HiddenServices, RouterState, RouterStatus, Settings, SettingsTab,
            SidebarSelection, Traffic,
        },
        util::{read_b32_address, save_router_config},
    },
};

use arboard::Clipboard;
use dioxus::prelude::*;
use emissary_core::{
    crypto::{base32_decode, base64_decode, base64_encode},
    events::{Event, EventSubscriber},
    primitives::{Destination, RouterId},
};
use tokio::sync::mpsc::Sender;

use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

mod address_book;
mod bandwidth;
mod bandwidth_monitor;
mod config;
mod dashboard;
mod hidden_services;
mod native;
mod settings;
mod sidebar;
mod style;
mod svg;
mod types;
mod util;
mod web;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ui";

/// UI kind.
enum UiKind {
    /// Native UI.
    Native {
        /// Clipboard for UI
        ///
        /// `None` if clipboard could not be initialized.
        clipboard: Option<Clipboard>,
    },

    /// Web UI.
    Web,
}

/// `App` options.
#[derive(Clone)]
struct AppOptions {
    /// Router configuration.
    config: EmissaryConfig,

    /// Router base path.
    base_path: PathBuf,

    /// Address book handle, if enabled.
    address_book_handle: Option<Arc<AddressBookHandle>>,

    /// TX channel for sending shutdown signal.
    shutdown_tx: Sender<()>,

    /// Shared router state, persisted across page refreshes.
    router_state: Arc<Mutex<RouterState>>,

    /// Shared traffic state, persisted across reconnections.
    traffic: Arc<Mutex<Traffic>>,

    /// Use the web UI.
    web_ui: bool,
}

/// Application state.
struct AppState {
    /// Address book.
    address_book: AddressBook,

    /// Address book handle, if enabled.
    address_book_handle: Option<Arc<AddressBookHandle>>,

    /// Router base path.
    base_path: PathBuf,

    /// Router configuration.
    config: EmissaryConfig,

    /// Hidden services.
    hidden_services: HiddenServices,

    /// Settings info.
    settings: Settings,

    /// Shared router state.
    router_state: Arc<Mutex<RouterState>>,

    /// TX channel for sending shutdown signal.
    shutdown_tx: Sender<()>,

    /// Has the sidebar been collapsed.
    sidebar_collapsed: bool,

    /// Router UI theme.
    theme: Theme,

    /// Toast notifications.
    toasts: VecDeque<(String, Instant)>,

    /// Traffic info, shared across reconnections.
    traffic: Arc<Mutex<Traffic>>,

    /// UI kind.
    ui: UiKind,

    /// Currently active view.
    view: SidebarSelection,

    /// Should router ID be displayed.
    show_router_id: bool,
}

impl AppState {
    /// Create new `AppState`.
    fn new(options: AppOptions) -> Self {
        let AppOptions {
            config,
            base_path,
            address_book_handle,
            shutdown_tx,
            router_state,
            traffic,
            web_ui,
        } = options;

        let ui = if !web_ui {
            match Clipboard::new() {
                Ok(clipboard) => UiKind::Native {
                    clipboard: Some(clipboard),
                },
                Err(error) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to initialize clipboard",
                    );

                    UiKind::Native { clipboard: None }
                }
            }
        } else {
            UiKind::Web
        };

        Self {
            address_book_handle,
            address_book: AddressBook::new(base_path.clone(), &config),
            base_path,
            hidden_services: HiddenServices::new(&config),
            theme: match config.router_ui {
                None => Theme::Dark,
                Some(ref config) => config.theme,
            },
            settings: Settings::new(&config),
            config,
            router_state,
            shutdown_tx,
            sidebar_collapsed: false,
            toasts: VecDeque::new(),
            traffic,
            ui,
            view: SidebarSelection::Dashboard,
            show_router_id: false,
        }
    }

    /// Is the router active.
    fn is_active(&self) -> bool {
        std::matches!(
            self.router_state.lock().expect("to succeed").status,
            RouterStatus::Active
        )
    }

    /// Get `RouterState`.
    fn router_state(&self) -> RouterState {
        self.router_state.lock().expect("to succeed").clone()
    }

    /// Get network status.
    ///
    /// Returns the network status string and a color representing that status.
    fn network_status(&self) -> (&'static str, &'static str) {
        let state = self.router_state();

        match state.status {
            RouterStatus::ShuttingDown => ("Shutting Down", "#e34234"),
            RouterStatus::Active =>
                if state.num_routers < 10 {
                    ("Connecting", "#f59e0b")
                } else {
                    let total = state.num_tunnels_built + state.num_tunnel_build_failures;
                    let rate = if total > 0 {
                        state.num_tunnels_built as f64 / total as f64
                    } else {
                        1.0
                    };

                    if rate < 0.30 {
                        ("Degraded", "#f97316")
                    } else {
                        ("Active", "#22c55e")
                    }
                },
        }
    }

    /// Advance the state of the router UI.
    ///
    /// Retain recent toasts and trigger rerenders for shared router state updates.
    fn tick(&mut self) {
        self.toasts.retain(|(_, pushed)| pushed.elapsed() < Duration::from_secs(3));
    }

    /// Save settings.
    pub fn save_settings(&mut self) -> Result<(), String> {
        match self.settings.active_tab {
            SettingsTab::Transports => {
                if !self.settings.ntcp2.enabled && !self.settings.ssu2.enabled {
                    return Err(String::from(
                        "At least one transport (NTCP2 or SSU2) must be enabled",
                    ));
                }

                self.config.ntcp2 = TryInto::<Option<crate::config::Ntcp2Config>>::try_into(
                    self.settings.ntcp2.clone(),
                )?;
                self.config.ssu2 = TryInto::<Option<crate::config::Ssu2Config>>::try_into(
                    self.settings.ssu2.clone(),
                )?;
                self.config.port_forwarding =
                    TryInto::<Option<crate::config::PortForwardingConfig>>::try_into(
                        self.settings.port_forwarding.clone(),
                    )?;
            }
            SettingsTab::Client => {
                self.config.i2cp = TryInto::<Option<crate::config::I2cpConfig>>::try_into(
                    self.settings.i2cp.clone(),
                )?;
                self.config.sam = TryInto::<Option<crate::config::SamConfig>>::try_into(
                    self.settings.sam.clone(),
                )?;
            }
            SettingsTab::Proxies => {
                self.config.http_proxy =
                    TryInto::<Option<crate::config::HttpProxyConfig>>::try_into(
                        self.settings.http_proxy.clone(),
                    )?;
                self.config.socks_proxy =
                    TryInto::<Option<crate::config::SocksProxyConfig>>::try_into(
                        self.settings.socks_proxy.clone(),
                    )?;
            }
            SettingsTab::Tunnels => {
                self.config.exploratory =
                    TryInto::<Option<crate::config::ExploratoryConfig>>::try_into(
                        self.settings.exploratory.clone(),
                    )?;
                self.config.transit = TryInto::<Option<crate::config::TransitConfig>>::try_into(
                    self.settings.transit.clone(),
                )?;
            }
            SettingsTab::Advanced => {
                self.config.floodfill = self.settings.advanced.floodfill;
                self.config.allow_local = self.settings.advanced.allow_local;
                self.config.insecure_tunnels = self.settings.advanced.insecure_tunnels;

                match &mut self.config.router_ui {
                    None => {
                        self.config.router_ui = Some(crate::config::RouterUiConfig {
                            theme: self.theme,
                            refresh_interval: 5,
                            port: None,
                            native: None,
                        });
                    }
                    Some(config) => {
                        config.theme = self.theme;
                    }
                }
            }
        }

        save_router_config(self.base_path.join("router.toml"), &self.config);
        self.settings.dirty = false;

        Ok(())
    }

    /// Save destination to address book.
    pub fn save_destination(&mut self) -> Result<(), String> {
        if !self.address_book.add_destination.hostname.ends_with(".i2p") {
            return Err(String::from("Hostname must end in .i2p"));
        }

        if self.address_book.add_destination.destination.is_empty() {
            return Err(String::from("Destination/Base32 address not specified"));
        }

        let dest = &self.address_book.add_destination.destination;
        let dest = dest.strip_prefix("http://").unwrap_or(dest);
        let dest = dest.strip_prefix("https://").unwrap_or(dest);
        let dest = dest.strip_prefix("www.").unwrap_or(dest);
        let dest = dest.strip_suffix(".b32.i2p").unwrap_or(dest);

        match base32_decode(dest) {
            Some(_) =>
                if let Some(handle) = &self.address_book_handle {
                    handle.add_base32(
                        self.address_book.add_destination.hostname.clone(),
                        dest.to_string(),
                    );
                },
            None => match base64_decode(dest) {
                Some(decoded) => match Destination::parse(&decoded) {
                    Ok(destination) =>
                        if let Some(handle) = &self.address_book_handle {
                            handle.add_base64(
                                self.address_book.add_destination.hostname.clone(),
                                destination,
                            );
                        },
                    Err(_) => return Err(String::from("Not a valid base64 destination")),
                },
                None => return Err(String::from("Not a valid base32/base64 destination")),
            },
        }

        self.address_book.add_destination.destination.clear();
        self.address_book.add_destination.hostname.clear();

        Ok(())
    }

    /// Remove host from address book.
    pub fn remove_host(&mut self, data: Arc<str>) {
        self.address_book.browse.addresses.remove(&data);

        if let Some(handle) = &self.address_book_handle {
            handle.remove(data.as_ref());
        }
    }

    /// Copy value to clipboard.
    pub fn copy_to_clipboard(&mut self, value: &str) {
        match &mut self.ui {
            UiKind::Native {
                clipboard: Some(clipboard),
            } =>
                if let Err(error) = clipboard.set_text(value.to_string()) {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to copy address to clipboard",
                    );
                },
            UiKind::Native { .. } => {}
            UiKind::Web => {
                let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
                let _ =
                    dioxus::document::eval(&format!("navigator.clipboard.writeText('{escaped}')"));
            }
        }
    }

    /// Save subscriptions to disk.
    pub fn save_subscriptions(&mut self) -> Result<(), String> {
        let is_empty = self.address_book.subscriptions.subscriptions.is_empty();
        let mut subs = self
            .address_book
            .subscriptions
            .subscriptions
            .split(',')
            .map(|s| s.trim().to_owned())
            .collect::<Vec<String>>();
        subs.dedup();

        if !is_empty
            && !subs.iter().all(|url| {
                url::Url::parse(url).ok().is_some_and(|host| {
                    host.host_str().is_some_and(|u| u.split('.').next_back() == Some("i2p"))
                })
            })
        {
            return Err(String::from(
                "All URLs are not valid I2P subscription URLs\n\nExample: http://host1.i2p/hosts.txt,http://host2.i2p/hosts.txt",
            ));
        }

        match self.config.address_book {
            None => {
                self.config.address_book = Some(AddressBookConfig {
                    default: None,
                    subscriptions: (!is_empty).then_some(subs),
                });
            }
            Some(ref mut config) => {
                config.subscriptions = (!is_empty).then_some(subs);
            }
        }

        save_router_config(self.base_path.join("router.toml"), &self.config);

        Ok(())
    }

    /// Save server tunnels.
    pub fn save_servers(&mut self) {
        self.config.server_tunnels = (!self.hidden_services.server.servers.is_empty()).then(|| {
            self.hidden_services
                .server
                .servers
                .iter()
                .map(|(name, s)| crate::config::ServerTunnelConfig {
                    name: name.clone(),
                    port: s.port.parse::<u16>().expect("valid port"),
                    destination_path: s.path.clone(),
                    i2cp: None,
                })
                .collect()
        });

        save_router_config(self.base_path.join("router.toml"), &self.config);
    }

    /// Remove server tunnel.
    pub fn remove_server(&mut self, name: &str) {
        if self.hidden_services.server.servers.remove(name).is_some() {
            self.save_servers();
        }

        self.hidden_services.server.pending_delete = None;
    }

    /// Validate new server tunnel config.
    pub fn validate_server(&mut self) -> Result<String, String> {
        if self.hidden_services.server.edit.name.is_empty() {
            return Err(String::from("Name cannot be empty"));
        }

        if self.hidden_services.server.edit.port.parse::<u16>().is_err() {
            return Err(String::from("Invalid port"));
        }

        if self.hidden_services.server.edit.path.is_empty() {
            return Err(String::from("Key path cannot be empty"));
        }

        match read_b32_address(&self.hidden_services.server.edit.path) {
            Some(address) => Ok(format!("{address}.b32.i2p")),
            None => Ok(String::from("Key file does not exist")),
        }
    }

    /// Save client tunnels.
    pub fn save_clients(&mut self) {
        self.config.client_tunnels = (!self.hidden_services.client.clients.is_empty()).then(|| {
            self.hidden_services
                .client
                .clients
                .iter()
                .map(|(name, tunnel)| crate::config::ClientTunnelConfig {
                    name: name.clone(),
                    address: Some(tunnel.address.clone()),
                    port: tunnel.port.parse::<u16>().expect("valid port"),
                    destination: tunnel.destination.clone(),
                    destination_port: Some(
                        tunnel.destination_port.parse::<u16>().expect("valid port"),
                    ),
                })
                .collect()
        });

        save_router_config(self.base_path.join("router.toml"), &self.config);
    }

    /// Remove client tunnel.
    pub fn remove_client(&mut self, name: &str) {
        if self.hidden_services.client.clients.remove(name).is_some() {
            self.save_clients();
        }

        self.hidden_services.client.pending_delete = None;
    }

    /// Validate client tunnel config.
    pub fn validate_client(&mut self) -> Result<(), String> {
        if self.hidden_services.client.edit.name.is_empty() {
            return Err(String::from("Name cannot be empty"));
        }

        if self.hidden_services.client.edit.address.is_empty() {
            return Err(String::from("Address cannot be empty"));
        }

        if self.hidden_services.client.edit.address.parse::<Ipv4Addr>().is_err() {
            return Err(String::from("Invalid local address"));
        }

        if self.hidden_services.client.edit.port.parse::<u16>().is_err() {
            return Err(String::from("Invalid local port"));
        }

        if !self.hidden_services.client.edit.destination.ends_with(".i2p") {
            return Err(String::from(
                "Destination must be a .i2p or .b32.i2p address",
            ));
        }

        if self.hidden_services.client.edit.destination_port.parse::<u16>().is_err() {
            return Err(String::from("Invalid destination port"));
        }

        Ok(())
    }

    /// Push toast notification.
    pub fn push_toast(&mut self, msg: impl Into<String>) {
        self.toasts.push_back((msg.into(), Instant::now()));

        while self.toasts.len() > 5 {
            self.toasts.pop_front();
        }
    }
}

async fn router_status_event_loop(
    mut events: EventSubscriber,
    router_state: Arc<Mutex<RouterState>>,
    traffic: Arc<Mutex<Traffic>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_uptime_secs = 0.0f64;

    loop {
        interval.tick().await;

        while let Some(event) = events.router_status() {
            match event {
                Event::RouterStatus {
                    transit,
                    transport,
                    tunnel,
                    firewall_statuses,
                    ..
                } => {
                    let uptime_secs = {
                        let mut state = router_state.lock().expect("to succeed");
                        state.num_transit_tunnels = transit.num_tunnels;
                        state.num_routers = transport.num_connected_routers;
                        state.num_tunnels_built = tunnel.num_tunnels_built;
                        state.num_tunnel_build_failures = tunnel.num_tunnel_build_failures;

                        if let Some((status, _)) = firewall_statuses.iter().find(|(_, ipv4)| *ipv4)
                        {
                            state.ipv4_status = status.clone();
                        }

                        if let Some((status, _)) = firewall_statuses.iter().find(|(_, ipv4)| !*ipv4)
                        {
                            state.ipv6_status = status.clone();
                        }

                        state.uptime.elapsed().as_secs_f64()
                    };

                    let mut traffic = traffic.lock().expect("to succeed");
                    traffic.prev_inbound_bandwidth = traffic.inbound_bandwidth;
                    traffic.prev_outbound_bandwidth = traffic.outbound_bandwidth;

                    let inbound_diff =
                        transport.inbound_bandwidth.saturating_sub(traffic.inbound_bandwidth);
                    let outbound_diff =
                        transport.outbound_bandwidth.saturating_sub(traffic.outbound_bandwidth);
                    let total_diff = inbound_diff + outbound_diff;
                    if total_diff > traffic.peak_traffic {
                        traffic.peak_traffic = total_diff;
                    }
                    traffic.inbound_bandwidth = transport.inbound_bandwidth;
                    traffic.outbound_bandwidth = transport.outbound_bandwidth;
                    traffic.total_bandwidth.update(
                        inbound_diff as f64,
                        outbound_diff as f64,
                        uptime_secs - last_uptime_secs,
                    );

                    let transit_in_diff =
                        transit.inbound_bandwidth.saturating_sub(traffic.transit_inbound_bandwidth);
                    let transit_out_diff = transit
                        .outbound_bandwidth
                        .saturating_sub(traffic.transit_outbound_bandwidth);
                    traffic.transit_inbound_bandwidth = transit.inbound_bandwidth;
                    traffic.transit_outbound_bandwidth = transit.outbound_bandwidth;
                    traffic.transit_bandwidth.update(
                        transit_in_diff as f64,
                        transit_out_diff as f64,
                        uptime_secs - last_uptime_secs,
                    );

                    last_uptime_secs = uptime_secs;
                }
                Event::ShuttingDown => {
                    router_state.lock().expect("to succeed").status = RouterStatus::ShuttingDown;
                }
                Event::ShutDown => {}
            }
        }
    }
}

#[component]
fn App() -> Element {
    let options = use_context::<Arc<Mutex<Option<AppOptions>>>>();
    let mut state = use_context_provider(move || {
        SyncSignal::new_maybe_sync(AppState::new(
            options.lock().expect("unpoisoned lock").take().expect("value to exist"),
        ))
    });
    let view = state.read().view;

    if std::matches!(state.read().ui, UiKind::Web) {
        use_future(move || async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                state.write().tick();
            }
        });
    } else {
        use_hook(|| {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    state.write().tick();
                }
            });
        });
    }

    let app_class = if state.read().theme == Theme::Dark {
        "app"
    } else {
        "app em-light"
    };

    let toasts = state.read().toasts.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>();

    rsx! {
        style { { global_css() } }
        div {
            class: app_class,
            sidebar::Sidebar { }
            div {
                class: "main-content",
                match view {
                    SidebarSelection::Dashboard => rsx! { dashboard::Dashboard {} },
                    SidebarSelection::Bandwidth => rsx! { bandwidth::BandwidthView {} },
                    SidebarSelection::AddressBook => rsx! { address_book::AddressBookView {} },
                    SidebarSelection::HiddenServices => rsx! { hidden_services::HiddenServicesView {} },
                    SidebarSelection::Settings => rsx! { settings::SettingsView {} },
                }
            }
            div {
                class: "toast-container",
                role: "status",
                aria_live: "polite",
                for msg in toasts {
                    div { class: "toast", "{msg}" }
                }
            }
        }
    }
}

/// Start the router UI.
pub async fn start(
    events: EventSubscriber,
    config: EmissaryConfig,
    base_path: PathBuf,
    address_book_handle: Option<Arc<AddressBookHandle>>,
    router_id: RouterId,
    shutdown_tx: Sender<()>,
    web_ui: bool,
) {
    let router_state = Arc::new(Mutex::new(RouterState::new(
        base64_encode(router_id.to_vec()).leak(),
        &config,
    )));
    let traffic = Arc::new(Mutex::new(Traffic::new()));

    tokio::spawn(router_status_event_loop(
        events,
        Arc::clone(&router_state),
        Arc::clone(&traffic),
    ));

    let params = AppOptions {
        config,
        base_path,
        address_book_handle,
        shutdown_tx,
        router_state,
        traffic,
        web_ui,
    };

    if web_ui {
        web::start(params).await;
    } else {
        native::start(params).await;
    }
}
