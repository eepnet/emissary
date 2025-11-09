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
    config::EmissaryConfig as Config,
    ui::{
        native::{
            bandwidth_monitor::BandwidthMonitor,
            config::{load_addresses, save_router_config},
            hidden_services::{ClientTunnel, HiddenService},
            settings::{
                advanced::AdvancedConfig,
                client::{I2cpConfig, SamConfig},
                proxies::{HttpProxyConfig, SocksProxyConfig},
                transports::{PortForwardingConfig, TransportConfig},
                tunnels::{ExploratoryConfig, TransitConfig},
            },
            sidebar::sidebar,
            types::{
                AddDestinationStatus, AddressBookTab, HiddenServiceStatus, Message, SettingsStatus,
                SettingsTab, SidebarMessage, SubscriptionStatus, Tab, TimeRange,
            },
            utils::read_b32_address,
        },
        Status,
    },
};

use emissary_core::events::{Event, EventSubscriber};
use iced::{
    advanced::widget::Text,
    alignment::Vertical,
    border::Radius,
    time,
    widget::{canvas::Cache, container, row, svg, Column, Container, Row},
    Alignment, Background, Border, Color, Element,
    Length::{self, FillPortion},
    Subscription, Task, Theme,
};
use tokio::sync::mpsc::Sender;

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

mod address_book;
mod bandwidth;
mod bandwidth_monitor;
mod config;
mod dashboard;
mod graph;
mod hidden_services;
mod network_status;
mod settings;
mod sidebar;
mod svg_util;
mod types;
mod utils;

pub struct RouterUi {
    events: EventSubscriber,
    inbound_bandwidth: usize,

    /// Router config.
    config: Config,

    /// NTCP2 config.
    ntcp2: TransportConfig,

    /// SSU2 config.
    ssu2: TransportConfig,

    /// Port forwarding config.
    port_forwarding: PortForwardingConfig,

    /// I2CP config.
    i2cp: I2cpConfig,

    /// SAM config.
    sam: SamConfig,

    /// HTTP proxy config.
    http_proxy: HttpProxyConfig,

    /// SOCKS proxy config.
    socks_proxy: SocksProxyConfig,

    /// Uptime
    uptime: Instant,

    /// Exploratory tunnel pool config.
    exploratory: ExploratoryConfig,

    /// Transit tunnel config.
    transit: TransitConfig,

    /// Advanced config.
    advanced: AdvancedConfig,

    /// Hidden services.
    hidden_services: BTreeMap<String, HiddenService>,

    /// Client tunnels.
    client_tunnels: BTreeMap<String, ClientTunnel>,

    cache: Cache,
    outbound_bandwidth: usize,
    transit_inbound_bandwidth: usize,
    transit_outbound_bandwidth: usize,
    num_transit_tunnels: usize,
    peak_traffic: usize,
    num_routers: usize,
    num_tunnels_built: usize,
    num_tunnel_build_failures: usize,
    view: SidebarMessage,
    light_mode: bool,
    show_router_id: bool,
    show_inbound: bool,
    show_outbound: bool,
    active_settings_tab: SettingsTab,
    active_address_book_tab: AddressBookTab,
    hostname: String,
    destination: String,
    settings_status: SettingsStatus,
    status: Status,
    service_status: HiddenServiceStatus,
    add_destination_status: AddDestinationStatus,
    subscription_status: SubscriptionStatus,
    subscriptions: String,
    addresses: BTreeMap<Arc<str>, Arc<str>>,
    search_term: String,
    selected_range: TimeRange,
    transit_only_bandwidth: bool,
    total_bandwidth: BandwidthMonitor,
    transit_bandwidth: BandwidthMonitor,
    server_name: String,
    server_port: String,
    server_path: String,

    // TODO:refctor
    edit_server_name: String,
    edit_server_original_name: String,
    edit_server_port: String,
    edit_server_path: String,

    // TODO refactor
    client_name: String,
    client_address: String,
    client_port: String,
    client_destination: String,
    client_destination_port: String,

    // TODO: refactor
    edit_client_name: String,
    edit_client_original_name: String,
    edit_client_address: String,
    edit_client_port: String,
    edit_client_destination: String,
    edit_client_destination_port: String,
    shutdown_tx: Sender<()>,
    base_path: PathBuf,
    address_book_handle: Option<Arc<AddressBookHandle>>,
}

impl RouterUi {
    fn new(
        events: EventSubscriber,
        config: Config,
        base_path: PathBuf,
        address_book_handle: Option<Arc<AddressBookHandle>>,
        shutdown_tx: Sender<()>,
    ) -> (Self, Task<Message>) {
        let ntcp2 = TransportConfig::from(&config.ntcp2);
        let ssu2 = TransportConfig::from(&config.ssu2);
        let port_forwarding = PortForwardingConfig::from(&config.port_forwarding);
        let i2cp = I2cpConfig::from(&config.i2cp);
        let sam = SamConfig::from(&config.sam);
        let http_proxy = HttpProxyConfig::from(&config.http_proxy);
        let socks_proxy = SocksProxyConfig::from(&config.socks_proxy);
        let exploratory = ExploratoryConfig::from(&config.exploratory);
        let transit = TransitConfig::from(&config.transit);
        let advanced = AdvancedConfig::from(&config);
        let subscriptions = config.address_book.as_ref().map_or_else(String::new, |address_book| {
            let Some(subscriptions) = &address_book.subscriptions else {
                return String::new();
            };

            subscriptions.iter().fold("".to_string(), |acc, line| {
                if acc.is_empty() {
                    line.to_string()
                } else {
                    format!("{acc},{line}")
                }
            })
        });

        let hidden_services =
            config.server_tunnels.as_ref().map_or_else(BTreeMap::default, |services| {
                services
                    .iter()
                    .map(|service| {
                        let address = read_b32_address(&service.destination_path)
                            .map(|address| format!("{address}.b32.i2p"))
                            .unwrap_or(String::from("Key file does not exist"));

                        (
                            service.name.clone(),
                            HiddenService {
                                port: service.port.to_string(),
                                path: service.destination_path.clone(),
                                address,
                            },
                        )
                    })
                    .collect()
            });

        let client_tunnels =
            config.client_tunnels.as_ref().map_or_else(BTreeMap::default, |tunnels| {
                tunnels
                    .iter()
                    .map(|tunnel| {
                        (
                            tunnel.name.clone(),
                            ClientTunnel {
                                address: tunnel
                                    .address
                                    .clone()
                                    .unwrap_or(String::from("127.0.0.1")),
                                port: tunnel.port.to_string(),
                                destination: tunnel.destination.clone(),
                                destination_port: tunnel
                                    .destination_port
                                    .map_or_else(|| String::from("80"), |port| port.to_string()),
                            },
                        )
                    })
                    .collect()
            });
        let addresses = load_addresses(base_path.join("addressbook/addresses").clone());

        let (test, test1) = (
            RouterUi {
                base_path,
                address_book_handle,
                shutdown_tx,
                search_term: String::new(),
                total_bandwidth: BandwidthMonitor::new(),
                transit_bandwidth: BandwidthMonitor::new(),
                hidden_services,
                client_tunnels,
                transit_only_bandwidth: false,
                addresses,
                subscriptions,
                uptime: Instant::now(),
                cache: Cache::new(),
                active_settings_tab: SettingsTab::Transports,
                active_address_book_tab: AddressBookTab::Browse,
                inbound_bandwidth: 0usize,
                num_routers: 0usize,
                status: Status::Active,
                config,
                ntcp2,
                ssu2,
                port_forwarding,
                i2cp,
                sam,
                server_name: String::from(""),
                server_port: String::from(""),
                server_path: String::from(""),
                edit_server_original_name: String::from(""),
                edit_server_name: String::from(""),
                edit_server_port: String::from(""),
                edit_server_path: String::from(""),
                client_name: String::from(""),
                client_address: String::from(""),
                client_port: String::from(""),
                client_destination: String::from(""),
                client_destination_port: String::from(""),
                edit_client_name: String::from(""),
                edit_client_original_name: String::from(""),
                edit_client_address: String::from(""),
                edit_client_port: String::from(""),
                edit_client_destination: String::from(""),
                edit_client_destination_port: String::from(""),
                http_proxy,
                socks_proxy,
                exploratory,
                transit,
                advanced,
                num_transit_tunnels: 0usize,
                outbound_bandwidth: 0usize,
                light_mode: false,
                events,
                transit_inbound_bandwidth: 0usize,
                transit_outbound_bandwidth: 0usize,
                num_tunnels_built: 0usize,
                peak_traffic: 0usize,
                num_tunnel_build_failures: 0usize,
                selected_range: TimeRange::Live,
                view: SidebarMessage::Dashboard,
                show_router_id: false,
                show_inbound: true,
                show_outbound: true,
                settings_status: SettingsStatus::Idle(SettingsTab::Transports),
                add_destination_status: AddDestinationStatus::Idle,
                subscription_status: SubscriptionStatus::Idle,
                service_status: HiddenServiceStatus::Idle,
                hostname: String::from(""),
                destination: String::from(""),
            },
            Task::none(),
        );

        (test, test1)
    }

    pub fn start(
        events: EventSubscriber,
        config: Config,
        base_path: PathBuf,
        address_book_handle: Option<Arc<AddressBookHandle>>,
        shutdown_tx: Sender<()>,
    ) -> anyhow::Result<()> {
        iced::application("emissary", RouterUi::update, RouterUi::view)
            .subscription(RouterUi::subscription)
            .theme(RouterUi::theme)
            .run_with(move || {
                RouterUi::new(events, config, base_path, address_book_handle, shutdown_tx)
            })
            .map_err(From::from)
    }

    fn save_settings(&mut self) -> Result<(), String> {
        match self.active_settings_tab {
            SettingsTab::Transports => {
                if !self.ntcp2.enabled() && !self.ssu2.enabled() {
                    return Err(String::from("One transport must be enabled"));
                }

                self.config.ntcp2 =
                    TryInto::<Option<crate::config::Ntcp2Config>>::try_into(self.ntcp2.clone())?;

                self.config.ssu2 =
                    TryInto::<Option<crate::config::Ssu2Config>>::try_into(self.ssu2.clone())?;

                self.config.port_forwarding =
                    TryInto::<Option<crate::config::PortForwardingConfig>>::try_into(
                        self.port_forwarding.clone(),
                    )?;
            }
            SettingsTab::Client => {
                self.config.i2cp =
                    TryInto::<Option<crate::config::I2cpConfig>>::try_into(self.i2cp.clone())?;

                self.config.sam =
                    TryInto::<Option<crate::config::SamConfig>>::try_into(self.sam.clone())?;
            }
            SettingsTab::Proxies => {
                self.config.http_proxy =
                    TryInto::<Option<crate::config::HttpProxyConfig>>::try_into(
                        self.http_proxy.clone(),
                    )?;

                self.config.socks_proxy =
                    TryInto::<Option<crate::config::SocksProxyConfig>>::try_into(
                        self.socks_proxy.clone(),
                    )?;
            }
            SettingsTab::Tunnels => {
                self.config.exploratory =
                    TryInto::<Option<crate::config::ExploratoryConfig>>::try_into(
                        self.exploratory.clone(),
                    )?;

                self.config.transit = TryInto::<Option<crate::config::TransitConfig>>::try_into(
                    self.transit.clone(),
                )?;
            }
            SettingsTab::Advanced => {
                self.config.allow_local = self.advanced.allow_local();
                self.config.insecure_tunnels = self.advanced.insecure_tunnels();
                self.config.floodfill = self.advanced.floodfill();
            }
        }

        save_router_config(self.base_path.join("router.toml"), &self.config);

        Ok(())
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                while let Some(event) = self.events.router_status() {
                    match event {
                        Event::RouterStatus {
                            transit,
                            transport,
                            tunnel,
                            ..
                        } => {
                            self.num_transit_tunnels = transit.num_tunnels;
                            self.num_routers = transport.num_connected_routers;
                            self.num_tunnels_built = tunnel.num_tunnels_built;
                            self.num_tunnel_build_failures = tunnel.num_tunnel_build_failures;

                            // calculate total bandwidth usage
                            {
                                let inbound_diff = transport
                                    .inbound_bandwidth
                                    .saturating_sub(self.inbound_bandwidth);
                                let outbound_diff = transport
                                    .outbound_bandwidth
                                    .saturating_sub(self.outbound_bandwidth);

                                // update peak traffic if needed
                                let total_diff = inbound_diff + outbound_diff;
                                if total_diff > self.peak_traffic {
                                    self.peak_traffic = total_diff;
                                }

                                self.inbound_bandwidth = transport.inbound_bandwidth;
                                self.outbound_bandwidth = transport.outbound_bandwidth;
                                self.total_bandwidth
                                    .update(inbound_diff as f64, outbound_diff as f64);
                            }

                            // calculate transit tunnel bandwidth usage
                            {
                                let inbound_diff = transit
                                    .inbound_bandwidth
                                    .saturating_sub(self.transit_inbound_bandwidth);
                                let outbound_diff = transit
                                    .outbound_bandwidth
                                    .saturating_sub(self.transit_outbound_bandwidth);

                                self.transit_inbound_bandwidth = transit.inbound_bandwidth;
                                self.transit_outbound_bandwidth = transit.outbound_bandwidth;
                                self.transit_bandwidth
                                    .update(inbound_diff as f64, outbound_diff as f64);
                            }

                            self.cache.clear();
                        }
                        Event::ShuttingDown =>
                            if let Status::Active = self.status {
                                self.status = Status::ShuttingDown(Instant::now());
                            },
                        Event::ShutDown => {}
                    }
                }

                Task::none()
            }
            Message::TabSelected(tab) => match tab {
                Tab::Settings(tab) => {
                    if self.settings_status.tab() != &tab {
                        self.settings_status = SettingsStatus::Idle(tab);
                    }
                    self.active_settings_tab = tab;

                    Task::none()
                }
                Tab::AddressBook(tab) => {
                    if !std::matches!(tab, AddressBookTab::AddDestination) {
                        self.add_destination_status = AddDestinationStatus::Idle;
                    }
                    self.active_address_book_tab = tab;

                    Task::none()
                }
            },
            Message::ButtonPressed(view) => {
                if !std::matches!(view, SidebarMessage::Settings) {
                    self.settings_status = SettingsStatus::Idle(self.active_settings_tab);
                }

                if !std::matches!(view, SidebarMessage::AddressBook) {
                    self.add_destination_status = AddDestinationStatus::Idle;
                }

                if !std::matches!(view, SidebarMessage::HiddenServices) {
                    self.service_status = HiddenServiceStatus::Idle;
                    self.server_name.clear();
                    self.server_port.clear();
                    self.server_path.clear();
                    self.client_name.clear();
                    self.client_address.clear();
                    self.client_port.clear();
                    self.client_destination.clear();
                    self.client_destination_port.clear();
                }

                self.view = view;

                Task::none()
            }
            Message::ShowRouterId => {
                self.show_router_id = !self.show_router_id;

                Task::none()
            }
            Message::ToggleInbound => {
                self.show_outbound = !self.show_outbound;
                self.cache.clear();

                Task::none()
            }
            Message::ToggleOutbound => {
                self.show_inbound = !self.show_inbound;
                self.cache.clear();

                Task::none()
            }
            Message::Ntcp2PortChanged(data) => {
                self.ntcp2.set_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ntcp2HostChanged(data) => {
                self.ntcp2.set_host(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ntcp2Published(published) => {
                self.ntcp2.set_published(published);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ntcp2Enabled(enabled) => {
                self.ntcp2.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ssu2PortChanged(data) => {
                self.ssu2.set_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ssu2HostChanged(data) => {
                self.ssu2.set_host(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ssu2Published(published) => {
                self.ssu2.set_published(published);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::Ssu2Enabled(enabled) => {
                self.ssu2.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::NatPmpEnabled(enabled) => {
                self.port_forwarding.nat_pmp = enabled;
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::UpnpEnabled(enabled) => {
                self.port_forwarding.upnp = enabled;
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::I2cpPortChanged(data) => {
                self.i2cp.set_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::I2cpHostChanged(data) => {
                self.i2cp.set_host(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::I2cpEnabled(enabled) => {
                self.i2cp.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::HostnameChanged(data) => {
                self.hostname = data;

                Task::none()
            }
            Message::DestinationChanged(data) => {
                self.destination = data;
                self.add_destination_status = AddDestinationStatus::Idle;
                self.handle_destination_changed();

                Task::none()
            }
            Message::SaveSettings => match self.save_settings() {
                Err(error) => {
                    self.settings_status = SettingsStatus::Error(self.active_settings_tab, error);
                    Task::none()
                }
                Ok(()) => {
                    self.settings_status = SettingsStatus::Saved(self.active_settings_tab);
                    Task::none()
                }
            },
            Message::SaveDestination => match self.save_destination() {
                Err(error) => {
                    self.add_destination_status = AddDestinationStatus::Error(error);
                    Task::none()
                }
                Ok(()) => {
                    self.add_destination_status = AddDestinationStatus::Saved;
                    Task::none()
                }
            },
            Message::SamTcpPortChanged(data) => {
                self.sam.set_tcp_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SamUdpPortChanged(data) => {
                self.sam.set_udp_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SamHostChanged(data) => {
                self.sam.set_host(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SamEnabled(enabled) => {
                self.sam.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::HttpPortChanged(data) => {
                self.http_proxy.set_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::HttpHostChanged(data) => {
                self.http_proxy.set_host(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::OutproxyChanged(data) => {
                self.http_proxy.set_outproxy(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::HttpEnabled(enabled) => {
                self.http_proxy.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::TransitTunnelCountChanged(data) => {
                self.transit.set_max_tunnels(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::TransitTunnelsEnabled(enabled) => {
                self.transit.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::FloodfillEnabled(enabled) => {
                self.advanced.set_floodfill(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::LocalAddressesEnabled(enabled) => {
                self.advanced.set_allow_local(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::InsecureTunnelsEnabled(enabled) => {
                self.advanced.set_insecure_tunnels(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::ExploratoryInboundLengthChanged(data) => {
                self.exploratory.set_inbound_len(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::ExploratoryInboundCountChanged(data) => {
                self.exploratory.set_inbound_count(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::ExploratoryOutboundLengthChanged(data) => {
                self.exploratory.set_outbound_len(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::ExploratoryOutboundCountChanged(data) => {
                self.exploratory.set_outbound_count(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SocksPortChanged(data) => {
                self.socks_proxy.set_port(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SocksHostChanged(data) => {
                self.socks_proxy.set_host(data);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SocksEnabled(enabled) => {
                self.socks_proxy.set_enabled(enabled);
                self.settings_status = SettingsStatus::Idle(self.active_settings_tab);

                Task::none()
            }
            Message::SubscriptionsChanged(data) => {
                self.subscriptions = data;
                Task::none()
            }
            Message::SaveSubscriptions => match self.save_subscriptions() {
                Err(error) => {
                    self.subscription_status = SubscriptionStatus::Error(error);
                    Task::none()
                }
                Ok(()) => {
                    self.subscription_status = SubscriptionStatus::Saved;
                    Task::none()
                }
            },
            Message::SearchChanged(data) => {
                self.search_term = data;
                Task::none()
            }
            Message::RemoveHost(data) => {
                self.remove_host(data);
                Task::none()
            }
            Message::CopyToClipboard(data) => iced::clipboard::write(data.to_string()),
            Message::RangeSelected(range) => {
                self.selected_range = range;
                self.cache.clear();
                Task::none()
            }
            Message::BanwidthKindToggled => {
                self.transit_only_bandwidth = !self.transit_only_bandwidth;
                self.cache.clear();
                Task::none()
            }
            Message::CreateServer => {
                self.service_status = HiddenServiceStatus::CreateServer(None);
                Task::none()
            }
            Message::CreateClient => {
                self.service_status = HiddenServiceStatus::CreateClient(None);
                Task::none()
            }
            Message::CancelHiddenService => {
                self.service_status = HiddenServiceStatus::Idle;
                self.server_name.clear();
                self.server_port.clear();
                self.server_path.clear();
                self.client_name.clear();
                self.client_address.clear();
                self.client_port.clear();
                self.client_destination.clear();
                self.client_destination_port.clear();

                Task::none()
            }
            Message::SaveServer => {
                match self.save_server() {
                    Ok(address) => {
                        self.hidden_services.insert(
                            self.server_name.clone(),
                            HiddenService {
                                port: self.server_port.clone(),
                                path: self.server_path.clone(),
                                address,
                            },
                        );

                        self.server_name.clear();
                        self.server_port.clear();
                        self.server_path.clear();
                        self.service_status = HiddenServiceStatus::Idle;
                        self.config.server_tunnels = self.export_hidden_services();

                        save_router_config(self.base_path.join("router.toml"), &self.config);
                    }
                    Err(error) => {
                        self.service_status = HiddenServiceStatus::CreateServer(Some(error));
                    }
                }
                Task::none()
            }
            Message::ServerNameChanged(data) => {
                self.server_name = data;
                Task::none()
            }
            Message::ServerPortChanged(data) => {
                self.server_port = data;
                Task::none()
            }
            Message::ServerPathChanged(data) => {
                self.server_path = data;
                Task::none()
            }
            Message::RemoveHiddenService(service) => {
                if self.hidden_services.remove(&service).is_some() {
                    self.config.server_tunnels = self.export_hidden_services();

                    save_router_config(self.base_path.join("router.toml"), &self.config);
                }

                Task::none()
            }
            Message::EditHiddenService(name) => {
                let entry = self.hidden_services.get(&name).expect("to exist");

                self.edit_server_name = name.clone();
                self.edit_server_original_name = name;
                self.edit_server_port = entry.port.clone();
                self.edit_server_path = entry.path.clone();
                self.service_status = HiddenServiceStatus::EditServer(None);

                Task::none()
            }
            Message::EditServerNameChanged(data) => {
                self.edit_server_name = data;
                Task::none()
            }
            Message::EditServerPortChanged(data) => {
                self.edit_server_port = data;
                Task::none()
            }
            Message::EditServerPathChanged(data) => {
                self.edit_server_path = data;
                Task::none()
            }
            Message::SaveEditServer => {
                match self.save_edit_server() {
                    Ok(address) => {
                        self.hidden_services.remove(&self.edit_server_original_name);

                        self.hidden_services.insert(
                            self.edit_server_name.clone(),
                            HiddenService {
                                port: self.edit_server_port.clone(),
                                path: self.edit_server_path.clone(),
                                address,
                            },
                        );

                        self.edit_server_name.clear();
                        self.edit_server_port.clear();
                        self.edit_server_path.clear();
                        self.edit_server_original_name.clear();
                        self.service_status = HiddenServiceStatus::Idle;
                        self.config.server_tunnels = self.export_hidden_services();

                        save_router_config(self.base_path.join("router.toml"), &self.config);
                    }
                    Err(error) => {
                        self.service_status = HiddenServiceStatus::EditServer(Some(error));
                    }
                }

                Task::none()
            }
            Message::RemoveClientTunnel(data) => {
                if self.client_tunnels.remove(&data).is_some() {
                    self.config.client_tunnels = self.export_client_tunnels();

                    save_router_config(self.base_path.join("router.toml"), &self.config);
                }
                Task::none()
            }
            Message::EditClientTunnel(name) => {
                let entry = self.client_tunnels.get(&name).expect("to exist");

                self.edit_client_name = name.clone();
                self.edit_client_original_name = name;
                self.edit_client_address = entry.address.clone();
                self.edit_client_port = entry.port.clone();
                self.edit_client_destination = entry.destination.clone();
                self.edit_client_destination_port = entry.destination_port.clone();

                self.service_status = HiddenServiceStatus::EditClient(None);

                Task::none()
            }
            Message::SaveClient => {
                match self.save_client() {
                    Ok(()) => {
                        self.client_tunnels.insert(
                            self.client_name.clone(),
                            ClientTunnel {
                                address: self.client_address.clone(),
                                port: self.client_port.clone(),
                                destination: self.client_destination.clone(),
                                destination_port: self.client_destination_port.clone(),
                            },
                        );

                        self.client_name.clear();
                        self.client_address.clear();
                        self.client_port.clear();
                        self.client_destination.clear();
                        self.client_destination_port.clear();
                        self.service_status = HiddenServiceStatus::Idle;
                        self.config.client_tunnels = self.export_client_tunnels();

                        save_router_config(self.base_path.join("router.toml"), &self.config);
                    }
                    Err(error) => {
                        self.service_status = HiddenServiceStatus::CreateClient(Some(error));
                    }
                }
                Task::none()
            }
            Message::ClientNameChanged(data) => {
                self.client_name = data;
                Task::none()
            }
            Message::ClientAddressChanged(data) => {
                self.client_address = data;
                Task::none()
            }
            Message::ClientPortChanged(data) => {
                self.client_port = data;
                Task::none()
            }
            Message::ClientDestinationChanged(data) => {
                self.client_destination = data;
                Task::none()
            }
            Message::ClientDestinationPortChanged(data) => {
                self.client_destination_port = data;
                Task::none()
            }
            Message::EditClientNameChanged(data) => {
                self.edit_client_name = data;
                Task::none()
            }
            Message::EditClientAddressChanged(data) => {
                self.edit_client_address = data;
                Task::none()
            }
            Message::EditClientPortChanged(data) => {
                self.edit_client_port = data;
                Task::none()
            }
            Message::EditClientDestinationChanged(data) => {
                self.edit_client_destination = data;
                Task::none()
            }
            Message::EditClientDestinationPortChanged(data) => {
                self.edit_client_destination_port = data;
                Task::none()
            }
            Message::SaveEditClient => {
                match self.save_edit_client() {
                    Ok(()) => {
                        self.client_tunnels.remove(&self.edit_client_original_name);

                        self.client_tunnels.insert(
                            self.edit_client_name.clone(),
                            ClientTunnel {
                                address: self.edit_client_address.clone(),
                                port: self.edit_client_port.clone(),
                                destination: self.edit_client_destination.clone(),
                                destination_port: self.edit_client_destination_port.clone(),
                            },
                        );

                        self.edit_client_name.clear();
                        self.edit_client_address.clear();
                        self.edit_client_port.clear();
                        self.edit_client_destination.clear();
                        self.edit_client_destination_port.clear();
                        self.service_status = HiddenServiceStatus::Idle;
                        self.config.client_tunnels = self.export_client_tunnels();

                        save_router_config(self.base_path.join("router.toml"), &self.config);
                    }
                    Err(error) => {
                        self.service_status = HiddenServiceStatus::EditClient(Some(error));
                    }
                }

                Task::none()
            }
            Message::Shutdown => match self.status {
                Status::Active => {
                    self.status = Status::ShuttingDown(Instant::now());
                    let _ = self.shutdown_tx.try_send(());

                    Task::none()
                }
                Status::ShuttingDown(_) => std::process::exit(0),
            },
        }
    }

    fn status_card<'a>(
        title: &'a str,
        content: String,
        handle: iced::widget::svg::Handle,
    ) -> Container<'a, Message> {
        Container::new(
            Row::new()
                .align_y(Vertical::Center)
                .push(
                    Container::new(
                        svg(handle).content_fit(iced::ContentFit::Contain).width(35).height(35),
                    )
                    .center_x(50)
                    .center_y(50)
                    .style(|_theme: &Theme| iced::widget::container::Style {
                        border: Border {
                            radius: Radius::from(12.0),
                            width: 1.0,
                            color: Color::from_rgb8(28, 36, 49),
                        },
                        background: Some(Background::Color(Color::from_rgb8(54, 40, 176))),
                        ..Default::default()
                    }),
                )
                .push(
                    Column::new()
                        .push(
                            Text::new(title)
                                .size(14)
                                .color(Color::from_rgb(0.8392, 0.8392, 0.8392)),
                        )
                        .push(Text::new(content).size(20).color(Color::WHITE)),
                )
                .spacing(10),
        )
        .padding(10)
        .width(Length::Fill)
        .style(|_theme: &Theme| iced::widget::container::Style {
            border: Border {
                radius: Radius::from(12.0),
                width: 1.0,
                color: Color::from_rgb8(28, 36, 49),
            },
            background: Some(iced::Background::Color(Color::from_rgb(
                28.0 / 255.0,
                36.0 / 255.0,
                49.0 / 255.0,
            ))),
            ..Default::default()
        })
    }

    fn view(&self) -> Element<'_, Message> {
        let sidebar = sidebar(Some(self.view), std::matches!(self.status, Status::Active));

        let content = match self.view {
            SidebarMessage::Dashboard => self.dashboard(),
            SidebarMessage::Bandwidth => self.bandwidth(),
            SidebarMessage::HiddenServices => self.hidden_services(),
            SidebarMessage::Settings => self.settings(),
            SidebarMessage::AddressBook => self.address_book(),
        };

        row![
            container(sidebar).width(FillPortion(2)),
            container(content)
                .width(FillPortion(13))
                .style(|_theme: &Theme| iced::widget::container::Style {
                    border: Border::default(),
                    text_color: Some(Color::WHITE),
                    background: Some(iced::Background::Color(Color::from_rgb(
                        0.051, 0.071, 0.118,
                    ))),
                    ..Default::default()
                })
                .height(Length::Fill)
        ]
        .align_y(Alignment::Start)
        .height(Length::Fill)
        .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        time::every(Duration::from_millis(1000)).map(|_| Message::Tick)
    }

    fn theme(&self) -> Theme {
        if self.light_mode {
            Theme::Light
        } else {
            Theme::Dark
        }
    }
}
