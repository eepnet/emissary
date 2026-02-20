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
    cli::{Arguments, HttpProxyOptions, SocksProxyOptions},
    error::Error,
    LOG_TARGET,
};

use emissary_util::{
    port_mapper::PortMapperConfig,
    storage::{Storage, StorageBundle},
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use std::{collections::HashSet, net::Ipv4Addr, path::PathBuf};

/// Reserved ports.
///
/// Taken from i2pd.
const RESERVED_PORTS: [u16; 57] = [
    9119, 9150, 9306, 9312, 9389, 9418, 9535, 9536, 9695, 9800, 9899, 10000, 10050, 10051, 10110,
    10212, 10933, 11001, 11112, 11235, 11371, 12222, 12223, 13075, 13400, 13720, 13721, 13724,
    13782, 13783, 13785, 13786, 15345, 17224, 17225, 17500, 18104, 19788, 19812, 19813, 19814,
    19999, 20000, 24465, 24554, 26000, 27000, 27001, 27002, 27003, 27004, 27005, 27006, 27007,
    27008, 27009, 28000,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploratoryConfig {
    pub inbound_len: Option<usize>,
    pub inbound_count: Option<usize>,
    pub outbound_len: Option<usize>,
    pub outbound_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ntcp2Config {
    pub port: u16,
    pub host: Option<Ipv4Addr>,
    pub publish: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ssu2Config {
    pub port: u16,
    pub host: Option<Ipv4Addr>,
    pub publish: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I2cpConfig {
    pub port: u16,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamConfig {
    pub tcp_port: u16,
    pub udp_port: u16,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReseedConfig {
    pub hosts: Option<Vec<String>>,
    pub reseed_threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    pub port: u16,
    pub host: String,
    pub outproxy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksProxyConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBookConfig {
    pub default: Option<String>,
    pub subscriptions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTunnelConfig {
    pub name: String,
    pub address: Option<String>,
    pub port: u16,
    pub destination: String,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTunnelConfig {
    pub name: String,
    pub port: u16,
    pub destination_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    pub max_tunnels: Option<usize>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    port: u16,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PortForwardingConfig {
    pub nat_pmp: bool,
    pub upnp: bool,
    pub name: String,
}

impl From<PortForwardingConfig> for PortMapperConfig {
    fn from(value: PortForwardingConfig) -> Self {
        PortMapperConfig {
            nat_pmp: value.nat_pmp,
            upnp: value.upnp,
            name: value.name,
        }
    }
}

#[derive(Default, Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize)]
pub enum Theme {
    #[serde(alias = "light")]
    Light,
    #[serde(alias = "dark")]
    #[default]
    Dark,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RouterUiConfig {
    pub theme: Theme,
    pub refresh_interval: usize,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissaryConfig {
    #[serde(rename = "address-book")]
    pub address_book: Option<AddressBookConfig>,
    #[serde(default)]
    pub allow_local: bool,
    pub caps: Option<String>,
    pub exploratory: Option<ExploratoryConfig>,
    #[serde(default)]
    pub floodfill: bool,
    #[serde(rename = "http-proxy")]
    pub http_proxy: Option<HttpProxyConfig>,
    #[serde(rename = "socks-proxy")]
    pub socks_proxy: Option<SocksProxyConfig>,
    pub i2cp: Option<I2cpConfig>,
    #[serde(default)]
    pub insecure_tunnels: bool,
    pub log: Option<String>,
    pub metrics: Option<MetricsConfig>,
    pub net_id: Option<u8>,
    pub ntcp2: Option<Ntcp2Config>,
    #[serde(rename = "port-forwarding")]
    pub port_forwarding: Option<PortForwardingConfig>,
    pub reseed: Option<ReseedConfig>,
    pub sam: Option<SamConfig>,
    pub ssu2: Option<Ssu2Config>,
    pub transit: Option<TransitConfig>,
    #[serde(rename = "client-tunnels")]
    pub client_tunnels: Option<Vec<ClientTunnelConfig>>,
    #[serde(rename = "server-tunnels")]
    pub server_tunnels: Option<Vec<ServerTunnelConfig>>,
    #[serde(rename = "router-ui")]
    pub router_ui: Option<RouterUiConfig>,
}

impl Default for EmissaryConfig {
    fn default() -> Self {
        Self {
            address_book: Some(AddressBookConfig {
                default: Some(String::from(
                    "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt",
                )),
                subscriptions: None,
            }),
            caps: Some(String::from("XR")),
            http_proxy: Some(HttpProxyConfig {
                host: "127.0.0.1".to_string(),
                port: 4444u16,
                outproxy: None,
            }),
            socks_proxy: None,
            i2cp: Some(I2cpConfig {
                port: 7654,
                host: None,
            }),
            metrics: Some(MetricsConfig { port: 7788 }),
            ntcp2: Some(Ntcp2Config {
                port: {
                    loop {
                        let port: u16 = thread_rng().gen_range(9151..=30777);

                        if !RESERVED_PORTS.iter().any(|reserved_port| reserved_port == &port) {
                            break port;
                        }
                    }
                },
                host: None,
                publish: Some(true),
            }),
            port_forwarding: Some(PortForwardingConfig {
                nat_pmp: true,
                upnp: true,
                name: String::from("emissary"),
            }),
            reseed: Some(ReseedConfig {
                reseed_threshold: 25usize,
                hosts: None,
            }),
            router_ui: Some(RouterUiConfig {
                theme: Theme::Dark,
                refresh_interval: 5usize,
                port: None,
            }),
            sam: Some(SamConfig {
                tcp_port: 7656,
                udp_port: 7655,
                host: None,
            }),
            transit: Some(TransitConfig {
                max_tunnels: Some(1000),
            }),
            allow_local: false,
            exploratory: None,
            floodfill: false,
            insecure_tunnels: false,
            log: None,
            net_id: None,
            ssu2: None,
            client_tunnels: None,
            server_tunnels: None,
        }
    }
}

/// Router configuration.
pub struct Config {
    /// Address book config.
    pub address_book: Option<AddressBookConfig>,

    /// Allow local addresses.
    pub allow_local: bool,

    /// Base path.
    pub base_path: PathBuf,

    /// Router capabilities.
    pub caps: Option<String>,

    /// Client tunnel configurations.
    pub client_tunnels: Vec<ClientTunnelConfig>,

    /// Exploratory tunnel pool config.
    pub exploratory: Option<emissary_core::ExploratoryConfig>,

    /// Should the node be run as a floodfill router.
    pub floodfill: bool,

    /// HTTP proxy config.
    pub http_proxy: Option<HttpProxyConfig>,

    /// I2CP config.
    pub i2cp_config: Option<emissary_core::I2cpConfig>,

    /// Are tunnels allowed to be insecure.
    pub insecure_tunnels: bool,

    /// Logging targets.
    pub log: Option<String>,

    /// Metrics configuration.
    pub metrics: Option<emissary_core::MetricsConfig>,

    /// Network ID.
    pub net_id: Option<u8>,

    /// NTCP2 config.
    pub ntcp2_config: Option<emissary_core::Ntcp2Config>,

    /// Port forwarding config.
    pub port_forwarding: Option<PortMapperConfig>,

    /// Profiles.
    pub profiles: Vec<(String, emissary_core::Profile)>,

    /// Reseed config.
    pub reseed: Option<ReseedConfig>,

    /// Router info.
    pub router_info: Option<Vec<u8>>,

    /// Router UI configuration.
    pub router_ui: Option<RouterUiConfig>,

    /// Router info.
    pub routers: Vec<Vec<u8>>,

    /// SAMv3 config.
    pub sam_config: Option<emissary_core::SamConfig>,

    /// Server tunnel configurations.
    pub server_tunnels: Vec<ServerTunnelConfig>,

    /// Signing key.
    pub signing_key: [u8; 32],

    //// SOCKS proxy config.
    pub socks_proxy: Option<SocksProxyConfig>,

    /// SSU2 configuration.
    pub ssu2_config: Option<emissary_core::Ssu2Config>,

    /// Static key.
    pub static_key: [u8; 32],

    /// Transit tunnel config.
    pub transit: Option<emissary_core::TransitConfig>,

    /// Config which is stored on disk.
    ///
    /// This is passed onto the UI.
    pub config: Option<EmissaryConfig>,
}

impl From<Config> for emissary_core::Config {
    fn from(val: Config) -> Self {
        emissary_core::Config {
            allow_local: val.allow_local,
            caps: val.caps,
            exploratory: val.exploratory,
            floodfill: val.floodfill,
            i2cp_config: val.i2cp_config,
            insecure_tunnels: val.insecure_tunnels,
            metrics: val.metrics,
            net_id: val.net_id,
            ntcp2: val.ntcp2_config,
            profiles: val.profiles,
            router_info: val.router_info,
            routers: val.routers,
            samv3_config: val.sam_config,
            signing_key: Some(val.signing_key),
            ssu2: val.ssu2_config,
            static_key: Some(val.static_key),
            transit: val.transit,
            refresh_interval: val.router_ui.map(|config| config.refresh_interval),
        }
    }
}

impl Config {
    /// Attemp to parse configuration from `path` and merge config with `arguments`.
    ///
    /// If the configuratin file exists but it's invalid, exit early, unless `--overwrite-config`
    /// has been passed in which case create new default configuration.
    pub async fn parse(arguments: &Arguments, storage: &Storage) -> Result<Self, Error> {
        let path = storage.base_path();

        tracing::trace!(
            target: LOG_TARGET,
            ?path,
            "parse router config",
        );

        // try to find `router.toml` and parse it into `EmissaryConfig`
        //
        // if the configuration is invalid (`Error::InvaliData`), and `overwrite_config` has been
        // passed, create new default configuration
        //
        // if the option hasn't been passed, exit early and allow user to take a copy of their
        // config before generating a new config
        let router_config = match Self::load_router_config(path.clone()).await {
            Err(Error::InvalidData) if arguments.overwrite_config.unwrap_or(false) => None,
            Err(Error::InvalidData) => return Err(Error::InvalidData),
            Err(_) => None,
            Ok(config) => Some(config),
        };

        let StorageBundle {
            ntcp2_iv,
            ntcp2_key,
            profiles,
            router_info,
            routers,
            signing_key,
            static_key,
            ssu2_intro_key,
            ssu2_static_key,
        } = storage.load().await;

        let mut config = Config::new(
            path.clone(),
            static_key,
            signing_key,
            ntcp2_key,
            ntcp2_iv,
            ssu2_static_key,
            ssu2_intro_key,
            router_config,
            router_info,
        )
        .await?
        .merge(arguments);

        config.routers = routers;
        config.profiles = profiles;

        Ok(config)
    }

    async fn load_router_config(path: PathBuf) -> crate::Result<EmissaryConfig> {
        let contents = tokio::fs::read_to_string(path.join("router.toml")).await?;
        // // parse configuration, if it exists
        // let mut file = fs::File::open(path.join("router.toml"))?;
        // let mut contents = String::new();
        // file.read_to_string(&mut contents)?;

        toml::from_str::<EmissaryConfig>(&contents).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                %error,
                "failed to parse router config",
            );

            Error::InvalidData
        })
    }

    /// Create new [`Config`].
    async fn new(
        base_path: PathBuf,
        static_key: [u8; 32],
        signing_key: [u8; 32],
        ntcp2_key: [u8; 32],
        ntcp2_iv: [u8; 16],
        ssu2_static_key: [u8; 32],
        ssu2_intro_key: [u8; 32],
        config: Option<EmissaryConfig>,
        router_info: Option<Vec<u8>>,
    ) -> crate::Result<Self> {
        let config = match config {
            Some(config) => config,
            None => {
                let config = EmissaryConfig::default();
                let toml_config = toml::to_string(&config).expect("to succeed");
                let mut file = tokio::fs::File::create(base_path.join("router.toml")).await?;
                file.write_all(toml_config.as_bytes()).await?;
                file.flush().await?;

                config
            }
        };
        let config_copy = config.clone();

        if let Some(tunnels) = &config.client_tunnels {
            // ensure each client tunnel has a unique name
            if tunnels.iter().map(|config| &config.name).collect::<HashSet<_>>().len()
                != tunnels.len()
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    "all client tunnels must have a unique name",
                );
                return Err(Error::InvalidData);
            }

            // ensure each client tunnel has a unique port
            if tunnels.iter().map(|config| config.port).collect::<HashSet<_>>().len()
                != tunnels.len()
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    "all client tunnels must have a unique port",
                );
                return Err(Error::InvalidData);
            }
        }

        if let Some(tunnels) = &config.server_tunnels {
            // ensure each server tunnel has a unique name
            if tunnels.iter().map(|config| &config.name).collect::<HashSet<_>>().len()
                != tunnels.len()
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    "all server tunnels must have a unique name",
                );
                return Err(Error::InvalidData);
            }

            // ensure each server tunnel has a unique port
            if tunnels.iter().map(|config| config.port).collect::<HashSet<_>>().len()
                != tunnels.len()
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    "all server tunnels must have a unique port",
                );
                return Err(Error::InvalidData);
            }

            // ensure each server tunnel has a unique path
            if tunnels
                .iter()
                .map(|config| config.destination_path.clone())
                .collect::<HashSet<_>>()
                .len()
                != tunnels.len()
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    "all server tunnels must have a destination path",
                );
                return Err(Error::InvalidData);
            }
        }

        Ok(Self {
            address_book: config.address_book,
            allow_local: config.allow_local,
            base_path,
            caps: config.caps,
            client_tunnels: config.client_tunnels.unwrap_or(Vec::new()),
            exploratory: config.exploratory.map(|config| emissary_core::ExploratoryConfig {
                inbound_len: config.inbound_len,
                inbound_count: config.inbound_count,
                outbound_len: config.outbound_len,
                outbound_count: config.outbound_count,
            }),
            floodfill: config.floodfill,
            http_proxy: config.http_proxy,
            i2cp_config: config.i2cp.map(|config| emissary_core::I2cpConfig {
                port: config.port,
                host: config.host.unwrap_or(String::from("127.0.0.1")),
            }),
            insecure_tunnels: config.insecure_tunnels,
            log: config.log,
            metrics: config
                .metrics
                .map(|config| emissary_core::MetricsConfig { port: config.port }),
            net_id: config.net_id,
            ntcp2_config: config.ntcp2.map(|config| emissary_core::Ntcp2Config {
                port: config.port,
                host: config.host,
                publish: config.publish.unwrap_or(false),
                key: ntcp2_key,
                iv: ntcp2_iv,
            }),
            port_forwarding: config.port_forwarding.map(From::from),
            profiles: Vec::new(),
            reseed: config.reseed,
            router_info,
            router_ui: config.router_ui,
            routers: Vec::new(),
            sam_config: config.sam.map(|config| emissary_core::SamConfig {
                tcp_port: config.tcp_port,
                udp_port: config.udp_port,
                host: config.host.unwrap_or(String::from("127.0.0.1")),
            }),
            server_tunnels: config.server_tunnels.unwrap_or(Vec::new()),
            signing_key,
            socks_proxy: config.socks_proxy,
            ssu2_config: config.ssu2.map(|config| emissary_core::Ssu2Config {
                port: config.port,
                host: config.host,
                publish: config.publish.unwrap_or(false),
                static_key: ssu2_static_key,
                intro_key: ssu2_intro_key,
            }),
            static_key,
            transit: config.transit.map(|config| emissary_core::TransitConfig {
                max_tunnels: config.max_tunnels,
            }),
            config: Some(config_copy),
        })
    }

    /// Attempt to merge `arguments` with [`Config`].
    fn merge(mut self, arguments: &Arguments) -> Self {
        if let Some(true) = arguments.floodfill {
            if !self.floodfill {
                self.floodfill = true;
            }
        }

        if let Some(true) = arguments.tunnel.insecure_tunnels {
            if !self.insecure_tunnels {
                self.insecure_tunnels = true;
            }
        }

        if let Some(true) = arguments.allow_local {
            if !self.allow_local {
                self.allow_local = true;
            }
        }

        match (
            arguments.metrics.disable_metrics,
            arguments.metrics.metrics_server_port,
        ) {
            (Some(true), _) => {
                self.metrics = None;
            }
            (Some(false), Some(port)) => self.metrics = Some(emissary_core::MetricsConfig { port }),
            _ => {}
        }

        if let Some(ref caps) = arguments.caps {
            self.caps = Some(caps.clone());
        }

        if let Some(net_id) = arguments.net_id {
            self.net_id = Some(net_id);
        }

        if let Some(log) = &arguments.log {
            self.log = Some(log.clone());
        }

        if let Some(hosts) = &arguments.reseed.reseed_hosts {
            match &mut self.reseed {
                None => {
                    self.reseed = Some(ReseedConfig {
                        hosts: Some(hosts.clone()),
                        reseed_threshold: 25usize,
                    });
                }
                Some(config) => {
                    config.hosts = Some(hosts.clone());
                }
            }
        }

        if let Some(threshold) = arguments.reseed.reseed_threshold {
            match &mut self.reseed {
                None => {
                    self.reseed = Some(ReseedConfig {
                        hosts: None,
                        reseed_threshold: threshold,
                    });
                }
                Some(config) => {
                    config.reseed_threshold = threshold;
                }
            }
        }

        if let Some(true) = arguments.reseed.disable_reseed {
            self.reseed = None;
        }

        match (&mut self.http_proxy, &arguments.http_proxy) {
            (
                Some(config),
                HttpProxyOptions {
                    http_proxy_port,
                    http_proxy_host,
                    http_outproxy,
                },
            ) => {
                if let Some(port) = http_proxy_port {
                    config.port = *port;
                }

                if let Some(host) = &http_proxy_host {
                    config.host = host.clone();
                }

                if let Some(outproxy) = http_outproxy {
                    config.outproxy = Some(outproxy.clone());
                }
            }
            (
                None,
                HttpProxyOptions {
                    http_proxy_port: Some(port),
                    http_proxy_host: Some(host),
                    http_outproxy,
                },
            ) => {
                self.http_proxy = Some(HttpProxyConfig {
                    port: *port,
                    host: host.clone(),
                    outproxy: http_outproxy.clone(),
                });
            }
            _ => {}
        }

        match (&mut self.socks_proxy, &arguments.socks_proxy) {
            (
                Some(config),
                SocksProxyOptions {
                    socks_proxy_port,
                    socks_proxy_host,
                },
            ) => {
                if let Some(port) = socks_proxy_port {
                    config.port = *port;
                }

                if let Some(host) = &socks_proxy_host {
                    config.host = host.clone();
                }
            }
            (
                None,
                SocksProxyOptions {
                    socks_proxy_port: Some(port),
                    socks_proxy_host: Some(host),
                },
            ) => {
                self.socks_proxy = Some(SocksProxyConfig {
                    port: *port,
                    host: host.clone(),
                });
            }
            _ => {}
        }

        self.exploratory = match &mut self.exploratory {
            None => Some(emissary_core::ExploratoryConfig {
                inbound_len: arguments.tunnel.exploratory_inbound_len,
                inbound_count: arguments.tunnel.exploratory_inbound_count,
                outbound_len: arguments.tunnel.exploratory_outbound_len,
                outbound_count: arguments.tunnel.exploratory_outbound_count,
            }),
            Some(config) => Some(emissary_core::ExploratoryConfig {
                inbound_len: arguments.tunnel.exploratory_inbound_len.or(config.inbound_len),
                inbound_count: arguments.tunnel.exploratory_inbound_count.or(config.inbound_count),
                outbound_len: arguments.tunnel.exploratory_outbound_len.or(config.outbound_len),
                outbound_count: arguments
                    .tunnel
                    .exploratory_outbound_count
                    .or(config.outbound_count),
            }),
        };

        if let Some(max_tunnels) = arguments.transit.max_transit_tunnels {
            self.transit = Some(emissary_core::TransitConfig {
                max_tunnels: Some(max_tunnels),
            });
        }

        if let Some(true) = arguments.transit.disable_transit_tunnels {
            self.transit = None;
        }

        if let Some(PortMapperConfig {
            nat_pmp,
            upnp,
            name,
        }) = &mut self.port_forwarding
        {
            if let Some(true) = arguments.port_forwarding.disable_upnp {
                *upnp = false;
            }

            if let Some(true) = arguments.port_forwarding.disable_nat_pmp {
                *nat_pmp = false;
            }

            if let Some(ref description) = arguments.port_forwarding.upnp_name {
                *name = description.clone();
            }
        }

        if let Some(RouterUiConfig {
            theme,
            refresh_interval,
            port,
        }) = &mut self.router_ui
        {
            if let Some(selected) = arguments.router_ui.theme {
                *theme = selected;
            }

            if let Some(selected) = arguments.router_ui.refresh_interval {
                *refresh_interval = selected;
            }

            if let Some(selected) = arguments.router_ui.web_ui_port {
                *port = Some(selected);
            }

            if let Some(true) = arguments.router_ui.disable_ui {
                self.router_ui = None;
            }
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::{
        MetricsOptions, PortForwardingOptions, ReseedOptions, TransitOptions, TunnelOptions,
    };

    use super::*;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;

    fn make_arguments() -> Arguments {
        Arguments {
            base_path: None,
            command: None,
            log: None,
            router_ui: crate::cli::RouterUiOptions {
                disable_ui: None,
                refresh_interval: None,
                theme: None,
                web_ui_port: None,
            },
            floodfill: None,
            allow_local: None,
            caps: None,
            net_id: None,
            overwrite_config: None,
            tunnel: TunnelOptions {
                exploratory_inbound_len: None,
                exploratory_inbound_count: None,
                exploratory_outbound_len: None,
                exploratory_outbound_count: None,
                insecure_tunnels: None,
            },
            reseed: ReseedOptions {
                reseed_hosts: None,
                disable_reseed: None,
                force_reseed: None,
                reseed_threshold: None,
                disable_force_ipv4: None,
            },
            metrics: MetricsOptions {
                metrics_server_port: None,
                disable_metrics: None,
            },
            http_proxy: HttpProxyOptions {
                http_proxy_port: None,
                http_proxy_host: None,
                http_outproxy: None,
            },
            socks_proxy: SocksProxyOptions {
                socks_proxy_port: None,
                socks_proxy_host: None,
            },
            transit: TransitOptions {
                max_transit_tunnels: None,
                disable_transit_tunnels: None,
            },
            port_forwarding: PortForwardingOptions {
                disable_upnp: None,
                disable_nat_pmp: None,
                upnp_name: None,
            },
        }
    }

    #[tokio::test]
    async fn fresh_boot_directory_created() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(Some(dir.path().to_owned())).await.unwrap();
        let config = Config::parse(&make_arguments(), &storage).await.unwrap();

        assert!(config.routers.is_empty());
        assert_eq!(config.static_key.len(), 32);
        assert_eq!(config.signing_key.len(), 32);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().host, None);

        // ensure ntcp2 port is within correct range and not any of the reserved ports
        {
            let port = config.ntcp2_config.as_ref().unwrap().port;

            assert!((9151..=30777).contains(&port));
            assert!(!RESERVED_PORTS.iter().any(|p| p == &port));
        }

        let (key, iv) = {
            let mut path = dir.path().to_owned();
            path.push("ntcp2.keys");
            let mut file = tokio::fs::File::open(&path).await.unwrap();

            let mut contents = [0u8; 48];
            file.read_exact(&mut contents).await.unwrap();

            (
                TryInto::<[u8; 32]>::try_into(&contents[..32]).expect("to succeed"),
                TryInto::<[u8; 16]>::try_into(&contents[32..]).expect("to succeed"),
            )
        };

        assert_eq!(config.ntcp2_config.as_ref().unwrap().key, key);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().iv, iv);
    }

    #[tokio::test]
    async fn load_configs_correctly() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(Some(dir.path().to_owned())).await.unwrap();

        let (static_key, signing_key, ntcp2_config) = {
            let config = Config::parse(&make_arguments(), &storage).await.unwrap();
            (config.static_key, config.signing_key, config.ntcp2_config)
        };

        let config = Config::parse(&make_arguments(), &storage).await.unwrap();
        assert_eq!(config.static_key, static_key);
        assert_eq!(config.signing_key, signing_key);
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().port,
            ntcp2_config.as_ref().unwrap().port
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().host,
            ntcp2_config.as_ref().unwrap().host
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().key,
            ntcp2_config.as_ref().unwrap().key
        );
        assert_eq!(
            config.ntcp2_config.as_ref().unwrap().iv,
            ntcp2_config.as_ref().unwrap().iv
        );
    }

    #[tokio::test]
    async fn config_update_works() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(Some(dir.path().to_owned())).await.unwrap();

        // create default config, verify the default ntcp2 port is 8888
        let (ntcp2_key, ntcp2_iv) = {
            let config = Config::parse(&make_arguments(), &storage).await.unwrap();
            let ntcp2_config = config.ntcp2_config.unwrap();

            assert!(ntcp2_config.port >= 9151 && ntcp2_config.port <= 30777);
            assert!(!RESERVED_PORTS.iter().any(|p| p == &ntcp2_config.port));

            (ntcp2_config.key, ntcp2_config.iv)
        };

        // create new ntcp2 config where the port is different
        let config = EmissaryConfig {
            i2cp: Some(I2cpConfig {
                port: 0u16,
                host: None,
            }),
            ntcp2: Some(Ntcp2Config {
                port: 1337u16,
                host: None,
                publish: None,
            }),
            ..Default::default()
        };
        let config = toml::to_string(&config).expect("to succeed");
        let mut file = tokio::fs::File::create(dir.path().to_owned().join("router.toml"))
            .await
            .unwrap();
        file.write_all(config.as_bytes()).await.unwrap();
        file.flush().await.unwrap();

        // load the new config
        //
        // verify that ntcp2 key & iv are the same but port is new
        let config = Config::parse(&make_arguments(), &storage).await.unwrap();
        let ntcp2_config = config.ntcp2_config.unwrap();

        assert_eq!(ntcp2_config.port, 1337u16);
        assert_eq!(ntcp2_config.key, ntcp2_key);
        assert_eq!(ntcp2_config.iv, ntcp2_iv);
    }

    #[tokio::test]
    async fn overwrite_config() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(Some(dir.path().to_owned())).await.unwrap();

        let mut file = tokio::fs::File::create(dir.path().to_owned().join("router.toml"))
            .await
            .unwrap();
        file.write_all("hello, world!".as_bytes()).await.unwrap();
        file.flush().await.unwrap();

        let mut args = make_arguments();

        // create default config, verify the default ntcp2 port is 8888
        match Config::parse(&args, &storage).await {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        }

        // allow emissary to overwrite config
        args.overwrite_config = Some(true);

        // verify default config is created
        let config = Config::parse(&args, &storage).await.unwrap();

        assert!(config.ntcp2_config.is_some());
        assert!(config.sam_config.is_some());
        assert!(config.address_book.is_some());
        assert!(config.http_proxy.is_some());
        assert!(!config.floodfill);
        assert!(!config.insecure_tunnels);
        assert!(!config.allow_local);
    }

    #[tokio::test]
    async fn client_tunnels_with_same_names() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(Some(dir.path().to_owned())).await.unwrap();

        // create new ntcp2 config where the port is different
        let config = EmissaryConfig {
            client_tunnels: Some(vec![
                ClientTunnelConfig {
                    name: "tunnel".to_string(),
                    address: None,
                    port: 1337,
                    destination: "hello".to_string(),
                    destination_port: None,
                },
                ClientTunnelConfig {
                    name: "tunnel".to_string(),
                    address: None,
                    port: 1338,
                    destination: "hello".to_string(),
                    destination_port: None,
                },
            ]),
            ..Default::default()
        };

        let config = toml::to_string(&config).expect("to succeed");
        let mut file = tokio::fs::File::create(dir.path().to_owned().join("router.toml"))
            .await
            .unwrap();
        file.write_all(config.as_bytes()).await.unwrap();
        file.flush().await.unwrap();

        match Config::parse(&make_arguments(), &storage).await {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn client_tunnels_with_same_ports() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(Some(dir.path().to_owned())).await.unwrap();

        // create new ntcp2 config where the port is different
        let config = EmissaryConfig {
            client_tunnels: Some(vec![
                ClientTunnelConfig {
                    name: "tunnel1".to_string(),
                    address: None,
                    port: 1337,
                    destination: "hello".to_string(),
                    destination_port: None,
                },
                ClientTunnelConfig {
                    name: "tunnel2".to_string(),
                    address: None,
                    port: 1337,
                    destination: "hello".to_string(),
                    destination_port: None,
                },
            ]),
            ..Default::default()
        };

        let config = toml::to_string(&config).expect("to succeed");
        let mut file = tokio::fs::File::create(dir.path().to_owned().join("router.toml"))
            .await
            .unwrap();
        file.write_all(config.as_bytes()).await.unwrap();
        file.flush().await.unwrap();

        match Config::parse(&make_arguments(), &storage).await {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        }
    }
}
