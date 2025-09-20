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

use home::home_dir;
use rand::{rngs::OsRng, thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};

use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    last_activity: Option<u64>,
    last_declined: Option<u64>,
    last_dial_failure: Option<u64>,
    num_accepted: Option<usize>,
    num_connection: Option<usize>,
    num_dial_failures: Option<usize>,
    num_lookup_failures: Option<usize>,
    num_lookup_no_responses: Option<usize>,
    num_lookup_successes: Option<usize>,
    num_rejected: Option<usize>,
    num_selected: Option<usize>,
    num_test_failures: Option<usize>,
    num_test_successes: Option<usize>,
    num_unaswered: Option<usize>,
}

impl From<emissary_core::Profile> for Profile {
    fn from(profile: emissary_core::Profile) -> Self {
        Profile {
            last_activity: Some(profile.last_activity.as_secs()),
            last_declined: profile.last_declined.map(|last_declined| last_declined.as_secs()),
            last_dial_failure: profile
                .last_dial_failure
                .map(|last_dial_failure| last_dial_failure.as_secs()),
            num_accepted: Some(profile.num_accepted),
            num_connection: Some(profile.num_connection),
            num_dial_failures: Some(profile.num_dial_failures),
            num_lookup_failures: Some(profile.num_lookup_failures),
            num_lookup_no_responses: Some(profile.num_lookup_no_responses),
            num_lookup_successes: Some(profile.num_lookup_successes),
            num_rejected: Some(profile.num_rejected),
            num_selected: Some(profile.num_selected),
            num_test_failures: Some(profile.num_test_failures),
            num_test_successes: Some(profile.num_test_successes),
            num_unaswered: Some(profile.num_unaswered),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ExploratoryConfig {
    inbound_len: Option<usize>,
    inbound_count: Option<usize>,
    outbound_len: Option<usize>,
    outbound_count: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ntcp2Config {
    port: u16,
    host: Option<Ipv4Addr>,
    publish: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ssu2Config {
    port: u16,
    host: Option<Ipv4Addr>,
    publish: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct I2cpConfig {
    port: u16,
    host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SamConfig {
    tcp_port: u16,
    udp_port: u16,
    host: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReseedConfig {
    pub hosts: Option<Vec<String>>,
    pub reseed_threshold: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    pub port: u16,
    pub host: String,
    pub outproxy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SocksProxyConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddressBookConfig {
    pub default: Option<String>,
    pub subscriptions: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientTunnelConfig {
    pub name: String,
    pub address: Option<String>,
    pub port: u16,
    pub destination: String,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerTunnelConfig {
    pub name: String,
    pub port: u16,
    pub destination_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransitConfig {
    pub max_tunnels: Option<usize>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MetricsConfig {
    port: u16,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PortForwardingConfig {
    pub nat_pmp: bool,
    pub upnp: bool,
    pub name: String,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize)]
pub enum Theme {
    #[serde(alias = "light")]
    Light,
    #[serde(alias = "dark")]
    Dark,
}

impl Default for Theme {
    fn default() -> Self {
        Self::Dark
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RouterUiConfig {
    pub theme: Theme,
    pub refresh_interval: usize,
    pub port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EmissaryConfig {
    #[serde(rename = "address-book")]
    address_book: Option<AddressBookConfig>,
    #[serde(default)]
    allow_local: bool,
    caps: Option<String>,
    exploratory: Option<ExploratoryConfig>,
    #[serde(default)]
    floodfill: bool,
    #[serde(rename = "http-proxy")]
    http_proxy: Option<HttpProxyConfig>,
    #[serde(rename = "socks-proxy")]
    socks_proxy: Option<SocksProxyConfig>,
    i2cp: Option<I2cpConfig>,
    #[serde(default)]
    insecure_tunnels: bool,
    log: Option<String>,
    metrics: Option<MetricsConfig>,
    net_id: Option<u8>,
    ntcp2: Option<Ntcp2Config>,
    #[serde(rename = "port-forwarding")]
    port_forwarding: Option<PortForwardingConfig>,
    reseed: Option<ReseedConfig>,
    sam: Option<SamConfig>,
    ssu2: Option<Ssu2Config>,
    transit: Option<TransitConfig>,
    #[serde(rename = "client-tunnels")]
    client_tunnels: Option<Vec<ClientTunnelConfig>>,
    #[serde(rename = "server-tunnels")]
    server_tunnels: Option<Vec<ServerTunnelConfig>>,
    #[serde(rename = "router-ui")]
    router_ui: Option<RouterUiConfig>,
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
                        let port: u16 = rand::thread_rng().gen_range(9151..=30777);

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
    pub port_forwarding: Option<PortForwardingConfig>,

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
    pub fn parse(path: Option<PathBuf>, arguments: &Arguments) -> Result<Self, Error> {
        let path = path
            .map_or_else(
                || {
                    let mut path = home_dir()?;
                    (!path.as_os_str().is_empty()).then(|| {
                        path.push(".emissary");
                        path
                    })
                },
                Some,
            )
            .ok_or(Error::Custom(String::from("couldn't resolve base path")))?;

        tracing::trace!(
            target: LOG_TARGET,
            ?path,
            "parse router config",
        );

        // if base path doesn't exist, create it and return empty config
        if !path.exists() {
            fs::create_dir_all(&path)?;
            Config::create_netdb_dir(path.join("netDb"))?;
            Config::create_profiles_dir(path.join("peerProfiles"))?;

            return Config::new_empty(path);
        }

        if !path.join("netDb").exists() {
            Config::create_netdb_dir(path.join("netDb"))?;
        }

        if !path.join("peerProfiles").exists() {
            Config::create_profiles_dir(path.join("peerProfiles"))?;
        }

        // read static & signing keys from disk or generate new ones
        let static_key = match Self::load_key(path.clone(), "static") {
            Ok(key) => x25519_dalek::StaticSecret::from(key).to_bytes(),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load static key, regenerating",
                );

                Self::create_static_key(path.clone())?
            }
        };

        let signing_key = match Self::load_key(path.clone(), "signing") {
            Ok(key) => ed25519_dalek::SigningKey::from(key).to_bytes(),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load signing key, regenerating",
                );

                Self::create_signing_key(path.clone())?
            }
        };

        let (ntcp2_key, ntcp2_iv) = match Self::load_ntcp2_keys(path.clone()) {
            Ok((key, iv)) => (key, iv),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load ntcp2 keys, regenerating",
                );

                Self::create_ntcp2_keys(path.clone())?
            }
        };

        let (ssu2_static_key, ssu2_intro_key) = match Self::load_ssu2_keys(path.clone()) {
            Ok((key, iv)) => (key, iv),
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    error = %error.to_string(),
                    "failed to load ssu2 keys, regenerating",
                );

                Self::create_ssu2_keys(path.clone())?
            }
        };

        // try to find `router.toml` and parse it into `EmissaryConfig`
        //
        // if the configuration is invalid (`Error::InvaliData`), and `overwrite_config` has been
        // passed, create new default configuration
        //
        // if the option hasn't been passed, exit early and allow user to take a copy of their
        // config before generating a new config
        let router_config = match Self::load_router_config(path.clone()) {
            Err(Error::InvalidData) if arguments.overwrite_config.unwrap_or(false) => None,
            Err(Error::InvalidData) => return Err(Error::InvalidData),
            Err(_) => None,
            Ok(config) => Some(config),
        };
        let router_info = Self::load_router_info(path.clone()).ok();

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
        )?
        .merge(arguments);

        config.routers = Self::load_router_infos(&path);
        config.profiles = Self::load_router_profiles(&path);

        Ok(config)
    }

    /// Create static key.
    fn create_static_key(base_path: PathBuf) -> crate::Result<[u8; 32]> {
        let key = x25519_dalek::StaticSecret::random();
        Self::save_key(base_path, "static", &key).map(|_| key.to_bytes())
    }

    /// Create signing key.
    fn create_signing_key(base_path: PathBuf) -> crate::Result<[u8; 32]> {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Self::save_key(base_path, "signing", key.as_bytes()).map(|_| key.to_bytes())
    }

    /// Create NTCP2 keys and store them on disk.
    fn create_ntcp2_keys(path: PathBuf) -> crate::Result<([u8; 32], [u8; 16])> {
        let key = x25519_dalek::StaticSecret::random().to_bytes().to_vec();
        let iv = {
            let mut iv = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut iv);

            iv
        };

        // append iv to key and write it to disk
        {
            let mut combined = vec![0u8; 32 + 16];
            combined[..32].copy_from_slice(&key);
            combined[32..].copy_from_slice(&iv);

            let mut file = fs::File::create(path.join("ntcp2.keys"))?;
            file.write_all(combined.as_ref())?;
        }

        Ok((TryInto::<[u8; 32]>::try_into(key).expect("to succeed"), iv))
    }

    /// Create SSU2 keys and store them on disk.
    fn create_ssu2_keys(path: PathBuf) -> crate::Result<([u8; 32], [u8; 32])> {
        let static_key = x25519_dalek::StaticSecret::random().to_bytes().to_vec();
        let intro_key = {
            let mut intro_key = [0u8; 32];
            thread_rng().fill_bytes(&mut intro_key);

            intro_key
        };

        // append iv to key and write it to disk
        {
            let mut combined = vec![0u8; 32 + 32];
            combined[..32].copy_from_slice(&static_key);
            combined[32..].copy_from_slice(&intro_key);

            let mut file = fs::File::create(path.join("ssu2.keys"))?;
            file.write_all(combined.as_ref())?;
        }

        Ok((
            TryInto::<[u8; 32]>::try_into(static_key).expect("to succeed"),
            TryInto::<[u8; 32]>::try_into(intro_key).expect("to succeed"),
        ))
    }

    /// Save key to disk.
    fn save_key<K: AsRef<[u8]>>(path: PathBuf, key_type: &str, key: &K) -> crate::Result<()> {
        let mut file = fs::File::create(path.join(format!("{key_type}.key")))?;
        file.write_all(key.as_ref())?;

        Ok(())
    }

    /// Load key from disk.
    fn load_key(path: PathBuf, key_type: &str) -> crate::Result<[u8; 32]> {
        let mut file = fs::File::open(path.join(format!("{key_type}.key")))?;
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;

        Ok(key_bytes)
    }

    /// Load NTCP2 key and IV from disk.
    fn load_ntcp2_keys(path: PathBuf) -> crate::Result<([u8; 32], [u8; 16])> {
        let key_bytes = {
            let mut file = fs::File::open(path.join("ntcp2.keys"))?;
            let mut key_bytes = [0u8; 32 + 16];
            file.read_exact(&mut key_bytes)?;

            key_bytes
        };

        Ok((
            TryInto::<[u8; 32]>::try_into(&key_bytes[..32]).expect("to succeed"),
            TryInto::<[u8; 16]>::try_into(&key_bytes[32..]).expect("to succeed"),
        ))
    }

    /// Load SSU2 static and introduction keys from disk.
    fn load_ssu2_keys(path: PathBuf) -> crate::Result<([u8; 32], [u8; 32])> {
        let key_bytes = {
            let mut file = fs::File::open(path.join("ssu2.keys"))?;
            let mut key_bytes = [0u8; 32 + 32];
            file.read_exact(&mut key_bytes)?;

            key_bytes
        };

        Ok((
            TryInto::<[u8; 32]>::try_into(&key_bytes[..32]).expect("to succeed"),
            TryInto::<[u8; 32]>::try_into(&key_bytes[32..]).expect("to succeed"),
        ))
    }

    fn load_router_config(path: PathBuf) -> crate::Result<EmissaryConfig> {
        // parse configuration, if it exists
        let mut file = fs::File::open(path.join("router.toml"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        toml::from_str::<EmissaryConfig>(&contents).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                %error,
                "failed to parse router config",
            );

            Error::InvalidData
        })
    }

    fn load_router_info(path: PathBuf) -> crate::Result<Vec<u8>> {
        // parse configuration, if it exists
        let mut file = fs::File::open(path.join("router.info"))?;
        let mut contents = Vec::new();

        file.read_to_end(&mut contents).map(|_| contents).map_err(From::from)
    }

    /// Create `netDb` directory.
    fn create_netdb_dir(path: PathBuf) -> crate::Result<()> {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

        // create base directory `.emissary/peerProfiles`
        fs::create_dir_all(&path)?;

        for c in chars.chars() {
            fs::create_dir_all(path.join(format!("r{c}")))?;
        }

        Ok(())
    }

    /// Create `peerProfiles` directory.
    fn create_profiles_dir(path: PathBuf) -> crate::Result<()> {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

        // create base directory `.emissary/peerProfiles`
        fs::create_dir_all(&path)?;

        for c in chars.chars() {
            fs::create_dir_all(path.join(format!("p{c}")))?;
        }

        Ok(())
    }

    /// Create empty config.
    ///
    /// Creates a default config with NTCP2 enabled.
    fn new_empty(base_path: PathBuf) -> crate::Result<Self> {
        let static_key = Self::create_static_key(base_path.clone())?;
        let signing_key = Self::create_signing_key(base_path.clone())?;
        let (ntcp2_key, ntcp2_iv) = Self::create_ntcp2_keys(base_path.clone())?;
        let (_ssu2_static_key, _ssu2_intro_key) = Self::create_ssu2_keys(base_path.clone())?;

        let config = EmissaryConfig::default();
        let serialized = toml::to_string(&config).expect("to succeed");
        let mut file = fs::File::create(base_path.join("router.toml"))?;
        file.write_all(serialized.as_bytes())?;

        tracing::info!(
            target: LOG_TARGET,
            ?base_path,
            "emissary starting for the first time",
        );

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
            ntcp2_config: Some(emissary_core::Ntcp2Config {
                port: config.ntcp2.as_ref().expect("ntcp").port,
                host: None,
                key: ntcp2_key,
                iv: ntcp2_iv,
                publish: true,
            }),
            port_forwarding: config.port_forwarding,
            profiles: Vec::new(),
            reseed: config.reseed,
            router_info: None,
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
            ssu2_config: None,
            static_key,
            transit: config.transit.map(|config| emissary_core::TransitConfig {
                max_tunnels: config.max_tunnels,
            }),
        })
    }

    /// Create new [`Config`].
    fn new(
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
                let mut file = fs::File::create(base_path.join("router.toml"))?;
                file.write_all(toml_config.as_bytes())?;

                config
            }
        };

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
            port_forwarding: config.port_forwarding,
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
        })
    }

    /// Attempt to load router infos.
    fn load_router_infos(path: &Path) -> Vec<Vec<u8>> {
        let Ok(router_dir) = fs::read_dir(path.join("netDb")) else {
            return Vec::new();
        };

        router_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?.path();

                if !dir.is_dir() {
                    return None;
                }

                Some(
                    fs::read_dir(dir)
                        .ok()?
                        .filter_map(|entry| {
                            let file_path = entry.ok()?.path();

                            if !file_path.is_file() {
                                return None;
                            }

                            let mut file = fs::File::open(file_path).ok()?;

                            let mut contents = Vec::new();
                            file.read_to_end(&mut contents).ok()?;

                            Some(contents)
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    /// Attempt to load router profiles.
    fn load_router_profiles(path: &Path) -> Vec<(String, emissary_core::Profile)> {
        let Ok(profile_dir) = fs::read_dir(path.join("peerProfiles")) else {
            return Vec::new();
        };

        profile_dir
            .into_iter()
            .filter_map(|entry| {
                let dir = entry.ok()?.path();

                if !dir.is_dir() {
                    return None;
                }

                Some(
                    fs::read_dir(dir)
                        .ok()?
                        .filter_map(|entry| {
                            let file_path = entry.ok()?.path();

                            if !file_path.is_file() {
                                return None;
                            }

                            let mut file = fs::File::open(&file_path).ok()?;

                            let mut contents = String::new();
                            file.read_to_string(&mut contents).ok()?;

                            let profile = toml::from_str::<Profile>(&contents).ok()?;
                            let name = {
                                let input = file_path.to_str().expect("to succeed");
                                let start = input.find("profile-")?;
                                let start = start + "profile-".len();
                                let end = input.find(".toml")?;

                                input[start..end].to_string()
                            };

                            Some((
                                name,
                                emissary_core::Profile {
                                    last_activity: Duration::from_secs(
                                        profile.last_activity.unwrap_or(0),
                                    ),
                                    last_declined: profile.last_declined.map(Duration::from_secs),
                                    last_dial_failure: profile
                                        .last_dial_failure
                                        .map(Duration::from_secs),
                                    num_accepted: profile.num_accepted.unwrap_or(0),
                                    num_connection: profile.num_connection.unwrap_or(0),
                                    num_dial_failures: profile.num_dial_failures.unwrap_or(0),
                                    num_lookup_failures: profile.num_lookup_failures.unwrap_or(0),
                                    num_lookup_no_responses: profile
                                        .num_lookup_no_responses
                                        .unwrap_or(0),
                                    num_lookup_successes: profile.num_lookup_successes.unwrap_or(0),
                                    num_rejected: profile.num_rejected.unwrap_or(0),
                                    num_selected: profile.num_selected.unwrap_or(0),
                                    num_test_failures: profile.num_test_failures.unwrap_or(0),
                                    num_test_successes: profile.num_test_successes.unwrap_or(0),
                                    num_unaswered: profile.num_unaswered.unwrap_or(0),
                                },
                            ))
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .flatten()
            .collect::<Vec<_>>()
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

        if let Some(PortForwardingConfig {
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
    use std::fs::File;
    use tempfile::tempdir;

    fn make_arguments() -> Arguments {
        Arguments {
            base_path: None,
            log: None,
            #[cfg(any(
                all(feature = "native-ui", not(feature = "web-ui")),
                all(not(feature = "native-ui"), feature = "web-ui")
            ))]
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

    #[test]
    fn fresh_boot_directory_created() {
        let dir = tempdir().unwrap();
        let config = Config::parse(Some(dir.path().to_owned()), &make_arguments()).unwrap();

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
            let mut file = File::open(&path).unwrap();

            let mut contents = [0u8; 48];
            file.read_exact(&mut contents).unwrap();

            (
                TryInto::<[u8; 32]>::try_into(&contents[..32]).expect("to succeed"),
                TryInto::<[u8; 16]>::try_into(&contents[32..]).expect("to succeed"),
            )
        };

        assert_eq!(config.ntcp2_config.as_ref().unwrap().key, key);
        assert_eq!(config.ntcp2_config.as_ref().unwrap().iv, iv);
    }

    #[test]
    fn load_configs_correctly() {
        let dir = tempdir().unwrap();

        let (static_key, signing_key, ntcp2_config) = {
            let config = Config::parse(Some(dir.path().to_owned()), &make_arguments()).unwrap();
            (config.static_key, config.signing_key, config.ntcp2_config)
        };

        let config = Config::parse(Some(dir.path().to_owned()), &make_arguments()).unwrap();
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

    #[test]
    fn config_update_works() {
        let dir = tempdir().unwrap();

        // create default config, verify the default ntcp2 port is 8888
        let (ntcp2_key, ntcp2_iv) = {
            let config = Config::parse(Some(dir.path().to_owned()), &make_arguments()).unwrap();
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
        let mut file = fs::File::create(dir.path().to_owned().join("router.toml")).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        // load the new config
        //
        // verify that ntcp2 key & iv are the same but port is new
        let config = Config::parse(Some(dir.path().to_owned()), &make_arguments()).unwrap();
        let ntcp2_config = config.ntcp2_config.unwrap();

        assert_eq!(ntcp2_config.port, 1337u16);
        assert_eq!(ntcp2_config.key, ntcp2_key);
        assert_eq!(ntcp2_config.iv, ntcp2_iv);
    }

    #[test]
    fn overwrite_config() {
        let dir = tempdir().unwrap();

        let mut file = fs::File::create(dir.path().to_owned().join("router.toml")).unwrap();
        file.write_all("hello, world!".as_bytes()).unwrap();

        let mut args = make_arguments();

        // create default config, verify the default ntcp2 port is 8888
        match Config::parse(Some(dir.path().to_owned()), &args) {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        }

        // allow emissary to overwrite config
        args.overwrite_config = Some(true);

        // verify default config is created
        let config = Config::parse(Some(dir.path().to_owned()), &args).unwrap();

        assert!(config.ntcp2_config.is_some());
        assert!(config.sam_config.is_some());
        assert!(config.address_book.is_some());
        assert!(config.http_proxy.is_some());
        assert!(!config.floodfill);
        assert!(!config.insecure_tunnels);
        assert!(!config.allow_local);
    }

    #[test]
    fn client_tunnels_with_same_names() {
        let dir = tempdir().unwrap();

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
        let mut file = fs::File::create(dir.path().to_owned().join("router.toml")).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        match Config::parse(Some(dir.path().to_owned()), &make_arguments()) {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn client_tunnels_with_same_ports() {
        let dir = tempdir().unwrap();

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
        let mut file = fs::File::create(dir.path().to_owned().join("router.toml")).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        match Config::parse(Some(dir.path().to_owned()), &make_arguments()) {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        }
    }
}
