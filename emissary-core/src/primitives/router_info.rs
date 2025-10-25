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
    config::Config,
    crypto::{base64_decode, SigningPrivateKey, StaticPrivateKey, StaticPublicKey},
    error::parser::RouterInfoParseError,
    primitives::{
        router_address::TransportKind, Capabilities, Date, Mapping, RouterAddress, RouterIdentity,
        Str, LOG_TARGET,
    },
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use hashbrown::HashMap;
use nom::{number::complete::be_u8, Err, IResult};

use alloc::{string::ToString, vec::Vec};

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// Router information
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// Router addresses.
    pub addresses: HashMap<TransportKind, RouterAddress>,

    /// Router capabilities.
    pub capabilities: Capabilities,

    /// Router identity.
    pub identity: RouterIdentity,

    /// Network ID.
    pub net_id: u8,

    /// Router options.
    pub options: Mapping,

    /// When the router info was published.
    pub published: Date,
}

impl RouterInfo {
    /// Create new [`RouterInfo`].
    ///
    /// `ntcp2` is `Some` if NTCP has been enabled.
    pub fn new<R: Runtime>(
        config: &Config,
        ntcp2: Option<RouterAddress>,
        ssu2: Option<RouterAddress>,
        static_key: &StaticPrivateKey,
        signing_key: &SigningPrivateKey,
        transit_tunnels_disabled: bool,
    ) -> Self {
        let Config {
            caps, router_info, ..
        } = config;

        let identity = match router_info {
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "generating new router identity",
                );

                RouterIdentity::from_keys::<R>(static_key, signing_key).expect("to succeed")
            }
            Some(router_info) => RouterIdentity::parse(router_info).expect("to succeed"),
        };

        let mut options = Mapping::default();
        options.insert(
            Str::from("netId"),
            config
                .net_id
                .map_or_else(|| Str::from("2"), |value| Str::from(value.to_string())),
        );

        let caps = match transit_tunnels_disabled {
            true => Str::from("G"),
            false => match caps {
                Some(caps) => Str::from(caps.clone()),
                None => match config.floodfill {
                    true => Str::from("Xf"),
                    false => Str::from("L"),
                },
            },
        };

        options.insert(Str::from("router.version"), Str::from("0.9.62"));
        options.insert(Str::from("caps"), caps.clone());

        RouterInfo {
            addresses: {
                let mut addresses = HashMap::<TransportKind, RouterAddress>::new();

                if let Some(ntcp2) = ntcp2 {
                    addresses.insert(TransportKind::Ntcp2, ntcp2);
                }

                if let Some(ssu2) = ssu2 {
                    addresses.insert(TransportKind::Ssu2, ssu2);
                }

                addresses
            },
            capabilities: Capabilities::parse(&caps).expect("to succeed"),
            identity,
            net_id: config.net_id.unwrap_or(2),
            options,
            published: Date::new(R::time_since_epoch().as_millis() as u64),
        }
    }

    fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterInfo, RouterInfoParseError> {
        let (rest, identity) = RouterIdentity::parse_frame(input).map_err(Err::convert)?;
        let (rest, published) = Date::parse_frame(rest).map_err(Err::convert)?;
        let (rest, num_addresses) = be_u8(rest)?;
        let (rest, addresses) = (0..num_addresses)
            .try_fold(
                (rest, HashMap::<TransportKind, RouterAddress>::new()),
                |(rest, mut addresses), _| {
                    let (rest, address) = RouterAddress::parse_frame(rest).ok()?;

                    // prefer `RouterAddress` which has a socket address specified
                    match addresses.get(&address.transport) {
                        None => {
                            addresses.insert(address.transport, address);
                        }
                        Some(old_address) =>
                            if old_address.socket_address.is_none() {
                                addresses.insert(address.transport, address);
                            },
                    }

                    Some((rest, addresses))
                },
            )
            .ok_or(Err::Error(RouterInfoParseError::InvalidBitstream))?;

        // ignore `peer_size`
        let (rest, _) = be_u8(rest)?;
        let (rest, options) = Mapping::parse_frame(rest).map_err(Err::convert)?;

        let capabilities = match options.get(&Str::from("caps")) {
            None => return Err(Err::Error(RouterInfoParseError::CapabilitiesMissing)),
            Some(caps) => match Capabilities::parse(caps) {
                Some(caps) => caps,
                None => {
                    return Err(Err::Error(RouterInfoParseError::InvalidCapabilities(
                        caps.clone(),
                    )));
                }
            },
        };

        let net_id = match options.get(&Str::from("netId")) {
            None => return Err(Err::Error(RouterInfoParseError::NetIdMissing)),
            Some(net_id) => net_id
                .parse::<u8>()
                .map_err(|_| Err::Error(RouterInfoParseError::NetIdMissing))?,
        };

        identity
            .signing_key()
            .verify(&input[..input.len() - SIGNATURE_LEN], rest)
            .map_err(|_| Err::Error(RouterInfoParseError::InvalidSignature))?;

        Ok((
            rest,
            RouterInfo {
                identity,
                published,
                addresses,
                options,
                capabilities,
                net_id,
            },
        ))
    }

    /// Serialize [`RouterInfo`] into a byte vector.
    pub fn serialize(&self, signing_key: &SigningPrivateKey) -> Vec<u8> {
        let identity = self.identity.serialize();
        let published = self.published.serialize();
        let maybe_ntcp2 =
            self.addresses.get(&TransportKind::Ntcp2).map(|address| address.serialize());
        let maybe_ssu2 =
            self.addresses.get(&TransportKind::Ssu2).map(|address| address.serialize());
        let options = self.options.serialize();

        let size = identity
            .len()
            .saturating_add(published.len())
            .saturating_add(1usize) // field for router address count
            .saturating_add(maybe_ntcp2.as_ref().map_or(0usize, |address| address.len()))
            .saturating_add(maybe_ssu2.as_ref().map_or(0usize, |address| address.len()))
            .saturating_add(options.len())
            .saturating_add(1usize) // psize
            .saturating_add(64usize); // signature

        let mut out = BytesMut::with_capacity(size);

        out.put_slice(&identity);
        out.put_slice(&published);

        match (maybe_ntcp2, maybe_ssu2) {
            (Some(ntcp2), Some(ssu2)) => {
                out.put_u8(2u8);
                out.put_slice(&ntcp2);
                out.put_slice(&ssu2);
            }
            (Some(info), None) | (None, Some(info)) => {
                out.put_u8(1u8);
                out.put_slice(&info);
            }
            (None, None) => panic!("tried to publish router info with no addresses"),
        }

        out.put_u8(0u8); // psize
        out.put_slice(&options);

        let signature = signing_key.sign(&out[..size - 64]);
        out.put_slice(&signature);

        out.to_vec()
    }

    /// Try to parse router information from `bytes`.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, RouterInfoParseError> {
        Ok(Self::parse_frame(bytes.as_ref())?.1)
    }

    /// Returns `true` if the router is a floodfill router.
    pub fn is_floodfill(&self) -> bool {
        self.capabilities.is_floodfill()
    }

    /// Returns `true` if the router is considered reachable.
    ///
    /// Router is considered reachable if its caps don't specify otherwise and it has at least one
    /// published address.
    pub fn is_reachable(&self) -> bool {
        if !self.capabilities.is_reachable() {
            return false;
        }

        if let Some(ntcp2) = self.addresses.get(&TransportKind::Ntcp2) {
            if ntcp2.options.get(&Str::from("host")).is_some()
                && ntcp2.options.get(&Str::from("port")).is_some()
            {
                return true;
            }
        }

        if let Some(ssu2) = self.addresses.get(&TransportKind::Ssu2) {
            if ssu2.options.get(&Str::from("host")).is_some()
                && ssu2.options.get(&Str::from("port")).is_some()
            {
                return true;
            }
        }

        false
    }

    /// Is the router usable.
    ///
    /// Any router who hasn't published `G` or `E` congestion caps is considered usable.
    pub fn is_usable(&self) -> bool {
        self.capabilities.is_usable()
    }

    /// Get network ID of the [`RouterInfo`].
    pub fn net_id(&self) -> u8 {
        self.net_id
    }

    /// Check if the router is reachable via NTCP2.
    pub fn is_reachable_ntcp2(&self) -> bool {
        let Some(ntcp2) = self.addresses.get(&TransportKind::Ntcp2) else {
            return false;
        };

        ntcp2.socket_address.is_some()
            && ntcp2.options.get(&Str::from("i")).is_some()
            && ntcp2.options.get(&Str::from("s")).is_some()
    }

    /// Attempt to get SSU2 intro key from [`RouterInfo`]
    pub fn ssu2_intro_key(&self) -> Option<[u8; 32]> {
        let intro_key = self.addresses.get(&TransportKind::Ssu2)?.options.get(&Str::from("i"))?;
        let intro_key = base64_decode(intro_key.as_bytes())?;

        TryInto::<[u8; 32]>::try_into(intro_key).ok()
    }

    /// Attempt to get SSU2 static key from [`RouterInfo`].
    pub fn ssu2_static_key(&self) -> Option<StaticPublicKey> {
        let static_key = self.addresses.get(&TransportKind::Ssu2)?.options.get(&Str::from("s"))?;
        let static_key = base64_decode(static_key.as_bytes())?;

        StaticPublicKey::from_bytes(&static_key)
    }

    /// Attempt to get NTCP2 static key from [`RouterInfo`].
    pub fn ntcp2_static_key(&self) -> Option<StaticPublicKey> {
        let static_key = self.addresses.get(&TransportKind::Ntcp2)?.options.get(&Str::from("s"))?;
        let static_key = base64_decode(static_key.as_bytes())?;

        StaticPublicKey::from_bytes(&static_key)
    }

    /// Attempt to get NTCP2 IV from [`RouterInfo`].
    pub fn ntcp2_iv(&self) -> Option<[u8; 16]> {
        let iv = self.addresses.get(&TransportKind::Ntcp2)?.options.get(&Str::from("i"))?;
        let iv = base64_decode(iv.as_bytes())?;

        TryInto::<[u8; 16]>::try_into(iv).ok()
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct RouterInfoBuilder {
    floodfill: bool,
    static_key: Option<Vec<u8>>,
    signing_key: Option<Vec<u8>>,
    ntcp2: Option<crate::Ntcp2Config>,
    ssu2: Option<crate::Ssu2Config>,
}

#[cfg(test)]
impl RouterInfoBuilder {
    /// Mark the router as floodfill
    pub fn as_floodfill(mut self) -> Self {
        self.floodfill = true;
        self
    }

    /// Specify static key.
    pub fn with_static_key(mut self, static_key: Vec<u8>) -> Self {
        self.static_key = Some(static_key);
        self
    }

    /// Specify signing key.
    pub fn with_signing_key(mut self, signing_key: Vec<u8>) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Specify NTCP configuration.
    pub fn with_ntcp2(mut self, ntcp2: crate::Ntcp2Config) -> Self {
        self.ntcp2 = Some(ntcp2);
        self
    }

    /// Specify SSU2 configuration.
    pub fn with_ssu2(mut self, ssu2: crate::Ssu2Config) -> Self {
        self.ssu2 = Some(ssu2);
        self
    }

    /// Build [`RouterInfoBuilder`] into a [`RouterInfo].
    pub fn build(&mut self) -> (RouterInfo, StaticPrivateKey, SigningPrivateKey) {
        use crate::{runtime::mock::MockRuntime, Ntcp2Config, Ssu2Config};
        use rand_core::RngCore;

        let static_key = match self.static_key.take() {
            Some(key) => StaticPrivateKey::from_bytes(&key).unwrap(),
            None => StaticPrivateKey::random(rand::thread_rng()),
        };
        let signing_key = match self.signing_key.take() {
            Some(key) => SigningPrivateKey::from_bytes(&key).unwrap(),
            None => SigningPrivateKey::random(rand::thread_rng()),
        };
        let identity = RouterIdentity::from_keys::<MockRuntime>(&static_key, &signing_key)
            .expect("to succeed");

        let mut ntcp2 = match self.ntcp2.take() {
            None => None,
            Some(Ntcp2Config {
                port,
                host,
                publish,
                key,
                iv,
            }) => match (publish, host) {
                (true, Some(host)) => Some(RouterAddress::new_published_ntcp2(key, iv, port, host)),
                (_, _) => Some(RouterAddress::new_unpublished_ntcp2(key, port)),
            },
        };
        let mut ssu2 = match self.ssu2.take() {
            None => None,
            Some(Ssu2Config {
                port,
                host,
                publish,
                static_key,
                intro_key,
            }) => match (publish, host) {
                (true, Some(host)) => Some(RouterAddress::new_published_ssu2(
                    static_key, intro_key, port, host,
                )),
                (_, _) => Some(RouterAddress::new_unpublished_ssu2(
                    static_key, intro_key, port,
                )),
            },
        };

        // create default ntcp2 transport if neither transport was explicitly enabled
        if ntcp2.is_none() && ssu2.is_none() {
            let ntcp2_port = MockRuntime::rng().next_u32() as u16;
            let ntcp2_host = format!(
                "{}.{}.{}.{}",
                {
                    loop {
                        let address = MockRuntime::rng().next_u32() % 256;

                        if address != 0 {
                            break address;
                        }
                    }
                },
                MockRuntime::rng().next_u32() % 256,
                MockRuntime::rng().next_u32() % 256,
                MockRuntime::rng().next_u32() % 256,
            );
            let ntcp2_key = {
                let mut key_bytes = [0u8; 32];
                MockRuntime::rng().fill_bytes(&mut key_bytes);

                key_bytes
            };
            let ntcp2_iv = {
                let mut iv_bytes = [0u8; 16];
                MockRuntime::rng().fill_bytes(&mut iv_bytes);

                iv_bytes
            };

            ntcp2 = Some(RouterAddress::new_published_ntcp2(
                ntcp2_key,
                ntcp2_iv,
                ntcp2_port,
                ntcp2_host.parse().unwrap(),
            ));
        }

        let mut options = Mapping::default();
        options.insert("netId".into(), "2".into());
        options.insert("router.version".into(), "0.9.62".into());

        let capabilities = if self.floodfill {
            options.insert(Str::from("caps"), Str::from("XfR"));
            Capabilities::parse(&Str::from("XfR")).expect("to succeed")
        } else {
            options.insert(Str::from("caps"), Str::from("L"));
            Capabilities::parse(&Str::from("L")).expect("to succeed")
        };

        let mut addresses = HashMap::<TransportKind, RouterAddress>::new();

        if let Some(ntcp2) = ntcp2.take() {
            addresses.insert(TransportKind::Ntcp2, ntcp2);
        }

        if let Some(ssu2) = ssu2.take() {
            addresses.insert(TransportKind::Ssu2, ssu2);
        }

        (
            RouterInfo {
                addresses,
                capabilities,
                identity,
                net_id: 2,
                options,
                published: Date::new(MockRuntime::rng().next_u64()),
            },
            static_key,
            signing_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::parser::RouterIdentityParseError,
        runtime::{mock::MockRuntime, Runtime},
    };
    use std::{str::FromStr, time::Duration};

    #[test]
    fn parse_router_1() {
        let router_info_bytes = include_bytes!("../../test-vectors/router1.dat");
        let router_info = RouterInfo::parse(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost,
            5
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("2.36.209.134").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("23154").unwrap())
        );

        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost,
            11
        );

        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from("host")),
            Some(&Str::from("2.36.209.134"))
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("1403").unwrap())
        );

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.64").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("NRD").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_2() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");
        let router_info = RouterInfo::parse(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost,
            8,
        );
        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost,
            3
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("64.53.67.11").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("25313").unwrap())
        );

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.58").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("XR").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_3() {
        let router_info_bytes = include_bytes!("../../test-vectors/router3.dat");
        assert_eq!(
            RouterInfo::parse(router_info_bytes).unwrap_err(),
            RouterInfoParseError::InvalidIdentity(RouterIdentityParseError::InvalidPublicKey(0))
        );
    }

    #[test]
    fn is_not_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");

        assert!(!RouterInfo::parse(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn is_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router4.dat");

        assert!(RouterInfo::parse(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn net_id_missing() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: Mapping::from_iter([(Str::from("caps"), Str::from("L"))]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
        }
        .serialize(&sgk);

        assert_eq!(
            RouterInfo::parse(&serialized).unwrap_err(),
            RouterInfoParseError::NetIdMissing
        );
    }

    #[test]
    fn caps_missing() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: Mapping::from_iter([(Str::from("netId"), Str::from("2"))]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
        }
        .serialize(&sgk);

        assert_eq!(
            RouterInfo::parse(&serialized).unwrap_err(),
            RouterInfoParseError::CapabilitiesMissing
        );
    }

    #[test]
    fn hidden_router_not_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("HL")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("HL")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn unreachable_router_not_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
            )]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("UL")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("UL")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn reachable_but_no_published_address() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
            )]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn reachable_explicitly_specified() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    // router doesn't explicitly specify the `R` flag
    #[test]
    fn maybe_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published_ntcp2(
                    [1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".parse().unwrap(),
                ),
            )]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("Xf")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("Xf")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn ssu2_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([
                (
                    TransportKind::Ntcp2,
                    RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                ),
                (
                    TransportKind::Ssu2,
                    RouterAddress::new_published_ssu2(
                        [1u8; 32],
                        [2u8; 32],
                        8888,
                        "127.0.0.1".parse().unwrap(),
                    ),
                ),
            ]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn ntcp2_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([
                (
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [2u8; 16],
                        8888,
                        "127.0.0.1".parse().unwrap(),
                    ),
                ),
                (
                    TransportKind::Ssu2,
                    RouterAddress::new_published_ssu2(
                        [1u8; 32],
                        [2u8; 32],
                        8888,
                        "127.0.0.1".parse().unwrap(),
                    ),
                ),
            ]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn both_transports_unpublished() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([
                (
                    TransportKind::Ntcp2,
                    RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                ),
                (
                    TransportKind::Ssu2,
                    RouterAddress::new_unpublished_ssu2([1u8; 32], [2u8; 32], 8888),
                ),
            ]),
            options: Mapping::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LU")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }
}
