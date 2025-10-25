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
    crypto::{SigningPrivateKey, SigningPublicKey, StaticPublicKey},
    error::parser::LeaseSetParseError,
    primitives::{Destination, Mapping, OfflineSignature, RouterId, TunnelId, LOG_TARGET},
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};

use alloc::{collections::BTreeSet, vec::Vec};
use core::{fmt, iter, time::Duration};

/// [`LeaseSet2`] is unpublished.
///
/// <https://geti2p.net/spec/common-structures#leaseset2header>
const UNPUBLISHED: u16 = 1u16 << 1;

/// Header for [`LeaseSet2`].
///
/// https://geti2p.net/spec/common-structures#leaseset2header
#[derive(Clone, Debug)]
pub struct LeaseSet2Header {
    /// Destination for [`LeaseSet2`].
    pub destination: Destination,

    /// When [`LeaseSet2`] expires.
    pub expires: u32,

    /// Offline key, if specified.
    pub offline_signature: Option<SigningPublicKey>,

    /// When [`LeaseSet2`] was published.
    pub published: u32,

    /// Should the [`LeaseSet2`] stay unpublished.
    pub is_unpublished: bool,
}

impl LeaseSet2Header {
    /// Attempt to parse [`LeaseSet2Header`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame<R: Runtime>(input: &[u8]) -> IResult<&[u8], Self, LeaseSetParseError> {
        let (rest, destination) = Destination::parse_frame(input).map_err(Err::convert)?;
        let (rest, published) = be_u32(rest)?;
        let (rest, expires) = be_u16(rest)?;
        let (rest, flags) = be_u16(rest)?;

        // no offline signature
        if flags & 1 == 0 {
            return Ok((
                rest,
                Self {
                    destination,
                    expires: published.saturating_add(expires as u32),
                    is_unpublished: (flags >> 1) & 1 == 1,
                    offline_signature: None,
                    published,
                },
            ));
        }

        // parse and verify offline signature and get key for verifying the lease set's signature
        let (rest, verifying_key) =
            OfflineSignature::parse_frame::<R>(rest, destination.verifying_key())
                .map_err(Err::convert)?;

        Ok((
            rest,
            Self {
                destination,
                expires: published.saturating_add(expires as u32),
                is_unpublished: (flags >> 1) & 1 == 1,
                offline_signature: Some(verifying_key),
                published,
            },
        ))
    }

    /// Get serialized length of [`LeaseSet2Header`].
    pub fn serialized_len(&self) -> usize {
        // destination + published + expires + flags
        self.destination.serialized_len() + 4usize + 2usize + 2usize
    }

    /// Serialize [`LeaseSet2Header`] into a byte vector.
    pub fn serialize(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.serialized_len());

        out.put_slice(&self.destination.serialize());
        out.put_u32(self.published);
        out.put_u16(self.expires as u16);
        out.put_u16(if self.is_unpublished {
            UNPUBLISHED
        } else {
            0u16
        });

        out
    }
}

/// Lease
///
/// [`Lease`] is common for `Lease` [1] and `Lease2` [2] and a difference
/// is made made only when serializing/deserializing them.
///
/// [1] https://geti2p.net/spec/common-structures#struct-lease
/// [2] https://geti2p.net/spec/common-structures#struct-lease2
#[derive(Clone, PartialEq, Eq)]
pub struct Lease {
    /// ID of the gateway router.
    pub router_id: RouterId,

    /// ID of the tunnel gateway.
    pub tunnel_id: TunnelId,

    /// When the lease expires.
    pub expires: Duration,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("router_id", &format_args!("{}", self.router_id))
            .field("tunnel_id", &self.tunnel_id)
            .field("expires", &self.expires)
            .finish()
    }
}

impl Lease {
    /// Attempt to parse `Lease2` from `input`.
    ///
    /// Returns the parsed lease and rest of `input` on success.
    pub fn parse_frame_lease2(input: &[u8]) -> IResult<&[u8], Self, LeaseSetParseError> {
        let (rest, tunnel_gateway) = take(32usize)(input)?;
        let (rest, tunnel_id) = be_u32(rest)?;
        let (rest, expires) = be_u32(rest)?;

        Ok((
            rest,
            Self {
                router_id: RouterId::from(tunnel_gateway),
                tunnel_id: TunnelId::from(tunnel_id),
                expires: Duration::from_secs(expires as u64),
            },
        ))
    }

    /// Attempt to parse `Lease` from `input`.
    ///
    /// Returns the parsed lease and rest of `input` on success.
    pub fn parse_frame_lease(input: &[u8]) -> IResult<&[u8], Self, LeaseSetParseError> {
        let (rest, tunnel_gateway) = take(32usize)(input)?;
        let (rest, tunnel_id) = be_u32(rest)?;
        let (rest, expires) = be_u64(rest)?;

        Ok((
            rest,
            Self {
                router_id: RouterId::from(tunnel_gateway),
                tunnel_id: TunnelId::from(tunnel_id),
                expires: Duration::from_millis(expires),
            },
        ))
    }

    /// Get serialized length of `Lease2`.
    pub fn serialized_len_lease2(&self) -> usize {
        // router hash length + tunnel id + expiration
        32usize + 4usize + 4usize
    }

    /// Get serialized length of `Lease`.
    pub fn serialized_len_lease(&self) -> usize {
        // router hash length + tunnel id + expiration
        32usize + 4usize + 8usize
    }

    /// Serialize [`Lease`] into a byte vector representing `Lease`.
    pub fn serialize_lease(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32usize + 4 + 8);

        out.put_slice(&Into::<Vec<u8>>::into(self.router_id));
        out.put_u32(*self.tunnel_id);
        out.put_u64(self.expires.as_millis() as u64);

        out.freeze().to_vec()
    }

    /// Serialize [`Lease`] into a byte vector representing `Lease2`.
    pub fn serialize_lease2(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32usize + 4 + 4);

        out.put_slice(&Into::<Vec<u8>>::into(self.router_id));
        out.put_u32(*self.tunnel_id);
        out.put_u32(self.expires.as_secs() as u32);

        out.freeze().to_vec()
    }
}

#[cfg(test)]
impl Lease {
    /// Create random [`Lease`].
    pub fn random() -> Self {
        Self {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("to succeed")
                + Duration::from_secs(10 * 60),
        }
    }
}

/// LeaseSet2
///
/// Parse lease set is guaranteed to contain at least one lease.
///
/// https://geti2p.net/spec/common-structures#struct-leaseset2
#[derive(Clone, Debug)]
pub struct LeaseSet2 {
    /// Header.
    pub header: LeaseSet2Header,

    /// Public keys.
    pub public_keys: Vec<StaticPublicKey>,

    /// Leases.
    pub leases: Vec<Lease>,
}

impl LeaseSet2 {
    /// Attempt to parse [`LeaseSet2`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame<R: Runtime>(input: &[u8]) -> IResult<&[u8], Self, LeaseSetParseError> {
        let (rest, header) = LeaseSet2Header::parse_frame::<R>(input).map_err(Err::convert)?;
        let (rest, _) = Mapping::parse_frame(rest).map_err(Err::convert)?;
        let (rest, num_key_types) = be_u8(rest)?;

        let (rest, public_keys) = (0..num_key_types)
            .try_fold(
                (rest, Vec::<StaticPublicKey>::new()),
                |(rest, mut public_keys), _| {
                    let (rest, pubkey_type) = be_u16::<&[u8], ()>(rest).ok()?;
                    let (rest, pubkey_len) = be_u16::<&[u8], ()>(rest).ok()?;
                    let (rest, pubkey) =
                        take::<usize, &[u8], ()>(pubkey_len as usize)(rest).ok()?;

                    match pubkey_type {
                        0x0004 => {
                            let key = StaticPublicKey::from_bytes(pubkey)?;
                            public_keys.push(key);

                            Some((rest, public_keys))
                        }
                        pubkey_type => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?pubkey_type,
                                "ignoring public key"
                            );

                            Some((rest, public_keys))
                        }
                    }
                },
            )
            .ok_or(Err::Error(LeaseSetParseError::InvalidBitstream))?;

        // for now, emissary only supports curve25519-based crypto
        if public_keys.is_empty() {
            return Err(Err::Error(LeaseSetParseError::NoSupportedPublicKey));
        }

        let (rest, num_leases) = be_u8(rest)?;

        if num_leases > 16 || num_leases == 0 {
            return Err(Err::Error(LeaseSetParseError::InvalidLeaseCount(
                num_leases,
            )));
        }

        let (rest, leases) = (0..num_leases)
            .try_fold((rest, Vec::<Lease>::new()), |(rest, mut leases), _| {
                let (rest, lease) = Lease::parse_frame_lease2(rest).ok()?;
                leases.push(lease);

                Some((rest, leases))
            })
            .ok_or(Err::Error(LeaseSetParseError::InvalidLeaseList))?;

        // ensure that lease set contains at least one valid lease
        // before returning so the caller doesn't have make this check.
        if leases.is_empty() {
            return Err(Err::Error(LeaseSetParseError::NoValidLeases));
        }

        // verify signature
        //
        // TODO: optimize?
        let (rest, signature) = take(header.destination.verifying_key().signature_len())(rest)?;

        let mut bytes = BytesMut::with_capacity(input.len());
        bytes.put_u8(3u8);
        bytes.put_slice(
            &input[..input.len() - rest.len() - header.destination.verifying_key().signature_len()],
        );

        match &header.offline_signature {
            None => {
                header
                    .destination
                    .verifying_key()
                    .verify(&bytes, signature)
                    .map_err(|_| Err::Error(LeaseSetParseError::InvalidSignature))?;
            }
            Some(verifying_key) => {
                verifying_key
                    .verify(&bytes, signature)
                    .map_err(|_| Err::Error(LeaseSetParseError::InvalidOfflineSignature))?;
            }
        }

        Ok((
            rest,
            Self {
                header,
                public_keys,
                leases,
            },
        ))
    }

    /// Attempt to parse `input` into [`LeaseSet2`].
    pub fn parse<R: Runtime>(input: &[u8]) -> Result<Self, LeaseSetParseError> {
        Ok(Self::parse_frame::<R>(input)?.1)
    }

    /// Get serialized length of [`LeaseSet2`].
    pub fn serialized_len(&self) -> usize {
        // header + no options + public keys + leases
        self.header.serialized_len()
            + 2usize
            + self.public_keys.iter().fold(0usize, |acc, _| acc + 32)
            + self.leases.iter().fold(0usize, |acc, x| acc + x.serialized_len_lease2())
            + 64usize // signature
    }

    /// Serialize [`LeaseSet2`] into a byte vector.
    pub fn serialize(self, signing_key: &SigningPrivateKey) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.serialized_len() + 1); // + 1 for signature

        out.put_u8(3u8); // leaset2
        out.put_slice(&self.header.serialize());
        out.put_u16(0u16); // no options
        out.put_u8(self.public_keys.len() as u8);

        self.public_keys.into_iter().for_each(|key| {
            out.put_u16(4); // x25519
            out.put_u16(32u16); // x25519 public key length
            out.put_slice(key.as_ref());
        });

        out.put_u8(self.leases.len() as u8);

        self.leases.into_iter().for_each(|lease| {
            out.put_slice(&lease.serialize_lease2());
        });

        let signature = signing_key.sign(&out[..out.len()]);
        out.put_slice(&signature);

        out[1..].to_vec()
    }

    /// Has the [`LeaseSet2`] expired.
    pub fn is_expired<R: Runtime>(&self) -> bool {
        let now = R::time_since_epoch();

        self.header.expires < now.as_secs() as u32
            || self.leases.iter().all(|lease| lease.expires < now)
    }

    /// When does the [`LeaseSet2`] expires, from seconds since epoch.
    pub fn expires(&self) -> Duration {
        // expiration must exist since the header contains an expiration and a valid (parsed)
        // `LeaseSet2` always contains at least one `Lease` which in turn contains an expiration
        Duration::from_secs(
            *BTreeSet::from_iter(
                iter::once(self.header.expires)
                    .chain(self.leases.iter().map(|lease| lease.expires.as_secs() as u32)),
            )
            .first()
            .expect("expiration to exist") as u64,
        )
    }

    #[cfg(test)]
    pub fn random() -> (LeaseSet2, SigningPrivateKey) {
        use crate::{crypto::StaticPrivateKey, runtime::mock::MockRuntime};
        use rand::{Rng, RngCore};
        use std::time::SystemTime;

        let mut rng = rand::thread_rng();

        let public_key = {
            let sk = StaticPrivateKey::random(rng.clone());

            sk.public()
        };

        let (destination, signing_private_key) = {
            let mut static_key = [0u8; 32];
            let mut signing_key = [0u8; 32];

            rng.fill_bytes(&mut static_key);
            rng.fill_bytes(&mut signing_key);

            (
                Destination::new::<MockRuntime>(
                    SigningPrivateKey::from_bytes(&signing_key).unwrap().public(),
                ),
                SigningPrivateKey::from_bytes(&signing_key).unwrap(),
            )
        };

        let leases = (0..rng.gen_range(1..16))
            .map(|_| Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::from(rng.next_u32()),
                expires: Duration::from_secs(
                    (SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap()
                        + Duration::from_secs(9 * 60))
                    .as_secs(),
                ),
            })
            .collect::<Vec<_>>();

        let published = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap()
            - Duration::from_secs(60);

        (
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination,
                    expires: (published + Duration::from_secs(8 * 60)).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: published.as_secs() as u32,
                },
                public_keys: vec![public_key],
                leases,
            },
            signing_private_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::{
        crypto::StaticPrivateKey,
        error::parser::OfflineSignatureParseError,
        runtime::{mock::MockRuntime, Runtime},
    };
    use rand_core::RngCore;

    #[test]
    fn serialize_and_parse_leaset() {
        let sk = StaticPrivateKey::random(MockRuntime::rng());
        let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(
            SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
        );
        let id = destination.id();

        let (_router1, _tunnel1, _expires1, lease1) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let (_router2, _tunnel2, _expires2, lease2) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                expires: 2 * 1337,
                is_unpublished: false,
                offline_signature: None,
                published: 1337,
            },
            public_keys: vec![sk.public()],
            leases: vec![lease1.clone(), lease2.clone()],
        }
        .serialize(&sgk);

        let leaseset = LeaseSet2::parse::<MockRuntime>(&serialized).unwrap();

        assert_eq!(leaseset.public_keys.len(), 1);
        assert_eq!(leaseset.public_keys[0].to_vec(), sk.public().to_vec());
        assert_eq!(leaseset.leases.len(), 2);
        assert_eq!(leaseset.leases[0], lease1);
        assert_eq!(leaseset.leases[1], lease2);
        assert_eq!(leaseset.header.destination.id(), id);
        assert!(!leaseset.header.is_unpublished);
    }

    #[test]
    fn serialize_and_parse_leaset_no_leases() {
        let sk = StaticPrivateKey::random(MockRuntime::rng());
        let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(
            SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
        );

        let serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                expires: 2 * 1337,
                is_unpublished: false,
                offline_signature: None,
                published: 1337,
            },
            public_keys: vec![sk.public()],
            leases: vec![],
        }
        .serialize(&sgk);

        assert_eq!(
            LeaseSet2::parse::<MockRuntime>(&serialized).unwrap_err(),
            LeaseSetParseError::InvalidLeaseCount(0)
        );
    }

    #[test]
    fn serialize_and_parse_leaset_no_public_keys() {
        let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(
            SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
        );

        let (_router1, _tunnel1, _expires1, lease1) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let (_router2, _tunnel2, _expires2, lease2) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                expires: 2 * 1337,
                is_unpublished: false,
                offline_signature: None,
                published: 1337,
            },
            public_keys: vec![],
            leases: vec![lease1.clone(), lease2.clone()],
        }
        .serialize(&sgk);

        assert_eq!(
            LeaseSet2::parse::<MockRuntime>(&serialized).unwrap_err(),
            LeaseSetParseError::NoSupportedPublicKey
        );
    }

    #[test]
    fn serialize_and_parse_random() {
        let (random, signing_key) = LeaseSet2::random();
        assert!(LeaseSet2::parse::<MockRuntime>(&random.serialize(&signing_key)).is_ok());
    }

    #[test]
    fn serialize_and_parse_leaset_too_many_leases() {
        let sk = StaticPrivateKey::random(MockRuntime::rng());
        let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(
            SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
        );

        let leases = (0..17)
            .map(|_| Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::from(MockRuntime::rng().next_u32()),
                expires: Duration::from_secs(MockRuntime::rng().next_u32() as u64),
            })
            .collect::<Vec<_>>();

        let serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                expires: 2 * 1337,
                is_unpublished: false,
                offline_signature: None,
                published: 1337,
            },
            public_keys: vec![sk.public()],
            leases,
        }
        .serialize(&sgk);

        assert_eq!(
            LeaseSet2::parse::<MockRuntime>(&serialized).unwrap_err(),
            LeaseSetParseError::InvalidLeaseCount(17)
        );
    }

    #[test]
    fn parse_leaseset2() {
        let buffer = vec![
            214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248,
            109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98,
            170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246,
            15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58,
            103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187,
            11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180,
            218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115,
            230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131,
            248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197,
            98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196,
            246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183,
            41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91,
            198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216,
            196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54,
            197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194,
            93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214,
            155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109,
            234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170,
            161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15,
            126, 91, 198, 187, 11, 54, 197, 115, 230, 64, 231, 155, 2, 143, 122, 48, 137, 247, 79,
            229, 220, 40, 212, 53, 67, 193, 196, 204, 21, 45, 109, 227, 237, 29, 17, 31, 189, 17,
            189, 195, 40, 5, 0, 4, 0, 7, 0, 0, 102, 216, 119, 64, 2, 88, 0, 0, 0, 0, 2, 0, 4, 0,
            32, 103, 57, 105, 36, 53, 6, 188, 207, 237, 100, 79, 208, 65, 73, 180, 118, 143, 162,
            202, 8, 103, 162, 220, 12, 95, 156, 67, 68, 62, 83, 112, 109, 0, 0, 1, 0, 119, 187, 61,
            243, 159, 159, 198, 178, 65, 81, 148, 19, 78, 105, 92, 175, 190, 170, 136, 62, 19, 45,
            23, 246, 228, 210, 215, 161, 129, 149, 160, 57, 137, 141, 144, 141, 163, 247, 34, 120,
            5, 161, 60, 107, 34, 107, 166, 40, 152, 252, 246, 205, 187, 51, 129, 52, 97, 95, 188,
            78, 176, 198, 254, 4, 19, 197, 215, 74, 73, 55, 135, 16, 43, 68, 159, 141, 78, 234, 63,
            118, 142, 114, 20, 96, 8, 38, 18, 211, 159, 107, 160, 236, 33, 3, 153, 100, 77, 117,
            145, 67, 173, 140, 69, 123, 31, 253, 172, 240, 74, 110, 148, 56, 229, 208, 81, 69, 175,
            122, 89, 252, 43, 29, 193, 100, 232, 33, 150, 48, 105, 230, 76, 125, 114, 135, 88, 222,
            21, 183, 56, 203, 58, 51, 187, 57, 64, 196, 238, 62, 35, 43, 226, 209, 160, 77, 171,
            252, 81, 125, 105, 3, 40, 216, 107, 1, 209, 223, 117, 237, 54, 151, 90, 133, 76, 32,
            217, 167, 214, 86, 42, 226, 222, 126, 45, 133, 138, 28, 77, 37, 28, 200, 74, 3, 240,
            188, 12, 47, 48, 49, 61, 154, 31, 74, 78, 229, 133, 62, 250, 249, 67, 180, 175, 156,
            60, 148, 227, 168, 127, 107, 118, 63, 220, 18, 242, 169, 94, 112, 58, 7, 196, 69, 243,
            206, 205, 89, 54, 174, 162, 106, 223, 195, 152, 90, 155, 98, 223, 122, 21, 248, 181,
            118, 208, 80, 41, 154, 232, 58, 3, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216,
            57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7,
            240, 177, 138, 122, 102, 216, 121, 152, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190,
            216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114,
            242, 7, 254, 77, 137, 9, 102, 216, 121, 152, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73,
            190, 216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94,
            114, 242, 7, 239, 37, 242, 32, 102, 216, 121, 152, 85, 131, 155, 161, 181, 62, 114,
            203, 208, 71, 210, 43, 204, 240, 181, 94, 146, 250, 118, 234, 79, 158, 201, 58, 167,
            187, 35, 177, 69, 215, 241, 60, 154, 198, 121, 194, 199, 142, 61, 196, 142, 139, 85,
            87, 210, 244, 83, 145, 143, 233, 154, 12, 60, 130, 140, 197, 170, 93, 124, 203, 142,
            46, 214, 11,
        ];

        let leaseset2 = LeaseSet2::parse_frame::<MockRuntime>(&buffer).unwrap().1;

        assert_eq!(leaseset2.public_keys.len(), 1);
        assert_eq!(leaseset2.leases.len(), 3);
    }

    #[test]
    fn expired_lease_set() {
        // field in the header says it's expired
        {
            let now = MockRuntime::time_since_epoch();

            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(
                SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
            );

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: now + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: now + Duration::from_secs(60),
            };

            let lease_set = LeaseSet2 {
                header: LeaseSet2Header {
                    destination,
                    is_unpublished: false,
                    expires: Duration::from_secs(60).as_secs() as u32,
                    offline_signature: None,
                    published: (now - Duration::from_secs(5 * 60)).as_secs() as u32,
                },
                public_keys: vec![sk.public()],
                leases: vec![lease1.clone(), lease2.clone()],
            }
            .serialize(&sgk);
            let lease_set = LeaseSet2::parse::<MockRuntime>(&lease_set).unwrap();

            assert!(lease_set.is_expired::<MockRuntime>());
            assert_eq!(
                lease_set.expires().as_secs(),
                (now - Duration::from_secs(4 * 60)).as_secs()
            );
            assert!(!lease_set.header.is_unpublished);
        }

        // all of the leases are expired
        {
            let now = MockRuntime::time_since_epoch();
            let sk = StaticPrivateKey::random(MockRuntime::rng());
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(
                SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
            );

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: now - Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: now - Duration::from_secs(60),
            };

            let lease_set = LeaseSet2 {
                header: LeaseSet2Header {
                    destination,
                    expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: (now - Duration::from_secs(60)).as_secs() as u32,
                },
                public_keys: vec![sk.public()],
                leases: vec![lease1.clone(), lease2.clone()],
            }
            .serialize(&sgk);
            let lease_set = LeaseSet2::parse::<MockRuntime>(&lease_set).unwrap();

            assert!(lease_set.is_expired::<MockRuntime>());
            assert_eq!(
                lease_set.expires().as_secs(),
                (now - Duration::from_secs(80)).as_secs()
            );
            assert!(!lease_set.header.is_unpublished);
        }

        // non-expired leaset
        {
            let now = MockRuntime::time_since_epoch();
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: now + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: now + Duration::from_secs(60),
            };

            let serialized = LeaseSet2 {
                header: LeaseSet2Header {
                    destination,
                    expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: (now).as_secs() as u32,
                },
                public_keys: vec![sk.public()],
                leases: vec![lease1.clone(), lease2.clone()],
            }
            .serialize(&sgk);
            let lease_set = LeaseSet2::parse::<MockRuntime>(&serialized).unwrap();

            assert!(!lease_set.is_expired::<MockRuntime>());
            assert_eq!(
                lease_set.expires().as_secs(),
                (now + Duration::from_secs(60)).as_secs()
            );
            assert!(!lease_set.header.is_unpublished);
        }
    }

    #[test]
    fn invalid_signature() {
        let sk = StaticPrivateKey::random(MockRuntime::rng());
        let wrong_sgk = SigningPrivateKey::from_bytes(&[2u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(
            SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
        );

        let (_router1, _tunnel1, _expires1, lease1) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let (_router2, _tunnel2, _expires2, lease2) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                expires: 2 * 1337,
                is_unpublished: false,
                offline_signature: None,
                published: 1337,
            },
            public_keys: vec![sk.public()],
            leases: vec![lease1.clone(), lease2.clone()],
        }
        .serialize(&wrong_sgk);

        assert_eq!(
            LeaseSet2::parse::<MockRuntime>(&serialized).unwrap_err(),
            LeaseSetParseError::InvalidSignature
        );
    }

    #[test]
    fn p256() {
        let input = vec![
            47, 62, 234, 30, 115, 135, 127, 6, 199, 3, 235, 241, 51, 76, 90, 14, 215, 226, 171,
            143, 42, 177, 22, 107, 110, 102, 234, 143, 109, 20, 219, 249, 8, 203, 186, 117, 243,
            232, 175, 198, 124, 157, 203, 73, 96, 168, 242, 160, 153, 209, 118, 115, 230, 189, 83,
            197, 41, 134, 222, 110, 5, 66, 255, 231, 115, 224, 91, 62, 220, 187, 44, 63, 186, 229,
            172, 96, 28, 38, 234, 148, 84, 134, 147, 107, 13, 49, 33, 156, 191, 35, 158, 27, 56,
            37, 137, 172, 221, 200, 227, 103, 102, 217, 23, 193, 230, 2, 125, 64, 217, 94, 140,
            153, 247, 227, 143, 73, 100, 122, 217, 196, 116, 241, 17, 27, 6, 161, 142, 227, 171,
            124, 113, 222, 164, 85, 99, 30, 219, 198, 10, 31, 110, 109, 66, 158, 16, 71, 107, 31,
            24, 27, 48, 120, 98, 213, 119, 92, 46, 131, 80, 100, 3, 141, 86, 197, 46, 208, 176, 67,
            29, 83, 106, 222, 78, 165, 116, 191, 187, 19, 94, 11, 45, 32, 93, 28, 184, 103, 101,
            200, 103, 173, 141, 116, 75, 200, 89, 77, 2, 126, 113, 98, 152, 158, 166, 151, 230,
            150, 25, 18, 186, 241, 33, 245, 64, 130, 191, 90, 196, 110, 165, 194, 253, 4, 204, 120,
            120, 15, 254, 5, 185, 42, 172, 68, 25, 98, 238, 145, 125, 97, 234, 62, 45, 147, 219,
            124, 212, 167, 25, 93, 52, 165, 195, 13, 157, 127, 191, 64, 196, 159, 62, 4, 202, 164,
            225, 232, 21, 123, 244, 59, 87, 72, 110, 7, 51, 205, 217, 100, 139, 234, 184, 15, 84,
            122, 148, 94, 90, 186, 209, 181, 14, 48, 186, 178, 55, 34, 150, 23, 117, 90, 116, 245,
            76, 221, 205, 89, 166, 156, 224, 171, 200, 73, 156, 56, 129, 167, 52, 233, 149, 107, 3,
            7, 133, 158, 209, 245, 215, 177, 96, 239, 192, 130, 3, 46, 86, 39, 66, 60, 118, 162,
            229, 97, 173, 67, 243, 111, 65, 251, 160, 77, 147, 69, 98, 124, 136, 136, 43, 35, 99,
            153, 139, 23, 191, 253, 8, 43, 111, 20, 109, 103, 116, 173, 242, 175, 191, 109, 74,
            123, 241, 201, 122, 35, 72, 242, 190, 146, 5, 0, 4, 0, 1, 0, 0, 103, 142, 164, 171, 2,
            88, 0, 0, 0, 0, 2, 0, 4, 0, 32, 186, 109, 69, 186, 154, 223, 138, 162, 52, 238, 113,
            41, 99, 62, 176, 162, 46, 102, 191, 209, 177, 199, 42, 126, 27, 169, 119, 95, 12, 122,
            154, 59, 0, 0, 1, 0, 105, 31, 160, 43, 230, 32, 239, 46, 192, 48, 117, 4, 139, 128,
            125, 54, 99, 176, 122, 146, 43, 68, 31, 17, 62, 228, 5, 74, 103, 147, 205, 116, 228,
            130, 202, 172, 229, 226, 254, 250, 76, 219, 201, 131, 124, 39, 141, 78, 57, 35, 218,
            252, 143, 167, 65, 36, 226, 134, 192, 4, 94, 183, 43, 83, 65, 98, 123, 39, 143, 177,
            142, 200, 75, 149, 143, 186, 23, 82, 248, 158, 26, 55, 9, 109, 187, 225, 40, 81, 0,
            154, 130, 171, 4, 107, 238, 119, 54, 224, 116, 159, 223, 57, 214, 213, 54, 188, 253,
            40, 220, 167, 232, 151, 236, 21, 225, 237, 75, 132, 150, 109, 44, 134, 188, 113, 231,
            151, 34, 170, 96, 229, 186, 57, 149, 148, 47, 3, 21, 177, 181, 160, 29, 210, 225, 167,
            33, 132, 142, 143, 178, 8, 158, 3, 223, 156, 149, 65, 199, 34, 71, 139, 144, 19, 64,
            123, 232, 239, 68, 166, 232, 151, 70, 32, 19, 185, 136, 23, 71, 185, 83, 183, 17, 26,
            143, 224, 121, 67, 54, 249, 58, 202, 149, 102, 145, 176, 136, 97, 174, 212, 246, 141,
            168, 45, 208, 198, 233, 233, 164, 161, 37, 153, 74, 190, 139, 22, 205, 101, 15, 41,
            109, 62, 186, 41, 176, 99, 111, 151, 174, 50, 180, 48, 63, 88, 166, 229, 159, 11, 131,
            110, 227, 106, 29, 253, 171, 153, 62, 42, 143, 160, 136, 247, 60, 127, 164, 221, 43,
            78, 3, 72, 46, 255, 164, 210, 109, 68, 40, 198, 79, 70, 132, 252, 45, 128, 105, 96, 85,
            249, 193, 214, 10, 217, 48, 243, 148, 174, 87, 165, 225, 34, 37, 90, 168, 156, 118,
            103, 142, 167, 3, 10, 91, 233, 157, 37, 25, 144, 226, 230, 63, 185, 23, 42, 37, 173,
            77, 61, 3, 135, 80, 186, 187, 125, 31, 174, 26, 98, 20, 15, 244, 193, 70, 79, 11, 203,
            170, 103, 142, 166, 214, 13, 145, 35, 198, 109, 92, 84, 207, 164, 192, 160, 158, 65,
            32, 229, 152, 37, 159, 225, 13, 241, 71, 79, 121, 82, 95, 241, 112, 47, 69, 186, 77,
            172, 95, 94, 30, 103, 142, 165, 230, 165, 116, 43, 1, 66, 81, 40, 86, 2, 238, 181, 67,
            255, 202, 236, 90, 136, 92, 24, 125, 134, 249, 84, 61, 73, 83, 20, 232, 53, 229, 62,
            143, 21, 204, 24, 200, 226, 232, 226, 13, 119, 50, 165, 163, 243, 173, 233, 198, 85,
            52, 251, 199, 89, 220, 21, 209, 37, 158, 59, 195, 58, 40, 19, 70,
        ];

        let _ = LeaseSet2::parse::<MockRuntime>(&input).unwrap();
    }

    #[test]
    fn offline_signature() {
        // set runtime unix time clock to 0 to pass the offline signature expiration check
        MockRuntime::set_time(Some(Duration::from_nanos(0)));

        let input = vec![
            24, 166, 169, 39, 201, 40, 81, 192, 99, 254, 57, 144, 204, 123, 19, 99, 16, 224, 218,
            218, 95, 90, 61, 49, 141, 4, 243, 119, 192, 97, 124, 47, 92, 220, 228, 185, 127, 3,
            193, 53, 168, 224, 23, 231, 142, 15, 167, 130, 140, 84, 234, 78, 90, 43, 150, 30, 199,
            157, 223, 36, 94, 61, 106, 110, 85, 6, 93, 63, 173, 14, 132, 125, 253, 133, 124, 118,
            101, 229, 231, 87, 9, 159, 211, 21, 77, 26, 196, 169, 21, 146, 37, 85, 219, 81, 76,
            253, 183, 147, 232, 233, 118, 182, 227, 181, 107, 210, 194, 103, 219, 180, 120, 42,
            130, 143, 241, 5, 99, 212, 107, 135, 233, 208, 119, 111, 172, 19, 61, 179, 154, 152,
            45, 221, 144, 237, 124, 190, 68, 36, 125, 149, 148, 117, 19, 3, 94, 77, 29, 240, 7, 99,
            7, 65, 52, 243, 174, 39, 57, 63, 201, 244, 90, 103, 119, 106, 80, 19, 155, 168, 21, 62,
            143, 208, 58, 173, 65, 29, 163, 176, 91, 223, 244, 193, 58, 213, 170, 139, 188, 163,
            207, 90, 153, 32, 118, 126, 51, 233, 153, 38, 248, 210, 78, 112, 60, 246, 54, 255, 18,
            139, 184, 101, 139, 222, 4, 245, 40, 33, 49, 132, 108, 118, 53, 62, 146, 115, 155, 42,
            252, 98, 106, 9, 252, 224, 82, 48, 112, 234, 94, 167, 27, 134, 254, 65, 87, 116, 62,
            77, 126, 193, 244, 191, 165, 43, 139, 123, 172, 19, 117, 214, 15, 179, 240, 232, 255,
            42, 85, 129, 119, 246, 53, 8, 171, 131, 162, 52, 204, 15, 156, 214, 51, 203, 99, 120,
            152, 51, 16, 118, 199, 71, 59, 114, 212, 86, 31, 195, 18, 154, 78, 203, 208, 0, 152,
            74, 7, 14, 56, 201, 198, 221, 129, 20, 22, 198, 197, 247, 105, 100, 42, 68, 54, 76, 47,
            153, 151, 152, 83, 35, 66, 11, 48, 18, 169, 51, 142, 148, 220, 221, 166, 119, 188, 114,
            231, 172, 159, 115, 67, 92, 138, 77, 158, 161, 4, 232, 231, 185, 66, 110, 88, 56, 156,
            164, 173, 127, 213, 199, 247, 5, 21, 61, 208, 204, 49, 164, 34, 56, 241, 148, 80, 108,
            141, 66, 114, 98, 65, 99, 5, 0, 4, 0, 7, 0, 0, 103, 145, 24, 146, 2, 87, 0, 1, 103,
            211, 114, 177, 0, 7, 114, 245, 169, 33, 134, 26, 252, 238, 198, 139, 178, 162, 137,
            244, 248, 219, 134, 158, 177, 169, 36, 111, 194, 146, 62, 64, 132, 131, 205, 60, 141,
            119, 75, 98, 229, 232, 91, 194, 2, 167, 112, 200, 140, 187, 82, 159, 142, 104, 231, 51,
            65, 186, 199, 13, 110, 250, 125, 184, 96, 36, 20, 106, 127, 70, 84, 46, 253, 209, 8,
            190, 88, 186, 122, 152, 13, 39, 3, 238, 211, 221, 88, 159, 203, 116, 189, 186, 222,
            120, 237, 193, 252, 251, 122, 55, 198, 6, 0, 0, 1, 0, 4, 0, 32, 250, 45, 143, 169, 233,
            103, 250, 255, 190, 251, 51, 16, 101, 224, 182, 135, 254, 87, 23, 3, 174, 163, 208,
            233, 164, 53, 89, 73, 254, 223, 166, 2, 2, 110, 27, 112, 170, 104, 203, 23, 254, 172,
            25, 167, 58, 65, 76, 245, 160, 32, 118, 167, 7, 175, 202, 173, 248, 57, 191, 38, 151,
            242, 201, 155, 138, 104, 137, 89, 100, 103, 145, 26, 233, 6, 136, 237, 205, 181, 252,
            77, 120, 184, 187, 162, 8, 12, 158, 188, 212, 200, 65, 245, 132, 161, 220, 83, 103, 54,
            20, 176, 15, 20, 159, 87, 227, 242, 4, 131, 233, 103, 145, 25, 157, 173, 224, 11, 74,
            17, 85, 226, 29, 103, 124, 15, 113, 242, 58, 254, 240, 45, 40, 139, 193, 121, 211, 190,
            82, 37, 199, 31, 103, 111, 110, 151, 44, 204, 145, 204, 134, 61, 81, 45, 239, 98, 43,
            255, 143, 72, 186, 230, 83, 179, 172, 49, 63, 148, 215, 219, 175, 57, 175, 212, 122,
            41, 207, 20, 11,
        ];

        let _ = LeaseSet2::parse::<MockRuntime>(&input).unwrap();
    }

    #[test]
    fn offline_signature_expired() {
        // set runtime unix time clock to current time to fail the offline signature expiration
        // check
        MockRuntime::set_time(Some(
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed"),
        ));

        let input = vec![
            24, 166, 169, 39, 201, 40, 81, 192, 99, 254, 57, 144, 204, 123, 19, 99, 16, 224, 218,
            218, 95, 90, 61, 49, 141, 4, 243, 119, 192, 97, 124, 47, 92, 220, 228, 185, 127, 3,
            193, 53, 168, 224, 23, 231, 142, 15, 167, 130, 140, 84, 234, 78, 90, 43, 150, 30, 199,
            157, 223, 36, 94, 61, 106, 110, 85, 6, 93, 63, 173, 14, 132, 125, 253, 133, 124, 118,
            101, 229, 231, 87, 9, 159, 211, 21, 77, 26, 196, 169, 21, 146, 37, 85, 219, 81, 76,
            253, 183, 147, 232, 233, 118, 182, 227, 181, 107, 210, 194, 103, 219, 180, 120, 42,
            130, 143, 241, 5, 99, 212, 107, 135, 233, 208, 119, 111, 172, 19, 61, 179, 154, 152,
            45, 221, 144, 237, 124, 190, 68, 36, 125, 149, 148, 117, 19, 3, 94, 77, 29, 240, 7, 99,
            7, 65, 52, 243, 174, 39, 57, 63, 201, 244, 90, 103, 119, 106, 80, 19, 155, 168, 21, 62,
            143, 208, 58, 173, 65, 29, 163, 176, 91, 223, 244, 193, 58, 213, 170, 139, 188, 163,
            207, 90, 153, 32, 118, 126, 51, 233, 153, 38, 248, 210, 78, 112, 60, 246, 54, 255, 18,
            139, 184, 101, 139, 222, 4, 245, 40, 33, 49, 132, 108, 118, 53, 62, 146, 115, 155, 42,
            252, 98, 106, 9, 252, 224, 82, 48, 112, 234, 94, 167, 27, 134, 254, 65, 87, 116, 62,
            77, 126, 193, 244, 191, 165, 43, 139, 123, 172, 19, 117, 214, 15, 179, 240, 232, 255,
            42, 85, 129, 119, 246, 53, 8, 171, 131, 162, 52, 204, 15, 156, 214, 51, 203, 99, 120,
            152, 51, 16, 118, 199, 71, 59, 114, 212, 86, 31, 195, 18, 154, 78, 203, 208, 0, 152,
            74, 7, 14, 56, 201, 198, 221, 129, 20, 22, 198, 197, 247, 105, 100, 42, 68, 54, 76, 47,
            153, 151, 152, 83, 35, 66, 11, 48, 18, 169, 51, 142, 148, 220, 221, 166, 119, 188, 114,
            231, 172, 159, 115, 67, 92, 138, 77, 158, 161, 4, 232, 231, 185, 66, 110, 88, 56, 156,
            164, 173, 127, 213, 199, 247, 5, 21, 61, 208, 204, 49, 164, 34, 56, 241, 148, 80, 108,
            141, 66, 114, 98, 65, 99, 5, 0, 4, 0, 7, 0, 0, 103, 145, 24, 146, 2, 87, 0, 1, 103,
            211, 114, 177, 0, 7, 114, 245, 169, 33, 134, 26, 252, 238, 198, 139, 178, 162, 137,
            244, 248, 219, 134, 158, 177, 169, 36, 111, 194, 146, 62, 64, 132, 131, 205, 60, 141,
            119, 75, 98, 229, 232, 91, 194, 2, 167, 112, 200, 140, 187, 82, 159, 142, 104, 231, 51,
            65, 186, 199, 13, 110, 250, 125, 184, 96, 36, 20, 106, 127, 70, 84, 46, 253, 209, 8,
            190, 88, 186, 122, 152, 13, 39, 3, 238, 211, 221, 88, 159, 203, 116, 189, 186, 222,
            120, 237, 193, 252, 251, 122, 55, 198, 6, 0, 0, 1, 0, 4, 0, 32, 250, 45, 143, 169, 233,
            103, 250, 255, 190, 251, 51, 16, 101, 224, 182, 135, 254, 87, 23, 3, 174, 163, 208,
            233, 164, 53, 89, 73, 254, 223, 166, 2, 2, 110, 27, 112, 170, 104, 203, 23, 254, 172,
            25, 167, 58, 65, 76, 245, 160, 32, 118, 167, 7, 175, 202, 173, 248, 57, 191, 38, 151,
            242, 201, 155, 138, 104, 137, 89, 100, 103, 145, 26, 233, 6, 136, 237, 205, 181, 252,
            77, 120, 184, 187, 162, 8, 12, 158, 188, 212, 200, 65, 245, 132, 161, 220, 83, 103, 54,
            20, 176, 15, 20, 159, 87, 227, 242, 4, 131, 233, 103, 145, 25, 157, 173, 224, 11, 74,
            17, 85, 226, 29, 103, 124, 15, 113, 242, 58, 254, 240, 45, 40, 139, 193, 121, 211, 190,
            82, 37, 199, 31, 103, 111, 110, 151, 44, 204, 145, 204, 134, 61, 81, 45, 239, 98, 43,
            255, 143, 72, 186, 230, 83, 179, 172, 49, 63, 148, 215, 219, 175, 57, 175, 212, 122,
            41, 207, 20, 11,
        ];

        assert_eq!(
            LeaseSet2::parse::<MockRuntime>(&input).unwrap_err(),
            LeaseSetParseError::OfflineSignature(OfflineSignatureParseError::Expired)
        );
    }

    #[test]
    fn unpublished_lease_set() {
        let sk = StaticPrivateKey::random(MockRuntime::rng());
        let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(
            SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap().public(),
        );
        let id = destination.id();

        let (_router1, _tunnel1, _expires1, lease1) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let (_router2, _tunnel2, _expires2, lease2) = {
            let router_id = RouterId::random();
            let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
            let expires = Duration::from_secs(MockRuntime::rng().next_u32() as u64);

            (
                router_id.clone(),
                tunnel_id,
                expires,
                Lease {
                    router_id,
                    tunnel_id,
                    expires,
                },
            )
        };

        let serialized = LeaseSet2 {
            header: LeaseSet2Header {
                destination,
                expires: 2 * 1337,
                is_unpublished: true,
                offline_signature: None,
                published: 1337,
            },
            public_keys: vec![sk.public()],
            leases: vec![lease1.clone(), lease2.clone()],
        }
        .serialize(&sgk);

        let leaseset = LeaseSet2::parse::<MockRuntime>(&serialized).unwrap();

        assert_eq!(leaseset.public_keys.len(), 1);
        assert_eq!(leaseset.public_keys[0].to_vec(), sk.public().to_vec());
        assert_eq!(leaseset.leases.len(), 2);
        assert_eq!(leaseset.leases[0], lease1);
        assert_eq!(leaseset.leases[1], lease2);
        assert_eq!(leaseset.header.destination.id(), id);
        assert!(leaseset.header.is_unpublished);
    }

    #[test]
    fn lease_set_dsa_sha1() {
        let input = vec![
            18, 16, 215, 62, 194, 45, 30, 46, 195, 127, 31, 63, 255, 72, 135, 63, 57, 35, 136, 173,
            121, 235, 204, 42, 18, 39, 192, 69, 58, 254, 158, 2, 51, 159, 5, 90, 6, 103, 132, 157,
            33, 215, 124, 185, 0, 251, 177, 127, 54, 186, 176, 247, 156, 144, 46, 86, 105, 141,
            174, 141, 212, 60, 144, 54, 210, 87, 63, 31, 131, 111, 118, 169, 94, 226, 176, 178,
            228, 205, 72, 104, 25, 153, 237, 164, 20, 117, 207, 135, 179, 194, 177, 252, 192, 71,
            12, 103, 225, 221, 190, 55, 30, 249, 87, 128, 82, 10, 4, 43, 210, 4, 99, 13, 175, 203,
            252, 153, 173, 196, 244, 84, 165, 149, 246, 55, 32, 111, 15, 76, 57, 49, 38, 131, 255,
            219, 120, 70, 224, 145, 67, 104, 21, 14, 149, 20, 13, 196, 225, 218, 57, 38, 217, 181,
            254, 71, 219, 209, 32, 120, 66, 100, 182, 172, 31, 16, 209, 238, 178, 66, 247, 237,
            252, 184, 203, 16, 235, 44, 29, 226, 233, 80, 65, 130, 44, 210, 64, 117, 176, 74, 31,
            117, 117, 50, 167, 42, 169, 133, 5, 61, 196, 140, 115, 237, 172, 224, 204, 162, 105,
            253, 209, 231, 38, 146, 122, 74, 150, 135, 237, 74, 195, 55, 230, 31, 58, 64, 47, 24,
            80, 91, 147, 217, 62, 187, 115, 70, 151, 158, 245, 99, 109, 57, 117, 1, 127, 151, 117,
            199, 189, 82, 159, 232, 212, 189, 252, 155, 237, 86, 29, 9, 137, 188, 16, 218, 162,
            213, 63, 45, 216, 253, 59, 85, 137, 247, 239, 166, 233, 205, 24, 234, 223, 157, 90,
            211, 231, 237, 92, 222, 85, 141, 31, 31, 32, 77, 169, 88, 221, 31, 175, 83, 154, 195,
            119, 192, 115, 220, 8, 77, 51, 162, 150, 146, 214, 106, 240, 184, 135, 30, 18, 84, 196,
            137, 30, 109, 118, 108, 137, 223, 159, 218, 15, 208, 129, 20, 114, 195, 17, 187, 146,
            194, 37, 42, 192, 140, 18, 125, 59, 233, 253, 55, 47, 234, 22, 36, 137, 107, 2, 14, 76,
            117, 7, 126, 170, 88, 53, 6, 205, 72, 134, 180, 124, 97, 63, 35, 53, 138, 215, 213,
            177, 157, 150, 99, 235, 36, 58, 98, 0, 0, 0, 103, 195, 21, 13, 2, 87, 0, 0, 0, 0, 1, 0,
            4, 0, 32, 20, 91, 61, 174, 160, 33, 209, 163, 0, 150, 8, 154, 29, 232, 174, 235, 192,
            96, 123, 3, 213, 16, 79, 84, 246, 158, 47, 220, 205, 31, 196, 47, 2, 46, 219, 116, 45,
            193, 31, 34, 103, 83, 102, 5, 254, 119, 73, 16, 178, 45, 213, 8, 127, 24, 7, 25, 87,
            97, 6, 81, 159, 52, 5, 111, 111, 249, 172, 240, 204, 103, 195, 23, 100, 189, 90, 21,
            96, 216, 171, 118, 150, 8, 39, 190, 58, 100, 216, 116, 180, 166, 184, 249, 155, 7, 131,
            54, 78, 57, 235, 80, 246, 138, 58, 94, 188, 12, 33, 155, 125, 103, 195, 21, 171, 110,
            233, 119, 62, 189, 223, 229, 10, 12, 49, 4, 85, 149, 49, 0, 43, 186, 186, 233, 216, 12,
            17, 20, 213, 252, 108, 42, 129, 123, 41, 151, 182, 156, 111, 238, 193, 184, 219, 35,
            94,
        ];

        let _ = LeaseSet2::parse::<MockRuntime>(&input).unwrap();
    }
}
