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
    crypto::{base64_encode, StaticPrivateKey},
    primitives::{Date, Mapping, Str},
};

use bytes::{BufMut, BytesMut};
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::{string::ToString, vec::Vec};
use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

/// Transport kind.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum TransportKind {
    /// NTCP2.
    Ntcp2,

    /// SSU2.
    Ssu2,
}

impl TryFrom<Str> for TransportKind {
    type Error = ();

    fn try_from(value: Str) -> Result<Self, Self::Error> {
        if value.starts_with("SSU") {
            return Ok(TransportKind::Ssu2);
        }

        if value.starts_with("NTCP2") {
            return Ok(TransportKind::Ntcp2);
        }

        Err(())
    }
}

impl TransportKind {
    /// Serialize [`TransportKind`].
    fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Ntcp2 => Str::from("NTCP2").serialize(),
            Self::Ssu2 => Str::from("SSU2").serialize(),
        }
    }
}

/// Router address.
#[derive(Debug, Clone)]
pub struct RouterAddress {
    /// Router cost.
    pub cost: u8,

    /// When the router expires (always 0).
    pub expires: Date,

    /// Transport.
    pub transport: TransportKind,

    /// Options.
    pub options: Mapping,

    /// Router's socket address.
    pub socket_address: Option<SocketAddr>,
}

impl RouterAddress {
    /// Create new unpublished NTCP2 [`RouterAddress`].
    pub fn new_unpublished_ntcp2(key: [u8; 32], port: u16) -> Self {
        let static_key = StaticPrivateKey::from(key).public();
        let key = base64_encode(&static_key);

        let mut options = Mapping::default();
        options.insert("v".into(), "2".into());
        options.insert("s".into(), key.into());

        Self {
            cost: 14,
            expires: Date::new(0),
            transport: TransportKind::Ntcp2,
            socket_address: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            options,
        }
    }

    /// Create new unpublished NTCP2 [`RouterAddress`].
    pub fn new_published_ntcp2(key: [u8; 32], iv: [u8; 16], port: u16, host: Ipv4Addr) -> Self {
        let static_key = StaticPrivateKey::from(key).public();

        let mut options = Mapping::default();
        options.insert(Str::from("v"), Str::from("2"));
        options.insert(Str::from("s"), Str::from(base64_encode(&static_key)));
        options.insert(Str::from("host"), Str::from(host.to_string()));
        options.insert(Str::from("port"), Str::from(port.to_string()));
        options.insert(Str::from("i"), Str::from(base64_encode(iv)));

        Self {
            cost: 3,
            expires: Date::new(0),
            transport: TransportKind::Ntcp2,
            options,
            socket_address: Some(SocketAddr::new(IpAddr::V4(host), port)),
        }
    }

    /// Create new unpublished SSU2 [`RouterAddress`].
    pub fn new_unpublished_ssu2(static_key: [u8; 32], intro_key: [u8; 32], port: u16) -> Self {
        let static_key = {
            let static_key = StaticPrivateKey::from(static_key).public();
            base64_encode(&static_key)
        };
        let intro_key = base64_encode(intro_key);

        let mut options = Mapping::default();
        options.insert(Str::from_str("v").unwrap(), Str::from_str("2").unwrap());
        options.insert(
            Str::from_str("s").unwrap(),
            Str::from_str(&static_key).unwrap(),
        );
        options.insert(
            Str::from_str("i").unwrap(),
            Str::from_str(&intro_key).unwrap(),
        );

        Self {
            cost: 14,
            expires: Date::new(0),
            transport: TransportKind::Ssu2,
            socket_address: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            options,
        }
    }

    /// Create new unpublished SSU2 [`RouterAddress`].
    pub fn new_published_ssu2(
        static_key: [u8; 32],
        intro_key: [u8; 32],
        port: u16,
        host: Ipv4Addr,
    ) -> Self {
        let static_key = {
            let static_key = StaticPrivateKey::from(static_key).public();
            base64_encode(&static_key)
        };
        let intro_key = base64_encode(intro_key);

        let mut options = Mapping::default();
        options.insert(Str::from("v"), Str::from("2"));
        options.insert(
            Str::from_str("s").unwrap(),
            Str::from_str(&static_key).unwrap(),
        );
        options.insert(
            Str::from_str("i").unwrap(),
            Str::from_str(&intro_key).unwrap(),
        );
        options.insert(Str::from("host"), Str::from(host.to_string()));
        options.insert(Str::from("port"), Str::from(port.to_string()));

        Self {
            cost: 8,
            expires: Date::new(0),
            transport: TransportKind::Ssu2,
            options,
            socket_address: Some(SocketAddr::new(IpAddr::V4(host), port)),
        }
    }

    /// Parse [`RouterAddress`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterAddress> {
        let (rest, cost) = be_u8(input)?;
        let (rest, expires) = Date::parse_frame(rest)?;
        let (rest, transport) = Str::parse_frame(rest)?;
        let (rest, options) = Mapping::parse_frame(rest)?;
        let socket_address: Option<SocketAddr> = {
            let maybe_host = options.get(&Str::from("host"));
            let maybe_port = options.get(&Str::from("port"));

            match (maybe_host, maybe_port) {
                (Some(host), Some(port)) => {
                    let port = port.parse::<u16>().ok();
                    let host = host.parse::<IpAddr>().ok();

                    match (host, port) {
                        (Some(host), Some(port)) => Some(SocketAddr::new(host, port)),
                        (_, _) => None,
                    }
                }
                _ => None,
            }
        };

        Ok((
            rest,
            RouterAddress {
                cost,
                expires,
                transport: TransportKind::try_from(transport)
                    .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?,
                options,
                socket_address,
            },
        ))
    }

    /// Try to convert `bytes` into a [`RouterAddress`].
    pub fn parse(bytes: impl AsRef<[u8]>) -> Option<RouterAddress> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Serialize [`RouterAddress`].
    pub fn serialize(&self) -> BytesMut {
        let options = self.options.serialize();
        let transport = self.transport.serialize();
        let mut out = BytesMut::with_capacity(1 + 8 + transport.len() + options.len());

        out.put_u8(self.cost);
        out.put_slice(&self.expires.serialize());
        out.put_slice(&transport);
        out.put_slice(&options);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_unpublished_ntcp2() {
        let serialized = RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888).serialize();
        let static_key = StaticPrivateKey::from([1u8; 32]).public();

        let address = RouterAddress::parse(&serialized).unwrap();
        assert_eq!(address.cost, 14);
        assert_eq!(
            address.options.get(&Str::from("s")),
            Some(&Str::from(base64_encode(&static_key)))
        );
        assert_eq!(address.options.get(&Str::from("v")), Some(&Str::from("2")));
        assert!(address.options.get(&Str::from("i")).is_none());
        assert!(address.options.get(&Str::from("host")).is_none());
        assert!(address.options.get(&Str::from("port")).is_none());
    }

    #[test]
    fn serialize_deserialize_published_ntcp2() {
        let serialized = RouterAddress::new_published_ntcp2(
            [1u8; 32],
            [0xaa; 16],
            8888,
            "127.0.0.1".parse().unwrap(),
        )
        .serialize();
        let static_key = StaticPrivateKey::from([1u8; 32]).public();

        let address = RouterAddress::parse(&serialized).unwrap();
        assert_eq!(address.cost, 3);
        assert_eq!(
            address.options.get(&Str::from("i")),
            Some(&Str::from(base64_encode(&[0xaa; 16])))
        );
        assert_eq!(
            address.options.get(&Str::from("s")),
            Some(&Str::from(base64_encode(&static_key)))
        );
        assert_eq!(address.options.get(&Str::from("v")), Some(&Str::from("2")));
        assert_eq!(
            address.options.get(&Str::from("host")),
            Some(&Str::from("127.0.0.1"))
        );
        assert_eq!(
            address.options.get(&Str::from("port")),
            Some(&Str::from("8888"))
        );
    }

    #[test]
    fn serialize_deserialize_unpublished_ssu2() {
        let serialized =
            RouterAddress::new_unpublished_ssu2([1u8; 32], [2u8; 32], 8888).serialize();
        let static_key = StaticPrivateKey::from([1u8; 32]).public();
        let intro_key = [2u8; 32];

        let address = RouterAddress::parse(&serialized).unwrap();
        assert_eq!(address.cost, 14);
        assert_eq!(
            address.options.get(&Str::from("s")),
            Some(&Str::from(base64_encode(&static_key)))
        );
        assert_eq!(
            address.options.get(&Str::from("i")),
            Some(&Str::from(base64_encode(&intro_key)))
        );
        assert_eq!(address.options.get(&Str::from("v")), Some(&Str::from("2")));
        assert!(address.options.get(&Str::from("host")).is_none());
        assert!(address.options.get(&Str::from("port")).is_none());
    }

    #[test]
    fn serialize_deserialize_published_ssu2() {
        let serialized = RouterAddress::new_published_ssu2(
            [1u8; 32],
            [2u8; 32],
            8888,
            "127.0.0.1".parse().unwrap(),
        )
        .serialize();
        let static_key = StaticPrivateKey::from([1u8; 32]).public();
        let intro_key = [2u8; 32];

        let address = RouterAddress::parse(&serialized).unwrap();
        assert_eq!(address.cost, 8);
        assert_eq!(
            address.options.get(&Str::from("s")),
            Some(&Str::from(base64_encode(&static_key)))
        );
        assert_eq!(
            address.options.get(&Str::from("i")),
            Some(&Str::from(base64_encode(&intro_key)))
        );
        assert_eq!(address.options.get(&Str::from("v")), Some(&Str::from("2")));
        assert_eq!(
            address.options.get(&Str::from("host")),
            Some(&Str::from("127.0.0.1"))
        );
        assert_eq!(
            address.options.get(&Str::from("port")),
            Some(&Str::from("8888"))
        );
    }
}
