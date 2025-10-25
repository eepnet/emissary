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
    crypto::{
        base64_decode, base64_encode, sha256::Sha256, SigningPrivateKey, SigningPublicKey,
        StaticPrivateKey, StaticPublicKey,
    },
    error::parser::RouterIdentityParseError,
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt;

/// Length of serialized [`RouterIdentity`].
const SERIALIZED_LEN: usize = 391usize;

/// Key certificate.
const KEY_CERTIFICATE: u8 = 0x05;

/// Key certificate length.
const KEY_CERTIFICATE_LEN: u16 = 0x04;

/// Key kind for `EdDSA_SHA512_Ed25519`.
///
/// https://geti2p.net/spec/common-structures#key-certificates
const KEY_KIND_EDDSA_SHA512_ED25519: u16 = 0x0007;

/// Key kind for `X25519`.
///
/// https://geti2p.net/spec/common-structures#key-certificates
const KEY_KIND_X25519: u16 = 0x0004;

/// Short router identity hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RouterId(Arc<String>);

impl RouterId {
    #[cfg(test)]
    pub fn random() -> RouterId {
        use rand::Rng;

        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        RouterId::from(bytes)
    }

    /// Copy [`RouterId`] into a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        base64_decode(self.0.as_bytes()).expect("to succeed")
    }
}

impl fmt::Display for RouterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0[..8])
    }
}

impl<T: AsRef<[u8]>> From<T> for RouterId {
    fn from(value: T) -> Self {
        RouterId(Arc::new(base64_encode(value)))
    }
}

impl From<RouterId> for Vec<u8> {
    fn from(value: RouterId) -> Self {
        base64_decode(value.0.as_bytes()).expect("to succeed")
    }
}

/// Router identity.
#[derive(Debug, Clone)]
pub struct RouterIdentity {
    /// Identity hash.
    identity_hash: Bytes,

    /// Padding bytes.
    padding: Bytes,

    /// Router ID.
    router: RouterId,

    /// Router's signing key.
    signing_key: SigningPublicKey,

    /// Router's public key.
    static_key: StaticPublicKey,
}

impl RouterIdentity {
    /// Create new [`RouterIdentity`] from keys.
    pub fn from_keys<R: Runtime>(
        static_key: &StaticPrivateKey,
        signing_key: &SigningPrivateKey,
    ) -> crate::Result<Self> {
        let padding = {
            let mut padding = [0u8; 320];
            R::rng().fill_bytes(&mut padding);

            padding
        };

        let identity_hash = {
            let mut out = BytesMut::with_capacity(SERIALIZED_LEN);

            out.put_slice(static_key.public().as_ref());
            out.put_slice(&padding);
            out.put_slice(signing_key.public().as_ref());
            out.put_u8(KEY_CERTIFICATE);
            out.put_u16(KEY_CERTIFICATE_LEN);
            out.put_u16(KEY_KIND_EDDSA_SHA512_ED25519);
            out.put_u16(KEY_KIND_X25519);

            Sha256::new().update(&out).finalize()
        };

        Ok(Self {
            identity_hash: Bytes::from(identity_hash.clone()),
            padding: Bytes::from(padding.to_vec()),
            router: RouterId::from(identity_hash),
            signing_key: signing_key.public(),
            static_key: static_key.public(),
        })
    }

    /// Parse [`RouterIdentity`] from `input`, returning rest of `input` and parsed router identity.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterIdentity, RouterIdentityParseError> {
        if input.len() < SERIALIZED_LEN {
            return Err(Err::Error(RouterIdentityParseError::InvalidLength(
                input.len(),
            )));
        }

        let (_, (initial_bytes, rest)) = tuple((take(384usize), take(input.len() - 384)))(input)?;

        let (rest, cert_type) = be_u8(rest)?;
        let (rest, cert_len) = be_u16(rest)?;
        let (rest, sig_key_type) = be_u16(rest)?;
        let (rest, pub_key_type) = be_u16(rest)?;

        let (KEY_CERTIFICATE, KEY_CERTIFICATE_LEN) = (cert_type, cert_len) else {
            return Err(Err::Error(RouterIdentityParseError::InvalidCertificate((
                cert_type, cert_len,
            ))));
        };

        let static_key = match pub_key_type {
            KEY_KIND_X25519 => StaticPublicKey::from_bytes(&initial_bytes[..32])
                .ok_or(Err::Error(RouterIdentityParseError::InvalidBitstream)),
            kind => Err(Err::Error(RouterIdentityParseError::InvalidPublicKey(kind))),
        }?;

        let signing_key = match sig_key_type {
            KEY_KIND_EDDSA_SHA512_ED25519 => Some({
                // call must succeed as the slice into `initial_bytes`
                // and `public_key` are the same size
                let public_key =
                    TryInto::<[u8; 32]>::try_into(initial_bytes[384 - 32..384].to_vec())
                        .expect("to succeed");

                SigningPublicKey::from_bytes(&public_key)
                    .ok_or_else(|| Err::Error(RouterIdentityParseError::InvalidBitstream))?
            }),
            _ => None,
        }
        .ok_or(Err::Error(RouterIdentityParseError::InvalidSigningKey(
            sig_key_type,
        )))?;

        let identity_hash = Bytes::from(Sha256::new().update(&input[..391]).finalize());

        Ok((
            rest,
            RouterIdentity {
                static_key,
                padding: Bytes::from(initial_bytes[32..352].to_vec()),
                signing_key,
                identity_hash: identity_hash.clone(),
                router: RouterId::from(identity_hash),
            },
        ))
    }

    /// Try to parse router information from `bytes`.
    #[allow(unused)]
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, RouterIdentityParseError> {
        Ok(Self::parse_frame(bytes.as_ref())?.1)
    }

    /// Serialize [`RouterIdentity`] into a byte vector.
    pub fn serialize(&self) -> BytesMut {
        let mut out = BytesMut::with_capacity(SERIALIZED_LEN);

        out.put_slice(self.static_key.as_ref());
        out.put_slice(&self.padding);
        out.put_slice(self.signing_key.as_ref());
        out.put_u8(KEY_CERTIFICATE);
        out.put_u16(KEY_CERTIFICATE_LEN);
        out.put_u16(KEY_KIND_EDDSA_SHA512_ED25519);
        out.put_u16(KEY_KIND_X25519);

        out
    }

    /// Get reference to router's static public key.
    pub fn static_key(&self) -> &StaticPublicKey {
        &self.static_key
    }

    /// Get reference to router's signing public key.
    pub fn signing_key(&self) -> &SigningPublicKey {
        &self.signing_key
    }

    /// Router identity hash as bytes.
    pub fn hash(&self) -> Bytes {
        self.identity_hash.clone()
    }

    /// Get [`RouterId`].
    pub fn id(&self) -> RouterId {
        self.router.clone()
    }

    /// Get serialized length of [`RouterIdentity`].
    pub fn serialized_len(&self) -> usize {
        SERIALIZED_LEN
    }

    /// Generate random [`RouterIdentity`].
    #[cfg(test)]
    pub fn random() -> (Self, StaticPrivateKey, SigningPrivateKey) {
        use crate::runtime::mock::MockRuntime;
        use rand::{thread_rng, RngCore};

        let sk = {
            let mut out = [0u8; 32];
            thread_rng().fill_bytes(&mut out);

            StaticPrivateKey::from(out)
        };
        let sgk = {
            let mut out = [0u8; 32];
            thread_rng().fill_bytes(&mut out);

            SigningPrivateKey::from(out)
        };

        let identity = RouterIdentity::from_keys::<MockRuntime>(&sk, &sgk).unwrap();

        (identity, sk, sgk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::base64_encode;

    #[test]
    fn expected_router_hash() {
        let router = include_bytes!("../../test-vectors/router5.dat");
        let identity = RouterIdentity::parse(router).unwrap();

        assert_eq!(
            base64_encode(&identity.identity_hash),
            "u9QdTy~qBwh8Mrcfrcqvea8MOiNmavLv8Io4XQsMDHg="
        );

        let serialized = identity.serialize();
        let parsed = RouterIdentity::parse(&serialized).unwrap();
        assert_eq!(
            base64_encode(&parsed.identity_hash),
            "u9QdTy~qBwh8Mrcfrcqvea8MOiNmavLv8Io4XQsMDHg="
        );
    }

    #[test]
    fn too_short_router_identity() {
        assert_eq!(
            RouterIdentity::parse(vec![1, 2, 3, 4]).unwrap_err(),
            RouterIdentityParseError::InvalidLength(4)
        );
    }

    #[test]
    fn serialize_deserialize() {
        let (identity, _, _) = RouterIdentity::random();
        let id = identity.id();

        let serialized = identity.serialize();
        let parsed = RouterIdentity::parse(&serialized).unwrap();
        assert_eq!(parsed.id(), id);
    }
}
