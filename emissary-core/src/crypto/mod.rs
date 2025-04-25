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
    crypto::dsa::{DsaPublicKey, DsaSignature},
    error::Error,
};

use data_encoding::{Encoding, Specification};
use ed25519_dalek::Signer;
use lazy_static::lazy_static;
use p256::ecdsa::signature::Verifier as _;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use alloc::{string::String, vec::Vec};
use core::convert::TryInto;

pub mod aes;
pub mod chachapoly;
pub mod dsa;
pub mod hmac;
pub mod noise;
pub mod sha256;
pub mod siphash;

// Taken from `ire` which is licensed under MIT
//
// Credits to str4d
lazy_static! {
    pub static ref I2P_BASE64: Encoding = {
        let mut spec = Specification::new();
        spec.symbols
            .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");
        spec.padding = Some('=');
        spec.encoding().unwrap()
    };
    pub static ref I2P_BASE32: Encoding = {
        let mut spec = Specification::new();
        spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        spec.encoding().unwrap()
    };
}

/// Base64 encode `data`
pub fn base64_encode<T: AsRef<[u8]>>(data: T) -> String {
    I2P_BASE64.encode(data.as_ref())
}

/// Base64 decode `data`
pub fn base64_decode<T: AsRef<[u8]>>(data: T) -> Option<Vec<u8>> {
    I2P_BASE64.decode(data.as_ref()).ok()
}

/// Base32 decode `data`.
pub fn base32_encode(data: impl AsRef<[u8]>) -> String {
    I2P_BASE32.encode(data.as_ref())
}

/// Base32 decode `data`.
#[allow(unused)]
pub fn base32_decode(data: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    I2P_BASE32.decode(data.as_ref()).ok()
}

/// Trait describing the expected API from secret keys.
pub trait SecretKey {
    /// Perform Diffie-Hellman key exchange between `self` and `public_key`.
    fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> [u8; 32];
}

/// Static public key.
#[derive(Debug, Clone)]
pub enum StaticPublicKey {
    /// x25519
    X25519(x25519_dalek::PublicKey),
}

impl StaticPublicKey {
    /// Try to create [`StaticPublicKey`] from `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key: [u8; 32] = bytes.try_into().ok()?;

        Some(Self::X25519(x25519_dalek::PublicKey::from(key)))
    }

    /// Convert [`StaticPublicKey`] to a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.to_bytes().to_vec(),
        }
    }
}

impl From<[u8; 32]> for StaticPublicKey {
    fn from(value: [u8; 32]) -> Self {
        StaticPublicKey::X25519(x25519_dalek::PublicKey::from(value))
    }
}

impl AsRef<[u8]> for StaticPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X25519(key) => key.as_ref(),
        }
    }
}

impl AsRef<x25519_dalek::PublicKey> for StaticPublicKey {
    fn as_ref(&self) -> &x25519_dalek::PublicKey {
        match self {
            Self::X25519(key) => key,
        }
    }
}

/// Static private key.
#[derive(Clone)]
pub enum StaticPrivateKey {
    /// X25519.
    X25519(x25519_dalek::StaticSecret),
}

impl StaticPrivateKey {
    /// Create new [`StaticPrivateKey`].
    pub fn random(csprng: impl RngCore + CryptoRng) -> Self {
        Self::X25519(x25519_dalek::StaticSecret::random_from_rng(csprng))
    }

    /// Get public key.
    pub fn public(&self) -> StaticPublicKey {
        match self {
            Self::X25519(key) => StaticPublicKey::X25519(x25519_dalek::PublicKey::from(key)),
        }
    }

    /// Perform Diffie-Hellman and return the shared secret as byte vector.
    pub fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.diffie_hellman(public_key.as_ref()).to_bytes().to_vec(),
        }
    }

    /// Try to create [`StaticPublicKey`] from `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key: [u8; 32] = bytes.try_into().ok()?;

        Some(StaticPrivateKey::X25519(x25519_dalek::StaticSecret::from(
            key,
        )))
    }
}

impl From<[u8; 32]> for StaticPrivateKey {
    fn from(value: [u8; 32]) -> Self {
        StaticPrivateKey::X25519(x25519_dalek::StaticSecret::from(value))
    }
}

impl AsRef<[u8]> for StaticPrivateKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X25519(key) => key.as_ref(),
        }
    }
}

impl SecretKey for StaticPrivateKey {
    fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> [u8; 32] {
        match self {
            Self::X25519(key) => key.diffie_hellman(public_key.as_ref()).to_bytes(),
        }
    }
}

/// Ephemeral private key.
pub enum EphemeralPrivateKey {
    /// X25519.
    X25519(x25519_dalek::ReusableSecret),
}

impl EphemeralPrivateKey {
    /// Create new [`EphemeralPrivateKey`].
    pub fn random(csprng: impl RngCore + CryptoRng) -> Self {
        Self::X25519(x25519_dalek::ReusableSecret::random_from_rng(csprng))
    }

    /// Get associated public key.
    pub fn public(&self) -> EphemeralPublicKey {
        match self {
            Self::X25519(key) => EphemeralPublicKey::X25519(x25519_dalek::PublicKey::from(key)),
        }
    }

    /// Perform Diffie-Hellman and return the shared secret as byte vector.
    pub fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.diffie_hellman(public_key.as_ref()).to_bytes().to_vec(),
        }
    }

    /// Zeroize private key.
    pub fn zeroize(self) {
        match self {
            Self::X25519(mut key) => key.zeroize(),
        }
    }
}

impl SecretKey for EphemeralPrivateKey {
    fn diffie_hellman<T: AsRef<x25519_dalek::PublicKey>>(&self, public_key: &T) -> [u8; 32] {
        match self {
            Self::X25519(key) => key.diffie_hellman(public_key.as_ref()).to_bytes(),
        }
    }
}

/// Ephemeral public key.
#[derive(Clone)]
pub enum EphemeralPublicKey {
    /// X25519.
    X25519(x25519_dalek::PublicKey),
}

impl EphemeralPublicKey {
    /// Convert [`EphemeralPublicKey`] to a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.as_bytes().to_vec(),
        }
    }

    /// Try to create [`EphemeralPublicKey`] from `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key: [u8; 32] = bytes.try_into().ok()?;

        Some(Self::X25519(x25519_dalek::PublicKey::from(key)))
    }
}

impl AsRef<[u8]> for EphemeralPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X25519(key) => key.as_ref(),
        }
    }
}

impl AsRef<x25519_dalek::PublicKey> for EphemeralPublicKey {
    fn as_ref(&self) -> &x25519_dalek::PublicKey {
        match self {
            Self::X25519(key) => key,
        }
    }
}

impl Zeroize for EphemeralPublicKey {
    fn zeroize(&mut self) {
        match self {
            Self::X25519(key) => key.zeroize(),
        }
    }
}

/// Signing private key.
#[derive(Clone)]
pub enum SigningPrivateKey {
    /// EdDSA.
    Ed25519(ed25519_dalek::SigningKey),
}

impl SigningPrivateKey {
    /// Generate random [`SigningPrivateKey`].
    pub fn random(mut csprng: impl RngCore + CryptoRng) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::generate(&mut csprng))
    }

    /// Try to create [`SigningPrivateKey`] from `bytes`.
    pub fn from_bytes(key: &[u8]) -> Option<Self> {
        let key: [u8; 32] = key.to_vec().try_into().ok()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&key);

        Some(SigningPrivateKey::Ed25519(key))
    }

    /// Sign `message`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
        }
    }

    /// Get verifying key.
    pub fn public(&self) -> SigningPublicKey {
        match self {
            Self::Ed25519(key) => SigningPublicKey::Ed25519(key.verifying_key()),
        }
    }
}

impl From<[u8; 32]> for SigningPrivateKey {
    fn from(value: [u8; 32]) -> Self {
        SigningPrivateKey::Ed25519(ed25519_dalek::SigningKey::from(value))
    }
}

impl AsRef<[u8]> for SigningPrivateKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(key) => key.as_bytes(),
        }
    }
}

/// Signing public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningPublicKey {
    /// EdDSA.
    Ed25519(ed25519_dalek::VerifyingKey),

    /// ECDSA-SHA256-P256
    //
    // Taken from `ire` which is licensed under MIT
    //
    // Credits to str4d
    P256(p256::EncodedPoint, p256::ecdsa::VerifyingKey),

    /// DSA-SHA1.
    //
    // Taken from `ire` which is licensed under MIT
    //
    // Credits to str4d
    DsaSha1(DsaPublicKey),
}

impl SigningPublicKey {
    /// Create signing public key from bytes.
    //
    // TODO: verify it's valid point on the curve
    pub fn from_bytes(key: &[u8; 32]) -> Option<Self> {
        Some(SigningPublicKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_bytes(key).ok()?,
        ))
    }

    /// Attempt to construct `SigningPublicKey::P256` from `data`.
    pub fn p256(data: &[u8]) -> Option<Self> {
        let encoded = p256::EncodedPoint::from_untagged_bytes(data.into());

        Some(Self::P256(
            encoded,
            p256::ecdsa::VerifyingKey::from_encoded_point(&encoded).ok()?,
        ))
    }

    /// Attempt to construct `SigningPublicKey::P256` from `data`.
    pub fn dsa_sha1(data: &[u8]) -> Option<Self> {
        DsaPublicKey::from_bytes(data).map(Self::DsaSha1)
    }

    /// Verify `signature` of `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> crate::Result<()> {
        match self {
            Self::Ed25519(key) => {
                let signature: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidData)?;
                let signature = ed25519_dalek::Signature::from_bytes(&signature);

                key.verify_strict(message, &signature).map_err(From::from)
            }
            Self::P256(_, vk) => {
                let signature =
                    p256::ecdsa::Signature::try_from(signature).map_err(|_| Error::InvalidData)?;

                vk.verify(message, &signature).map_err(|_| Error::InvalidData)
            }
            Self::DsaSha1(public_key) => {
                let signature = DsaSignature::from_bytes(signature).ok_or(Error::InvalidData)?;

                match public_key.verify(message, &signature) {
                    true => Ok(()),
                    false => Err(Error::InvalidData),
                }
            }
        }
    }

    /// Get signature length.
    pub fn signature_len(&self) -> usize {
        match self {
            Self::Ed25519(_) => 64usize,
            Self::P256(_, _) => 64usize,
            Self::DsaSha1(_) => 40usize,
        }
    }
}

impl AsRef<[u8]> for SigningPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(key) => key.as_bytes(),
            Self::P256(pk, _) => &pk.as_bytes()[1..],
            Self::DsaSha1(key) => key.as_bytes(),
        }
    }
}
