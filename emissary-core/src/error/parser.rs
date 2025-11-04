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

use crate::primitives::Str;

use nom::{
    error::{ErrorKind, ParseError},
    Err,
};

use core::str::Utf8Error;

/// Offline signature parse error.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum OfflineSignatureParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid public key.
    InvalidPublicKey,

    /// Unsupported public key.
    UnsupportedPublicKey(u16),

    /// Invalid signature.
    InvalidSignature,

    /// Offline signature has expired.
    Expired,
}

/// Destination parse error.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DestinationParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Destination is too short.
    InvalidLength,

    /// Unsupported signing key kind.
    UnsupportedSigningKey(u16),

    /// Unsupported private key kind.
    UnsupportedPrivateKey(u16),

    /// Unsupported certificate kind.
    UnsupportedCertificate(u8),

    /// DSA-SHA1 signing key but not a NULL certificate.
    NotANullCertificate,
}

/// `Str` parse error.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum StrParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid UTF-8 bytes.
    Utf8(Utf8Error),
}

/// `Date` parse error.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DateParseError {
    /// Invalid bitstream.
    InvalidBitstream,
}

/// Mapping parse error.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MappingParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid `Str`.
    Str(StrParseError),
}

impl From<StrParseError> for MappingParseError {
    fn from(value: StrParseError) -> Self {
        Self::Str(value)
    }
}

/// Lease set parser error.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LeaseSetParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid offline signature.
    OfflineSignature(OfflineSignatureParseError),

    /// Invalid destination.
    Destination(DestinationParseError),

    /// Invalid mapping.
    Options(MappingParseError),

    /// Lease set did not contain any supported public key.
    NoSupportedPublicKey,

    /// Invalid number of leases.
    InvalidLeaseCount(u8),

    /// Lease set didn't contain any valid leases.
    NoValidLeases,

    /// Invalid signature.
    InvalidSignature,

    /// Invalid offline signature.
    InvalidOfflineSignature,

    /// Invalid lease list.
    InvalidLeaseList,
}

impl From<OfflineSignatureParseError> for LeaseSetParseError {
    fn from(value: OfflineSignatureParseError) -> Self {
        Self::OfflineSignature(value)
    }
}

impl From<DestinationParseError> for LeaseSetParseError {
    fn from(value: DestinationParseError) -> Self {
        Self::Destination(value)
    }
}

impl From<MappingParseError> for LeaseSetParseError {
    fn from(value: MappingParseError) -> Self {
        Self::Options(value)
    }
}

/// Parse error for `Flags`.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum FlagsParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid offline signature.
    OfflineSignature(OfflineSignatureParseError),

    /// Invalid destination.
    Destination(DestinationParseError),

    /// Destination missing.
    DestinationMissing,
}

impl From<DestinationParseError> for FlagsParseError {
    fn from(value: DestinationParseError) -> Self {
        Self::Destination(value)
    }
}

impl From<OfflineSignatureParseError> for FlagsParseError {
    fn from(value: OfflineSignatureParseError) -> Self {
        Self::OfflineSignature(value)
    }
}

/// Parse error for `DatagramFlags`.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DatagramFlagsParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid length.
    InvalidLength,

    /// Unknown datagram version.
    UnknownVersion,

    /// Invalid `Mapping`
    InvalidOptions(MappingParseError),
}

impl From<MappingParseError> for DatagramFlagsParseError {
    fn from(value: MappingParseError) -> Self {
        Self::InvalidOptions(value)
    }
}

/// Parse error for `Packet`.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid flags.
    Flags(FlagsParseError),

    /// Packet is too short.
    PacketTooShort,

    /// Invalid NACK list.
    InvalidNackList,
}

impl From<FlagsParseError> for PacketParseError {
    fn from(value: FlagsParseError) -> Self {
        Self::Flags(value)
    }
}

/// Parse error for `RouterIdentity`
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RouterIdentityParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Destination is too short.
    InvalidLength(usize),

    /// Invalid certificate.
    InvalidCertificate((u8, u16)),

    /// Invalid public key.
    InvalidPublicKey(u16),

    /// Invalid signing key.
    InvalidSigningKey(u16),
}

/// Parse error for `RouterInfo`
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouterInfoParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid `Mapping`.
    InvalidOptions(MappingParseError),

    /// Invalid `Date`
    InvalidDate(DateParseError),

    /// Invalid `RouterIdentity`
    InvalidIdentity(RouterIdentityParseError),

    /// Capabilities not specified.
    CapabilitiesMissing,

    /// Invalid capabilities.
    InvalidCapabilities(Str),

    /// Network ID not specified.
    NetIdMissing,

    /// Invalid signature.
    InvalidSignature,
}

impl From<MappingParseError> for RouterInfoParseError {
    fn from(value: MappingParseError) -> Self {
        Self::InvalidOptions(value)
    }
}

impl From<DateParseError> for RouterInfoParseError {
    fn from(value: DateParseError) -> Self {
        Self::InvalidDate(value)
    }
}

impl From<RouterIdentityParseError> for RouterInfoParseError {
    fn from(value: RouterIdentityParseError) -> Self {
        Self::InvalidIdentity(value)
    }
}

/// Parse error for `RouterAddress`
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouterAddressParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid options.
    Options(MappingParseError),

    /// Invalid expiration.
    InvalidExpiration,

    /// Invalid transport.
    InvalidTransport,

    /// Invalid options.
    InvalidOptions(MappingParseError),
}

impl From<MappingParseError> for RouterAddressParseError {
    fn from(value: MappingParseError) -> Self {
        Self::InvalidOptions(value)
    }
}

/// Parse error for `TunnelBuildRecord`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TunnelBuildRecordParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid tunnel options.
    Options(MappingParseError),

    /// Invalid value for a tunnel hop.
    InvalidHop(u8),
}

impl From<MappingParseError> for TunnelBuildRecordParseError {
    fn from(value: MappingParseError) -> Self {
        Self::Options(value)
    }
}

/// Parse error for `DatabaseStore`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DatabaseStoreParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid database store type.
    InvalidStoreType(u8),

    /// GZIP compression failed.
    CompressionFailed,

    /// Invalid `RouterInfo`.
    RouterInfo(RouterInfoParseError),

    /// Invalid lease set.
    LeaseSet(LeaseSetParseError),

    /// Unsupported store type.
    UnsupportedStoreType(u8),
}

impl From<RouterInfoParseError> for DatabaseStoreParseError {
    fn from(value: RouterInfoParseError) -> Self {
        Self::RouterInfo(value)
    }
}

impl From<LeaseSetParseError> for DatabaseStoreParseError {
    fn from(value: LeaseSetParseError) -> Self {
        Self::LeaseSet(value)
    }
}

/// Parse error for `DatabaseLookup`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DatabaseLookupParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid lookup type.
    InvalidLookupType(u8),

    /// Too long ignore list.
    TooLongIgnoreList(u16),

    /// Invalid ignore list.
    InvalidIgnoreList,

    /// Lookup encryption not supported.
    LookupEncryptionNotSupported,
}

/// Parse error for `DatabaseSearchReply`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DatabaseSearchReplyParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid reply hash list.
    InvalidReplyHashList,
}

/// Parse error for `TunnelData`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TunnelDataParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Invalid fragment kind.
    InvalidFragment(u8),

    /// Invalid message kind.
    InvalidMessage(u8),

    /// Unknown delivery kind.
    InvalidDelivery(u8),
}

/// Parse error for `Garlic`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum GarlicParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Encrypted garlic message not supported.
    EncryptionNotSupported,

    /// Delay not supported.
    DelayNotSupported,

    /// Invalid delivery kind.
    InvalidDelivery(u8),

    /// Invalid message kind.
    InvalidMessage(u8),

    /// Invalid message size.
    InvalidSize,

    /// Invalid ACK list.
    InvalidAcks,
}

/// Parse error for an I2NP message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum I2npParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Too short header.
    TooShortHeader,

    /// Invalid message kind.
    InvalidMessage(u8),

    /// Payload of the message is empty.
    EmptyPayload,
}

/// Parse error for NTCP2 message block.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ntcp2ParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Empty router info block.
    EmptyRouterInfo,

    /// Invalid I2NP message.
    I2npMessage(I2npParseError),

    /// Invalid NTCP2 message block.
    InvalidBlock(u8),
}

impl From<I2npParseError> for Ntcp2ParseError {
    fn from(value: I2npParseError) -> Self {
        Self::I2npMessage(value)
    }
}

/// Parse error for SSU2 message block.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ssu2ParseError {
    /// Invalid bitstream.
    InvalidBitstream,

    /// Empty router info block.
    EmptyRouterInfo,

    /// Compressed router infos not supported.
    CompressedRouterInfo,

    /// Malformed router info.
    RouterInfo(RouterInfoParseError),

    /// Invalid I2NP message.
    I2npMessage(I2npParseError),

    /// Invalid message type for first fragment.
    InvalidMessageTypeFirstFrag(u8),

    /// Empty first fragment.
    EmptyFirstFragment,

    /// First fragment is too short.
    FirstFragmentTooShort,

    /// Empty follow-on fragment.
    EmptyFollowOnFragment,

    /// Follow-on is too short.
    FollowOnFragmentTooShort,

    /// Invalid SSU2 message block
    InvalidBlock(u8),
}

impl From<I2npParseError> for Ssu2ParseError {
    fn from(value: I2npParseError) -> Self {
        Self::I2npMessage(value)
    }
}

impl From<RouterInfoParseError> for Ssu2ParseError {
    fn from(value: RouterInfoParseError) -> Self {
        Self::RouterInfo(value)
    }
}

macro_rules! derive_nom_parse_error {
    ($error:ident) => {
        impl ParseError<&[u8]> for $error {
            fn from_error_kind(_: &[u8], _: ErrorKind) -> Self {
                Self::InvalidBitstream
            }

            fn append(_: &[u8], _: ErrorKind, _: Self) -> Self {
                Self::InvalidBitstream
            }
        }

        impl From<Err<$error>> for $error {
            fn from(value: Err<$error>) -> Self {
                match value {
                    Err::Incomplete(_) => $error::InvalidBitstream,
                    Err::Error(error) | Err::Failure(error) => error,
                }
            }
        }
    };
}

derive_nom_parse_error!(DatabaseLookupParseError);
derive_nom_parse_error!(DatabaseSearchReplyParseError);
derive_nom_parse_error!(DatabaseStoreParseError);
derive_nom_parse_error!(DateParseError);
derive_nom_parse_error!(DestinationParseError);
derive_nom_parse_error!(FlagsParseError);
derive_nom_parse_error!(DatagramFlagsParseError);
derive_nom_parse_error!(GarlicParseError);
derive_nom_parse_error!(I2npParseError);
derive_nom_parse_error!(LeaseSetParseError);
derive_nom_parse_error!(MappingParseError);
derive_nom_parse_error!(Ntcp2ParseError);
derive_nom_parse_error!(OfflineSignatureParseError);
derive_nom_parse_error!(PacketParseError);
derive_nom_parse_error!(RouterAddressParseError);
derive_nom_parse_error!(RouterIdentityParseError);
derive_nom_parse_error!(RouterInfoParseError);
derive_nom_parse_error!(Ssu2ParseError);
derive_nom_parse_error!(StrParseError);
derive_nom_parse_error!(TunnelBuildRecordParseError);
derive_nom_parse_error!(TunnelDataParseError);
