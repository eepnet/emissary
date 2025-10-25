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

//! I2NP message parser
//!
//! https://geti2p.net/spec/i2np

use crate::{
    crypto::sha256::Sha256, error::parser::I2npParseError, runtime::Runtime,
    subsystem::SubsystemKind,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::{fmt, time::Duration};

pub mod database;
pub mod delivery_status;
pub mod garlic;
pub mod tunnel;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2np";

/// Poly1305 authentication tag length.
const ROUTER_HASH_LEN: usize = 32usize;

/// AES key length.
const AES256_KEY_LEN: usize = 32usize;

/// AES IV length.
const AES256_IV_LEN: usize = 16usize;

/// I2NP short header size.
const I2NP_SHORT_HEADER_LEN: usize = 9usize;

/// I2NP standard header size.
const I2NP_STANDARD_HEADER_LEN: usize = 16usize;

/// I2NP message expiration timeout.
///
/// Defaults to 8000 milliseconds.
pub const I2NP_MESSAGE_EXPIRATION: Duration = Duration::from_millis(8000);

/// Message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Database store.
    DatabaseStore,

    /// Database lookup.
    DatabaseLookup,

    /// Database search reply.
    DatabaseSearchReply,

    /// Delivery status.
    DeliveryStatus,

    /// Garlic message.
    Garlic,

    /// Tunnel data.
    TunnelData,

    /// Tunnel gateway.
    TunnelGateway,

    /// Generic data.
    Data,

    /// Tunnel build.
    TunnelBuild,

    /// Tunnel build reply.
    TunnelBuildReply,

    /// Variable tunnel build.
    VariableTunnelBuild,

    /// Variable tunnel build reply.
    VariableTunnelBuildReply,

    /// Short tunnel build.
    ShortTunnelBuild,

    /// Outbound tunnel build reply.
    OutboundTunnelBuildReply,
}

impl MessageType {
    /// Serialize [`MessageType`].
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::DatabaseStore => 1,
            Self::DatabaseLookup => 2,
            Self::DatabaseSearchReply => 3,
            Self::DeliveryStatus => 10,
            Self::Garlic => 11,
            Self::TunnelData => 18,
            Self::TunnelGateway => 19,
            Self::Data => 20,
            Self::TunnelBuild => 21,
            Self::TunnelBuildReply => 22,
            Self::VariableTunnelBuild => 23,
            Self::VariableTunnelBuildReply => 24,
            Self::ShortTunnelBuild => 25,
            Self::OutboundTunnelBuildReply => 26,
        }
    }

    /// Try to convert `msg_type` into `MessageType`.
    pub fn from_u8(msg_type: u8) -> Option<MessageType> {
        match msg_type {
            1 => Some(Self::DatabaseStore),
            2 => Some(Self::DatabaseLookup),
            3 => Some(Self::DatabaseSearchReply),
            10 => Some(Self::DeliveryStatus),
            11 => Some(Self::Garlic),
            18 => Some(Self::TunnelData),
            19 => Some(Self::TunnelGateway),
            20 => Some(Self::Data),
            21 => Some(Self::TunnelBuild),
            22 => Some(Self::TunnelBuildReply),
            23 => Some(Self::VariableTunnelBuild),
            24 => Some(Self::VariableTunnelBuildReply),
            25 => Some(Self::ShortTunnelBuild),
            26 => Some(Self::OutboundTunnelBuildReply),
            msg_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?msg_type,
                    "invalid message id",
                );
                None
            }
        }
    }
}

/// Hop role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopRole {
    /// Router acts as the inbound endpoint.
    InboundGateway,

    /// Router acts as the outbound endpoint.
    OutboundEndpoint,

    /// Router acts as an intermediary participant.
    Participant,
}

impl HopRole {
    /// Serialize `HopRole`.
    fn as_u8(self) -> u8 {
        match self {
            HopRole::InboundGateway => 0x80,
            HopRole::OutboundEndpoint => 0x40,
            HopRole::Participant => 0x00,
        }
    }

    /// Try to convert `role` into `HopRole`.
    fn from_u8(role: u8) -> Option<HopRole> {
        match role {
            0x80 => Some(HopRole::InboundGateway),
            0x40 => Some(HopRole::OutboundEndpoint),
            0x00 => Some(HopRole::Participant),
            role => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?role,
                    "unrecognized flag"
                );
                None
            }
        }
    }
}

/// I2NP message builder.
#[derive(Debug)]
pub enum MessageBuilder<'a> {
    /// Standard I2NP header (tunnel messages).
    Standard {
        /// Message type.
        message_type: Option<MessageType>,

        /// Message ID.
        message_id: Option<u32>,

        /// Expiration.
        expiration: Option<Duration>,

        /// Raw, unparsed payload.
        payload: Option<&'a [u8]>,
    },

    /// Short I2NP header (NTCP2/SSU2).
    Short {
        /// Message type.
        message_type: Option<MessageType>,

        /// Message ID.
        message_id: Option<u32>,

        /// Expiration.
        expiration: Option<Duration>,

        /// Raw, unparsed payload.
        payload: Option<&'a [u8]>,
    },
}

impl<'a> MessageBuilder<'a> {
    /// Create I2NP message with short header.
    pub fn short() -> Self {
        Self::Short {
            message_type: None,
            message_id: None,
            expiration: None,
            payload: None,
        }
    }

    /// Create I2NP message with standard header.
    pub fn standard() -> Self {
        Self::Standard {
            message_type: None,
            message_id: None,
            expiration: None,
            payload: None,
        }
    }

    /// Add expiration.
    pub fn with_expiration(mut self, message_expiration: Duration) -> Self {
        match self {
            Self::Standard {
                expiration: ref mut exp,
                ..
            }
            | Self::Short {
                expiration: ref mut exp,
                ..
            } => *exp = Some(message_expiration),
        }

        self
    }

    /// Add mesage type.
    pub fn with_message_type(mut self, message_type: MessageType) -> Self {
        match self {
            Self::Standard {
                message_type: ref mut msg_type,
                ..
            }
            | Self::Short {
                message_type: ref mut msg_type,
                ..
            } => *msg_type = Some(message_type),
        }

        self
    }

    /// Add message ID.
    pub fn with_message_id<T: Into<u32>>(mut self, message_id: T) -> Self {
        match self {
            Self::Standard {
                message_id: ref mut msg_id,
                ..
            }
            | Self::Short {
                message_id: ref mut msg_id,
                ..
            } => *msg_id = Some(message_id.into()),
        }

        self
    }

    /// Add payload
    pub fn with_payload(mut self, payload: &'a [u8]) -> Self {
        match self {
            Self::Standard {
                payload: ref mut msg_payload,
                ..
            }
            | Self::Short {
                payload: ref mut msg_payload,
                ..
            } => *msg_payload = Some(payload),
        }

        self
    }

    /// Serialize I2NP message.
    pub fn build(self) -> Vec<u8> {
        match self {
            Self::Standard {
                message_type,
                message_id,
                expiration,
                mut payload,
            } => {
                let payload = payload.take().expect("to exist");
                let mut out = BytesMut::with_capacity(payload.len() + I2NP_STANDARD_HEADER_LEN);

                out.put_u8(message_type.expect("to exist").as_u8());
                out.put_u32(message_id.expect("to exist"));
                out.put_u64(expiration.expect("to exist").as_millis() as u64);
                out.put_u16(payload.len() as u16);
                out.put_u8(Sha256::new().update(payload).finalize()[0]); // checksum
                out.put_slice(payload);

                out.freeze().to_vec()
            }
            Self::Short {
                message_type,
                message_id,
                expiration,
                mut payload,
            } => {
                let payload = payload.take().expect("to exist");

                // two extra bytes for the length field
                let mut out = BytesMut::with_capacity(payload.len() + I2NP_SHORT_HEADER_LEN + 2);

                out.put_u16((payload.len() + I2NP_SHORT_HEADER_LEN) as u16);
                out.put_u8(message_type.expect("to exist").as_u8());
                out.put_u32(message_id.expect("to exist"));
                out.put_u32(expiration.expect("to exist").as_secs() as u32);
                out.put_slice(payload);

                out.freeze().to_vec()
            }
        }
    }
}

/// Raw, unparsed I2NP message.
///
/// These messages are dispatched by the enabled transports
/// to appropriate subsystems, based on `message_type`.
#[derive(Clone)]
pub struct Message {
    /// Message type.
    pub message_type: MessageType,

    /// Message ID.
    pub message_id: u32,

    /// Expiration.
    pub expiration: Duration,

    /// Raw, unparsed payload.
    pub payload: Vec<u8>,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            message_type: MessageType::Data,
            message_id: 0u32,
            expiration: Duration::new(0u64, 0u32),
            payload: Vec::new(),
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("message_type", &self.message_type)
            .field("message_id", &self.message_id)
            .field("expiration", &self.expiration)
            .finish_non_exhaustive()
    }
}

impl Message {
    /// Attempt to parse I2NP message with short header from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame_short(input: &[u8]) -> IResult<&[u8], Message, I2npParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;

        if size as usize <= I2NP_SHORT_HEADER_LEN {
            return Err(Err::Error(I2npParseError::TooShortHeader));
        }

        let (rest, payload) = take(size as usize - I2NP_SHORT_HEADER_LEN)(rest)?;
        let message_type = MessageType::from_u8(message_type)
            .ok_or(Err::Error(I2npParseError::InvalidMessage(message_type)))?;

        Ok((
            rest,
            Message {
                message_type,
                message_id,
                expiration: Duration::from_secs(expiration as u64),
                payload: payload.to_vec(),
            },
        ))
    }

    /// Attempt to parse I2NP message with standard header from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame_standard(input: &[u8]) -> IResult<&[u8], Message, I2npParseError> {
        let (rest, message_type) = be_u8(input)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u64(rest)?;
        let (rest, size) = be_u16(rest)?;
        let (rest, _checksum) = be_u8(rest)?;
        let (rest, payload) = take(size as usize)(rest)?;

        if payload.is_empty() {
            return Err(Err::Error(I2npParseError::EmptyPayload));
        }

        let message_type = MessageType::from_u8(message_type)
            .ok_or(Err::Error(I2npParseError::InvalidMessage(message_type)))?;

        Ok((
            rest,
            Message {
                message_type,
                message_id,
                expiration: Duration::from_millis(expiration),
                payload: payload.to_vec(),
            },
        ))
    }

    /// Attempt to parse I2NP message with short header from `input`.
    pub fn parse_short(input: &[u8]) -> Result<Message, I2npParseError> {
        Ok(Self::parse_frame_short(input)?.1)
    }

    /// Attempt to parse I2NP message with standard header from `input`.
    pub fn parse_standard(input: &[u8]) -> Result<Message, I2npParseError> {
        Ok(Self::parse_frame_standard(input)?.1)
    }

    /// Get destination subsystem of the message based on its message type.
    pub fn destination(&self) -> SubsystemKind {
        match self.message_type {
            MessageType::DatabaseStore
            | MessageType::DatabaseLookup
            | MessageType::DatabaseSearchReply => SubsystemKind::NetDb,
            _ => SubsystemKind::Tunnel,
        }
    }

    /// Serialize `self` into an I2NP message with short header.
    pub fn serialize_short(self) -> Vec<u8> {
        MessageBuilder::short()
            .with_expiration(self.expiration)
            .with_message_type(self.message_type)
            .with_message_id(self.message_id)
            .with_payload(&self.payload)
            .build()
    }

    /// Serialize `self` into an I2NP message with standard header.
    pub fn serialize_standard(self) -> Vec<u8> {
        MessageBuilder::standard()
            .with_expiration(self.expiration)
            .with_message_type(self.message_type)
            .with_message_id(self.message_id)
            .with_payload(&self.payload)
            .build()
    }

    /// Get serialized length of [`Message`] with short header
    pub fn serialized_len_short(&self) -> usize {
        self.payload.len() + I2NP_SHORT_HEADER_LEN + 2 // length field
    }

    /// Get serialized length of [`Message`] with long header
    pub fn serialized_len_long(&self) -> usize {
        self.payload.len() + I2NP_STANDARD_HEADER_LEN
    }

    /// Returns `true` if [`Message`] is expired.
    pub fn is_expired<R: Runtime>(&self) -> bool {
        self.expiration < R::time_since_epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[test]
    fn parse_short_as_standard() {
        let message = MessageBuilder::short()
            .with_message_type(MessageType::DeliveryStatus)
            .with_message_id(1337u32)
            .with_expiration(Duration::from_secs(0xdeadbeefu64))
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        assert_eq!(
            Message::parse_standard(&message).unwrap_err(),
            I2npParseError::InvalidBitstream
        );
    }

    #[test]
    fn parse_standard_as_short() {
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::DeliveryStatus)
            .with_message_id(1337u32)
            .with_expiration(Duration::from_secs(0xdeadbeefu64))
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        assert_eq!(
            Message::parse_short(&message).unwrap_err(),
            I2npParseError::InvalidBitstream
        );
    }

    #[test]
    fn invalid_message_type() {
        let mut out = BytesMut::with_capacity(4 + I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16((4 + I2NP_SHORT_HEADER_LEN) as u16);
        out.put_u8(252);
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        out.put_slice(&vec![1, 2, 3, 4]);
        let serialized = out.freeze().to_vec();

        assert_eq!(
            Message::parse_short(&serialized).unwrap_err(),
            I2npParseError::InvalidMessage(252)
        );
    }

    #[test]
    fn incomplete_short_header() {
        assert_eq!(
            Message::parse_short(&vec![1, 2, 3, 4]).unwrap_err(),
            I2npParseError::InvalidBitstream
        );
    }

    #[test]
    fn incomplete_standard_header() {
        assert_eq!(
            Message::parse_standard(&vec![1, 2, 3, 4]).unwrap_err(),
            I2npParseError::InvalidBitstream
        );
    }

    #[test]
    fn invalid_size_short() {
        let mut out = BytesMut::with_capacity(4 + I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16(4u16); // invalid size
        out.put_u8(MessageType::DeliveryStatus.as_u8());
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        out.put_slice(&vec![1, 2, 3, 4]);
        let serialized = out.freeze().to_vec();

        assert_eq!(
            Message::parse_short(&serialized).unwrap_err(),
            I2npParseError::TooShortHeader
        );
    }

    #[test]
    fn empty_payload_short() {
        let mut out = BytesMut::with_capacity(I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16(4u16); // invalid size
        out.put_u8(MessageType::DeliveryStatus.as_u8());
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        let serialized = out.freeze().to_vec();

        assert_eq!(
            Message::parse_short(&serialized).unwrap_err(),
            I2npParseError::TooShortHeader
        );
    }

    #[test]
    fn empty_payload_standard() {
        let mut out = BytesMut::with_capacity(I2NP_SHORT_HEADER_LEN + 2);

        out.put_u16(4u16); // invalid size
        out.put_u8(MessageType::DeliveryStatus.as_u8());
        out.put_u32(13371338u32);
        out.put_u32(0xdeadbeefu32);
        let serialized = out.freeze().to_vec();

        assert_eq!(
            Message::parse_short(&serialized).unwrap_err(),
            I2npParseError::TooShortHeader
        );
    }

    #[test]
    fn i2np_message_expired_short() {
        let message = MessageBuilder::short()
            .with_message_type(MessageType::DeliveryStatus)
            .with_message_id(1337u32)
            .with_expiration(MockRuntime::time_since_epoch() - Duration::from_secs(10))
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        assert!(Message::parse_short(&message).unwrap().is_expired::<MockRuntime>());
    }

    #[test]
    fn i2np_message_expired_standard() {
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::DeliveryStatus)
            .with_message_id(1337u32)
            .with_expiration(MockRuntime::time_since_epoch() - I2NP_MESSAGE_EXPIRATION)
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        assert!(Message::parse_standard(&message).unwrap().is_expired::<MockRuntime>());
    }
}
