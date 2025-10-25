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
    crypto::StaticPublicKey,
    error::parser::GarlicParseError,
    i2np::{Message, MessageType, LOG_TARGET},
    primitives::MessageId,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::{boxed::Box, vec::Vec};
use core::{fmt, time::Duration};

/// Garlic message header length.
///
/// Message type (1 byte) + size (2 bytes).
const GARLIC_HEADER_LEN: usize = 3;

/// Garlic message overhead.
///
/// Poly13055 tag, ephemeral key and garlic message length.
pub const GARLIC_MESSAGE_OVERHEAD: usize = 16 + 32 + 4;

/// Garlic message type.
#[derive(Debug)]
pub enum GarlicMessageType {
    /// Date time.
    DateTime,

    /// Termination.
    Termination,

    /// Options.
    Options,

    /// Message number.
    MessageNumber,

    /// Next key.
    NextKey,

    /// ACK.
    Ack,

    /// ACK request.
    AckRequest,

    /// Garlic clove.
    GarlicClove,

    /// Padding.
    Padding,
}

impl GarlicMessageType {
    /// Attempt to convert `byte` into [`GarlicMessageType`].
    fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::DateTime),
            4 => Some(Self::Termination),
            5 => Some(Self::Options),
            6 => Some(Self::MessageNumber),
            7 => Some(Self::NextKey),
            8 => Some(Self::Ack),
            9 => Some(Self::AckRequest),
            11 => Some(Self::GarlicClove),
            254 => Some(Self::Padding),
            _ => None,
        }
    }

    /// Serialize [`GarlicMessageType`].
    fn as_u8(self) -> u8 {
        match self {
            Self::DateTime => 0,
            Self::Termination => 4,
            Self::Options => 5,
            Self::MessageNumber => 6,
            Self::NextKey => 7,
            Self::Ack => 8,
            Self::AckRequest => 9,
            Self::GarlicClove => 11,
            Self::Padding => 254,
        }
    }
}

/// Garlic clove delivery instructions.
#[derive(Debug)]
pub enum DeliveryInstructions<'a> {
    /// Clove meant for the local node
    Local,

    /// Clove meant for a `Destination`.
    Destination {
        /// Hash of the destination.
        hash: &'a [u8],
    },

    /// Clove meant for a router.
    Router {
        /// Hash of the router.
        hash: &'a [u8],
    },

    /// Clove meant for a tunnel.
    Tunnel {
        /// Hash of the tunnel.
        hash: &'a [u8],

        /// Tunnel ID.
        tunnel_id: u32,
    },
}

/// Owned garlic clove delivery instructions.
#[derive(Debug)]
pub enum OwnedDeliveryInstructions {
    /// Clove meant for the local node
    Local,

    /// Clove meant for a `Destination`.
    Destination {
        /// Hash of the destination.
        hash: Vec<u8>,
    },

    /// Clove meant for a router.
    Router {
        /// Hash of the router.
        hash: Vec<u8>,
    },

    /// Clove meant for a tunnel.
    Tunnel {
        /// Hash of the tunnel.
        hash: Vec<u8>,

        /// Tunnel ID.
        tunnel_id: u32,
    },
}

impl<'a> From<&'a DeliveryInstructions<'a>> for OwnedDeliveryInstructions {
    fn from(value: &'a DeliveryInstructions<'a>) -> Self {
        match value {
            DeliveryInstructions::Local => OwnedDeliveryInstructions::Local,
            DeliveryInstructions::Destination { hash } => OwnedDeliveryInstructions::Destination {
                hash: hash.to_vec(),
            },
            DeliveryInstructions::Router { hash } => OwnedDeliveryInstructions::Router {
                hash: hash.to_vec(),
            },
            DeliveryInstructions::Tunnel { hash, tunnel_id } => OwnedDeliveryInstructions::Tunnel {
                hash: hash.to_vec(),
                tunnel_id: *tunnel_id,
            },
        }
    }
}

impl DeliveryInstructions<'_> {
    /// Get serialized length of the delivery instructions.
    fn serialized_len(&self) -> usize {
        match self {
            // 1-byte flag
            Self::Local => 1usize,

            // 1-byte flag + 32-byte destination/router hash
            Self::Destination { .. } | Self::Router { .. } => 33usize,

            // 1-byte flag + 32-byte router hash + 4-byte tunnel id
            Self::Tunnel { .. } => 37usize,
        }
    }

    /// Serialize [`DeliveryInstructions`] into a byte vector.
    fn serialize(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.serialized_len());

        match self {
            Self::Local => out.put_u8(0x00),
            Self::Destination { hash } => {
                out.put_u8(0x01 << 5);
                out.put_slice(hash);
            }
            Self::Router { hash } => {
                out.put_u8(0x02 << 5);
                out.put_slice(hash);
            }
            Self::Tunnel { hash, tunnel_id } => {
                out.put_u8(0x03 << 5);
                out.put_slice(hash);
                out.put_u32(tunnel_id);
            }
        }

        out
    }
}

/// Builder for [`NextKeyKind`].
pub struct NextKeyBuilder {
    /// Is the [`NextKeyKind`] forward.
    forward: bool,

    /// Public key sent to the remote.
    public_key: Option<StaticPublicKey>,

    /// Key ID.
    key_id: u16,

    /// Request reverse key.
    request_reverse_key: bool,
}

impl NextKeyBuilder {
    /// Create new [`NextKeyBuilder`] for forward key.
    pub fn forward(key_id: u16) -> Self {
        Self {
            forward: true,
            key_id,
            public_key: None,
            request_reverse_key: false,
        }
    }

    /// Create new [`NextKeyBuilder`] for reverse key.
    pub fn reverse(key_id: u16) -> Self {
        Self {
            forward: false,
            key_id,
            public_key: None,
            request_reverse_key: false,
        }
    }

    /// Specify `StaticPublicKey` for the `NextKey` block.
    pub fn with_public_key(mut self, public_key: StaticPublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Specify whether remote should send reverse key.
    ///
    /// By default, reverse key is not requested.
    pub fn with_request_reverse_key(mut self, request_reverse_key: bool) -> Self {
        self.request_reverse_key = request_reverse_key;
        self
    }

    /// Build [`NextKeyKind`]
    pub fn build(self) -> NextKeyKind {
        match self.forward {
            true => NextKeyKind::ForwardKey {
                key_id: self.key_id,
                public_key: self.public_key,
                reverse_key_requested: self.request_reverse_key,
            },
            false => NextKeyKind::ReverseKey {
                key_id: self.key_id,
                public_key: self.public_key,
            },
        }
    }
}

/// `NextKey` messsage kind.
pub enum NextKeyKind {
    /// Forward key.
    ForwardKey {
        /// Key ID.
        key_id: u16,

        /// Public key of the `Destination`, if sent.
        public_key: Option<StaticPublicKey>,

        /// Reverse key requested.
        reverse_key_requested: bool,
    },

    /// Reverse key.
    ReverseKey {
        /// Key ID.
        key_id: u16,

        /// Public key of the `Destination`, if requested.
        public_key: Option<StaticPublicKey>,
    },
}

impl NextKeyKind {
    /// Get serialized length of [`NextKey`].
    fn serialized_len(&self) -> usize {
        match self {
            NextKeyKind::ForwardKey { public_key, .. }
            | NextKeyKind::ReverseKey { public_key, .. }
                if public_key.is_some() =>
                GARLIC_HEADER_LEN + 3usize + 32usize, // flag + key id + public key
            _ => GARLIC_HEADER_LEN + 3usize, // flag + key id
        }
    }
}

impl fmt::Debug for NextKeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForwardKey {
                key_id,
                public_key,
                reverse_key_requested,
            } => f
                .debug_struct("NextKeyKind::ForwardKey")
                .field("key_id", &key_id)
                .field("key_exists", &public_key.is_some())
                .field("reverse_requested", &reverse_key_requested)
                .finish(),
            Self::ReverseKey { key_id, public_key } => f
                .debug_struct("NextKeyKind::ReverseKey")
                .field("key_id", &key_id)
                .field("key_exists", &public_key.is_some())
                .finish(),
        }
    }
}

/// Garlic message block.
pub enum GarlicMessageBlock<'a> {
    /// Date time.
    DateTime {
        /// Timestamp.
        timestamp: u32,
    },

    /// Session termination.
    Termination {},

    /// Options.
    Options {},

    /// Message number.
    MessageNumber {},

    /// Next key.
    NextKey {
        /// `NextKey` kind.
        kind: Box<NextKeyKind>,
    },

    /// ACK.
    Ack {
        /// Vector of (tag set ID, tag index) tuples
        acks: Vec<(u16, u16)>,
    },

    /// ACK request.
    AckRequest,

    /// Garlic clove.
    GarlicClove {
        /// I2NP message type.
        message_type: MessageType,

        /// Message ID.
        message_id: MessageId,

        /// Message expiration, seconds since UNIX epoch.
        expiration: Duration,

        /// Delivery instructions.
        delivery_instructions: DeliveryInstructions<'a>,

        /// Message body.
        message_body: &'a [u8],
    },

    /// Padding
    Padding {
        /// Padding bytes.
        padding: &'a [u8],
    },
}

impl fmt::Debug for GarlicMessageBlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DateTime { timestamp } => f
                .debug_struct("GarlicMessageBlock::DateTime")
                .field("timestamp", &timestamp)
                .finish(),
            Self::GarlicClove {
                message_type,
                message_id,
                expiration,
                delivery_instructions,
                ..
            } => f
                .debug_struct("GarlicMessageBlock::GarlicClove")
                .field("message_type", &message_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .field("delivery_instructions", &delivery_instructions)
                .finish_non_exhaustive(),
            Self::Padding { .. } =>
                f.debug_struct("GarlicMessageBlock::Padding").finish_non_exhaustive(),
            Self::Termination {} => f.debug_struct("GarlicMessageBlock::Termination").finish(),
            Self::Options {} => f.debug_struct("GarlicMessageBlock::Options").finish(),
            Self::MessageNumber {} => f.debug_struct("GarlicMessageBlock::MessageNumber").finish(),
            Self::NextKey { kind } =>
                f.debug_struct("GarlicMessageBlock::NextKey").field("kind", &kind).finish(),
            Self::Ack { acks } => f
                .debug_struct("GarlicMessageBlock::Ack")
                .field("num_acks", &acks.len())
                .finish(),
            Self::AckRequest => f.debug_struct("GarlicMessageBlock::AckRequest").finish(),
        }
    }
}

/// Garlic message.
#[derive(Debug)]
pub struct GarlicMessage<'a> {
    /// Message blocks.
    pub blocks: Vec<GarlicMessageBlock<'a>>,
}

impl<'a> GarlicMessage<'a> {
    /// Try to parse [`GarlicMessage::DateTime`] from `input`.
    fn parse_date_time(
        input: &'a [u8],
    ) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        Ok((rest, GarlicMessageBlock::DateTime { timestamp }))
    }

    /// Try to parse [`DeliveryInstructions`] for [`GarlicMessage::GarlicClove`] from `input`.
    fn parse_delivery_instructions(
        input: &'a [u8],
    ) -> IResult<&'a [u8], DeliveryInstructions<'a>, GarlicParseError> {
        let (rest, flag) = be_u8(input)?;

        if (flag >> 7) & 1 != 0 {
            return Err(Err::Error(GarlicParseError::EncryptionNotSupported));
        }

        if (flag >> 4) & 1 != 0 {
            return Err(Err::Error(GarlicParseError::DelayNotSupported));
        }

        match (flag >> 5) & 0x3 {
            0x00 => Ok((rest, DeliveryInstructions::Local)),
            0x01 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, DeliveryInstructions::Destination { hash }))
            }
            0x02 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, DeliveryInstructions::Router { hash }))
            }
            0x03 => {
                let (rest, hash) = take(32usize)(rest)?;
                let (rest, tunnel_id) = be_u32(rest)?;

                Ok((rest, DeliveryInstructions::Tunnel { hash, tunnel_id }))
            }
            kind => Err(Err::Error(GarlicParseError::InvalidDelivery(kind))),
        }
    }

    /// Try to parse [`GarlicMessage::GarlicClove`] from `input`.
    fn parse_garlic_clove(
        input: &'a [u8],
    ) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, delivery_instructions) = Self::parse_delivery_instructions(rest)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;

        let message_type = MessageType::from_u8(message_type)
            .ok_or(Err::Error(GarlicParseError::InvalidMessage(message_type)))?;

        // parse body and make sure it has sane length
        let message_body_len =
            (size as usize).saturating_sub(delivery_instructions.serialized_len() + 1 + 2 * 4);
        let (rest, message_body) = take(message_body_len)(rest)?;

        Ok((
            rest,
            GarlicMessageBlock::GarlicClove {
                message_type,
                message_id: MessageId::from(message_id),
                expiration: Duration::from_secs(expiration as u64),
                delivery_instructions,
                message_body,
            },
        ))
    }

    /// Try to parse [`GarlicMessage::Padding`] from `input`.
    fn parse_padding(
        input: &'a [u8],
    ) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, padding) = take(size)(rest)?;

        Ok((rest, GarlicMessageBlock::Padding { padding }))
    }

    /// Try to parse [`GarlicMessage::NextKey`] from `input`.
    fn parse_next_key(
        input: &'a [u8],
    ) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, flag) = be_u8(rest)?;
        let (rest, key_id) = be_u16(rest)?;

        let (rest, public_key) = match flag & 1 {
            0 => (rest, None),
            1 => {
                let (rest, key) = take(32usize)(rest)?;

                (
                    rest,
                    Some(StaticPublicKey::from(
                        TryInto::<[u8; 32]>::try_into(key).expect("to succeed"),
                    )),
                )
            }
            _ => unreachable!(),
        };

        let kind = match (flag >> 1) & 1 {
            1 => NextKeyKind::ReverseKey { key_id, public_key },
            0 => NextKeyKind::ForwardKey {
                key_id,
                public_key,
                reverse_key_requested: (flag >> 2) & 1 == 1,
            },
            _ => unreachable!(),
        };

        Ok((
            rest,
            GarlicMessageBlock::NextKey {
                kind: Box::new(kind),
            },
        ))
    }

    /// Try to parse [`GarlicMessage::AckRequest`] from `input`.
    fn parse_ack_request(
        input: &'a [u8],
    ) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, _flag) = be_u8(rest)?;

        Ok((rest, GarlicMessageBlock::AckRequest))
    }

    /// Try to parse [`GarlicMessage::Ack`] from `input`.
    fn parse_ack(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, size) = be_u16(input)?;

        if size % 4 != 0 {
            return Err(Err::Error(GarlicParseError::InvalidSize));
        }

        let (rest, acks) = (0..size / 4)
            .try_fold((rest, Vec::<(u16, u16)>::new()), |(rest, mut acks), _| {
                let (rest, tag_set_id) = be_u16::<_, ()>(rest).ok()?;
                let (rest, tag_index) = be_u16::<_, ()>(rest).ok()?;

                acks.push((tag_set_id, tag_index));

                Some((rest, acks))
            })
            .ok_or(Err::Error(GarlicParseError::InvalidAcks))?;

        Ok((rest, GarlicMessageBlock::Ack { acks }))
    }

    /// Attempt to parse [`GarlicMessageBlock`] from `input`.
    fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>, GarlicParseError> {
        let (rest, message_type) = be_u8(input)?;

        match GarlicMessageType::from_u8(message_type) {
            Some(GarlicMessageType::DateTime) => Self::parse_date_time(rest),
            Some(GarlicMessageType::GarlicClove) => Self::parse_garlic_clove(rest),
            Some(GarlicMessageType::Padding) => Self::parse_padding(rest),
            Some(GarlicMessageType::NextKey) => Self::parse_next_key(rest),
            Some(GarlicMessageType::AckRequest) => Self::parse_ack_request(rest),
            Some(GarlicMessageType::Ack) => Self::parse_ack(rest),
            parsed_message_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_type,
                    ?parsed_message_type,
                    "unsupported garlic message block",
                );
                let (rest, size) = be_u16(rest)?;
                let (rest, _) = take(size)(rest)?;

                Self::parse_frame(rest)
            }
        }
    }

    /// Recursively parse `input` into a vector of [`GarlicMessageBlock`]s
    fn parse_inner(
        input: &'a [u8],
        mut messages: Vec<GarlicMessageBlock<'a>>,
    ) -> Result<Vec<GarlicMessageBlock<'a>>, GarlicParseError> {
        let (rest, message) = Self::parse_frame(input)?;
        messages.push(message);

        match rest.is_empty() {
            true => Ok(messages),
            false => Self::parse_inner(rest, messages),
        }
    }

    /// Attempt to parse `input` into [`GarlicMessage`].
    pub fn parse(input: &'a [u8]) -> Result<Self, GarlicParseError> {
        Ok(Self {
            blocks: Self::parse_inner(input, Vec::new())?,
        })
    }

    /// Extract garlic tag from `message`.
    ///
    /// Panics if `message` isn't long enough to contain a garlic tag.
    pub fn garlic_tag(message: &Message) -> u64 {
        u64::from_le_bytes(
            TryInto::<[u8; 8]>::try_into(&message.payload[4..12]).expect("valid garlic message"),
        )
    }
}

/// Garlic message builder.
#[derive(Default)]
pub struct GarlicMessageBuilder<'a> {
    /// Cloves.
    cloves: Vec<GarlicMessageBlock<'a>>,

    /// Total message size.
    message_size: usize,
}

impl<'a> GarlicMessageBuilder<'a> {
    /// Add [`GarlicMessageBlock::DateTime`].
    pub fn with_date_time(mut self, timestamp: u32) -> Self {
        self.message_size = self.message_size.saturating_add(GARLIC_HEADER_LEN).saturating_add(4); // 4-byte timestamp
        self.cloves.push(GarlicMessageBlock::DateTime { timestamp });

        self
    }

    /// Add [`GarlicMessageBlock::GarlicClove`].
    pub fn with_garlic_clove(
        mut self,
        message_type: MessageType,
        message_id: MessageId,
        expiration: Duration,
        delivery_instructions: DeliveryInstructions<'a>,
        message_body: &'a [u8],
    ) -> Self {
        self.message_size = self
            .message_size
            .saturating_add(GARLIC_HEADER_LEN)
            .saturating_add(delivery_instructions.serialized_len())
            .saturating_add(1) // message type
            .saturating_add(4) // message id
            .saturating_add(4) // expiration
            .saturating_add(message_body.len());

        self.cloves.push(GarlicMessageBlock::GarlicClove {
            message_type,
            message_id,
            expiration,
            delivery_instructions,
            message_body,
        });

        self
    }

    // Add [`GarlicMessageBlock::NextKey`]
    pub fn with_next_key(mut self, kind: NextKeyKind) -> Self {
        self.message_size += kind.serialized_len();
        self.cloves.push(GarlicMessageBlock::NextKey {
            kind: Box::new(kind),
        });
        self
    }

    /// Add [`GarlicMessageBlock::AckRequest`].
    pub fn with_ack_request(mut self) -> Self {
        self.message_size += GARLIC_HEADER_LEN + 1; // 1 byte flag
        self.cloves.push(GarlicMessageBlock::AckRequest);
        self
    }

    /// Add [`GarlicMessageBlock::Ack`].
    pub fn with_ack(mut self, acks: Vec<(u16, u16)>) -> Self {
        self.message_size += GARLIC_HEADER_LEN + acks.len() * 4;
        self.cloves.push(GarlicMessageBlock::Ack { acks });
        self
    }

    /// Serialize [`GarlicMessageBuilder`] into a byte vector.
    pub fn build(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.message_size);

        for clove in self.cloves {
            match clove {
                GarlicMessageBlock::DateTime { timestamp } => {
                    out.put_u8(GarlicMessageType::DateTime.as_u8());
                    out.put_u16(4u16); // size of `timestamp`
                    out.put_u32(timestamp);
                }
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => {
                    out.put_u8(GarlicMessageType::GarlicClove.as_u8());
                    out.put_u16(
                        delivery_instructions
                            .serialized_len()
                            .saturating_add(1) // message type
                            .saturating_add(4) // message id
                            .saturating_add(4) // expiration
                            .saturating_add(message_body.len()) as u16,
                    );
                    out.put_slice(&delivery_instructions.serialize());
                    out.put_u8(message_type.as_u8());
                    out.put_u32(*message_id);
                    out.put_u32(expiration.as_secs() as u32);
                    out.put_slice(message_body);
                }
                GarlicMessageBlock::NextKey { kind } => match *kind {
                    NextKeyKind::ForwardKey {
                        key_id,
                        public_key,
                        reverse_key_requested,
                    } => {
                        out.put_u8(GarlicMessageType::NextKey.as_u8());
                        out.put_u16(if public_key.is_some() { 35u16 } else { 3u16 });
                        out.put_u8(match (public_key.is_some(), reverse_key_requested) {
                            (true, true) => 0x01 | 0x04, // key present + request reverse key
                            (true, false) => 0x01,       // key present
                            (false, true) => 0x04,       // request reverse key
                            (false, false) => panic!(
                                "state mismatch: no public key and reverse key not requested"
                            ),
                        });
                        out.put_u16(key_id);

                        if let Some(public_key) = public_key {
                            out.put_slice(public_key.as_ref());
                        }
                    }
                    NextKeyKind::ReverseKey { key_id, public_key } => {
                        out.put_u8(GarlicMessageType::NextKey.as_u8());

                        match public_key {
                            Some(public_key) => {
                                out.put_u16(35u16);
                                out.put_u8(0x01 | 0x02); // key present + reverse key
                                out.put_u16(key_id);
                                out.put_slice(public_key.as_ref());
                            }
                            None => {
                                out.put_u16(3u16);
                                out.put_u8(0x02); // reverse key
                                out.put_u16(key_id);
                            }
                        }
                    }
                },
                GarlicMessageBlock::AckRequest => {
                    out.put_u8(GarlicMessageType::AckRequest.as_u8());
                    out.put_u16(1u16);
                    out.put_u8(0u8); // flag, unused
                }
                GarlicMessageBlock::Ack { acks } => {
                    out.put_u8(GarlicMessageType::Ack.as_u8());
                    out.put_u16(acks.len() as u16 * 4);

                    for (tag_set_id, tag_index) in acks {
                        out.put_u16(tag_set_id);
                        out.put_u16(tag_index);
                    }
                }
                block => todo!("unimplemented block: {block:?}"),
            }
        }

        out.freeze().to_vec()
    }
}

/// Garlic clove.
pub struct GarlicClove {
    /// I2NP message type.
    pub message_type: MessageType,

    /// Message ID.
    pub message_id: MessageId,

    /// Message expiration, seconds since UNIX epoch.
    pub expiration: Duration,

    /// Delivery instructions.
    pub delivery_instructions: OwnedDeliveryInstructions,

    /// Message body.
    pub message_body: Vec<u8>,
}

impl fmt::Debug for GarlicClove {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GarlicClove")
            .field("message_type", &self.message_type)
            .field("message_id", &self.message_id)
            .field("expiration", &self.expiration)
            .field("delivery_instructions", &self.delivery_instructions)
            .field("message_len", &self.message_body.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_garlic_message_block() {
        let mut message = GarlicMessageBuilder::default()
            .with_date_time(1337u32)
            .with_garlic_clove(
                MessageType::DatabaseStore,
                MessageId::from(1337u32),
                Duration::from_secs(1337u64),
                DeliveryInstructions::Local,
                &vec![1, 2, 3, 4],
            )
            .build();

        message.extend_from_slice(&{
            let mut out = BytesMut::with_capacity(1 + 2 + 2);

            out.put_u8(15u8); // unknown garlic message block type
            out.put_u16(15u16);
            out.put_slice(&vec![0xaa; 15]);

            out.to_vec()
        });
        message.extend_from_slice(&{
            let mut out = BytesMut::with_capacity(1 + 2 + 2);

            out.put_u8(GarlicMessageType::DateTime.as_u8());
            out.put_u16(4u16);
            out.put_u32(1338u32);

            out.to_vec()
        });

        let message = GarlicMessage::parse(&message).unwrap();
        assert_eq!(message.blocks.len(), 3);

        match message.blocks[0] {
            GarlicMessageBlock::DateTime { timestamp } => assert_eq!(timestamp, 1337u32),
            _ => panic!("invalid garlic block"),
        }

        match &message.blocks[1] {
            GarlicMessageBlock::GarlicClove {
                message_type,
                message_id,
                expiration,
                delivery_instructions,
                message_body,
            } => {
                assert_eq!(message_type, &MessageType::DatabaseStore);
                assert_eq!(message_id, &MessageId::from(1337u32));
                assert_eq!(expiration, &Duration::from_secs(1337u64));
                assert!(std::matches!(
                    delivery_instructions,
                    DeliveryInstructions::Local
                ));
                assert_eq!(message_body, &vec![1, 2, 3, 4]);
            }
            _ => panic!("invalid garlic block"),
        }

        match message.blocks[2] {
            GarlicMessageBlock::DateTime { timestamp } => assert_eq!(timestamp, 1338u32),
            _ => panic!("invalid garlic block"),
        }
    }
}
