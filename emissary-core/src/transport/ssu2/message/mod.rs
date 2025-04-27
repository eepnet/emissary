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

//! SSU2 message block implementation
//!
//! https://geti2p.net/spec/ssu2#noise-payload

use crate::{
    crypto::{chachapoly::ChaCha, EphemeralPublicKey},
    error::Ssu2Error,
    i2np::{Message, MessageType as I2npMessageType},
    primitives::{MessageId, RouterInfo},
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops::{Deref, Range},
};

pub mod data;
pub mod handshake;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::message";

/// Minimum size for [`Block::Options`].
const OPTIONS_MIN_SIZE: u16 = 12u16;

/// Minimum size for [`Block::Termination`].
const TERMINATION_MIN_SIZE: u16 = 9u16;

/// IV size for header encryption.
const IV_SIZE: usize = 12usize;

/// Maximum amount of padding added to messages.
const MAX_PADDING: usize = 128usize;

/// Poly13055 MAC size.
const POLY13055_MAC_LEN: usize = 16usize;

/// Long header length.
const LONG_HEADER_LEN: usize = 32usize;

/// Short header length.
const SHORT_HEADER_LEN: usize = 16usize;

/// Public key length.
const PUBLIC_KEY_LEN: usize = 32usize;

/// Minimum size for a packet.
const PKT_MIN_SIZE: usize = 24usize;

/// Protocol version.
const PROTOCOL_VERSION: u8 = 2u8;

/// SSU2 block type.
#[derive(Debug)]
pub enum BlockType {
    DateTime,
    Options,
    RouterInfo,
    I2Np,
    FirstFragment,
    FollowOnFragment,
    Termination,
    RelayRequest,
    RelayResponse,
    RelayIntro,
    PeerTest,
    NextNonce,
    Ack,
    Address,
    RelayTagRequest,
    RelayTag,
    NewToken,
    PathChallenge,
    PathResponse,
    FirstPacketNumber,
    Congestion,
    Padding,
}

impl BlockType {
    fn as_u8(&self) -> u8 {
        match self {
            Self::DateTime => 0u8,
            Self::Options => 1u8,
            Self::RouterInfo => 2u8,
            Self::I2Np => 3u8,
            Self::FirstFragment => 4u8,
            Self::FollowOnFragment => 5u8,
            Self::Termination => 6u8,
            Self::RelayRequest => 7u8,
            Self::RelayResponse => 8u8,
            Self::RelayIntro => 9u8,
            Self::PeerTest => 10u8,
            Self::NextNonce => 11u8,
            Self::Ack => 12u8,
            Self::Address => 13u8,
            Self::RelayTagRequest => 15u8,
            Self::RelayTag => 16u8,
            Self::NewToken => 17u8,
            Self::PathChallenge => 18u8,
            Self::PathResponse => 19u8,
            Self::FirstPacketNumber => 20u8,
            Self::Congestion => 21u8,
            Self::Padding => 254u8,
        }
    }

    pub fn from_u8(block: u8) -> Option<Self> {
        match block {
            0u8 => Some(Self::DateTime),
            1u8 => Some(Self::Options),
            2u8 => Some(Self::RouterInfo),
            3u8 => Some(Self::I2Np),
            4u8 => Some(Self::FirstFragment),
            5u8 => Some(Self::FollowOnFragment),
            6u8 => Some(Self::Termination),
            7u8 => Some(Self::RelayRequest),
            8u8 => Some(Self::RelayResponse),
            9u8 => Some(Self::RelayIntro),
            10u8 => Some(Self::PeerTest),
            11u8 => Some(Self::NextNonce),
            12u8 => Some(Self::Ack),
            13u8 => Some(Self::Address),
            15u8 => Some(Self::RelayTagRequest),
            16u8 => Some(Self::RelayTag),
            17u8 => Some(Self::NewToken),
            18u8 => Some(Self::PathChallenge),
            19u8 => Some(Self::PathResponse),
            20u8 => Some(Self::FirstPacketNumber),
            21u8 => Some(Self::Congestion),
            254u8 => Some(Self::Padding),
            _ => None,
        }
    }
}

/// SSU2 message block.
#[allow(unused)]
pub enum Block {
    /// Date time.
    DateTime {
        /// Seconds since UNIX epoch.
        timestamp: u32,
    },

    /// Options.
    Options {
        /// Requested minimum padding for transfers.
        t_min: u8,

        /// Requested maximum padding for transfers.
        t_max: u8,

        /// Requested minimum padding for receptions.
        r_min: u8,

        /// Requested maximum padding for receptions.
        r_max: u8,

        /// Maximum dummy traffic router is willing to send.
        t_dmy: u16,

        /// Requested maximum dummy traffic.
        r_dmy: u16,

        /// Maximum intra-message delay router is willing to insert.
        t_delay: u16,

        /// Requested intra-message delay.
        r_delay: u16,
    },

    /// Router info.
    RouterInfo {
        /// Router info.
        router_info: RouterInfo,
    },

    /// I2NP message.
    I2Np {
        /// Parsed I2NP message.
        message: Message,
    },

    /// First fragment.
    FirstFragment {
        /// Message type.
        message_type: I2npMessageType,

        /// Message ID.
        message_id: MessageId,

        /// Expiration, seconds since UNIX epoch.
        expiration: u32,

        /// Fragment of an I2NP message.
        fragment: Vec<u8>,
    },

    /// Follow-on fragment.
    FollowOnFragment {
        /// Last fragment.
        last: bool,

        /// Message ID.
        message_id: MessageId,

        /// Fragment number.
        fragment_num: u8,

        /// Fragment of an I2NP message.
        fragment: Vec<u8>,
    },

    /// Termination.
    Termination {
        /// Number of valid packets received.
        num_valid_pkts: u64,

        /// Reason for termination.
        reason: u8,
    },

    /// Relay request.
    RelayRequest {},

    /// Relay response.
    RelayResponse {},

    /// Relay intro.
    RelayIntro {},

    /// Peer test.
    PeerTest {},

    /// Next nonce.
    NextNonce {},

    /// Ack.
    Ack {
        /// ACK through.
        ack_through: u32,

        /// Number of ACKs below `ack_through`.
        num_acks: u8,

        /// NACK/ACK ranges.
        ///
        /// First element of the tuple is NACKs, second is ACKs.
        ranges: Vec<(u8, u8)>,
    },

    /// Address.
    Address {
        /// Socket address.
        address: SocketAddr,
    },

    /// Relay tag request.
    RelayTagRequest {},

    /// Relay tag.
    RelayTag {},

    /// New token.
    NewToken {
        /// Expiration, seconds since UNIX epoch.
        expires: u32,

        /// Token.
        token: u64,
    },

    /// Path challenge.
    PathChallenge {
        /// Challenge.
        challenge: Vec<u8>,
    },

    /// Path response.
    PathResponse {
        /// Response.
        response: Vec<u8>,
    },

    /// First packet number.
    FirstPacketNumber {
        /// First packet number.
        first_pkt_num: u32,
    },

    /// Congestion.
    Congestion {
        /// Flag.
        flag: u8,
    },

    /// Padding.
    Padding {
        /// Padding.
        padding: Vec<u8>,
    },

    /// Unsupported block.
    ///
    /// Will be removed once all block types are supported.
    Unsupported,
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::DateTime { timestamp } =>
                f.debug_struct("Block::DateTime").field("timestamp", &timestamp).finish(),
            Self::Options {
                t_min,
                t_max,
                r_min,
                r_max,
                t_dmy,
                r_dmy,
                t_delay,
                r_delay,
            } => f
                .debug_struct("Block::Options")
                .field("t_min", &t_min)
                .field("t_max", &t_max)
                .field("r_min", &r_min)
                .field("r_max", &r_max)
                .field("t_dmy", &t_dmy)
                .field("r_dmy", &r_dmy)
                .field("t_delay", &t_delay)
                .field("r_deay", &r_delay)
                .finish(),
            Self::RouterInfo { .. } => f.debug_struct("Block::RouterInfo").finish_non_exhaustive(),
            Self::I2Np { message } =>
                f.debug_struct("Block::I2NP").field("message", &message).finish(),
            Self::Termination {
                num_valid_pkts,
                reason,
            } => f
                .debug_struct("Block::Termination")
                .field("num_valid_pkts", &num_valid_pkts)
                .field("reason", &reason)
                .finish(),
            Self::Padding { padding } =>
                f.debug_struct("Block::Padding").field("padding_len", &padding.len()).finish(),
            Self::FirstFragment {
                message_type,
                message_id,
                expiration,
                fragment,
            } => f
                .debug_struct("Block::FirstFragment")
                .field("message_type", &message_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .field("fragment_len", &fragment.len())
                .finish(),
            Self::FollowOnFragment {
                last,
                message_id,
                fragment_num,
                fragment,
            } => f
                .debug_struct("Block::FollowOnFragment")
                .field("last", &last)
                .field("message_id", &message_id)
                .field("fragment_num", &fragment_num)
                .field("fragment_len", &fragment.len())
                .finish(),
            Self::Ack {
                ack_through,
                num_acks,
                ranges,
            } => f
                .debug_struct("Block::Ack")
                .field("ack_through", &ack_through)
                .field("num_acks", &num_acks)
                .field("ranges", &ranges)
                .finish(),
            Self::NewToken { expires, token } => f
                .debug_struct("Block::NewToken")
                .field("expires", &expires)
                .field("token", &token)
                .finish(),
            Self::PathChallenge { challenge } =>
                f.debug_struct("Block::PathChallenge").field("challenge", &challenge).finish(),
            Self::PathResponse { response } =>
                f.debug_struct("Block::PathResponse").field("response", &response).finish(),
            Self::FirstPacketNumber { first_pkt_num } => f
                .debug_struct("Block::FirstPacketNumber")
                .field("first_pkt_num", &first_pkt_num)
                .finish(),
            Self::Congestion { flag } =>
                f.debug_struct("Block::Congestion").field("flag", &flag).finish(),
            _ => f.debug_struct("Unsupported").finish(),
        }
    }
}

impl Block {
    /// Attempt to parse [`Block::DateTime`] from `input`.
    fn parse_date_time(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, _size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        Ok((rest, Block::DateTime { timestamp }))
    }

    /// Attempt to parse [`Block::Options`] from `input`.
    fn parse_options(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, t_min) = be_u8(rest)?;
        let (rest, t_max) = be_u8(rest)?;
        let (rest, r_min) = be_u8(rest)?;
        let (rest, r_max) = be_u8(rest)?;
        let (rest, t_dmy) = be_u16(rest)?;
        let (rest, r_dmy) = be_u16(rest)?;
        let (rest, t_delay) = be_u16(rest)?;
        let (rest, r_delay) = be_u16(rest)?;

        let rest = if size > OPTIONS_MIN_SIZE {
            let (rest, _) = take(size - OPTIONS_MIN_SIZE)(rest)?;
            rest
        } else {
            rest
        };

        Ok((
            rest,
            Block::Options {
                t_min,
                t_max,
                r_min,
                r_max,
                r_dmy,
                t_dmy,
                t_delay,
                r_delay,
            },
        ))
    }

    /// Attempt to parse [`Block::RouterInfo`] from `input`.
    fn parse_router_info(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        if size == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "received empty `RouterInfo` message",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }
        let (rest, flag) = be_u8(rest)?;
        let (rest, _frag) = be_u8(rest)?;
        let (rest, router_info) = take(size - 2)(rest)?;

        if flag & 1 == 1 {
            tracing::warn!(
                target: LOG_TARGET,
                "ignoring flood request for received router info",
            );
        }
        // TODO: implement
        if (flag >> 1) & 1 == 1 {
            tracing::warn!(
                target: LOG_TARGET,
                "ignoring gzip-compressed router info",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        let router_info = RouterInfo::parse(router_info).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                "malformed router info",
            );
            Err::Error(make_error(input, ErrorKind::Fail))
        })?;

        Ok((rest, Block::RouterInfo { router_info }))
    }

    /// Attempt to parse [`Block::I2Np`] from `input`.
    fn parse_i2np(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, message) = Message::parse_frame_short(input)?;

        Ok((rest, Block::I2Np { message }))
    }

    /// Attempt to parse [`Block::Termination`] from `input`.
    fn parse_termination(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, num_valid_pkts) = be_u64(rest)?;
        let (rest, reason) = be_u8(rest)?;

        let rest = if size > TERMINATION_MIN_SIZE {
            let (rest, _) = take(size - TERMINATION_MIN_SIZE)(rest)?;
            rest
        } else {
            rest
        };

        Ok((
            rest,
            Block::Termination {
                num_valid_pkts,
                reason,
            },
        ))
    }

    /// Parse [`MessageBlock::Padding`].
    fn parse_padding(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, padding) = take(size)(rest)?;

        Ok((
            rest,
            Block::Padding {
                padding: padding.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::FirstFragment`].
    fn parse_first_fragment(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;
        let fragment_len = size.saturating_sub(9) as usize; // type + id + size + expiration
        let message_type = I2npMessageType::from_u8(message_type).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "invalid message type for first fragment",
            );
            Err::Error(make_error(input, ErrorKind::Fail))
        })?;

        if fragment_len == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "first fragment is empty",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        if rest.len() < fragment_len {
            tracing::warn!(
                target: LOG_TARGET,
                "first fragment message is too short",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }
        let (rest, fragment) = take(fragment_len)(rest)?;

        Ok((
            rest,
            Block::FirstFragment {
                message_type,
                message_id: MessageId::from(message_id),
                expiration,
                fragment: fragment.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::FollowOnFragment`].
    fn parse_follow_on_fragment(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, frag) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let fragment_len = size.saturating_sub(5) as usize; // frag + id

        if fragment_len == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "follow-on fragment is empty",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }

        if rest.len() < fragment_len {
            tracing::warn!(
                target: LOG_TARGET,
                "follow-on fragment message is too short",
            );
            return Err(Err::Error(make_error(input, ErrorKind::Fail)));
        }
        let (rest, fragment) = take(fragment_len)(rest)?;

        Ok((
            rest,
            Block::FollowOnFragment {
                last: frag & 1 == 1,
                message_id: MessageId::from(message_id),
                fragment_num: frag >> 1,
                fragment: fragment.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::Ack`].
    fn parse_ack(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, ack_through) = be_u32(rest)?;
        let (rest, num_acks) = be_u8(rest)?;

        let (rest, ranges) = match size.saturating_sub(5) {
            0 => (rest, Vec::new()),
            num_ranges if num_ranges % 2 == 0 => {
                let (rest, ranges) = take(num_ranges)(rest)?;

                (
                    rest,
                    ranges.chunks(2usize).map(|chunk| (chunk[0], chunk[1])).collect::<Vec<_>>(),
                )
            }
            num_ranges => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?num_ranges,
                    "invalid nack/ack range count",
                );
                debug_assert!(false);

                (rest, Vec::new())
            }
        };

        Ok((
            rest,
            Block::Ack {
                ack_through,
                num_acks,
                ranges,
            },
        ))
    }

    /// Parse [`MessageBlock::NewToken`].
    fn parse_new_token(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, _size) = be_u16(input)?;
        let (rest, expires) = be_u32(rest)?;
        let (rest, token) = be_u64(rest)?;

        Ok((rest, Block::NewToken { expires, token }))
    }

    /// Parse [`MessageBlock::PathChallenge`].
    fn parse_path_challenge(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, data) = take(size)(rest)?;

        Ok((
            rest,
            Block::PathChallenge {
                challenge: data.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::PathResponse`].
    fn parse_path_response(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, data) = take(size)(rest)?;

        Ok((
            rest,
            Block::PathResponse {
                response: data.to_vec(),
            },
        ))
    }

    /// Parse [`MessageBlock::FirstPacketNumber`].
    fn parse_first_packet_number(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, _size) = be_u16(input)?;
        let (rest, first_pkt_num) = be_u32(rest)?;

        Ok((rest, Block::FirstPacketNumber { first_pkt_num }))
    }

    /// Parse [`MessageBlock::Congestion`].
    fn parse_congestion(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, _size) = be_u16(input)?;
        let (rest, flag) = be_u8(rest)?;

        Ok((rest, Block::Congestion { flag }))
    }

    /// Attempt to parse unsupported block from `input`
    fn parse_unsupported_block(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, size) = be_u16(input)?;
        let (rest, _bytes) = take(size)(rest)?;

        Ok((rest, Block::Unsupported))
    }

    /// Attempt to parse [`Block`] from `input`, returning the parsed block
    // and the rest of `input` to caller.
    fn parse_inner(input: &[u8]) -> IResult<&[u8], Block> {
        let (rest, block_type) = be_u8(input)?;

        match BlockType::from_u8(block_type) {
            Some(BlockType::DateTime) => Self::parse_date_time(rest),
            Some(BlockType::Options) => Self::parse_options(rest),
            Some(BlockType::RouterInfo) => Self::parse_router_info(rest),
            Some(BlockType::I2Np) => Self::parse_i2np(rest),
            Some(BlockType::FirstFragment) => Self::parse_first_fragment(rest),
            Some(BlockType::FollowOnFragment) => Self::parse_follow_on_fragment(rest),
            Some(BlockType::Termination) => Self::parse_termination(rest),
            Some(BlockType::Ack) => Self::parse_ack(rest),
            Some(BlockType::NewToken) => Self::parse_new_token(rest),
            Some(BlockType::PathChallenge) => Self::parse_path_challenge(rest),
            Some(BlockType::PathResponse) => Self::parse_path_response(rest),
            Some(BlockType::FirstPacketNumber) => Self::parse_first_packet_number(rest),
            Some(BlockType::Congestion) => Self::parse_congestion(rest),
            Some(BlockType::Padding) => Self::parse_padding(rest),
            Some(block_type) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?block_type,
                    "ignoring block",
                );
                Self::parse_unsupported_block(rest)
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?block_type,
                    "unrecognized ssu2 block type",
                );
                Err(Err::Error(make_error(input, ErrorKind::Fail)))
            }
        }
    }

    /// Attempt to parse `input` into an SSU2 message [`Block`] and recursive call
    /// `Block::parse_multiple()` until there are no bytes or an error was encountered.
    fn parse_multiple(input: &[u8], mut messages: Vec<Block>) -> Option<Vec<Block>> {
        let (rest, message) = Self::parse_inner(input).ok()?;
        messages.push(message);

        match rest.is_empty() {
            true => Some(messages),
            false => Self::parse_multiple(rest, messages),
        }
    }

    /// Attempt to parse `input` into one or more SSU2 message [`Block`]s.
    pub fn parse(input: &[u8]) -> Option<Vec<Block>> {
        Self::parse_multiple(input, Vec::new())
    }

    /// Get serialized length of a [`Block`].
    pub fn serialized_len(&self) -> usize {
        3usize // message type + size
            + match self {
                Block::DateTime { .. } => 4usize,
                Block::Options { .. } => OPTIONS_MIN_SIZE as usize,
                Block::RouterInfo { .. } => todo!(),
                Block::I2Np { message } => message.serialized_len_short(),
                Block::FirstFragment { fragment, .. } => fragment
                    .len()
                    .saturating_add(1usize) // message type
                    .saturating_add(4usize) // message id
                    .saturating_add(4usize), // expiration
                Block::FollowOnFragment { fragment, .. } => fragment
                    .len()
                    .saturating_add(1usize) // fragmentation info
                    .saturating_add(4usize), // message id
                Block::Termination { .. } => TERMINATION_MIN_SIZE as usize,
                Block::Ack { ranges, .. } => 4usize // ack through
                    .saturating_add(1usize) // ack count
                    .saturating_add(ranges.len() * 2), // nack/ack ranges
                Block::NewToken { .. } => 12usize, // expires + token
                Block::PathChallenge { challenge } => challenge.len(),
                Block::PathResponse { response } => response.len(),
                Block::FirstPacketNumber { .. } => 4usize, // packet number
                Block::Congestion { .. } => 1usize, // flag
                Block::Padding { padding } => padding.len(),
                Block::Address { address } => match address.ip() {
                    IpAddr::V4(_) => 2usize + 4usize, // port + address
                    IpAddr::V6(_) => 2usize + 16usize, // port + address
                },
                block_type => todo!("unsupported block type: {block_type:?}"),
            }
    }

    /// Serialize [`Block`] into a byte vector.
    pub fn serialize(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.serialized_len());

        match self {
            Self::DateTime { timestamp } => {
                out.put_u8(BlockType::DateTime.as_u8());
                out.put_u16(4u16);
                out.put_u32(timestamp);

                out
            }
            Self::Address { address } => {
                out.put_u8(BlockType::Address.as_u8());

                match address {
                    SocketAddr::V4(address) => {
                        out.put_u16(6u16);
                        out.put_u16(address.port());
                        out.put_slice(&address.ip().octets());
                    }
                    SocketAddr::V6(address) => {
                        out.put_u16(18u16);
                        out.put_u16(address.port());
                        out.put_slice(&address.ip().octets());
                    }
                }

                out
            }
            Self::Padding { padding } => {
                out.put_u8(BlockType::Padding.as_u8());
                out.put_u16(padding.len() as u16);
                out.put_slice(&padding);

                out
            }
            Self::Ack {
                ack_through,
                num_acks,
                ranges,
            } => {
                out.put_u8(BlockType::Ack.as_u8());
                out.put_u16((4usize + 1usize + ranges.len() * 2) as u16);
                out.put_u32(ack_through);
                out.put_u8(num_acks);
                ranges.into_iter().for_each(|(nack, ack)| {
                    out.put_u8(nack);
                    out.put_u8(ack);
                });

                out
            }
            block_type => todo!("unsupported block type: {block_type:?}"),
        }
    }
}

/// SSU2 message type.
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
    SessionRequest,
    SessionCreated,
    SessionConfirmed,
    Data,
    PeerTest,
    Retry,
    TokenRequest,
    HolePunch,
}

impl Deref for MessageType {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SessionRequest => &0u8,
            Self::SessionCreated => &1u8,
            Self::SessionConfirmed => &2u8,
            Self::Data => &6u8,
            Self::PeerTest => &7u8,
            Self::Retry => &9u8,
            Self::TokenRequest => &10u8,
            Self::HolePunch => &11u8,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0u8 => Ok(Self::SessionRequest),
            1u8 => Ok(Self::SessionCreated),
            2u8 => Ok(Self::SessionConfirmed),
            6u8 => Ok(Self::Data),
            7u8 => Ok(Self::PeerTest),
            9u8 => Ok(Self::Retry),
            10u8 => Ok(Self::TokenRequest),
            11u8 => Ok(Self::HolePunch),
            _ => Err(()),
        }
    }
}

/// Header kind.
pub enum HeaderKind {
    /// Retry
    Retry {
        /// Network ID.
        net_id: u8,

        /// Packet number.
        pkt_num: u32,

        /// Token.
        token: u64,
    },

    /// Session confirmed.
    //
    // TODO: router info fragmentation
    SessionConfirmed {
        /// Packet number.
        pkt_num: u32,
    },

    /// Session created.
    SessionCreated {
        /// Extracted ephemeral public key.
        ephemeral_key: EphemeralPublicKey,

        /// Network ID.
        net_id: u8,

        /// Packet number.
        pkt_num: u32,
    },

    /// Session request.
    SessionRequest {
        /// Extracted ephemeral public key.
        ephemeral_key: EphemeralPublicKey,

        /// Network ID.
        net_id: u8,

        /// Packet number.
        pkt_num: u32,

        /// Token
        token: u64,
    },

    /// Token request.
    TokenRequest {
        /// Network ID.
        net_id: u8,

        /// Packet number.
        pkt_num: u32,

        /// Source connection ID.
        src_id: u64,
    },

    /// Data.
    Data {
        /// Was immediate ACK requested.
        immediate_ack: bool,

        /// Packet number.
        pkt_num: u32,
    },
}

impl fmt::Debug for HeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderKind::Retry {
                net_id,
                pkt_num,
                token,
            } => f
                .debug_struct("HeaderKind::Retry")
                .field("net_id", &net_id)
                .field("pkt_num", &pkt_num)
                .field("token", &token)
                .finish(),
            HeaderKind::SessionConfirmed { pkt_num } => f
                .debug_struct("HeaderKind::SessionConfirmed")
                .field("pkt_num", &pkt_num)
                .finish(),
            HeaderKind::SessionCreated {
                net_id, pkt_num, ..
            } => f
                .debug_struct("HeaderKind::SessionCreated")
                .field("net_id", &net_id)
                .field("pkt_num", &pkt_num)
                .finish_non_exhaustive(),
            Self::SessionRequest {
                net_id,
                pkt_num,
                token,
                ..
            } => f
                .debug_struct("HeaderKind::SessionRequest")
                .field("net_id", &net_id)
                .field("pkt_num", &pkt_num)
                .field("token", &token)
                .finish_non_exhaustive(),
            Self::TokenRequest {
                net_id,
                pkt_num,
                src_id,
            } => f
                .debug_struct("HeaderKind::TokenRequest")
                .field("net_id", &net_id)
                .field("pkt_num", &pkt_num)
                .field("src_id", &src_id)
                .finish(),
            Self::Data {
                immediate_ack,
                pkt_num,
            } => f
                .debug_struct("HeaderKind::Data")
                .field("pkt_num", &pkt_num)
                .field("immediate_ack", &immediate_ack)
                .finish(),
        }
    }
}

/// Header reader.
pub struct HeaderReader<'a> {
    k_header_1: [u8; 32],
    iv1: [u8; IV_SIZE],
    iv2: [u8; IV_SIZE],
    pkt: &'a mut [u8],
}

impl<'a> HeaderReader<'a> {
    /// Create new [`HeaderReader`].
    ///
    /// Minimum size for `pkt` is 24 bytes as the IVs used for header decryption are 12 bytes long.
    pub fn new(k_header_1: [u8; 32], pkt: &'a mut [u8]) -> Result<Self, Ssu2Error> {
        if pkt.len() < PKT_MIN_SIZE {
            return Err(Ssu2Error::NotEnoughBytes);
        }

        Ok(Self {
            k_header_1,
            iv1: TryInto::<[u8; IV_SIZE]>::try_into(&pkt[pkt.len() - 24..pkt.len() - 12])
                .expect("to succeed"),
            iv2: TryInto::<[u8; IV_SIZE]>::try_into(&pkt[pkt.len() - 12..pkt.len()])
                .expect("to succeed"),
            pkt,
        })
    }

    /// Apply obfuscation mask generated from `key` and `iv` to the packet over `range`.
    fn apply_mask(&mut self, key: [u8; 32], iv: [u8; 12], range: Range<usize>) {
        ChaCha::with_iv(key, iv)
            .decrypt([0u8; 8])
            .into_iter()
            .zip(&mut self.pkt[range])
            .for_each(|(a, b)| {
                *b ^= a;
            });
    }

    /// Extract destination connection ID from the header.
    pub fn dst_id(&mut self) -> u64 {
        self.apply_mask(self.k_header_1, self.iv1, 0..8);

        u64::from_le_bytes(TryInto::<[u8; 8]>::try_into(&self.pkt[..8]).expect("to succeed"))
    }

    /// Reset key.
    ///
    /// Used for during pending outbound connections when the first and second part of the short
    /// header are encrypted not with our intro key but remote's intro key.
    pub fn reset_key(&mut self, k_header_1: [u8; 32]) -> &mut Self {
        self.apply_mask(self.k_header_1, self.iv1, 0..8);
        self.apply_mask(self.k_header_1, self.iv2, 8..16);

        self.k_header_1 = k_header_1;
        self
    }

    /// Attempt to parse the second part of the header using `k_header_2`.
    ///
    /// Apply mask for the second part of the short header and extract message type from the header.
    /// Based on the type of the message, decrypt additional header fields (if the message type
    /// indicated a long header) and return all useful context to caller for further processing.
    pub fn parse(&mut self, k_header_2: [u8; 32]) -> Result<HeaderKind, Ssu2Error> {
        self.apply_mask(k_header_2, self.iv2, 8..16);

        let header =
            u64::from_le_bytes(TryInto::<[u8; 8]>::try_into(&self.pkt[8..16]).expect("to succeed"));

        match MessageType::try_from(((header >> 32) & 0xff) as u8)
            .map_err(|_| Ssu2Error::Malformed)?
        {
            MessageType::SessionRequest => {
                if ((header >> 40) as u8) != PROTOCOL_VERSION {
                    return Err(Ssu2Error::InvalidVersion);
                }

                if self.pkt.len() < 64 {
                    return Err(Ssu2Error::NotEnoughBytes);
                }

                ChaCha::with_iv(k_header_2, [0u8; 12]).decrypt_ref(&mut self.pkt[16..64]);

                let net_id = ((header >> 48) & 0xff) as u8;
                let pkt_num = u32::from_be(header as u32);

                // these are expected to succeed as the packet has been confirmed to be long enough
                let token = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.pkt[24..32]).expect("to succeed"),
                );
                let ephemeral_key =
                    EphemeralPublicKey::from_bytes(&self.pkt[32..64]).expect("to succeed");

                Ok(HeaderKind::SessionRequest {
                    ephemeral_key,
                    net_id,
                    pkt_num,
                    token,
                })
            }
            MessageType::SessionCreated => {
                if ((header >> 40) as u8) != PROTOCOL_VERSION {
                    return Err(Ssu2Error::InvalidVersion);
                }

                if self.pkt.len() < 64 {
                    return Err(Ssu2Error::NotEnoughBytes);
                }

                ChaCha::with_iv(k_header_2, [0u8; 12]).decrypt_ref(&mut self.pkt[16..64]);

                let net_id = ((header >> 48) & 0xff) as u8;
                let pkt_num = u32::from_be(header as u32);

                // expected to succeed as the packet has been confirmed to be long enough
                let ephemeral_key =
                    EphemeralPublicKey::from_bytes(&self.pkt[32..64]).expect("to succeed");

                Ok(HeaderKind::SessionCreated {
                    ephemeral_key,
                    net_id,
                    pkt_num,
                })
            }
            MessageType::SessionConfirmed => Ok(HeaderKind::SessionConfirmed {
                pkt_num: u32::from_be(header as u32),
            }),
            MessageType::Data => Ok(HeaderKind::Data {
                immediate_ack: ((header >> 40) & 0x01) == 0x01,
                pkt_num: u32::from_be(header as u32),
            }),
            MessageType::Retry => {
                if ((header >> 40) as u8) != PROTOCOL_VERSION {
                    return Err(Ssu2Error::InvalidVersion);
                }

                if self.pkt.len() < 32 {
                    return Err(Ssu2Error::NotEnoughBytes);
                }

                ChaCha::with_iv(k_header_2, [0u8; 12]).decrypt_ref(&mut self.pkt[16..32]);

                let net_id = ((header >> 48) & 0xff) as u8;
                let pkt_num = u32::from_be(header as u32);

                // expected to succeed as the packet has been confirmed to be long enough
                let token = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.pkt[24..32]).expect("to succeed"),
                );

                Ok(HeaderKind::Retry {
                    net_id,
                    pkt_num,
                    token,
                })
            }
            MessageType::TokenRequest => {
                if ((header >> 40) as u8) != PROTOCOL_VERSION {
                    return Err(Ssu2Error::InvalidVersion);
                }

                if self.pkt.len() < 32 {
                    return Err(Ssu2Error::NotEnoughBytes);
                }

                ChaCha::with_iv(k_header_2, [0u8; 12]).decrypt_ref(&mut self.pkt[16..32]);

                let net_id = ((header >> 48) & 0xff) as u8;
                let pkt_num = u32::from_be(header as u32);
                let src_id = u64::from_le_bytes(
                    TryInto::<[u8; 8]>::try_into(&self.pkt[16..24]).expect("to succeed"),
                );

                Ok(HeaderKind::TokenRequest {
                    net_id,
                    pkt_num,
                    src_id,
                })
            }
            message_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_type,
                    "unsupported message type",
                );
                Err(Ssu2Error::UnexpectedMessage)
            }
        }
    }
}
