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
    crypto::{
        chachapoly::{ChaCha, ChaChaPoly},
        EphemeralPublicKey,
    },
    error::{parser::Ssu2ParseError, Ssu2Error},
    i2np::{Message, MessageType as I2npMessageType},
    primitives::{MessageId, RouterId, RouterInfo},
    runtime::Runtime,
    transport::ssu2::peer_test::types::RejectionReason,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
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

/// Router hash length.
const ROUTER_HASH_LEN: usize = 32usize;

/// Ed25519 signature length.
const ED25519_SIGNATURE_LEN: usize = 64usize;

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

/// Parsed `PeerTest` message.
#[derive(Debug, Default, Clone)]
pub enum PeerTestMessage {
    /// Message 1, sent from Alice to Bob.
    Message1 {
        /// Alice's address.
        address: SocketAddr,

        /// Portion of the message that is covered by `signature`.
        message: Vec<u8>,

        /// Test nonce.
        nonce: u32,

        /// Signature.
        signature: Vec<u8>,
    },

    /// Message 2, sent from Bob to Charlie.
    Message2 {
        /// Alice's address.
        address: SocketAddr,

        /// Portion of the message that is covered by `signature`.
        message: Vec<u8>,

        /// Test nonce.
        nonce: u32,

        /// Router ID of Alice.
        router_id: RouterId,

        /// Signature.
        signature: Vec<u8>,
    },

    /// Message 3, sent from Charlie to Bob.
    Message3 {
        /// Portion of the message that is covered by `signature`.
        message: Vec<u8>,

        /// Test nonce.
        nonce: u32,

        /// Rejection reason from Charlie, if request was not accepted.
        ///
        /// `None` if requested was accepted.
        rejection: Option<RejectionReason>,

        /// Signature.
        signature: Vec<u8>,
    },

    /// Message 4, sent from Bob to Alice, either directly or relayed from Charlie.
    Message4 {
        message: Vec<u8>,

        /// Test nonce,
        nonce: u32,

        /// Rejection reason from Bob/Charlie, if request was not accepted.
        ///
        /// `None` if requested was accepted.
        rejection: Option<RejectionReason>,

        /// Router hash.
        ///
        /// All zeros if Bob rejected the request.
        router_hash: Vec<u8>,

        /// Signature.
        signature: Vec<u8>,
    },

    /// Message 5, from Charlie to Alice (out-of-session).
    Message5 {
        /// Test nonce.
        nonce: u32,
    },

    /// Message 6, from Alice to Charlie (out-of-session).
    Message6 {
        /// Test nonce.
        nonce: u32,
    },

    /// Message 7, from Charlie to Alice (out-of-session).
    Message7 {
        /// Test nonce.
        nonce: u32,
    },

    #[default]
    Dummy,
}

/// SSU2 message block.
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
        router_info: Box<RouterInfo>,
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
    #[allow(unused)]
    RelayRequest {},

    /// Relay response.
    #[allow(unused)]
    RelayResponse {},

    /// Relay intro.
    #[allow(unused)]
    RelayIntro {},

    /// Peer test.
    PeerTest { message: PeerTestMessage },

    /// Next nonce.
    #[allow(unused)]
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
    #[allow(unused)]
    RelayTagRequest {},

    /// Relay tag.
    #[allow(unused)]
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
            Self::PeerTest { message } =>
                f.debug_struct("Block::PeerTest").field("message", &message).finish(),
            _ => f.debug_struct("Unsupported").finish(),
        }
    }
}

impl Block {
    /// Attempt to parse [`Block::DateTime`] from `input`.
    fn parse_date_time(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        Ok((rest, Block::DateTime { timestamp }))
    }

    /// Attempt to parse [`Block::Options`] from `input`.
    fn parse_options(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
    fn parse_router_info(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, size) = be_u16(input)?;
        if size == 0 {
            return Err(Err::Error(Ssu2ParseError::EmptyRouterInfo));
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
            return Err(Err::Error(Ssu2ParseError::CompressedRouterInfo));
        }

        let router_info = RouterInfo::parse(router_info)
            .map_err(|error| Err::Error(Ssu2ParseError::RouterInfo(error)))?;

        Ok((
            rest,
            Block::RouterInfo {
                router_info: Box::new(router_info),
            },
        ))
    }

    /// Attempt to parse [`Block::I2Np`] from `input`.
    fn parse_i2np(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, message) = Message::parse_frame_short(input).map_err(Err::convert)?;

        Ok((rest, Block::I2Np { message }))
    }

    /// Attempt to parse [`Block::Termination`] from `input`.
    fn parse_termination(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
    fn parse_padding(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
    fn parse_first_fragment(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;
        let fragment_len = size.saturating_sub(9) as usize; // type + id + size + expiration
        let message_type = I2npMessageType::from_u8(message_type).ok_or(Err::Error(
            Ssu2ParseError::InvalidMessageTypeFirstFrag(message_type),
        ))?;

        if fragment_len == 0 {
            return Err(Err::Error(Ssu2ParseError::EmptyFirstFragment));
        }

        if rest.len() < fragment_len {
            return Err(Err::Error(Ssu2ParseError::FirstFragmentTooShort));
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
    fn parse_follow_on_fragment(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, frag) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let fragment_len = size.saturating_sub(5) as usize; // frag + id

        if fragment_len == 0 {
            return Err(Err::Error(Ssu2ParseError::EmptyFollowOnFragment));
        }

        if rest.len() < fragment_len {
            return Err(Err::Error(Ssu2ParseError::FollowOnFragmentTooShort));
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
    fn parse_ack(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
    fn parse_new_token(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, expires) = be_u32(rest)?;
        let (rest, token) = be_u64(rest)?;

        Ok((rest, Block::NewToken { expires, token }))
    }

    /// Parse [`MessageBlock::PathChallenge`].
    fn parse_path_challenge(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
    fn parse_path_response(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
    fn parse_first_packet_number(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, first_pkt_num) = be_u32(rest)?;

        Ok((rest, Block::FirstPacketNumber { first_pkt_num }))
    }

    /// Parse [`MessageBlock::Congestion`].
    fn parse_congestion(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, flag) = be_u8(rest)?;

        Ok((rest, Block::Congestion { flag }))
    }

    /// Parse [`MessageBlock::PeerTest`].
    fn parse_peer_test(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, size) = be_u16::<_, ()>(input).unwrap();
        let (rest, msg) = be_u8::<_, ()>(rest).unwrap();
        let (rest, code) = be_u8::<_, ()>(rest).unwrap();
        let (rest, _flag) = be_u8::<_, ()>(rest).unwrap();
        let (rest, router_hash) = match msg {
            2 | 4 => {
                let (rest, hash) = take::<_, _, ()>(ROUTER_HASH_LEN)(rest).unwrap();
                (rest, Some(hash))
            }
            _ => (rest, None),
        };

        // keep track of message start so it can be sent unmodified to alice/charlie
        //
        // https://geti2p.net/spec/ssu2#peertest
        let message_start = rest;

        let (rest, _version) = be_u8::<_, ()>(rest).unwrap();
        let (rest, nonce) = be_u32::<_, ()>(rest).unwrap();
        let (rest, _timestamp) = be_u32::<_, ()>(rest).unwrap();
        let (rest, address_size) = be_u8::<_, ()>(rest).unwrap();
        let (rest, address) = match address_size {
            6 => {
                let (rest, port) = be_u16::<_, ()>(rest).unwrap();
                let (rest, address) = be_u32::<_, ()>(rest).unwrap();

                (
                    rest,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(address), port)),
                )
            }
            18 => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "ipv6 not supported"
                );
                panic!("zzzzz");
                return Err(Err::Error(Ssu2ParseError::InvalidBitstream));
            }
            _ => panic!("kkkk"),
            // _ => return Err(Err::Error(Ssu2ParseError::InvalidBitstream)),
        };
        let (rest, maybe_signature) = match msg {
            1..=4 => {
                println!("parse signature");
                let (rest, signature) = take::<_, _, ()>(ED25519_SIGNATURE_LEN)(rest).unwrap();

                (rest, Some(signature))
            }
            _ => {
                let bytes_left = (size as usize)
                    .saturating_sub(1 + 1 + 1) // message, code, flag
                    .saturating_sub(router_hash.map_or(0, |hash| hash.len()))
                    .saturating_sub(1) // version
                    .saturating_sub(4) // nonce
                    .saturating_sub(4) // timesetamp
                    .saturating_sub(1) // address size
                    .saturating_sub(address_size as usize);

                if bytes_left == 0 {
                    (rest, None)
                } else if bytes_left == ED25519_SIGNATURE_LEN {
                    let (rest, signature) = take::<_, _, ()>(ED25519_SIGNATURE_LEN)(rest).unwrap();

                    (rest, Some(signature))
                } else {
                    panic!("sig issue");
                    // return Err(Err::Error(Ssu2ParseError::InvalidBitstream));
                }
            }
        };

        match msg {
            1 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message1 {
                        nonce,
                        address,
                        // signature exists since it was extracted for message 1
                        signature: maybe_signature.expect("to exist").to_vec(),
                        message: {
                            let message_end = 1usize // version
                                    .saturating_add(4) // nonce
                                    .saturating_add(4) // timestamp
                                    .saturating_add(1) // address size
                                    .saturating_add(address_size as usize);

                            message_start[..message_end].to_vec()
                        },
                    },
                },
            )),
            2 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message2 {
                        nonce,
                        address,
                        // signature exists since it was extracted for message 2
                        signature: maybe_signature.expect("to exist").to_vec(),
                        message: {
                            let message_end = 1usize // version
                                    .saturating_add(4) // nonce
                                    .saturating_add(4) // timestamp
                                    .saturating_add(1) // address size
                                    .saturating_add(address_size as usize);

                            message_start[..message_end].to_vec()
                        },
                        // `router_hash` must exist since it was extracted for message 2
                        router_id: RouterId::from(router_hash.expect("to exist")),
                    },
                },
            )),
            3 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message3 {
                        nonce,
                        rejection: (code != 0).then(|| RejectionReason::from(code)),
                        // signature exists since it was extracted for message 4
                        signature: maybe_signature.expect("to exist").to_vec(),
                        message: {
                            let message_end = 1usize // version
                                    .saturating_add(4) // nonce
                                    .saturating_add(4) // timestamp
                                    .saturating_add(1) // address size
                                    .saturating_add(address_size as usize);

                            message_start[..message_end].to_vec()
                        },
                    },
                },
            )),
            4 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message4 {
                        // router hash must exist since it was extracted for message 4
                        router_hash: router_hash.expect("to exist").to_vec(),
                        nonce,
                        rejection: (code != 0).then(|| RejectionReason::from(code)),
                        // signature must exist since it was extracted for message 4
                        signature: maybe_signature.expect("to exist").to_vec(),
                        message: {
                            let message_end = 1usize // version
                                    .saturating_add(4) // nonce
                                    .saturating_add(4) // timestamp
                                    .saturating_add(1) // address size
                                    .saturating_add(address_size as usize)
                                    .saturating_add(ED25519_SIGNATURE_LEN);

                            message_start[..message_end].to_vec()
                        },
                    },
                },
            )),
            5 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message5 { nonce },
                },
            )),
            6 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message6 { nonce },
                },
            )),
            7 => Ok((
                rest,
                Block::PeerTest {
                    message: PeerTestMessage::Message7 { nonce },
                },
            )),
            msg => return Err(Err::Error(Ssu2ParseError::UnknownPeerTestMessage(msg))),
        }
    }

    /// Parse [`MessageBlock::Address`].
    fn parse_address(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, port) = be_u16(rest)?;
        let (rest, address) = match size {
            6 => {
                let (rest, address) = take(4usize)(rest)?;

                // must succeed since `take(4)` took 4 bytes
                (
                    rest,
                    IpAddr::V4(Ipv4Addr::from_octets(
                        TryInto::<[u8; 4]>::try_into(address).expect("to succeed"),
                    )),
                )
            }
            18 => {
                let (rest, address) = take(16usize)(rest)?;

                // must succeed since `take(16)` took 16 bytes
                (
                    rest,
                    IpAddr::V6(Ipv6Addr::from_octets(
                        TryInto::<[u8; 16]>::try_into(address).expect("to succeed"),
                    )),
                )
            }
            size => return Err(Err::Error(Ssu2ParseError::InvalidAddressBlock(size))),
        };

        Ok((
            rest,
            Block::Address {
                address: SocketAddr::new(address, port),
            },
        ))
    }

    /// Attempt to parse unsupported block from `input`
    fn parse_unsupported_block(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, _bytes) = take(size)(rest)?;

        Ok((rest, Block::Unsupported))
    }

    /// Attempt to parse [`Block`] from `input`, returning the parsed block
    // and the rest of `input` to caller.
    fn parse_inner(input: &[u8]) -> IResult<&[u8], Block, Ssu2ParseError> {
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
            Some(BlockType::PeerTest) => Self::parse_peer_test(rest),
            Some(BlockType::Address) => Self::parse_address(rest),
            Some(block_type) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?block_type,
                    "ignoring block",
                );
                Self::parse_unsupported_block(rest)
            }
            None => Err(Err::Error(Ssu2ParseError::InvalidBlock(block_type))),
        }
    }

    /// Attempt to parse `input` into an SSU2 message [`Block`] and recursive call
    /// `Block::parse_multiple()` until there are no bytes or an error was encountered.
    fn parse_multiple(
        input: &[u8],
        mut messages: Vec<Block>,
    ) -> Result<Vec<Block>, Ssu2ParseError> {
        let (rest, message) = Self::parse_inner(input)?;
        messages.push(message);

        match rest.is_empty() {
            true => Ok(messages),
            false => Self::parse_multiple(rest, messages),
        }
    }

    /// Attempt to parse `input` into one or more SSU2 message [`Block`]s.
    pub fn parse(input: &[u8]) -> Result<Vec<Block>, Ssu2ParseError> {
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
            Self::Termination {
                num_valid_pkts,
                reason,
            } => {
                out.put_u8(BlockType::Termination.as_u8());
                out.put_u16(9u16);
                out.put_u64(num_valid_pkts);
                out.put_u8(reason);
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

    /// Peer test
    PeerTest {
        /// Network ID.
        net_id: u8,

        /// Packet number.
        pkt_num: u32,

        /// Source connection ID.
        src_id: u64,
    },
}

impl fmt::Debug for HeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry {
                net_id,
                pkt_num,
                token,
            } => f
                .debug_struct("HeaderKind::Retry")
                .field("net_id", &net_id)
                .field("pkt_num", &pkt_num)
                .field("token", &token)
                .finish(),
            Self::SessionConfirmed { pkt_num } => f
                .debug_struct("HeaderKind::SessionConfirmed")
                .field("pkt_num", &pkt_num)
                .finish(),
            Self::SessionCreated {
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
            Self::PeerTest {
                net_id,
                pkt_num,
                src_id,
            } => f
                .debug_struct("HeaderKind::PeerTest")
                .field("net_id", &net_id)
                .field("pkt_num", &pkt_num)
                .field("src_id", &src_id)
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
            MessageType::SessionConfirmed => {
                let pkt_num = u32::from_be(header as u32);

                // the packet number of `SessionConfirmed` must be zero
                //
                // having non-zero packet number doesn't necessarily mean there's a bug in the code
                // but could also mean that a duplicate `SessionCreated` message was received, and
                // after header decryption the `type` field happened to contain 2, which is the
                // message number for `SessionConfirmed`
                //
                // these messages should be ignored
                if pkt_num != 0 {
                    return Err(Ssu2Error::Malformed);
                }

                Ok(HeaderKind::SessionConfirmed { pkt_num })
            }
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
            MessageType::PeerTest => {
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

                Ok(HeaderKind::PeerTest {
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

/// Builder for `PeerTest`.
pub struct PeerTestBuilder<'a> {
    /// Address block.
    address: Option<SocketAddr>,

    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Remote router's intro key.
    intro_key: Option<[u8; 32]>,

    /// Message.
    message: &'a [u8],

    /// Peer test message code.
    msg_code: u8,

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Source connection ID.
    src_id: Option<u64>,
}

impl<'a> PeerTestBuilder<'a> {
    /// Create new `PeerTestBuilder`.
    pub fn new(msg_code: u8, message: &'a [u8]) -> Self {
        Self {
            address: None,
            dst_id: None,
            intro_key: None,
            message,
            msg_code,
            net_id: 2u8,
            src_id: None,
        }
    }

    /// Specify destination connection ID.
    pub fn with_dst_id(mut self, dst_id: u64) -> Self {
        self.dst_id = Some(dst_id);
        self
    }

    /// Specify source connection ID.
    pub fn with_src_id(mut self, src_id: u64) -> Self {
        self.src_id = Some(src_id);
        self
    }

    /// Specify remote router's intro key.
    pub fn with_intro_key(mut self, intro_key: [u8; 32]) -> Self {
        self.intro_key = Some(intro_key);
        self
    }

    /// Specify network ID.
    pub fn with_net_id(mut self, net_id: u8) -> Self {
        self.net_id = net_id;
        self
    }

    /// Specfy address.
    pub fn with_addres(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    /// Build [`PeerTestBuilder`] into a byte vector.
    pub fn build<R: Runtime>(mut self) -> BytesMut {
        let intro_key = self.intro_key.take().expect("to exist");
        let mut rng = R::rng();
        let padding = {
            let padding_len = rng.next_u32() % MAX_PADDING as u32 + 8;
            let mut padding = vec![0u8; padding_len as usize];
            rng.fill_bytes(&mut padding);

            padding
        };

        let (mut header, pkt_num) = {
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN);
            let pkt_num = rng.next_u32();

            out.put_u64_le(self.dst_id.take().expect("to exist"));
            out.put_u32(pkt_num);
            out.put_u8(*MessageType::PeerTest);
            out.put_u8(2u8); // version
            out.put_u8(self.net_id);
            out.put_u8(0u8); // flag
            out.put_u64_le(self.src_id.take().expect("to exist"));
            out.put_u64(0u64);

            (out, pkt_num)
        };

        let mut payload = Vec::with_capacity(10 + padding.len() + POLY13055_MAC_LEN);
        payload.extend_from_slice(
            &Block::DateTime {
                timestamp: R::time_since_epoch().as_secs() as u32,
            }
            .serialize(),
        );
        if let Some(address) = self.address.take() {
            payload.extend_from_slice(&Block::Address { address }.serialize());
        }
        // TODO: not good...
        {
            // message number + code + flag + message
            let size = (1 + 1 + 1 + self.message.len()) as u16;

            payload.push(BlockType::PeerTest.as_u8());
            payload.extend_from_slice(&size.to_be_bytes());
            payload.push(self.msg_code);
            payload.push(0); // code
            payload.push(0); // flag
            payload.extend_from_slice(&self.message);
        }
        payload.extend_from_slice(&Block::Padding { padding }.serialize());

        // must succeed since all the parameters are controlled by us
        ChaChaPoly::with_nonce(&intro_key, pkt_num as u64)
            .encrypt_with_ad_new(&header, &mut payload)
            .expect("to succeed");

        // encrypt first 16 bytes of the long header
        //
        // https://geti2p.net/spec/ssu2#header-encryption-kdf
        payload[payload.len() - 2 * IV_SIZE..]
            .chunks(IV_SIZE)
            .zip(header.chunks_mut(8usize))
            .zip([intro_key, intro_key])
            .for_each(|((chunk, header_chunk), key)| {
                ChaCha::with_iv(
                    key,
                    TryInto::<[u8; IV_SIZE]>::try_into(chunk).expect("to succeed"),
                )
                .decrypt([0u8; 8])
                .iter()
                .zip(header_chunk.iter_mut())
                .for_each(|(mask_byte, header_byte)| {
                    *header_byte ^= mask_byte;
                });
            });

        // encrypt last 16 bytes of the header
        ChaCha::with_iv(intro_key, [0u8; IV_SIZE]).encrypt_ref(&mut header[16..32]);

        let mut out = BytesMut::with_capacity(LONG_HEADER_LEN + payload.len());
        out.put_slice(&header);
        out.put_slice(&payload);

        out
    }
}
