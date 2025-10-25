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

//! NTCP2 message block implementation
//!
//! https://geti2p.net/spec/ntcp2#unencrypted-data

use crate::{error::parser::Ntcp2ParseError, i2np::Message};

use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    Err, IResult,
};

use alloc::{vec, vec::Vec};
use core::fmt;

/// Minimum size for options message.
const OPTIONS_MIN_SIZE: u16 = 12u16;

/// Minimum size for termination message.
const TERMINATION_MIN_SIZE: u16 = 9u16;

/// Block format identifier.
#[derive(Debug)]
enum BlockType {
    /// Date time.
    DateTime,

    /// Updated options.
    Options,

    /// Router information.
    RouterInfo,

    /// I2NP message.
    I2Np,

    /// NTCP2 termination.
    Termination,

    /// Padding
    Padding,
}

impl BlockType {
    /// Serialize [`BlockType`].
    fn as_u8(&self) -> u8 {
        match self {
            Self::DateTime => 0,
            Self::Options => 1,
            Self::RouterInfo => 2,
            Self::I2Np => 3,
            Self::Termination => 4,
            Self::Padding => 254,
        }
    }

    /// Deserialize [`BlockType`].
    fn from_u8(block: u8) -> Option<Self> {
        match block {
            0 => Some(Self::DateTime),
            1 => Some(Self::Options),
            2 => Some(Self::RouterInfo),
            3 => Some(Self::I2Np),
            4 => Some(Self::Termination),
            254 => Some(Self::Padding),
            _ => None,
        }
    }

    /// Get header size for a message block.
    fn header_size(&self) -> usize {
        match self {
            // `<1 byte block id><2 byte length>`
            Self::DateTime | Self::Options | Self::Termination | Self::Padding => 3,

            // `<1 byte block id><2 byte length><1 byte flag>`
            Self::RouterInfo => 4,

            // `<1 byte block id><2 byte length><1 byte type><4 byte message id><4 byte expiration`
            Self::I2Np => 12,
        }
    }
}

/// NTCP2 message block.
pub enum MessageBlock<'a> {
    /// Date time update, used for time synchronization.
    DateTime {
        /// Time since Unix epoch, in seconds.
        timestamp: u32,
    },

    /// Options update.
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

    /// Router info update.
    RouterInfo {
        /// Whether the received message was a floodfill request.
        floodfill_request: bool,

        /// Router info.
        router_info: &'a [u8],
    },

    /// I2NP message.
    I2Np {
        /// Raw, unparsed I2NP message.
        message: Message,
    },

    /// Session termination.
    Termination {
        /// How many valid frames have been received.
        valid_frames: u64,

        /// Reason for termination.
        reason: u8,
    },

    /// Padding
    Padding {
        /// Padding bytes.
        padding: &'a [u8],
    },
}

impl fmt::Debug for MessageBlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::DateTime { timestamp } =>
                f.debug_struct("MessageBlock::DateTime").field("timestamp", &timestamp).finish(),
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
                .debug_struct("MessageBlock::Options")
                .field("t_min", &t_min)
                .field("t_max", &t_max)
                .field("r_min", &r_min)
                .field("r_max", &r_max)
                .field("t_dmy", &t_dmy)
                .field("r_dmy", &r_dmy)
                .field("t_delay", &t_delay)
                .field("r_deay", &r_delay)
                .finish(),
            Self::RouterInfo {
                floodfill_request,
                router_info,
            } => f
                .debug_struct("MessageBlock::RouterInfo")
                .field("floodfill", &floodfill_request)
                .field("router_info_len", &router_info.len())
                .finish(),
            Self::I2Np { message } =>
                f.debug_struct("MessageBlock::I2NP").field("message", &message).finish(),
            Self::Termination {
                valid_frames,
                reason,
            } => f
                .debug_struct("MessageBlock::Termination")
                .field("valid_frames", &valid_frames)
                .field("reason", &reason)
                .finish(),
            Self::Padding { padding } => f
                .debug_struct("MessageBlock::Padding")
                .field("padding_len", &padding.len())
                .finish(),
        }
    }
}

impl<'a> MessageBlock<'a> {
    /// Parse [`MessageBlock::DateTime`].
    fn parse_date_time(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
        let (rest, _size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        Ok((rest, MessageBlock::DateTime { timestamp }))
    }

    /// Parse [`MessageBlock::Options`].
    fn parse_options(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
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
            MessageBlock::Options {
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

    /// Parse [`MessageBlock::RouterInfo`].
    fn parse_router_info(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
        let (rest, size) = be_u16(input)?;
        if size == 0 {
            return Err(Err::Error(Ntcp2ParseError::EmptyRouterInfo));
        }
        let (rest, flag) = be_u8(rest)?;
        let (rest, router_info) = take(size - 1)(rest)?;

        Ok((
            rest,
            MessageBlock::RouterInfo {
                floodfill_request: flag & 1 == 1,
                router_info,
            },
        ))
    }

    /// Parse [`MessageBlock::I2Np`].
    fn parse_i2np(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
        let (rest, message) = Message::parse_frame_short(input).map_err(Err::convert)?;

        Ok((rest, MessageBlock::I2Np { message }))
    }

    /// Parse [`MessageBlock::Termination`].
    fn parse_termination(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, valid_frames) = be_u64(rest)?;
        let (rest, reason) = be_u8(rest)?;

        let rest = if size > TERMINATION_MIN_SIZE {
            let (rest, _) = take(size - TERMINATION_MIN_SIZE)(rest)?;
            rest
        } else {
            rest
        };

        Ok((
            rest,
            MessageBlock::Termination {
                valid_frames,
                reason,
            },
        ))
    }

    /// Parse [`MessageBlock::Padding`].
    fn parse_padding(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
        let (rest, size) = be_u16(input)?;
        let (rest, padding) = take(size)(rest)?;

        Ok((rest, MessageBlock::Padding { padding }))
    }

    fn parse_inner(input: &'a [u8]) -> IResult<&'a [u8], MessageBlock<'a>, Ntcp2ParseError> {
        let (rest, block_type) = be_u8(input)?;

        match BlockType::from_u8(block_type) {
            Some(BlockType::DateTime) => Self::parse_date_time(rest),
            Some(BlockType::Options) => Self::parse_options(rest),
            Some(BlockType::RouterInfo) => Self::parse_router_info(rest),
            Some(BlockType::I2Np) => Self::parse_i2np(rest),
            Some(BlockType::Termination) => Self::parse_termination(rest),
            Some(BlockType::Padding) => Self::parse_padding(rest),
            None => Err(Err::Error(Ntcp2ParseError::InvalidBlock(block_type))),
        }
    }

    fn parse_multiple_inner(
        input: &'a [u8],
        mut messages: Vec<MessageBlock<'a>>,
    ) -> Result<Vec<MessageBlock<'a>>, Ntcp2ParseError> {
        let (rest, message) = Self::parse_inner(input)?;
        messages.push(message);

        match rest.is_empty() {
            true => Ok(messages),
            false => Self::parse_multiple_inner(rest, messages),
        }
    }

    /// Try to parse `input` into one or more NTCP2 message blocks.
    pub fn parse_multiple(input: &'a [u8]) -> Result<Vec<MessageBlock<'a>>, Ntcp2ParseError> {
        MessageBlock::parse_multiple_inner(input, Vec::new())
    }

    /// Try to parse `input` into an NTCP2 message block
    pub fn parse(input: &'a [u8]) -> Result<MessageBlock<'a>, Ntcp2ParseError> {
        let (_rest, parsed) = MessageBlock::parse_inner(input)?;

        Ok(parsed)
    }

    /// Create new NTCP2 `RouterInfo` message block.
    pub fn new_router_info(router_info: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; router_info.len() + BlockType::RouterInfo.header_size()];
        let block_size = router_info.len() as u16 + 1u16; // router info length + 1 byte for the flag

        out[0] = BlockType::RouterInfo.as_u8();
        out[1..3].copy_from_slice(block_size.to_be_bytes().as_ref());
        out[3] = 0;
        out[4..].copy_from_slice(router_info);

        out
    }

    // TODO: unnecessary copy
    pub fn new_i2np_message(message: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; message.len() + 1];

        out[0] = BlockType::I2Np.as_u8();
        out[1..].copy_from_slice(message);

        out
    }
}
