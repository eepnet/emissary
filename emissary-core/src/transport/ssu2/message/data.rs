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
    crypto::chachapoly::{ChaCha, ChaChaPoly},
    i2np::MessageType as I2npMessageType,
    transport::{
        ssu2::{message::*, session::KeyContext},
        TerminationReason,
    },
};

use bytes::{BufMut, BytesMut};

use alloc::vec::Vec;

/// Message kind for [`DataMessageBuilder`].
enum MessageKind<'a> {
    UnFragmented {
        /// Unfragmented I2NP message.
        message: &'a [u8],
    },

    /// First fragment.
    FirstFragment {
        /// Fragment.
        fragment: &'a [u8],

        /// Short expiration.
        expiration: u32,

        /// Message type.
        message_type: I2npMessageType,

        /// Message ID.
        message_id: u32,
    },

    /// Follow-on fragment.
    FollowOnFragment {
        /// Fragment.
        fragment: &'a [u8],

        /// Fragment number.
        fragment_num: u8,

        /// Last fragment.
        last: bool,

        /// Message ID.
        message_id: u32,
    },
}

/// Data message
#[derive(Default)]
pub struct DataMessageBuilder<'a> {
    /// ACK information.
    acks: Option<(u32, u8, Option<Vec<(u8, u8)>>)>,

    // Destination connection ID.
    dst_id: Option<u64>,

    /// Message kind.
    i2np: Option<MessageKind<'a>>,

    /// Key context for the message.
    key_context: Option<([u8; 32], &'a KeyContext)>,

    /// Payload length.
    payload_len: usize,

    /// Packet number.
    pkt_num: Option<u32>,

    /// Termination reason.
    termination_reason: Option<TerminationReason>,
}

impl<'a> DataMessageBuilder<'a> {
    /// Specify destination connection ID.
    pub fn with_dst_id(mut self, value: u64) -> Self {
        self.dst_id = Some(value);
        self
    }

    /// Specify packet number.
    pub fn with_pkt_num(mut self, value: u32) -> Self {
        self.pkt_num = Some(value);
        self
    }

    /// Specify key context.
    pub fn with_key_context(mut self, intro_key: [u8; 32], key_ctx: &'a KeyContext) -> Self {
        self.key_context = Some((intro_key, key_ctx));
        self
    }

    /// Specify I2NP message.
    pub fn with_i2np(mut self, message: &'a [u8]) -> Self {
        self.payload_len = self
            .payload_len
            .saturating_add(1usize) // type
            .saturating_add(2usize) // len
            .saturating_add(message.len());
        self.i2np = Some(MessageKind::UnFragmented { message });
        self
    }

    /// Specify first fragment.
    pub fn with_first_fragment(
        mut self,
        message_type: I2npMessageType,
        message_id: u32,
        expiration: u32,
        fragment: &'a [u8],
    ) -> Self {
        self.payload_len = self
            .payload_len
            .saturating_add(1usize) // type
            .saturating_add(2usize) // len
            .saturating_add(fragment.len());
        self.i2np = Some(MessageKind::FirstFragment {
            expiration,
            fragment,
            message_id,
            message_type,
        });
        self
    }

    /// Specify follow-on fragment.
    pub fn with_follow_on_fragment(
        mut self,
        message_id: u32,
        fragment_num: u8,
        last: bool,
        fragment: &'a [u8],
    ) -> Self {
        self.payload_len = self
            .payload_len
            .saturating_add(1usize) // type
            .saturating_add(2usize) // len
            .saturating_add(fragment.len());
        self.i2np = Some(MessageKind::FollowOnFragment {
            fragment,
            fragment_num,
            last,
            message_id,
        });
        self
    }

    /// Specify ACK information.
    pub fn with_ack(
        mut self,
        ack_through: u32,
        num_acks: u8,
        ranges: Option<Vec<(u8, u8)>>,
    ) -> Self {
        self.payload_len = self
            .payload_len
            .saturating_add(1usize) // type
            .saturating_add(2usize) // len
            .saturating_add(4usize) // ack through
            .saturating_add(1usize) // num acks
            .saturating_add(ranges.as_ref().map_or(0usize, |ranges| ranges.len() * 2)); // ranges
        self.acks = Some((ack_through, num_acks, ranges));
        self
    }

    /// Add termination block.
    pub fn with_termination(mut self, termination_reason: TerminationReason) -> Self {
        self.termination_reason = Some(termination_reason);
        self
    }

    /// Build message into one or more packets.
    pub fn build(mut self) -> BytesMut {
        let pkt_num = self.pkt_num.expect("to exist");

        let mut header = {
            let mut out = BytesMut::with_capacity(16usize);

            out.put_u64_le(self.dst_id.expect("to exist"));
            out.put_u32(pkt_num);

            out.put_u8(*MessageType::Data);
            out.put_u8(0u8); // immediate ack
            out.put_u16(0u16); // more flags

            out
        };

        // build payload
        let mut payload = {
            let mut out = BytesMut::with_capacity(self.payload_len + POLY13055_MAC_LEN);

            match self.i2np.take() {
                None => {}
                Some(MessageKind::UnFragmented { message }) => {
                    out.put_u8(BlockType::I2Np.as_u8());
                    out.put_slice(message);
                }
                Some(MessageKind::FirstFragment {
                    expiration,
                    fragment,
                    message_id,
                    message_type,
                }) => {
                    out.put_u8(BlockType::FirstFragment.as_u8());
                    out.put_u16((fragment.len() + 1 + 4 + 4) as u16);
                    out.put_u8(message_type.as_u8());
                    out.put_u32(message_id);
                    out.put_u32(expiration);
                    out.put_slice(fragment);
                }
                Some(MessageKind::FollowOnFragment {
                    fragment,
                    fragment_num,
                    last,
                    message_id,
                }) => {
                    out.put_u8(BlockType::FollowOnFragment.as_u8());
                    out.put_u16((fragment.len() + 1 + 4) as u16);
                    out.put_u8((fragment_num << 1) | last as u8);
                    out.put_u32(message_id);
                    out.put_slice(fragment);
                }
            }

            match self.acks.take() {
                None => {}
                Some((ack_through, num_acks, None)) => {
                    out.put_u8(BlockType::Ack.as_u8());
                    out.put_u16(5u16);
                    out.put_u32(ack_through);
                    out.put_u8(num_acks);
                }
                Some((ack_through, num_acks, Some(ranges))) => {
                    out.put_u8(BlockType::Ack.as_u8());
                    out.put_u16((5usize + ranges.len() * 2) as u16);
                    out.put_u32(ack_through);
                    out.put_u8(num_acks);

                    ranges.into_iter().for_each(|(nack, ack)| {
                        out.put_u8(nack);
                        out.put_u8(ack);
                    });
                }
            }

            out.to_vec()
        };

        // encrypt payload and headers, and build the full message
        let (intro_key, KeyContext { k_data, k_header_2 }) =
            self.key_context.take().expect("to exist");

        ChaChaPoly::with_nonce(k_data, pkt_num as u64)
            .encrypt_with_ad_new(&header, &mut payload)
            .expect("to succeed");

        // encrypt first 16 bytes of the long header
        //
        // https://geti2p.net/spec/ssu2#header-encryption-kdf
        payload[payload.len() - 2 * IV_SIZE..]
            .chunks(IV_SIZE)
            .zip(header.chunks_mut(8usize))
            .zip([intro_key, *k_header_2])
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

        let mut out = BytesMut::with_capacity(header.len() + payload.len());
        out.put_slice(&header);
        out.put_slice(&payload);

        out
    }
}
