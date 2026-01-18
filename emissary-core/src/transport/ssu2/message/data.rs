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
    primitives::RouterId,
    runtime::Runtime,
    transport::{
        ssu2::{message::*, peer_test::types::RejectionReason, session::KeyContext},
        TerminationReason,
    },
};

use bytes::{BufMut, BytesMut};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};

/// Minimum size for an ACK block.
const ACK_BLOCK_MIN_SIZE: usize = 8usize;

/// Termination block minimum size.
const TERMINATION_BLOCK_MIN_SIZE: usize = 12usize;

/// Minimum size for `Data` packet.
const DATA_PKT_MIN_SIZE: usize = 24usize;

/// Router hash length.
const ROUTER_HASH_LEN: usize = 32usize;

/// Message kind for [`DataMessageBuilder`].
pub enum MessageKind<'a> {
    /// Unfragmented I2NP message.
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

/// Peer test block.
pub enum PeerTestBlock {
    /// Bob rejected Alice's peer test request.
    BobReject {
        /// Rejection reason.
        reason: RejectionReason,

        /// Message + signature.
        ///
        /// Sent by Alice in peer test 1 message and covers all the fields
        /// the signature verifies and the signature itself.
        message: Vec<u8>,
    },

    /// Request Charlie to participate in a peer test for Alice.
    RequestCharlie {
        /// Router ID of Alice.
        router_id: RouterId,

        /// Message sent by Alice + signature.
        message: Vec<u8>,
    },

    /// Accept peer test request from Bob for Alice as Charlie.
    AcceptAlice {
        /// Message sent by Alice + signature from Charlie.
        message: Vec<u8>,

        /// Rejection reason.
        ///
        /// `None` if Charlie accepted the peer test request.
        rejection: Option<RejectionReason>,
    },

    /// Relay Charlie's response to Alice's request as Bob.
    RelayCharlieResponse {
        /// Message sent by Alice + signature from Charlie.
        message: Vec<u8>,

        /// Rejection reason.
        ///
        /// `None` if Charlie accepted the peer test request.
        rejection: Option<RejectionReason>,

        /// Router ID of Charlie.
        router_id: RouterId,
    },
}

#[allow(unused)]
impl PeerTestBlock {
    /// Get serialized length of the block.
    pub fn serialized_len(&self) -> usize {
        // block type + block length + message number + code + flag
        let overhead = 1 + 2 + 1 + 1 + 1;

        match self {
            Self::BobReject { message, .. } => overhead + ROUTER_HASH_LEN + message.len(),
            Self::RequestCharlie { message, .. } => overhead + ROUTER_HASH_LEN + message.len(),
            Self::AcceptAlice { message, .. } => overhead + message.len(),
            Self::RelayCharlieResponse { message, .. } =>
                overhead + message.len() + ROUTER_HASH_LEN,
        }
    }
}

/// Data message
#[derive(Default)]
pub struct DataMessageBuilder<'a> {
    /// ACK information.
    acks: Option<(u32, u8, Option<Vec<(u8, u8)>>)>,

    // Destination connection ID.
    dst_id: Option<u64>,

    /// Should the immediate ACK bit be set.
    immediate_ack: bool,

    /// Key context for the message.
    key_context: Option<([u8; 32], &'a KeyContext)>,

    /// Packet number and [`MessageKind`].
    message: Option<(u32, MessageKind<'a>)>,

    /// Peer test block.
    peer_test_block: Option<PeerTestBlock>,

    /// Packet number.
    ///
    /// Set only if `message` is `None`.
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

    /// Specify key context.
    pub fn with_key_context(mut self, intro_key: [u8; 32], key_ctx: &'a KeyContext) -> Self {
        self.key_context = Some((intro_key, key_ctx));
        self
    }

    /// Set immediate ACK in the header.
    pub fn with_immediate_ack(mut self) -> Self {
        self.immediate_ack = true;
        self
    }

    /// Specify `PeerTestBlock`.
    pub fn with_peer_test_block(mut self, block: PeerTestBlock) -> Self {
        self.peer_test_block = Some(block);
        self
    }

    /// Specify packet number.
    ///
    /// Set only if `DataMessageBuilder::with_message()` is not used.
    pub fn with_pkt_num(mut self, pkt_num: u32) -> Self {
        self.pkt_num = Some(pkt_num);
        self
    }

    /// Specify packet number and [`MessageKind`].
    pub fn with_message(mut self, pkt_num: u32, message_kind: MessageKind<'a>) -> Self {
        self.message = Some((pkt_num, message_kind));
        self
    }

    /// Specify ACK information.
    pub fn with_ack(
        mut self,
        ack_through: u32,
        num_acks: u8,
        ranges: Option<Vec<(u8, u8)>>,
    ) -> Self {
        self.acks = Some((ack_through, num_acks, ranges));
        self
    }

    /// Add termination block.
    pub fn with_termination(mut self, termination_reason: TerminationReason) -> Self {
        self.termination_reason = Some(termination_reason);
        self
    }

    /// Build message into one or more packets.
    pub fn build<R: Runtime>(mut self) -> BytesMut {
        let (pkt_num, message) = match self.pkt_num.take() {
            Some(pkt_num) => (pkt_num, None),
            None => self
                .message
                .map(|(pkt_num, message)| (pkt_num, Some(message)))
                .expect("to exist"),
        };

        let mut header = {
            let mut out = BytesMut::with_capacity(16usize);

            out.put_u64_le(self.dst_id.expect("to exist"));
            out.put_u32(pkt_num);

            out.put_u8(*MessageType::Data);
            if self.immediate_ack {
                out.put_u8(1u8);
            } else {
                out.put_u8(0u8);
            }
            out.put_u16(0u16); // more flags

            out
        };

        // build payload
        let mut payload = {
            let mut bytes_left = if self.termination_reason.is_some() {
                1300 - TERMINATION_BLOCK_MIN_SIZE // TODO: not correct
            } else {
                1300 // TODO: not correct
            };
            let mut out = BytesMut::with_capacity(bytes_left);

            match message {
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
            bytes_left = bytes_left.saturating_sub(out.len());

            match self.acks.take() {
                None => {}
                Some((ack_through, num_acks, None)) =>
                    if bytes_left > ACK_BLOCK_MIN_SIZE {
                        out.put_u8(BlockType::Ack.as_u8());
                        out.put_u16(5u16);
                        out.put_u32(ack_through);
                        out.put_u8(num_acks);
                    },
                Some((ack_through, num_acks, Some(ranges))) =>
                    if bytes_left > ACK_BLOCK_MIN_SIZE {
                        out.put_u8(BlockType::Ack.as_u8());
                        out.put_u16((5usize + ranges.len() * 2) as u16);
                        out.put_u32(ack_through);
                        out.put_u8(num_acks);

                        ranges
                            .into_iter()
                            .take(bytes_left.saturating_sub(ACK_BLOCK_MIN_SIZE) / 2)
                            .for_each(|(nack, ack)| {
                                out.put_u8(nack);
                                out.put_u8(ack);
                            });
                    },
            }

            match self.peer_test_block.take() {
                None => {}
                Some(PeerTestBlock::BobReject { reason, message }) => {
                    out.put_u8(BlockType::PeerTest.as_u8());
                    out.put_u16((3 + message.len() + ROUTER_HASH_LEN) as u16);
                    out.put_u8(4); // message 4 (bob -> alice)
                    out.put_u8(reason.as_bob()); // code
                    out.put_u8(0u8); // flag
                    out.put_slice(&[0u8; 32]);
                    out.put_slice(&message);
                }
                Some(PeerTestBlock::RequestCharlie { router_id, message }) => {
                    out.put_u8(BlockType::PeerTest.as_u8());
                    out.put_u16((3 + message.len() + ROUTER_HASH_LEN) as u16);
                    out.put_u8(2); // message 2 (bob -> charlie)
                    out.put_u8(0); // accept
                    out.put_u8(0u8); // flag
                    out.put_slice(&router_id.to_vec());
                    out.put_slice(&message);
                }
                Some(PeerTestBlock::AcceptAlice { message, rejection }) => {
                    out.put_u8(BlockType::PeerTest.as_u8());
                    out.put_u16((3 + message.len()) as u16);
                    out.put_u8(3); // message 3 (charlie -> bob)
                    out.put_u8(rejection.map_or(0, |reason| reason.as_charlie()));
                    out.put_u8(0u8); // flag
                    out.put_slice(&message);
                }
                Some(PeerTestBlock::RelayCharlieResponse {
                    message,
                    rejection,
                    router_id,
                }) => {
                    out.put_u8(BlockType::PeerTest.as_u8());
                    out.put_u16((3 + message.len() + ROUTER_HASH_LEN) as u16);
                    out.put_u8(4); // message 4 (bob -> alice)
                    out.put_u8(rejection.map_or(0, |reason| reason.as_charlie()));
                    out.put_u8(0u8); // flag
                    out.put_slice(&router_id.to_vec());
                    out.put_slice(&message);
                }
            }

            if let Some(reason) = self.termination_reason {
                if bytes_left < TERMINATION_BLOCK_MIN_SIZE {
                    tracing::error!(
                        target: LOG_TARGET,
                        "packet doesn't have enough space for termination block",
                    );
                    debug_assert!(false);
                }

                out.put_u8(BlockType::Termination.as_u8());
                out.put_u16(9u16);
                out.put_u64(pkt_num as u64); // TODO: not correct
                out.put_u8(reason.from_ssu2());
            }

            if out.len() < DATA_PKT_MIN_SIZE {
                let padding = {
                    let mut padding = vec![0u8; (R::rng().next_u32() % 128 + 8) as usize];
                    R::rng().fill_bytes(&mut padding);

                    padding
                };
                out.put_u8(BlockType::Padding.as_u8());
                out.put_u16(padding.len() as u16);
                out.put_slice(&padding);
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

        debug_assert!(out.len() < 1500 - 68);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[test]
    fn immediate_ack() {
        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(1337u64)
            .with_pkt_num(0xdeadbeef)
            .with_key_context(
                [1u8; 32],
                &KeyContext {
                    k_data: [2u8; 32],
                    k_header_2: [3u8; 32],
                },
            )
            .with_ack(16, 5, None)
            .with_immediate_ack()
            .build::<MockRuntime>()
            .to_vec();

        match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([3u8; 32]).unwrap() {
            HeaderKind::Data {
                immediate_ack,
                pkt_num,
            } => {
                assert_eq!(pkt_num, 0xdeadbeef);
                assert!(immediate_ack);
            }
            _ => panic!("invalid type"),
        }

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(1337u64)
            .with_pkt_num(1)
            .with_key_context(
                [1u8; 32],
                &KeyContext {
                    k_data: [2u8; 32],
                    k_header_2: [3u8; 32],
                },
            )
            .with_ack(16, 5, None)
            .build::<MockRuntime>()
            .to_vec();

        match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([3u8; 32]).unwrap() {
            HeaderKind::Data { immediate_ack, .. } => assert!(!immediate_ack),
            _ => panic!("invalid type"),
        }
    }
}
