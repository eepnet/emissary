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
    crypto::sha256::Sha256,
    error::parser::TunnelDataParseError,
    i2np::{AES256_IV_LEN, ROUTER_HASH_LEN},
    primitives::{MessageId, TunnelId},
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::{fmt, iter};

/// Local delivery
const LOCAL_DELIVERY: u8 = 0x00;

/// Tunnel delivery.
const TUNNEL_DELIVERY: u8 = 0x01;

/// Router delivery.
const ROUTER_DELIVERY: u8 = 0x02;

/// Unfragmented message.
const UNFRAGMENTED: u8 = 0x00;

/// Fragmented message.
const FRAGMENTED: u8 = 0x01;

/// First fragment.
const FIRST_FRAGMENT: u8 = 0x01;

/// Middle fragment.
const MIDDLE_FRAGMENT: u8 = 0x00;

/// Last fragment.
const LAST_FRAGMENT: u8 = 0x01;

/// Maximum size for `TunnelData` message.
const TUNNEL_DATA_LEN: usize = 1028usize;

/// Tunnel data payload length.
const TUNNEL_DATA_PAYLOAD_LEN: usize = 1008usize;

/// Encrypted tunnel data.
pub struct EncryptedTunnelData<'a> {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// AES-256-ECB IV.
    iv: &'a [u8],

    /// Encrypted [`TunnelData`].
    ciphertext: &'a [u8],
}

impl<'a> EncryptedTunnelData<'a> {
    /// Attempt to parse [`EncryptedTunnelData`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], EncryptedTunnelData<'a>> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, iv) = take(AES256_IV_LEN)(rest)?;
        let (rest, ciphertext) = take(TUNNEL_DATA_PAYLOAD_LEN)(rest)?;

        Ok((
            rest,
            EncryptedTunnelData {
                tunnel_id: TunnelId::from(tunnel_id),
                iv,
                ciphertext,
            },
        ))
    }

    /// Attempt to parse `input` into [`EncryptedTunnelData`].
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self::parse_frame(input).ok()?.1)
    }

    /// Get tunnel ID of the message.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Get reference to AES-256-ECB IV.
    pub fn iv(&self) -> &[u8] {
        self.iv
    }

    /// Get reference to ciphertext ([`TunnelData`]).
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }

    /// Get XOR of IV and ciphertext's first block.
    pub fn xor(&self) -> [u8; AES256_IV_LEN] {
        let mut result = [0u8; AES256_IV_LEN];

        for (i, item) in result.iter_mut().enumerate().take(AES256_IV_LEN) {
            *item = self.iv[i] ^ self.ciphertext[i];
        }

        result
    }
}

/// Delivery instructions for the wrapped I2NP message.
#[derive(Debug)]
pub enum DeliveryInstructions<'a> {
    /// Fragment meant for the local router.
    Local,

    /// Fragment meant for a router.
    Router {
        /// Hash of the router.
        hash: &'a [u8],
    },

    /// Fragment meant for a tunnel.
    Tunnel {
        /// Tunnel ID.
        tunnel_id: u32,

        /// Hash of the tunnel.
        hash: &'a [u8],
    },
}

/// I2NP message kind.
///
/// [`MessageKind::MiddleFragment`] and [`MessageKind::LastFragment`] do not have explicit
/// delivery instructions as they're delivered to the same destination as the first fragment.
#[derive(Debug)]
pub enum MessageKind<'a> {
    /// Unfragmented I2NP message.
    Unfragmented {
        /// Delivery instructions,
        delivery_instructions: DeliveryInstructions<'a>,
    },

    /// First fragment of a fragmented I2NP message.
    FirstFragment {
        /// Message ID.
        ///
        /// Rest of the fragments will use the same message ID.
        message_id: u32,

        /// Delivery instructions,
        delivery_instructions: DeliveryInstructions<'a>,
    },

    /// Middle fragment of a fragmented I2NP message.
    MiddleFragment {
        /// Message ID.
        ///
        /// Same as the first fragment's message ID.
        message_id: u32,

        /// Sequence number.
        sequence_number: usize,
    },

    /// Last fragment of a fragmented I2NP message.
    LastFragment {
        /// Message ID.
        ///
        /// Same as the first fragment's message ID.
        message_id: u32,

        /// Sequence number.
        sequence_number: usize,
    },
}

impl MessageKind<'_> {
    /// Get serialized length of [`MessageKind`]'s [`DeliveryInstructions`].
    fn serialized_len(&self) -> usize {
        match self {
            Self::Unfragmented {
                delivery_instructions,
            } => match delivery_instructions {
                DeliveryInstructions::Local => 1usize,
                DeliveryInstructions::Router { .. } => 33usize,
                DeliveryInstructions::Tunnel { .. } => 37usize,
            },
            _ => unreachable!(),
        }
    }

    fn into_fragmented(self, message_id: MessageId) -> Self {
        match self {
            Self::Unfragmented {
                delivery_instructions,
            } => Self::FirstFragment {
                message_id: *message_id,
                delivery_instructions,
            },
            _ => unreachable!(),
        }
    }

    /// Serialize [`MessageKind`]'s [`DeliveryInstructions`].
    fn serialize(self) -> BytesMut {
        match self {
            MessageKind::Unfragmented {
                delivery_instructions,
            } => match delivery_instructions {
                DeliveryInstructions::Local => BytesMut::from_iter(vec![0x00]),
                DeliveryInstructions::Router { hash } => {
                    let mut out = BytesMut::with_capacity(33);
                    out.put_u8(0x02 << 5);
                    out.put_slice(hash);

                    out
                }
                DeliveryInstructions::Tunnel { tunnel_id, hash } => {
                    let mut out = BytesMut::with_capacity(37);
                    out.put_u8(0x01 << 5);
                    out.put_u32(tunnel_id);
                    out.put_slice(hash);

                    out
                }
            },
            MessageKind::FirstFragment {
                message_id,
                delivery_instructions,
            } => match delivery_instructions {
                DeliveryInstructions::Local => {
                    let mut out = BytesMut::with_capacity(5);
                    out.put_u8(0x01 << 3);
                    out.put_u32(message_id);

                    out
                }
                DeliveryInstructions::Router { hash } => {
                    let mut out = BytesMut::with_capacity(38);
                    out.put_u8((0x01 << 3) | (0x02 << 5));
                    out.put_slice(hash);
                    out.put_u32(message_id);

                    out
                }
                DeliveryInstructions::Tunnel { tunnel_id, hash } => {
                    let mut out = BytesMut::with_capacity(41);
                    out.put_u8((0x01 << 3) | (0x01 << 5));
                    out.put_u32(tunnel_id);
                    out.put_slice(hash);
                    out.put_u32(message_id);

                    out
                }
            },
            MessageKind::MiddleFragment {
                message_id,
                sequence_number,
            } => {
                let mut out = BytesMut::with_capacity(5);
                out.put_u8((0x01 << 7) | ((sequence_number as u8 & 0x3f) << 1));
                out.put_u32(message_id);

                out
            }
            MessageKind::LastFragment {
                message_id,
                sequence_number,
            } => {
                let mut out = BytesMut::with_capacity(5);
                out.put_u8((0x01 << 7) | ((sequence_number as u8 & 0x3f) << 1) | 0x01);
                out.put_u32(message_id);

                out
            }
        }
    }
}

/// Parsed `TunnelData` block.
pub struct TunnelDataBlock<'a> {
    /// Message kind.
    ///
    /// Defines the fragmentation (if any) of the message and its delivery instructions.
    pub message_kind: MessageKind<'a>,

    /// I2NP message (fragment).
    pub message: &'a [u8],
}

impl fmt::Debug for TunnelDataBlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelDataBlock")
            .field("message_kind", &self.message_kind)
            .finish_non_exhaustive()
    }
}

/// Decrypted `TunnelData` message.
#[derive(Debug)]
pub struct TunnelData<'a> {
    /// Parsed messages.
    pub messages: Vec<TunnelDataBlock<'a>>,
}

impl<'a> TunnelData<'a> {
    /// Attempt to parse `input` into first or follow-on delivery instructions and payload.
    fn parse_frame(
        input: &'a [u8],
    ) -> IResult<&'a [u8], TunnelDataBlock<'a>, TunnelDataParseError> {
        let (rest, flag) = be_u8(input)?;

        // parse follow-on fragment delivery instructions
        //
        // https://geti2p.net/spec/tunnel-message#follow-on-fragment-delivery-instructions
        match flag >> 7 {
            FRAGMENTED => {
                // format: 1nnnnnnd
                //  - msb set for a middle fragment
                //  - middle bits make up the sequence number
                //  - lsb specifies whether this is the last fragment
                let sequence_number = ((flag >> 1) & 0x3f) as usize;
                let (rest, message_id) = be_u32(rest)?;
                let (rest, size) = be_u16(rest)?;
                let (rest, message) = take(size as usize)(rest)?;

                let (rest, message_kind) = match flag & 0x01 {
                    MIDDLE_FRAGMENT => (
                        rest,
                        MessageKind::MiddleFragment {
                            message_id,
                            sequence_number,
                        },
                    ),
                    LAST_FRAGMENT => (
                        rest,
                        MessageKind::LastFragment {
                            message_id,
                            sequence_number,
                        },
                    ),
                    fragment =>
                        return Err(Err::Error(TunnelDataParseError::InvalidFragment(fragment))),
                };

                return Ok((
                    rest,
                    TunnelDataBlock {
                        message_kind,
                        message,
                    },
                ));
            }
            UNFRAGMENTED => {}
            kind => return Err(Err::Error(TunnelDataParseError::InvalidMessage(kind))),
        }

        // parse first fragment delivery instructions.
        //
        // https://geti2p.net/spec/tunnel-message#first-fragment-delivery-instructions
        let (rest, delivery_instructions) = match (flag >> 5) & 0x03 {
            LOCAL_DELIVERY => (rest, DeliveryInstructions::Local),
            TUNNEL_DELIVERY => {
                let (rest, tunnel_id) = be_u32(rest)?;
                let (rest, hash) = take(ROUTER_HASH_LEN)(rest)?;

                (rest, DeliveryInstructions::Tunnel { hash, tunnel_id })
            }
            ROUTER_DELIVERY => {
                let (rest, hash) = take(ROUTER_HASH_LEN)(rest)?;

                (rest, DeliveryInstructions::Router { hash })
            }
            kind => return Err(Err::Error(TunnelDataParseError::InvalidDelivery(kind))),
        };

        let (rest, message_kind) = match (flag >> 3) & 0x01 {
            UNFRAGMENTED => (
                rest,
                MessageKind::Unfragmented {
                    delivery_instructions,
                },
            ),
            FIRST_FRAGMENT => {
                let (rest, message_id) = be_u32(rest)?;

                (
                    rest,
                    MessageKind::FirstFragment {
                        delivery_instructions,
                        message_id,
                    },
                )
            }
            kind => return Err(Err::Error(TunnelDataParseError::InvalidFragment(kind))),
        };

        let (rest, size) = be_u16(rest)?;
        let (rest, message) = take(size as usize)(rest)?;

        Ok((
            rest,
            TunnelDataBlock {
                message_kind,
                message,
            },
        ))
    }

    /// Recursively parse `input` into a vector of [`TunnelDataBlock`]s
    fn parse_inner(
        input: &'a [u8],
        mut messages: Vec<TunnelDataBlock<'a>>,
    ) -> Result<Vec<TunnelDataBlock<'a>>, TunnelDataParseError> {
        let (rest, message) = Self::parse_frame(input)?;
        messages.push(message);

        match rest.is_empty() {
            true => Ok(messages),
            false => Self::parse_inner(rest, messages),
        }
    }

    /// Attempt to parse `input` into [`TunnelData`].
    pub fn parse(input: &'a [u8]) -> Result<Self, TunnelDataParseError> {
        Ok(Self {
            messages: Self::parse_inner(input, Vec::new())?,
        })
    }
}

/// Tunnel data builder.
pub struct TunnelDataBuilder<'a> {
    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Messages.
    message: Option<TunnelDataBlock<'a>>,
}

impl<'a> TunnelDataBuilder<'a> {
    /// Create new [`TunnelDataBuilder`].
    pub fn new(next_tunnel_id: TunnelId) -> Self {
        Self {
            next_tunnel_id,
            message: None,
        }
    }

    /// Add [`TunnelData`] block with local delivery.
    pub fn with_local_delivery(mut self, message: &'a [u8]) -> Self {
        self.message = Some(TunnelDataBlock {
            message_kind: MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Local,
            },
            message,
        });

        self
    }

    /// Add [`TunnelData`] block with router delivery.
    pub fn with_router_delivery(mut self, hash: &'a [u8], message: &'a [u8]) -> Self {
        self.message = Some(TunnelDataBlock {
            message_kind: MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Router { hash },
            },
            message,
        });

        self
    }

    /// Add [`TunnelData`] block with tunnel delivery.
    pub fn with_tunnel_delivery(
        mut self,
        hash: &'a [u8],
        tunnel_id: TunnelId,
        message: &'a [u8],
    ) -> Self {
        self.message = Some(TunnelDataBlock {
            message_kind: MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Tunnel {
                    tunnel_id: tunnel_id.into(),
                    hash,
                },
            },
            message,
        });

        self
    }

    /// Calculate checksum for a `TunnelData` message.
    fn checksum(delivery_instructions: &[u8], message: &[u8], iv: &[u8]) -> [u8; 4] {
        TryInto::<[u8; 4]>::try_into(
            &Sha256::new()
                .update(delivery_instructions)
                .update((message.len() as u16).to_be_bytes())
                .update(message)
                .update(iv)
                .finalize()[..4],
        )
        .expect("to succeed")
    }

    fn serialize<R: Runtime>(
        tunnel_id: TunnelId,
        delivery_instructions: &[u8],
        payload_size: usize,
        message: &[u8],
        padding: Option<&[u8]>,
    ) -> Vec<u8> {
        // generate random aes iv for the message
        //
        // the iv is different for each message
        let aes_iv = {
            let mut iv = [0u8; 16];
            R::rng().fill_bytes(&mut iv);

            iv
        };

        let mut out = BytesMut::with_capacity(TUNNEL_DATA_LEN);

        out.put_u32(tunnel_id.into());
        out.put_slice(&aes_iv);
        out.put_slice(&Self::checksum(delivery_instructions, message, &aes_iv));

        if let Some(padding) = padding {
            // calculate padding size and generate random offset into `padding`
            let padding_size = payload_size.saturating_sub(message.len());
            let padding_offset = R::rng().next_u32() as usize % (TUNNEL_DATA_LEN - padding_size);

            out.put_slice(&padding[padding_offset..padding_offset + padding_size]);
        }

        out.put_u8(0x00); // zero byte (end of padding)
        out.put_slice(delivery_instructions);
        out.put_u16(message.len() as u16);
        out.put_slice(message);

        out.freeze().to_vec()
    }

    /// Serialize `message` into two or more `TunnelData` message fragments.
    fn serialize_fragmented<R: Runtime>(
        tunnel_id: TunnelId,
        message: TunnelDataBlock<'a>,
        payload_size: usize,
        padding: &[u8],
    ) -> Vec<Vec<u8>> {
        // first and all follow-on fragments contain a unique message,
        // identifiying all fragments that belong to the same message
        let first_fragment_payload_size = payload_size.saturating_sub(4usize); // message id

        // follow-on fragments contain the same message id as the first fragment but do not
        // contain delivery instructions as those are already transported in the first fragment
        let follow_on_fragment_payload_size = payload_size
            .saturating_sub(1usize) // flag
            .saturating_sub(4usize) // message id
            .saturating_add(message.message_kind.serialized_len());

        // unique message id for all fragments
        let message_id = MessageId::from(R::rng().next_u32());

        // serialize first fragment
        let first_fragment = Self::serialize::<R>(
            tunnel_id,
            &message.message_kind.into_fragmented(message_id).serialize(),
            first_fragment_payload_size,
            &message.message[..first_fragment_payload_size],
            None,
        );

        // count the number of remaining fragments and serialize remaining fragments
        let num_fragments = message.message[first_fragment_payload_size..]
            .chunks(follow_on_fragment_payload_size)
            .count();

        iter::once(first_fragment)
            .chain(
                message.message[first_fragment_payload_size..]
                    .chunks(follow_on_fragment_payload_size)
                    .enumerate()
                    .map(|(idx, chunk)| match idx + 1 == num_fragments {
                        true => Self::serialize::<R>(
                            tunnel_id,
                            &MessageKind::LastFragment {
                                message_id: *message_id,
                                sequence_number: idx + 1,
                            }
                            .serialize(),
                            follow_on_fragment_payload_size,
                            chunk,
                            Some(padding),
                        ),
                        false => Self::serialize::<R>(
                            tunnel_id,
                            &MessageKind::MiddleFragment {
                                message_id: *message_id,
                                sequence_number: idx + 1,
                            }
                            .serialize(),
                            chunk.len(),
                            chunk,
                            None,
                        ),
                    }),
            )
            .collect()
    }

    /// Serialize `self` into one or more `TunnelData` messages.
    pub fn build<R: Runtime>(
        mut self,
        padding: &[u8; TUNNEL_DATA_LEN],
    ) -> impl Iterator<Item = Vec<u8>> {
        // message must exist since `TunnelDataBuilder` is called by `emissary`
        let message = self.message.take().expect("message to exist");

        // calculate payload size for the `TunnelData` message
        //
        // if the payload size is >= than `message.message.len()`,
        // the message can be sent an an unfragmented `TunnelData` message
        //
        // if the message is larger than the maximum payload size,
        // the message must be fragmented into multiple `TunnelData` messages
        let delivery_instructions_len = message.message_kind.serialized_len();
        let payload_size = TUNNEL_DATA_LEN
            .saturating_sub(AES256_IV_LEN)
            .saturating_sub(4usize) // tunnel id
            .saturating_sub(delivery_instructions_len)
            .saturating_sub(4usize) // checksum
            .saturating_sub(1usize) // end of padding flag
            .saturating_sub(2usize); // message size

        // if the message size is smaller than what the payload of `TunnelData` can hold,
        // send the message as unfragmented
        if payload_size >= message.message.len() {
            return vec![Self::serialize::<R>(
                self.next_tunnel_id,
                &message.message_kind.serialize(),
                payload_size,
                message.message,
                (payload_size != message.message.len()).then_some(padding),
            )]
            .into_iter();
        }

        Self::serialize_fragmented::<R>(self.next_tunnel_id, message, payload_size, padding)
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    fn find_payload_start(ciphertext: &[u8], iv: &[u8]) -> Option<usize> {
        let padding_end = ciphertext[4..].iter().enumerate().find(|(_, byte)| byte == &&0x0)?;
        let payload_start = padding_end.0 + 1 + 4;

        let checksum = Sha256::new()
            .update(&ciphertext[4 + padding_end.0 + 1..])
            .update(&iv)
            .finalize();

        if ciphertext[..4] != checksum[..4] {
            println!("invalid checksum");
            return None;
        }

        if payload_start >= ciphertext.len() {
            println!("zero byte not found");
        }

        Some(payload_start)
    }

    #[test]
    fn unfragmented_local_delivery() {
        let message = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_local_delivery(&vec![0u8; 512])
            .build::<MockRuntime>(&[0xaa; 1028])
            .next()
            .unwrap();
        assert_eq!(message.len(), TUNNEL_DATA_LEN);

        let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
        let payload = &message[16 + 4 + payload_start..];
        let parsed = TunnelData::parse(&payload).unwrap();
        assert_eq!(parsed.messages.len(), 1);

        match parsed.messages[0].message_kind {
            MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Local,
            } => {}
            _ => panic!("invalid message"),
        }
    }

    #[test]
    fn fragmented_local_delivery_2_fragments() {
        let original = (0..1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_local_delivery(&original)
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|message| message.len() == TUNNEL_DATA_LEN));

        // first fragment
        let mut payload1 = {
            let message = &messages[0];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::FirstFragment {
                    delivery_instructions: DeliveryInstructions::Local,
                    ..
                } => {}
                _ => panic!("invalid message"),
            }

            parsed.messages[0].message.to_vec()
        };

        // last fragment
        let payload2 = {
            let message = &messages[1];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();

            assert_eq!(parsed.messages.len(), 1);
            assert!(std::matches!(
                parsed.messages[0].message_kind,
                MessageKind::LastFragment { .. }
            ));

            parsed.messages[0].message.to_vec()
        };

        // verify reconstructed payload matches the original
        payload1.extend(&payload2);
        assert_eq!(payload1, original);
    }

    #[test]
    fn fragmented_local_delivery_5_fragments() {
        let original = (0..4 * 1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_local_delivery(&original)
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 5);
        assert!(messages.iter().all(|message| message.len() == TUNNEL_DATA_LEN));

        // first fragment
        let mut payload1 = {
            let message = &messages[0];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::FirstFragment {
                    delivery_instructions: DeliveryInstructions::Local,
                    ..
                } => {}
                _ => panic!("invalid message"),
            }

            parsed.messages[0].message.to_vec()
        };

        for i in 1..4 {
            let message = &messages[i];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::MiddleFragment { .. } => {}
                _ => panic!("invalid message"),
            }

            payload1.extend(parsed.messages[0].message);
        }

        // last fragment
        {
            let message = &messages.last().unwrap();

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();

            assert_eq!(parsed.messages.len(), 1);
            assert!(std::matches!(
                parsed.messages[0].message_kind,
                MessageKind::LastFragment { .. }
            ));

            payload1.extend(parsed.messages[0].message);
        }

        assert_eq!(payload1, original);
    }

    #[test]
    fn unfragmented_router_delivery() {
        let router = vec![0xbb; 32];

        let message = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_router_delivery(&router, &vec![0u8; 512])
            .build::<MockRuntime>(&[0xaa; 1028])
            .next()
            .unwrap();
        assert_eq!(message.len(), TUNNEL_DATA_LEN);

        let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
        let payload = &message[16 + 4 + payload_start..];
        let parsed = TunnelData::parse(&payload).unwrap();
        assert_eq!(parsed.messages.len(), 1);

        match parsed.messages[0].message_kind {
            MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Router { hash },
            } => {
                assert_eq!(&hash, &router);
            }
            _ => panic!("invalid message"),
        }
    }

    #[test]
    fn fragmented_router_delivery_2_fragments() {
        let original = (0..1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let router = vec![0xbb; 32];

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_router_delivery(&router, &original)
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|message| message.len() == TUNNEL_DATA_LEN));

        // first fragment
        let mut payload1 = {
            let message = &messages[0];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::FirstFragment {
                    delivery_instructions: DeliveryInstructions::Router { hash },
                    ..
                } => {
                    assert_eq!(hash, router);
                }
                _ => panic!("invalid message"),
            }

            parsed.messages[0].message.to_vec()
        };

        // last fragment
        let payload2 = {
            let message = &messages[1];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();

            assert_eq!(parsed.messages.len(), 1);
            assert!(std::matches!(
                parsed.messages[0].message_kind,
                MessageKind::LastFragment { .. }
            ));

            parsed.messages[0].message.to_vec()
        };

        // verify reconstructed payload matches the original
        payload1.extend(&payload2);
        assert_eq!(payload1, original);
    }

    #[test]
    fn fragmented_router_delivery_5_fragments() {
        let original = (0..4 * 1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let router = vec![0xbb; 32];

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_router_delivery(&router, &original)
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 5);
        assert!(messages.iter().all(|message| message.len() == TUNNEL_DATA_LEN));

        // first fragment
        let mut payload1 = {
            let message = &messages[0];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::FirstFragment {
                    delivery_instructions: DeliveryInstructions::Router { hash },
                    ..
                } => {
                    assert_eq!(router, hash);
                }
                _ => panic!("invalid message"),
            }

            parsed.messages[0].message.to_vec()
        };

        for i in 1..4 {
            let message = &messages[i];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::MiddleFragment { .. } => {}
                _ => panic!("invalid message"),
            }

            payload1.extend(parsed.messages[0].message);
        }

        // last fragment
        {
            let message = &messages.last().unwrap();

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();

            assert_eq!(parsed.messages.len(), 1);
            assert!(std::matches!(
                parsed.messages[0].message_kind,
                MessageKind::LastFragment { .. }
            ));

            payload1.extend(parsed.messages[0].message);
        }

        assert_eq!(payload1, original);
    }

    #[test]
    fn unfragmented_tunnel_delivery() {
        let router = vec![0xbb; 32];
        let tunnel_id = TunnelId::from(0xcafe);

        let message = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_tunnel_delivery(&router, tunnel_id, &vec![0u8; 512])
            .build::<MockRuntime>(&[0xaa; 1028])
            .next()
            .unwrap();
        assert_eq!(message.len(), TUNNEL_DATA_LEN);

        let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
        let payload = &message[16 + 4 + payload_start..];
        let parsed = TunnelData::parse(&payload).unwrap();
        assert_eq!(parsed.messages.len(), 1);

        match parsed.messages[0].message_kind {
            MessageKind::Unfragmented {
                delivery_instructions:
                    DeliveryInstructions::Tunnel {
                        hash,
                        tunnel_id: recv_tunnel,
                    },
            } => {
                assert_eq!(&hash, &router);
                assert_eq!(recv_tunnel, *tunnel_id);
            }
            _ => panic!("invalid message"),
        }
    }

    #[test]
    fn fragmented_tunnel_delivery_2_fragments() {
        let original = (0..1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let router = vec![0xbb; 32];
        let tunnel_id = TunnelId::from(0xcafe);

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_tunnel_delivery(&router, tunnel_id, &original)
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|message| message.len() == TUNNEL_DATA_LEN));

        // first fragment
        let mut payload1 = {
            let message = &messages[0];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::FirstFragment {
                    delivery_instructions:
                        DeliveryInstructions::Tunnel {
                            hash,
                            tunnel_id: recv_tunnel,
                        },
                    ..
                } => {
                    assert_eq!(hash, router);
                    assert_eq!(*tunnel_id, recv_tunnel);
                }
                _ => panic!("invalid message"),
            }

            parsed.messages[0].message.to_vec()
        };

        // last fragment
        let payload2 = {
            let message = &messages[1];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();

            assert_eq!(parsed.messages.len(), 1);
            assert!(std::matches!(
                parsed.messages[0].message_kind,
                MessageKind::LastFragment { .. }
            ));

            parsed.messages[0].message.to_vec()
        };

        // verify reconstructed payload matches the original
        payload1.extend(&payload2);
        assert_eq!(payload1, original);
    }

    #[test]
    fn fragmented_tunnel_delivery_5_fragments() {
        let original = (0..4 * 1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let router = vec![0xbb; 32];
        let tunnel_id = TunnelId::from(0xcafe);

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_tunnel_delivery(&router, tunnel_id, &original)
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 5);
        assert!(messages.iter().all(|message| message.len() == TUNNEL_DATA_LEN));

        // first fragment
        let mut payload1 = {
            let message = &messages[0];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::FirstFragment {
                    delivery_instructions:
                        DeliveryInstructions::Tunnel {
                            hash,
                            tunnel_id: recv_tunnel,
                        },
                    ..
                } => {
                    assert_eq!(router, hash);
                    assert_eq!(*tunnel_id, recv_tunnel);
                }
                _ => panic!("invalid message"),
            }

            parsed.messages[0].message.to_vec()
        };

        for i in 1..4 {
            let message = &messages[i];

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();
            assert_eq!(parsed.messages.len(), 1);

            match parsed.messages[0].message_kind {
                MessageKind::MiddleFragment { .. } => {}
                _ => panic!("invalid message"),
            }

            payload1.extend(parsed.messages[0].message);
        }

        // last fragment
        {
            let message = &messages.last().unwrap();

            let payload_start = find_payload_start(&message[16 + 4..], &message[4..20]).unwrap();
            let payload = &message[16 + 4 + payload_start..];
            let parsed = TunnelData::parse(&payload).unwrap();

            assert_eq!(parsed.messages.len(), 1);
            assert!(std::matches!(
                parsed.messages[0].message_kind,
                MessageKind::LastFragment { .. }
            ));

            payload1.extend(parsed.messages[0].message);
        }

        assert_eq!(payload1, original);
    }

    // user payload consumes the available space to the byte, i.e., no padding and no fragmentation
    #[test]
    fn local_delivery_payload_fits() {
        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_local_delivery(&vec![0u8; 1000])
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].len(), TUNNEL_DATA_LEN);

        let payload_start =
            find_payload_start(&messages[0][16 + 4..], &messages[0][4..20]).unwrap();
        let payload = &messages[0][16 + 4 + payload_start..];
        let parsed = TunnelData::parse(&payload).unwrap();
        assert_eq!(parsed.messages.len(), 1);

        match parsed.messages[0].message_kind {
            MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Local,
            } => {}
            _ => panic!("invalid message"),
        }
    }

    #[test]
    fn router_delivery_payload_fits() {
        let router = vec![0xbb; 32];

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_router_delivery(&router, &vec![0u8; 968])
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].len(), TUNNEL_DATA_LEN);

        let payload_start =
            find_payload_start(&messages[0][16 + 4..], &messages[0][4..20]).unwrap();
        let payload = &messages[0][16 + 4 + payload_start..];
        let parsed = TunnelData::parse(&payload).unwrap();
        assert_eq!(parsed.messages.len(), 1);

        match parsed.messages[0].message_kind {
            MessageKind::Unfragmented {
                delivery_instructions: DeliveryInstructions::Router { hash },
            } => {
                assert_eq!(router, hash);
            }
            _ => panic!("invalid message"),
        }
    }

    #[test]
    fn tunnel_delivery_payload_fits() {
        let router = vec![0xbb; 32];
        let tunnel_id = TunnelId::from(0xcafe);

        let messages = TunnelDataBuilder::new(TunnelId::from(1337))
            .with_tunnel_delivery(&router, tunnel_id, &vec![0u8; 964])
            .build::<MockRuntime>(&[0xaa; 1028])
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].len(), TUNNEL_DATA_LEN);

        let payload_start =
            find_payload_start(&messages[0][16 + 4..], &messages[0][4..20]).unwrap();
        let payload = &messages[0][16 + 4 + payload_start..];
        let parsed = TunnelData::parse(&payload).unwrap();
        assert_eq!(parsed.messages.len(), 1);

        match parsed.messages[0].message_kind {
            MessageKind::Unfragmented {
                delivery_instructions:
                    DeliveryInstructions::Tunnel {
                        hash,
                        tunnel_id: recv_tunnel,
                    },
            } => {
                assert_eq!(router, hash);
                assert_eq!(*tunnel_id, recv_tunnel);
            }
            _ => panic!("invalid message"),
        }
    }
}
