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
    crypto::{
        chachapoly::{ChaCha, ChaChaPoly},
        noise::NoiseContext,
        EphemeralPublicKey, StaticPublicKey,
    },
    runtime::Runtime,
    transport::{ssu2::message::*, TerminationReason},
};

use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

use alloc::{vec, vec::Vec};
use core::net::SocketAddr;

/// Static key size.
const STATIC_KEY_SIZE: usize = 32usize;

/// Minimum size for a packet.
const PKT_MIN_SIZE: usize = 24usize;

/// Builder for `TokenRequest`.
pub struct TokenRequestBuilder {
    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Remote router's intro key.
    intro_key: Option<[u8; 32]>,

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Protocol version.
    version: u8,
}

impl Default for TokenRequestBuilder {
    fn default() -> Self {
        Self {
            dst_id: None,
            intro_key: None,
            net_id: 2u8,
            src_id: None,
            version: 2u8,
        }
    }
}

impl TokenRequestBuilder {
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

    /// Specify version.
    ///
    /// `2` for x25519.
    /// `3` for ML-KEM-512-x25519
    /// `4` for ML-KEM-768-x25519
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Build [`TokenRequestBuilder`] into a byte vector.
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
            out.put_u8(*MessageType::TokenRequest);
            out.put_u8(self.version);
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

/// Unserialized `SessionCreated` message.
pub struct SessionRequest {
    /// Encapsulation key.
    ///
    /// `None` for x25519.
    encapsulation_key: Option<Vec<u8>>,

    /// Serialized, unencrypted header.
    header: BytesMut,

    /// Serialized, unencrypted payload
    payload: Vec<u8>,
}

impl SessionRequest {
    /// Get reference to header.
    pub fn header(&self) -> &[u8] {
        &self.header[..32]
    }

    /// Get reference to payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encrypt payload.
    ///
    /// <https://i2p.net/en/docs/specs/ssu2-hybrid/#alice-kdf-for-message-1>
    pub fn encrypt_payload(&mut self, cipher_key: &[u8], noise_ctx: &mut NoiseContext) {
        let nonce = match self.encapsulation_key.as_mut() {
            None => 0u64,
            Some(encap_key) => {
                ChaChaPoly::with_nonce(cipher_key, 0u64)
                    .encrypt_with_ad_new(noise_ctx.state(), encap_key)
                    .expect("to succeed");

                // MixHash(ciphertext)
                noise_ctx.mix_hash(&encap_key);

                1u64
            }
        };

        // must succeed since all the parameters are controlled by us
        ChaChaPoly::with_nonce(cipher_key, nonce)
            .encrypt_with_ad_new(noise_ctx.state(), &mut self.payload)
            .expect("to succeed");
    }

    /// Encrypt header.
    pub fn encrypt_header(&mut self, k_header_1: [u8; 32], k_header_2: [u8; 32]) {
        // encrypt first 16 bytes of the long header
        //
        // https://geti2p.net/spec/ssu2#header-encryption-kdf
        self.payload[self.payload.len() - 2 * IV_SIZE..]
            .chunks(IV_SIZE)
            .zip(self.header.chunks_mut(8usize))
            .zip([k_header_1, k_header_2])
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

        // encrypt last 16 bytes of the header and the public key
        ChaCha::with_iv(k_header_2, [0u8; IV_SIZE]).encrypt_ref(&mut self.header[16..64]);
    }

    /// Serialize [`SessionRequest`] into a byte vector.
    pub fn build(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(
            self.header.len()
                + self.payload.len()
                + self.encapsulation_key.as_ref().map_or(0, |c| c.len()),
        );
        out.put_slice(&self.header);
        if let Some(encap_key) = self.encapsulation_key {
            out.put_slice(&encap_key);
        }
        out.put_slice(&self.payload);

        out
    }
}

/// Builder for `SessionRequest`.
pub struct SessionRequestBuilder {
    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Encapsulation key.
    ///
    /// `None` for x25519.
    encapsulation_key: Option<Vec<u8>>,

    /// Local ephemeral public key.
    ephemeral_key: Option<EphemeralPublicKey>,

    /// Maximum payload size.
    max_payload_size: usize,

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Should relay tag be requested.
    request_tag: bool,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Token.
    token: Option<u64>,

    /// Protocol version.
    version: u8,
}

impl Default for SessionRequestBuilder {
    fn default() -> Self {
        Self {
            dst_id: None,
            encapsulation_key: None,
            ephemeral_key: None,
            max_payload_size: 1472,
            net_id: 2u8,
            request_tag: false,
            src_id: None,
            token: None,
            version: 2u8,
        }
    }
}

impl SessionRequestBuilder {
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

    /// Specify token.
    pub fn with_token(mut self, token: u64) -> Self {
        self.token = Some(token);
        self
    }

    /// Specify local ephemeral public key.
    pub fn with_ephemeral_key(mut self, ephemeral_key: EphemeralPublicKey) -> Self {
        self.ephemeral_key = Some(ephemeral_key);
        self
    }

    /// Specify whether relay tag should be requested.
    pub fn with_relay_tag_request(mut self, request_tag: bool) -> Self {
        self.request_tag = request_tag;
        self
    }

    /// Specify network ID.
    pub fn with_net_id(mut self, net_id: u8) -> Self {
        self.net_id = net_id;
        self
    }

    /// Specify ML-KEM encapsulation key.
    pub fn with_encapsulation_key(mut self, encap_key: Option<Vec<u8>>) -> Self {
        self.encapsulation_key = encap_key;
        self
    }

    /// Specify protocol version.
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Specify maximum payload size.
    pub fn with_max_payload_size(mut self, max_payload_size: usize) -> Self {
        self.max_payload_size = max_payload_size;
        self
    }

    /// Build [`SessionRequestBuilder`] into [`SessionRequest`].
    pub fn build<R: Runtime>(mut self) -> SessionRequest {
        let mut rng = R::rng();
        let header = {
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN + PUBLIC_KEY_LEN);

            out.put_u64_le(self.dst_id.take().expect("to exist"));
            out.put_u32(rng.next_u32());
            out.put_u8(*MessageType::SessionRequest);
            out.put_u8(self.version);
            out.put_u8(self.net_id);
            out.put_u8(0u8); // flag
            out.put_u64_le(self.src_id.take().expect("to exist"));
            out.put_u64_le(self.token.take().expect("to exist"));
            out.put_slice(self.ephemeral_key.take().expect("to exist").as_ref());

            out
        };

        // padding must not exceed maximum payload size which depends on encryption and ip types
        //
        // the encrypted payload must be at least `2 * IV_SIZE` bytes so that header encryption
        // has two IVs to derive from the payload
        let padding = {
            let bytes_left = self
                .max_payload_size
                .saturating_sub(header.len())
                .saturating_sub(self.encapsulation_key.as_ref().map_or(0, |c| c.len()))
                .saturating_sub(10 + POLY13055_MAC_LEN);

            let padding_len = rng.next_u32() % MAX_PADDING as u32 + 16;
            let mut padding = vec![0u8; (padding_len as usize).min(bytes_left).max(1usize)];
            rng.fill_bytes(&mut padding);

            padding
        };

        let mut payload = Vec::with_capacity(10 + padding.len() + POLY13055_MAC_LEN);
        payload.extend_from_slice(
            &Block::DateTime {
                timestamp: R::time_since_epoch().as_secs() as u32,
            }
            .serialize(),
        );

        if self.request_tag {
            payload.extend_from_slice(&Block::RelayTagRequest.serialize());
        }

        if !padding.is_empty() {
            payload.extend_from_slice(&Block::Padding { padding }.serialize());
        }

        SessionRequest {
            encapsulation_key: self.encapsulation_key,
            header,
            payload,
        }
    }
}

/// Unserialized `SessionConfirmed` message.
pub struct SessionConfirmed {
    /// Destination connection ID.
    dst_id: u64,

    /// Serialized, unencrypted header.
    header: BytesMut,

    /// Maximum payload size.
    max_payload_size: usize,

    /// Serialized, unecrypted payload.
    payload: Vec<u8>,

    /// Serialized, unencrypted static key.
    static_key: Vec<u8>,
}

impl SessionConfirmed {
    /// Get reference to header.
    pub fn header(&self) -> &[u8] {
        &self.header[..16]
    }

    /// Get reference to public key.
    pub fn public_key(&self) -> &[u8] {
        &self.static_key
    }

    /// Encrypt public key.
    pub fn encrypt_public_key(&mut self, cipher_key: &[u8], nonce: u64, state: &[u8]) {
        // must succeed as the parameters are controlled by us
        ChaChaPoly::with_nonce(cipher_key, nonce)
            .encrypt_with_ad_new(state, &mut self.static_key)
            .expect("to succeed");
    }

    /// Encrypt payload.
    pub fn encrypt_payload(&mut self, cipher_key: &[u8], nonce: u64, state: &[u8]) {
        // must succeed as the parameters are controlled by us
        ChaChaPoly::with_nonce(cipher_key, nonce)
            .encrypt_with_ad_new(state, &mut self.payload)
            .expect("to succeed");
    }

    // Encrypt 16-byte short header
    //
    // https://geti2p.net/spec/ssu2#header-encryption-kdf
    fn encrypt_header(
        k_header_1: [u8; 32],
        k_header_2: [u8; 32],
        header: &mut [u8],
        payload: &[u8],
    ) {
        payload[payload.len() - 2 * IV_SIZE..]
            .chunks(IV_SIZE)
            .zip(header.chunks_mut(8usize))
            .zip([k_header_1, k_header_2])
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
    }

    /// Serialize [`SessionConfirmed`] into a byte vector.
    ///
    /// If `SessionConfirmed` is too large to fit into a single UDP datagram, the
    /// packet is fragmented into multiple packets.
    ///
    /// <https://i2p.net/en/docs/specs/ssu2/#session-confirmed-fragmentation>
    pub fn build(mut self, k_header_1: [u8; 32], k_header_2: [u8; 32]) -> Vec<Vec<u8>> {
        let max_pkt_size = self.max_payload_size - SHORT_HEADER_LEN;

        // SessionConfirmed fits inside a single datagram
        if self.payload.len() + self.static_key.len() <= max_pkt_size {
            Self::encrypt_header(k_header_1, k_header_2, &mut self.header, &self.payload);

            let mut out = BytesMut::with_capacity(
                self.header.len() + self.static_key.len() + self.payload.len(),
            );

            out.put_slice(&self.header);
            out.put_slice(&self.static_key);
            out.put_slice(&self.payload);

            return vec![out.to_vec()];
        }

        // create jumbo packet
        let mut out = BytesMut::with_capacity(self.static_key.len() + self.payload.len());
        out.put_slice(&self.static_key);
        out.put_slice(&self.payload);

        // calculate total number of fragments
        let num_fragments = {
            let num_fragments = out.len() / max_pkt_size;

            if num_fragments.is_multiple_of(max_pkt_size) {
                num_fragments as u8
            } else {
                num_fragments as u8 + 1
            }
        };
        debug_assert!(num_fragments <= 15);

        out.chunks(max_pkt_size)
            .enumerate()
            .map(|(i, fragment)| {
                debug_assert!(fragment.len() >= 24);

                let mut pkt = BytesMut::with_capacity(SHORT_HEADER_LEN + fragment.len());

                pkt.put_u64_le(self.dst_id);
                pkt.put_u32(0u32); // packet number, always 0
                pkt.put_u8(*MessageType::SessionConfirmed);
                pkt.put_u8(((i as u8) << 4) | num_fragments);
                pkt.put_u16(0u16); // flags
                pkt.put_slice(fragment);

                Self::encrypt_header(k_header_1, k_header_2, &mut pkt[..16], fragment);

                pkt.to_vec()
            })
            .collect()
    }
}

/// `SessionConfirmed` builder.
pub struct SessionConfirmedBuilder {
    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Maximum payload size.
    max_payload_size: usize,

    /// Serialized local router info.
    router_info: Option<Bytes>,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Local static public key.
    static_key: Option<StaticPublicKey>,
}

impl Default for SessionConfirmedBuilder {
    fn default() -> Self {
        Self {
            dst_id: None,
            max_payload_size: 1472,
            router_info: None,
            src_id: None,
            static_key: None,
        }
    }
}

impl SessionConfirmedBuilder {
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

    /// Specify maximum payload size.
    pub fn with_max_payload_size(mut self, max_payload_size: usize) -> Self {
        self.max_payload_size = max_payload_size;
        self
    }

    /// Specify router info.
    pub fn with_router_info(mut self, router_info: Bytes) -> Self {
        self.router_info = Some(router_info);
        self
    }

    /// Specify local static public key.
    pub fn with_static_key(mut self, static_key: StaticPublicKey) -> Self {
        self.static_key = Some(static_key);
        self
    }

    /// Build [`SessionConfirmedBuilder`] into a byte vector.
    pub fn build<R: Runtime>(mut self) -> SessionConfirmed {
        let router_info = self.router_info.expect("to exist");
        let dst_id = self.dst_id.take().expect("to exist");
        let max_pkt_size = self.max_payload_size - SHORT_HEADER_LEN;

        let static_key = self.static_key.expect("to exist").to_vec();
        let mut payload = {
            let mut out = BytesMut::with_capacity(5 + router_info.len());

            out.put_u8(BlockType::RouterInfo.as_u8());
            out.put_u16((2 + router_info.len()) as u16);
            out.put_u8(0u8);
            out.put_u8(1u8);
            out.put_slice(&router_info);

            out
        };

        // check if `SessionConfirmed` needs to be fragmented
        //
        // if so, calculate how many fragments are needed and if the last fragment
        // is less than 24 bytes, add a padding block to make the fragment large eough
        //
        // https://i2p.net/en/docs/specs/ssu2/#session-confirmed-fragmentation
        let pkt_size = router_info.len() + STATIC_KEY_SIZE + 2 * POLY13055_MAC_LEN;

        let num_fragments = if pkt_size > max_pkt_size {
            let mut num_fragments = pkt_size / max_pkt_size;

            if !num_fragments.is_multiple_of(max_pkt_size) {
                num_fragments += 1;
            }

            // add padding if necessary
            if pkt_size % max_pkt_size < PKT_MIN_SIZE {
                let padding = {
                    let mut padding =
                        vec![0u8; (R::rng().next_u32() % 64 + PKT_MIN_SIZE as u32) as usize];
                    R::rng().fill_bytes(&mut padding);

                    padding
                };
                payload.put_u8(BlockType::Padding.as_u8());
                payload.put_u16(padding.len() as u16);
                payload.put_slice(&padding);
            }

            num_fragments
        } else {
            1
        };

        let header = {
            let mut out = BytesMut::with_capacity(SHORT_HEADER_LEN);

            out.put_u64_le(dst_id);
            out.put_u32(0u32);
            out.put_u8(*MessageType::SessionConfirmed);
            out.put_u8(num_fragments as u8); // fragment count + number
            out.put_u16(0u16); // flags

            out
        };

        SessionConfirmed {
            dst_id,
            header,
            max_payload_size: self.max_payload_size,
            payload: payload.to_vec(),
            static_key,
        }
    }
}

/// Builder for `Retry`.
pub struct RetryBuilder {
    /// Remote's socket address.
    address: Option<SocketAddr>,

    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Remote's intro key.
    k_header_1: Option<[u8; 32]>,

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Termination reason.
    termination: Option<TerminationReason>,

    /// Token.
    token: Option<u64>,

    /// Protocol version.
    version: u8,
}

impl Default for RetryBuilder {
    fn default() -> Self {
        Self {
            address: None,
            dst_id: None,
            k_header_1: None,
            net_id: 2u8,
            src_id: None,
            termination: None,
            token: None,
            version: 2u8,
        }
    }
}

impl RetryBuilder {
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
    pub fn with_k_header_1(mut self, k_header_1: [u8; 32]) -> Self {
        self.k_header_1 = Some(k_header_1);
        self
    }

    /// Specify token.
    pub fn with_token(mut self, token: u64) -> Self {
        self.token = Some(token);
        self
    }

    /// Specify remote socket address.
    pub fn with_address(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    /// Specify termination reason.
    pub fn with_termination(mut self, termination: TerminationReason) -> Self {
        self.termination = Some(termination);
        self
    }

    /// Specify network ID.
    pub fn with_net_id(mut self, net_id: u8) -> Self {
        self.net_id = net_id;
        self
    }

    /// Specify protocol version.
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Build [`Retry`] into a byte vector.
    pub fn build<R: Runtime>(self) -> BytesMut {
        let (mut header, pkt_num) = {
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN);
            let pkt_num = R::rng().next_u32();

            out.put_u64_le(self.dst_id.expect("to exist"));
            out.put_u32(pkt_num);
            out.put_u8(*MessageType::Retry);
            out.put_u8(self.version);
            out.put_u8(self.net_id);
            out.put_u8(0u8);
            out.put_u64_le(self.src_id.expect("to exist"));
            out.put_u64_le(self.token.expect("to exist"));

            (out, pkt_num)
        };
        let padding = {
            let padding_len = R::rng().next_u32() as usize % MAX_PADDING + 1;
            let mut padding = vec![0u8; padding_len];
            R::rng().fill_bytes(&mut padding);

            padding
        };
        // TODO: this is confusing, fix
        let payload_size = 3 * 3
            + 4
            + 6
            + padding.len()
            + POLY13055_MAC_LEN
            + self.termination.as_ref().map_or(0, |_| TERMINATION_MIN_SIZE as usize);
        let k_header_1 = self.k_header_1.expect("to exist");

        let mut payload = if let Some(reason) = self.termination {
            vec![
                Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                },
                Block::Address {
                    address: self.address.expect("to exist"),
                },
                Block::Termination {
                    num_valid_pkts: 0,
                    reason: reason.from_ssu2(),
                },
                Block::Padding { padding },
            ]
        } else {
            vec![
                Block::DateTime {
                    timestamp: R::time_since_epoch().as_secs() as u32,
                },
                Block::Address {
                    address: self.address.expect("to exist"),
                },
                Block::Padding { padding },
            ]
        }
        .into_iter()
        .fold(BytesMut::with_capacity(payload_size), |mut out, block| {
            out.put_slice(&block.serialize());
            out
        })
        .to_vec();

        // expected to succeed since the parameters are controlled by us
        ChaChaPoly::with_nonce(&k_header_1, pkt_num as u64)
            .encrypt_with_ad_new(&header, &mut payload)
            .expect("to succeed");

        // encrypt first 16 bytes of the long header
        //
        // https://geti2p.net/spec/ssu2#header-encryption-kdf
        payload[payload.len() - 2 * IV_SIZE..]
            .chunks(IV_SIZE)
            .zip(header.chunks_mut(8usize))
            .zip([k_header_1, k_header_1])
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

        // encrypt third part of the header
        ChaCha::with_iv(k_header_1, [0u8; IV_SIZE]).encrypt_ref(&mut header[16..32]);

        let mut out = BytesMut::with_capacity(header.len() + payload.len());
        out.put_slice(&header);
        out.put_slice(&payload);

        out
    }
}

/// Unserialized `SessionCreated` message.
pub struct SessionCreated {
    /// Serialized, unencrypted header.
    header: BytesMut,

    /// KEM ciphertext.
    ///
    /// `None` for x25519.
    kem_ciphertext: Option<Vec<u8>>,

    /// Serialized, unencrypted payload
    payload: Vec<u8>,
}

impl SessionCreated {
    /// Get reference to payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encrypt header.
    pub fn encrypt_header(&mut self, k_header_1: [u8; 32], k_header_2: [u8; 32]) {
        // encrypt first 16 bytes of the long header
        //
        // https://geti2p.net/spec/ssu2#header-encryption-kdf
        self.payload[self.payload.len() - 2 * IV_SIZE..]
            .chunks(IV_SIZE)
            .zip(self.header.chunks_mut(8usize))
            .zip([k_header_1, k_header_2])
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

        ChaCha::with_iv(k_header_2, [0u8; IV_SIZE]).encrypt_ref(&mut self.header[16..64]);
    }

    /// Encrypt payload.
    pub fn encrypt_payload(&mut self, cipher_key: &[u8], nonce: u64, state: &[u8]) {
        // expected to succeed as the parameters are controlled by us
        ChaChaPoly::with_nonce(cipher_key, nonce)
            .encrypt_with_ad_new(state, &mut self.payload)
            .expect("to succeed");
    }

    /// Serialize `SessionCreated` into a byte vector.
    pub fn build(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(
            self.header.len()
                + self.payload.len()
                + self.kem_ciphertext.as_ref().map_or(0, |c| c.len()),
        );

        out.put_slice(&self.header);
        if let Some(kem_ciphertext) = self.kem_ciphertext {
            out.put_slice(&kem_ciphertext);
        }
        out.put_slice(&self.payload);

        out
    }
}

/// Builder for `SessionCreated`.
pub struct SessionCreatedBuilder {
    /// Remote router's address.
    address: Option<SocketAddr>,

    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Our ephemeral public key.
    ephemeral_key: Option<EphemeralPublicKey>,

    /// Header for the message.
    ///
    /// `None` if not yet built.
    header: Option<BytesMut>,

    /// KEM ciphertext.
    ///
    /// `None` for x25519.
    kem_ciphertext: Option<Vec<u8>>,

    /// Maximum payload size.
    max_payload_size: usize,

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Optional relay tag, if requested by remote router.
    relay_tag: Option<u32>,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Protocol version.
    version: u8,
}

impl Default for SessionCreatedBuilder {
    fn default() -> Self {
        Self {
            address: None,
            dst_id: None,
            ephemeral_key: None,
            header: None,
            kem_ciphertext: None,
            max_payload_size: 1472,
            net_id: 2u8,
            relay_tag: None,
            src_id: None,
            version: 2u8,
        }
    }
}

impl SessionCreatedBuilder {
    /// Specify remote's socket address.
    pub fn with_address(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    /// Specify destination connection ID.
    pub fn with_dst_id(mut self, dst_id: u64) -> Self {
        self.dst_id = Some(dst_id);
        self
    }

    /// Specify local ephemeral public key.
    pub fn with_ephemeral_key(mut self, ephemeral_key: EphemeralPublicKey) -> Self {
        self.ephemeral_key = Some(ephemeral_key);
        self
    }

    /// Specify source connection ID.
    pub fn with_src_id(mut self, src_id: u64) -> Self {
        self.src_id = Some(src_id);
        self
    }

    /// Specify network ID.
    pub fn with_net_id(mut self, net_id: u8) -> Self {
        self.net_id = net_id;
        self
    }

    /// Specify relay tag.
    pub fn with_relay_tag(mut self, relay_tag: u32) -> Self {
        self.relay_tag = Some(relay_tag);
        self
    }

    /// Specify protocol version.
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Add optional KEM ciphertext.
    pub fn with_kem_ciphertext(mut self, kem_ciphertext: Vec<u8>) -> Self {
        self.kem_ciphertext = Some(kem_ciphertext);
        self
    }

    /// Specify maximum payload size.
    pub fn with_max_payload_size(mut self, max_payload_size: usize) -> Self {
        self.max_payload_size = max_payload_size;
        self
    }

    /// Build header for the `SessionCreated` message.
    pub fn build_header<R: Runtime>(mut self) -> Self {
        self.header = Some({
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN);

            out.put_u64_le(self.dst_id.expect("to exist"));
            out.put_u32(R::rng().next_u32());
            out.put_u8(*MessageType::SessionCreated);
            out.put_u8(self.version);
            out.put_u8(self.net_id);
            out.put_u8(0u8);
            out.put_u64_le(self.src_id.expect("to exist"));
            out.put_u64(0u64);
            out.put_slice(self.ephemeral_key.take().expect("to exist").as_ref());

            out
        });

        self
    }

    /// Get header for the `SessionCreated` message
    ///
    /// Panics if `SessionCreatedBuilder::build_header()` has not been called.
    pub fn header(&self) -> &[u8] {
        &self.header.as_ref().expect("header to exist")[..32]
    }

    /// Build [`SessionCreatedBuilder`] into [`SessionCreated`] by creating a long header
    /// and a payload with needed blocks.
    ///
    /// This function doesn't return a serialized `SessionCreated` message as the caller needs to
    /// encrypt the payload with "non-static" key/state which future encryption/decryption is
    /// depended on.
    pub fn build<R: Runtime>(mut self) -> SessionCreated {
        let address = self.address.expect("address to exist");
        // TODO: still ugly
        let mut payload_size = 7usize // date time
         + match address {
             SocketAddr::V4(_) => 9usize,
             SocketAddr::V6(_) => 21usize,
         }
         + POLY13055_MAC_LEN
         + self.relay_tag.map_or(0, |_| 7);

        // padding must not exceed maximum payload size which depends on encryption and ip types
        let padding = {
            let bytes_left = self
                .max_payload_size
                .saturating_sub(64) // header + public key
                .saturating_sub(self.kem_ciphertext.as_ref().map_or(0, |c| c.len()))
                .saturating_sub(payload_size);

            if bytes_left == 0 {
                vec![]
            } else {
                let mut rng = R::rng();
                let padding_len = rng.next_u32() % MAX_PADDING as u32 + 16;
                let mut padding = vec![0u8; (padding_len as usize).min(bytes_left)];
                rng.fill_bytes(&mut padding);

                payload_size += padding.len();
                padding
            }
        };

        let mut blocks = vec![
            Block::DateTime {
                timestamp: R::time_since_epoch().as_secs() as u32,
            },
            Block::Address {
                address: self.address.expect("to exist"),
            },
        ];

        if let Some(relay_tag) = self.relay_tag {
            blocks.push(Block::RelayTag { relay_tag });
        }

        if !padding.is_empty() {
            blocks.push(Block::Padding { padding });
        }

        let payload = blocks
            .into_iter()
            .fold(BytesMut::with_capacity(payload_size), |mut out, block| {
                out.put_slice(&block.serialize());
                out
            })
            .to_vec();

        SessionCreated {
            header: self.header.take().expect("to exist"),
            payload,
            kem_ciphertext: self.kem_ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base64_encode, noise::NoiseContext, EphemeralPrivateKey, StaticPrivateKey},
        primitives::{RouterInfoBuilder, Str},
        runtime::mock::MockRuntime,
    };

    #[test]
    fn token_request_custom_net_id() {
        // no network id specified
        {
            let mut pkt = TokenRequestBuilder::default()
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_intro_key([1u8; 32])
                .build::<MockRuntime>()
                .to_vec();

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::TokenRequest { net_id, .. } => {
                    assert_eq!(net_id, 2);
                }
                _ => panic!("invalid message"),
            }
        }

        // custom network id
        {
            let mut pkt = TokenRequestBuilder::default()
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_net_id(13)
                .with_intro_key([1u8; 32])
                .build::<MockRuntime>()
                .to_vec();

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::TokenRequest { net_id, .. } => {
                    assert_eq!(net_id, 13);
                }
                _ => panic!("invalid message"),
            }
        }
    }

    #[test]
    fn session_request_custom_net_id() {
        // no network id specified
        {
            let mut pkt = {
                let mut pkt = SessionRequestBuilder::default()
                    .with_dst_id(1337)
                    .with_src_id(1338)
                    .with_ephemeral_key(EphemeralPrivateKey::random(MockRuntime::rng()).public())
                    .with_token(1339)
                    .build::<MockRuntime>();

                pkt.encrypt_header([1u8; 32], [1u8; 32]);
                pkt.build().to_vec()
            };

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::SessionRequest { net_id, .. } => {
                    assert_eq!(net_id, 2);
                }
                _ => panic!("invalid message"),
            }
        }

        // custom network id
        {
            let mut pkt = {
                let mut pkt = SessionRequestBuilder::default()
                    .with_dst_id(1337)
                    .with_src_id(1338)
                    .with_net_id(13)
                    .with_ephemeral_key(EphemeralPrivateKey::random(MockRuntime::rng()).public())
                    .with_token(1339)
                    .build::<MockRuntime>();

                pkt.encrypt_header([1u8; 32], [1u8; 32]);
                pkt.build().to_vec()
            };

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::SessionRequest { net_id, .. } => {
                    assert_eq!(net_id, 13);
                }
                _ => panic!("invalid message"),
            }
        }
    }

    #[test]
    fn session_request_small_max_payload_size() {
        let mut message = SessionRequestBuilder::default()
            .with_max_payload_size(80)
            .with_dst_id(1337)
            .with_src_id(1338)
            .with_ephemeral_key(EphemeralPrivateKey::random(MockRuntime::rng()).public())
            .with_token(1339)
            .build::<MockRuntime>();

        let mut noise_ctx = NoiseContext::new([0xaa; 32], [0xbb; 32]);
        message.encrypt_payload(&[0xcc; 32], &mut noise_ctx);

        message.encrypt_header([1u8; 32], [1u8; 32]);
        let _ = message.build();
    }

    #[test]
    fn retry_custom_net_id() {
        // no network id specified
        {
            let mut pkt = RetryBuilder::default()
                .with_k_header_1([1u8; 32])
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_token(1339)
                .with_address("127.0.0.1:8888".parse().unwrap())
                .build::<MockRuntime>();

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::Retry { net_id, .. } => {
                    assert_eq!(net_id, 2);
                }
                _ => panic!("invalid message"),
            }
        }

        // custom network id
        {
            let mut pkt = RetryBuilder::default()
                .with_k_header_1([1u8; 32])
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_token(1339)
                .with_net_id(13)
                .with_address("127.0.0.1:8888".parse().unwrap())
                .build::<MockRuntime>();

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::Retry { net_id, .. } => {
                    assert_eq!(net_id, 13);
                }
                _ => panic!("invalid message"),
            }
        }
    }

    #[test]
    fn session_created_custom_net_id() {
        // no network id specified
        {
            let mut pkt = {
                let mut pkt = SessionCreatedBuilder::default()
                    .with_address("127.0.0.1:8888".parse().unwrap())
                    .with_dst_id(1337)
                    .with_src_id(1338)
                    .with_ephemeral_key(EphemeralPrivateKey::random(MockRuntime::rng()).public())
                    .build_header::<MockRuntime>()
                    .build::<MockRuntime>();

                pkt.encrypt_payload(&[1u8; 32], 1337, &[0u8; 32]);
                pkt.encrypt_header([1u8; 32], [1u8; 32]);
                pkt.build().to_vec()
            };

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::SessionCreated { net_id, .. } => {
                    assert_eq!(net_id, 2);
                }
                _ => panic!("invalid message"),
            }
        }

        // custom network id
        {
            let mut pkt = {
                let mut pkt = SessionCreatedBuilder::default()
                    .with_address("127.0.0.1:8888".parse().unwrap())
                    .with_dst_id(1337)
                    .with_src_id(1338)
                    .with_net_id(13)
                    .with_ephemeral_key(EphemeralPrivateKey::random(MockRuntime::rng()).public())
                    .build_header::<MockRuntime>()
                    .build::<MockRuntime>();

                pkt.encrypt_payload(&[1u8; 32], 1337, &[0u8; 32]);
                pkt.encrypt_header([1u8; 32], [1u8; 32]);
                pkt.build().to_vec()
            };

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([1u8; 32]).unwrap() {
                HeaderKind::SessionCreated { net_id, .. } => {
                    assert_eq!(net_id, 13);
                }
                _ => panic!("invalid message"),
            }
        }
    }

    #[test]
    fn fragmented_session_confirmed_ipv4() {
        fragmented_session_confirmed(1472);
    }

    #[test]
    fn fragmented_session_confirmed_ipv6() {
        fragmented_session_confirmed(1452);
    }

    fn fragmented_session_confirmed(mtu: usize) {
        let local_static_key = StaticPrivateKey::random(&mut MockRuntime::rng());
        let remote_ephemeral_key = EphemeralPrivateKey::random(&mut MockRuntime::rng());
        let mut noise_ctx = NoiseContext::new([0xaa; 32], [0xbb; 32]);
        let cipher_key = [0xcc; 32];
        let remote_intro_key = [0xdd; 32];
        let k_header_2 = [0xdd; 32];
        let (mut router_info, _, signing_key) = RouterInfoBuilder::default().build();
        for i in 0..10 {
            router_info.options.insert(
                Str::from(format!("garbage{i}")),
                Str::from(base64_encode(vec![0xaa; 128])),
            );
        }
        assert!(router_info.serialize(&signing_key).len() > 1500);

        let (encrypted, pubkey_state, payload_state, payload_cipher_key) = {
            let mut message = SessionConfirmedBuilder::default()
                .with_max_payload_size(mtu)
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_static_key(local_static_key.public())
                .with_router_info(Bytes::from(router_info.serialize(&signing_key)))
                .build::<MockRuntime>();

            // MixHash(header) & encrypt public key
            noise_ctx.mix_hash(message.header());
            message.encrypt_public_key(&cipher_key, 1u64, noise_ctx.state());
            let pubkey_state = noise_ctx.state().to_vec();

            // MixHash(apk)
            noise_ctx.mix_hash(message.public_key());

            let payload_cipher_key =
                noise_ctx.mix_key(&local_static_key, &remote_ephemeral_key.public());

            message.encrypt_payload(&payload_cipher_key, 0u64, noise_ctx.state());
            let payload_state = noise_ctx.state().to_vec();

            (
                message.build(remote_intro_key, k_header_2).to_vec(),
                pubkey_state,
                payload_state,
                payload_cipher_key,
            )
        };
        assert_eq!(encrypted.len(), 2);
        assert!(encrypted.iter().all(|pkt| pkt.len() <= mtu));

        let mut reassembled = Vec::<u8>::new();

        for (i, mut fragment) in encrypted.into_iter().enumerate() {
            let mut reader = HeaderReader::new(remote_intro_key, &mut fragment).unwrap();
            let _dst_id = reader.dst_id();

            match reader.parse(k_header_2).unwrap() {
                HeaderKind::SessionConfirmed {
                    fragment,
                    num_fragments,
                    ..
                } => {
                    assert_eq!(fragment, i);
                    assert_eq!(num_fragments, 2);
                }
                _ => panic!("unexpected message"),
            }

            if i == 0 {
                reassembled.extend(fragment)
            } else {
                reassembled.extend(&fragment[16..]);
            }
        }

        let mut static_key = reassembled[16..64].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 1u64)
            .decrypt_with_ad(&pubkey_state, &mut static_key)
            .unwrap();

        // decrypt payload
        let mut payload = reassembled[64..].to_vec();
        ChaChaPoly::with_nonce(&payload_cipher_key, 0u64)
            .decrypt_with_ad(&payload_state, &mut payload)
            .unwrap();

        assert!(Block::parse::<MockRuntime>(&payload).is_ok());
    }

    #[test]
    fn fragmented_session_confirmed_multiple_fragments_ipv4() {
        fragmented_session_confirmed_multiple_fragments(1472);
    }

    #[test]
    fn fragmented_session_confirmed_multiple_fragments_ipv6() {
        fragmented_session_confirmed_multiple_fragments(1452);
    }

    fn fragmented_session_confirmed_multiple_fragments(mtu: usize) {
        let local_static_key = StaticPrivateKey::random(&mut MockRuntime::rng());
        let remote_ephemeral_key = EphemeralPrivateKey::random(&mut MockRuntime::rng());
        let mut noise_ctx = NoiseContext::new([0xaa; 32], [0xbb; 32]);
        let cipher_key = [0xcc; 32];
        let remote_intro_key = [0xdd; 32];
        let k_header_2 = [0xdd; 32];
        let (mut router_info, _, signing_key) = RouterInfoBuilder::default().build();
        for i in 0..20 {
            router_info.options.insert(
                Str::from(format!("garbage{i}")),
                Str::from(base64_encode(vec![0xaa; 128])),
            );
        }
        assert!(router_info.serialize(&signing_key).len() > 1500);

        let (encrypted, pubkey_state, payload_state, payload_cipher_key) = {
            let mut message = SessionConfirmedBuilder::default()
                .with_max_payload_size(mtu)
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_static_key(local_static_key.public())
                .with_router_info(Bytes::from(router_info.serialize(&signing_key)))
                .build::<MockRuntime>();

            // MixHash(header) & encrypt public key
            noise_ctx.mix_hash(message.header());
            message.encrypt_public_key(&cipher_key, 1u64, noise_ctx.state());
            let pubkey_state = noise_ctx.state().to_vec();

            // MixHash(apk)
            noise_ctx.mix_hash(message.public_key());

            let payload_cipher_key =
                noise_ctx.mix_key(&local_static_key, &remote_ephemeral_key.public());

            message.encrypt_payload(&payload_cipher_key, 0u64, noise_ctx.state());
            let payload_state = noise_ctx.state().to_vec();

            (
                message.build(remote_intro_key, k_header_2).to_vec(),
                pubkey_state,
                payload_state,
                payload_cipher_key,
            )
        };
        assert_eq!(encrypted.len(), 4);
        assert!(encrypted.iter().all(|pkt| pkt.len() <= mtu));

        let mut reassembled = Vec::<u8>::new();

        for (i, mut fragment) in encrypted.into_iter().enumerate() {
            let mut reader = HeaderReader::new(remote_intro_key, &mut fragment).unwrap();
            let _dst_id = reader.dst_id();

            match reader.parse(k_header_2).unwrap() {
                HeaderKind::SessionConfirmed {
                    fragment,
                    num_fragments,
                    ..
                } => {
                    assert_eq!(fragment, i);
                    assert_eq!(num_fragments, 4);
                }
                _ => panic!("unexpected message"),
            }

            if i == 0 {
                reassembled.extend(fragment)
            } else {
                reassembled.extend(&fragment[16..]);
            }
        }

        let mut static_key = reassembled[16..64].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 1u64)
            .decrypt_with_ad(&pubkey_state, &mut static_key)
            .unwrap();

        // decrypt payload
        let mut payload = reassembled[64..].to_vec();
        ChaChaPoly::with_nonce(&payload_cipher_key, 0u64)
            .decrypt_with_ad(&payload_state, &mut payload)
            .unwrap();

        assert!(Block::parse::<MockRuntime>(&payload).is_ok());
    }

    #[test]
    fn fragmented_session_confirmed_with_padding_ipv4() {
        fragmented_session_confirmed_with_padding(1472, 25, 2);
    }

    #[test]
    fn fragmented_session_confirmed_with_padding_ipv6() {
        fragmented_session_confirmed_with_padding(1452, 74, 3);
    }

    fn fragmented_session_confirmed_with_padding(mtu: usize, num_iters: usize, num_frags: usize) {
        let local_static_key = StaticPrivateKey::random(&mut MockRuntime::rng());
        let remote_ephemeral_key = EphemeralPrivateKey::random(&mut MockRuntime::rng());
        let mut noise_ctx = NoiseContext::new([0xaa; 32], [0xbb; 32]);
        let cipher_key = [0xcc; 32];
        let remote_intro_key = [0xdd; 32];
        let k_header_2 = [0xdd; 32];
        let (mut router_info, _, signing_key) = RouterInfoBuilder::default().build();
        for i in 0..=num_iters {
            router_info.options.insert(
                Str::from(format!("garbage{i}")),
                Str::from(base64_encode(vec![0xaa; 10])),
            );
        }
        router_info.options.insert(Str::from("test"), Str::from("test"));

        // verify that the last fragment is too short
        assert!(
            (STATIC_KEY_SIZE + 2 * POLY13055_MAC_LEN + router_info.serialize(&signing_key).len())
                % (mtu - SHORT_HEADER_LEN)
                < PKT_MIN_SIZE
        );

        let (encrypted, pubkey_state, payload_state, payload_cipher_key) = {
            let mut message = SessionConfirmedBuilder::default()
                .with_max_payload_size(mtu)
                .with_dst_id(1337)
                .with_src_id(1338)
                .with_static_key(local_static_key.public())
                .with_router_info(Bytes::from(router_info.serialize(&signing_key)))
                .build::<MockRuntime>();

            // MixHash(header) & encrypt public key
            noise_ctx.mix_hash(message.header());
            message.encrypt_public_key(&cipher_key, 1u64, noise_ctx.state());
            let pubkey_state = noise_ctx.state().to_vec();

            // MixHash(apk)
            noise_ctx.mix_hash(message.public_key());

            let payload_cipher_key =
                noise_ctx.mix_key(&local_static_key, &remote_ephemeral_key.public());

            message.encrypt_payload(&payload_cipher_key, 0u64, noise_ctx.state());
            let payload_state = noise_ctx.state().to_vec();

            (
                message.build(remote_intro_key, k_header_2).to_vec(),
                pubkey_state,
                payload_state,
                payload_cipher_key,
            )
        };
        assert_eq!(encrypted.len(), num_frags);
        assert!(encrypted.iter().all(|pkt| pkt.len() <= mtu));

        let mut reassembled = Vec::<u8>::new();

        for (i, mut fragment) in encrypted.into_iter().enumerate() {
            let mut reader = HeaderReader::new(remote_intro_key, &mut fragment).unwrap();
            let _dst_id = reader.dst_id();

            match reader.parse(k_header_2).unwrap() {
                HeaderKind::SessionConfirmed {
                    fragment,
                    num_fragments,
                    ..
                } => {
                    assert_eq!(fragment, i);
                    assert_eq!(num_fragments, num_frags);
                }
                _ => panic!("unexpected message"),
            }

            if i == 0 {
                reassembled.extend(fragment)
            } else {
                reassembled.extend(&fragment[16..]);
            }
        }

        let mut static_key = reassembled[16..64].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 1u64)
            .decrypt_with_ad(&pubkey_state, &mut static_key)
            .unwrap();

        // decrypt payload
        let mut payload = reassembled[64..].to_vec();
        ChaChaPoly::with_nonce(&payload_cipher_key, 0u64)
            .decrypt_with_ad(&payload_state, &mut payload)
            .unwrap();

        let blocks = Block::parse::<MockRuntime>(&payload).unwrap();
        assert!(blocks.iter().any(|block| core::matches!(block, Block::Padding { .. })));
    }
}
