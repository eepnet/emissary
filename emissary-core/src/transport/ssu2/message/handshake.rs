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
        EphemeralPublicKey, StaticPublicKey,
    },
    runtime::Runtime,
    transport::ssu2::message::*,
};

use bytes::{BufMut, Bytes, BytesMut};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};
use core::net::SocketAddr;

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
}

impl Default for TokenRequestBuilder {
    fn default() -> Self {
        Self {
            dst_id: None,
            intro_key: None,
            src_id: None,
            net_id: 2u8,
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
    pub fn encrypt_payload(&mut self, cipher_key: &[u8], nonce: u64, state: &[u8]) {
        // must succeed since all the parameters are controlled by us
        ChaChaPoly::with_nonce(cipher_key, nonce)
            .encrypt_with_ad_new(state, &mut self.payload)
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
        let mut out = BytesMut::with_capacity(self.header.len() + self.payload.len());
        out.put_slice(&self.header);
        out.put_slice(&self.payload);

        out
    }
}

/// Builder for `SessionRequest`.
pub struct SessionRequestBuilder {
    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Local ephemeral public key.
    ephemeral_key: Option<EphemeralPublicKey>,

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Token.
    token: Option<u64>,
}

impl Default for SessionRequestBuilder {
    fn default() -> Self {
        Self {
            dst_id: None,
            ephemeral_key: None,
            net_id: 2u8,
            src_id: None,
            token: None,
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

    /// Specify network ID.
    pub fn with_net_id(mut self, net_id: u8) -> Self {
        self.net_id = net_id;
        self
    }

    /// Build [`SessionRequestBuilder`] into [`SessionRequest`].
    pub fn build<R: Runtime>(mut self) -> SessionRequest {
        let mut rng = R::rng();
        let padding = {
            let padding_len = rng.next_u32() % MAX_PADDING as u32 + 1;
            let mut padding = vec![0u8; padding_len as usize];
            rng.fill_bytes(&mut padding);

            padding
        };
        let header = {
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN + PUBLIC_KEY_LEN);

            out.put_u64_le(self.dst_id.take().expect("to exist"));
            out.put_u32(rng.next_u32());
            out.put_u8(*MessageType::SessionRequest);
            out.put_u8(2u8); // version
            out.put_u8(self.net_id);
            out.put_u8(0u8); // flag
            out.put_u64_le(self.src_id.take().expect("to exist"));
            out.put_u64_le(self.token.take().expect("to exist"));
            out.put_slice(self.ephemeral_key.take().expect("to exist").as_ref());

            out
        };

        let mut payload = Vec::with_capacity(10 + padding.len() + POLY13055_MAC_LEN);
        payload.extend_from_slice(
            &Block::DateTime {
                timestamp: R::time_since_epoch().as_secs() as u32,
            }
            .serialize(),
        );
        payload.extend_from_slice(&Block::Padding { padding }.serialize());

        SessionRequest { header, payload }
    }
}

/// Unserialized `SessionConfirmed` message.
pub struct SessionConfirmed {
    /// Serialized, unencrypted header.
    header: BytesMut,

    /// Serialized, unencrypted static key.
    static_key: Vec<u8>,

    /// Serialized, unecrypted payload.
    payload: Vec<u8>,
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
    }

    /// Serialize [`SessionConfirmed`] into a byte vector.
    pub fn build(self) -> BytesMut {
        let mut out =
            BytesMut::with_capacity(self.header.len() + self.static_key.len() + self.payload.len());
        out.put_slice(&self.header);
        out.put_slice(&self.static_key);
        out.put_slice(&self.payload);

        out
    }
}

/// `SessionConfirmed` builder.
#[derive(Default)]
pub struct SessionConfirmedBuilder {
    /// Destination connection ID.
    dst_id: Option<u64>,

    /// Source connection ID.
    src_id: Option<u64>,

    /// Serialized local router info.
    router_info: Option<Bytes>,

    /// Local static public key.
    static_key: Option<StaticPublicKey>,
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
    pub fn build(mut self) -> SessionConfirmed {
        let header = {
            let mut out = BytesMut::with_capacity(SHORT_HEADER_LEN);

            out.put_u64_le(self.dst_id.take().expect("to exist"));
            out.put_u32(0u32);
            out.put_u8(*MessageType::SessionConfirmed);
            out.put_u8(1u8); // 1 fragment
            out.put_u16(0u16); // flags

            out
        };
        let static_key = self.static_key.expect("to exist").to_vec();
        let payload = {
            let router_info = self.router_info.take().expect("to exist");
            let mut out = BytesMut::with_capacity(5 + router_info.len());

            out.put_u8(BlockType::RouterInfo.as_u8());
            out.put_u16((2 + router_info.len()) as u16);
            out.put_u8(0u8);
            out.put_u8(1u8);
            out.put_slice(&router_info);

            out.to_vec()
        };

        SessionConfirmed {
            header,
            static_key,
            payload,
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

    /// Token.
    token: Option<u64>,
}

impl Default for RetryBuilder {
    fn default() -> Self {
        Self {
            address: None,
            dst_id: None,
            k_header_1: None,
            net_id: 2u8,
            src_id: None,
            token: None,
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

    /// Specify network ID.
    pub fn with_net_id(mut self, net_id: u8) -> Self {
        self.net_id = net_id;
        self
    }

    /// Build [`SessionConfirmedBuilder`] into a byte vector.
    pub fn build<R: Runtime>(self) -> BytesMut {
        let (mut header, pkt_num) = {
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN);
            let pkt_num = R::rng().next_u32();

            out.put_u64_le(self.dst_id.expect("to exist"));
            out.put_u32(pkt_num);
            out.put_u8(*MessageType::Retry);
            out.put_u8(2u8);
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
        let payload_size = 3 * 3 + 4 + 6 + padding.len() + POLY13055_MAC_LEN;
        let k_header_1 = self.k_header_1.expect("to exist");

        let mut payload = [
            Block::DateTime {
                timestamp: R::time_since_epoch().as_secs() as u32,
            },
            Block::Address {
                address: self.address.expect("to exist"),
            },
            Block::Padding { padding },
        ]
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

    /// Serialized, unencrypted payload
    payload: Vec<u8>,
}

impl SessionCreated {
    /// Get reference to header.
    pub fn header(&self) -> &[u8] {
        &self.header[..32]
    }

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

    /// Serialize [`SessionCreated`] into a byte vector.
    pub fn build(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.header.len() + self.payload.len());
        out.put_slice(&self.header);
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

    /// Network ID.
    ///
    /// Defaults to 2.
    net_id: u8,

    /// Source connection ID.
    src_id: Option<u64>,
}

impl Default for SessionCreatedBuilder {
    fn default() -> Self {
        Self {
            address: None,
            dst_id: None,
            ephemeral_key: None,
            net_id: 2u8,
            src_id: None,
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

    /// Build [`SessionCreatedBuilder`] into [`SessionCreated`] by creating a long header
    /// and a payload with needed blocks.
    ///
    /// This function doesn't return a serialized `SessionCreated` message as the caller needs to
    /// encrypt the payload with "non-static" key/state which future encryption/decryption is
    /// depended on.
    pub fn build<R: Runtime>(mut self) -> SessionCreated {
        let header = {
            let mut out = BytesMut::with_capacity(LONG_HEADER_LEN);

            out.put_u64_le(self.dst_id.expect("to exist"));
            out.put_u32(R::rng().next_u32());
            out.put_u8(*MessageType::SessionCreated);
            out.put_u8(2u8);
            out.put_u8(self.net_id);
            out.put_u8(0u8);
            out.put_u64_le(self.src_id.expect("to exist"));
            out.put_u64(0u64);
            out.put_slice(self.ephemeral_key.take().expect("to exist").as_ref());

            out
        };
        let padding = {
            let padding_len = R::rng().next_u32() as usize % MAX_PADDING + 1;
            let mut padding = vec![0u8; padding_len];
            R::rng().fill_bytes(&mut padding);

            padding
        };
        let payload_size = 3 * 3 + 4 + 6 + padding.len() + POLY13055_MAC_LEN;

        let payload = [
            Block::DateTime {
                timestamp: R::time_since_epoch().as_secs() as u32,
            },
            Block::Address {
                address: self.address.expect("to exist"),
            },
            Block::Padding { padding },
        ]
        .into_iter()
        .fold(BytesMut::with_capacity(payload_size), |mut out, block| {
            out.put_slice(&block.serialize());
            out
        })
        .to_vec();

        SessionCreated { header, payload }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::EphemeralPrivateKey, runtime::mock::MockRuntime};

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
                    .build::<MockRuntime>();

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
                    .build::<MockRuntime>();

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
}
