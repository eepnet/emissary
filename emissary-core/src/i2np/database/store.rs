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
    i2np::{database::DATABASE_KEY_SIZE, LOG_TARGET, ROUTER_HASH_LEN},
    primitives::{LeaseSet2, RouterId, RouterInfo, TunnelId},
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use core::{fmt, marker::PhantomData};

/// "No reply" token/tunnel ID.
const NO_REPLY: u32 = 0u32;

#[derive(Debug)]
enum StoreType {
    /// Router info.
    RouterInfo,

    /// Lease set.
    LeaseSet,

    /// Lease set, type 2.
    LeaseSet2,

    /// Encrypted lease set.
    EncryptedLeaseSet,

    /// Meta lease set.
    MetaLeaseSet,
}

impl StoreType {
    /// Try to convert `store_type` into `StoreType`.
    fn from_u8(store_type: u8) -> Option<Self> {
        match store_type & 1 {
            0 => Some(Self::RouterInfo),
            _ => match (store_type >> 1) & 0x7 {
                0 => Some(Self::LeaseSet),
                1 => Some(Self::LeaseSet2),
                2 => Some(Self::EncryptedLeaseSet),
                3 => Some(Self::MetaLeaseSet),
                _ => None,
            },
        }
    }

    /// Serialize [`StoreType`].
    fn as_u8(&self) -> u8 {
        match self {
            Self::RouterInfo => 0u8,
            Self::LeaseSet => 1u8,
            Self::LeaseSet2 => 1u8 | (1u8 << 1),
            Self::EncryptedLeaseSet => 1u8 | (2u8 << 1),
            Self::MetaLeaseSet => 1u8 | (3u8 << 1),
        }
    }
}

/// Reply type.
pub enum ReplyType {
    /// Reply should be sent to tunnel.
    Tunnel {
        /// Reply token.
        reply_token: u32,

        /// ID of the gateway tunnel.
        tunnel_id: TunnelId,

        /// Router ID of the gateway tunnel.
        router_id: RouterId,
    },

    /// Reply should be sent to router.
    Router {
        /// Reply token.
        reply_token: u32,

        /// Router ID of the gateway tunnel.
        router_id: RouterId,
    },

    /// No reply required.
    None,
}

impl fmt::Debug for ReplyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => f
                .debug_struct("ReplyType::Tunnel")
                .field("reply_token", &reply_token)
                .field("router_id", &format_args!("{router_id}"))
                .field("tunnel_id", &format_args!("{tunnel_id}"))
                .finish_non_exhaustive(),
            Self::Router {
                reply_token,
                router_id,
            } => f
                .debug_struct("ReplyType::Router")
                .field("reply_token", &reply_token)
                .field("router_id", &format_args!("{router_id}"))
                .finish_non_exhaustive(),
            Self::None => f.debug_struct("ReplyType::None").finish(),
        }
    }
}

impl ReplyType {
    fn serialized_len(&self) -> usize {
        match self {
            Self::Tunnel { .. } | Self::Router { .. } => {
                // reply token + tunnel id + router hash length
                4usize + 4usize + ROUTER_HASH_LEN
            }
            Self::None => 4usize,
        }
    }
}

/// Payload contained within the `DatabaseStore` message.
pub enum DatabaseStorePayload {
    /// Router info.
    RouterInfo {
        /// Router info.
        router_info: RouterInfo,
    },

    /// Lease set type 2.
    LeaseSet2 {
        /// Lease set.
        lease_set: LeaseSet2,
    },
}

impl fmt::Display for DatabaseStorePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouterInfo { router_info } => write!(
                f,
                "DatabaseStorePayload::RouterInfo ({})",
                router_info.identity.id()
            ),
            Self::LeaseSet2 { lease_set } => write!(
                f,
                "DatabaseStorePayload::LeaseSet2 ({})",
                lease_set.header.destination.id()
            ),
        }
    }
}

impl DatabaseStorePayload {
    #[allow(unused)]
    fn serialized_len(&self) -> usize {
        match self {
            // TODO: calculate actual size
            Self::RouterInfo { .. } => 2048usize,
            Self::LeaseSet2 { lease_set } => lease_set.serialized_len(),
        }
    }
}

/// Database store message.
pub struct DatabaseStore<R: Runtime> {
    /// Search key.
    pub key: Bytes,

    /// Payload contained within the `DatabaseStore` message.
    pub payload: DatabaseStorePayload,

    /// Reply type.
    pub reply: ReplyType,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> fmt::Debug for DatabaseStore<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseStore")
            .field("payload", &format_args!("{}", self.payload))
            .field("reply", &self.reply)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> DatabaseStore<R> {
    /// Attempt to parse [`DatabaseStore`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, key) = take(DATABASE_KEY_SIZE)(input)?;
        let (rest, store_type) = be_u8(rest)?;
        let (rest, reply_token) = be_u32(rest)?;
        let store_type = StoreType::from_u8(store_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        let (rest, reply) = match reply_token == NO_REPLY {
            true => (rest, ReplyType::None),
            false => {
                let (rest, gateway_tunnel) = be_u32(rest)?;
                let (rest, gateway_router) = take(ROUTER_HASH_LEN)(rest)?;

                match gateway_tunnel == NO_REPLY {
                    true => (
                        rest,
                        ReplyType::Router {
                            reply_token,
                            router_id: RouterId::from(gateway_router),
                        },
                    ),
                    false => (
                        rest,
                        ReplyType::Tunnel {
                            reply_token,
                            tunnel_id: TunnelId::from(gateway_tunnel),
                            router_id: RouterId::from(gateway_router),
                        },
                    ),
                }
            }
        };

        match store_type {
            StoreType::RouterInfo => {
                let (rest, size) = be_u16(rest)?;
                let (rest, data) = take(size)(rest)?;

                let data = R::gzip_decompress(data).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "failed to decompress gzip",
                    );

                    Err::Error(make_error(input, ErrorKind::Fail))
                })?;

                let router_info = RouterInfo::parse(&data).ok_or_else(|| {
                    tracing::debug!(
                        target: LOG_TARGET,
                        "failed to parse gzipped router info",
                    );

                    Err::Error(make_error(input, ErrorKind::Fail))
                })?;

                Ok((
                    rest,
                    Self {
                        key: Bytes::from(key.to_vec()),
                        payload: DatabaseStorePayload::RouterInfo { router_info },
                        reply,
                        _runtime: Default::default(),
                    },
                ))
            }
            StoreType::LeaseSet2 => {
                let (rest, lease_set) = LeaseSet2::parse_frame::<R>(rest)?;

                Ok((
                    rest,
                    Self {
                        key: Bytes::from(key.to_vec()),
                        payload: DatabaseStorePayload::LeaseSet2 { lease_set },
                        reply,
                        _runtime: Default::default(),
                    },
                ))
            }
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    "support for store kind not implemented",
                );
                Err(Err::Error(make_error(input, ErrorKind::Fail)))
            }
        }
    }

    /// Attempt to parse `input` into [`DatabaseStore`].
    pub fn parse(input: &[u8]) -> Option<Self> {
        Self::parse_frame(input).ok().map(|(_, message)| message)
    }

    /// Extract raw payload from [`DatabaseStore`] message.
    fn extraw_raw_data_payload(input: &[u8], router_info: bool) -> Bytes {
        let (rest, _) = take::<_, _, ()>(DATABASE_KEY_SIZE)(input).expect("to succeed");
        let (rest, _) = be_u8::<_, ()>(rest).expect("to succeed");
        let (rest, reply_token) = be_u32::<_, ()>(rest).expect("to succeed");

        let rest = match reply_token == NO_REPLY {
            true => rest,
            false => {
                let (rest, _) = be_u32::<_, ()>(rest).expect("to succeed");
                let (rest, _) = take::<_, _, ()>(ROUTER_HASH_LEN)(rest).expect("to succeed");

                rest
            }
        };

        if router_info {
            let (rest, size) = be_u16::<_, ()>(rest).expect("to succeed");
            let (_, data) = take::<_, _, ()>(size)(rest).expect("to succeed");

            BytesMut::from(data).freeze()
        } else {
            BytesMut::from(rest).freeze()
        }
    }

    /// Extract raw, unserialized [`LeaseSet`] from `input`.
    ///
    /// Caller is expected to ensure that `input` is a valid [`DatabaseStore`] that contains
    /// a valid [`LeaseSet2`].
    pub fn extract_raw_lease_set(input: &[u8]) -> Bytes {
        Self::extraw_raw_data_payload(input, false)
    }

    /// Extract raw, unserialized [`RouterInfo`] from `input`.
    ///
    /// Caller is expected to ensure that `input` is a valid [`DatabaseStore`] that contains
    /// a valid [`RouterInfo`].
    pub fn extract_raw_router_info(input: &[u8]) -> Bytes {
        Self::extraw_raw_data_payload(input, true)
    }
}

/// Database store kind.
pub enum DatabaseStoreKind {
    /// [`RouterInfo`].
    RouterInfo {
        /// Serialized [`RouterInfo`].
        router_info: Bytes,
    },

    /// [`LeaseSet2`].
    LeaseSet2 {
        /// Serialized [`LeaseSet2`].
        lease_set: Bytes,
    },
}

impl DatabaseStoreKind {
    /// Get serialized length of the payload.
    fn serialized_len(&self) -> usize {
        match self {
            Self::RouterInfo { router_info } => router_info.len(),
            Self::LeaseSet2 { lease_set } => lease_set.len(),
        }
    }
}

/// [`DatabaseStore`] builder.
pub struct DatabaseStoreBuilder {
    /// Store key.
    key: Bytes,

    /// Database store kind.
    kind: DatabaseStoreKind,

    /// Reply type, if specified.
    reply: Option<ReplyType>,
}

impl DatabaseStoreBuilder {
    /// Create new [`DatabaseStoreBuilder`].
    pub fn new(key: Bytes, kind: DatabaseStoreKind) -> Self {
        Self {
            key,
            kind,
            reply: None,
        }
    }

    /// Specify reply type.
    pub fn with_reply_type(mut self, reply: ReplyType) -> Self {
        self.reply = Some(reply);
        self
    }

    /// Serialize [`DatabaseStore`] into a byte vector.
    pub fn build(self) -> BytesMut {
        let reply = self.reply.unwrap_or(ReplyType::None);
        let mut out = BytesMut::with_capacity(
            DATABASE_KEY_SIZE
                .saturating_add(1usize) // store type
                .saturating_add(reply.serialized_len())
                .saturating_add(self.kind.serialized_len()),
        );

        out.put_slice(&self.key);

        match &self.kind {
            DatabaseStoreKind::RouterInfo { .. } => out.put_u8(StoreType::RouterInfo.as_u8()),
            DatabaseStoreKind::LeaseSet2 { .. } => out.put_u8(StoreType::LeaseSet2.as_u8()),
        }

        match reply {
            ReplyType::None => {
                out.put_u32(NO_REPLY);
            }
            ReplyType::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => {
                out.put_u32(reply_token);
                out.put_u32(*tunnel_id);
                out.put_slice(&router_id.to_vec());
            }
            ReplyType::Router {
                reply_token,
                router_id,
            } => {
                out.put_u32(reply_token);
                out.put_u32(NO_REPLY);
                out.put_slice(&router_id.to_vec());
            }
        }

        match self.kind {
            DatabaseStoreKind::RouterInfo { router_info } => {
                out.put_u16(router_info.len() as u16);
                out.put_slice(&router_info);
            }
            DatabaseStoreKind::LeaseSet2 { lease_set } => out.put_slice(&lease_set),
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use rand::RngCore;

    #[test]
    fn parse_database_store() {
        let buffer = vec![
            249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216, 57, 137, 166, 213, 35, 195, 36,
            79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7, 0, 101, 5, 15, 45, 0, 0, 0, 0,
            249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216, 57, 137, 166, 213, 35, 195, 36,
            79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7, 2, 151, 31, 139, 8, 0, 0, 0, 0,
            0, 2, 255, 1, 128, 2, 127, 253, 222, 205, 6, 59, 50, 200, 120, 177, 26, 105, 6, 11, 22,
            247, 62, 125, 94, 166, 157, 159, 205, 26, 68, 197, 126, 246, 167, 208, 34, 44, 152, 53,
            156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227,
            27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212,
            169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207,
            146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19,
            226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163,
            237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255,
            56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71,
            229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149,
            94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66,
            197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76,
            222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36,
            242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111,
            156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227,
            27, 83, 149, 94, 207, 146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212,
            169, 64, 66, 197, 83, 19, 226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207,
            146, 177, 76, 222, 163, 237, 79, 111, 156, 157, 71, 229, 212, 169, 64, 66, 197, 83, 19,
            226, 150, 36, 242, 255, 56, 236, 227, 27, 83, 149, 94, 207, 146, 177, 76, 222, 163,
            237, 79, 111, 193, 118, 156, 13, 187, 24, 148, 135, 201, 57, 162, 146, 109, 209, 194,
            238, 49, 30, 8, 187, 55, 61, 104, 151, 23, 241, 84, 73, 35, 18, 228, 159, 5, 0, 4, 0,
            7, 0, 4, 0, 0, 1, 145, 153, 163, 42, 152, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 5, 78, 84, 67,
            80, 50, 0, 113, 4, 104, 111, 115, 116, 61, 9, 49, 50, 55, 46, 48, 46, 48, 46, 49, 59,
            1, 105, 61, 24, 77, 117, 115, 99, 83, 117, 67, 90, 106, 105, 57, 108, 72, 113, 102, 73,
            56, 121, 74, 73, 56, 103, 61, 61, 59, 4, 112, 111, 114, 116, 61, 4, 56, 56, 57, 48, 59,
            1, 115, 61, 44, 101, 49, 65, 97, 74, 80, 67, 126, 104, 80, 117, 80, 49, 54, 52, 80, 71,
            105, 71, 107, 97, 105, 52, 50, 119, 80, 55, 110, 89, 70, 117, 111, 56, 121, 74, 115,
            76, 119, 76, 77, 48, 106, 77, 61, 59, 1, 118, 61, 1, 50, 59, 0, 0, 43, 4, 99, 97, 112,
            115, 61, 1, 76, 59, 5, 110, 101, 116, 73, 100, 61, 1, 50, 59, 14, 114, 111, 117, 116,
            101, 114, 46, 118, 101, 114, 115, 105, 111, 110, 61, 6, 48, 46, 57, 46, 54, 50, 59,
            187, 28, 65, 149, 0, 49, 238, 139, 72, 152, 68, 124, 54, 114, 146, 48, 122, 88, 53, 97,
            92, 3, 49, 209, 233, 3, 27, 94, 50, 13, 78, 133, 155, 126, 53, 213, 174, 143, 152, 192,
            84, 122, 104, 147, 39, 185, 101, 38, 20, 216, 147, 187, 19, 47, 233, 162, 56, 58, 45,
            26, 246, 141, 69, 9, 132, 119, 99, 190, 128, 2, 0, 0,
        ];

        let _ = DatabaseStore::<MockRuntime>::parse(&buffer).unwrap();
    }

    #[test]
    fn parse_leaseset2_store() {
        let buffer = vec![
            88, 34, 216, 162, 50, 127, 74, 133, 95, 237, 241, 77, 176, 11, 35, 188, 105, 25, 245,
            184, 0, 22, 72, 59, 149, 131, 27, 71, 110, 227, 236, 9, 3, 0, 0, 0, 0, 214, 155, 197,
            98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196,
            246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183,
            41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91,
            198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216,
            196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54,
            197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194,
            93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214,
            155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109,
            234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170,
            161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15,
            126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58,
            103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187,
            11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180,
            218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115,
            230, 214, 155, 197, 98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131,
            248, 109, 234, 196, 246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197,
            98, 170, 161, 183, 41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196,
            246, 15, 126, 91, 198, 187, 11, 54, 197, 115, 230, 214, 155, 197, 98, 170, 161, 183,
            41, 58, 103, 216, 196, 180, 218, 194, 93, 131, 248, 109, 234, 196, 246, 15, 126, 91,
            198, 187, 11, 54, 197, 115, 230, 64, 231, 155, 2, 143, 122, 48, 137, 247, 79, 229, 220,
            40, 212, 53, 67, 193, 196, 204, 21, 45, 109, 227, 237, 29, 17, 31, 189, 17, 189, 195,
            40, 5, 0, 4, 0, 7, 0, 0, 102, 216, 119, 64, 2, 88, 0, 0, 0, 0, 2, 0, 4, 0, 32, 103, 57,
            105, 36, 53, 6, 188, 207, 237, 100, 79, 208, 65, 73, 180, 118, 143, 162, 202, 8, 103,
            162, 220, 12, 95, 156, 67, 68, 62, 83, 112, 109, 0, 0, 1, 0, 119, 187, 61, 243, 159,
            159, 198, 178, 65, 81, 148, 19, 78, 105, 92, 175, 190, 170, 136, 62, 19, 45, 23, 246,
            228, 210, 215, 161, 129, 149, 160, 57, 137, 141, 144, 141, 163, 247, 34, 120, 5, 161,
            60, 107, 34, 107, 166, 40, 152, 252, 246, 205, 187, 51, 129, 52, 97, 95, 188, 78, 176,
            198, 254, 4, 19, 197, 215, 74, 73, 55, 135, 16, 43, 68, 159, 141, 78, 234, 63, 118,
            142, 114, 20, 96, 8, 38, 18, 211, 159, 107, 160, 236, 33, 3, 153, 100, 77, 117, 145,
            67, 173, 140, 69, 123, 31, 253, 172, 240, 74, 110, 148, 56, 229, 208, 81, 69, 175, 122,
            89, 252, 43, 29, 193, 100, 232, 33, 150, 48, 105, 230, 76, 125, 114, 135, 88, 222, 21,
            183, 56, 203, 58, 51, 187, 57, 64, 196, 238, 62, 35, 43, 226, 209, 160, 77, 171, 252,
            81, 125, 105, 3, 40, 216, 107, 1, 209, 223, 117, 237, 54, 151, 90, 133, 76, 32, 217,
            167, 214, 86, 42, 226, 222, 126, 45, 133, 138, 28, 77, 37, 28, 200, 74, 3, 240, 188,
            12, 47, 48, 49, 61, 154, 31, 74, 78, 229, 133, 62, 250, 249, 67, 180, 175, 156, 60,
            148, 227, 168, 127, 107, 118, 63, 220, 18, 242, 169, 94, 112, 58, 7, 196, 69, 243, 206,
            205, 89, 54, 174, 162, 106, 223, 195, 152, 90, 155, 98, 223, 122, 21, 248, 181, 118,
            208, 80, 41, 154, 232, 58, 3, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190, 216, 57,
            137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114, 242, 7,
            240, 177, 138, 122, 102, 216, 121, 152, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73, 190,
            216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94, 114,
            242, 7, 254, 77, 137, 9, 102, 216, 121, 152, 249, 0, 187, 182, 11, 128, 61, 16, 80, 73,
            190, 216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118, 161, 49, 37, 5, 174, 148, 94,
            114, 242, 7, 239, 37, 242, 32, 102, 216, 121, 152, 85, 131, 155, 161, 181, 62, 114,
            203, 208, 71, 210, 43, 204, 240, 181, 94, 146, 250, 118, 234, 79, 158, 201, 58, 167,
            187, 35, 177, 69, 215, 241, 60, 154, 198, 121, 194, 199, 142, 61, 196, 142, 139, 85,
            87, 210, 244, 83, 145, 143, 233, 154, 12, 60, 130, 140, 197, 170, 93, 124, 203, 142,
            46, 214, 11,
        ];

        let _ = DatabaseStore::<MockRuntime>::parse(&buffer).unwrap();
        let raw_lease_set = DatabaseStore::<MockRuntime>::extract_raw_lease_set(&buffer);

        assert!(LeaseSet2::parse::<MockRuntime>(&raw_lease_set).is_some());
    }

    #[test]
    fn serialize_and_parse_store_with_no_reply() {
        let (leaseset, signing_key) = LeaseSet2::random();
        let key = {
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);

            Bytes::from(key)
        };

        let serialized = DatabaseStoreBuilder::new(
            key.clone(),
            DatabaseStoreKind::LeaseSet2 {
                lease_set: Bytes::from(leaseset.clone().serialize(&signing_key)),
            },
        )
        .build();

        let store = DatabaseStore::<MockRuntime>::parse(&serialized).unwrap();

        assert_eq!(store.key, key);
        assert!(std::matches!(store.reply, ReplyType::None));

        match store.payload {
            DatabaseStorePayload::LeaseSet2 { lease_set: parsed } => assert!(parsed
                .leases
                .iter()
                .zip(leaseset.leases.iter())
                .all(|(lease1, lease2)| lease1 == lease2)),
            _ => panic!("invalid payload"),
        }
    }

    #[test]
    fn serialize_and_parse_store_with_reply() {
        let (leaseset, signing_key) = LeaseSet2::random();
        let reply_router = RouterId::random();
        let key = {
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);

            Bytes::from(key)
        };

        let serialized = DatabaseStoreBuilder::new(
            key.clone(),
            DatabaseStoreKind::LeaseSet2 {
                lease_set: Bytes::from(leaseset.clone().serialize(&signing_key)),
            },
        )
        .with_reply_type(ReplyType::Tunnel {
            reply_token: 0x13371338,
            tunnel_id: TunnelId::from(0x13351336),
            router_id: reply_router.clone(),
        })
        .build();

        let store = DatabaseStore::<MockRuntime>::parse(&serialized).unwrap();

        assert_eq!(store.key, key);

        match store.reply {
            ReplyType::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => {
                assert_eq!(reply_token, 0x13371338);
                assert_eq!(tunnel_id, TunnelId::from(0x13351336));
                assert_eq!(router_id, reply_router);
            }
            _ => panic!("invalid reply type"),
        }

        match store.payload {
            DatabaseStorePayload::LeaseSet2 { lease_set: parsed } => assert!(parsed
                .leases
                .iter()
                .zip(leaseset.leases.iter())
                .all(|(lease1, lease2)| lease1 == lease2)),
            _ => panic!("invalid payload"),
        }
    }
}
