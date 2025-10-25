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
    error::parser::DatabaseLookupParseError,
    i2np::{database::DATABASE_KEY_SIZE, LOG_TARGET, ROUTER_HASH_LEN},
    primitives::{RouterId, TunnelId},
};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::HashSet;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;

/// Maximum number of routers to ignore.
const MAX_ROUTERS_TO_IGNORE: usize = 512;

/// Lookup type.
#[derive(Debug, PartialEq, Eq)]
pub enum LookupType {
    /// Normal lookup.
    ///
    /// Not supported
    Normal,

    /// Lease set lookup.
    LeaseSet,

    /// Router lookup.
    Router,

    /// Exploration.
    Exploration,
}

impl LookupType {
    /// Try to convert `lookup_type` into `StoreType`.
    fn from_u8(lookup_type: u8) -> Option<Self> {
        match (lookup_type >> 2) & 0x3 {
            0x00 => Some(Self::Normal),
            0x01 => Some(Self::LeaseSet),
            0x02 => Some(Self::Router),
            0x03 => Some(Self::Exploration),
            lookup_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?lookup_type,
                    "unsupported lookup type",
                );

                None
            }
        }
    }

    /// Serialize `self` into an `u8`.
    fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0x00 << 2,
            Self::LeaseSet => 0x01 << 2,
            Self::Router => 0x02 << 2,
            Self::Exploration => 0x03 << 2,
        }
    }
}

/// Reply type.
pub enum ReplyType {
    /// Send reply to tunnel.
    Tunnel {
        /// Tunnel ID of the gateway.
        tunnel_id: TunnelId,

        /// Router ID of the gateway.
        router_id: RouterId,
    },

    /// Send reply to router.
    Router {
        /// ID of the router expecting the reply
        router_id: RouterId,
    },
}

/// Database store message.
pub struct DatabaseLookup {
    /// Routers to ignore from reply.
    pub ignore: HashSet<RouterId>,

    /// Search Key.
    pub key: Bytes,

    /// Lookup type.
    pub lookup: LookupType,

    /// Reply type.
    pub reply: ReplyType,
}

impl DatabaseLookup {
    /// Attempt to parse [`DatabaseLookup`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self, DatabaseLookupParseError> {
        let (rest, key) = take(DATABASE_KEY_SIZE)(input)?;
        let (rest, router) = take(ROUTER_HASH_LEN)(rest)?;
        let (rest, flag) = be_u8(rest)?;
        let lookup = LookupType::from_u8(flag)
            .ok_or_else(|| Err::Error(DatabaseLookupParseError::InvalidLookupType(flag)))?;

        let (rest, reply) = match flag & 1 == 1 {
            true => {
                let (rest, tunnel_id) = be_u32(rest)?;
                (
                    rest,
                    ReplyType::Tunnel {
                        tunnel_id: TunnelId::from(tunnel_id),
                        router_id: RouterId::from(&router),
                    },
                )
            }
            false => (
                rest,
                ReplyType::Router {
                    router_id: RouterId::from(&router),
                },
            ),
        };

        let (rest, num_routers_to_ignore) = be_u16(rest)?;

        if num_routers_to_ignore as usize > MAX_ROUTERS_TO_IGNORE {
            return Err(Err::Error(DatabaseLookupParseError::TooLongIgnoreList(
                num_routers_to_ignore,
            )));
        }

        let (rest, ignore) = (0..num_routers_to_ignore)
            .try_fold(
                (rest, HashSet::<RouterId>::new()),
                |(rest, mut routers), _| {
                    take::<usize, &[u8], ()>(ROUTER_HASH_LEN)(rest).ok().map(|(rest, router)| {
                        routers.insert(RouterId::from(&router));

                        (rest, routers)
                    })
                },
            )
            .ok_or_else(|| Err::Error(DatabaseLookupParseError::InvalidIgnoreList))?;

        if (flag >> 1) & 1 == 1 || (flag >> 4) & 1 == 1 {
            return Err(Err::Error(
                DatabaseLookupParseError::LookupEncryptionNotSupported,
            ));
        }

        Ok((
            rest,
            Self {
                ignore,
                key: Bytes::from(key.to_vec()),
                lookup,
                reply,
            },
        ))
    }

    /// Attempt to parse `input` into [`DatabaseLookup`].
    pub fn parse(input: &[u8]) -> Result<Self, DatabaseLookupParseError> {
        Ok(Self::parse_frame(input)?.1)
    }
}

/// [`DatabaseLookup`] message builder.
pub struct DatabaseLookupBuilder {
    /// Search key.
    key: Bytes,

    /// Lookup type.
    lookup: LookupType,

    /// Reply type.
    reply_type: Option<ReplyType>,

    /// IDs of the routers that should be ignored.
    routers_to_ignore: Vec<RouterId>,
}

impl DatabaseLookupBuilder {
    /// Create new [`DatabaseLookupBuilder`].
    pub fn new(key: Bytes, lookup: LookupType) -> Self {
        Self {
            key,
            lookup,
            reply_type: None,
            routers_to_ignore: Vec::new(),
        }
    }

    /// Specify reply type.
    pub fn with_reply_type(mut self, reply_type: ReplyType) -> Self {
        self.reply_type = Some(reply_type);
        self
    }

    /// Specify which routers should be ignored in the reply.
    pub fn with_ignored_routers(mut self, routers_to_ignore: Vec<RouterId>) -> Self {
        self.routers_to_ignore = routers_to_ignore;
        self
    }

    /// Serialize `self` into [`DatabaseLookup`] message.
    pub fn build(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(
            DATABASE_KEY_SIZE
                + ROUTER_HASH_LEN
                + 1usize // flag
                + 2usize // ignore list size
                + self.routers_to_ignore.len() * ROUTER_HASH_LEN,
        );

        out.put_slice(&self.key);

        match self.reply_type.expect("reply type to exist") {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => {
                out.put_slice(&Into::<Vec<u8>>::into(router_id));
                out.put_u8(self.lookup.as_u8() | 0x01); // send reply to tunnel
                out.put_u32(*tunnel_id);
            }
            ReplyType::Router { router_id } => {
                out.put_slice(&Into::<Vec<u8>>::into(router_id));
                out.put_u8(self.lookup.as_u8());
            }
        }
        out.put_u16(self.routers_to_ignore.len() as u16);

        self.routers_to_ignore.into_iter().for_each(|router| {
            out.put_slice(&Into::<Vec<u8>>::into(router));
        });

        out.freeze().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_database_lookup() {
        let payloads = vec![
            vec![
                215, 46, 105, 162, 17, 97, 42, 165, 17, 19, 74, 252, 149, 245, 47, 140, 84, 126,
                138, 213, 149, 64, 2, 186, 2, 217, 194, 66, 237, 92, 144, 129, 187, 212, 29, 79,
                47, 234, 7, 8, 124, 50, 183, 31, 173, 202, 175, 121, 175, 12, 58, 35, 102, 106,
                242, 239, 240, 138, 56, 93, 11, 12, 12, 120, 8, 0, 0,
            ],
            vec![
                75, 242, 209, 197, 159, 177, 182, 35, 184, 57, 69, 43, 40, 122, 205, 225, 213, 60,
                49, 250, 106, 197, 227, 189, 150, 172, 251, 84, 19, 209, 39, 113, 187, 212, 29, 79,
                47, 234, 7, 8, 124, 50, 183, 31, 173, 202, 175, 121, 175, 12, 58, 35, 102, 106,
                242, 239, 240, 138, 56, 93, 11, 12, 12, 120, 8, 0, 0,
            ],
            vec![
                24, 179, 37, 69, 217, 247, 36, 218, 158, 69, 110, 11, 12, 161, 127, 61, 193, 102,
                232, 197, 85, 43, 151, 247, 119, 192, 90, 37, 167, 230, 26, 95, 187, 212, 29, 79,
                47, 234, 7, 8, 124, 50, 183, 31, 173, 202, 175, 121, 175, 12, 58, 35, 102, 106,
                242, 239, 240, 138, 56, 93, 11, 12, 12, 120, 8, 0, 0,
            ],
        ];

        for payload in &payloads {
            let _ = DatabaseLookup::parse(&payload).unwrap();
        }
    }

    #[test]
    fn normal_lookup() {
        let message = DatabaseLookupBuilder::new(Bytes::from(vec![1u8; 32]), LookupType::Normal)
            .with_reply_type(ReplyType::Router {
                router_id: RouterId::from(vec![0u8; 32]),
            })
            .build();

        let message = DatabaseLookup::parse(&message).unwrap();
        assert_eq!(message.lookup, LookupType::Normal);
        assert_eq!(message.key, vec![1u8; 32]);

        match message.reply {
            ReplyType::Router { router_id } => assert_eq!(router_id, RouterId::from(vec![0u8; 32])),
            _ => panic!("invalid reply type"),
        }
    }

    #[test]
    fn leaseset_lookup() {
        let message = DatabaseLookupBuilder::new(Bytes::from(vec![2u8; 32]), LookupType::LeaseSet)
            .with_reply_type(ReplyType::Tunnel {
                router_id: RouterId::from(vec![1u8; 32]),
                tunnel_id: TunnelId::from(1337u32),
            })
            .build();

        let message = DatabaseLookup::parse(&message).unwrap();
        assert_eq!(message.lookup, LookupType::LeaseSet);
        assert_eq!(message.key, vec![2u8; 32]);

        match message.reply {
            ReplyType::Tunnel {
                router_id,
                tunnel_id,
            } => {
                assert_eq!(router_id, RouterId::from(vec![1u8; 32]));
                assert_eq!(tunnel_id, TunnelId::from(1337u32));
            }
            _ => panic!("invalid reply type"),
        }
    }

    #[test]
    fn router_lookup() {
        let message = DatabaseLookupBuilder::new(Bytes::from(vec![3u8; 32]), LookupType::Router)
            .with_reply_type(ReplyType::Router {
                router_id: RouterId::from(vec![2u8; 32]),
            })
            .build();

        let message = DatabaseLookup::parse(&message).unwrap();
        assert_eq!(message.lookup, LookupType::Router);
        assert_eq!(message.key, vec![3u8; 32]);

        match message.reply {
            ReplyType::Router { router_id } => assert_eq!(router_id, RouterId::from(vec![2u8; 32])),
            _ => panic!("invalid reply type"),
        }
    }

    #[test]
    fn router_lookup_with_ignore_list() {
        let mut ignored =
            (5..10).map(|id| RouterId::from(vec![id as u8; 32])).collect::<HashSet<_>>();

        let message = DatabaseLookupBuilder::new(Bytes::from(vec![3u8; 32]), LookupType::Router)
            .with_reply_type(ReplyType::Router {
                router_id: RouterId::from(vec![3u8; 32]),
            })
            .with_ignored_routers(ignored.clone().into_iter().collect())
            .build();

        let message = DatabaseLookup::parse(&message).unwrap();
        assert_eq!(message.lookup, LookupType::Router);
        assert_eq!(message.key, vec![3u8; 32]);

        match message.reply {
            ReplyType::Router { router_id } => assert_eq!(router_id, RouterId::from(vec![3u8; 32])),
            _ => panic!("invalid reply type"),
        }

        assert_eq!(ignored.len(), 5);
        for router in message.ignore {
            ignored.remove(&router);
        }
        assert!(ignored.is_empty());
    }

    #[test]
    fn exploration_lookup() {
        let message =
            DatabaseLookupBuilder::new(Bytes::from(vec![4u8; 32]), LookupType::Exploration)
                .with_reply_type(ReplyType::Router {
                    router_id: RouterId::from(vec![4u8; 32]),
                })
                .build();

        let message = DatabaseLookup::parse(&message).unwrap();
        assert_eq!(message.lookup, LookupType::Exploration);
        assert_eq!(message.key, vec![4u8; 32]);

        match message.reply {
            ReplyType::Router { router_id } => assert_eq!(router_id, RouterId::from(vec![4u8; 32])),
            _ => panic!("invalid reply type"),
        }
    }
}
