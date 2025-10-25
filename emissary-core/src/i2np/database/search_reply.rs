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
    error::parser::DatabaseSearchReplyParseError,
    i2np::{database::DATABASE_KEY_SIZE, ROUTER_HASH_LEN},
    primitives::RouterId,
};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{bytes::complete::take, number::complete::be_u8, Err, IResult};

use alloc::vec::Vec;

/// Database search reply.
pub struct DatabaseSearchReply {
    /// Router ID of the sender.
    pub from: Vec<u8>,

    /// Search key.
    pub key: Bytes,

    /// Router IDs.
    pub routers: Vec<RouterId>,
}

impl DatabaseSearchReply {
    /// Attempt to parse [`DatabaseSearchReply`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self, DatabaseSearchReplyParseError> {
        let (rest, key) = take(DATABASE_KEY_SIZE)(input)?;
        let (rest, num_hashes) = be_u8(rest)?;
        let (rest, routers) = (0..num_hashes)
            .try_fold((rest, Vec::new()), |(rest, mut hashes), _| {
                take::<usize, &[u8], ()>(ROUTER_HASH_LEN)(rest).ok().map(|(rest, router)| {
                    hashes.push(RouterId::from(router));

                    (rest, hashes)
                })
            })
            .ok_or(Err::Error(
                DatabaseSearchReplyParseError::InvalidReplyHashList,
            ))?;

        // `from` field is not needed
        let (rest, from) = take(ROUTER_HASH_LEN)(rest)?;

        Ok((
            rest,
            Self {
                from: from.to_vec(),
                key: BytesMut::from(key).freeze(),
                routers,
            },
        ))
    }

    /// Attempt to parse `input` into [`DatabaseSearchReply`].
    pub fn parse(input: &[u8]) -> Result<Self, DatabaseSearchReplyParseError> {
        Ok(Self::parse_frame(input)?.1)
    }

    /// Serialize [`DatabaseSearchReply`].
    pub fn serialize(self) -> BytesMut {
        let mut out = BytesMut::with_capacity(
            self.routers.len() * ROUTER_HASH_LEN + DATABASE_KEY_SIZE + ROUTER_HASH_LEN,
        );

        out.put_slice(&self.key);
        out.put_u8(self.routers.len() as u8);
        self.routers
            .into_iter()
            .for_each(|router_id| out.put_slice(&router_id.to_vec()));
        out.put_slice(&self.from.to_vec());

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize() {
        let sender = RouterId::random();
        let router1 = RouterId::random();
        let router2 = RouterId::random();
        let router3 = RouterId::random();

        let serialized = DatabaseSearchReply {
            from: sender.to_vec(),
            key: Bytes::from(vec![1u8; 32]),
            routers: vec![router1.clone(), router2.clone(), router3.clone()],
        }
        .serialize();

        let parsed = DatabaseSearchReply::parse(&serialized).unwrap();

        assert_eq!(parsed.from, sender.to_vec());
        assert_eq!(parsed.key, Bytes::from(vec![1u8; 32]));
        assert_eq!(parsed.routers, vec![router1, router2, router3]);
    }
}
