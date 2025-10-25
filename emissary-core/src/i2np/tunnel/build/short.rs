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
    error::parser::TunnelBuildRecordParseError,
    i2np::{HopRole, AES256_IV_LEN, ROUTER_HASH_LEN},
    primitives::{Mapping, MessageId, RouterId, TunnelId},
};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u32, be_u8},
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{vec, vec::Vec};

/// Short tunnel build reply builder.
#[derive(Default)]
pub struct TunnelBuildReplyBuilder;

impl TunnelBuildReplyBuilder {
    /// Build tunnel buid reply from records.
    pub fn from_records(records: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(1 + 218 * records.len());
        out.put_u8(records.len() as u8);

        records
            .into_iter()
            .fold(out, |mut acc, record| {
                acc.put_slice(&record);
                acc
            })
            .freeze()
            .to_vec()
    }
}

/// Short tunnel build record builder.
#[derive(Default)]
pub struct TunnelBuildRecordBuilder<'a> {
    /// Tunnel ID.
    tunnel_id: Option<TunnelId>,

    /// Next tunnel ID.
    next_tunnel_id: Option<TunnelId>,

    /// Next router hash.
    next_router_hash: Option<&'a [u8]>,

    /// Hop role.
    role: Option<HopRole>,

    /// Request time.
    request_time: Option<u32>,

    /// Request expiration.
    request_expiration: Option<u32>,

    /// Next message id.
    next_message_id: Option<MessageId>,
}

impl<'a> TunnelBuildRecordBuilder<'a> {
    /// Add tunnel ID.
    pub fn with_tunnel_id(mut self, tunnel_id: TunnelId) -> Self {
        self.tunnel_id = Some(tunnel_id);
        self
    }

    /// Add next tunnel ID.
    pub fn with_next_tunnel_id(mut self, next_tunnel_id: TunnelId) -> Self {
        self.next_tunnel_id = Some(next_tunnel_id);
        self
    }

    /// Add next router hash.
    pub fn with_next_router_hash(mut self, next_router_hash: &'a [u8]) -> Self {
        self.next_router_hash = Some(next_router_hash);
        self
    }

    /// Add hop role.
    pub fn with_hop_role(mut self, role: HopRole) -> Self {
        self.role = Some(role);
        self
    }

    /// Add request time.
    pub fn with_request_time(mut self, request_time: u32) -> Self {
        self.request_time = Some(request_time);
        self
    }

    /// Add request expiration.
    pub fn with_request_expiration(mut self, request_expiration: u32) -> Self {
        self.request_expiration = Some(request_expiration);
        self
    }

    /// Add next message id.
    pub fn with_next_message_id(mut self, next_message_id: MessageId) -> Self {
        self.next_message_id = Some(next_message_id);
        self
    }

    /// Returns a full-length build record (218) of random bytes.
    pub fn random<R: RngCore>(rng: &mut R) -> Vec<u8> {
        let mut out = vec![0u8; 218];
        rng.fill_bytes(&mut out);

        out
    }

    /// Serialize `TunnelBuildRecordBuilder`.
    pub fn serialize(self, rng: &mut impl RngCore) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(154 + AES256_IV_LEN);

        out.put_u32(*self.tunnel_id.expect("to exist"));
        out.put_u32(*self.next_tunnel_id.expect("to exist"));
        out.put_slice(self.next_router_hash.expect("to exist"));
        out.put_u8(self.role.expect("to exist").as_u8());
        out.put_u16(0u16); // reserved
        out.put_u8(0u8); // encryption type

        out.put_u32(self.request_time.expect("to exist"));
        out.put_u32(self.request_expiration.expect("to exist"));
        out.put_u32(*self.next_message_id.expect("to exist"));
        out.put_u16(0u16); // options

        let mut padding = vec![0u8; out.capacity() - out.len() - AES256_IV_LEN];
        rng.fill_bytes(&mut padding);
        out.put_slice(&padding);

        out.freeze().to_vec()
    }
}

/// Short tunnel build request record.
#[derive(Debug)]
pub struct TunnelBuildRecord {
    /// Next message ID.
    next_message_id: MessageId,

    /// Next router's `RouterId`.
    next_router: RouterId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Hop role.
    role: HopRole,

    /// Our tunnel ID.
    tunnel_id: TunnelId,
}

impl TunnelBuildRecord {
    /// Attempt to parse [`TunnelBuildRecord`] from `input`.
    ///
    /// Returns the parsed record and rest of `input` on success.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self, TunnelBuildRecordParseError> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, next_tunnel_id) = be_u32(rest)?;
        let (rest, next_router_hash) = take(ROUTER_HASH_LEN)(rest)?;
        let (rest, flags) = be_u8(rest)?;
        let (rest, _reserved) = take(2usize)(rest)?;
        let (rest, _encryption_type) = be_u8(rest)?;
        let (rest, _request_time) = be_u32(rest)?;
        let (rest, _request_expiration) = be_u32(rest)?;
        let (rest, next_message_id) = be_u32(rest)?;
        let (rest, _options) = Mapping::parse_frame(rest).map_err(Err::convert)?;
        let (rest, _padding) = take(rest.len())(rest)?;
        let role = HopRole::from_u8(flags)
            .ok_or(Err::Error(TunnelBuildRecordParseError::InvalidHop(flags)))?;

        Ok((
            rest,
            Self {
                next_message_id: MessageId::from(next_message_id),
                next_router: RouterId::from(next_router_hash),
                next_tunnel_id: TunnelId::from(next_tunnel_id),
                role,
                tunnel_id: TunnelId::from(tunnel_id),
            },
        ))
    }

    /// Attempt to parse `input` into `TunnelBuildRecord`.
    pub fn parse(input: &[u8]) -> Result<Self, TunnelBuildRecordParseError> {
        Ok(Self::parse_frame(input)?.1)
    }

    /// Get tunnel ID.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Get next tunnel ID.
    pub fn next_tunnel_id(&self) -> TunnelId {
        self.next_tunnel_id
    }

    /// Get `RouterId` of the next router.
    pub fn next_router(&self) -> RouterId {
        self.next_router.clone()
    }

    /// Get hop role.
    pub fn role(&self) -> HopRole {
        self.role
    }

    /// Get next message ID.
    pub fn next_message_id(&self) -> MessageId {
        self.next_message_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_bytes() {
        let serialized = TunnelBuildRecordBuilder::default()
            .with_tunnel_id(TunnelId::from(0))
            .with_next_tunnel_id(TunnelId::from(0))
            .with_next_router_hash(&[0u8; 32])
            .with_hop_role(HopRole::Participant)
            .with_request_time(0)
            .with_request_expiration(0)
            .with_next_message_id(MessageId::from(0))
            .serialize(&mut rand_core::OsRng);

        assert!(TunnelBuildRecord::parse(&serialized).is_ok());
    }

    #[test]
    fn invalid_role() {
        let mut out = BytesMut::with_capacity(154 + AES256_IV_LEN);

        out.put_u32(0u32);
        out.put_u32(0u32);
        out.put_slice(&[0u8; 32]);
        out.put_u8(254);
        out.put_u16(0u16); // reserved
        out.put_u8(0u8); // encryption type

        out.put_u32(0u32);
        out.put_u32(0u32);
        out.put_u32(0u32);
        out.put_u16(0u16); // options

        let mut padding = vec![0u8; out.capacity() - out.len() - AES256_IV_LEN];
        rand_core::OsRng.fill_bytes(&mut padding);
        out.put_slice(&padding);

        let serialized = out.freeze().to_vec();

        assert_eq!(
            TunnelBuildRecord::parse(&serialized).unwrap_err(),
            TunnelBuildRecordParseError::InvalidHop(254)
        );
    }

    #[test]
    fn options_parsed_correctly() {
        let mut out = BytesMut::with_capacity(154 + AES256_IV_LEN);

        out.put_u32(0u32);
        out.put_u32(0u32);
        out.put_slice(&[0u8; 32]);
        out.put_u8(HopRole::InboundGateway.as_u8());
        out.put_u16(0u16); // reserved
        out.put_u8(0u8); // encryption type

        out.put_u32(0u32);
        out.put_u32(0u32);
        out.put_u32(0u32);

        {
            let mut option1 = Mapping::default();
            option1.insert("hello".into(), "world".into());
            let option1 = option1.serialize();

            let mut option2 = Mapping::default();
            option2.insert("goodbye".into(), "world".into());
            let option2 = option2.serialize();

            out.put_u16((option1.len() + option2.len()) as u16);
            out.put_slice(&option1);
            out.put_slice(&option2);
        }

        let mut padding = vec![0u8; out.capacity() - out.len() - AES256_IV_LEN];
        rand_core::OsRng.fill_bytes(&mut padding);
        out.put_slice(&padding);

        let serialized = out.freeze().to_vec();

        assert!(TunnelBuildRecord::parse(&serialized).is_ok());
    }
}
