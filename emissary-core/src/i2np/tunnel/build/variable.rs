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
    i2np::{HopRole, AES256_IV_LEN, AES256_KEY_LEN, ROUTER_HASH_LEN},
    primitives::{Mapping, MessageId, RouterId, TunnelId},
};

use nom::{
    bytes::complete::take,
    number::complete::{be_u32, be_u8},
    Err, IResult,
};

/// Variable tunnel build record.
#[derive(Debug)]
pub struct TunnelBuildRecord<'a> {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Next router.
    next_router: RouterId,

    /// Tunnel layer key (AES-256)
    tunnel_layer_key: &'a [u8],

    /// Tunnel layer IV (AES-256)
    tunnel_iv_key: &'a [u8],

    /// Flags.
    role: HopRole,

    /// Next message ID.
    ///
    /// Used as the reply message's message ID.
    next_message_id: MessageId,
}

impl<'a> TunnelBuildRecord<'a> {
    /// Attempt to parse `input` into `TunnelBuildRecord`.
    ///
    /// Returns the tunnel build record and what's left of `input` on success.
    pub fn parse_frame(
        input: &'a [u8],
    ) -> IResult<&'a [u8], TunnelBuildRecord<'a>, TunnelBuildRecordParseError> {
        let (rest, tunnel_id) = be_u32(input)?;
        let (rest, next_tunnel_id) = be_u32(rest)?;
        let (rest, next_router_hash) = take(ROUTER_HASH_LEN)(rest)?;
        let (rest, tunnel_layer_key) = take(AES256_KEY_LEN)(rest)?;
        let (rest, tunnel_iv_key) = take(AES256_KEY_LEN)(rest)?;
        let (rest, _tunnel_reply_key) = take(AES256_KEY_LEN)(rest)?;
        let (rest, _tunnel_reply_iv) = take(AES256_IV_LEN)(rest)?;
        let (rest, flags) = be_u8(rest)?;
        let (rest, _reserved) = take(3usize)(rest)?;
        let (rest, _request_time) = be_u32(rest)?;
        let (rest, _request_expiration) = be_u32(rest)?;
        let (rest, next_message_id) = be_u32(rest)?;
        let (rest, _options) = Mapping::parse_frame(rest).map_err(Err::convert)?;
        let (rest, _padding) = take(input.len() - rest.len())(rest)?;
        let role = HopRole::from_u8(flags)
            .ok_or(Err::Error(TunnelBuildRecordParseError::InvalidHop(flags)))?;

        Ok((
            rest,
            TunnelBuildRecord {
                tunnel_id: TunnelId::from(tunnel_id),
                next_tunnel_id: TunnelId::from(next_tunnel_id),
                next_router: RouterId::from(next_router_hash),
                tunnel_layer_key,
                tunnel_iv_key,
                role,
                next_message_id: MessageId::from(next_message_id),
            },
        ))
    }

    /// Attempt to parse `input` into `TunnelBuildRecord`.
    pub fn parse(input: &'a [u8]) -> Result<TunnelBuildRecord<'a>, TunnelBuildRecordParseError> {
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

    /// Get `RouterId` of next router.
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

    /// Get reference to tunnel layer key.
    pub fn tunnel_layer_key(&self) -> &[u8] {
        self.tunnel_layer_key
    }

    /// Get reference to tunnel IV key.
    pub fn tunnel_iv_key(&self) -> &[u8] {
        self.tunnel_iv_key
    }
}
