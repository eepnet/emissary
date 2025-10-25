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

#![allow(unused)]

use crate::{
    crypto::{SigningPrivateKey, SigningPublicKey},
    error::parser::{
        DestinationParseError, FlagsParseError, OfflineSignatureParseError, PacketParseError,
    },
    primitives::{Destination, DestinationId, OfflineSignature},
    runtime::Runtime,
    sam::protocol::streaming::LOG_TARGET,
};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str};

/// Minimum header size without NACKs or options data.
const MIN_HEADER_SIZE: usize = 22usize;

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// DSA-SHA1 signature length.
const DSA_SIGNATURE_LEN: usize = 40usize;

/// MTU size.
const MTU: usize = 1812usize;

/// Flags of the streaming packet.
pub struct Flags<'a> {
    /// Included destination, if received.
    destination: Option<Destination>,

    /// Flags.
    flags: u16,

    /// Maximum packet size, if received.
    max_packet_size: Option<u16>,

    /// Signing public key from [`OfflineSignature`].
    offline_signature: Option<SigningPublicKey>,

    /// Requested delay, if received.
    requested_delay: Option<u16>,

    /// Included signature, if received.
    signature: Option<&'a [u8]>,
}

impl fmt::Display for Flags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::<&'static str>::new();

        if self.synchronize() {
            flags.push("SYN");
        }

        if self.close() {
            flags.push("CLOSE")
        }

        if self.reset() {
            flags.push("RST")
        }

        if self.signature().is_some() {
            flags.push("SIG");
        }

        if self.from_included().is_some() {
            flags.push("FROM_INCLUDED");
        }

        if self.echo() {
            flags.push("ECHO");
        }

        if self.no_ack() {
            flags.push("NACK");
        }

        if self.offline_signature().is_some() {
            flags.push("OFFLINE_SIG");
        }

        let mut flags = {
            if flags.is_empty() {
                "[]".to_string()
            } else {
                let num_flags = flags.len();
                let mut ret = String::from("flags = [");

                for (i, flag) in flags.into_iter().enumerate() {
                    if i + 1 < num_flags {
                        ret += format!("{flag}, ").as_str();
                    } else {
                        ret += flag;
                    }
                }

                ret + "]"
            }
        };

        if let Some(delay) = self.delay_requested() {
            flags += format!(", delay = {delay}").as_str();
        }

        if let Some(mtu) = self.max_packet_size() {
            flags += format!(", mtu = {mtu}").as_str();
        }

        write!(f, "{flags}")
    }
}

impl<'a> Flags<'a> {
    fn new<R: Runtime>(flags: u16, options: &'a [u8]) -> IResult<&'a [u8], Self, FlagsParseError> {
        let (rest, requested_delay) = match (flags >> 6) & 1 == 1 {
            true => be_u16(options).map(|(rest, requested_delay)| (rest, Some(requested_delay)))?,
            false => (options, None),
        };

        let (rest, destination) = match (flags >> 5) & 1 == 1 {
            true => Destination::parse_frame(rest)
                .map(|(rest, destination)| (rest, Some(destination)))
                .map_err(Err::convert)?,
            false => (rest, None),
        };

        let (rest, max_packet_size) = match (flags >> 7) & 1 == 1 {
            true => be_u16(rest).map(|(rest, max_packet_size)| (rest, Some(max_packet_size)))?,
            false => (rest, None),
        };

        let (rest, offline_signature) = match (flags >> 11) & 1 == 1 {
            true => match destination.as_ref() {
                None => {
                    debug_assert!(false);
                    return Err(Err::Error(FlagsParseError::DestinationMissing));
                }
                Some(destination) => {
                    let (rest, verifying_key) =
                        OfflineSignature::parse_frame::<R>(rest, destination.verifying_key())
                            .map_err(Err::convert)?;

                    (rest, Some(verifying_key))
                }
            },
            false => (rest, None),
        };

        let (rest, signature) = match (flags >> 3) & 1 == 1 {
            true => match destination.as_ref() {
                None => {
                    // destination not specified, optimistically take rest of the input
                    let (rest, _signature) = take(rest.len())(rest)?;

                    (rest, Some(rest))
                }
                Some(destination) => take(destination.verifying_key().signature_len())(rest)
                    .map(|(rest, signature)| (rest, Some(signature)))?,
            },
            false => (rest, None),
        };

        Ok((
            rest,
            Flags {
                destination,
                flags,
                max_packet_size,
                offline_signature,
                requested_delay,
                signature,
            },
        ))
    }

    /// Has `SYNCHRONIZE` flag been sent.
    pub fn synchronize(&self) -> bool {
        self.flags & 1 == 1
    }

    /// Has `CLOSE` flag been set.
    pub fn close(&self) -> bool {
        (self.flags >> 1) & 1 == 1
    }

    /// Has `RESET` flag been set.
    pub fn reset(&self) -> bool {
        (self.flags >> 2) & 1 == 1
    }

    /// Get included signature, if received.
    pub fn signature(&self) -> Option<&'a [u8]> {
        self.signature
    }

    /// Get included `Destination`, if received.
    pub fn from_included(&self) -> &Option<Destination> {
        &self.destination
    }

    /// Get requested delay, if received.
    pub fn delay_requested(&self) -> Option<u16> {
        self.requested_delay
    }

    /// Get maximum packet size, if received.
    pub fn max_packet_size(&self) -> Option<u16> {
        self.max_packet_size
    }

    /// Has `ECHO` flag been sent.
    pub fn echo(&self) -> bool {
        (self.flags >> 9) & 1 == 1
    }

    /// Has `NO_ACK` flag been sent.
    pub fn no_ack(&self) -> bool {
        (self.flags >> 10) & 1 == 1
    }

    /// Get included offline signature, if received.
    pub fn offline_signature(&self) -> Option<&SigningPublicKey> {
        self.offline_signature.as_ref()
    }
}

impl fmt::Debug for Flags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags").field("flags", &self.flags).finish()
    }
}

/// [`Packet`] peek info.
///
/// Used to peek into packet so it can be handled correctly without fully deserializing it.
#[derive(Debug)]
pub struct PeekInfo {
    /// Packet flags.
    flags: u16,

    /// Receive stream ID.
    recv_stream_id: u32,

    /// Send stream ID.
    send_stream_id: u32,

    /// Sequence number of the packet.
    seq_nro: u32,
}

impl PeekInfo {
    /// Has `SYNCHRONIZE` flag been sent.
    pub fn synchronize(&self) -> bool {
        self.flags & 1 == 1
    }

    /// Has `CLOSE` flag been set.
    pub fn close(&self) -> bool {
        (self.flags >> 1) & 1 == 1
    }

    /// Has `RESET` flag been set.
    pub fn reset(&self) -> bool {
        (self.flags >> 2) & 1 == 1
    }

    /// Has `ECHO` flag been sent.
    pub fn echo(&self) -> bool {
        (self.flags >> 9) & 1 == 1
    }

    /// Get send stream ID of the packet.
    pub fn send_stream_id(&self) -> u32 {
        self.send_stream_id
    }

    /// Get receive stream ID of the packet.
    pub fn recv_stream_id(&self) -> u32 {
        self.recv_stream_id
    }

    /// Get sequence number of the packet.
    pub fn seq_nro(&self) -> u32 {
        self.seq_nro
    }
}

/// Streaming protocol packet.
pub struct Packet<'a> {
    /// Send stream ID.
    pub send_stream_id: u32,

    /// Receive stream ID.
    pub recv_stream_id: u32,

    /// Sequence number of the packet.
    pub seq_nro: u32,

    /// ACK through bytes.
    pub ack_through: u32,

    /// Negative ACKs.
    pub nacks: Vec<u32>,

    /// Resend delay.
    pub resend_delay: u8,

    /// Flags.
    pub flags: Flags<'a>,

    /// Payload.
    pub payload: &'a [u8],
}

impl fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let test = str::from_utf8(self.payload).unwrap_or("falure");

        f.debug_struct("Packet")
            .field("send_stream_id", &self.send_stream_id)
            .field("recv_stream_id", &self.recv_stream_id)
            .field("seq_nro", &self.seq_nro)
            .field("ack_through", &self.ack_through)
            .field("nacks", &self.nacks)
            .field("resend_delay", &self.resend_delay)
            .field("flags", &self.flags)
            .field("payload", &test)
            .finish()
    }
}

impl<'a> Packet<'a> {
    /// Attempt to parse [`Packet`] from `input`.
    ///
    /// Returns the parsed message and rest of `input` on success.
    fn parse_frame<R: Runtime>(input: &'a [u8]) -> IResult<&'a [u8], Self, PacketParseError> {
        let (rest, send_stream_id) = be_u32(input)?;
        let (rest, recv_stream_id) = be_u32(rest)?;
        let (rest, seq_nro) = be_u32(rest)?;
        let (rest, ack_through) = be_u32(rest)?;
        let (rest, nack_count) = be_u8(rest)?;
        let (rest, nacks) = (0..nack_count)
            .try_fold((rest, Vec::new()), |(rest, mut nacks), _| {
                be_u32::<_, ()>(rest).ok().map(|(rest, nack)| {
                    nacks.push(nack);

                    (rest, nacks)
                })
            })
            .ok_or(Err::Error(PacketParseError::InvalidNackList))?;

        let (rest, resend_delay) = be_u8(rest)?;
        let (rest, flags) = be_u16(rest)?;
        let (rest, options_size) = be_u16(rest)?;
        let (rest, options) = take(options_size)(rest)?;
        let (_, flags) = Flags::new::<R>(flags, options).map_err(Err::convert)?;

        Ok((
            &[],
            Self {
                send_stream_id,
                recv_stream_id,
                seq_nro,
                ack_through,
                nacks,
                resend_delay,
                flags,
                payload: rest,
            },
        ))
    }

    /// Attempt to parse `input` into [`Packet`].
    pub fn parse<R: Runtime>(input: &'a [u8]) -> Result<Self, PacketParseError> {
        Ok(Self::parse_frame::<R>(input)?.1)
    }

    /// Inner implementation of [`Packet::peek()`].
    fn peek_inner(input: &'a [u8]) -> IResult<&'a [u8], PeekInfo> {
        let (rest, send_stream_id) = be_u32(input)?;
        let (rest, recv_stream_id) = be_u32(rest)?;
        let (rest, seq_nro) = be_u32(rest)?;
        let (rest, _) = take(4usize)(rest)?;
        let (rest, nack_count) = be_u8(rest)?;
        let (rest, _nacks) = take(4 * nack_count as usize + 1)(rest)?;
        let (rest, flags) = be_u16(rest)?;

        Ok((
            rest,
            PeekInfo {
                flags,
                recv_stream_id,
                send_stream_id,
                seq_nro,
            },
        ))
    }

    /// Peek into serialized [`Packet`] and return relevant information.
    pub fn peek(input: &'a [u8]) -> Option<PeekInfo> {
        Some(Self::peek_inner(input).ok()?.1)
    }
}

/// Flags builder for [`PacketBuilder`].
#[derive(Default)]
pub struct FlagsBuilder<'a> {
    /// Included destination, if received.
    destination: Option<Bytes>,

    /// Flags.
    flags: u16,

    /// Maximum packet size, if received.
    max_packet_size: Option<u16>,

    /// Offline signature, if received.
    offline_signature: Option<&'a [u8]>,

    /// Options length.
    options_len: usize,

    /// Requested delay, if received.
    requested_delay: Option<u16>,

    /// Included signature, if received.
    signature: Option<&'a [u8]>,
}

impl FlagsBuilder<'_> {
    /// Specify `SYNCHRONIZE` .
    pub fn with_synchronize(mut self) -> Self {
        self.flags |= 1;
        self
    }

    /// Specify `CLOSE`.
    pub fn with_close(mut self) -> Self {
        self.flags |= 1 << 1;
        self
    }

    /// Specify `RESET`.
    pub fn with_reset(mut self) -> Self {
        self.flags |= 1 << 2;
        self
    }

    /// Specify that signature is included.
    pub fn with_signature(mut self) -> Self {
        self.flags |= 1 << 3;
        self.options_len += 64;
        self
    }

    /// Specify that local destination ID is included.
    pub fn with_from_included(mut self, destination: Destination) -> Self {
        self.options_len += destination.serialized_len();
        self.destination = Some(destination.serialize());
        self.flags |= 1 << 5;
        self
    }

    /// Get requested delay, if received.
    pub fn with_delay_requested(mut self, requested_delay: u16) -> Self {
        self.requested_delay = Some(requested_delay);
        self.options_len += 2;
        self.flags |= 1 << 6;
        self
    }

    /// Get maximum packet size, if received.
    pub fn with_max_packet_size(mut self, max_packet_size: u16) -> Self {
        self.max_packet_size = Some(max_packet_size);
        self.options_len += 2;
        self.flags |= 1 << 7;
        self
    }

    /// Specify `ECHO`.
    pub fn with_echo(mut self) -> Self {
        self.flags |= 1 << 9;
        self
    }

    /// Specify `NO_ACK`.
    pub fn with_no_ack(mut self) -> Self {
        self.flags |= 1 << 10;
        self
    }

    /// Build [`FlagsBuilder`] and return `(flags, options)` tuple.
    fn build(self) -> (u16, Option<BytesMut>) {
        // no options
        if self.options_len == 0 {
            return (self.flags, None);
        }

        let mut out = BytesMut::with_capacity(self.options_len);

        if let Some(requested_delay) = self.requested_delay {
            out.put_u16(requested_delay);
        }

        if let Some(destination) = self.destination {
            out.put_slice(&destination);
        }

        if let Some(max_packet_size) = self.max_packet_size {
            out.put_u16(max_packet_size);
        }

        // the field needs to be all zeros when the signature is calculated
        if (self.flags >> 3) & 1 == 1 {
            out.put_slice(&[0u8; 64]);
        }

        (self.flags, Some(out))
    }
}

/// Packet builder.
pub struct PacketBuilder<'a> {
    /// Send stream ID.
    send_stream_id: Option<u32>,

    /// Receive stream ID.
    recv_stream_id: u32,

    /// Sequence number of the packet, defaults to `0u32`.
    seq_nro: u32,

    /// ACK through bytes, defaults to `0u32`.
    ack_through: u32,

    /// Negative ACKs.
    nacks: Option<Vec<u32>>,

    /// Resend delay, defaults to `0u8`.
    resend_delay: u8,

    /// Flags builder.
    flags_builder: FlagsBuilder<'a>,

    /// Payload.
    payload: Option<&'a [u8]>,
}

impl<'a> PacketBuilder<'a> {
    /// Create new [`PacketBuilder`] with receive stream ID.
    pub fn new(recv_stream_id: u32) -> Self {
        Self {
            send_stream_id: None,
            recv_stream_id,
            seq_nro: 0u32,
            ack_through: 0u32,
            nacks: None,
            resend_delay: 0u8,
            flags_builder: Default::default(),
            payload: None,
        }
    }

    /// Specify send stream ID.
    pub fn with_send_stream_id(mut self, send_stream_id: u32) -> Self {
        self.send_stream_id = Some(send_stream_id);
        self
    }

    /// Specify sequence number of the packet.
    pub fn with_seq_nro(mut self, seq_nro: u32) -> Self {
        self.seq_nro = seq_nro;
        self
    }

    /// Specify aCK through bytes.
    pub fn with_ack_through(mut self, ack_through: u32) -> Self {
        self.ack_through = ack_through;
        self
    }

    /// Specify negative ACKs.
    pub fn with_nacks(mut self, nacks: Vec<u32>) -> Self {
        self.nacks = Some(nacks);
        self
    }

    /// Serialize `destination_id` into `nacks` field for replay protection.
    pub fn with_replay_protection(mut self, destination_id: &DestinationId) -> Self {
        self.nacks = Some(
            destination_id
                .to_vec()
                .chunks(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("to succeed")))
                .collect(),
        );
        self
    }

    /// Specify resend delay.
    pub fn with_resend_delay(mut self, resend_delay: u8) -> Self {
        self.resend_delay = resend_delay;
        self
    }

    /// Specify payload.
    pub fn with_payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Specify `SYNCHRONIZE` .
    pub fn with_synchronize(mut self) -> Self {
        self.flags_builder = self.flags_builder.with_synchronize();
        self
    }

    /// Specify `CLOSE`.
    pub fn with_close(mut self) -> Self {
        self.flags_builder = self.flags_builder.with_close();
        self
    }

    /// Specify `RESET`.
    pub fn with_reset(mut self) -> Self {
        self.flags_builder = self.flags_builder.with_reset();
        self
    }

    /// Specify that signature is included.
    pub fn with_signature(mut self) -> Self {
        self.flags_builder = self.flags_builder.with_signature();
        self
    }

    /// Specify that local destination ID is included.
    pub fn with_from_included(mut self, destination: Destination) -> Self {
        self.flags_builder = self.flags_builder.with_from_included(destination);
        self
    }

    /// Get requested delay, if received.
    pub fn with_delay_requested(mut self, requested_delay: u16) -> Self {
        self.flags_builder = self.flags_builder.with_delay_requested(requested_delay);
        self
    }

    /// Get maximum packet size, if received.
    pub fn with_max_packet_size(mut self, max_packet_size: u16) -> Self {
        self.flags_builder = self.flags_builder.with_max_packet_size(max_packet_size);
        self
    }

    /// Specify `ECHO`.
    pub fn with_echo(mut self) -> Self {
        self.flags_builder = self.flags_builder.with_echo();
        self
    }

    /// Specify `NO_ACK`.
    pub fn with_no_ack(mut self) -> Self {
        self.flags_builder = self.flags_builder.with_no_ack();
        self
    }

    /// Build [`PacketBuilder`] into [`Packet`].
    pub fn build(self) -> BytesMut {
        let (flags, options) = self.flags_builder.build();

        if (flags >> 3) & 1 == 1 {
            panic!("`PacketBuilder::build()` called but signature specified");
        }

        let mut out = BytesMut::with_capacity(
            MIN_HEADER_SIZE
                .wrapping_add(options.as_ref().map_or(0usize, |options| options.len()))
                .wrapping_add(self.nacks.as_ref().map_or(0usize, |nacks| nacks.len() * 4))
                .wrapping_add(self.payload.as_ref().map_or(0usize, |payload| payload.len())),
        );

        out.put_u32(self.send_stream_id.expect("to exist"));
        out.put_u32(self.recv_stream_id);
        out.put_u32(self.seq_nro);
        out.put_u32(self.ack_through);

        match self.nacks {
            None => out.put_u8(0u8),
            Some(nacks) => {
                out.put_u8(nacks.len() as u8);
                nacks.into_iter().for_each(|nack| {
                    out.put_u32(nack);
                });
            }
        }
        out.put_u8(self.resend_delay);
        out.put_u16(flags);

        match options {
            None => {
                out.put_u16(0u16);
            }
            Some(options) => {
                out.put_u16(options.len() as u16);
                out.put_slice(&options);
            }
        }

        if let Some(payload) = self.payload {
            out.put_slice(payload);
        }

        out
    }

    /// Build [`PacketBuilder`] into [`Packet`] with signature.
    ///
    /// Panics if one of the needed fields is missing.
    pub fn build_and_sign(self, signing_key: &SigningPrivateKey) -> BytesMut {
        let (flags, options) = self.flags_builder.build();

        if (flags >> 3) & 1 == 0 {
            panic!("`PacketBuilder::build_and_sign()` called without specifying signature");
        }

        let mut out = BytesMut::with_capacity(
            MIN_HEADER_SIZE
                .wrapping_add(options.as_ref().map_or(0usize, |options| options.len()))
                .wrapping_add(self.nacks.as_ref().map_or(0usize, |nacks| nacks.len() * 4))
                .wrapping_add(self.payload.as_ref().map_or(0usize, |payload| payload.len())),
        );

        out.put_u32(self.send_stream_id.expect("to exist"));
        out.put_u32(self.recv_stream_id);
        out.put_u32(self.seq_nro);
        out.put_u32(self.ack_through);

        match self.nacks {
            None => out.put_u8(0u8),
            Some(nacks) => {
                out.put_u8(nacks.len() as u8);
                nacks.into_iter().for_each(|nack| {
                    out.put_u32(nack);
                });
            }
        }
        out.put_u8(self.resend_delay);
        out.put_u16(flags);

        match options {
            None => {
                out.put_u16(0u16);
            }
            Some(options) => {
                out.put_u16(options.len() as u16);
                out.put_slice(&options);
            }
        }

        let signature_start = match self.payload {
            None => out.len() - SIGNATURE_LEN,
            Some(payload) => {
                out.put_slice(payload);
                out.len() - SIGNATURE_LEN - payload.len()
            }
        };

        // calculate signature over the entire packet and copy calculated signature
        // into the options field which previously contained zeros
        {
            let signature = signing_key.sign(&out);
            out[signature_start..signature_start + SIGNATURE_LEN].copy_from_slice(&signature);
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, Runtime};
    use rand_core::RngCore;

    #[test]
    fn syn_flags() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let destination = Destination::new::<MockRuntime>(signing_key.public());

        let (flags, options) = FlagsBuilder::default()
            .with_synchronize()
            .with_from_included(destination.clone())
            .with_signature()
            .with_max_packet_size(1337)
            .with_delay_requested(750)
            .build();

        assert!(options.is_some());

        let (rest, flags) = Flags::new::<MockRuntime>(flags, options.as_ref().unwrap()).unwrap();

        assert!(rest.is_empty());
        assert!(flags.synchronize());

        assert_eq!(flags.max_packet_size(), Some(1337));
        assert_eq!(flags.delay_requested(), Some(750));
        assert_eq!(flags.signature(), Some([0u8; 64].as_ref()));

        let dest = flags.from_included().as_ref().unwrap();

        assert_eq!(dest.verifying_key().as_ref(), signing_key.public().as_ref());
        assert_eq!(dest.id(), destination.id());
    }

    #[test]
    fn no_options() {
        let (flags, options) =
            FlagsBuilder::default().with_synchronize().with_close().with_no_ack().build();

        assert!(options.is_none());

        let (rest, flags) = Flags::new::<MockRuntime>(flags, &[]).unwrap();

        assert!(rest.is_empty());
        assert!(flags.synchronize());
        assert!(flags.close());
        assert!(flags.no_ack());

        assert!(!flags.reset());
        assert!(!flags.echo());
        assert!(flags.signature().is_none());
        assert!(flags.from_included().is_none());
        assert!(flags.delay_requested().is_none());
        assert!(flags.max_packet_size().is_none());
        assert!(flags.offline_signature().is_none());
    }

    #[test]
    fn all_flags() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let destination = Destination::new::<MockRuntime>(signing_key.public());

        let (flags, options) = FlagsBuilder::default()
            .with_synchronize()
            .with_close()
            .with_reset()
            .with_echo()
            .with_no_ack()
            .with_from_included(destination.clone())
            .with_signature()
            .with_max_packet_size(1338)
            .with_delay_requested(800)
            .build();

        assert!(options.is_some());

        let (rest, flags) = Flags::new::<MockRuntime>(flags, options.as_ref().unwrap()).unwrap();

        assert!(rest.is_empty());
        assert!(flags.synchronize());
        assert!(flags.close());
        assert!(flags.reset());
        assert!(flags.echo());
        assert!(flags.no_ack());

        assert_eq!(flags.max_packet_size(), Some(1338));
        assert_eq!(flags.delay_requested(), Some(800));
        assert_eq!(flags.signature(), Some([0u8; 64].as_ref()));

        let dest = flags.from_included().as_ref().unwrap();

        assert_eq!(dest.verifying_key().as_ref(), signing_key.public().as_ref());
        assert_eq!(dest.id(), destination.id());
    }

    #[test]
    fn build_syn() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let recv_destination_id = DestinationId::random();
        let mut payload = "hello, world".as_bytes();

        let recv_stream_id = MockRuntime::rng().next_u32();

        let serialized = PacketBuilder::new(recv_stream_id)
            .with_send_stream_id(0)
            .with_synchronize()
            .with_signature()
            .with_replay_protection(&recv_destination_id)
            .with_resend_delay(128)
            .with_from_included(destination.clone())
            .with_payload(&payload)
            .build_and_sign(&signing_key);

        let packet = Packet::parse::<MockRuntime>(&serialized).unwrap();

        assert!(packet.flags.synchronize());
        assert!(packet.flags.signature().is_some());
        assert!(packet.flags.from_included().is_some());
        assert_eq!(packet.resend_delay, 128);

        // ensure nacks field contains the correct destination id
        {
            let parsed_destination_id = packet
                .nacks
                .iter()
                .fold(BytesMut::with_capacity(32), |mut acc, x| {
                    acc.put_slice(&x.to_be_bytes());
                    acc
                })
                .freeze()
                .to_vec();

            assert_eq!(parsed_destination_id, recv_destination_id.to_vec());
        }
        assert_eq!(packet.payload, b"hello, world");

        // verify signature
        {
            let destination = packet.flags.from_included().clone().unwrap();
            let verifying_key = destination.verifying_key().clone();
            let signature = packet.flags.signature().clone().unwrap();
            let signature_offset = serialized.len() - SIGNATURE_LEN - packet.payload.len();

            let mut copy = serialized.clone();
            copy[signature_offset..signature_offset + SIGNATURE_LEN].copy_from_slice(&[0u8; 64]);
            verifying_key.verify(&copy, signature).unwrap();
        }
    }

    #[test]
    fn build_ack_packet() {
        let serialized = PacketBuilder::new(1337)
            .with_send_stream_id(1338)
            .with_ack_through(10)
            .with_nacks(vec![1, 3, 5, 7, 9])
            .build();

        let packet = Packet::parse::<MockRuntime>(&serialized).unwrap();

        assert!(!packet.flags.synchronize());
        assert!(!packet.flags.close());
        assert!(!packet.flags.reset());
        assert!(!packet.flags.echo());
        assert!(!packet.flags.no_ack());

        assert_eq!(packet.ack_through, 10);
        assert_eq!(packet.nacks, vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn peek_packet() {
        let serialized = PacketBuilder::new(13371338)
            .with_send_stream_id(13351336)
            .with_seq_nro(1337)
            .with_synchronize()
            .with_reset()
            .build();

        let info = Packet::peek(&serialized).unwrap();

        assert!(info.synchronize());
        assert!(info.reset());
        assert_eq!(info.recv_stream_id, 13371338);
        assert_eq!(info.send_stream_id, 13351336);
        assert_eq!(info.seq_nro, 1337);
    }

    #[test]
    #[should_panic]
    fn call_build_and_sign_without_signature() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let recv_destination_id = DestinationId::random();
        let mut payload = "hello, world".as_bytes();

        let recv_stream_id = MockRuntime::rng().next_u32();

        let serialized = PacketBuilder::new(recv_stream_id)
            .with_send_stream_id(0)
            .with_synchronize()
            .with_replay_protection(&recv_destination_id)
            .with_resend_delay(128)
            .with_from_included(destination.clone())
            .with_payload(&payload)
            .build_and_sign(&signing_key);
    }

    #[test]
    #[should_panic]
    fn call_build_with_signature() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let recv_destination_id = DestinationId::random();
        let mut payload = "hello, world".as_bytes();

        let recv_stream_id = MockRuntime::rng().next_u32();

        let serialized = PacketBuilder::new(recv_stream_id)
            .with_send_stream_id(0)
            .with_synchronize()
            .with_signature()
            .with_replay_protection(&recv_destination_id)
            .with_resend_delay(128)
            .with_from_included(destination.clone())
            .with_payload(&payload)
            .build();
    }

    #[test]
    fn maximum_nacks() {
        let nacks = (0..u8::MAX).map(|i| i as u32).collect::<Vec<_>>();
        let serialized = PacketBuilder::new(13371338)
            .with_send_stream_id(13351336)
            .with_seq_nro(1337)
            .with_nacks(nacks)
            .with_synchronize()
            .with_reset()
            .build();

        let info = Packet::peek(&serialized).unwrap();

        assert!(info.synchronize());
        assert!(info.reset());
    }
}
