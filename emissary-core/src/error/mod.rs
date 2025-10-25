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
    error::parser::PacketParseError,
    i2np::Message,
    primitives::{MessageId, TunnelId},
    transport::TerminationReason,
};

use alloc::string::String;
use core::fmt;

pub mod parser;

/// SSU2 error.
#[derive(Debug, PartialEq, Eq)]
pub enum Ssu2Error {
    /// Encryption/decryption error.
    Chacha,

    /// Channel error.
    Channel(ChannelError),

    /// Invalid protocol version.
    InvalidVersion,

    /// Malformed packet.
    Malformed,

    /// Packet is too short.
    NotEnoughBytes,

    /// Session terminated.
    SessionTerminated(TerminationReason),

    /// Unexpected message.
    UnexpectedMessage,

    /// Token mismatch.
    TokenMismatch,

    /// Network mismatch.
    NetworkMismatch,
}

impl fmt::Display for Ssu2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chacha => write!(f, "encryption/decryption error"),
            Self::Channel(error) => write!(f, "{error}"),
            Self::InvalidVersion => write!(f, "invalid protocol version"),
            Self::Malformed => write!(f, "malformed packet"),
            Self::NotEnoughBytes => write!(f, "packet is too short"),
            Self::SessionTerminated(reason) => write!(f, "session forcibly terminated: {reason:?}"),
            Self::UnexpectedMessage => write!(f, "unexpected message"),
            Self::TokenMismatch => write!(f, "token mismatch"),
            Self::NetworkMismatch => write!(f, "network mismatch"),
        }
    }
}

/// Connection error.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    /// Session terminated forcibly due to protocol error.
    SessionTerminated,

    /// Unknown garlic tag.
    UnknownTag,

    /// Message was malformed.
    Malformed,

    /// Encryption/decryption error.
    Chacha,

    /// State machine has entered an invalid state.
    InvalidState,

    /// Invalid key.
    InvalidKey,

    /// New session message has an invalid timestamp
    Timestamp,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionTerminated => write!(f, "session forcibly terminated"),
            Self::UnknownTag => write!(f, "unknown garlic tag"),
            Self::Malformed => write!(f, "malformed message"),
            Self::Chacha => write!(f, "encryption/decryption error"),
            Self::InvalidState => write!(f, "invalid state"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::Timestamp => write!(f, "excess message timestamp skew"),
        }
    }
}

/// Connection error.
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionError {
    /// Socket closed.
    SocketClosed,

    /// Failed to bind to socket.
    BindFailure,

    /// Keep-alive timeout.
    KeepAliveTimeout,

    /// Read timeout.
    ReadTimeout,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketClosed => write!(f, "socket closed"),
            Self::BindFailure => write!(f, "failed to bind to socket"),
            Self::KeepAliveTimeout => write!(f, "keep-alive timeout"),
            Self::ReadTimeout => write!(f, "read timeout"),
        }
    }
}

/// I2CP error.
#[derive(Debug, PartialEq, Eq)]
pub enum I2cpError {
    /// Invalid control byte read from the client.
    InvalidProtocolByte(u8),
}

impl fmt::Display for I2cpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolByte(byte) => write!(f, "invalid protocol byte ({byte})"),
        }
    }
}

/// Query error.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QueryError {
    /// No floodfills.
    NoFloodfills,

    /// Query timed out.
    Timeout,

    /// Value not found.
    ValueNotFound,

    /// Malformed reply.
    Malformed,

    /// Retry limimt reached.
    RetryFailure,

    /// No tunnel available to send/receive query/query result.
    NoTunnel,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFloodfills => write!(f, "no floodfills"),
            Self::Timeout => write!(f, "query timed out"),
            Self::ValueNotFound => write!(f, "value not found"),
            Self::Malformed => write!(f, "malformed reply"),
            Self::RetryFailure => write!(f, "operation retried too many times"),
            Self::NoTunnel => write!(f, "no tunnel available"),
        }
    }
}

/// Streaming protocol error.
#[derive(Debug, PartialEq, Eq)]
pub enum StreamingError {
    /// Mismatch between send and receive stream IDs.
    StreamIdMismatch(u32, u32),

    /// Signature missing from `SYN` packet.
    SignatureMissing,

    /// Destination mssing from `SYN` packet.
    DestinationMissing,

    /// Verifying key missing from included destination.
    VerifyingKeyMissing,

    /// Replay protection check failed.
    ///
    /// NACk field didn't contain destination's ID.
    ReplayProtectionCheckFailed,

    /// Invalid signature.
    InvalidSignature,

    /// Malformed packet.
    Malformed(PacketParseError),

    /// Listener kind mismatch.
    ///
    /// Persistent listener registered when one or more ephemeral listeners
    /// are active or vice versa.
    ListenerMismatch,

    /// Stream closed.
    Closed,

    /// Receive window is full.
    ReceiveWindowFull,

    /// Sequence number for the packet is unexpected high.
    SequenceNumberTooHigh,
}

impl From<PacketParseError> for StreamingError {
    fn from(value: PacketParseError) -> Self {
        Self::Malformed(value)
    }
}

impl fmt::Display for StreamingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamIdMismatch(send, recv) => {
                write!(f, "stream mismatch: {send} (send) vs {recv} (recv)")
            }
            Self::SignatureMissing => write!(f, "signature missing"),
            Self::DestinationMissing => write!(f, "destination missing"),
            Self::VerifyingKeyMissing => write!(f, "verifying key mssing"),
            Self::ReplayProtectionCheckFailed => {
                write!(f, "nack field didn't contain correct destination id")
            }
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::Malformed(error) => write!(f, "malformed packet: {error:?}"),
            Self::ListenerMismatch => write!(f, "listener kind mismatch"),
            Self::Closed => write!(f, "stream closed"),
            Self::ReceiveWindowFull => write!(f, "receive window is full"),
            Self::SequenceNumberTooHigh => {
                write!(f, "sequnce number for the packet is unexpectedly high")
            }
        }
    }
}

/// Channel error.
#[derive(Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// Channel is full.
    Full,

    /// Channel is closed.
    Closed,

    /// Channel doesn't exist.
    DoesntExist,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "channel full"),
            Self::Closed => write!(f, "channel closed"),
            Self::DoesntExist => write!(f, "channel doesn't exist"),
        }
    }
}

/// Tunnel message rejection reason.
#[derive(Debug, PartialEq, Eq)]
pub enum RejectionReason {
    /// Message/operation not supported.
    NotSupported,

    /// Invalid checksum.
    InvalidChecksum,
}

/// Tunnel error.
#[derive(Debug, PartialEq, Eq)]
pub enum TunnelError {
    /// Tunnel doesn't exist.
    TunnelDoesntExist(TunnelId),

    /// Invalid hop role for an operation.
    InvalidHop,

    /// Too many hops.
    TooManyHops(usize),

    /// Not enough hops.
    NotEnoughHops(usize),

    /// Invalid tunnel message.
    InvalidMessage,

    /// Tunnel rejected.
    TunnelRejected(u8),

    /// Local record not found in the build request.
    RecordNotFound,

    /// Tunnel message rejected.
    ///
    /// This is different from tunnel rejection.
    MessageRejected(RejectionReason),

    /// Message doesn't exist.
    MessageDoesntExist(MessageId),
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TunnelDoesntExist(tunnel_id) => write!(f, "tunnel ({tunnel_id}) does't exist"),
            Self::InvalidHop => write!(f, "invalid hop role for operation"),
            Self::TooManyHops(hops) => write!(f, "too many hops {hops}"),
            Self::InvalidMessage => write!(f, "invalid tunnel message"),
            Self::TunnelRejected(reason) => write!(f, "tunnel rejected: {reason}"),
            Self::NotEnoughHops(hops) => write!(f, "not enough hops {hops}"),
            Self::RecordNotFound => write!(f, "local record not found"),
            Self::MessageRejected(reason) => write!(f, "message rejected, reason: {reason:?}"),
            Self::MessageDoesntExist(message_id) => {
                write!(f, "message doesn't exist: {message_id}")
            }
        }
    }
}

/// Route kind for [`RoutingError::RouteNotFound`].
#[derive(Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// Tunnel not found.
    Tunnel(TunnelId),

    /// Listener for message not found.
    #[allow(unused)]
    Message(MessageId),
}

impl fmt::Display for RouteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tunnel(tunnel_id) => write!(f, "{tunnel_id:?}"),
            Self::Message(message_id) => write!(f, "{message_id:?}"),
        }
    }
}

/// Message routing error.
#[derive(Debug)]
pub enum RoutingError {
    /// Route not found.
    #[allow(unused)]
    RouteNotFound(Message, RouteKind),

    /// Failed to parse route from message.
    ///
    /// Message is invalid and doesn't contain a route.
    #[allow(unused)]
    FailedToParseRoute(Message),

    /// Channel full.
    #[allow(unused)]
    ChannelFull(Message),

    /// Channel closed.
    #[allow(unused)]
    ChannelClosed(Message),

    /// Tunnel already exists in the routing table.
    TunnelExists(TunnelId),
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteNotFound(_, route) => write!(f, "route not found: {route}"),
            Self::FailedToParseRoute(_) => write!(f, "failed to parse route"),
            Self::ChannelFull(_) => write!(f, "channel full"),
            Self::ChannelClosed(_) => write!(f, "channel closed"),
            Self::TunnelExists(tunnel_id) => {
                write!(f, "tunnel ({tunnel_id}) exists in the routing table")
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Ed25519(ed25519_dalek::ed25519::Error),
    Chacha20Poly1305(chacha20poly1305::Error),
    InvalidData,
    InvalidState,
    NonceOverflow,
    NotSupported,
    EssentialTaskClosed,
    RouterDoesntExist,
    DialFailure,
    Timeout,
    Tunnel(TunnelError),
    Channel(ChannelError),
    Streaming(StreamingError),
    Query(QueryError),
    I2cp(I2cpError),
    Connection(ConnectionError),
    Custom(String),
    Missing,
    Session(SessionError),
    NetworkMismatch,
    Expired,
    Routing(RoutingError),
    Duplicate,
    Ssu2(Ssu2Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(error) => write!(f, "ed25519 error: {error:?}"),
            Self::Chacha20Poly1305(error) => write!(f, "chacha20poly1305 error: {error:?}"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::InvalidState => write!(f, "invalid state"),
            Self::NonceOverflow => write!(f, "nonce overflow"),
            Self::NotSupported => write!(f, "protocol or operation not supported"),
            Self::EssentialTaskClosed => write!(f, "essential task closed"),
            Self::RouterDoesntExist => write!(f, "router doesn't exist"),
            Self::DialFailure => write!(f, "dial failure"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::Tunnel(error) => write!(f, "tunnel error: {error}"),
            Self::Channel(error) => write!(f, "channel error: {error}"),
            Self::Streaming(error) => write!(f, "streaming protocol error: {error}"),
            Self::Query(error) => write!(f, "query error: {error}"),
            Self::I2cp(error) => write!(f, "i2cp error: {error}"),
            Self::Connection(error) => write!(f, "connection error: {error}"),
            Self::Custom(error) => write!(f, "{error}"),
            Self::Missing => write!(f, "value missing"),
            Self::Session(error) => write!(f, "session error: {error}"),
            Self::NetworkMismatch => write!(f, "network mismatch"),
            Self::Expired => write!(f, "message has expired"),
            Self::Routing(error) => write!(f, "routing: {error}"),
            Self::Duplicate => write!(f, "duplicate message"),
            Self::Ssu2(error) => write!(f, "ssu2: {error}"),
        }
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        Error::Ed25519(value)
    }
}

impl From<chacha20poly1305::Error> for Error {
    fn from(value: chacha20poly1305::Error) -> Self {
        Error::Chacha20Poly1305(value)
    }
}

// TODO: not good, fix chacha error
impl From<Error> for SessionError {
    fn from(_: Error) -> Self {
        SessionError::Chacha
    }
}

// TODO: not good, fix chacha error
impl From<Error> for Ssu2Error {
    fn from(_: Error) -> Self {
        Ssu2Error::Chacha
    }
}

impl From<RoutingError> for Error {
    fn from(value: RoutingError) -> Self {
        Error::Routing(value)
    }
}

impl<T> From<thingbuf::mpsc::errors::TrySendError<T>> for ChannelError {
    fn from(value: thingbuf::mpsc::errors::TrySendError<T>) -> Self {
        match value {
            thingbuf::mpsc::errors::TrySendError::Full(_) => ChannelError::Full,
            thingbuf::mpsc::errors::TrySendError::Closed(_) => ChannelError::Closed,
            _ => unreachable!(),
        }
    }
}

impl<T> From<thingbuf::mpsc::errors::TrySendError<T>> for Ssu2Error {
    fn from(value: thingbuf::mpsc::errors::TrySendError<T>) -> Self {
        match value {
            thingbuf::mpsc::errors::TrySendError::Full(_) => Ssu2Error::Channel(ChannelError::Full),
            thingbuf::mpsc::errors::TrySendError::Closed(_) =>
                Ssu2Error::Channel(ChannelError::Closed),
            _ => unreachable!(),
        }
    }
}

impl From<thingbuf::mpsc::errors::TrySendError<Message>> for RoutingError {
    fn from(value: thingbuf::mpsc::errors::TrySendError<Message>) -> Self {
        match value {
            thingbuf::mpsc::errors::TrySendError::Full(message) =>
                RoutingError::ChannelFull(message),
            thingbuf::mpsc::errors::TrySendError::Closed(message) =>
                RoutingError::ChannelClosed(message),
            _ => unreachable!(),
        }
    }
}
