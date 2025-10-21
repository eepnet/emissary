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
    crypto::StaticPrivateKey,
    i2cp::payload::I2cpParameters,
    primitives::{Date, Destination, LeaseSet2, Mapping, Str},
    runtime::Runtime,
};

use bytes::Bytes;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
};

use alloc::vec::Vec;
use core::{fmt, time::Duration};

pub use bandwidth::BandwidthLimits;
pub use host_reply::{HostReply, HostReplyKind};
pub use lease_set::RequestVariableLeaseSet;
pub use payload::MessagePayload;
pub use session_status::{SessionStatus, SessionStatusKind};
pub use set_date::SetDate;

mod bandwidth;
mod host_reply;
mod lease_set;
mod payload;
mod session_status;
mod set_date;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::message";

/// I2CP header length.
///
/// Header is payload size (4 bytes) + message type (1 bytes).
pub const I2CP_HEADER_SIZE: usize = 5;

/// Signature length.
const SIGNATURE_LEN: usize = 64usize;

/// Session ID.
#[derive(Debug)]
pub enum SessionId {
    /// Session with iD.
    Session(u16),

    /// No session, special value `0xffff`;
    NoSession,
}

impl SessionId {
    /// Serialize [`SessionId`].
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Session(session_id) => session_id,
            Self::NoSession => 0xffff,
        }
    }
}

impl From<u16> for SessionId {
    fn from(value: u16) -> Self {
        match value {
            0xffff => SessionId::NoSession,
            value => SessionId::Session(value),
        }
    }
}

/// Request kind for host lookups.
pub enum RequestKind {
    /// Host name.
    HostName {
        /// Host name.
        host_name: Str,
    },

    /// Hash.
    Hash {
        /// SHA256 hash.
        hash: Vec<u8>,
    },
}

impl fmt::Debug for RequestKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostName { host_name } =>
                f.debug_struct("RequestKind::HostName").field("host_name", &host_name).finish(),
            Self::Hash { .. } => f.debug_struct("RequestKind::Hash").finish_non_exhaustive(),
        }
    }
}

/// I2CP message type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    /// Bandwidth limit
    BandwidthLimits,

    /// Binding info.
    BlindingInfo,

    /// Create `LeaseSet`.
    CreateLeaseSet,

    /// Create `LeaseSet2`.
    CreateLeaseSet2,

    /// Create session.
    CreateSession,

    /// Lookup destination.
    DestLookup,

    /// Destination lookup reply.
    DestReply,

    /// Destroy session.
    DestroySession,

    /// Disconnect connection.
    Disconnect,

    /// Get bandwidth limits.
    GetBandwidthLimits,

    /// Get date.
    GetDate,

    /// Lookup host.
    HostLookup,

    /// Host lookup reply.
    HostReply,

    /// Delivery payload of message to client.
    MessagePayload,

    /// Notify client of a delivery status.
    MessageStatus,

    /// Start reception of a message.
    ReceiveMessageBegin,

    /// Inform router that a message was delivered successfully.
    ReceiveMessageEnd,

    /// Reconfigure session.
    ReconfigureSession,

    /// Report abuse.
    ReportAbuse,

    /// Request `LeaseSet`.
    RequestLeaseSet,

    /// Request `VariableLeaseSet`.
    RequestVariableLeaseSet,

    /// Send message to remote router.
    SendMessage,

    /// Send message to remote router with expiration and options.
    SendMessageExpires,

    /// Inform client about the status of the session.
    SessionStatus,

    /// Set date.
    SetDate,
}

impl MessageType {
    /// Serialize [`MessageType`].
    pub fn as_u8(self) -> u8 {
        match self {
            Self::BandwidthLimits => 23,
            Self::BlindingInfo => 42,
            Self::CreateLeaseSet => 4,
            Self::CreateLeaseSet2 => 41,
            Self::CreateSession => 1,
            Self::DestLookup => 34,
            Self::DestReply => 35,
            Self::DestroySession => 3,
            Self::Disconnect => 30,
            Self::GetBandwidthLimits => 8,
            Self::GetDate => 32,
            Self::HostLookup => 38,
            Self::HostReply => 39,
            Self::MessagePayload => 31,
            Self::MessageStatus => 22,
            Self::ReceiveMessageBegin => 6,
            Self::ReceiveMessageEnd => 7,
            Self::ReconfigureSession => 2,
            Self::ReportAbuse => 29,
            Self::RequestLeaseSet => 21,
            Self::RequestVariableLeaseSet => 37,
            Self::SendMessage => 5,
            Self::SendMessageExpires => 36,
            Self::SessionStatus => 20,
            Self::SetDate => 33,
        }
    }

    /// Try to convert `msg_type` into `MessageType`.
    pub fn from_u8(msg_type: u8) -> Option<Self> {
        match msg_type {
            23 => Some(Self::BandwidthLimits),
            42 => Some(Self::BlindingInfo),
            4 => Some(Self::CreateLeaseSet),
            41 => Some(Self::CreateLeaseSet2),
            1 => Some(Self::CreateSession),
            34 => Some(Self::DestLookup),
            35 => Some(Self::DestReply),
            3 => Some(Self::DestroySession),
            30 => Some(Self::Disconnect),
            8 => Some(Self::GetBandwidthLimits),
            32 => Some(Self::GetDate),
            38 => Some(Self::HostLookup),
            39 => Some(Self::HostReply),
            31 => Some(Self::MessagePayload),
            22 => Some(Self::MessageStatus),
            6 => Some(Self::ReceiveMessageBegin),
            7 => Some(Self::ReceiveMessageEnd),
            2 => Some(Self::ReconfigureSession),
            29 => Some(Self::ReportAbuse),
            21 => Some(Self::RequestLeaseSet),
            37 => Some(Self::RequestVariableLeaseSet),
            5 => Some(Self::SendMessage),
            36 => Some(Self::SendMessageExpires),
            20 => Some(Self::SessionStatus),
            33 => Some(Self::SetDate),
            byte => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?byte,
                    "unknown i2cp message type",
                );
                None
            }
        }
    }
}

/// I2CP message.
#[allow(unused)]
pub enum Message {
    /// Bandwidth limit
    BandwidthLimits,

    /// Binding info.
    BlindingInfo,

    /// Create `LeaseSet`.
    CreateLeaseSet,

    /// Create `LeaseSet2`.
    CreateLeaseSet2 {
        /// Session ID.
        session_id: SessionId,

        /// SHA256 of the `Destination`.
        ///
        /// `leaseset` needs to be stored in `key` in `NetDb`.
        key: Bytes,

        /// Serialized `LeaseSet2`.
        leaseset: Bytes,

        /// Encryption private keys.
        private_keys: Vec<StaticPrivateKey>,
    },

    /// Create session.
    CreateSession {
        /// Destination.
        destination: Destination,

        /// Create date.
        date: Date,

        /// Session options.
        options: Mapping,
    },

    /// Lookup destination.
    DestLookup,

    /// Destination lookup reply.
    DestReply,

    /// Destroy session.
    DestroySession {
        /// Session ID.
        session_id: SessionId,
    },

    /// Disconnect connection.
    Disconnect,

    /// Get bandwidth limits.
    GetBandwidthLimits,

    /// Get date.
    GetDate {
        /// I2CP version.
        version: Str,

        /// Options.
        options: Mapping,
    },

    /// Lookup host.
    HostLookup {
        /// Session ID.
        session_id: SessionId,

        /// Request ID.
        request_id: u32,

        /// Timeout.
        timeout: Duration,

        /// Lookup kind.
        kind: RequestKind,
    },

    /// Host lookup reply.
    HostReply,

    /// Delivery payload of message to client.
    MessagePayload,

    /// Notify client of a delivery status.
    MessageStatus,

    /// Start reception of a message.
    ReceiveMessageBegin,

    /// Inform router that a message was delivered successfully.
    ReceiveMessageEnd,

    /// Reconfigure session.
    ReconfigureSession,

    /// Report abuse.
    ReportAbuse,

    /// Request `LeaseSet`.
    RequestLeaseSet,

    /// Request `VariableLeaseSet`.
    RequestVariableLeaseSet,

    /// Send message to remote router.
    SendMessage,

    /// Send message to remote router with expiration and options.
    SendMessageExpires {
        /// Session ID.
        session_id: SessionId,

        /// Destination.
        destination: Destination,

        /// I2CP protocol parameters.
        parameters: I2cpParameters,

        /// Serialized I2CP payload.
        payload: Vec<u8>,

        /// Nonce.
        nonce: u32,

        /// Options,
        options: u16,

        /// Message expiration, as duration since UNIX epoch.
        expires: Duration,
    },

    /// Inform client about the status of the session.
    SessionStatus,

    /// Set date.
    SetDate {
        /// Date.
        date: Date,

        /// Version.
        version: Str,
    },
}

impl Message {
    /// Attempt to parse [`Message::GetDate`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#getdatemessage
    fn parse_get_date(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, version) = Str::parse_frame(input.as_ref()).ok()?;
        let (rest, options) = Mapping::parse_frame(rest).ok()?;

        debug_assert!(rest.is_empty());

        Some(Message::GetDate { version, options })
    }

    /// Attempt to parse [`Message::SetDate`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#setdatemessage
    fn parse_set_date(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, date) = Date::parse_frame(input.as_ref()).ok()?;
        let (rest, version) = Str::parse_frame(rest).ok()?;

        debug_assert!(rest.is_empty());

        Some(Message::SetDate { date, version })
    }

    /// Attempt to parse [`Message::GetBandwidthLimits`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#getbandwidthlimitsmessage
    fn parse_get_bandwidth_limits(input: impl AsRef<[u8]>) -> Option<Self> {
        debug_assert!(input.as_ref().is_empty());

        Some(Message::GetBandwidthLimits)
    }

    /// Attempt to parse [`Message::DestroySession`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#destroysessionmessage
    fn parse_destroy_session(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, session_id) = be_u16::<_, ()>(input.as_ref()).ok()?;

        debug_assert!(rest.is_empty());

        Some(Message::DestroySession {
            session_id: SessionId::from(session_id),
        })
    }

    /// Attempt to parse [`Message::CreateSession`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#createsessionmessage
    fn parse_create_session(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, destination) = Destination::parse_frame(input.as_ref()).ok()?;
        let (rest, options) = Mapping::parse_frame(rest).ok()?;
        let (rest, date) = Date::parse_frame(rest).ok()?;
        let (_rest, signature) = take::<_, _, ()>(SIGNATURE_LEN)(rest).ok()?;

        if let Err(error) = destination.verifying_key().verify(
            &input.as_ref()[..input.as_ref().len() - SIGNATURE_LEN],
            signature,
        ) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to verify `CreateSession` signature",
            );

            return None;
        }

        Some(Message::CreateSession {
            destination,
            date,
            options,
        })
    }

    /// Attempt to parse [`Message::HostLookup`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#hostlookupmessage
    fn parse_host_lookup(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, session_id) = be_u16::<_, ()>(input.as_ref()).ok()?;
        let (rest, request_id) = be_u32::<_, ()>(rest).ok()?;
        let (rest, timeout) = be_u32::<_, ()>(rest).ok()?;
        let (rest, kind) = be_u8::<_, ()>(rest).ok()?;

        let kind = match kind {
            0 => RequestKind::Hash {
                hash: take::<_, _, ()>(32usize)(rest).ok()?.1.to_vec(),
            },
            1 => RequestKind::HostName {
                host_name: Str::parse_frame(rest).ok()?.1,
            },
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    "invalid host lookup kind",
                );
                return None;
            }
        };

        Some(Message::HostLookup {
            session_id: SessionId::from(session_id),
            request_id,
            timeout: Duration::from_millis(timeout as u64),
            kind,
        })
    }

    /// Attempt to parse [`Message::CreateLeaseSet2`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#createleaseset2message
    fn parse_create_leaseset2<R: Runtime>(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, session_id) = be_u16::<_, ()>(input.as_ref()).ok()?;
        let (rest, kind) = be_u8::<_, ()>(rest).ok()?;

        let (rest, key, leaseset) = match kind {
            3 => {
                // parse `LeaseSet2` from input to verify it's valid and supports correct crypto
                //
                // emissary discards unneeded date from the `Destination`/`LeaseSet2` when it
                // deserializes them which would make the parsed `LeaseSet2` unpublishable as
                // `emissary` cannot recreate and sign it since it doesn't hold the signing key for
                // the client
                //
                // in order to keep the `LeaseSet2` publishable, parse the raw byte vector from
                // input and return that in `Message::CreateLeaseSet2` so it can be published
                // unmodified to `NetDb`
                let (rest, parsed) = LeaseSet2::parse_frame::<R>(rest).ok()?;

                (
                    rest,
                    Bytes::from(parsed.header.destination.id().to_vec()),
                    Bytes::from(input.as_ref()[3..(input.as_ref().len() - rest.len())].to_vec()),
                )
            }
            1 => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "leasesets not supported",
                );
                return None;
            }
            5 => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "encrypted leasesets not supported",
                );
                return None;
            }
            7 => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "meta leasesets not supported",
                );
                return None;
            }
            _ => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?kind,
                    "invalid leaseset kind",
                );
                return None;
            }
        };

        let (rest, num_private_keys) = be_u8::<_, ()>(rest).ok()?;
        let (_rest, private_keys) = (0..num_private_keys).try_fold(
            (rest, Vec::<StaticPrivateKey>::new()),
            |(rest, mut keys), _| {
                let (rest, key_kind) = be_u16::<_, ()>(rest).ok()?;
                let (rest, key_length) = be_u16::<_, ()>(rest).ok()?;
                let (rest, key) = take::<_, _, ()>(key_length)(rest).ok()?;

                match key_kind {
                    0x0004 if key_length == 32 => {
                        keys.push(StaticPrivateKey::from_bytes(key)?);

                        Some((rest, keys))
                    }
                    key_kind => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?key_kind,
                            "unsupported key kind",
                        );
                        None
                    }
                }
            },
        )?;

        if private_keys.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                "no encryption keys",
            );
        }

        Some(Message::CreateLeaseSet2 {
            session_id: SessionId::from(session_id),
            key,
            leaseset,
            private_keys,
        })
    }

    /// Attempt to parse [`Message::SendMessageExpires`] from `input`.
    ///
    /// https://geti2p.net/spec/i2cp#sendmessageexpiresmessage
    fn parse_send_message_expires(input: impl AsRef<[u8]>) -> Option<Self> {
        let (rest, session_id) = be_u16::<_, ()>(input.as_ref()).ok()?;
        let (rest, destination) = Destination::parse_frame(rest).ok()?;
        let (rest, payload_len) = be_u32::<_, ()>(rest).ok()?;
        let (rest, payload) = take::<_, _, ()>(payload_len)(rest).ok()?;
        let (rest, nonce) = be_u32::<_, ()>(rest).ok()?;
        let (rest, options) = be_u16::<_, ()>(rest).ok()?;
        let expires = {
            let expiration = take::<_, _, ()>(6usize)(rest).ok()?.1;
            let mut extended = [0u8; 8];
            extended[2..].copy_from_slice(expiration);

            Duration::from_millis(u64::from_be_bytes(extended))
        };

        let Some(parameters) = I2cpParameters::new(payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                ?session_id,
                "invalid i2cp payload",
            );
            return None;
        };

        Some(Message::SendMessageExpires {
            session_id: SessionId::from(session_id),
            destination,
            parameters,
            payload: payload.to_vec(),
            nonce,
            options,
            expires,
        })
    }

    /// Attempt to parse `input` into [`Message`].
    pub fn parse<R: Runtime>(msg_type: MessageType, input: impl AsRef<[u8]>) -> Option<Self> {
        match msg_type {
            MessageType::GetDate => Self::parse_get_date(input),
            MessageType::SetDate => Self::parse_set_date(input),
            MessageType::GetBandwidthLimits => Self::parse_get_bandwidth_limits(input),
            MessageType::DestroySession => Self::parse_destroy_session(input),
            MessageType::CreateSession => Self::parse_create_session(input),
            MessageType::HostLookup => Self::parse_host_lookup(input),
            MessageType::CreateLeaseSet2 => Self::parse_create_leaseset2::<R>(input),
            MessageType::SendMessageExpires => Self::parse_send_message_expires(input),
            msg_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?msg_type,
                    "parser not implemented",
                );

                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::mock::MockRuntime;

    use super::*;

    #[test]
    fn parse_create_leaseset2() {
        let message = vec![
            0, 2, 3, 161, 188, 214, 236, 128, 189, 119, 155, 149, 15, 103, 59, 133, 120, 146, 190,
            219, 94, 244, 254, 170, 105, 111, 60, 33, 87, 105, 100, 147, 146, 113, 201, 161, 188,
            214, 236, 128, 189, 119, 155, 149, 15, 103, 59, 133, 120, 146, 190, 219, 94, 244, 254,
            170, 105, 111, 60, 33, 87, 105, 100, 147, 146, 113, 201, 161, 188, 214, 236, 128, 189,
            119, 155, 149, 15, 103, 59, 133, 120, 146, 190, 219, 94, 244, 254, 170, 105, 111, 60,
            33, 87, 105, 100, 147, 146, 113, 201, 161, 188, 214, 236, 128, 189, 119, 155, 149, 15,
            103, 59, 133, 120, 146, 190, 219, 94, 244, 254, 170, 105, 111, 60, 33, 87, 105, 100,
            147, 146, 113, 201, 161, 188, 214, 236, 128, 189, 119, 155, 149, 15, 103, 59, 133, 120,
            146, 190, 219, 94, 244, 254, 170, 105, 111, 60, 33, 87, 105, 100, 147, 146, 113, 201,
            161, 188, 214, 236, 128, 189, 119, 155, 149, 15, 103, 59, 133, 120, 146, 190, 219, 94,
            244, 254, 170, 105, 111, 60, 33, 87, 105, 100, 147, 146, 113, 201, 161, 188, 214, 236,
            128, 189, 119, 155, 149, 15, 103, 59, 133, 120, 146, 190, 219, 94, 244, 254, 170, 105,
            111, 60, 33, 87, 105, 100, 147, 146, 113, 201, 161, 188, 214, 236, 128, 189, 119, 155,
            149, 15, 103, 59, 133, 120, 146, 190, 219, 94, 244, 254, 170, 105, 111, 60, 33, 87,
            105, 100, 147, 146, 113, 201, 161, 188, 214, 236, 128, 189, 119, 155, 149, 15, 103, 59,
            133, 120, 146, 190, 219, 94, 244, 254, 170, 105, 111, 60, 33, 87, 105, 100, 147, 146,
            113, 201, 161, 188, 214, 236, 128, 189, 119, 155, 149, 15, 103, 59, 133, 120, 146, 190,
            219, 94, 244, 254, 170, 105, 111, 60, 33, 87, 105, 100, 147, 146, 113, 201, 161, 188,
            214, 236, 128, 189, 119, 155, 149, 15, 103, 59, 133, 120, 146, 190, 219, 94, 244, 254,
            170, 105, 111, 60, 33, 87, 105, 100, 147, 146, 113, 201, 55, 230, 91, 80, 122, 122, 80,
            230, 218, 220, 163, 141, 116, 3, 154, 178, 46, 33, 45, 176, 86, 88, 53, 55, 134, 6,
            142, 105, 68, 152, 7, 222, 5, 0, 4, 0, 7, 0, 0, 103, 4, 36, 95, 2, 87, 0, 0, 0, 0, 1,
            0, 4, 0, 32, 19, 126, 50, 234, 104, 194, 242, 90, 231, 249, 16, 61, 140, 95, 139, 51,
            191, 75, 145, 72, 239, 39, 170, 37, 3, 90, 126, 236, 0, 63, 150, 1, 1, 249, 0, 187,
            182, 11, 128, 61, 16, 80, 73, 190, 216, 57, 137, 166, 213, 35, 195, 36, 79, 56, 118,
            161, 49, 37, 5, 174, 148, 94, 114, 242, 7, 191, 145, 154, 197, 103, 4, 38, 182, 179,
            59, 226, 238, 95, 209, 4, 132, 89, 207, 155, 202, 52, 193, 120, 84, 210, 180, 114, 204,
            152, 224, 101, 25, 129, 155, 98, 137, 183, 232, 231, 62, 182, 0, 228, 184, 67, 239,
            239, 110, 98, 62, 71, 23, 146, 128, 244, 117, 50, 157, 17, 49, 46, 201, 99, 89, 109,
            216, 180, 195, 236, 57, 92, 8, 1, 0, 4, 0, 32, 214, 240, 124, 122, 202, 10, 154, 164,
            239, 93, 80, 233, 10, 158, 39, 174, 132, 26, 242, 214, 53, 186, 119, 19, 61, 184, 149,
            26, 115, 111, 255, 68,
        ];

        assert!(Message::parse::<MockRuntime>(MessageType::CreateLeaseSet2, &message).is_some());
    }
}
