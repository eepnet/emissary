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
    crypto::{base32_decode, base64_decode, SigningPrivateKey, StaticPrivateKey},
    primitives::{Destination, DestinationId},
    runtime::Runtime,
};

use hashbrown::HashMap;
use nom::{
    branch::alt,
    bytes::complete::{escaped, is_not, tag, take, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0},
    combinator::{map, opt, recognize},
    error::{make_error, ErrorKind},
    multi::{many0, many0_count},
    sequence::{delimited, pair, preceded, separated_pair, tuple},
    Err, IResult, Parser,
};

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{fmt, marker::PhantomData};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::parser";

/// Parsed command.
///
/// Represent a command that had value form but isn't necessarily
/// a command that `yosemite` recognizes.
struct ParsedCommand<'a, R: Runtime> {
    /// Command
    ///
    /// Supported values: `HELLO`, `STATUS` and `STREAM`.
    command: &'a str,

    /// Subcommand.
    ///
    /// Supported values: `REPLY` for `HELLO`, `STATUS` for `SESSION`/`STREAM`.
    subcommand: Option<&'a str>,

    /// Parsed key-value pairs.
    key_value_pairs: HashMap<&'a str, &'a str>,

    /// Marker for `Runtime.`
    _runtime: PhantomData<R>,
}

/// Session kind.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionKind {
    /// Streaming.
    Stream,

    /// Repliable datagram.
    Datagram,

    /// Anonymous datagrams.
    Anonymous,

    /// Primary sessions.
    Primary,
}

/// Supported SAM versions.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SamVersion {
    /// v3.1
    V31,

    /// V3.2
    V32,

    /// V3.3
    V33,
}

impl TryFrom<&str> for SamVersion {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "3.1" => Ok(SamVersion::V31),
            "3.2" => Ok(SamVersion::V32),
            "3.3" => Ok(SamVersion::V33),
            _ => Err(()),
        }
    }
}

impl fmt::Display for SamVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V31 => write!(f, "3.1"),
            Self::V32 => write!(f, "3.2"),
            Self::V33 => write!(f, "3.3"),
        }
    }
}

/// Destination context.
#[derive(Clone)]
pub struct DestinationContext {
    /// Destination.
    pub destination: Destination,

    /// Private key of the destination.
    pub private_key: Box<StaticPrivateKey>,

    /// Signing key of the destination.
    pub signing_key: Box<SigningPrivateKey>,
}

impl fmt::Debug for DestinationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationContext").finish_non_exhaustive()
    }
}

impl PartialEq for DestinationContext {
    fn eq(&self, other: &Self) -> bool {
        self.destination == other.destination
            && (*self.private_key).as_ref() == (*other.private_key).as_ref()
            && (*self.signing_key).as_ref() == (*other.signing_key).as_ref()
    }
}

impl Eq for DestinationContext {}

/// Host kind.
#[derive(Debug, Clone)]
pub enum HostKind {
    /// Destination.
    Destination {
        /// Destination.
        destination: Box<Destination>,
    },

    /// Base32-encoded host, such as udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p.
    B32Host {
        /// Destination ID.
        destination_id: DestinationId,
    },

    /// Regular host, such as host.i2p.
    Host {
        /// Host.
        host: String,
    },
}

impl PartialEq for HostKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Host { host: host1 }, Self::Host { host: host2 }) => host1 == host2,
            (
                Self::B32Host {
                    destination_id: destination_id1,
                },
                Self::B32Host {
                    destination_id: destination_id2,
                },
            ) => destination_id1 == destination_id2,
            (
                Self::Destination {
                    destination: destination1,
                },
                Self::Destination {
                    destination: destination2,
                },
            ) => destination1 == destination2,
            _ => false,
        }
    }
}

impl Eq for HostKind {}

/// SAMv3 commands received from the client.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SamCommand {
    /// `HELLO VERSION` message.
    Hello {
        /// Minimum supported version, if specified.
        min: Option<SamVersion>,

        /// Maximum supported version, if specified.
        max: Option<SamVersion>,
    },

    /// `SESSION CREATE` message.
    CreateSession {
        /// Session ID.
        session_id: String,

        /// Session kind:
        session_kind: SessionKind,

        /// Destination context.
        destination: Box<DestinationContext>,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `SESSION ADD` message.
    CreateSubSession {
        /// Session ID.
        session_id: String,

        /// Session kind:
        session_kind: SessionKind,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `STREAM CONNECT` message.
    Connect {
        /// Session ID.
        session_id: String,

        /// Host where to connect to.
        host: HostKind,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `STREAM ACCEPT` message.
    Accept {
        /// Session ID.
        session_id: String,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `STREAM FORWARD` message.
    Forward {
        /// Session ID.
        session_id: String,

        /// Port where the TCP listener is listening on.
        port: u16,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `NAMING LOOKUP` message.
    NamingLookup {
        /// Hostname to lookup.
        name: String,
    },

    /// Generate destination.
    GenerateDestination,

    /// Dummy event
    Dummy,
}

impl Default for SamCommand {
    fn default() -> Self {
        Self::Dummy
    }
}

impl fmt::Display for SamCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { min, max } => write!(f, "SamCommand::Hello({min:?}, {max:?})"),
            Self::CreateSession { session_id, .. } =>
                write!(f, "SamCommand::CreateSession({session_id})"),
            Self::CreateSubSession { session_id, .. } =>
                write!(f, "SamCommand::CreateSubSession({session_id})"),
            Self::Connect { session_id, .. } =>
                write!(f, "SamCommand::StreamConnect({session_id})"),
            Self::Accept { session_id, .. } => write!(f, "SamCommand::StreamAccept({session_id})"),
            Self::Forward { session_id, .. } => write!(f, "SamCommand::Forward({session_id})"),
            Self::NamingLookup { name } => write!(f, "SamCommand::NamingLookup({name})"),
            Self::GenerateDestination => write!(f, "SamCommand::GenerateDestination"),
            Self::Dummy => unreachable!(),
        }
    }
}

impl<'a, R: Runtime> TryFrom<ParsedCommand<'a, R>> for SamCommand {
    type Error = ();

    fn try_from(mut parsed_cmd: ParsedCommand<'a, R>) -> Result<Self, Self::Error> {
        match (parsed_cmd.command, parsed_cmd.subcommand) {
            ("HELLO", Some("VERSION")) => Ok(Self::Hello {
                min: parsed_cmd
                    .key_value_pairs
                    .get("MIN")
                    .and_then(|value| SamVersion::try_from(*value).ok()),
                max: parsed_cmd
                    .key_value_pairs
                    .get("MAX")
                    .and_then(|value| SamVersion::try_from(*value).ok()),
            }),
            ("SESSION", Some("CREATE")) => {
                // checking that the options have valid values
                let data_for_options_check:[(&'static str, u8, u8, &'static str); 4] = [
                    ("inbound.quantity", 1, 16, "invalid inbound tunnel quantity, 16 is the maximum quantity"),
                    ("outbound.quantity", 1, 16, "invalid outbound tunnel quantity, 16 is the maximum quantity"), 
                    ("inbound.length", 1, 7, "invalid inbound tunnel length, 0-hop is not supported and 7 is the maximum length"), 
                    ("outbound.length", 1, 8, "invalid outbound tunnel length, 0-hop is not supported and 8 is the maximum length")
                ];

                for (option, min, max, error_msg) in data_for_options_check {
                    let Some(value) = parsed_cmd.key_value_pairs.get(option) else {
                        continue;
                    };

                    let Ok(value) = value.parse::<u8>() else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?value,
                            %option,
                            "invalid tunnel configuration",
                        );
                        return Err(());
                    };

                    if value > max || value < min {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?min,
                            ?max,
                            ?value,
                            error_msg
                        );
                        return Err(());
                    }
                }

                let session_id = parsed_cmd
                    .key_value_pairs
                    .remove("ID")
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "session id missing from `SESSION CREATE`",
                        );
                    })?
                    .to_string();

                let session_kind = match parsed_cmd.key_value_pairs.remove("STYLE") {
                    Some("STREAM") => SessionKind::Stream,
                    Some("PRIMARY") | Some("MASTER") => SessionKind::Primary,
                    style @ (Some("RAW") | Some("DATAGRAM")) => {
                        // currently only forwarded datagrams are supported
                        let _ = parsed_cmd.key_value_pairs.get("PORT").ok_or_else(|| {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "only forwarded raw datagrams are supported",
                            );
                        })?;

                        // if no host was specified, default to localhost
                        if parsed_cmd.key_value_pairs.get("HOST").is_none() {
                            parsed_cmd.key_value_pairs.insert("HOST", "127.0.0.1");
                        }

                        match style {
                            Some("RAW") => SessionKind::Anonymous,
                            Some("DATAGRAM") => SessionKind::Datagram,
                            _ => unreachable!(),
                        }
                    }
                    kind => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?kind,
                            "unsupported session kind",
                        );

                        return Err(());
                    }
                };

                let destination = match parsed_cmd.key_value_pairs.remove("DESTINATION") {
                    Some("TRANSIENT") => {
                        let signing_key = SigningPrivateKey::random(R::rng());
                        let encryption_key = StaticPrivateKey::random(R::rng());
                        let destination = Destination::new::<R>(signing_key.public());

                        DestinationContext {
                            destination,
                            private_key: Box::new(encryption_key),
                            signing_key: Box::new(signing_key),
                        }
                    }
                    Some(destination) => {
                        let decoded = base64_decode(destination).ok_or(())?;
                        let (rest, destination) =
                            Destination::parse_frame(&decoded).map_err(|_| ())?;
                        let (rest, private_key) =
                            take::<_, _, ()>(32usize)(rest).map_err(|_| ())?;
                        let (_, signing_key) = take::<_, _, ()>(32usize)(rest).map_err(|_| ())?;

                        // conversions are expected to succeed since the client is interacting with
                        // a local router and would only crash their onw router if they provided
                        // invalid keying material
                        DestinationContext {
                            destination,
                            private_key: Box::new(
                                StaticPrivateKey::from_bytes(private_key).expect("to succeed"),
                            ),
                            signing_key: Box::new(
                                SigningPrivateKey::from_bytes(signing_key).expect("to succeed"),
                            ),
                        }
                    }
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "destination type not specified",
                        );

                        return Err(());
                    }
                };

                Ok(SamCommand::CreateSession {
                    session_id,
                    session_kind,
                    destination: Box::new(destination),
                    options: parsed_cmd
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("SESSION", Some("ADD")) => {
                let session_id = parsed_cmd
                    .key_value_pairs
                    .remove("ID")
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "session id missing from `SESSION CREATE`",
                        );
                    })?
                    .to_string();

                let session_kind = match parsed_cmd.key_value_pairs.remove("STYLE") {
                    Some("STREAM") => SessionKind::Stream,
                    Some("PRIMARY") | Some("MASTER") => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "sub-session kind cannot be `Primary`",
                        );
                        return Err(());
                    }
                    style @ (Some("RAW") | Some("DATAGRAM")) => {
                        // currently only forwarded datagrams are supported
                        let _ = parsed_cmd.key_value_pairs.get("PORT").ok_or_else(|| {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "only forwarded raw datagrams are supported",
                            );
                        })?;

                        // if no host was specified, default to localhost
                        if parsed_cmd.key_value_pairs.get("HOST").is_none() {
                            parsed_cmd.key_value_pairs.insert("HOST", "127.0.0.1");
                        }

                        match style {
                            Some("RAW") => SessionKind::Anonymous,
                            Some("DATAGRAM") => SessionKind::Datagram,
                            _ => unreachable!(),
                        }
                    }
                    kind => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?kind,
                            "unsupported session kind",
                        );

                        return Err(());
                    }
                };

                Ok(SamCommand::CreateSubSession {
                    session_id,
                    session_kind,
                    options: parsed_cmd
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("STREAM", Some("CONNECT")) => {
                let session_id = parsed_cmd.key_value_pairs.get("ID").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "session id missing for `STREAM CONNECT`"
                    );
                })?;
                let destination =
                    parsed_cmd.key_value_pairs.get("DESTINATION").ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "destination missing for `STREAM CONNECT`"
                        );
                    })?;

                let host = if let Some(end) = destination.find(".b32.i2p") {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %destination,
                        "stream connect for .b32.i2p address",
                    );

                    let start = if destination.starts_with("http://") {
                        7usize
                    } else if destination.starts_with("https://") {
                        8usize
                    } else {
                        0usize
                    };

                    let decoded = base32_decode(&destination[start..end]).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?destination,
                            "invalid .b32.i2p address",
                        );
                    })?;

                    HostKind::B32Host {
                        destination_id: DestinationId::from(&decoded),
                    }
                } else if destination.ends_with(".i2p") {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %destination,
                        "stream connect for .i2p address",
                    );

                    let start = if destination.starts_with("http://") {
                        7usize
                    } else if destination.starts_with("https://") {
                        8usize
                    } else {
                        0usize
                    };

                    HostKind::Host {
                        host: destination[start..].to_string(),
                    }
                } else {
                    let decoded = base64_decode(destination).ok_or(())?;

                    HostKind::Destination {
                        destination: Box::new(Destination::parse(&decoded).ok_or(())?),
                    }
                };

                Ok(SamCommand::Connect {
                    host,
                    session_id: session_id.to_string(),
                    options: parsed_cmd
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("STREAM", Some("ACCEPT")) => {
                let session_id = parsed_cmd.key_value_pairs.get("ID").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "session id missing for `STREAM ACCEPT`"
                    );
                })?;

                Ok(SamCommand::Accept {
                    session_id: session_id.to_string(),
                    options: parsed_cmd
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("STREAM", Some("FORWARD")) => {
                let session_id = parsed_cmd.key_value_pairs.get("ID").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "session id missing for `STREAM FORWARD`"
                    );
                })?;
                let port = parsed_cmd
                    .key_value_pairs
                    .get("PORT")
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "destination missing for `STREAM FORWARD`"
                        );
                    })?
                    .parse::<u16>()
                    .map_err(|_| ())?;

                Ok(SamCommand::Forward {
                    session_id: session_id.to_string(),
                    port,
                    options: parsed_cmd
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("NAMING", Some("LOOKUP")) => Ok(SamCommand::NamingLookup {
                name: parsed_cmd.key_value_pairs.get("NAME").ok_or(())?.to_string(),
            }),
            ("DEST", Some("GENERATE")) => match parsed_cmd.key_value_pairs.get("SIGNATURE_TYPE") {
                Some(signature_type) if *signature_type == "7" =>
                    Ok(SamCommand::GenerateDestination),
                Some(signature_type) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?signature_type,
                        "unsupported signature type",
                    );
                    Err(())
                }
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "signature type not specified"
                    );
                    Err(())
                }
            },
            (command, subcommand) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %command,
                    ?subcommand,
                    "unrecognized command",
                );

                Err(())
            }
        }
    }
}

impl SamCommand {
    /// Attempt to parse `input` into `Response`.
    //
    // Non-public method returning `IResult` for cleaner error handling.
    fn parse_inner<R: Runtime>(input: &str) -> IResult<&str, Self> {
        let (rest, (command, _, subcommand, _, key_value_pairs)) = tuple((
            alt((
                tag("HELLO"),
                tag("SESSION"),
                tag("STREAM"),
                tag("NAMING"),
                tag("DEST"),
            )),
            opt(char(' ')),
            opt(alt((
                tag("VERSION"),
                tag("CREATE"),
                tag("ADD"),
                tag("CONNECT"),
                tag("ACCEPT"),
                tag("FORWARD"),
                tag("LOOKUP"),
                tag("GENERATE"),
            ))),
            opt(char(' ')),
            opt(parse_key_value_pairs),
        ))(input)?;

        Ok((
            rest,
            SamCommand::try_from(ParsedCommand::<R> {
                command,
                subcommand,
                key_value_pairs: key_value_pairs.unwrap_or(HashMap::new()),
                _runtime: Default::default(),
            })
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?,
        ))
    }

    /// Attempt to parse `input` into `Response`.
    pub fn parse<R: Runtime>(input: &str) -> Option<Self> {
        Some(Self::parse_inner::<R>(input).ok()?.1)
    }
}

/// Anonymous/repliable datagram.
pub struct Datagram {
    /// Session ID.
    pub session_id: Arc<str>,

    /// Destination of the remote peer where the datagram should be sent.
    pub destination: Destination,

    /// Datagram.
    pub datagram: Vec<u8>,

    /// Options.
    #[allow(unused)]
    pub options: HashMap<String, String>,
}

impl Datagram {
    fn parse_version(input: &str) -> IResult<&str, ()> {
        let (input, _) = tag("3.")(input)?;
        let (input, _) = take_while1(|c: char| c.is_ascii_digit())(input)?;

        Ok((input, ()))
    }

    fn parse_session_id(input: &str) -> IResult<&str, Arc<str>> {
        let (input, id) = take_while1(|c| c != ' ')(input)?;

        Ok((input, Arc::from(id)))
    }

    fn parse_destination(input: &str) -> IResult<&str, Destination> {
        let (input, dest_b64) = take_while1(|c| c != ' ')(input)?;
        let decoded = base64_decode(dest_b64)
            .ok_or_else(|| nom::Err::Error(nom::error::Error::new(input, ErrorKind::Char)))?;
        let destination = Destination::parse(&decoded)
            .ok_or_else(|| nom::Err::Error(nom::error::Error::new(input, ErrorKind::Char)))?;

        Ok((input, destination))
    }

    /// Attempt to parse `input` into `Datagram`.
    pub fn parse(input: &[u8]) -> Option<Self> {
        let pos = input.iter().position(|&b| b == b'\n')?;
        let (info, datagram) = input.split_at(pos);
        let info = core::str::from_utf8(info).ok()?;

        let (_, (_, _, session_id, _, destination, options)) = tuple((
            Self::parse_version,
            char(' '),
            Self::parse_session_id,
            char(' '),
            Self::parse_destination,
            opt(parse_key_value_pairs),
        ))(info)
        .ok()?;

        let options = options?
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();

        Some(Self {
            session_id,
            destination,
            options,
            datagram: datagram[1..].to_vec(),
        })
    }
}

fn parse_key_value_pairs(input: &str) -> IResult<&str, HashMap<&str, &str>> {
    let (input, key_value_pairs) = many0(preceded(multispace0, parse_key_value))(input)?;
    Ok((input, key_value_pairs.into_iter().collect()))
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(parse_key, char('='), parse_value)(input)
}

fn parse_key(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_"), tag(".")))),
    ))
    .parse(input)
}

fn parse_value(input: &str) -> IResult<&str, &str> {
    alt((
        parse_quoted_value,
        map(take_while1(|c: char| !c.is_whitespace()), |s: &str| s),
    ))(input)
}

fn parse_quoted_value(input: &str) -> IResult<&str, &str> {
    delimited(
        char('"'),
        escaped(is_not("\\\""), '\\', alt((tag("\""), tag("\\")))),
        char('"'),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base64_encode,
        runtime::{mock::MockRuntime, Runtime},
    };
    use bytes::{BufMut, BytesMut};

    #[test]
    fn parse_hello() {
        // min and max are the same
        match SamCommand::parse::<MockRuntime>("HELLO VERSION MIN=3.3 MAX=3.3") {
            Some(SamCommand::Hello {
                min: Some(SamVersion::V33),
                max: Some(SamVersion::V33),
            }) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // no version defined
        match SamCommand::parse::<MockRuntime>("HELLO VERSION") {
            Some(SamCommand::Hello {
                min: None,
                max: None,
            }) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // invalid subcommand
        assert!(SamCommand::parse::<MockRuntime>("HELLO REPLY").is_none());
    }

    #[test]
    fn unrecognized_command() {
        assert!(SamCommand::parse::<MockRuntime>("TEST COMMAND KEY=VALUE").is_none());
    }

    #[test]
    fn parse_session_create_stream() {
        // transient
        match SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=STREAM ID=test DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        ) {
            Some(SamCommand::CreateSession {
                session_id,
                session_kind: SessionKind::Stream,
                options,
                ..
            }) => {
                assert_eq!(session_id.as_str(), "test");
                assert_eq!(
                    options.get("i2cp.leaseSetEncType"),
                    Some(&"4,0".to_string())
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // persistent
        let privkey = {
            let signing_key = SigningPrivateKey::random(MockRuntime::rng());
            let encryption_key = StaticPrivateKey::random(MockRuntime::rng());

            let destination = Destination::new::<MockRuntime>(signing_key.public());

            let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
            out.put_slice(&destination.serialize());
            out.put_slice(encryption_key.as_ref());
            out.put_slice(signing_key.as_ref());

            base64_encode(out)
        };

        match SamCommand::parse::<MockRuntime>(&format!(
            "SESSION CREATE STYLE=STREAM ID=test DESTINATION={privkey} i2cp.leaseSetEncType=4,0"
        )) {
            Some(SamCommand::CreateSession {
                session_id,
                session_kind: SessionKind::Stream,
                options,
                ..
            }) => {
                assert_eq!(session_id.as_str(), "test");
                assert_eq!(
                    options.get("i2cp.leaseSetEncType"),
                    Some(&"4,0".to_string())
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // invalid destination
        assert!(SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=DATAGRAM ID=test DESTINATION=BASE64_DESTINATION i2cp.leaseSetEncType=4,0",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=DATAGRAM DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        )
        .is_none());
    }

    #[test]
    fn reject_invalid_outbound_tunnel_quantity() {
        let test_cases = ["0", "17", "abc", "-1", "1.1"];
        for invalid_out_qty in test_cases {
            let invalid_cmd = ParsedCommand::<MockRuntime> {
                command: "SESSION",
                subcommand: Some("CREATE"),
                key_value_pairs: HashMap::from([
                    ("STYLE", "STREAM"),
                    ("ID", "test"),
                    ("DESTINATION", "TRANSIENT"),
                    ("outbound.quantity", invalid_out_qty),
                ]),
                _runtime: Default::default(),
            };

            match SamCommand::try_from(invalid_cmd) {
                Ok(_) => panic!(
                    "Failed to reject the invalid outbound tunnel quantity {invalid_out_qty:?}",
                ),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn reject_invalid_inbound_tunnel_length() {
        let test_cases = ["0", "8", "abc", "-1", "1.1"];
        for invalid_in_len in test_cases {
            let invalid_cmd = ParsedCommand::<MockRuntime> {
                command: "SESSION",
                subcommand: Some("CREATE"),
                key_value_pairs: HashMap::from([
                    ("STYLE", "STREAM"),
                    ("ID", "test"),
                    ("DESTINATION", "TRANSIENT"),
                    ("inbound.length", invalid_in_len),
                ]),
                _runtime: Default::default(),
            };

            match SamCommand::try_from(invalid_cmd) {
                Ok(_) =>
                    panic!("Failed to reject the invalid inbound tunnel length {invalid_in_len:?}",),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn reject_invalid_outbound_tunnel_length() {
        let test_cases = ["0", "9", "abc", "-1", "1.1"];
        for invalid_out_len in test_cases {
            let invalid_cmd = ParsedCommand::<MockRuntime> {
                command: "SESSION",
                subcommand: Some("CREATE"),
                key_value_pairs: HashMap::from([
                    ("STYLE", "STREAM"),
                    ("ID", "test"),
                    ("DESTINATION", "TRANSIENT"),
                    ("outbound.length", invalid_out_len),
                ]),
                _runtime: Default::default(),
            };

            match SamCommand::try_from(invalid_cmd) {
                Ok(_) => panic!(
                    "Failed to reject the invalid outbound tunnel length {invalid_out_len:?}"
                ),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn parse_stream_connect() {
        let destination = {
            let signing_key = SigningPrivateKey::random(MockRuntime::rng());
            base64_encode(Destination::new::<MockRuntime>(signing_key.public()).serialize())
        };

        match SamCommand::parse::<MockRuntime>(&format!(
            "STREAM CONNECT ID=MM9z52ZwnTTPwfeD DESTINATION={destination} SILENT=false"
        )) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::Destination { .. },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
            }
            response => panic!("invalid response: {response:?}"),
        }

        // base32-encoded hostname
        match SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT \
            ID=MM9z52ZwnTTPwfeD \
            DESTINATION=udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p \
            SILENT=false",
        ) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::B32Host { destination_id },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
                assert_eq!(
                    destination_id,
                    DestinationId::from(
                        &base32_decode("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna")
                            .unwrap()
                    )
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // base32-encoded hostname
        match SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT \
            ID=MM9z52ZwnTTPwfeD \
            DESTINATION=http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p \
            SILENT=false",
        ) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::B32Host { destination_id },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
                assert_eq!(
                    destination_id,
                    DestinationId::from(
                        &base32_decode("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna")
                            .unwrap()
                    )
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // base32-encoded hostname
        match SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT \
            ID=MM9z52ZwnTTPwfeD \
            DESTINATION=https://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p \
            SILENT=false",
        ) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::B32Host { destination_id },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
                assert_eq!(
                    destination_id,
                    DestinationId::from(
                        &base32_decode("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna")
                            .unwrap()
                    )
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // regular hostname
        match SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT \
            ID=MM9z52ZwnTTPwfeD \
            DESTINATION=host.i2p \
            SILENT=false",
        ) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::Host { host },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
                assert_eq!(host.as_str(), "host.i2p");
            }
            response => panic!("invalid response: {response:?}"),
        }

        // regular hostname
        match SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT \
            ID=MM9z52ZwnTTPwfeD \
            DESTINATION=http://host.i2p \
            SILENT=false",
        ) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::Host { host },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
                assert_eq!(host.as_str(), "host.i2p");
            }
            response => panic!("invalid response: {response:?}"),
        }

        // regular hostname
        match SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT \
            ID=MM9z52ZwnTTPwfeD \
            DESTINATION=https://host.i2p \
            SILENT=false",
        ) {
            Some(SamCommand::Connect {
                session_id,
                options,
                host: HostKind::Host { host },
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
                assert_eq!(host.as_str(), "host.i2p");
            }
            response => panic!("invalid response: {response:?}"),
        }

        // invalid subcommand
        assert!(SamCommand::parse::<MockRuntime>(
            "STREAM CREATE ID=MM9z52ZwnTTPwfeD  DESTINATION=host.i2p SILENT=false",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT DESTINATION=host.i2p SILENT=false",
        )
        .is_none());

        // non-transient destination
        assert!(SamCommand::parse::<MockRuntime>(
            "STREAM CONNECT ID=MM9z52ZwnTTPwfeD SILENT=false",
        )
        .is_none());
    }

    #[test]
    fn parse_stream_accept() {
        match SamCommand::parse::<MockRuntime>("STREAM ACCEPT ID=MM9z52ZwnTTPwfeD SILENT=false") {
            Some(SamCommand::Accept {
                session_id,
                options,
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
            }
            response => panic!("invalid response: {response:?}"),
        }

        // session id missing
        assert!(SamCommand::parse::<MockRuntime>("STREAM ACCEPT SILENT=false").is_none());
    }

    #[test]
    fn parse_stream_forward() {
        match SamCommand::parse::<MockRuntime>(
            "STREAM FORWARD ID=MM9z52ZwnTTPwfeD PORT=8888 SILENT=false",
        ) {
            Some(SamCommand::Forward {
                session_id,
                port,
                options,
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(port, 8888);
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
            }
            response => panic!("invalid response: {response:?}"),
        }

        // session id missing
        assert!(
            SamCommand::parse::<MockRuntime>("STREAM FORWARD PORT=8888 SILENT=false").is_none()
        );

        // port missing
        assert!(SamCommand::parse::<MockRuntime>(
            "STREAM FORWARD ID=MM9z52ZwnTTPwfeD SILENT=false"
        )
        .is_none());
    }

    #[test]
    fn parse_naming_lookup() {
        match SamCommand::parse::<MockRuntime>("NAMING LOOKUP NAME=host.i2p") {
            Some(SamCommand::NamingLookup { name }) => {
                assert_eq!(name.as_str(), "host.i2p");
            }
            response => panic!("invalid response: {response:?}"),
        }

        // subcommand missing
        assert!(SamCommand::parse::<MockRuntime>("NAMING").is_none());

        // invalid subcommand
        assert!(SamCommand::parse::<MockRuntime>("NAMING GENERATE").is_none());

        // name missing
        assert!(SamCommand::parse::<MockRuntime>("NAMING LOOKUP").is_none());
    }

    #[test]
    fn parse_dest_generate() {
        match SamCommand::parse::<MockRuntime>("DEST GENERATE SIGNATURE_TYPE=7") {
            Some(SamCommand::GenerateDestination) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // invalid signature type
        assert!(SamCommand::parse::<MockRuntime>("DEST GENERATE SIGNATURE_TYPE=1337").is_none());

        // signature type missing
        assert!(SamCommand::parse::<MockRuntime>("DEST GENERATE").is_none());

        // subcommand missing
        assert!(SamCommand::parse::<MockRuntime>("DEST").is_none());

        // invalid subcommand
        assert!(SamCommand::parse::<MockRuntime>("DEST LOOKUP").is_none());
    }

    #[test]
    fn parse_repliable_datagram() {
        {
            let command = "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        PORT=8888 \
                        HOST=127.2.2.2 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse::<MockRuntime>(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Datagram,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.2.2.2".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no host specified, defaults to 127.0.0.1
        {
            let command = "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        PORT=8888 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse::<MockRuntime>(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Datagram,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.0.0.1".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no port specifed, currently not supported
        {
            let command = "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            assert!(SamCommand::parse::<MockRuntime>(command).is_none());
        }

        // session with persistent destination
        {
            let privkey = {
                let signing_key = SigningPrivateKey::random(MockRuntime::rng());
                let encryption_key = StaticPrivateKey::random(MockRuntime::rng());

                let destination = Destination::new::<MockRuntime>(signing_key.public());

                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            let command = format!(
                "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        PORT=8888 \
                        DESTINATION={privkey} \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n"
            );

            match SamCommand::parse::<MockRuntime>(&command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Datagram,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id.as_str(), "test");
                    assert_eq!(options.get("i2cp.leaseSetEncType"), Some(&"4".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // invalid destination
        assert!(SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=DATAGRAM PORT=8888 ID=test DESTINATION=BASE64_DESTINATION i2cp.leaseSetEncType=4,0",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=DATAGRAM PORT=8888 DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        )
        .is_none());
    }

    #[test]
    fn parse_anonymous_datagram() {
        {
            let command = "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        PORT=8888 \
                        HOST=127.2.2.2 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse::<MockRuntime>(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Anonymous,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.2.2.2".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no host specified, defaults to 127.0.0.1
        {
            let command = "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        PORT=8888 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse::<MockRuntime>(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Anonymous,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.0.0.1".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no port specifed, currently not supported
        {
            let command = "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            assert!(SamCommand::parse::<MockRuntime>(command).is_none());
        }

        // session with persistent destination
        {
            let privkey = {
                let signing_key = SigningPrivateKey::random(MockRuntime::rng());
                let encryption_key = StaticPrivateKey::random(MockRuntime::rng());

                let destination = Destination::new::<MockRuntime>(signing_key.public());

                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            let command = format!(
                "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        PORT=8888 \
                        DESTINATION={privkey} \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n"
            );

            match SamCommand::parse::<MockRuntime>(&command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Anonymous,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id.as_str(), "test");
                    assert_eq!(options.get("i2cp.leaseSetEncType"), Some(&"4".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // invalid destination
        assert!(SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=RAW PORT=8888 ID=test DESTINATION=BASE64_DESTINATION i2cp.leaseSetEncType=4,0",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=RAW PORT=8888 DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        )
        .is_none());
    }

    #[test]
    fn parse_datagram_basic() {
        let destination = {
            let rng = MockRuntime::rng();
            let signing_key = SigningPrivateKey::random(rng);
            Destination::new::<MockRuntime>(signing_key.public())
        };
        let serialized = {
            let mut out = BytesMut::with_capacity(destination.serialized_len());
            out.put_slice(&destination.serialize());
            base64_encode(out)
        };

        let mut datagram = format!("3.0 test {serialized}\n").as_bytes().to_vec();
        datagram.extend_from_slice(b"hello, world");

        match Datagram::parse(&datagram) {
            Some(Datagram {
                session_id,
                datagram,
                options,
                ..
            }) => {
                assert_eq!(*session_id, *"test");
                assert_eq!(datagram, b"hello, world");
                assert!(options.is_empty());
            }
            _ => panic!("invalid datagram"),
        }
    }

    #[test]
    fn parse_datagram_with_all_options() {
        let destination = {
            let rng = MockRuntime::rng();
            let signing_key = SigningPrivateKey::random(rng);
            Destination::new::<MockRuntime>(signing_key.public())
        };
        let serialized = {
            let mut out = BytesMut::with_capacity(destination.serialized_len());
            out.put_slice(&destination.serialize());
            base64_encode(out)
        };

        let mut datagram = format!(
            "3.0 test {serialized} FROM_PORT=1234 TO_PORT=5678 PROTOCOL=17 \
            SEND_TAGS=2 TAG_THRESHOLD=3 EXPIRES=3600 SEND_LEASESET=true\n"
        )
        .as_bytes()
        .to_vec();
        datagram.extend_from_slice(b"hello with options");

        match Datagram::parse(&datagram) {
            Some(Datagram {
                session_id,
                datagram,
                options,
                ..
            }) => {
                assert_eq!(*session_id, *"test");
                assert_eq!(datagram, b"hello with options");
                assert_eq!(options.get("FROM_PORT"), Some(&String::from("1234")));
                assert_eq!(options.get("TO_PORT"), Some(&String::from("5678")));
                assert_eq!(options.get("PROTOCOL"), Some(&String::from("17")));
                assert_eq!(options.get("SEND_TAGS"), Some(&String::from("2")));
                assert_eq!(options.get("TAG_THRESHOLD"), Some(&String::from("3")));
                assert_eq!(options.get("EXPIRES"), Some(&String::from("3600")));
                assert_eq!(options.get("SEND_LEASESET"), Some(&String::from("true")));
            }
            _ => panic!("invalid datagram"),
        }
    }

    #[test]
    fn parse_datagram_with_port_options() {
        let destination = {
            let rng = MockRuntime::rng();
            let signing_key = SigningPrivateKey::random(rng);
            Destination::new::<MockRuntime>(signing_key.public())
        };
        let serialized = {
            let mut out = BytesMut::with_capacity(destination.serialized_len());
            out.put_slice(&destination.serialize());
            base64_encode(out)
        };

        let mut datagram = format!("3.0 test {serialized} FROM_PORT=1234 TO_PORT=5678\n")
            .as_bytes()
            .to_vec();
        datagram.extend_from_slice(b"hello with ports");

        match Datagram::parse(&datagram) {
            Some(Datagram {
                session_id,
                datagram,
                options,
                ..
            }) => {
                assert_eq!(*session_id, *"test");
                assert_eq!(datagram, b"hello with ports");
                assert_eq!(options.get("FROM_PORT"), Some(&String::from("1234")));
                assert_eq!(options.get("TO_PORT"), Some(&String::from("5678")));
            }
            _ => panic!("invalid datagram"),
        }
    }

    #[test]
    fn parse_datagram_real_destination() {
        let datagram = "3.0 12OzbmMqo3bdv3w8 Mja~hsQgYVQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-Gx\
        CBhVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkTI2v4bEIGFUG5bIrm7Zyx5GfFC0D9UclVJ2QoXrx4GRMja~hsQ\
        gYVQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-GxCBhVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkTI2v4bEI\
        GFUG5bIrm7Zyx5GfFC0D9UclVJ2QoXrx4GRMja~hsQgYVQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-GxCB\
        hVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkTI2v4bEIGFUG5bIrm7Zyx5GfFC0D9UclVJ2QoXrx4GRMja~hsQgY\
        VQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-GxCBhVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkQL4ggEoB~o\
        SzcMX2fuc~MDG6lmUbi6G9sfRnscl9uh4BQAEAAcAAA==\nhello, world 1"
            .as_bytes()
            .to_vec();

        match Datagram::parse(&datagram) {
            Some(Datagram {
                session_id,
                datagram,
                options,
                ..
            }) => {
                assert_eq!(*session_id, *"12OzbmMqo3bdv3w8");
                assert_eq!(datagram, b"hello, world 1");
                assert!(options.is_empty());
            }
            _ => panic!("invalid datagram"),
        }
    }

    #[test]
    fn parse_primary_session() {
        // transient
        match SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=PRIMARY ID=test DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        ) {
            Some(SamCommand::CreateSession {
                session_id,
                session_kind: SessionKind::Primary,
                options,
                ..
            }) => {
                assert_eq!(session_id.as_str(), "test");
                assert_eq!(
                    options.get("i2cp.leaseSetEncType"),
                    Some(&"4,0".to_string())
                );
            }
            response => panic!("invalid response: {response:?}"),
        }
    }

    #[test]
    fn parse_master_session() {
        // transient
        match SamCommand::parse::<MockRuntime>(
            "SESSION CREATE STYLE=MASTER ID=test DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        ) {
            Some(SamCommand::CreateSession {
                session_id,
                session_kind: SessionKind::Primary,
                options,
                ..
            }) => {
                assert_eq!(session_id.as_str(), "test");
                assert_eq!(
                    options.get("i2cp.leaseSetEncType"),
                    Some(&"4,0".to_string())
                );
            }
            response => panic!("invalid response: {response:?}"),
        }
    }

    #[test]
    fn parse_sub_session_stream() {
        match SamCommand::parse::<MockRuntime>("SESSION ADD STYLE=STREAM ID=stream-sub-session") {
            Some(SamCommand::CreateSubSession {
                session_id,
                session_kind: SessionKind::Stream,
                ..
            }) => {
                assert_eq!(session_id, "stream-sub-session");
            }
            response => panic!("invalid response: {response:?}"),
        }
    }

    #[test]
    fn parse_sub_session_repliable() {
        match SamCommand::parse::<MockRuntime>(
            "SESSION ADD STYLE=DATAGRAM ID=repliable-sub-session PORT=8888",
        ) {
            Some(SamCommand::CreateSubSession {
                session_id,
                session_kind: SessionKind::Datagram,
                ..
            }) => {
                assert_eq!(session_id, "repliable-sub-session");
            }
            response => panic!("invalid response: {response:?}"),
        }
    }

    #[test]
    fn parse_sub_session_anonymous() {
        match SamCommand::parse::<MockRuntime>(
            "SESSION ADD STYLE=RAW ID=anonymous-sub-session PORT=9999",
        ) {
            Some(SamCommand::CreateSubSession {
                session_id,
                session_kind: SessionKind::Anonymous,
                ..
            }) => {
                assert_eq!(session_id, "anonymous-sub-session");
            }
            response => panic!("invalid response: {response:?}"),
        }
    }

    #[test]
    fn parse_sub_session_session_kind_primary() {
        assert!(
            SamCommand::parse::<MockRuntime>("SESSION ADD STYLE=PRIMARY ID=sub-session").is_none()
        );
    }

    #[test]
    fn parse_sub_session_id_missing() {
        assert!(SamCommand::parse::<MockRuntime>("SESSION ADD STYLE=STREAM").is_none());
    }
}
