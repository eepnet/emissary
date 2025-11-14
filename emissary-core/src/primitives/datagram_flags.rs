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
    error::parser::DatagramFlagsParseError,
    primitives::{Mapping, LOG_TARGET},
};
use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::be_u16,
    Err, IResult,
};

/// Serialized length of [`DatagramFlags`].
const FLAGS_LEN: usize = 2;
/// Version mask for [`DatagramFlags`].
const VERSION_MASK: u8 = 0x0f;

/// Options mask for [`DatagramFlags::V2`].
const V2_OPTIONS_MASK: u8 = 0x10;
/// Offline mask for [`DatagramFlags::V2`].
const V2_OFFLINE_MASK: u8 = 0x20;

/// Datagram flags.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DatagramFlags {
    /// Used in Datagram2.
    ///
    /// https://geti2p.net/spec/datagrams#id9
    V2 {
        options: Option<Mapping>,
        has_offsig: bool,
    },
    /// Used in Datagram3.
    ///
    /// https://geti2p.net/spec/datagrams#id14
    V3, // Stub
}

impl DatagramFlags {
    pub fn new_v2(options: Option<Mapping>, has_offsig: bool) -> DatagramFlags {
        DatagramFlags::V2 {
            options,
            has_offsig,
        }
    }

    /// Serialize [`DatagramFlags`] into a byte vector.
    pub fn serialize(&self) -> Bytes {
        match self {
            Self::V2 {
                options,
                has_offsig: has_offline_signature,
            } => DatagramFlags::serialize_v2(options.as_ref(), *has_offline_signature),
            Self::V3 => unreachable!(),
        }
    }

    /// Parse [`DatagramFlags`] from `input`, returning rest of `input` and parsed
    /// [`DatagramFlags`].
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], DatagramFlags, DatagramFlagsParseError> {
        if input.len() < FLAGS_LEN {
            tracing::warn!(
                target: LOG_TARGET,
                serialized_len = ?input.len(),
                "not enough bytes in flags",
            );

            return Err(Err::Error(DatagramFlagsParseError::InvalidLength));
        }

        let (rest, flags) = take(FLAGS_LEN)(input)?;

        match flags[0] & VERSION_MASK {
            2 => DatagramFlags::parse_v2(rest, flags),
            version => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?version,
                    "unknown flags version",
                );

                Err(Err::Error(DatagramFlagsParseError::UnknownVersion))
            }
        }
    }

    /// Try to parse router information from `bytes`.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, DatagramFlagsParseError> {
        Ok(Self::parse_frame(bytes.as_ref())?.1)
    }

    fn serialize_v2(options: Option<&Mapping>, has_offline_signature: bool) -> Bytes {
        const V2: u8 = 2;

        let mut flags = BytesMut::with_capacity(2);
        flags.put_u16(0);

        flags[0] = V2;

        if has_offline_signature {
            flags[0] |= V2_OFFLINE_MASK
        }

        if let Some(opts) = options {
            flags[0] |= V2_OPTIONS_MASK;
            opts.serialize_into(flags).freeze()
        } else {
            flags.freeze()
        }
    }

    fn parse_v2<'a>(
        input: &'a [u8],
        flags: &[u8],
    ) -> IResult<&'a [u8], DatagramFlags, DatagramFlagsParseError> {
        let flags = flags[0];

        // parse options
        let (rest, options) = if (flags & V2_OPTIONS_MASK) == 0 {
            (input, None)
        } else {
            let (_, optlen) = be_u16(input)?;

            match optlen {
                0 => (input, None),
                len if input.len() < len as usize => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        serialized_len = ?input.len(),
                        "not enough bytes for mapping",
                    );
                    return Err(Err::Error(make_error(input, ErrorKind::Fail)));
                }
                _ => {
                    let (rest, mapping) = Mapping::parse_frame(input).map_err(Err::convert)?;
                    (rest, Some(mapping))
                }
            }
        };

        Ok((
            rest,
            DatagramFlags::V2 {
                options,
                has_offsig: (flags & V2_OFFLINE_MASK) != 0,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_flags() {
        assert_eq!(
            DatagramFlags::parse(b"\0\0"),
            Err(DatagramFlagsParseError::UnknownVersion)
        );
    }

    #[test]
    fn undersized() {
        assert_eq!(
            DatagramFlags::parse(b"\x01"),
            Err(DatagramFlagsParseError::InvalidLength)
        );
    }

    #[test]
    fn valid_flags() {
        let flags = DatagramFlags::V2 {
            options: None,
            has_offsig: false,
        };
        let ser = flags.serialize();

        assert_eq!(DatagramFlags::parse(ser), Ok(flags));
    }

    #[test]
    fn valid_flags_with_all_fields() {
        let mut opts = Mapping::default();
        opts.insert("hello".into(), "world".into());

        let flags = DatagramFlags::V2 {
            options: Some(opts),
            has_offsig: true,
        };

        let ser = flags.serialize();

        assert_eq!(DatagramFlags::parse(ser), Ok(flags));
    }

    #[test]
    fn valid_string_with_extra_bytes() {
        let mut opts = Mapping::default();
        opts.insert("hello".into(), "world".into());

        let flags = DatagramFlags::V2 {
            options: Some(opts),
            has_offsig: true,
        };

        let mut ser = flags.serialize().to_vec();
        ser.push(1);
        ser.push(2);
        ser.push(3);
        ser.push(4);

        assert_eq!(DatagramFlags::parse(ser), Ok(flags));
    }

    #[test]
    fn extra_bytes_returned() {
        let mut opts = Mapping::default();
        opts.insert("hello".into(), "world".into());

        let flags = DatagramFlags::V2 {
            options: Some(opts),
            has_offsig: true,
        };

        let mut ser = flags.serialize().to_vec();
        ser.push(1);
        ser.push(2);
        ser.push(3);
        ser.push(4);

        let (rest, parsed_mapping) = DatagramFlags::parse_frame(&ser).unwrap();

        assert_eq!(parsed_mapping, flags);
        assert_eq!(rest, [1, 2, 3, 4]);
    }
}
