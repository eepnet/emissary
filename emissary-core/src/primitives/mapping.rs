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

use crate::{error::parser::MappingParseError, primitives::Str};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::{
    hash_map::{IntoIter, Iter},
    HashMap,
};
use nom::{
    number::complete::{be_u16, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::{
    fmt::{self, Debug},
    num::NonZeroUsize,
};

/// Key-value mapping
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Mapping(HashMap<Str, Str>);

impl fmt::Display for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Mapping {
    /// Serialize [`Mapping`] into a byte vector.
    pub fn serialize(&self) -> Bytes {
        // Allocate at least two bytes for the size prefix
        let out = BytesMut::with_capacity(2);
        self.serialize_into(out).freeze()
    }

    pub fn serialize_into(&self, mut out: BytesMut) -> BytesMut {
        let start_len = out.len();

        // Reserve 2 bytes for size prefix
        if out.capacity() - out.len() < 2 {
            out.reserve(2);
        }
        out.put_u16(0); // temporary placeholder

        let data_start = out.len();
        let mut entries: Vec<_> = self.0.iter().collect();

        // Our mapping implementation does not support duplicate keys, so we do not need to preserve
        // order
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (key, value) in entries {
            let key = key.serialize();
            let value = value.serialize();
            out.reserve(key.len() + value.len() + 2);
            out.extend_from_slice(&key);
            out.put_u8(b'=');
            out.extend_from_slice(&value);
            out.put_u8(b';');
        }

        let data_len = out.len() - data_start;
        debug_assert!(data_len <= u16::MAX as usize);

        // Write actual length into the 2-byte prefix we reserved
        let prefix_pos = start_len;
        out[prefix_pos..prefix_pos + 2].copy_from_slice(&(data_len as u16).to_be_bytes());

        out
    }

    /// Parse [`Mapping`] from `input`, returning rest of `input` and parsed mapping.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self, MappingParseError> {
        let (rest, size) = be_u16(input)?;
        let mut mapping = Self::default();

        match rest.split_at_checked(size as usize) {
            Some((mut data, rest)) => {
                while !data.is_empty() {
                    let (remaining, key) = Str::parse_frame(data).map_err(Err::convert)?;
                    let (remaining, _) = be_u8(remaining)?;
                    let (remaining, value) = Str::parse_frame(remaining).map_err(Err::convert)?;
                    let (remaining, _) = be_u8(remaining)?;
                    mapping.insert(key, value);
                    data = remaining;
                }

                Ok((rest, mapping))
            }
            None => {
                // This is safe as the zero case will always pass `split_at_checked`
                let non_zero_size = NonZeroUsize::new(size as usize).expect("non-zero size");
                Err(nom::Err::Incomplete(nom::Needed::Size(non_zero_size)))
            }
        }
    }

    /// Try to convert `bytes` into a [`Mapping`].
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Mapping, MappingParseError> {
        Ok(Self::parse_frame(bytes.as_ref())?.1)
    }

    /// Equivalent to `HashMap::insert`
    pub fn insert(&mut self, key: Str, value: Str) -> Option<Str> {
        self.0.insert(key, value)
    }

    /// Equivalent to `HashMap::get`
    pub fn get(&self, key: &Str) -> Option<&Str> {
        self.0.get(key)
    }

    /// Equivalent to `HashMap::len`
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Equivalent to `HashMap::is_empty`
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Equivalent to `HashMap::iter`
    pub fn iter(&self) -> Iter<'_, Str, Str> {
        self.0.iter()
    }
}

impl IntoIterator for Mapping {
    type Item = (Str, Str);
    type IntoIter = IntoIter<Str, Str>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<(Str, Str)> for Mapping {
    fn from_iter<T: IntoIterator<Item = (Str, Str)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mapping() {
        assert_eq!(Mapping::parse(b"\0\0"), Ok(Mapping::default()));
    }

    #[test]
    fn valid_mapping() {
        let mut mapping = Mapping::default();
        mapping.insert("hello".into(), "world".into());

        let ser = mapping.serialize();

        assert_eq!(Mapping::parse(ser), Ok(mapping));
    }

    #[test]
    fn valid_string_with_extra_end_bytes() {
        let mut mapping = Mapping::default();
        mapping.insert("hello".into(), "world".into());

        let mut ser = mapping.serialize().to_vec();
        ser.push(1);
        ser.push(2);
        ser.push(3);
        ser.push(4);

        assert_eq!(Mapping::parse(ser), Ok(mapping));
    }

    #[test]
    fn valid_string_with_extra_start_bytes() {
        let mut mapping = Mapping::default();
        mapping.insert("hello".into(), "world".into());

        const PREFIX: &[u8] = b"prefix";

        let buf = BytesMut::from(PREFIX);
        let ser = mapping.serialize_into(buf).to_vec();

        assert_eq!(&ser[..PREFIX.len()], b"prefix");
        assert_eq!(Mapping::parse(&ser[PREFIX.len()..]), Ok(mapping));
    }

    #[test]
    fn extra_bytes_returned() {
        let mut mapping = Mapping::default();
        mapping.insert("hello".into(), "world".into());

        let mut ser = mapping.serialize().to_vec();
        ser.push(1);
        ser.push(2);
        ser.push(3);
        ser.push(4);

        let (rest, parsed_mapping) = Mapping::parse_frame(&ser).unwrap();

        assert_eq!(parsed_mapping, mapping);
        assert_eq!(rest, [1, 2, 3, 4]);
    }

    #[test]
    fn multiple_mappings() {
        let expected_ser = b"\x00\x19\x01a=\x01b;\x01c=\x01d;\x01e=\x01f;\x02zz=\x01z;";
        let mapping = Mapping::parse(expected_ser).expect("to be valid");

        assert_eq!(mapping.get(&"a".into()), Some(&Str::from("b")));
        assert_eq!(mapping.get(&"c".into()), Some(&Str::from("d")));
        assert_eq!(mapping.get(&"e".into()), Some(&Str::from("f")));
        assert_eq!(mapping.get(&"zz".into()), Some(&Str::from("z")));

        assert_eq!(mapping.serialize().to_vec(), expected_ser);
    }

    #[test]
    fn over_sized() {
        let ser = b"\x01\x00\x01a=\x01b;\x01c=\x01d;\x01e=\x01f;";
        assert_eq!(
            Mapping::parse(ser).unwrap_err(),
            MappingParseError::InvalidBitstream
        );
    }
}
