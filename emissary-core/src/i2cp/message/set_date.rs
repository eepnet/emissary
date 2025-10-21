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
    i2cp::message::{MessageType, I2CP_HEADER_SIZE},
    primitives::{Date, Str},
};

use bytes::{BufMut, BytesMut};

/// `SetDate` message.
///
/// https://geti2p.net/spec/i2cp#setdatemessage
pub struct SetDate(());

impl SetDate {
    /// Create new `SetDate` message.
    pub fn new(date: Date, version: Str) -> BytesMut {
        let date = date.serialize();
        let version = version.serialize();
        let len = date.len() + version.len();

        let mut out = BytesMut::with_capacity(I2CP_HEADER_SIZE + len);

        out.put_u32(len as u32);
        out.put_u8(MessageType::SetDate.as_u8());
        out.put_slice(&date);
        out.put_slice(&version);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{i2cp::message::Message, runtime::mock::MockRuntime};
    use std::str::FromStr;

    #[test]
    fn serialize_deserialize() {
        let message = SetDate::new(Date::new(1337u64), Str::from_str("0.9.68").unwrap());

        match Message::parse::<MockRuntime>(MessageType::SetDate, &message[5..]) {
            Some(Message::SetDate { date, version }) => {
                assert_eq!(date, Date::new(1337u64));
                assert_eq!(version, Str::from_str("0.9.68").unwrap());
            }
            _ => panic!("invalid message"),
        }
    }

    #[test]
    fn invalid_message() {
        let message = {
            let date = Date::new(1337u64).serialize();
            let len = I2CP_HEADER_SIZE + date.len();

            let mut out = BytesMut::with_capacity(len);

            out.put_u32(len as u32);
            out.put_u8(MessageType::SetDate.as_u8());
            out.put_slice(&date);

            out
        };

        match Message::parse::<MockRuntime>(MessageType::SetDate, &message[5..]) {
            None => {}
            Some(_) => panic!("invalid message received"),
        }
    }
}
