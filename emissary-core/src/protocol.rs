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

/// Protocol type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// Streaming protocol.
    Streaming,

    /// Repliable datagrams.
    Datagram,

    /// Repliable datagrams with replay prevention,
    /// offline signature support and flags extensibility.
    Datagram2,

    /// Raw datagrams.
    Anonymous,
}

impl Protocol {
    /// Attempt to convert `protocol` into [`Protocol`].
    pub fn from_u8(protocol: u8) -> Option<Self> {
        match protocol {
            6u8 => Some(Self::Streaming),
            17u8 => Some(Self::Datagram),
            19u8 => Some(Self::Datagram2),
            18u8 => Some(Self::Anonymous),
            _ => {
                tracing::warn!(?protocol, "unknown i2cp protocol");
                None
            }
        }
    }

    /// Serialize [`Protocol`].
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Streaming => 6u8,
            Self::Datagram => 17u8,
            Self::Datagram2 => 19u8,
            Self::Anonymous => 18u8,
        }
    }
}
