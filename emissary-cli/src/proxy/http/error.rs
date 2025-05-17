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

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError {
    /// Host missing from request.
    InvalidHost,

    // Invalid path.
    InvalidPath,

    /// I/O error.
    Io(std::io::ErrorKind),

    /// Parse error.
    Malformed,

    /// Method missing.
    MethodMissing,

    /// Method not supported.
    MethodNotSupported(String),

    /// Host was not found in address book.
    HostNotFound,

    /// Address book was not enabled.
    AddressBookNotEnabled,

    /// Outproxy was not enabled.
    OutproxyNotEnabled,

    /// Received partial request.
    PartialRequest,
}

impl From<std::io::Error> for HttpError {
    fn from(value: std::io::Error) -> Self {
        HttpError::Io(value.kind())
    }
}

impl From<httparse::Error> for HttpError {
    fn from(_: httparse::Error) -> Self {
        HttpError::Malformed
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::InvalidHost => write!(f, "Invalid host"),
            HttpError::InvalidPath => write!(f, "Invalid path"),
            HttpError::Io(error) => write!(f, "I/O error: {error}"),
            HttpError::Malformed => write!(f, "Malformed request"),
            HttpError::MethodMissing => write!(f, "Method missing"),
            HttpError::MethodNotSupported(method) => write!(f, "Method not supported: {method}"),
            HttpError::HostNotFound => write!(f, "Host not found in address book"),
            HttpError::AddressBookNotEnabled =>
                write!(f, "Cannot connect to .i2p host, address book not enabled"),
            HttpError::OutproxyNotEnabled => write!(
                f,
                "Cannot connect to clearnet address, outproxy not enabled"
            ),
            HttpError::PartialRequest => write!(f, "Partial request"),
        }
    }
}
