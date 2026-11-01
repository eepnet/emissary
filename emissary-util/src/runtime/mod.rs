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

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "smol")]
pub mod smol;

/// Returns `true` if `error` is a transient `accept()` error after which the
/// listener socket is still usable and should keep accepting connections.
///
/// A single aborted or reset connection (e.g. a peer that connected and then
/// reset, reported as `ECONNABORTED`/`ECONNRESET`) must not tear down the
/// listener.
///
/// Only genuinely fatal errors (e.g. the listening socket was closed
/// or is invalid, or the file descriptor limit was reached) should terminate
/// the listener.
pub(crate) fn is_transient_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_accept_errors_are_retryable() {
        assert!(is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "connection aborted",
        )));
        assert!(is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset",
        )));
        assert!(is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "interrupted",
        )));
        assert!(is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "would block",
        )));
        assert!(is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )));
        assert!(is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        )));
    }

    #[test]
    fn fatal_accept_errors_terminate() {
        assert!(!is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid input",
        )));
        assert!(!is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        )));
        assert!(!is_transient_accept_error(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "other",
        )));
    }
}
