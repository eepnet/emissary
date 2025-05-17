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

use crate::proxy::http::HttpError;

use tokio::{io::AsyncWriteExt, net::TcpStream};

/// Error status.
pub enum Status {
    /// HTTP 400 Bad Request.
    BadRequest(HttpError),

    /// HTTP 500 Gateway Timeout.
    GatewayTimeout(String),
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::BadRequest(_) => write!(f, "400 Bad Request"),
            Self::GatewayTimeout(_) => write!(f, "504 Gateway Timeout"),
        }
    }
}

// Send HTTP error response to client.
pub async fn send_response(mut stream: TcpStream, status: Status) {
    let http_error = status.to_string();
    let status_line = format!("HTTP/1.1 {http_error}");
    let headers = "Connection: close\r\nContent-Type: text/html; charset=UTF-8";
    let error = match status {
        Status::BadRequest(error) => error.to_string(),
        Status::GatewayTimeout(host) => format!("Failed to establish connection to {host}"),
    };
    let body = format!(
        r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>{http_error}</title>
            </head>
            <body>
                <h1>{http_error}</h1>
                <p>{error}</p>
            </body>
            </html>
        "#
    );

    // Combine status line, headers, and body
    let response = format!(
        "{status_line}\r\n{headers}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}
