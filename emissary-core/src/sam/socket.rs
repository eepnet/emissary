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
    runtime::{AsyncRead, AsyncWrite, Runtime},
    sam::parser::SamCommand,
    util::AsyncWriteExt,
};

use futures::Stream;

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::socket";

/// Write state
enum WriteState {
    /// Read next outbound message from message buffer.
    GetMessage,

    /// Send message.
    SendMessage {
        /// Write offset.
        offset: usize,

        /// SAMv3 message, potentially partially written.
        message: Vec<u8>,
    },

    /// [`WriteState`] has been poisoned due to a bug.
    Poisoned,
}

/// SAMv3 socket.
///
/// Reads new line-delimeted commands from socket and returns them to the caller.
///
/// Invalid or unsupported commands cause the socket to be closed.
pub struct SamSocket<R: Runtime> {
    /// Pending messages.
    pending_messages: VecDeque<Vec<u8>>,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Read offset.
    read_offset: usize,

    /// TCP stream.
    stream: R::TcpStream,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> SamSocket<R> {
    /// Create new [`SamSocket`] from an active TCP stream.
    pub fn new(stream: R::TcpStream) -> Self {
        Self {
            pending_messages: VecDeque::new(),
            read_buffer: vec![0u8; 4096],
            read_offset: 0usize,
            stream,
            write_state: WriteState::GetMessage,
        }
    }

    /// Convert [`SamSocket`] into `TcpStream`.
    pub fn into_inner(self) -> R::TcpStream {
        self.stream
    }

    /// Send `message` to client.
    pub fn send_message(&mut self, message: Vec<u8>) {
        self.pending_messages.push_back(message);
    }

    /// Send `message` to client and block until the message has been fully written.
    pub async fn send_message_blocking(&mut self, message: Vec<u8>) -> crate::Result<()> {
        self.stream.write_all(&message).await
    }
}

impl<R: Runtime> Stream for SamSocket<R> {
    type Item = SamCommand;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut this.stream);

        loop {
            match stream.as_mut().poll_read(cx, &mut this.read_buffer[this.read_offset..]) {
                Poll::Pending => break,
                Poll::Ready(Err(error)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "socket read error",
                    );

                    return Poll::Ready(None);
                }
                Poll::Ready(Ok(nread)) => {
                    if nread == 0 {
                        tracing::debug!(
                            target: LOG_TARGET,
                            offset = ?this.read_offset,
                            "read zero bytes from socket",
                        );

                        return Poll::Ready(None);
                    }

                    match this.read_buffer.iter().position(|byte| byte == &b'\n') {
                        // full command hasn't been read yet
                        None => {
                            this.read_offset += nread;
                        }
                        // full command read
                        //
                        // parse and return it to socket's owner
                        Some(pos) => match core::str::from_utf8(&this.read_buffer[..pos]) {
                            Ok(command) => {
                                this.read_offset = 0usize;

                                match SamCommand::parse::<R>(command) {
                                    Some(command) => return Poll::Ready(Some(command)),
                                    None => tracing::warn!(
                                        target: LOG_TARGET,
                                        %command,
                                        "invalid sam command",
                                    ),
                                }
                            }
                            Err(error) => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "invalid command"
                                );
                                return Poll::Ready(None);
                            }
                        },
                    }
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.pending_messages.pop_front() {
                    None => {
                        this.write_state = WriteState::GetMessage;
                        break;
                    }
                    Some(message) => {
                        this.write_state = WriteState::SendMessage {
                            offset: 0usize,
                            message,
                        };
                    }
                },
                WriteState::SendMessage { offset, message } =>
                    match stream.as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::SendMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(None),
                        Poll::Ready(Ok(0)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "wrote zero bytes to socket",
                            );

                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(nwritten)) => match nwritten + offset == message.len() {
                            true => {
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::SendMessage {
                                    offset: offset + nwritten,
                                    message,
                                };
                            }
                        },
                    },
                WriteState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(None);
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            TcpStream as _,
        },
        sam::parser::SamVersion,
    };
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    #[tokio::test(start_paused = true)]
    async fn read_command_normal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        tokio::spawn(async move {
            let (mut stream, _) = stream1.unwrap();
            stream.write_all("HELLO VERSION\n".as_bytes()).await.unwrap();

            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        match socket.next().await {
            Some(command) => assert_eq!(
                command,
                SamCommand::Hello {
                    min: None,
                    max: None
                }
            ),
            None => panic!("socket exited"),
        }

        assert_eq!(socket.read_offset, 0usize);
    }

    #[tokio::test(start_paused = true)]
    async fn read_command_partial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        // send partial command at first
        stream.write_all("HELLO VER".as_bytes()).await.unwrap();

        // poll socket until the partial command has been read
        loop {
            futures::future::poll_fn(|cx| match socket.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("socket is ready"),
            })
            .await;

            if socket.read_offset == 9usize {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // send rest of the command
        stream.write_all("SION MIN=3.1 MAX=3.3\n".as_bytes()).await.unwrap();

        match socket.next().await {
            Some(command) => assert_eq!(
                command,
                SamCommand::Hello {
                    min: Some(SamVersion::V31),
                    max: Some(SamVersion::V33)
                }
            ),
            None => panic!("socket exited"),
        }

        assert_eq!(socket.read_offset, 0usize);
    }
}
