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
    i2cp::message::{Message, MessageType, I2CP_HEADER_SIZE},
    runtime::{AsyncRead, AsyncWrite, Runtime},
};

use bytes::BytesMut;
use futures::Stream;

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::socket";

/// Read state.
enum ReadState {
    /// Read I2CP message header.
    ReadHeader {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Read I2CP frame.
    ReadFrame {
        /// Size of the next frame.
        size: usize,

        /// Unparsed message type.
        ///
        /// Message type parsed only after the full frame has been read so that
        /// the payload of the invalid message can be read and discarded.
        msg_type: u8,

        /// Offset into read buffer.
        offset: usize,
    },
}

/// Write state
enum WriteState {
    /// Read next outbound message from message buffer.
    GetMessage,

    /// Send message.
    SendMessage {
        /// Write offset.
        offset: usize,

        /// I2CP message, potentially partially written.
        message: BytesMut,
    },

    /// [`WriteState`] has been poisoned due to a bug.
    Poisoned,
}

/// I2CP client socket.
pub struct I2cpSocket<R: Runtime> {
    /// Pending outbound frames.
    pending_frames: VecDeque<BytesMut>,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Read state.
    read_state: ReadState,

    /// TCP stream.
    stream: R::TcpStream,

    /// Waker, if any.
    waker: Option<Waker>,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> I2cpSocket<R> {
    /// Create new [`I2cpSocket`].
    pub fn new(stream: R::TcpStream) -> Self {
        Self {
            pending_frames: VecDeque::new(),
            read_buffer: vec![0u8; 0xffff],
            read_state: ReadState::ReadHeader { offset: 0usize },
            stream,
            write_state: WriteState::GetMessage,
            waker: None,
        }
    }

    /// Attempt to send `message` to the connected I2CP client.
    pub fn send_message(&mut self, message: BytesMut) {
        self.pending_frames.push_back(message);

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }
}

impl<R: Runtime> Stream for I2cpSocket<R> {
    type Item = Message;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut this.stream);

        loop {
            match this.read_state {
                ReadState::ReadHeader { offset } => {
                    match stream
                        .as_mut()
                        .poll_read(cx, &mut this.read_buffer[offset..I2CP_HEADER_SIZE])
                    {
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
                                    ?offset,
                                    "read zero bytes from socket (header)",
                                );

                                return Poll::Ready(None);
                            }

                            if offset + nread != I2CP_HEADER_SIZE {
                                this.read_state = ReadState::ReadHeader {
                                    offset: offset + nread,
                                };
                                continue;
                            }

                            // conversion succeeds because `read_buffer` is ensured to have 5 bytes
                            let size = u32::from_be_bytes(
                                TryInto::<[u8; 4]>::try_into(&this.read_buffer[..4])
                                    .expect("to succeed"),
                            );
                            let msg_type = this.read_buffer[4];

                            // some i2cp messages may not contain a payload (such as
                            // `GetBandwithLimits`) meaning the message type is the entire message
                            //
                            // these messages must be handled before attempting to read any bytes
                            // from socket and the read state must be reset to `ReadHeader`
                            if size == 0 {
                                this.read_state = ReadState::ReadHeader { offset: 0usize };

                                let Some(msg_type) = MessageType::from_u8(msg_type) else {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        ?msg_type,
                                        "invalid message type",
                                    );

                                    continue;
                                };

                                let Some(message) = Message::parse::<R>(msg_type, []) else {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        ?msg_type,
                                        "failed to parse i2cp message with no payload",
                                    );

                                    continue;
                                };

                                return Poll::Ready(Some(message));
                            }

                            this.read_state = ReadState::ReadFrame {
                                size: size as usize,
                                msg_type,
                                offset: 0usize,
                            };
                        }
                    }
                }
                ReadState::ReadFrame {
                    size,
                    msg_type,
                    offset,
                } => {
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer[offset..size]) {
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
                                    "read zero bytes from socket (payload)",
                                );

                                return Poll::Ready(None);
                            }

                            // next frame hasn't been read completely
                            if offset + nread < size {
                                this.read_state = ReadState::ReadFrame {
                                    size,
                                    msg_type,
                                    offset: offset + nread,
                                };
                                continue;
                            }

                            // frame has been fully, reset read state and attempt to parse message
                            this.read_state = ReadState::ReadHeader { offset: 0usize };

                            let Some(msg_type) = MessageType::from_u8(msg_type) else {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?msg_type,
                                    "invalid message type",
                                );

                                continue;
                            };

                            let Some(message) =
                                Message::parse::<R>(msg_type, &this.read_buffer[..size])
                            else {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    ?msg_type,
                                    "failed to parse i2cp message",
                                );
                                continue;
                            };

                            return Poll::Ready(Some(message));
                        }
                    }
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.pending_frames.pop_front() {
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

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
