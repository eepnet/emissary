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

//! Active NTCP2 session.
//!
//! https://geti2p.net/spec/ntcp2#data-phase

use crate::{
    crypto::{chachapoly::ChaChaPoly, siphash::SipHash},
    events::EventHandle,
    primitives::{RouterId, RouterInfo},
    runtime::{AsyncRead, AsyncWrite, Runtime},
    subsystem::SubsystemCommand,
    transport::{
        ntcp2::{
            message::MessageBlock,
            session::{KeyContext, Role},
        },
        Direction, SubsystemHandle, TerminationReason,
    },
};

use futures::FutureExt;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::active";

/// Read state.
enum ReadState {
    /// Read NTCP2 frame length.
    ReadSize {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Read NTCP2 frame.
    ReadFrame {
        /// Size of the next frame.
        size: usize,

        /// Offset into read buffer.
        offset: usize,
    },
}

/// Write state
enum WriteState {
    /// Read next message from `cmd_rx`.
    GetMessage,

    /// Send message size.
    SendSize {
        /// Write offset.
        offset: usize,

        /// Obfuscated message size as a byte vector.
        size: Vec<u8>,

        /// I2NP message.
        message: Vec<u8>,
    },

    /// Send message.
    SendMessage {
        /// Write offset.
        offset: usize,

        /// I2NP message, potentially partially written.
        message: Vec<u8>,
    },

    /// [`WriteState`] has been poisoned due to a bug.
    Poisoned,
}

/// Active NTCP2 session.
pub struct Ntcp2Session<R: Runtime> {
    /// RX channel for receiving messages from subsystems.
    cmd_rx: Receiver<SubsystemCommand>,

    /// TX channel for sending commands for this connection.
    cmd_tx: Sender<SubsystemCommand>,

    /// Direction of the session.
    direction: Direction,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// Total inbound bandwidth.
    inbound_bandwidth: usize,

    /// Total outbound bandwidth.
    outbound_bandwidth: usize,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Read state.
    read_state: ReadState,

    /// Cipher for inbound messages.
    recv_cipher: ChaChaPoly,

    /// Role of the session.
    role: Role,

    /// Router ID.
    router: RouterId,

    /// `RouterInfo` of the remote peer.
    router_info: RouterInfo,

    /// Cipher for outbound messages.
    send_cipher: ChaChaPoly,

    /// SipHasher for (de)obfuscating message lengths.
    sip: SipHash,

    /// TCP stream.
    stream: R::TcpStream,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Ntcp2Session<R> {
    /// Create new active NTCP2 [`Session`].
    pub fn new(
        role: Role,
        router_info: RouterInfo,
        stream: R::TcpStream,
        key_context: KeyContext,
        subsystem_handle: SubsystemHandle,
        direction: Direction,
        event_handle: EventHandle<R>,
    ) -> Self {
        let KeyContext {
            send_key,
            recv_key,
            sip,
        } = key_context;

        let (cmd_tx, cmd_rx) = channel(512);

        Self {
            cmd_rx,
            cmd_tx,
            direction,
            event_handle,
            inbound_bandwidth: 0usize,
            outbound_bandwidth: 0usize,
            read_buffer: vec![0u8; 0xffff],
            read_state: ReadState::ReadSize { offset: 0usize },
            recv_cipher: ChaChaPoly::new(&recv_key),
            role,
            router: router_info.identity.id(),
            router_info,
            send_cipher: ChaChaPoly::new(&send_key),
            sip,
            stream,
            subsystem_handle,
            write_state: WriteState::GetMessage,
        }
    }

    /// Get [`Direction`] of the session.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Get role of the session.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get `RouterInfo` of the remote peer.
    pub fn router(&self) -> RouterInfo {
        self.router_info.clone()
    }

    pub async fn run(mut self) -> (RouterId, TerminationReason) {
        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router,
            "start ntcp2 event loop",
        );

        self.subsystem_handle
            .report_connection_established(self.router.clone(), self.cmd_tx.clone())
            .await;

        // run the event loop until it returns which happens only when
        // the peer has disconnected or an error was encoutered
        //
        // inform other subsystems of the disconnection
        let reason = (&mut self).await;

        self.subsystem_handle.report_connection_closed(self.router.clone()).await;
        (self.router, reason)
    }
}

impl<R: Runtime> Future for Ntcp2Session<R> {
    type Output = TerminationReason;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut this.stream);

        loop {
            match this.read_state {
                ReadState::ReadSize { offset } => {
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer[offset..2]) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                router_id = %this.router,
                                ?error,
                                "socket error",
                            );
                            return Poll::Ready(TerminationReason::IoError);
                        }
                        Poll::Ready(Ok(nread)) => {
                            if nread == 0 {
                                return Poll::Ready(TerminationReason::IoError);
                            }

                            if offset + nread != 2 {
                                this.read_state = ReadState::ReadSize {
                                    offset: offset + nread,
                                };
                                continue;
                            }

                            let size = ((this.read_buffer[0] as u16) << 8)
                                | (this.read_buffer[1] as u16) & 0xff;

                            this.read_state = ReadState::ReadFrame {
                                size: this.sip.deobfuscate(size) as usize,
                                offset: 0usize,
                            };
                        }
                    }
                }
                ReadState::ReadFrame { size, offset } => {
                    match stream.as_mut().poll_read(cx, &mut this.read_buffer[offset..size]) {
                        Poll::Pending => break,
                        Poll::Ready(Err(_)) => return Poll::Ready(TerminationReason::IoError),
                        Poll::Ready(Ok(nread)) => {
                            if nread == 0 {
                                return Poll::Ready(TerminationReason::IoError);
                            }

                            // next frame hasn't been read completely
                            if offset + nread < size {
                                this.read_state = ReadState::ReadFrame {
                                    size,
                                    offset: offset + nread,
                                };
                                continue;
                            }
                            this.inbound_bandwidth += this.read_buffer[..size].len();

                            let data_block =
                                match this.recv_cipher.decrypt(this.read_buffer[..size].to_vec()) {
                                    Ok(data_block) => data_block,
                                    Err(_) => return Poll::Ready(TerminationReason::AeadFailure),
                                };

                            let messages = match MessageBlock::parse_multiple(&data_block) {
                                Ok(messages) => messages,
                                Err(error) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        router_id = %this.router,
                                        ?data_block,
                                        ?error,
                                        "failed to parse message(s)",
                                    );
                                    continue;
                                }
                            };

                            tracing::trace!(
                                target: LOG_TARGET,
                                router_id = %this.router,
                                ?size,
                                num_messages = ?messages.len(),
                                "read ntcp2 frame",
                            );

                            if let Some(MessageBlock::Termination { reason, .. }) =
                                messages.iter().find(|message| {
                                    core::matches!(message, MessageBlock::Termination { .. })
                                })
                            {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    router_id = %this.router,
                                    ?reason,
                                    "session terminated by remote router",
                                );
                                return Poll::Ready(TerminationReason::ntcp2(*reason));
                            }

                            let messages = messages
                                .into_iter()
                                .filter_map(|message| match message {
                                    MessageBlock::I2Np { message } =>
                                        if message.is_expired::<R>() {
                                            tracing::trace!(
                                                target: LOG_TARGET,
                                                router_id = %this.router,
                                                message_type = ?message.message_type,
                                                message_id = ?message.message_id,
                                                expiration = ?message.expiration,
                                                "discarding expired message",
                                            );
                                            None
                                        } else {
                                            Some(message)
                                        },
                                    MessageBlock::Padding { .. } => None,
                                    message => {
                                        tracing::debug!(
                                            target: LOG_TARGET,
                                            router_id = %this.router,
                                            ?message,
                                            "ignoring message",
                                        );
                                        None
                                    }
                                })
                                .collect::<Vec<_>>();

                            if let Err(error) = this
                                .subsystem_handle
                                .dispatch_messages(this.router.clone(), messages)
                            {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    router_id = %this.router,
                                    ?error,
                                    "failed to dispatch messages to subsystems",
                                );
                            }
                            this.read_state = ReadState::ReadSize { offset: 0usize };
                        }
                    }
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                // TODO: poll messages until `Poll::Pending` is returned
                // or there's enough messages to fill one ntcp2 message?
                WriteState::GetMessage => match this.cmd_rx.poll_recv(cx) {
                    Poll::Pending => {
                        this.write_state = WriteState::GetMessage;
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(TerminationReason::Unspecified),
                    Poll::Ready(Some(SubsystemCommand::Dummy)) => unreachable!(),
                    Poll::Ready(Some(SubsystemCommand::SendMessage { message })) => {
                        assert!(message.len() as u16 <= u16::MAX, "too large message");

                        // TODO: in-place?
                        let test = MessageBlock::new_i2np_message(&message);
                        let data_block = this.send_cipher.encrypt(&test).unwrap();
                        let size = this.sip.obfuscate(data_block.len() as u16);

                        this.write_state = WriteState::SendSize {
                            size: size.to_be_bytes().to_vec(),
                            offset: 0usize,
                            message: data_block,
                        };
                    }
                },
                WriteState::SendSize {
                    offset,
                    size,
                    message,
                } => match stream.as_mut().poll_write(cx, &size[offset..]) {
                    Poll::Pending => {
                        this.write_state = WriteState::SendSize {
                            offset,
                            size,
                            message,
                        };
                        break;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(TerminationReason::IoError),
                    Poll::Ready(Ok(0)) => return Poll::Ready(TerminationReason::IoError),
                    Poll::Ready(Ok(nwritten)) => {
                        this.outbound_bandwidth += nwritten;

                        match nwritten + offset == size.len() {
                            true => {
                                this.write_state = WriteState::SendMessage {
                                    offset: 0usize,
                                    message,
                                };
                            }
                            false => {
                                this.write_state = WriteState::SendSize {
                                    size,
                                    offset: offset + nwritten,
                                    message,
                                };
                            }
                        }
                    }
                },
                WriteState::SendMessage { offset, message } => {
                    match stream.as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::SendMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(TerminationReason::IoError),
                        Poll::Ready(Ok(0)) => return Poll::Ready(TerminationReason::IoError),
                        Poll::Ready(Ok(nwritten)) => {
                            this.outbound_bandwidth += nwritten;

                            match nwritten + offset == message.len() {
                                true => {
                                    this.write_state = WriteState::GetMessage;
                                }
                                false => {
                                    this.write_state = WriteState::SendMessage {
                                        offset: offset + nwritten,
                                        message,
                                    };
                                }
                            }
                        }
                    }
                }
                WriteState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        router = %this.router,
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(TerminationReason::Unspecified);
                }
            }
        }

        if this.event_handle.poll_unpin(cx).is_ready() {
            self.event_handle.transport_inbound_bandwidth(self.inbound_bandwidth);
            self.event_handle.transport_outbound_bandwidth(self.outbound_bandwidth);
            self.inbound_bandwidth = 0;
            self.outbound_bandwidth = 0;
        }

        Poll::Pending
    }
}
