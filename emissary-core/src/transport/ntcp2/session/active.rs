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
    runtime::{AsyncRead, AsyncWrite, Counter, Histogram, MetricsHandle, Runtime},
    subsystem::{OutboundMessage, OutboundMessageRecycle, SubsystemEvent},
    transport::{
        ntcp2::{
            message::MessageBlock,
            metrics::{
                MESSAGE_SIZES, NUM_BLOCKS_PER_MSG, NUM_INBOUND_MESSAGES, NUM_OUTBOUND_MESSAGES,
            },
            session::{KeyContext, Role},
        },
        Direction, TerminationReason,
    },
};

use futures::FutureExt;
use futures_channel::oneshot;
use thingbuf::mpsc::{with_recycle, Receiver, Sender};

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
    /// Read next message from `msg_rx`.
    GetMessage,

    /// Send message size.
    SendSize {
        /// Write offset.
        offset: usize,

        /// Obfuscated message size as a byte vector.
        size: Vec<u8>,

        /// I2NP message.
        message: Vec<u8>,

        /// TX channel for sending feedback of the send operation.
        ///
        /// `None` if feedback was not requested.
        feedback_tx: Option<oneshot::Sender<()>>,
    },

    /// Send message.
    SendMessage {
        /// Write offset.
        offset: usize,

        /// I2NP message, potentially partially written.
        message: Vec<u8>,

        /// TX channel for sending feedback of the send operation.
        ///
        /// `None` if feedback was not requested.
        feedback_tx: Option<oneshot::Sender<()>>,
    },

    /// [`WriteState`] has been poisoned due to a bug.
    Poisoned,
}

/// Active NTCP2 session.
pub struct Ntcp2Session<R: Runtime> {
    /// TX channel given to `SubsystemManager`.
    msg_tx: Sender<OutboundMessage, OutboundMessageRecycle>,

    /// RX channel for receiving messages from `SubsystemManager`.
    #[allow(unused)]
    msg_rx: Receiver<OutboundMessage, OutboundMessageRecycle>,

    /// TX channel for sending events to `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,

    /// Direction of the session.
    direction: Direction,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// Total inbound bandwidth.
    inbound_bandwidth: usize,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

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

    /// When was the hanshake started.
    started: R::Instant,

    /// TCP stream.
    stream: R::TcpStream,

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
        direction: Direction,
        event_handle: EventHandle<R>,
        transport_tx: Sender<SubsystemEvent>,
        started: R::Instant,
        metrics_handle: R::MetricsHandle,
    ) -> Self {
        let KeyContext {
            send_key,
            recv_key,
            sip,
        } = key_context;

        let (msg_tx, msg_rx) = with_recycle(512, OutboundMessageRecycle::default());

        Self {
            msg_rx,
            msg_tx,
            direction,
            event_handle,
            inbound_bandwidth: 0usize,
            metrics_handle,
            outbound_bandwidth: 0usize,
            read_buffer: vec![0u8; 0xffff],
            read_state: ReadState::ReadSize { offset: 0usize },
            recv_cipher: ChaChaPoly::new(&recv_key),
            role,
            router: router_info.identity.id(),
            router_info,
            send_cipher: ChaChaPoly::new(&send_key),
            sip,
            started,
            stream,
            transport_tx,
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

    /// When was the handshake started.
    pub fn started(&self) -> &R::Instant {
        &self.started
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

        // subsystem manager should never exit
        self.transport_tx
            .send(SubsystemEvent::ConnectionEstablished {
                router_id: self.router.clone(),
                tx: self.msg_tx.clone(),
            })
            .await
            .expect("manager to stay alive");

        // run the event loop until it returns which happens only when
        // the peer has disconnected or an error was encoutered
        //
        // inform other subsystems of the disconnection
        let reason = (&mut self).await;

        self.transport_tx
            .send(SubsystemEvent::ConnectionClosed {
                router_id: self.router.clone(),
            })
            .await
            .expect("manager to stay alive");

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
                            this.metrics_handle
                                .histogram(MESSAGE_SIZES)
                                .record(this.read_buffer[..size].len() as f64);
                            this.metrics_handle.counter(NUM_INBOUND_MESSAGES).increment(1);

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
                            this.metrics_handle
                                .histogram(NUM_BLOCKS_PER_MSG)
                                .record(messages.len() as f64);

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

                            if let Err(error) =
                                this.transport_tx.try_send(SubsystemEvent::Message {
                                    messages: messages
                                        .iter()
                                        .map(|message| (this.router.clone(), message.clone()))
                                        .collect(),
                                })
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
                WriteState::GetMessage => match this.msg_rx.poll_recv(cx) {
                    Poll::Pending => {
                        this.write_state = WriteState::GetMessage;
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(TerminationReason::Unspecified),
                    Poll::Ready(Some(OutboundMessage::Message(message))) => {
                        if message.is_expired::<R>() {
                            this.write_state = WriteState::GetMessage;
                            continue;
                        }

                        let message = message.serialize_short();
                        assert!(message.len() as u16 <= u16::MAX, "too large message");

                        // TODO: in-place?
                        let test = MessageBlock::new_i2np_message(&message);
                        let data_block = this.send_cipher.encrypt(&test).unwrap();
                        let size = this.sip.obfuscate(data_block.len() as u16);

                        this.write_state = WriteState::SendSize {
                            size: size.to_be_bytes().to_vec(),
                            offset: 0usize,
                            message: data_block,
                            feedback_tx: None,
                        };
                    }
                    Poll::Ready(Some(OutboundMessage::MessageWithFeedback(
                        message,
                        feedback_tx,
                    ))) => {
                        if message.is_expired::<R>() {
                            this.write_state = WriteState::GetMessage;
                            continue;
                        }

                        let message = message.serialize_short();
                        assert!(message.len() as u16 <= u16::MAX, "too large message");

                        // TODO: in-place?
                        let test = MessageBlock::new_i2np_message(&message);
                        let data_block = this.send_cipher.encrypt(&test).unwrap();
                        let size = this.sip.obfuscate(data_block.len() as u16);

                        this.write_state = WriteState::SendSize {
                            size: size.to_be_bytes().to_vec(),
                            offset: 0usize,
                            message: data_block,
                            feedback_tx: Some(feedback_tx),
                        };
                    }
                    Poll::Ready(Some(OutboundMessage::Messages(mut messages))) => {
                        assert!(!messages.is_empty());

                        // TODO: add support for packing multiple message blocks
                        if messages.len() > 1 {
                            todo!("not implemented")
                        }

                        let message = messages.pop().expect("message to exist");
                        if message.is_expired::<R>() {
                            this.write_state = WriteState::GetMessage;
                            continue;
                        }

                        let message = message.serialize_short();
                        assert!(message.len() as u16 <= u16::MAX, "too large message");

                        // TODO: in-place?
                        let test = MessageBlock::new_i2np_message(&message);
                        let data_block = this.send_cipher.encrypt(&test).unwrap();
                        let size = this.sip.obfuscate(data_block.len() as u16);

                        this.write_state = WriteState::SendSize {
                            size: size.to_be_bytes().to_vec(),
                            offset: 0usize,
                            message: data_block,
                            feedback_tx: None,
                        };
                    }
                    Poll::Ready(Some(OutboundMessage::Dummy)) => unreachable!(),
                },
                WriteState::SendSize {
                    offset,
                    size,
                    message,
                    feedback_tx,
                } => match stream.as_mut().poll_write(cx, &size[offset..]) {
                    Poll::Pending => {
                        this.write_state = WriteState::SendSize {
                            offset,
                            size,
                            message,
                            feedback_tx,
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
                                    feedback_tx,
                                };
                            }
                            false => {
                                this.write_state = WriteState::SendSize {
                                    size,
                                    offset: offset + nwritten,
                                    message,
                                    feedback_tx,
                                };
                            }
                        }
                    }
                },
                WriteState::SendMessage {
                    offset,
                    message,
                    feedback_tx,
                } => match stream.as_mut().poll_write(cx, &message[offset..]) {
                    Poll::Pending => {
                        this.write_state = WriteState::SendMessage {
                            offset,
                            message,
                            feedback_tx,
                        };
                        break;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(TerminationReason::IoError),
                    Poll::Ready(Ok(0)) => return Poll::Ready(TerminationReason::IoError),
                    Poll::Ready(Ok(nwritten)) => {
                        this.outbound_bandwidth += nwritten;

                        match nwritten + offset == message.len() {
                            true => {
                                if let Some(tx) = feedback_tx {
                                    let _ = tx.send(());
                                }

                                this.metrics_handle.counter(NUM_OUTBOUND_MESSAGES).increment(1);
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::SendMessage {
                                    offset: offset + nwritten,
                                    message,
                                    feedback_tx,
                                };
                            }
                        }
                    }
                },
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
