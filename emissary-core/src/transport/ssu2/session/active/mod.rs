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

#![allow(unused)]

use crate::{
    crypto::chachapoly::{ChaCha, ChaChaPoly},
    error::Ssu2Error,
    i2np::Message,
    primitives::RouterId,
    runtime::Runtime,
    subsystem::{SubsystemCommand, SubsystemHandle},
    transport::{
        ssu2::{
            message::{
                data::{DataMessageBuilder, MessageKind},
                Block, HeaderKind, HeaderReader,
            },
            session::{
                active::{
                    ack::{AckInfo, RemoteAckManager},
                    duplicate::DuplicateFilter,
                    fragment::FragmentHandler,
                    transmission::TransmissionManager,
                },
                terminating::TerminationContext,
                KeyContext,
            },
            Packet,
        },
        TerminationReason,
    },
};

use futures::{FutureExt, StreamExt};
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Poll},
    time::Duration,
};

mod ack;
mod duplicate;
mod fragment;
mod transmission;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::active";

/// Command channel size.
const CMD_CHANNEL_SIZE: usize = 512;

/// SSU2 resend timeout
const SSU2_RESEND_TIMEOUT: Duration = Duration::from_millis(40);

/// SSU2 active session context.
pub struct Ssu2SessionContext {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    pub intro_key: [u8; 32],

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pub pkt_rx: Receiver<Packet>,

    /// Key context for inbound packets.
    pub recv_key_ctx: KeyContext,

    /// ID of the remote router.
    pub router_id: RouterId,

    /// Key context for outbound packets.
    pub send_key_ctx: KeyContext,
}

/// Active SSU2 session.
pub struct Ssu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// RX channel for receiving messages from subsystems.
    cmd_rx: Receiver<SubsystemCommand>,

    /// TX channel for sending commands for this connection.
    cmd_tx: Sender<SubsystemCommand>,

    /// Destination connection ID.
    dst_id: u64,

    /// Duplicate message filter.
    duplicate_filter: DuplicateFilter<R>,

    /// Fragment handler.
    fragment_handler: FragmentHandler<R>,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    intro_key: [u8; 32],

    /// Next packet number.
    pkt_num: Arc<AtomicU32>,

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pkt_rx: Receiver<Packet>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: `R::UdpSocket` should be clonable
    pkt_tx: Sender<Packet>,

    /// Key context for inbound packets.
    recv_key_ctx: KeyContext,

    /// Remote ACK manager.
    remote_ack: RemoteAckManager<R>,

    /// Resend timer.
    resend_timer: Option<R::Timer>,

    /// ID of the remote router.
    router_id: RouterId,

    /// Key context for outbound packets.
    send_key_ctx: KeyContext,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Transmission manager.
    transmission: TransmissionManager<R>,
}

impl<R: Runtime> Ssu2Session<R> {
    /// Create new [`Ssu2Session`].
    pub fn new(
        context: Ssu2SessionContext,
        pkt_tx: Sender<Packet>,
        subsystem_handle: SubsystemHandle,
    ) -> Self {
        let (cmd_tx, cmd_rx) = channel(CMD_CHANNEL_SIZE);
        let pkt_num = Arc::new(AtomicU32::new(1u32));

        tracing::debug!(
            target: LOG_TARGET,
            dst_id = ?context.dst_id,
            address = ?context.address,
            "starting active session",
        );

        Self {
            address: context.address,
            cmd_rx,
            cmd_tx,
            dst_id: context.dst_id,
            duplicate_filter: DuplicateFilter::new(),
            fragment_handler: FragmentHandler::<R>::new(),
            intro_key: context.intro_key,
            pkt_num: Arc::clone(&pkt_num),
            pkt_rx: context.pkt_rx,
            pkt_tx,
            recv_key_ctx: context.recv_key_ctx,
            remote_ack: RemoteAckManager::<R>::new(Arc::clone(&pkt_num)),
            resend_timer: None,
            router_id: context.router_id.clone(),
            send_key_ctx: context.send_key_ctx,
            subsystem_handle,
            transmission: TransmissionManager::<R>::new(context.router_id, pkt_num),
        }
    }

    /// Handle inbound `message`.
    ///
    /// If the message is expired or a duplicate, it's dropped. Otherwise it's
    /// dispatched to the correct subsystem for further processing.
    fn handle_message(&mut self, message: Message) {
        if message.is_expired::<R>() {
            tracing::trace!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                message_type = ?message.message_type,
                message_id = ?message.message_id,
                expiration = ?message.expiration,
                "discarding expired message",
            );
            return;
        }

        if !self.duplicate_filter.insert(message.message_id) {
            tracing::debug!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                message_id = ?message.message_id,
                message_type = ?message.message_type,
                "ignoring duplicate message",
            );
            return;
        }

        if let Err(error) =
            self.subsystem_handle.dispatch_messages(self.router_id.clone(), vec![message])
        {
            tracing::warn!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                ?error,
                "failed to dispatch messages to subsystems",
            );
        }
    }

    /// Handle received `pkt` for this session.
    fn handle_packet(&mut self, pkt: Packet) -> Result<(), Ssu2Error> {
        let Packet { mut pkt, .. } = pkt;

        let (pkt_num, immediate_ack) = match HeaderReader::new(self.intro_key, &mut pkt)?
            .parse(self.recv_key_ctx.k_header_2)?
        {
            HeaderKind::Data {
                immediate_ack,
                pkt_num,
            } => (pkt_num, immediate_ack),
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?kind,
                    "unexpected packet",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        };

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            ?pkt_num,
            pkt_len = ?pkt.len(),
            ?immediate_ack,
            "handle packet",
        );

        // TODO: unnecessary memory copy
        let mut payload = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&self.recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&pkt[..16], &mut payload)?;

        for block in Block::parse(&payload).ok_or(Ssu2Error::Malformed)? {
            match block {
                Block::Termination {
                    reason,
                    num_valid_pkts,
                } => {
                    self.remote_ack.register_non_ack_eliciting_pkt(pkt_num, immediate_ack);

                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?reason,
                        ?num_valid_pkts,
                        "session terminated by remote router",
                    );

                    return Err(Ssu2Error::SessionTerminated(TerminationReason::ssu2(
                        reason,
                    )));
                }
                Block::I2Np { message } => {
                    self.handle_message(message);
                    self.remote_ack.register_pkt(pkt_num, immediate_ack);
                }
                Block::FirstFragment {
                    message_type,
                    message_id,
                    expiration,
                    fragment,
                } => {
                    self.remote_ack.register_pkt(pkt_num, immediate_ack);

                    if let Some(message) = self.fragment_handler.first_fragment(
                        message_type,
                        message_id,
                        expiration,
                        fragment,
                    ) {
                        self.handle_message(message);
                    }
                }
                Block::FollowOnFragment {
                    last,
                    message_id,
                    fragment_num,
                    fragment,
                } => {
                    self.remote_ack.register_pkt(pkt_num, immediate_ack);

                    if let Some(message) = self.fragment_handler.follow_on_fragment(
                        message_id,
                        fragment_num,
                        last,
                        fragment,
                    ) {
                        self.handle_message(message);
                    }
                }
                Block::Ack {
                    ack_through,
                    num_acks,
                    ranges,
                } => {
                    self.remote_ack.register_non_ack_eliciting_pkt(pkt_num, immediate_ack);
                    self.remote_ack.register_ack(ack_through, num_acks, &ranges);
                    self.transmission.register_ack(ack_through, num_acks, &ranges);
                }
                Block::Address { .. } | Block::DateTime { .. } | Block::Padding { .. } => {
                    self.remote_ack.register_non_ack_eliciting_pkt(pkt_num, immediate_ack);
                }
                block => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?block,
                        "ignoring block",
                    );
                    self.remote_ack.register_pkt(pkt_num, immediate_ack);
                }
            }
        }

        Ok(())
    }

    /// Send `message` to remote router.
    fn send_message(&mut self, message: Vec<u8>) {
        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            message_len = ?message.len(),
            "send i2np message",
        );

        // TODO: this makes no sense, get unserialized message from subsystem
        let message = Message::parse_short(&message).unwrap();
        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack.ack_info();

        for (pkt_num, message_kind) in self.transmission.segment(message) {
            let message = DataMessageBuilder::default()
                .with_dst_id(self.dst_id)
                .with_key_context(self.intro_key, &self.send_key_ctx)
                .with_message(pkt_num, message_kind)
                .with_ack(highest_seen, num_acks, ranges.clone()) // TODO: remove clone
                .build::<R>();

            if let Err(error) = self.pkt_tx.try_send(Packet {
                pkt: message.to_vec(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?error,
                    "failed to send packet",
                );
            }

            if self.resend_timer.is_none() {
                self.resend_timer = Some(R::timer(SSU2_RESEND_TIMEOUT));
            }
        }
    }

    fn resend(&mut self) -> usize {
        let Some(packets_to_resend) = self.transmission.resend() else {
            return 0;
        };

        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack.ack_info();

        packets_to_resend.fold(0usize, |mut pkt_count, (pkt_num, message_kind)| {
            let message = DataMessageBuilder::default()
                .with_dst_id(self.dst_id)
                .with_key_context(self.intro_key, &self.send_key_ctx)
                .with_message(pkt_num, message_kind)
                .with_ack(highest_seen, num_acks, ranges.clone()) // TODO: remove clone
                .build::<R>();

            if let Err(error) = self.pkt_tx.try_send(Packet {
                pkt: message.to_vec(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?error,
                    "failed to send packet",
                );
            }

            pkt_count + 1
        })
    }

    /// Run the event loop of an active SSU2 session.
    pub async fn run(mut self) -> TerminationContext {
        self.subsystem_handle
            .report_connection_established(self.router_id.clone(), self.cmd_tx.clone())
            .await;

        // run the event loop until it returns which happens only when
        // the peer has disconnected or an error was encoutered
        //
        // inform other subsystems of the disconnection
        let reason = (&mut self).await;

        self.subsystem_handle.report_connection_closed(self.router_id.clone()).await;

        TerminationContext {
            address: self.address,
            dst_id: self.dst_id,
            intro_key: self.intro_key,
            next_pkt_num: self.transmission.next_pkt_num(),
            reason,
            recv_key_ctx: self.recv_key_ctx,
            router_id: self.router_id,
            rx: self.pkt_rx,
            send_key_ctx: self.send_key_ctx,
            tx: self.pkt_tx,
        }
    }
}

impl<R: Runtime> Future for Ssu2Session<R> {
    type Output = TerminationReason;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.pkt_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(TerminationReason::Unspecified),
                Poll::Ready(Some(pkt)) => match self.handle_packet(pkt) {
                    Ok(()) => {}
                    Err(Ssu2Error::Malformed) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "failed to parse ssu2 message blocks",
                        );
                        debug_assert!(false);
                    }
                    Err(Ssu2Error::SessionTerminated(reason)) => return Poll::Ready(reason),
                    Err(Ssu2Error::Chacha) => tracing::warn!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        "encryption/decryption failure, shutting down session",
                    ),
                    Err(error) => tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?error,
                        "failed to process packet",
                    ),
                },
            }
        }

        loop {
            match self.cmd_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(TerminationReason::Unspecified),
                Poll::Ready(Some(SubsystemCommand::SendMessage { message })) =>
                    self.send_message(message),
                Poll::Ready(Some(SubsystemCommand::Dummy)) => {}
            }
        }

        loop {
            match &mut self.resend_timer {
                None => break,
                Some(timer) => match timer.poll_unpin(cx) {
                    Poll::Pending => break,
                    Poll::Ready(_) => {
                        let num_resent = self.resend();

                        if num_resent > 0 {
                            tracing::trace!(
                                target: LOG_TARGET,
                                router_id = %self.router_id,
                                ?num_resent,
                                "packet resent",
                            );
                        }

                        self.resend_timer = Some(R::timer(SSU2_RESEND_TIMEOUT));
                    }
                },
            }
        }

        if let Poll::Ready(AckInfo {
            highest_seen,
            num_acks,
            ranges,
        }) = self.remote_ack.poll_unpin(cx)
        {
            tracing::error!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                ?highest_seen,
                ?num_acks,
                ?ranges,
                "send explicit ack",
            );

            let message = DataMessageBuilder::default()
                .with_dst_id(self.dst_id)
                .with_key_context(self.intro_key, &self.send_key_ctx)
                .with_pkt_num(self.pkt_num.fetch_add(1u32, Ordering::Relaxed))
                .with_ack(highest_seen, num_acks, ranges)
                .build::<R>();

            // TODO: report `pkt_num` to `RemoteAckManager`?

            if let Err(error) = self.pkt_tx.try_send(Packet {
                pkt: message.to_vec(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?error,
                    "failed to send explicit ack packet",
                );
            }

            // TODO: start resend timer for ack?
        }

        // poll duplicate message filter and fragment handler
        //
        // the futures don't return anything but must be polled so they make progress
        let _ = self.duplicate_filter.poll_unpin(cx);
        let _ = self.fragment_handler.poll_unpin(cx);

        Poll::Pending
    }
}
