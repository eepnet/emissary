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
    crypto::chachapoly::{ChaCha, ChaChaPoly},
    error::Ssu2Error,
    i2np::Message,
    primitives::RouterId,
    runtime::Runtime,
    subsystem::{SubsystemCommand, SubsystemHandle},
    transport::{
        ssu2::{
            message::{data::DataMessageBuilder, Block},
            session::{
                active::{
                    ack::{LocalAckManager, RemoteAckManager},
                    duplicate::DuplicateFilter,
                    fragment::FragmentHandler,
                },
                terminating::TerminationContext,
                KeyContext,
            },
            Packet,
        },
        TerminationReason,
    },
};

use futures::FutureExt;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

mod ack;
mod duplicate;
mod fragment;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::active";

/// Command channel size.
const CMD_CHANNEL_SIZE: usize = 512;

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

    /// Local ACK manager.
    _local_ack: LocalAckManager,

    /// Next packet number.
    pkt_num: u32,

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pkt_rx: Receiver<Packet>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: `R::UdpSocket` should be clonable
    pkt_tx: Sender<Packet>,

    /// Key context for inbound packets.
    recv_key_ctx: KeyContext,

    /// Remote ACK manager.
    remote_ack: RemoteAckManager,
    /// ID of the remote router.
    router_id: RouterId,

    /// Key context for outbound packets.
    send_key_ctx: KeyContext,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,
}

impl<R: Runtime> Ssu2Session<R> {
    /// Create new [`Ssu2Session`].
    pub fn new(
        context: Ssu2SessionContext,
        pkt_tx: Sender<Packet>,
        subsystem_handle: SubsystemHandle,
    ) -> Self {
        let (cmd_tx, cmd_rx) = channel(CMD_CHANNEL_SIZE);

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
            _local_ack: LocalAckManager::new(),
            pkt_num: 1u32, // TODO: may not be correct for outbound sessions
            pkt_rx: context.pkt_rx,
            pkt_tx,
            recv_key_ctx: context.recv_key_ctx,
            remote_ack: RemoteAckManager::new(),
            router_id: context.router_id,
            send_key_ctx: context.send_key_ctx,
            subsystem_handle,
        }
    }

    /// Get next outbound packet number.
    fn next_pkt_num(&mut self) -> Option<u32> {
        self.pkt_num.checked_add(1).map(|pkt_num| {
            self.pkt_num = pkt_num;
            pkt_num
        })
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

    /// Handle ACKs.
    fn handle_acks(&mut self, _ack_through: u32, _num_acks: u8, _ranges: Vec<(u8, u8)>) {}

    /// Handle received `pkt` for this session.
    fn handle_packet(&mut self, pkt: Packet) -> Result<(), Ssu2Error> {
        let Packet { mut pkt, .. } = pkt;

        let iv2 = TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..]).expect("to succeed");
        ChaCha::with_iv(self.recv_key_ctx.k_header_2, iv2)
            .decrypt([0u8; 8])
            .into_iter()
            .zip(&mut pkt[8..])
            .for_each(|(a, b)| {
                *b ^= a;
            });

        // TODO: immediate ack

        let pkt_num = u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(&pkt[8..12]).unwrap());

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
                    self.remote_ack.register_non_ack_eliciting_pkt(pkt_num);

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
                    self.remote_ack.register_pkt(pkt_num);
                }
                Block::FirstFragment {
                    message_type,
                    message_id,
                    expiration,
                    fragment,
                } => {
                    self.remote_ack.register_pkt(pkt_num);

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
                    self.remote_ack.register_pkt(pkt_num);

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
                    self.remote_ack.register_non_ack_eliciting_pkt(pkt_num);
                    self.handle_acks(ack_through, num_acks, ranges);
                }
                Block::Address { .. } | Block::DateTime { .. } | Block::Padding { .. } => {
                    self.remote_ack.register_non_ack_eliciting_pkt(pkt_num);
                }
                block => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?block,
                        "ignoring block",
                    );
                    self.remote_ack.register_pkt(pkt_num);
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
        let msg = Message::parse_short(&message).unwrap();
        let message_id = msg.message_id;
        let (highest_seen, num_acks, ranges) = self.remote_ack.ack_info();

        if message.len() <= 1200 {
            let message = DataMessageBuilder::default()
                .with_dst_id(self.dst_id)
                .with_pkt_num(self.next_pkt_num().unwrap()) // TODO: no unwraps
                .with_key_context(self.intro_key, &self.send_key_ctx)
                .with_i2np(&message)
                .with_ack(highest_seen, num_acks, ranges)
                .build();

            if let Err(error) = self.pkt_tx.try_send(Packet {
                pkt: message.to_vec(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to send packet",
                );
            }
        } else {
            let mut fragments = msg.payload.chunks(1200).collect::<VecDeque<_>>();
            let num_fragments = fragments.len();
            let (highest_seen, num_acks, ranges) = self.remote_ack.ack_info();

            let first_fragment = DataMessageBuilder::default()
                .with_dst_id(self.dst_id)
                .with_pkt_num(self.next_pkt_num().unwrap()) // TODO: no unwraps
                .with_key_context(self.intro_key, &self.send_key_ctx)
                .with_first_fragment(
                    msg.message_type,
                    msg.message_id,
                    msg.expiration.as_secs() as u32,
                    fragments.pop_front().expect("to exist"),
                )
                .with_ack(highest_seen, num_acks, ranges.clone()) // TODO: overflow
                .build();

            if let Err(error) = self.pkt_tx.try_send(Packet {
                pkt: first_fragment.to_vec(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to send packet",
                );
            }

            fragments.into_iter().enumerate().for_each(|(i, fragment)| {
                let message = DataMessageBuilder::default()
                    .with_dst_id(self.dst_id)
                    .with_pkt_num(self.next_pkt_num().unwrap()) // TODO: no unwraps
                    .with_key_context(self.intro_key, &self.send_key_ctx)
                    .with_follow_on_fragment(
                        message_id,
                        i as u8 + 1u8,
                        i == num_fragments - 2,
                        fragment,
                    )
                    .with_ack(highest_seen, num_acks, ranges.clone()) // TODO: overflow
                    .build()
                    .to_vec();

                if let Err(error) = self.pkt_tx.try_send(Packet {
                    pkt: message,
                    address: self.address,
                }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to send packet",
                    );
                }
            });
        };
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
            next_pkt_num: self.next_pkt_num().unwrap(), // TODO: no unwraps
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

        // poll duplicate message filter and fragment handler
        //
        // the futures don't return anything but must be polled so they make progress
        let _ = self.duplicate_filter.poll_unpin(cx);
        let _ = self.fragment_handler.poll_unpin(cx);

        Poll::Pending
    }
}
