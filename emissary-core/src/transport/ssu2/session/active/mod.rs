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
    crypto::chachapoly::ChaChaPoly,
    error::Ssu2Error,
    i2np::Message,
    primitives::RouterId,
    runtime::{Counter, MetricsHandle, Runtime},
    subsystem::{SubsystemCommand, SubsystemHandle},
    transport::{
        ssu2::{
            message::{data::DataMessageBuilder, Block, HeaderKind, HeaderReader},
            metrics::*,
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

use futures::FutureExt;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    cmp::min,
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

// TODO: move code from `TransmissionManager` into here?

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::active";

/// Command channel size.
const CMD_CHANNEL_SIZE: usize = 512;

/// SSU2 resend timeout
const SSU2_RESEND_TIMEOUT: Duration = Duration::from_millis(40);

/// Maximum timeout for immediate ACK response.
const MAX_IMMEDIATE_ACK_TIMEOUT: Duration = Duration::from_millis(5);

/// Maximum timeout for ACK.
const MAX_ACK_TIMEOUT: Duration = Duration::from_millis(150);

/// Immediate ACK interval.
///
/// How often should an immediate ACK be bundled in a message.
const IMMEDIATE_ACK_INTERVAL: u32 = 10u32;

/// ACK timer.
///
/// Keeps track and allows scheduling both while respecting the priority of an immediate ACK.
struct AckTimer<R: Runtime> {
    /// Immediate ACK timer, if set.
    immediate: Option<R::Timer>,

    /// Normal ACK timer, if set.
    normal: Option<R::Timer>,
}

impl<R: Runtime> AckTimer<R> {
    fn new() -> Self {
        Self {
            immediate: None,
            normal: None,
        }
    }

    /// Schedule immediate ACK.
    ///
    /// It's only scheduled if there is no immediate ACK pending
    fn schedule_immediate_ack(&mut self, rtt: Duration) {
        if self.immediate.is_none() {
            self.immediate = Some(R::timer(min(rtt / 16, MAX_IMMEDIATE_ACK_TIMEOUT)));
        }
    }

    /// Schedule normal ACK.
    ///
    /// It's only scheduled if there is no previous ACK, neither immediate nor regular, pending.
    fn schedule_ack(&mut self, rtt: Duration) {
        if self.immediate.is_none() && self.normal.is_none() {
            self.normal = Some(R::timer(min(rtt / 6, MAX_ACK_TIMEOUT)));
        }
    }
}

impl<R: Runtime> Future for AckTimer<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(timer) = &mut self.immediate {
            if timer.poll_unpin(cx).is_ready() {
                self.immediate = None;
                self.normal = None;

                return Poll::Ready(());
            }
        }

        if let Some(timer) = &mut self.normal {
            if timer.poll_unpin(cx).is_ready() {
                self.immediate = None;
                self.normal = None;

                return Poll::Ready(());
            }
        }

        Poll::Pending
    }
}

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
    /// ACK timer.
    ack_timer: AckTimer<R>,

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

    /// Packet number of the packet that last requested an immediate ACK.
    last_immediate_ack: u32,

    /// Metrics handle.
    metrics: R::MetricsHandle,

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
    remote_ack: RemoteAckManager,

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
        metrics: R::MetricsHandle,
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
            ack_timer: AckTimer::<R>::new(),
            address: context.address,
            cmd_rx,
            cmd_tx,
            dst_id: context.dst_id,
            duplicate_filter: DuplicateFilter::new(),
            fragment_handler: FragmentHandler::<R>::new(metrics.clone()),
            intro_key: context.intro_key,
            last_immediate_ack: 0u32,
            metrics: metrics.clone(),
            pkt_num: Arc::clone(&pkt_num),
            pkt_rx: context.pkt_rx,
            pkt_tx,
            recv_key_ctx: context.recv_key_ctx,
            remote_ack: RemoteAckManager::new(),
            resend_timer: None,
            router_id: context.router_id.clone(),
            send_key_ctx: context.send_key_ctx,
            subsystem_handle,
            transmission: TransmissionManager::<R>::new(context.router_id, pkt_num, metrics),
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
            self.metrics.counter(EXPIRED_PKT_COUNT).increment(1);
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
            self.metrics.counter(DUPLICATE_PKT_COUNT).increment(1);
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

        if immediate_ack {
            self.ack_timer.schedule_immediate_ack(self.transmission.round_trip_time());
        }

        for block in Block::parse(&payload).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                ?error,
                "failed to parse message block",
            );
            Ssu2Error::Malformed
        })? {
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
                    self.ack_timer.schedule_ack(self.transmission.round_trip_time());
                }
                Block::FirstFragment {
                    message_type,
                    message_id,
                    expiration,
                    fragment,
                } => {
                    self.remote_ack.register_pkt(pkt_num);
                    self.ack_timer.schedule_ack(self.transmission.round_trip_time());

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
                    self.ack_timer.schedule_ack(self.transmission.round_trip_time());

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
                    self.remote_ack.register_ack(ack_through, num_acks, &ranges);
                    self.transmission.register_ack(ack_through, num_acks, &ranges);

                    if let Some(packets) = self.transmission.pending_packets() {
                        let AckInfo {
                            highest_seen,
                            num_acks,
                            ranges,
                        } = self.remote_ack.ack_info();
                        let num_pkts = packets.len();

                        for (i, (pkt_num, message_kind)) in packets.into_iter().enumerate() {
                            // include immediate ack in the last fragment
                            let message = if num_pkts > 1 && i == num_pkts - 1 {
                                self.last_immediate_ack = pkt_num;

                                DataMessageBuilder::default().with_immediate_ack()
                            } else {
                                DataMessageBuilder::default()
                            }
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
                                self.metrics.counter(NUM_DROPS_CHANNEL_FULL).increment(1);
                            }

                            if self.resend_timer.is_none() {
                                self.resend_timer = Some(R::timer(SSU2_RESEND_TIMEOUT));
                            }
                        }
                    }
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
        // TODO: this makes no sense, get unserialized message from subsystem
        let message = Message::parse_short(&message).unwrap();
        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack.ack_info();
        let pkt_len = message.payload.len();

        let Some(packets) = self.transmission.segment(message) else {
            return;
        };
        let num_pkts = packets.len();

        for (i, (pkt_num, message_kind)) in packets.into_iter().enumerate() {
            // include immediate ack flag if:
            //  1) this is the last in a burst of messages
            //  2) immediate ack has not been sent in the last `IMMEDIATE_ACK_INTERVAL` packets
            let last_in_burst = num_pkts > 1 && i == num_pkts - 1;
            let immediate_ack_threshold =
                pkt_num.saturating_sub(self.last_immediate_ack) > IMMEDIATE_ACK_INTERVAL;

            let message = if last_in_burst || immediate_ack_threshold {
                self.last_immediate_ack = pkt_num;

                DataMessageBuilder::default().with_immediate_ack()
            } else {
                DataMessageBuilder::default()
            }
            .with_dst_id(self.dst_id)
            .with_key_context(self.intro_key, &self.send_key_ctx)
            .with_message(pkt_num, message_kind)
            .with_ack(highest_seen, num_acks, ranges.clone()) // TODO: remove clone
            .build::<R>();

            tracing::trace!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                ?pkt_num,
                ?pkt_len,
                "send i2np message",
            );

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
                self.metrics.counter(NUM_DROPS_CHANNEL_FULL).increment(1);
            }

            if self.resend_timer.is_none() {
                self.resend_timer = Some(R::timer(SSU2_RESEND_TIMEOUT));
            }
        }
    }

    fn resend(&mut self) -> Result<usize, ()> {
        let Some(packets_to_resend) = self.transmission.resend()? else {
            return Ok(0);
        };
        self.metrics.counter(RETRANSMISSION_COUNT).increment(packets_to_resend.len());

        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack.ack_info();

        Ok(packets_to_resend
            .into_iter()
            .fold(0usize, |pkt_count, (pkt_num, message_kind)| {
                self.last_immediate_ack = pkt_num;

                let message = DataMessageBuilder::default()
                    .with_dst_id(self.dst_id)
                    .with_key_context(self.intro_key, &self.send_key_ctx)
                    .with_message(pkt_num, message_kind)
                    .with_immediate_ack()
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
                    self.metrics.counter(NUM_DROPS_CHANNEL_FULL).increment(1);
                }

                pkt_count + 1
            }))
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

        while self.transmission.has_capacity() {
            match self.cmd_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(TerminationReason::Timeout),
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
                    Poll::Ready(_) => match self.resend() {
                        Err(()) => return Poll::Ready(TerminationReason::Timeout),
                        Ok(num_resent) => {
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
                },
            }
        }

        if self.ack_timer.poll_unpin(cx).is_ready() {
            let AckInfo {
                highest_seen,
                num_acks,
                ranges,
            } = self.remote_ack.ack_info();

            tracing::trace!(
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
                self.metrics.counter(NUM_DROPS_CHANNEL_FULL).increment(1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::{MessageType, I2NP_MESSAGE_EXPIRATION},
        primitives::MessageId,
        runtime::mock::MockRuntime,
    };

    #[tokio::test]
    async fn backpressure_works() {
        let (from_socket_tx, from_socket_rx) = channel(128);
        let (to_socket_tx, to_socket_rx) = channel(128);

        let ctx = Ssu2SessionContext {
            address: "127.0.0.1:8888".parse().unwrap(),
            dst_id: 1337u64,
            intro_key: [1u8; 32],
            pkt_rx: from_socket_rx,
            recv_key_ctx: KeyContext {
                k_data: [2u8; 32],
                k_header_2: [3u8; 32],
            },
            router_id: RouterId::random(),
            send_key_ctx: KeyContext {
                k_data: [3u8; 32],
                k_header_2: [2u8; 32],
            },
        };

        let cmd_tx = {
            // register one subsystem, start active session andn poll command handle
            let (handle, cmd_rx) = {
                let (cmd_tx, cmd_rx) = channel(16);
                let mut handle = SubsystemHandle::new();
                handle.register_subsystem(cmd_tx);

                (handle, cmd_rx)
            };

            tokio::spawn(
                Ssu2Session::<MockRuntime>::new(
                    ctx,
                    to_socket_tx,
                    handle,
                    MockRuntime::register_metrics(vec![], None),
                )
                .run(),
            );

            match cmd_rx.recv().await.unwrap() {
                crate::subsystem::InnerSubsystemEvent::ConnectionEstablished { tx, .. } => tx,
                _ => panic!("invalid event"),
            }
        };

        // send maximum amount of messages to the channel
        for _ in 0..CMD_CHANNEL_SIZE {
            cmd_tx
                .try_send(SubsystemCommand::SendMessage {
                    message: Message {
                        message_type: MessageType::Data,
                        message_id: *MessageId::random(),
                        expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        payload: vec![1, 2, 3, 4],
                    }
                    .serialize_short(),
                })
                .unwrap();
        }

        // try to send one more packet and verify the call fails because window is full
        assert!(cmd_tx
            .try_send(SubsystemCommand::SendMessage {
                message: Message {
                    message_type: MessageType::Data,
                    message_id: *MessageId::random(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: vec![1, 2, 3, 4],
                }
                .serialize_short(),
            })
            .is_err());

        // read and parse all packets
        for _ in 0..16 {
            let Packet { mut pkt, .. } = to_socket_rx.recv().await.unwrap();

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([2u8; 32]).unwrap() {
                HeaderKind::Data { .. } => {}
                _ => panic!("invalid packet"),
            }
        }

        // verify that 16 more messags can be sent to the channel
        for _ in 0..16 {
            assert!(cmd_tx
                .try_send(SubsystemCommand::SendMessage {
                    message: Message {
                        message_type: MessageType::Data,
                        message_id: *MessageId::random(),
                        expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        payload: vec![1, 2, 3, 4],
                    }
                    .serialize_short(),
                })
                .is_ok());
        }

        // verify that the excess messages are rejected
        assert!(cmd_tx
            .try_send(SubsystemCommand::SendMessage {
                message: Message {
                    message_type: MessageType::Data,
                    message_id: *MessageId::random(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: vec![1, 2, 3, 4],
                }
                .serialize_short(),
            })
            .is_err());

        // send ack
        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(1337u64)
            .with_pkt_num(1)
            .with_key_context(
                [1u8; 32],
                &KeyContext {
                    k_data: [2u8; 32],
                    k_header_2: [3u8; 32],
                },
            )
            .with_ack(16, 5, None)
            .build::<MockRuntime>()
            .to_vec();

        let mut reader = HeaderReader::new([1u8; 32], &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        from_socket_tx
            .try_send(Packet {
                pkt,
                address: "127.0.0.1:8888".parse().unwrap(),
            })
            .unwrap();

        let future = async move {
            for _ in 0..6 {
                cmd_tx
                    .send(SubsystemCommand::SendMessage {
                        message: Message {
                            message_type: MessageType::Data,
                            message_id: *MessageId::random(),
                            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                            payload: vec![1, 2, 3, 4],
                        }
                        .serialize_short(),
                    })
                    .await
                    .unwrap();
            }
        };

        let _ = tokio::time::timeout(Duration::from_secs(5), future).await.expect("no timeout");
    }

    #[tokio::test]
    async fn session_terminated_after_too_many_resends() {
        let (_from_socket_tx, from_socket_rx) = channel(128);
        let (to_socket_tx, to_socket_rx) = channel(128);

        let ctx = Ssu2SessionContext {
            address: "127.0.0.1:8888".parse().unwrap(),
            dst_id: 1337u64,
            intro_key: [1u8; 32],
            pkt_rx: from_socket_rx,
            recv_key_ctx: KeyContext {
                k_data: [2u8; 32],
                k_header_2: [3u8; 32],
            },
            router_id: RouterId::random(),
            send_key_ctx: KeyContext {
                k_data: [3u8; 32],
                k_header_2: [2u8; 32],
            },
        };

        let (cmd_tx, handle) = {
            // register one subsystem, start active session andn poll command handle
            let (handle, cmd_rx) = {
                let (cmd_tx, cmd_rx) = channel(16);
                let mut handle = SubsystemHandle::new();
                handle.register_subsystem(cmd_tx);

                (handle, cmd_rx)
            };

            let handle = tokio::spawn(
                Ssu2Session::<MockRuntime>::new(
                    ctx,
                    to_socket_tx,
                    handle,
                    MockRuntime::register_metrics(vec![], None),
                )
                .run(),
            );

            match cmd_rx.recv().await.unwrap() {
                crate::subsystem::InnerSubsystemEvent::ConnectionEstablished { tx, .. } =>
                    (tx, handle),
                _ => panic!("invalid event"),
            }
        };

        // send maximum amount of messages to the channel
        for _ in 0..CMD_CHANNEL_SIZE {
            cmd_tx
                .try_send(SubsystemCommand::SendMessage {
                    message: Message {
                        message_type: MessageType::Data,
                        message_id: *MessageId::random(),
                        expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        payload: vec![1, 2, 3, 4],
                    }
                    .serialize_short(),
                })
                .unwrap();
        }

        // read and parse all packets
        for _ in 0..16 {
            let Packet { mut pkt, .. } = to_socket_rx.recv().await.unwrap();

            match HeaderReader::new([1u8; 32], &mut pkt).unwrap().parse([2u8; 32]).unwrap() {
                HeaderKind::Data { .. } => {}
                _ => panic!("invalid packet"),
            }
        }

        match tokio::time::timeout(Duration::from_secs(15), handle).await {
            Ok(Ok(context)) => assert!(std::matches!(context.reason, TerminationReason::Timeout)),
            Ok(Err(_)) => panic!("session panicked"),
            Err(_) => panic!("timeout"),
        }
    }
}
