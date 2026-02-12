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
    crypto::{chachapoly::ChaChaPoly, SigningPublicKey},
    error::Ssu2Error,
    i2np::Message,
    primitives::{RouterId, RouterInfo},
    router::context::RouterContext,
    runtime::{Counter, MetricsHandle, Runtime, UdpSocket},
    subsystem::{OutboundMessage, OutboundMessageRecycle, SubsystemEvent},
    transport::{
        ssu2::{
            duplicate::DuplicateFilter,
            message::{Block, HeaderKind, HeaderReader},
            metrics::*,
            peer_test::types::PeerTestHandle,
            session::{
                active::{
                    ack::RemoteAckManager, fragment::FragmentHandler,
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

use bytes::BytesMut;
use futures::{FutureExt, StreamExt};
use thingbuf::mpsc::{with_recycle, Receiver, Sender};

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec};
use core::{
    cmp::min,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::AtomicU32,
    task::{Context, Poll},
    time::Duration,
};

mod ack;
mod fragment;
mod peer_test;
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

    /// Verifying key of remote router.
    pub verifying_key: SigningPublicKey,
}

/// Active SSU2 session.
pub struct Ssu2Session<R: Runtime> {
    /// ACK timer.
    ack_timer: AckTimer<R>,

    /// Socket address of the remote router.
    address: SocketAddr,

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

    /// RX channel for receiving messages from `SubsystemManager`.
    msg_rx: Receiver<OutboundMessage, OutboundMessageRecycle>,

    /// TX channel given to `SubsystemManager` which it uses
    /// to send messages to this connection.
    msg_tx: Sender<OutboundMessage, OutboundMessageRecycle>,

    /// Peer test handle.
    peer_test_handle: PeerTestHandle<R>,

    /// Pending router info for a peer test.
    ///
    /// Sent by Bob in a `RouterInfo` block bundled together with a `PeerTest` block.
    pending_router_info: Option<Box<RouterInfo>>,

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pkt_rx: Receiver<Packet>,

    /// Key context for inbound packets.
    recv_key_ctx: KeyContext,

    /// Resend timer.
    resend_timer: Option<R::Timer>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// ID of the remote router.
    router_id: RouterId,

    /// Key context for outbound packets.
    send_key_ctx: KeyContext,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Transmission manager.
    transmission: TransmissionManager<R>,

    /// TX channel for communicating with `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,

    /// Verifying key of remote router.
    verifying_key: SigningPublicKey,

    /// Write buffer
    write_buffer: VecDeque<BytesMut>,
}

impl<R: Runtime> Ssu2Session<R> {
    /// Create new [`Ssu2Session`].
    pub fn new(
        context: Ssu2SessionContext,
        socket: R::UdpSocket,
        transport_tx: Sender<SubsystemEvent>,
        router_ctx: RouterContext<R>,
        peer_test_handle: PeerTestHandle<R>,
    ) -> Self {
        let (msg_tx, msg_rx) = with_recycle(CMD_CHANNEL_SIZE, OutboundMessageRecycle::default());
        let metrics = router_ctx.metrics_handle().clone();
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
            dst_id: context.dst_id,
            duplicate_filter: DuplicateFilter::new(),
            fragment_handler: FragmentHandler::<R>::new(metrics.clone()),
            intro_key: context.intro_key,
            msg_rx,
            msg_tx,
            peer_test_handle,
            pending_router_info: None,
            pkt_rx: context.pkt_rx,
            recv_key_ctx: context.recv_key_ctx,
            resend_timer: None,
            router_ctx,
            router_id: context.router_id.clone(),
            send_key_ctx: context.send_key_ctx.clone(),
            socket,
            transmission: TransmissionManager::<R>::new(
                context.dst_id,
                context.router_id,
                context.intro_key,
                context.send_key_ctx,
                pkt_num,
                metrics,
            ),
            transport_tx,
            verifying_key: context.verifying_key,
            write_buffer: VecDeque::new(),
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
            self.router_ctx.metrics_handle().counter(EXPIRED_PKT_COUNT).increment(1);
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
            self.router_ctx.metrics_handle().counter(DUPLICATE_PKT_COUNT).increment(1);
            return;
        }

        if let Err(error) = self.transport_tx.try_send(SubsystemEvent::Message {
            messages: vec![(self.router_id.clone(), message.clone())],
        }) {
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
                ?payload,
                "failed to parse message block",
            );
            Ssu2Error::Malformed
        })? {
            match block {
                Block::Termination {
                    reason,
                    num_valid_pkts,
                } => {
                    self.transmission.register_remote_pkt(pkt_num);

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
                    self.transmission.register_remote_pkt(pkt_num);
                    self.ack_timer.schedule_ack(self.transmission.round_trip_time());
                }
                Block::FirstFragment {
                    message_type,
                    message_id,
                    expiration,
                    fragment,
                } => {
                    self.transmission.register_remote_pkt(pkt_num);
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
                    self.transmission.register_remote_pkt(pkt_num);
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
                    self.transmission.register_remote_pkt(pkt_num);
                    self.transmission.register_ack(ack_through, num_acks, &ranges);
                }
                Block::Address { .. } | Block::DateTime { .. } | Block::Padding { .. } => {
                    self.transmission.register_remote_pkt(pkt_num);
                }
                Block::PeerTest { message } => {
                    self.transmission.register_remote_pkt(pkt_num);
                    self.ack_timer.schedule_ack(self.transmission.round_trip_time());
                    self.handle_peer_test_message(message);
                }
                Block::RouterInfo { router_info, .. } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        received_router_id = %router_info.identity.id(),
                        "received an in-session router info",
                    );

                    self.pending_router_info = Some(router_info);
                }
                block => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?block,
                        "ignoring block",
                    );
                    self.transmission.register_remote_pkt(pkt_num);
                }
            }
        }

        // clear the pending router if it exists
        //
        // currently it's only used to handle peer test messages
        self.pending_router_info.take();

        Ok(())
    }

    /// Run the event loop of an active SSU2 session.
    pub async fn run(mut self) -> TerminationContext<R> {
        // subsystem manager doesn't exit
        self.transport_tx
            .send(SubsystemEvent::ConnectionEstablished {
                router_id: self.router_id.clone(),
                tx: self.msg_tx.clone(),
            })
            .await
            .expect("manager to stay alive");

        // run the event loop until it returns which happens only when
        // the peer has disconnected or an error was encoutered
        //
        // inform other subsystems of the disconnection
        let reason = (&mut self).await;

        // subsystem manager doesn't exit
        self.transport_tx
            .send(SubsystemEvent::ConnectionClosed {
                router_id: self.router_id.clone(),
            })
            .await
            .expect("manager to stay alive");

        TerminationContext {
            address: self.address,
            dst_id: self.dst_id,
            intro_key: self.intro_key,
            k_session_confirmed: None,
            next_pkt_num: self.transmission.next_pkt_num(),
            reason,
            recv_key_ctx: self.recv_key_ctx,
            router_id: self.router_id,
            rx: self.pkt_rx,
            send_key_ctx: self.send_key_ctx,
            socket: self.socket,
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
            match self.msg_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(TerminationReason::Timeout),
                Poll::Ready(Some(OutboundMessage::Message(message))) => {
                    self.transmission.schedule(message);
                }
                Poll::Ready(Some(OutboundMessage::MessageWithFeedback(message, feedback_tx))) => {
                    self.transmission.schedule(message);
                    let _ = feedback_tx.send(());
                }
                Poll::Ready(Some(OutboundMessage::Messages(messages))) =>
                    for message in messages {
                        self.transmission.schedule(message);
                    },
                Poll::Ready(Some(OutboundMessage::Dummy)) => {}
            }
        }

        // drain expired packets
        loop {
            let Some(ref mut timer) = self.resend_timer else {
                break;
            };

            let Poll::Ready(()) = timer.poll_unpin(cx) else {
                break;
            };

            match self.transmission.drain_expired() {
                Ok(None) => {}
                Err(_) => return Poll::Ready(TerminationReason::Timeout),
                Ok(Some(pkts)) => {
                    let address = self.address;

                    for pkt in pkts.into_iter() {
                        match Pin::new(&mut self.socket).poll_send_to(cx, &pkt, address) {
                            Poll::Pending => {}
                            Poll::Ready(None) =>
                                return Poll::Ready(TerminationReason::RouterShutdown),
                            Poll::Ready(Some(_)) => {}
                        }
                    }
                }
            }

            self.resend_timer = Some(R::timer(SSU2_RESEND_TIMEOUT));
        }

        // poll command from `PeerTestManager`
        //
        // handling a command (most often) results in outbound message which is why this
        // is done before draining transmission from pending packets
        loop {
            match self.peer_test_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(TerminationReason::RouterShutdown),
                Poll::Ready(Some(command)) => self.handle_peer_test_command(command),
            }
        }

        if self.ack_timer.poll_unpin(cx).is_ready() {
            let pkt = self.transmission.build_explicit_ack();

            // try to send the immediate ack right away and if it fails,
            // push it at the front of the queue
            let address = self.address;

            match Pin::new(&mut self.socket).poll_send_to(cx, &pkt, address) {
                Poll::Pending => {
                    self.write_buffer.push_front(pkt);
                }
                Poll::Ready(None) => return Poll::Ready(TerminationReason::RouterShutdown),
                Poll::Ready(Some(_)) => {}
            }
        }

        // send all outbound packets
        {
            let address = self.address;

            while let Some(pkt) = self.write_buffer.pop_front() {
                match Pin::new(&mut self.socket).poll_send_to(cx, &pkt, address) {
                    Poll::Pending => {
                        self.write_buffer.push_front(pkt);
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(TerminationReason::RouterShutdown),
                    Poll::Ready(Some(_)) => {}
                }
            }

            // only drain more packets from `TransmissionManager` if write buffer is empty,
            // otherwise the window size is skewed because there's an extra buffer
            if self.write_buffer.is_empty() {
                if let Some(pkts) = self.transmission.drain() {
                    for pkt in pkts {
                        match Pin::new(&mut self.socket).poll_send_to(cx, &pkt, address) {
                            Poll::Pending => {
                                // if the socket is pending, store the packet in a temporary buffer
                                // that'll be flushed before `TransmissioManager::drain()` is called
                                // the next time
                                self.write_buffer.push_back(pkt);
                            }
                            Poll::Ready(None) =>
                                return Poll::Ready(TerminationReason::RouterShutdown),
                            Poll::Ready(Some(_)) => {}
                        }
                    }

                    // create timer for resends and register it into the executor
                    self.resend_timer = {
                        let mut timer = R::timer(SSU2_RESEND_TIMEOUT);
                        let _ = timer.poll_unpin(cx);

                        Some(timer)
                    };
                }
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
        crypto::SigningPrivateKey,
        events::EventManager,
        i2np::{MessageType, I2NP_MESSAGE_EXPIRATION},
        primitives::{MessageId, RouterInfoBuilder},
        profile::ProfileStorage,
        runtime::mock::MockRuntime,
        transport::ssu2::{
            message::data::DataMessageBuilder, peer_test::types::PeerTestEventRecycle,
        },
    };
    use bytes::Bytes;
    use thingbuf::mpsc::channel;

    #[tokio::test(start_paused = true)]
    async fn backpressure_works() {
        let (from_socket_tx, from_socket_rx) = channel(128);
        let socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut recv_socket =
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let remote_signing_key = SigningPrivateKey::random(&mut rand::thread_rng());
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let router_ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new()),
            router_info.identity.id(),
            Bytes::from(router_info.serialize(&signing_key)),
            static_key.clone(),
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let ctx = Ssu2SessionContext {
            address: recv_socket.local_address().unwrap(),
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
            verifying_key: remote_signing_key.public(),
        };
        let (event_tx, _event_rx) = with_recycle(16, PeerTestEventRecycle::default());
        let handle = PeerTestHandle::new(event_tx);

        let cmd_tx = {
            let (transport_tx, transport_rx) = channel(16);

            tokio::spawn(
                Ssu2Session::<MockRuntime>::new(ctx, socket, transport_tx, router_ctx, handle)
                    .run(),
            );

            match transport_rx.recv().await.unwrap() {
                SubsystemEvent::ConnectionEstablished { tx, .. } => tx,
                _ => panic!("invalid event"),
            }
        };

        // send maximum amount of messages to the channel
        for _ in 0..CMD_CHANNEL_SIZE {
            cmd_tx
                .try_send(OutboundMessage::Message(Message {
                    message_type: MessageType::Data,
                    message_id: *MessageId::random(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: vec![1, 2, 3, 4],
                }))
                .unwrap();
        }

        // try to send one more packet and verify the call fails because window is full
        assert!(cmd_tx
            .try_send(OutboundMessage::Message(Message {
                message_type: MessageType::Data,
                message_id: *MessageId::random(),
                expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                payload: vec![1, 2, 3, 4],
            }))
            .is_err());

        // read and parse all packets
        let mut buffer = vec![0u8; 0xffff];

        for _ in 0..16 {
            let (nread, _from) = recv_socket.recv_from(&mut buffer).await.unwrap();
            let pkt = &mut buffer[..nread];

            match HeaderReader::new([1u8; 32], pkt).unwrap().parse([2u8; 32]).unwrap() {
                HeaderKind::Data { .. } => {}
                _ => panic!("invalid packet"),
            }
        }

        // verify that 16 more messags can be sent to the channel
        for _ in 0..16 {
            assert!(cmd_tx
                .try_send(OutboundMessage::Message(Message {
                    message_type: MessageType::Data,
                    message_id: *MessageId::random(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: vec![1, 2, 3, 4],
                }))
                .is_ok());
        }

        // verify that the excess messages are rejected
        assert!(cmd_tx
            .try_send(OutboundMessage::Message(Message {
                message_type: MessageType::Data,
                message_id: *MessageId::random(),
                expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                payload: vec![1, 2, 3, 4],
            }))
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
                    .send(OutboundMessage::Message(Message {
                        message_type: MessageType::Data,
                        message_id: *MessageId::random(),
                        expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        payload: vec![1, 2, 3, 4],
                    }))
                    .await
                    .unwrap();
            }
        };

        let _ = tokio::time::timeout(Duration::from_secs(5), future).await.expect("no timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn session_terminated_after_too_many_resends() {
        let (_from_socket_tx, from_socket_rx) = channel(128);
        let (transport_tx, transport_rx) = channel(16);
        let socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut recv_socket =
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let remote_signing_key = SigningPrivateKey::random(&mut rand::thread_rng());
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let router_ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new()),
            router_info.identity.id(),
            Bytes::from(router_info.serialize(&signing_key)),
            static_key.clone(),
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let ctx = Ssu2SessionContext {
            address: recv_socket.local_address().unwrap(),
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
            verifying_key: remote_signing_key.public(),
        };
        let (event_tx, _event_rx) = with_recycle(16, PeerTestEventRecycle::default());
        let handle = PeerTestHandle::new(event_tx);

        let (cmd_tx, handle) = {
            let handle = tokio::spawn(
                Ssu2Session::<MockRuntime>::new(ctx, socket, transport_tx, router_ctx, handle)
                    .run(),
            );

            match transport_rx.recv().await.unwrap() {
                SubsystemEvent::ConnectionEstablished { tx, .. } => (tx, handle),
                _ => panic!("invalid event"),
            }
        };

        // send maximum amount of messages to the channel
        for _ in 0..CMD_CHANNEL_SIZE {
            cmd_tx
                .try_send(OutboundMessage::Message(Message {
                    message_type: MessageType::Data,
                    message_id: *MessageId::random(),
                    expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                    payload: vec![1, 2, 3, 4],
                }))
                .unwrap();
        }

        // read and parse all packets
        let mut buffer = vec![0u8; 0xffff];

        for _ in 0..16 {
            let (nread, _from) = recv_socket.recv_from(&mut buffer).await.unwrap();
            let pkt = &mut buffer[..nread];

            match HeaderReader::new([1u8; 32], pkt).unwrap().parse([2u8; 32]).unwrap() {
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
