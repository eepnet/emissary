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
    crypto::SigningPrivateKey,
    destination::{routing_path::RoutingPathHandle, DeliveryStyle},
    error::StreamingError,
    primitives::{Destination, DestinationId},
    runtime::{AsyncRead, AsyncWrite, Instant, Runtime},
    sam::protocol::streaming::{
        config::StreamConfig,
        packet::{Packet, PacketBuilder},
    },
};

use futures::FutureExt;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec,
    vec::Vec,
};
use core::{
    cmp,
    future::Future,
    marker::PhantomData,
    mem,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::streaming::active";

/// Read buffer size.
const READ_BUFFER_SIZE: usize = 0xffff;

/// Initial ACK delay.
const INITIAL_ACK_DELAY: Duration = Duration::from_millis(200);

/// Sequence number for a plain ACK message.
const PLAIN_ACK: u32 = 0u32;

/// Initial window size.
const INITIAL_WINDOW_SIZE: usize = 1usize;

/// Maximum window size in packets.
const MAX_WINDOW_SIZE: usize = 128usize;

/// How far ahead of the current highest received sequence number is a packet accepted.
const MAX_WINDOW_LOOKAHEAD: usize = 4 * MAX_WINDOW_SIZE;

/// Delay request which indicates choking.
const CHOKING_REQUEST: u16 = 60_001u16;

/// Maximum number of NACKs sent.
const MAX_NACKS: usize = 255usize;

/// Initial RTO.
const INITIAL_RTO: Duration = Duration::from_millis(9000);

/// Initial RTT.
const INITIAL_RTT: Duration = Duration::from_millis(8000);

/// RTT dampening factor (alpha).
const RTT_DAMPENING_FACTOR: f64 = 0.125f64;

/// RTTDEV dampening factor (beta).
const RTTDEV_DAMPENING_FACTOR: f64 = 0.25;

/// Threshold for stopping exponential growth of the window size.
const EXP_GROWTH_STOP_THRESHOLD: usize = 64;

/// MTU size.
const MTU_SIZE: usize = 1812;

/// Stream event.
#[derive(Default, Debug, Clone)]
pub enum StreamEvent {
    /// Streaming packet received from remote.
    Packet {
        /// Serialized packet.
        packet: Vec<u8>,
    },

    /// [`StreamManager`] has asked the stream to be shut down.
    #[default]
    ShutDown,
}

/// Measured RTT.
#[derive(Debug, Copy, Clone)]
enum Rtt {
    /// Stream has just started so there are no RTT values.
    Unsampled(Duration),

    /// RTT values have been measured.
    Sampled(Duration),
}

impl Rtt {
    /// Create new [`Rtt`].
    fn new() -> Self {
        Self::Unsampled(INITIAL_RTT)
    }

    /// Calculate new [`Rtt`] from `sample` and previous RTT.
    fn calculate_rtt(&mut self, sample: Duration) {
        match self {
            Self::Unsampled(_) => *self = Self::Sampled(sample),
            Self::Sampled(rtt) => {
                // calculate smoothed rtt
                let rtt = (1f64 - RTT_DAMPENING_FACTOR) * rtt.as_millis() as f64
                    + RTT_DAMPENING_FACTOR * sample.as_millis() as f64;

                *self = Self::Sampled(Duration::from_millis(rtt as u64));
            }
        }
    }
}

impl Deref for Rtt {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Unsampled(rtt) => rtt,
            Self::Sampled(rtt) => rtt,
        }
    }
}

/// Measured RTO.
#[derive(Debug, Copy, Clone)]
enum Rto {
    /// Stream has just started so there are no RTO values.
    Unsampled(Duration),

    /// RTO values have been measured.
    Sampled((Duration, Duration, usize)),
}

impl Rto {
    /// Create new [`Rto`].
    fn new() -> Self {
        Self::Unsampled(INITIAL_RTO)
    }

    fn calculate_rto(&mut self, rtt: &Rtt, sample: Duration) {
        match self {
            Self::Unsampled(_) => *self = Self::Sampled(((**rtt) * 2, (**rtt) / 2, 1)),
            Self::Sampled((_, rtt_var, _)) => {
                // calculate smoothed rto
                // let rtt_var = (1−β)×RTTVAR+β×∣SRTT−RTT∣
                let srtt = (**rtt).as_millis() as i64;
                let abs = {
                    let sample = sample.as_millis() as i64;
                    RTTDEV_DAMPENING_FACTOR * i64::abs(srtt - sample) as f64
                };
                let rtt_var = rtt_var.as_millis() as f64;
                let rtt_var = (1f64 - RTTDEV_DAMPENING_FACTOR) * rtt_var + abs;
                let rto = srtt as f64 + 4f64 * rtt_var;

                *self = Self::Sampled((
                    Duration::from_millis(rto as u64),
                    Duration::from_millis(rtt_var as u64),
                    2usize,
                ))
            }
        }
    }

    /// Get exponential back-off if packet loss has occurred.
    fn exponential_backoff(&mut self) -> Duration {
        match self {
            Self::Unsampled(rto) => *rto,
            Self::Sampled((rto, rtt_var, backoff)) => {
                let timeout = *rto * (*backoff as u32);

                *self = Self::Sampled((*rto, *rtt_var, *backoff + 1));
                timeout
            }
        }
    }
}

impl Deref for Rto {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Unsampled(rto) => rto,
            Self::Sampled((rto, _, _)) => rto,
        }
    }
}

/// Stream kind.
pub enum StreamKind {
    /// Stream is uninitialized and there has been no activity on it before.
    Inbound {
        /// Payload of the `SYN` packet, may be empty.
        payload: Vec<u8>,
    },

    /// Stream was pending before a listener was ready to accept it and there may have been data
    /// exchange in stream before the listener was ready. [`Stream`] must initialize its state
    /// using with the provided data.
    InboundPending {
        /// Selected send stream ID.
        send_stream_id: u32,

        /// Remote peer's current sequence number.
        seq_nro: u32,

        /// Received packets, if any.
        packets: VecDeque<Vec<u8>>,
    },

    /// Outbound stream.
    Outbound {
        /// Destination port.
        dst_port: u16,

        /// Payload received in `SYN`.
        payload: Vec<u8>,

        /// Selected send stream ID.
        send_stream_id: u32,

        /// Source port.
        src_port: u16,
    },
}

/// Context needed to initialize [`Stream`].
pub struct StreamContext {
    /// Local destination.
    pub destination: Destination,

    /// RX channel for receiving [`Packet`]s from the network.
    pub cmd_rx: Receiver<StreamEvent>,

    /// TX channel for sending [`Packet`]s to the network.
    pub event_tx: Sender<(DeliveryStyle, Vec<u8>, u16, u16)>,

    /// ID of the local destination.
    pub local: DestinationId,

    /// Stream ID selected by the stream originator.
    pub recv_stream_id: u32,

    /// ID of the remote destination.
    pub remote: DestinationId,

    /// Signing key.
    pub signing_key: SigningPrivateKey,
}

/// Pending outbound packet.
pub struct PendingPacket<R: Runtime> {
    /// When was the packet sent.
    sent: R::Instant,

    /// Sequence number of the packet.
    seq_nro: u32,

    /// Serialized packet.
    packet: Vec<u8>,
}

/// Write state.
enum WriteState {
    /// Get next message from channel.
    GetMessage,

    /// Send message into the socket.
    WriteMessage {
        /// Offset into `message`.
        offset: usize,

        /// Message.
        message: Vec<u8>,
    },

    /// Socket has been closed.
    Closed,

    /// [`WriteState`] has been poisoned.
    Poisoned,
}

/// Read state.
enum SocketState {
    /// Read message from client.
    ReadMessage,

    /// Sending message
    SendMessage {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Socket has been closed.
    Closed,
}

/// Inbound context.
pub struct InboundContext<R: Runtime> {
    /// ACK timer.
    ack_timer: Option<R::Timer>,

    /// Missing packets.
    missing: BTreeSet<u32>,

    /// Pending packets.
    pending: BTreeMap<u32, Vec<u8>>,

    /// Ready packets.
    ready: VecDeque<Vec<u8>>,

    /// Measured RTT.
    rtt: Duration,

    /// Highest received sequence number from remote destination.
    seq_nro: u32,

    /// Close requested, either by client or remote peer.
    close_requested: bool,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> InboundContext<R> {
    /// Create new [`InboundContext`] with highest received `seq_nro`.
    fn new(seq_nro: u32) -> Self {
        Self {
            ack_timer: None,
            missing: BTreeSet::new(),
            pending: BTreeMap::new(),
            ready: VecDeque::new(),
            rtt: INITIAL_ACK_DELAY,
            close_requested: false,
            seq_nro,
            _runtime: Default::default(),
        }
    }

    // TODO: so ugly
    fn handle_packet(&mut self, seq_nro: u32, payload: Vec<u8>) -> Result<(), StreamingError> {
        // packet received in order
        if seq_nro == self.seq_nro + 1 {
            self.missing.remove(&seq_nro);
            if self.missing.is_empty() {
                self.ready.push_back(payload);
            } else {
                self.pending.insert(seq_nro, payload);
            }
            self.seq_nro = seq_nro;

            if self.ack_timer.is_none() {
                self.ack_timer = Some(R::timer(self.rtt));
            }

            return Ok(());
        }

        if seq_nro > self.seq_nro + 1 {
            if (seq_nro - self.seq_nro - 1) as usize > MAX_WINDOW_LOOKAHEAD {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?seq_nro,
                    next_seq_nro = ?(self.seq_nro + 1),
                    "packet is too far in the future",
                );

                return Err(StreamingError::SequenceNumberTooHigh);
            }

            tracing::trace!(
                target: LOG_TARGET,
                ?seq_nro,
                expected = ?self.seq_nro + 1,
                "received out-of-order packet",
            );

            (self.seq_nro + 1..seq_nro).for_each(|seq_nro| {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?seq_nro,
                    "marking packet as missing",
                );

                if !self.pending.contains_key(&seq_nro) {
                    self.missing.insert(seq_nro);
                }
            });

            self.pending.insert(seq_nro, payload);
            self.missing.remove(&seq_nro);
            self.seq_nro = seq_nro;

            if self.ack_timer.is_none() {
                self.ack_timer = Some(R::timer(self.rtt));
            }
        } else if self.missing.first() == Some(&seq_nro) {
            self.ready.push_back(payload);
            self.missing.remove(&seq_nro);

            let mut next_seq = seq_nro + 1;

            while let Some(payload) = self.pending.remove(&next_seq) {
                self.ready.push_back(payload);
                next_seq += 1;
            }

            if self.ack_timer.is_none() {
                self.ack_timer = Some(R::timer(self.rtt));
            }
        } else {
            self.missing.remove(&seq_nro);
            self.pending.insert(seq_nro, payload);

            if self.ack_timer.is_none() {
                self.ack_timer = Some(R::timer(self.rtt));
            }
        }

        Ok(())
    }

    fn pop_message(&mut self) -> Option<Vec<u8>> {
        self.ready.pop_front()
    }

    fn close(&mut self) {
        self.close_requested = true;

        if self.ack_timer.is_none() {
            self.ack_timer = Some(R::timer(self.rtt));
        }
    }

    fn can_close(&self) -> bool {
        self.close_requested && self.missing.is_empty()
    }
}

impl<R: Runtime> Future for InboundContext<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(timer) = &mut self.ack_timer {
            if timer.poll_unpin(cx).is_ready() {
                self.ack_timer = None;
                return Poll::Ready(());
            }
        }

        Poll::Pending
    }
}

/// I2P virtual stream.
///
/// Implements a `Future` which returns the send stream ID after the virtual stream has been shut
/// down, either by the client or by the remote participant.
pub struct Stream<R: Runtime> {
    /// Close requested.
    close_requested: bool,

    /// RX channel for receiving [`StreamEvent`]s from the network.
    cmd_rx: Receiver<StreamEvent>,

    /// Local destination.
    destination: Destination,

    /// Destination port.
    dst_port: u16,

    /// TX channel for sending [`Packet`]s to the network.
    event_tx: Sender<(DeliveryStyle, Vec<u8>, u16, u16)>,

    /// Inbound context for packets received from the network.
    inbound_context: InboundContext<R>,

    /// ID of the local destination.
    local: DestinationId,

    /// Next sequence number.
    next_seq_nro: u32,

    /// Pending (unsent) outbound packets.
    pending: BTreeMap<u32, PendingPacket<R>>,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Socket state.
    read_state: SocketState,

    /// Receive stream ID (selected by remote peer).
    recv_stream_id: u32,

    /// ID of the remote destination.
    remote: DestinationId,

    /// Routing path handle.
    #[allow(unused)]
    routing_path_handle: RoutingPathHandle<R>,

    /// RTO.
    rto: Rto,

    /// RTO timer.
    rto_timer: Option<R::Timer>,

    /// RTT.
    rtt: Rtt,

    /// Send stream ID (selected by us).
    send_stream_id: u32,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Source port.
    src_port: u16,

    /// Underlying TCP stream used to communicate with the client.
    stream: R::TcpStream,

    /// Pending (unACKed) outbound packets.
    unacked: BTreeMap<u32, PendingPacket<R>>,

    /// Window size.
    window_size: usize,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Stream<R> {
    /// Create new [`Stream`]
    pub fn new(
        stream: R::TcpStream,
        initial_message: Option<Vec<u8>>,
        context: StreamContext,
        _: StreamConfig,
        state: StreamKind,
        mut routing_path_handle: RoutingPathHandle<R>,
    ) -> Self {
        let StreamContext {
            local,
            remote,
            cmd_rx,
            event_tx,
            recv_stream_id,
            signing_key,
            destination,
        } = context;

        let (send_stream_id, initial_message, highest_ack, src_port, dst_port) = match state {
            StreamKind::Inbound { payload } => {
                let send_stream_id = R::rng().next_u32();
                let packet = PacketBuilder::new(send_stream_id)
                    .with_send_stream_id(recv_stream_id)
                    .with_from_included(destination.clone())
                    .with_seq_nro(0)
                    .with_synchronize()
                    .with_signature()
                    .build_and_sign(&signing_key);

                // TODO: correct?
                event_tx
                    .try_send((
                        match routing_path_handle.routing_path() {
                            None => DeliveryStyle::Unspecified {
                                destination_id: remote.clone(),
                            },
                            Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
                        },
                        packet.to_vec(),
                        0u16,
                        0u16,
                    ))
                    .unwrap();

                (
                    send_stream_id,
                    match (initial_message, payload.is_empty()) {
                        (Some(mut initial), false) => {
                            initial.extend_from_slice(&payload);
                            Some(initial)
                        }
                        (Some(initial), true) => Some(initial),
                        (None, false) => Some(payload),
                        (None, true) => None,
                    },
                    0u32,
                    0u16, // TODO: correct?
                    0u16, // TODO: correct?
                )
            }
            StreamKind::InboundPending {
                send_stream_id,
                seq_nro,
                packets,
            } => {
                let combined = packets.into_iter().fold(Vec::new(), |mut message, packet| {
                    message.extend_from_slice(&packet);
                    message
                });

                tracing::trace!(
                    target: LOG_TARGET,
                    %local,
                    %remote,
                    ?send_stream_id,
                    ?recv_stream_id,
                    pending_payload_len = ?combined.len(),
                    "initialize state from pending connection",
                );

                (
                    send_stream_id,
                    match (initial_message, combined.is_empty()) {
                        (None, true) => None,
                        (None, false) => Some(combined),
                        (Some(message), true) => Some(message),
                        (Some(mut message), false) => {
                            message.extend_from_slice(&combined);
                            Some(message)
                        }
                    },
                    seq_nro,
                    0u16, // TODO: correct?
                    0u16, // TODO: correct?
                )
            }
            StreamKind::Outbound {
                dst_port,
                payload,
                send_stream_id,
                src_port,
            } => (
                send_stream_id,
                match (initial_message, payload.is_empty()) {
                    (Some(mut initial), false) => {
                        initial.extend_from_slice(&payload);
                        Some(initial)
                    }
                    (Some(initial), true) => Some(initial),
                    (None, false) => Some(payload),
                    (None, true) => None,
                },
                0u32,
                src_port,
                dst_port,
            ),
        };

        Self {
            close_requested: false,
            cmd_rx,
            destination,
            dst_port,
            event_tx,
            inbound_context: InboundContext::new(highest_ack),
            local,
            next_seq_nro: 1u32,
            pending: BTreeMap::new(),
            read_buffer: vec![0u8; READ_BUFFER_SIZE],
            read_state: SocketState::ReadMessage,
            recv_stream_id,
            remote,
            routing_path_handle,
            rto: Rto::new(),
            rto_timer: None,
            rtt: Rtt::new(),
            send_stream_id,
            signing_key,
            src_port,
            stream,
            unacked: BTreeMap::new(),
            window_size: INITIAL_WINDOW_SIZE,
            write_state: match initial_message {
                None => WriteState::GetMessage,
                Some(message) => WriteState::WriteMessage {
                    offset: 0usize,
                    message,
                },
            },
        }
    }

    /// Handle acknowledgements.
    fn handle_acks(&mut self, ack_through: u32, nacks: &[u32]) {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            recv_id = ?self.recv_stream_id,
            send_id = ?self.send_stream_id,
            ?ack_through,
            ?nacks,
            unacked = ?self.unacked.len(),
            pending = ?self.pending.len(),
            seq = ?(self.next_seq_nro - 1),
            rtt = ?*self.rtt,
            rto = ?*self.rto,
            wnd = ?self.window_size,
            "handle acks",
        );

        if ack_through > self.next_seq_nro {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                ?ack_through,
                next_seq_nro = ?self.next_seq_nro,
                "unexpected ack",
            );
            return;
        }

        let acked = self
            .unacked
            .iter()
            .filter_map(|(seq_nro, _)| {
                (seq_nro <= &ack_through && !nacks.iter().any(|nack| nack == seq_nro))
                    .then_some(*seq_nro)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|seq_nro| (seq_nro, self.unacked.remove(&seq_nro).expect("to exist")))
            .collect::<Vec<_>>();

        for (_, packet) in acked {
            self.rtt.calculate_rtt(packet.sent.elapsed());
            self.rto.calculate_rto(&self.rtt, packet.sent.elapsed());

            if self.window_size < EXP_GROWTH_STOP_THRESHOLD {
                self.window_size *= 2;
            } else if self.window_size < MAX_WINDOW_SIZE {
                self.window_size += 1;
            }
        }
    }

    /// Handle `packet` received from the network.
    fn on_packet(&mut self, packet: Vec<u8>) -> Result<(), StreamingError> {
        let Packet {
            seq_nro,
            ack_through,
            nacks,
            flags,
            payload,
            ..
        } = Packet::parse(&packet).ok_or(StreamingError::Malformed)?;

        if flags.synchronize() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                "received `SYN` to an active session",
            );

            let packet = PacketBuilder::new(self.send_stream_id)
                .with_send_stream_id(self.recv_stream_id)
                .with_seq_nro(0)
                .with_synchronize()
                .with_from_included(self.destination.clone())
                .with_signature()
                .build_and_sign(&self.signing_key);

            self.event_tx
                .try_send((
                    match self.routing_path_handle.routing_path() {
                        None => DeliveryStyle::Unspecified {
                            destination_id: self.remote.clone(),
                        },
                        Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
                    },
                    packet.to_vec(),
                    self.src_port,
                    self.dst_port,
                ))
                .unwrap();
        }

        if flags.reset() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                "stream reset",
            );

            return Err(StreamingError::Closed);
        }

        if flags.close() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                payload_len = ?payload.len(),
                "remote sent `CLOSE`",
            );

            // stop reading any  more data from the client socket
            self.read_state = SocketState::Closed;
            self.inbound_context.close();
        }

        if !flags.no_ack() {
            self.handle_acks(ack_through, &nacks);
        }

        if !payload.is_empty() {
            self.inbound_context.handle_packet(seq_nro, payload.to_vec())?;
        }

        if self.close_requested && self.unacked.is_empty() && self.pending.is_empty() {
            tracing::trace!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                "shutting down stream",
            );
            return Err(StreamingError::Closed);
        }

        Ok(())
    }

    fn packetize(&mut self, offset: usize) {
        let sent = R::now();

        let packets = self.read_buffer[..offset]
            .chunks(MTU_SIZE)
            .map(|chunk| {
                let seq_nro = {
                    let seq_nro = self.next_seq_nro;
                    self.next_seq_nro += 1;
                    seq_nro
                };
                let ack_through = self.inbound_context.seq_nro;
                let nacks = self
                    .inbound_context
                    .missing
                    .iter()
                    .copied()
                    .take(MAX_NACKS)
                    .collect::<Vec<_>>();

                let builder = PacketBuilder::new(self.send_stream_id)
                    .with_send_stream_id(self.recv_stream_id)
                    .with_ack_through(ack_through)
                    .with_nacks(nacks)
                    .with_seq_nro(seq_nro)
                    .with_payload(chunk);

                let packet = if self.inbound_context.missing.len() >= MAX_NACKS {
                    builder.with_delay_requested(CHOKING_REQUEST)
                } else {
                    builder
                }
                .build()
                .to_vec();

                (
                    seq_nro,
                    PendingPacket::<R> {
                        sent,
                        seq_nro,
                        packet,
                    },
                )
            })
            .collect::<Vec<_>>();

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            recv_id = ?self.recv_stream_id,
            send_id = ?self.send_stream_id,
            num_packets = ?packets.len(),
            windows_size = %self.window_size,
            "send packets",
        );

        packets.into_iter().for_each(|(seq_nro, packet)| {
            if self.unacked.len() >= self.window_size {
                self.pending.insert(seq_nro, packet);
            } else {
                match self.event_tx.try_send((
                    match self.routing_path_handle.routing_path() {
                        None => DeliveryStyle::Unspecified {
                            destination_id: self.remote.clone(),
                        },
                        Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
                    },
                    packet.packet.clone(),
                    self.src_port,
                    self.dst_port,
                )) {
                    Err(_) => {
                        self.pending.insert(seq_nro, packet);
                    }
                    Ok(()) => {
                        self.unacked.insert(seq_nro, packet);
                    }
                }
            }
        });

        if self.rto_timer.is_none() {
            self.rto_timer = Some(R::timer(*self.rto));
        }
    }

    /// Resend any unACKed packets.
    fn resend(&mut self) {
        if self.unacked.is_empty() {
            self.rto_timer = None;
            return;
        }

        let expired = self
            .unacked
            .values_mut()
            .take_while(|packet| packet.sent.elapsed() > *self.rto)
            .take(self.window_size)
            .collect::<Vec<_>>();

        // no expired packetes
        if expired.is_empty() {
            self.rto_timer = Some(R::timer(*self.rto));
            return;
        }

        // reset routing path as there has been packet loss
        let routing_path = match self.routing_path_handle.recreate_routing_path() {
            Some(routing_path) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    recv_id = ?self.recv_stream_id,
                    send_id = ?self.send_stream_id,
                    inbound = ?routing_path.inbound,
                    outbound = ?routing_path.outbound,
                    "routing path recreated"
                );
                self.rto = Rto::new();
                self.rtt = Rtt::new();

                routing_path
            }
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    recv_id = ?self.recv_stream_id,
                    send_id = ?self.send_stream_id,
                    "no routing path, cannot resend packets",
                );
                self.rto_timer = Some(R::timer(*self.rto));
                return;
            }
        };

        for packet in expired {
            packet.sent = R::now();

            tracing::trace!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                seq_nro = ?packet.seq_nro,
                "resend packet"
            );

            if let Err(error) = self.event_tx.try_send((
                DeliveryStyle::ViaRoute {
                    routing_path: routing_path.clone(),
                },
                packet.packet.clone(),
                self.src_port,
                self.dst_port,
            )) {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.local,
                    remote = %self.remote,
                    recv_id = ?self.recv_stream_id,
                    send_id = ?self.send_stream_id,
                    ?error,
                    "failed to send packet",
                );
            }
        }

        self.rto_timer = Some(R::timer(self.rto.exponential_backoff()));

        if self.window_size > 1 {
            self.window_size -= 1;
        }
    }

    /// Client has closed down the socket.
    fn shutdown(&mut self) {
        if self.close_requested {
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            local = %self.local,
            remote = %self.remote,
            recv_id = ?self.recv_stream_id,
            send_id = ?self.send_stream_id,
            num_pending = ?self.pending.len(),
            num_unacked = ?self.unacked.len(),
            "shutdown stream",
        );

        self.close_requested = true;

        let seq_nro = {
            let seq_nro = self.next_seq_nro;
            self.next_seq_nro += 1;
            seq_nro
        };

        let packet = PacketBuilder::new(self.send_stream_id)
            .with_send_stream_id(self.recv_stream_id)
            .with_ack_through(self.inbound_context.seq_nro)
            .with_seq_nro(seq_nro)
            .with_close()
            .with_from_included(self.destination.clone())
            .with_signature()
            .build_and_sign(&self.signing_key)
            .to_vec();

        if self.window_size.saturating_sub(self.unacked.len()) == 0 {
            tracing::info!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                wnd = ?self.window_size,
                "postponing `CLOSE`, send window is full",
            );

            self.pending.insert(
                seq_nro,
                PendingPacket::<R> {
                    sent: R::now(),
                    seq_nro,
                    packet,
                },
            );
        } else {
            match self.event_tx.try_send((
                match self.routing_path_handle.routing_path() {
                    None => DeliveryStyle::Unspecified {
                        destination_id: self.remote.clone(),
                    },
                    Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
                },
                packet.clone(),
                self.src_port,
                self.dst_port,
            )) {
                Err(_) => {
                    self.pending.insert(
                        seq_nro,
                        PendingPacket::<R> {
                            sent: R::now(),
                            seq_nro,
                            packet,
                        },
                    );
                }
                Ok(()) => {
                    self.unacked.insert(
                        seq_nro,
                        PendingPacket::<R> {
                            sent: R::now(),
                            seq_nro,
                            packet,
                        },
                    );
                }
            }

            if self.rto_timer.is_none() {
                self.rto_timer = Some(R::timer(*self.rto));
            }
        }
    }
}

impl<R: Runtime> Future for Stream<R> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::into_inner(self);

        // poll routing path handle to get tunnel updates
        if this.routing_path_handle.poll_unpin(cx).is_ready() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %this.local,
                remote = %this.remote,
                recv_id = ?this.recv_stream_id,
                send_id = ?this.send_stream_id,
                "routing path handle exited",
            );
            return Poll::Ready(this.recv_stream_id);
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.cmd_rx.poll_recv(cx) {
                    Poll::Pending => match this.inbound_context.pop_message() {
                        None => {
                            this.write_state = WriteState::GetMessage;
                            break;
                        }
                        Some(message) =>
                            this.write_state = WriteState::WriteMessage {
                                offset: 0usize,
                                message,
                            },
                    },
                    Poll::Ready(None) => return Poll::Ready(this.recv_stream_id),
                    Poll::Ready(Some(StreamEvent::ShutDown)) => {
                        this.write_state = WriteState::Closed;
                        this.read_state = SocketState::Closed;
                        this.shutdown();
                    }
                    Poll::Ready(Some(StreamEvent::Packet { packet })) => {
                        match this.on_packet(packet) {
                            Err(StreamingError::Closed | StreamingError::SequenceNumberTooHigh) =>
                                return Poll::Ready(this.recv_stream_id),
                            Err(error) => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    local = %this.local,
                                    remote = %this.remote,
                                    recv_id = ?this.recv_stream_id,
                                    send_id = ?this.send_stream_id,
                                    ?error,
                                    "failed to handle packet"
                                );
                                this.write_state = WriteState::GetMessage;
                            }
                            Ok(()) => match this.inbound_context.pop_message() {
                                Some(message) =>
                                    this.write_state = WriteState::WriteMessage {
                                        offset: 0usize,
                                        message,
                                    },
                                None => this.write_state = WriteState::GetMessage,
                            },
                        }
                    }
                },
                WriteState::WriteMessage { offset, message } => {
                    match Pin::new(&mut this.stream).as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::WriteMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(_)) | Poll::Ready(Ok(0)) => {
                            this.write_state = WriteState::Closed;
                            this.read_state = SocketState::Closed;
                            this.shutdown();
                            continue;
                        }
                        Poll::Ready(Ok(nwritten)) => match nwritten + offset == message.len() {
                            true => {
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::WriteMessage {
                                    offset: offset + nwritten,
                                    message,
                                };
                            }
                        },
                    }
                }
                WriteState::Closed => match this.cmd_rx.poll_recv(cx) {
                    Poll::Pending => {
                        this.write_state = WriteState::Closed;
                        break;
                    }
                    Poll::Ready(None) => return Poll::Ready(this.recv_stream_id),
                    Poll::Ready(Some(StreamEvent::ShutDown)) => {
                        this.write_state = WriteState::Closed;
                        this.read_state = SocketState::Closed;
                        break;
                    }
                    Poll::Ready(Some(StreamEvent::Packet { packet })) => {
                        match this.on_packet(packet) {
                            Err(StreamingError::Closed | StreamingError::SequenceNumberTooHigh) =>
                                return Poll::Ready(this.recv_stream_id),
                            Err(error) => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    local = %this.local,
                                    remote = %this.remote,
                                    recv_id = ?this.recv_stream_id,
                                    send_id = ?this.send_stream_id,
                                    ?error,
                                    "failed to handle packet"
                                );
                                this.write_state = WriteState::Closed;
                            }
                            Ok(()) => {
                                this.write_state = WriteState::Closed;
                            }
                        }
                    }
                },
                WriteState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        recv_id = ?this.recv_stream_id,
                        send_id = ?this.send_stream_id,
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(this.recv_stream_id);
                }
            }
        }

        loop {
            match this.read_state {
                // if there are pending messages from previous reads, the socket shouldn't be read
                SocketState::ReadMessage | SocketState::Closed => match this.pending.is_empty() {
                    false => {
                        let outstanding = this.unacked.len();
                        let available = this.window_size.saturating_sub(outstanding);

                        // cannot send more data for now
                        if available == 0 {
                            break;
                        }

                        tracing::info!(
                            target: LOG_TARGET,
                            local = %this.local,
                            remote = %this.remote,
                            recv_id = ?this.recv_stream_id,
                            send_id = ?this.send_stream_id,
                            window_size = this.window_size,
                            num_unacked = ?this.unacked.len(),
                            num_pending = ?this.pending.len(),
                            "send pending packets",
                        );

                        let now = R::now();
                        let num_packets = cmp::min(this.pending.len(), available);
                        let packets =
                            this.pending.keys().take(num_packets).copied().collect::<Vec<_>>();

                        let num_sent = packets.into_iter().fold(0usize, |count, seq_nro| {
                            // packet must exist since its key existed in `pending`
                            let mut packet = this.pending.remove(&seq_nro).expect("to exist");

                            match this.event_tx.try_send((
                                match this.routing_path_handle.routing_path() {
                                    None => DeliveryStyle::Unspecified {
                                        destination_id: this.remote.clone(),
                                    },
                                    Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
                                },
                                packet.packet.clone(),
                                this.src_port,
                                this.dst_port,
                            )) {
                                Err(_) => {
                                    this.pending.insert(seq_nro, packet);
                                    count
                                }
                                Ok(()) => {
                                    packet.sent = now;
                                    this.unacked.insert(seq_nro, packet);

                                    count + 1
                                }
                            }
                        });

                        if num_sent > 0 && this.rto_timer.is_none() {
                            this.rto_timer = Some(R::timer(*this.rto));
                        }
                    }
                    true if !core::matches!(this.read_state, SocketState::Closed) =>
                        match Pin::new(&mut this.stream)
                            .as_mut()
                            .poll_read(cx, &mut this.read_buffer)
                        {
                            Poll::Pending => {
                                this.read_state = SocketState::ReadMessage;
                                break;
                            }
                            Poll::Ready(Err(_)) | Poll::Ready(Ok(0)) => {
                                this.write_state = WriteState::Closed;
                                this.read_state = SocketState::Closed;
                                this.shutdown();
                                continue;
                            }
                            Poll::Ready(Ok(nread)) => {
                                this.read_state = SocketState::SendMessage { offset: nread };
                            }
                        },
                    true => break,
                },
                SocketState::SendMessage { offset } => {
                    this.packetize(offset);
                    this.read_state = SocketState::ReadMessage;
                }
            }
        }

        // resend packets
        while let Some(timer) = &mut this.rto_timer {
            match timer.poll_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(_) => this.resend(),
            }
        }

        // send plain ack
        if this.inbound_context.poll_unpin(cx).is_ready() {
            let ack_through = this.inbound_context.seq_nro;
            let nacks =
                this.inbound_context.missing.iter().copied().take(MAX_NACKS).collect::<Vec<_>>();

            let mut builder = PacketBuilder::new(this.send_stream_id)
                .with_send_stream_id(this.recv_stream_id)
                .with_ack_through(ack_through)
                .with_nacks(nacks)
                .with_seq_nro(PLAIN_ACK);

            builder = if this.inbound_context.missing.len() >= MAX_NACKS {
                builder.with_delay_requested(CHOKING_REQUEST)
            } else {
                builder
            };

            let packet = if this.inbound_context.can_close() {
                builder
                    .with_close()
                    .with_from_included(this.destination.clone())
                    .with_signature()
                    .build_and_sign(&this.signing_key)
            } else {
                builder.build()
            }
            .to_vec();

            if let Err(error) = this.event_tx.try_send((
                match this.routing_path_handle.routing_path() {
                    None => DeliveryStyle::Unspecified {
                        destination_id: this.remote.clone(),
                    },
                    Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
                },
                packet.to_vec(),
                this.src_port,
                this.dst_port,
            )) {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %this.local,
                    remote = %this.remote,
                    recv_id = ?this.recv_stream_id,
                    send_id = ?this.send_stream_id,
                    ?error,
                    "failed to send packet",
                );
            }

            if this.inbound_context.can_close() {
                return Poll::Ready(this.recv_stream_id);
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        destination::routing_path::RoutingPathManager,
        primitives::{Lease, TunnelId},
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            TcpStream,
        },
    };
    use futures::StreamExt;
    use rand::{
        distributions::{Alphanumeric, DistString},
        seq::SliceRandom,
        thread_rng, Rng,
    };
    use thingbuf::mpsc::channel;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    struct StreamBuilder {
        cmd_tx: Sender<StreamEvent>,
        event_rx: Receiver<(DeliveryStyle, Vec<u8>, u16, u16)>,
        stream: tokio::net::TcpStream,
        _outbound: TunnelId,
        _inbound: Lease,
    }

    impl StreamBuilder {
        pub async fn build_stream() -> (Stream<MockRuntime>, Self) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let signing_key = SigningPrivateKey::random(MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            let destination_id = destination.id();

            let address = listener.local_addr().unwrap();
            let (stream1, stream2) =
                tokio::join!(listener.accept(), MockTcpStream::connect(address));
            let (stream, _) = stream1.unwrap();

            let (event_tx, event_rx) = channel(64);
            let (cmd_tx, cmd_rx) = channel(64);

            let remote = DestinationId::random();
            let outbound = TunnelId::random();
            let inbound = Lease::random();
            let mut path_manager =
                RoutingPathManager::<MockRuntime>::new(destination_id.clone(), vec![outbound]);
            path_manager.register_leases(&remote, Ok(vec![inbound.clone()]));
            let handle = path_manager.handle(remote.clone());

            tokio::spawn(async move { while let Some(_) = path_manager.next().await {} });

            (
                Stream::new(
                    stream2.unwrap(),
                    None,
                    StreamContext {
                        destination,
                        cmd_rx,
                        event_tx,
                        local: destination_id,
                        recv_stream_id: 1337u32,
                        remote: DestinationId::random(),
                        signing_key,
                    },
                    Default::default(),
                    StreamKind::Inbound { payload: vec![] },
                    handle,
                ),
                Self {
                    cmd_tx,
                    event_rx,
                    stream,
                    _outbound: outbound,
                    _inbound: inbound,
                },
            )
        }
    }

    #[tokio::test]
    async fn receive_multiple_packets() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        let messages = vec![
            b"hello\n".to_vec(),
            b"world\n".to_vec(),
            b"goodbye\n".to_vec(),
            b"world\n".to_vec(),
        ];

        for (i, message) in messages.iter().enumerate() {
            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(i as u32 + 1)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        for message in messages.into_iter() {
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(std::str::from_utf8(&message).unwrap(), response);
            response.clear();
        }

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        // all four messages acked with one packet
        {
            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 4u32);
            assert_eq!(seq_nro, 0u32);
            assert!(nacks.is_empty());
            assert!(payload.is_empty());
        }

        // send one more packet and verify that it's acked
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(5u32)
                    .with_payload(b"test message\n")
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("event")
            .expect("to succeed");

        let Packet {
            seq_nro,
            ack_through,
            nacks,
            payload,
            ..
        } = Packet::parse(&packet).unwrap();

        assert_eq!(ack_through, 5u32);
        assert_eq!(seq_nro, 0u32);
        assert!(nacks.is_empty());
        assert!(payload.is_empty());

        // read payload
        reader.read_line(&mut response).await.unwrap();
        assert_eq!("test message\n", response.as_str());
        response.clear();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect_err("stream closed");
    }

    #[tokio::test]
    async fn out_of_order() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        let mut messages = VecDeque::from_iter([
            (4u32, b"message\n".to_vec()),
            (6u32, b"world\n".to_vec()),
            (2u32, b"world\n".to_vec()),
            (1u32, b"hello\n".to_vec()),
            (3u32, b"testing\n".to_vec()),
            (5u32, b"goodbye\n".to_vec()),
        ]);

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        // send first packet and verify that there are nacks for packets 1, 2 and 3
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 4u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![1, 2, 3]);
            assert!(payload.is_empty());

            // verify the client is sent nothing
            assert!(tokio::time::timeout(
                Duration::from_millis(200),
                reader.read_line(&mut response)
            )
            .await
            .is_err());
        }

        // send second packet and verify that there is an additional nack for 5
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![1, 2, 3, 5]);
            assert!(payload.is_empty());

            // verify the client is sent nothing
            assert!(tokio::time::timeout(
                Duration::from_millis(200),
                reader.read_line(&mut response)
            )
            .await
            .is_err());
        }

        // send two more packets and verify that there is a nack left for packets 5 and 3
        // and that the client is send data for the first two packets
        {
            for _ in 0..2 {
                let (seq_nro, message) = messages.pop_front().unwrap();

                cmd_tx
                    .send(StreamEvent::Packet {
                        packet: PacketBuilder::new(1338u32)
                            .with_send_stream_id(1337u32)
                            .with_seq_nro(seq_nro)
                            .with_payload(&message)
                            .build()
                            .to_vec(),
                    })
                    .await
                    .unwrap();
            }

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![3, 5]);
            assert!(payload.is_empty());

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "hello\n");

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "world\n");
        }

        // send the 3rd packet and verify there's still nack for packet 5
        // and that messages for packets 3 and 4 are returned to client
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![5]);
            assert!(payload.is_empty());

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "testing\n");

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "message\n");
        }

        // send 5th packet and verify that there are no more nacks
        // and that the payloads for packets 5 and 6 are returned
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![]);
            assert!(payload.is_empty());

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "goodbye\n");

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "world\n");
        }

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect_err("stream closed");
    }

    #[tokio::test]
    async fn out_of_order_random() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        let test_string = Alphanumeric.sample_string(&mut thread_rng(), 256);

        let mut packets = test_string
            .clone()
            .into_bytes()
            .chunks(4)
            .enumerate()
            .map(|(seq_nro, message)| {
                PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(seq_nro as u32 + 1)
                    .with_payload(&message)
                    .build()
                    .to_vec()
            })
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 64);
        packets.shuffle(&mut thread_rng());

        // send packet to stream with random sleeps
        for packet in packets {
            cmd_tx.try_send(StreamEvent::Packet { packet }).unwrap();

            tokio::time::sleep(Duration::from_millis(thread_rng().gen_range(5..100))).await;
        }

        // ignore acks received from the stream
        tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

        // read back response which is exactly 256 bytes long
        let mut response = [0u8; 256];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(std::str::from_utf8(&response).unwrap(), test_string);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect_err("stream closed");
    }

    #[tokio::test]
    async fn stream_reset() {
        let (stream, StreamBuilder { cmd_tx, .. }) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // send two normal packets
        for (seq_nro, message) in vec![(1u32, b"msg1\n".to_vec()), (2u32, b"msg2\n".to_vec())] {
            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        // send packet with high seq number (missing packets) with `RESET`
        // and verify that the stream is closed event though there's missing data
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(10u32)
                    .with_reset()
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("no timeout")
            .unwrap();
    }

    #[tokio::test]
    async fn duplicate_packets() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        tokio::spawn(stream);

        let messages = vec![
            (1u32, b"hello1".to_vec()),
            (2u32, b"world1\n".to_vec()),
            (1u32, b"hello1\n".to_vec()),
            (4u32, b"world2\n".to_vec()),
            (3u32, b"goodbye2".to_vec()),
            (4u32, b"world3\n".to_vec()),
            (6u32, b"test2\n".to_vec()),
            (5u32, b"test1".to_vec()),
        ];

        for (i, message) in messages.iter() {
            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(*i)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        // 1st and 2nd messages are received normally
        {
            reader.read_line(&mut response).await.unwrap();
            assert_eq!("hello1world1\n", response);
            response.clear();
        }

        // 4th is send before 3rd but 3rd is ready normally
        {
            // concatenated 3rd and 4th message
            reader.read_line(&mut response).await.unwrap();
            assert_eq!("goodbye2world2\n", response);
            response.clear();
        }

        // 5th and 6th are received out of order and the duplicate 4th is ignored
        {
            // concatenated 5th and 6th message
            reader.read_line(&mut response).await.unwrap();
            assert_eq!("test1test2\n", response);
            response.clear();
        }
    }

    #[tokio::test]
    async fn out_of_order_last_packet_closes_connection() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        let test_string = Alphanumeric.sample_string(&mut thread_rng(), 128);

        let mut packets = test_string
            .clone()
            .into_bytes()
            .chunks(4)
            .enumerate()
            .map(|(seq_nro, message)| {
                let builder = PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(seq_nro as u32 + 1)
                    .with_payload(&message);

                if seq_nro == 31 {
                    builder.with_close()
                } else {
                    builder
                }
                .build()
                .to_vec()
            })
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 32);
        packets.shuffle(&mut thread_rng());

        // send packet to stream with random sleeps
        for packet in packets {
            cmd_tx.try_send(StreamEvent::Packet { packet }).unwrap();

            tokio::time::sleep(Duration::from_millis(thread_rng().gen_range(5..100))).await;
        }

        // read back response which is exactly 256 bytes long
        let mut response = [0u8; 128];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(std::str::from_utf8(&response).unwrap(), test_string);

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("no timeout")
            .unwrap();

        // ignore syn
        let (_, mut prev, _, _) = event_rx.recv().await.unwrap();

        // verify the last packet sent by the stream has the `CLOSE` flag set
        while let Ok((_, packet, _, _)) = event_rx.try_recv() {
            prev = packet;
        }

        let packet = Packet::parse(&prev).unwrap();
        assert!(packet.flags.close());
    }

    #[tokio::test]
    async fn sequence_number_too_high() {
        let (stream, StreamBuilder { cmd_tx, .. }) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        let messages = vec![
            b"hello\n".to_vec(),
            b"world\n".to_vec(),
            b"goodbye\n".to_vec(),
            b"world\n".to_vec(),
        ];

        for (i, message) in messages.iter().enumerate() {
            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(i as u32 + 1)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        // send packet with way too high sequence number
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(1024)
                    .with_payload(b"hello, world")
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stream to exist")
            .unwrap();
    }

    #[tokio::test]
    async fn choke() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                event_rx,
                stream: _stream,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        tokio::spawn(stream);

        // send every other packet so that the nack window grows
        for i in 0..1024 {
            if i % 2 == 0 {
                cmd_tx
                    .send(StreamEvent::Packet {
                        packet: PacketBuilder::new(1338u32)
                            .with_send_stream_id(1337u32)
                            .with_seq_nro(i as u32 + 1)
                            .with_payload(b"test")
                            .build()
                            .to_vec(),
                    })
                    .await
                    .unwrap();
            }
        }

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        // verify the last packet sent by the stream has the `CLOSE` flag set
        loop {
            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed");
            let packet = Packet::parse(&packet).unwrap();

            if packet.flags.delay_requested() == Some(CHOKING_REQUEST) {
                break;
            }
        }
    }

    #[tokio::test]
    async fn outbound_packets() {
        let (
            mut stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        client.write_all(b"hello, world\n").await.unwrap();
        client.write_all(b"testing 123\n").await.unwrap();
        client.write_all(b"goodbye, world\n").await.unwrap();

        // poll stream and send outbound packets
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed");

        let packet = Packet::parse(&packet).unwrap();
        assert_eq!(
            packet.payload,
            b"hello, world\ntesting 123\ngoodbye, world\n"
        );

        // verify there's one pending packet and that the rto timer is active
        assert_eq!(stream.unacked.len(), 1);
        assert_eq!(stream.next_seq_nro, 2);
        assert!(stream.pending.is_empty());
        assert!(stream.rto_timer.is_some());

        // send ack for the packet
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        // poll stream and handle ack
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        assert_eq!(stream.window_size, 2);
        assert_ne!(*stream.rtt, INITIAL_RTT);
        assert_ne!(*stream.rto, INITIAL_RTO);
    }

    #[tokio::test]
    async fn rto_works() {
        let (
            mut stream,
            StreamBuilder {
                stream: mut client,
                event_rx,
                cmd_tx: _cmd_tx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        client.write_all(b"hello, world\n").await.unwrap();
        client.write_all(b"testing 123\n").await.unwrap();
        client.write_all(b"goodbye, world\n").await.unwrap();

        // poll stream and send outbound packets
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        let (_, first_packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed");

        let packet = Packet::parse(&first_packet).unwrap();
        assert_eq!(
            packet.payload,
            b"hello, world\ntesting 123\ngoodbye, world\n"
        );

        // verify there's one pending packet and that the rto timer is active
        assert_eq!(stream.unacked.len(), 1);
        assert_eq!(stream.next_seq_nro, 2);
        assert!(stream.pending.is_empty());
        assert!(stream.rto_timer.is_some());

        let future = async {
            loop {
                tokio::select! {
                    _ = &mut stream => {}
                    event = event_rx.recv() => break event,
                }
            }
        };

        let (_, second_packet, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
            .await
            .expect("no timeout")
            .expect("to succeed");

        assert_eq!(first_packet, second_packet);

        // verify state is unchanged
        assert_eq!(stream.unacked.len(), 1);
        assert_eq!(stream.next_seq_nro, 2);
        assert_eq!(stream.window_size, 1);
        assert!(stream.pending.is_empty());
        assert!(stream.rto_timer.is_some());
    }

    #[tokio::test]
    async fn resend_decrease_window_size() {
        let (
            mut stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        client.write_all(b"hello, world\n").await.unwrap();
        client.write_all(b"testing 123\n").await.unwrap();
        client.write_all(b"goodbye, world\n").await.unwrap();

        // poll stream and send outbound packets
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        let (_, first_packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed");

        let packet = Packet::parse(&first_packet).unwrap();
        assert_eq!(
            packet.payload,
            b"hello, world\ntesting 123\ngoodbye, world\n"
        );

        // send ack for the packet
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        // poll stream and handle ack
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        assert_eq!(stream.window_size, 2);
        assert_ne!(*stream.rtt, INITIAL_RTT);
        assert_ne!(*stream.rto, INITIAL_RTO);

        client.write_all(b"dropped packet\n").await.unwrap();

        // poll stream and send outbound packets
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        let (_, first_packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed");

        let packet = Packet::parse(&first_packet).unwrap();
        assert_eq!(packet.payload, b"dropped packet\n");

        // verify there's one pending packet and that the rto timer is active
        assert_eq!(stream.unacked.len(), 1);
        assert_eq!(stream.next_seq_nro, 3);
        assert_eq!(stream.window_size, 2);
        assert!(stream.pending.is_empty());
        assert!(stream.rto_timer.is_some());

        let future = async {
            loop {
                tokio::select! {
                    _ = &mut stream => {}
                    event = event_rx.recv() => break event,
                }
            }
        };

        let (_, second_packet, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
            .await
            .expect("no timeout")
            .expect("to succeed");

        assert_eq!(first_packet, second_packet);

        // verify state is unchanged
        assert_eq!(stream.unacked.len(), 1);
        assert_eq!(stream.next_seq_nro, 3);
        assert_eq!(stream.window_size, 1);
        assert!(stream.pending.is_empty());
        assert!(stream.rto_timer.is_some());
    }

    #[tokio::test]
    async fn data_split_into_multiple_packets() {
        let (
            mut stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        client
            .write_all(&{
                let mut data = Vec::new();
                data.extend_from_slice(&vec![1u8; MTU_SIZE]);
                data.extend_from_slice(&vec![2u8; MTU_SIZE]);
                data.extend_from_slice(&vec![3u8; MTU_SIZE]);

                data
            })
            .await
            .unwrap();

        // poll stream and send outbound packets
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        let (_, first_packet, _, _) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed");

        let packet = Packet::parse(&first_packet).unwrap();
        assert_eq!(packet.payload, vec![1u8; MTU_SIZE]);
        assert_eq!(stream.window_size, 1);
        assert_eq!(stream.unacked.len(), INITIAL_WINDOW_SIZE);
        assert_eq!(stream.pending.len(), 2);

        // send ack for the packet
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        // poll stream and handle ack
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        assert_eq!(stream.window_size, 2);
        assert_ne!(*stream.rtt, INITIAL_RTT);
        assert_ne!(*stream.rto, INITIAL_RTO);

        // send more data
        client.write_all(&vec![4u8; MTU_SIZE]).await.unwrap();

        // verify the other two packets are sent now that window size is 2
        let future = async {
            let mut packets = Vec::new();
            while packets.len() != 2 {
                tokio::select! {
                    _ = &mut stream => {}
                    event = event_rx.recv() => {
                        packets.push(event.unwrap());
                    }
                }
            }

            packets
        };

        let packets =
            tokio::time::timeout(Duration::from_secs(2), future).await.expect("no timeout");

        let first = Packet::parse(&packets[0].1).unwrap();
        assert_eq!(first.payload, vec![2u8; MTU_SIZE]);

        let second = Packet::parse(&packets[1].1).unwrap();
        assert_eq!(second.payload, vec![3u8; MTU_SIZE]);

        assert!(stream.pending.is_empty());
        assert_eq!(stream.unacked.len(), 2);

        // send ack for both packets
        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(second.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        let future = async {
            loop {
                tokio::select! {
                    _ = &mut stream => {}
                    event = event_rx.recv() => break event,
                }
            }
        };

        let (_, third_packet, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
            .await
            .expect("no timeout")
            .expect("to succeed");

        let third = Packet::parse(&third_packet).unwrap();
        assert_eq!(third.payload, vec![4u8; MTU_SIZE]);
    }

    #[tokio::test]
    async fn nacks_work() {
        let (
            mut stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        // send five packets
        client
            .write_all(&{
                let mut data = Vec::new();
                data.extend_from_slice(&vec![1u8; MTU_SIZE]);
                data.extend_from_slice(&vec![2u8; MTU_SIZE]);
                data.extend_from_slice(&vec![3u8; MTU_SIZE]);
                data.extend_from_slice(&vec![4u8; MTU_SIZE]);
                data.extend_from_slice(&vec![5u8; MTU_SIZE]);

                data
            })
            .await
            .unwrap();

        // poll stream and send outbound packets
        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        // ack first packet
        {
            let first_packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
                .1;

            let packet = Packet::parse(&first_packet).unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        // ack the next two packets
        {
            let future = async {
                let mut packets = Vec::new();
                while packets.len() != 2 {
                    tokio::select! {
                        _ = &mut stream => {}
                        event = event_rx.recv() => {
                            packets.push(event.unwrap());
                        }
                    }
                }

                packets
            };

            let packets =
                tokio::time::timeout(Duration::from_secs(2), future).await.expect("no timeout");
            let packet = Packet::parse(&packets[1].1).unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        // read and ack the last two packets and verify window size
        {
            let future = async {
                let mut packets = Vec::new();
                while packets.len() != 2 {
                    tokio::select! {
                        _ = &mut stream => {}
                        event = event_rx.recv() => {
                            packets.push(event.unwrap());
                        }
                    }
                }

                packets
            };

            let packets =
                tokio::time::timeout(Duration::from_secs(2), future).await.expect("no timeout");
            let packet = Packet::parse(&packets[1].1).unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

            assert_eq!(stream.window_size, 32);
            assert!(stream.unacked.is_empty());
            assert!(stream.pending.is_empty());
        }

        // send 6 packets and NACK 2 of them
        client
            .write_all(&{
                let mut data = Vec::new();
                data.extend_from_slice(&vec![6u8; MTU_SIZE]);
                data.extend_from_slice(&vec![7u8; MTU_SIZE]);
                data.extend_from_slice(&vec![8u8; MTU_SIZE]);
                data.extend_from_slice(&vec![9u8; MTU_SIZE]);
                data.extend_from_slice(&vec![0xau8; MTU_SIZE]);
                data.extend_from_slice(&vec![0xbu8; MTU_SIZE]);

                data
            })
            .await
            .unwrap();

        let future = async {
            let mut packets = Vec::new();
            while packets.len() != 6 {
                tokio::select! {
                    _ = &mut stream => {}
                    event = event_rx.recv() => {
                        packets.push(event.unwrap());
                    }
                }
            }

            packets
        };

        let packets =
            tokio::time::timeout(Duration::from_secs(2), future).await.expect("no timeout");
        let packet = Packet::parse(&packets[5].1).unwrap();

        cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_nacks(vec![packet.seq_nro - 1, packet.seq_nro - 3])
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .build()
                    .to_vec(),
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();

        assert_eq!(stream.window_size, 67);
        assert_eq!(stream.unacked.len(), 2);
        assert!(stream.pending.is_empty());

        let future = async {
            let mut packets = Vec::new();
            while packets.len() != 2 {
                tokio::select! {
                    _ = &mut stream => {}
                    event = event_rx.recv() => {
                        packets.push(event.unwrap());
                    }
                }
            }

            packets
        };

        let packets =
            tokio::time::timeout(Duration::from_secs(12), future).await.expect("no timeout");
        let first_missing = Packet::parse(&packets[0].1).unwrap();
        let second_missing = Packet::parse(&packets[1].1).unwrap();

        assert_eq!(first_missing.payload, vec![8u8; MTU_SIZE]);
        assert_eq!(second_missing.payload, vec![0xau8; MTU_SIZE]);
        assert_eq!(stream.window_size, 66);
    }

    #[tokio::test]
    async fn rtt_rto_calculated_correctly() {
        let (
            mut stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stream => {},
                    _ = tokio::time::sleep(Duration::from_secs(5)) => return stream,
                }
            }
        });

        // ignore syn
        let (_, _, _, _) = event_rx.recv().await.unwrap();

        // send 11 packets, each with 100ms delay
        for i in 1..=11 {
            client.write_all(&vec![i as u8; 256]).await.unwrap();

            let (_, packet, _, _) = event_rx.recv().await.unwrap();
            let packet = Packet::parse(&packet).unwrap();

            tokio::time::sleep(Duration::from_millis(100)).await;

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }

        let stream = handle.await.unwrap();
        assert!((*stream.rtt).as_millis() >= 100 && (*stream.rtt).as_millis() <= 105);
        assert!(
            (*stream.rto).as_millis() > (*stream.rtt).as_millis()
                && (*stream.rto).as_millis() <= 130
        );
    }

    #[tokio::test]
    async fn window_size_clamping() {
        let (
            mut stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // ignore syn
        let (_, _, _, _) = event_rx.recv().await.unwrap();

        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);

        // verify window is first grown to 2 and then decreased back to 1
        {
            client.write_all(&vec![1 as u8; 256]).await.unwrap();

            let future = async {
                loop {
                    tokio::select! {
                        _ = &mut stream => {}
                        event = event_rx.recv() => break event,
                    }
                }
            };

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
                .await
                .expect("no timeout")
                .expect("to succeed");

            let packet = Packet::parse(&packet).unwrap();

            tokio::time::sleep(Duration::from_millis(500)).await;

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            // verify that window size is doubled
            tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();
            assert_eq!(stream.window_size, 2);

            // send another packet but this time allow rto to expire
            client.write_all(&vec![1 as u8; 256]).await.unwrap();

            let future = async {
                loop {
                    tokio::select! {
                        _ = &mut stream => {}
                        event = event_rx.recv() => break event,
                    }
                }
            };

            // read packet and ignore it
            let (_, ignored, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
                .await
                .expect("no timeout")
                .expect("to succeed");

            let future = async {
                loop {
                    tokio::select! {
                        _ = &mut stream => {}
                        event = event_rx.recv() => break event,
                    }
                }
            };

            // read it again and verify it's the same as `ignored`
            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
                .await
                .expect("no timeout")
                .expect("to succeed");
            assert_eq!(ignored, packet);

            // verify that window size is decreased back to 1
            assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);

            let packet = Packet::parse(&packet).unwrap();
            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();
        }

        // verify exponential window growth works
        for i in 0..5 {
            client.write_all(&vec![i as u8; 256]).await.unwrap();

            let future = async {
                loop {
                    tokio::select! {
                        _ = &mut stream => {}
                        event = event_rx.recv() => break event,
                    }
                }
            };

            let (_, packet, _, _) = tokio::time::timeout(Duration::from_secs(15), future)
                .await
                .expect("no timeout")
                .expect("to succeed");

            let packet = Packet::parse(&packet).unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();

            tokio::time::timeout(Duration::from_secs(1), &mut stream).await.unwrap_err();
        }
        assert_eq!(stream.window_size, EXP_GROWTH_STOP_THRESHOLD);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stream => {}
                    _ = tokio::time::sleep(Duration::from_secs(5)) => return stream,
                }
            }
        });

        // send 100 more packets and verify the window size is capped at 128
        for i in 0..100 {
            client.write_all(&vec![i as u8; 256]).await.unwrap();

            let (_, packet, _, _) = event_rx.recv().await.unwrap();
            let packet = Packet::parse(&packet).unwrap();

            cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await
                .unwrap();
        }
        let stream = handle.await.unwrap();
        assert_eq!(stream.window_size, MAX_WINDOW_SIZE);
    }

    #[test]
    fn exponential_backoff_rto() {
        let mut rto = Rto::new();
        let mut rtt = Rtt::new();

        for _ in 0..10 {
            let sample = Duration::from_millis(100 + 1);

            rtt.calculate_rtt(sample);
            rto.calculate_rto(&rtt, sample);
        }

        assert_eq!(rtt.as_millis(), 101);
        assert_eq!(rto.as_millis(), 113);

        assert_eq!(rto.exponential_backoff(), Duration::from_millis(226));
        assert_eq!(rto.exponential_backoff(), Duration::from_millis(339));
        assert_eq!(rto.exponential_backoff(), Duration::from_millis(452));

        let sample = Duration::from_millis(110);

        rtt.calculate_rtt(sample);
        rto.calculate_rto(&rtt, sample);

        assert_eq!(rtt.as_millis(), 102);
        assert_eq!(rto.as_millis(), 119);

        assert_eq!(rto.exponential_backoff(), Duration::from_millis(238));
    }

    #[tokio::test]
    async fn client_closes_socket_with_pending_data() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        let handle = tokio::spawn(async move {
            let _ = stream.await;
        });

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        // send 20 packets
        client
            .write_all(&{
                (1..=20).fold(Vec::new(), |mut data, i| {
                    data.extend_from_slice(&vec![i as u8; MTU_SIZE]);
                    data
                })
            })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(client);

        for i in 1..=20 {
            let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
                .1;

            let packet = Packet::parse(&packet).unwrap();

            assert_eq!(packet.payload, vec![i as u8; MTU_SIZE]);

            tokio::time::sleep(Duration::from_millis(500)).await;

            let _ = cmd_tx
                .send(StreamEvent::Packet {
                    packet: PacketBuilder::new(1338u32)
                        .with_ack_through(packet.seq_nro)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(PLAIN_ACK)
                        .build()
                        .to_vec(),
                })
                .await;
        }

        let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
            .1;

        let packet = Packet::parse(&packet).unwrap();
        let _ = cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .with_close()
                    .build()
                    .to_vec(),
            })
            .await;

        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("no timeout")
            .expect("to succeed");
    }

    #[tokio::test]
    async fn local_client_closes_socket() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        let mut handle = tokio::spawn(async move {
            let _ = stream.await;
        });

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        client
            .write_all(&{
                let mut data = Vec::new();
                data.extend_from_slice(&vec![1u8; MTU_SIZE]);
                data
            })
            .await
            .unwrap();

        let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
            .1;

        let packet = Packet::parse(&packet).unwrap();

        assert_eq!(packet.payload, vec![1u8; MTU_SIZE]);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // send ack with payload
        let _ = cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(1u32)
                    .with_payload(&vec![2u8; MTU_SIZE])
                    .build()
                    .to_vec(),
            })
            .await;

        // verify the correct payload was received and close client socket
        let mut buffer = vec![0u8; MTU_SIZE * 2];
        let nread = client.read(&mut buffer).await.unwrap();
        assert_eq!(buffer[..nread], vec![2u8; MTU_SIZE]);

        client.shutdown().await.unwrap();
        drop(client);

        // verify `CLOSE` is received
        let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
            .1;
        let packet = Packet::parse(&packet).unwrap();
        assert!(packet.flags.close());

        // verify that the stream is not shut down because ack hasn't been received
        assert!(tokio::time::timeout(Duration::from_secs(5), &mut handle).await.is_err());

        let _ = cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(PLAIN_ACK)
                    .with_close()
                    .build()
                    .to_vec(),
            })
            .await;

        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("no timeout")
            .expect("to succeed");
    }

    #[tokio::test]
    async fn remote_closes_socket() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                event_rx,
                ..
            },
        ) = StreamBuilder::build_stream().await;

        // verify initial state
        assert_eq!(stream.window_size, INITIAL_WINDOW_SIZE);
        assert_eq!(*stream.rtt, INITIAL_RTT);
        assert_eq!(*stream.rto, INITIAL_RTO);

        let handle = tokio::spawn(async move {
            let _ = stream.await;
        });

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        client
            .write_all(&{
                let mut data = Vec::new();
                data.extend_from_slice(&vec![1u8; MTU_SIZE]);
                data
            })
            .await
            .unwrap();

        let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
            .1;

        let packet = Packet::parse(&packet).unwrap();

        assert_eq!(packet.payload, vec![1u8; MTU_SIZE]);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // send ack with payload
        let _ = cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(1u32)
                    .with_payload(&vec![2u8; MTU_SIZE])
                    .build()
                    .to_vec(),
            })
            .await;

        tokio::time::sleep(Duration::from_secs(5)).await;

        // verify the correct payload was received and close client socket
        let mut buffer = vec![0u8; MTU_SIZE * 2];
        let nread = client.read(&mut buffer).await.unwrap();
        assert_eq!(buffer[..nread], vec![2u8; MTU_SIZE]);

        // verify `CLOSE` is received
        let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
            .1;
        let packet = Packet::parse(&packet).unwrap();
        assert!(!packet.flags.close());

        // send close
        let _ = cmd_tx
            .send(StreamEvent::Packet {
                packet: PacketBuilder::new(1338u32)
                    .with_ack_through(packet.seq_nro)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(2u32)
                    .with_close()
                    .build()
                    .to_vec(),
            })
            .await;

        // verify `CLOSE` is received
        let packet = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
            .1;
        let packet = Packet::parse(&packet).unwrap();
        assert!(packet.flags.close());

        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("no timeout")
            .expect("to succeed");
    }
}
