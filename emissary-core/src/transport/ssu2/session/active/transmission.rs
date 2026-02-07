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
    i2np::{Message, MessageType},
    primitives::RouterId,
    runtime::{Counter, Histogram, Instant, MetricsHandle, Runtime},
    transport::ssu2::{
        message::data::{DataMessageBuilder, MessageKind, PeerTestBlock},
        metrics::*,
        session::{
            active::{ack::AckInfo, RemoteAckManager},
            KeyContext,
        },
    },
};

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use bytes::BytesMut;
use core::{
    cmp::{max, min},
    fmt,
    ops::Deref,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::active::transmission";

/// SSU2 overheader
///
/// Short header + block type + Poly1305 authentication tag.
const SSU2_OVERHEAD: usize = 16usize + 1usize + 16usize;

/// Overhead of `RouterInfo` block.
///
/// Block type + size + flag + frag.
const RI_BLOCK_OVERHEAD: usize = 1usize + 2usize + 1usize + 1usize;

/// Immediate ACK interval.
///
/// How often should an immediate ACK be bundled in a message.
const IMMEDIATE_ACK_INTERVAL: u32 = 10u32;

/// Resend termination threshold.
///
/// How many times is a packet resent before the remote router is considered unresponsive
/// and the session is terminated.
const RESEND_TERMINATION_THRESHOLD: usize = 7usize;

/// Initial RTO.
const INITIAL_RTO: Duration = Duration::from_millis(540);

/// Minimum RTO.
const MIN_RTO: Duration = Duration::from_millis(100);

/// Maximum RTO.
const MAX_RTO: Duration = Duration::from_millis(2500);

/// RTT dampening factor (alpha).
const RTT_DAMPENING_FACTOR: f64 = 0.125f64;

/// RTTDEV dampening factor (beta).
const RTTDEV_DAMPENING_FACTOR: f64 = 0.25;

/// Minimum window size.
const MIN_WINDOW_SIZE: usize = 16usize;

/// Maximum window size.
const MAX_WINDOW_SIZE: usize = 256usize;

/// Retransmission timeout (RTO).
enum RetransmissionTimeout {
    /// Unsampled RTO.
    Unsampled,

    /// Sample RTO.
    Sampled {
        /// RTO.
        rto: Duration,

        /// Round-trip time (RTT).
        rtt: Duration,

        /// RTT variance.
        rtt_var: Duration,
    },
}

impl RetransmissionTimeout {
    /// Calculate retransmission timeout (RTO).
    ///
    /// If this is the first measured sample, use it as-is. Otherwise calculate a smoothed
    /// round-trip time (RTT) and from that calculate a smoothed RTO.
    fn calculate_rto(&mut self, sample: Duration) {
        let rtt = match self {
            Self::Unsampled => sample,
            Self::Sampled { rtt, .. } => Duration::from_millis(
                ((1f64 - RTT_DAMPENING_FACTOR) * rtt.as_millis() as f64
                    + RTT_DAMPENING_FACTOR * sample.as_millis() as f64) as u64,
            ),
        };

        match self {
            Self::Unsampled => {
                *self = Self::Sampled {
                    rto: rtt * 2,
                    rtt,
                    rtt_var: rtt / 2,
                };
            }
            Self::Sampled { rtt_var, .. } => {
                // calculate smoothed rto:
                //
                // rtt_var = (1 − β) × RTTVAR + β ×∣SRTT − RTT∣
                let srtt = rtt.as_millis() as i64;
                let abs = {
                    let sample = sample.as_millis() as i64;
                    RTTDEV_DAMPENING_FACTOR * i64::abs(srtt - sample) as f64
                };
                let rtt_var = rtt_var.as_millis() as f64;
                let rtt_var = (1f64 - RTTDEV_DAMPENING_FACTOR) * rtt_var + abs;
                let rto = Duration::from_millis((srtt as f64 + 4f64 * rtt_var) as u64);

                *self = Self::Sampled {
                    rto: min(MAX_RTO, max(rto, MIN_RTO)),
                    rtt,
                    rtt_var: Duration::from_millis(rtt_var as u64),
                };
            }
        }
    }
}

impl Deref for RetransmissionTimeout {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Unsampled => &INITIAL_RTO,
            Self::Sampled { rto, .. } => rto,
        }
    }
}

/// Segment kind.
enum SegmentKind {
    /// Unfragmented I2NP message.
    UnFragmented {
        /// Unfragmented I2NP message.
        message: Vec<u8>,
    },

    /// First fragment.
    FirstFragment {
        /// Fragment.
        fragment: Vec<u8>,

        /// Short expiration.
        expiration: u32,

        /// Message type.
        message_type: MessageType,

        /// Message ID.
        message_id: u32,
    },

    /// Follow-on fragment.
    FollowOnFragment {
        /// Fragment.
        fragment: Vec<u8>,

        /// Fragment number.
        fragment_num: u8,

        /// Last fragment.
        last: bool,

        /// Message ID.
        message_id: u32,
    },

    /// Peer test block.
    PeerTest {
        /// Peer test message block.
        peer_test_block: PeerTestBlock,

        /// Serialized `RouterInfo`, if sent.
        router_info: Option<Vec<u8>>,
    },

    /// `RouterInfo` block.
    RouterInfo {
        /// Serialized `RouterInfo`.
        router_info: Vec<u8>,
    },
}

impl<'a> From<&'a SegmentKind> for MessageKind<'a> {
    fn from(value: &'a SegmentKind) -> Self {
        match value {
            SegmentKind::UnFragmented { message } => Self::UnFragmented { message },
            SegmentKind::FirstFragment {
                fragment,
                expiration,
                message_type,
                message_id,
            } => Self::FirstFragment {
                fragment,
                expiration: *expiration,
                message_type: *message_type,
                message_id: *message_id,
            },
            SegmentKind::FollowOnFragment {
                fragment,
                fragment_num,
                last,
                message_id,
            } => Self::FollowOnFragment {
                fragment,
                fragment_num: *fragment_num,
                last: *last,
                message_id: *message_id,
            },
            SegmentKind::PeerTest {
                peer_test_block,
                router_info,
            } => Self::PeerTest {
                peer_test_block,
                router_info: router_info.as_deref(),
            },
            SegmentKind::RouterInfo { router_info } => Self::RouterInfo { router_info },
        }
    }
}

/// In-flight segment.
struct Segment<R: Runtime> {
    /// How many times the packet has been sent to remote router.
    num_sent: usize,

    /// Segment kind.
    ///
    /// Either an unfragmented I2NP message or a fragment of an I2NP message.
    segment: SegmentKind,

    /// When was the packet sent.
    sent: R::Instant,
}

/// Transmission manager.
pub struct TransmissionManager<R: Runtime> {
    /// Destination connection ID.
    dst_id: u64,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    intro_key: [u8; 32],

    /// Number of the packet that contained last immediate ACK.
    last_immediate_ack: u32,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Pending segments.
    pending: VecDeque<SegmentKind>,

    /// Next packet number.
    pkt_num: Arc<AtomicU32>,

    /// Remote ACK manager.
    remote_ack_manager: RemoteAckManager,

    /// ID of the remote router.
    router_id: RouterId,

    /// RTO.
    rto: RetransmissionTimeout,

    /// In-flight segments.
    segments: BTreeMap<u32, Segment<R>>,

    /// Key context for outbound packets.
    send_key_ctx: KeyContext,

    /// Window size.
    window_size: usize,
}

/// Transmission message.
pub enum TransmissionMessage {
    /// I2NP message.
    Message(Message),

    /// Peer test message.
    PeerTest(PeerTestBlock),

    /// Peer test message with `RouterInfo`.
    ///
    /// May be split into two datagrams.
    PeerTestWithRouterInfo((PeerTestBlock, Vec<u8>)),
}

impl From<Message> for TransmissionMessage {
    fn from(value: Message) -> Self {
        Self::Message(value)
    }
}

impl From<PeerTestBlock> for TransmissionMessage {
    fn from(value: PeerTestBlock) -> Self {
        Self::PeerTest(value)
    }
}

impl From<(PeerTestBlock, Vec<u8>)> for TransmissionMessage {
    fn from(value: (PeerTestBlock, Vec<u8>)) -> Self {
        Self::PeerTestWithRouterInfo(value)
    }
}

impl fmt::Debug for TransmissionMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f
                .debug_struct("TransmissionMessage::Message")
                .field("message", &message)
                .finish(),
            Self::PeerTest(block) =>
                f.debug_struct("TransmissionMessage::PeerTest").field("block", &block).finish(),
            Self::PeerTestWithRouterInfo((block, _)) => f
                .debug_struct("TransmissionMessage::PeerTestWithRouterInfo")
                .field("block", &block)
                .finish_non_exhaustive(),
        }
    }
}

impl<R: Runtime> TransmissionManager<R> {
    /// Create new [`TransmissionManager`].
    pub fn new(
        dst_id: u64,
        router_id: RouterId,
        intro_key: [u8; 32],
        send_key_ctx: KeyContext,
        pkt_num: Arc<AtomicU32>,
        metrics: R::MetricsHandle,
    ) -> Self {
        Self {
            dst_id,
            intro_key,
            last_immediate_ack: 0u32,
            metrics,
            pending: VecDeque::new(),
            pkt_num,
            remote_ack_manager: RemoteAckManager::new(),
            router_id,
            rto: RetransmissionTimeout::Unsampled,
            segments: BTreeMap::new(),
            send_key_ctx,
            window_size: MIN_WINDOW_SIZE,
        }
    }

    /// Get next packet number.
    pub fn next_pkt_num(&self) -> u32 {
        self.pkt_num.fetch_add(1u32, Ordering::Relaxed)
    }

    /// Does [`TransmissionManager`] have capacity to send more packets?
    ///
    /// Compares the current window size to the number of in-flight packets.
    pub fn has_capacity(&self) -> bool {
        self.segments.len() + self.pending.len() < self.window_size
    }

    /// Get reference to measured Round-trip time (RTT).
    pub fn round_trip_time(&self) -> Duration {
        match &self.rto {
            RetransmissionTimeout::Unsampled => INITIAL_RTO,
            RetransmissionTimeout::Sampled { rtt, .. } => *rtt,
        }
    }

    /// Does a payload of size `size` fit inside a single datagram.
    pub fn fits_in_datagram(&self, size: usize) -> bool {
        size + SSU2_OVERHEAD <= 1200
    }

    /// Register packet number for a packet received from remote router.
    pub fn register_remote_pkt(&mut self, pkt_num: u32) {
        self.remote_ack_manager.register_pkt(pkt_num);
    }

    /// Schedule `messsage` for outbound delivery.
    ///
    /// The message is split into one or more segments, depending on `message`'s size.
    ///
    /// The segment(s) are only marked as pending and [`TransmissionManager::drain()`]
    /// must be called to drain the pending queue and mark the message as "in-flight".
    pub fn schedule(&mut self, message: impl Into<TransmissionMessage>) {
        let message = message.into();

        match message {
            TransmissionMessage::Message(message) => {
                if self.fits_in_datagram(message.serialized_len_short()) {
                    self.metrics.histogram(OUTBOUND_FRAGMENT_COUNT).record(1f64);

                    return self.pending.push_back(SegmentKind::UnFragmented {
                        message: message.serialize_short(),
                    });
                }

                let fragments = message.payload.chunks(1200).collect::<Vec<_>>();
                let num_fragments = fragments.len();
                self.metrics.histogram(OUTBOUND_FRAGMENT_COUNT).record(num_fragments as f64);

                for (fragment_num, fragment) in fragments.into_iter().enumerate() {
                    let segment = match fragment_num {
                        0 => SegmentKind::FirstFragment {
                            fragment: fragment.to_vec(),
                            expiration: message.expiration.as_secs() as u32,
                            message_type: message.message_type,
                            message_id: message.message_id,
                        },
                        _ => SegmentKind::FollowOnFragment {
                            fragment: fragment.to_vec(),
                            fragment_num: fragment_num as u8,
                            last: fragment_num == num_fragments - 1,
                            message_id: message.message_id,
                        },
                    };

                    self.pending.push_back(segment);
                }
            }
            TransmissionMessage::PeerTest(peer_test_block) => {
                debug_assert!(self.fits_in_datagram(peer_test_block.serialized_len()));

                self.pending.push_back(SegmentKind::PeerTest {
                    peer_test_block,
                    router_info: None,
                });
            }
            TransmissionMessage::PeerTestWithRouterInfo((peer_test_block, router_info)) => {
                if self.fits_in_datagram(
                    peer_test_block.serialized_len() + router_info.len() + RI_BLOCK_OVERHEAD,
                ) {
                    self.pending.push_back(SegmentKind::PeerTest {
                        peer_test_block,
                        router_info: Some(router_info),
                    });
                } else {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        "fragmenting peer test with router info into two packets",
                    );

                    self.pending.push_back(SegmentKind::RouterInfo { router_info });
                    self.pending.push_back(SegmentKind::PeerTest {
                        peer_test_block,
                        router_info: None,
                    });
                }
            }
        }
    }

    /// Register ACK.
    ///
    /// - `ack_through` marks the highest packet that was ACKed.
    /// - `num_acks` marks the number of ACKs below `ack_through`
    /// - `range` contains a `(# of NACK, # of ACK)` tuples
    ///
    /// Start from `ack_through` and mark it and `num_acks` many packet that follow as received and
    /// if there are any ranges specified, go through them and marked packets as received dropped.
    /// Packets have not been explicitly NACKed are also considered dropped.
    pub fn register_ack(&mut self, ack_through: u32, num_acks: u8, ranges: &[(u8, u8)]) {
        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            ?ack_through,
            ?num_acks,
            ?ranges,
            num_segments = ?self.segments.len(),
            "handle ack",
        );

        (0..=num_acks).for_each(|i| {
            // TODO: if-let chain
            if let Some(Segment { num_sent, sent, .. }) =
                self.segments.remove(&(ack_through.saturating_sub(i as u32)))
            {
                // register ack time irrespective of how many the packet was sent
                self.metrics
                    .histogram(ACK_RECEIVE_TIME)
                    .record(sent.elapsed().as_millis() as f64);

                // packet has not been resent
                if num_sent == 1 {
                    self.rto.calculate_rto(sent.elapsed());
                }

                self.window_size += 1;
            }
        });

        // first packet in the ranges start at `ack_through - num_acks` and the first acked packet
        // that can be removed from `segments` starts at `ack_through - num_acks - ranges[0].0`
        let mut next_pkt = ack_through.saturating_sub(num_acks as u32);

        for (nack, ack) in ranges {
            next_pkt = next_pkt.saturating_sub(*nack as u32);

            for _ in 1..=*ack {
                next_pkt = next_pkt.saturating_sub(1);

                // TODO: if-let chain
                if let Some(Segment { num_sent, sent, .. }) = self.segments.remove(&next_pkt) {
                    // register ack time irrespective of how many the packet was sent
                    self.metrics
                        .histogram(ACK_RECEIVE_TIME)
                        .record(sent.elapsed().as_millis() as f64);

                    // packet has not been resent
                    if num_sent == 1 {
                        self.rto.calculate_rto(sent.elapsed());
                    }

                    self.window_size += 1;
                }
            }
        }

        if self.window_size > MAX_WINDOW_SIZE {
            self.window_size = MAX_WINDOW_SIZE;
        }
    }

    /// Drain pending, unsent packets.
    ///
    /// Packets which have not yet been sent (from oldest to newest) are selected from pending
    /// packets (respecting window size). Each packet is generated a packet number and `Data`
    /// message is created for each packet.
    ///
    /// Packets are internally stored into `segments` which tracks when the packet expires and must
    /// be resent.
    pub fn drain(&mut self) -> Option<Vec<BytesMut>> {
        if self.pending.is_empty() {
            return None;
        }

        // TODO: optimization: insert into `segments` only after creating data packet
        let pkts_to_send = (0..min(
            self.pending.len(),
            self.window_size.saturating_sub(self.segments.len()),
        ))
            .filter_map(|_| {
                let segment = self.pending.pop_front()?;
                let pkt_num = self.next_pkt_num();

                self.segments.insert(
                    pkt_num,
                    Segment {
                        num_sent: 1usize,
                        sent: R::now(),
                        segment,
                    },
                );

                Some(pkt_num)
            })
            .collect::<Vec<_>>();

        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack_manager.ack_info();
        let num_pkts = pkts_to_send.len();

        Some(
            pkts_to_send
                .into_iter()
                .enumerate()
                .map(|(i, pkt_num)| {
                    // segment must exist since it was just inserted into `segments`
                    let segment = (&self.segments.get(&pkt_num).expect("to exist").segment).into();

                    // include immediate ack flag if:
                    //  1) this is the last in a burst of messages
                    //  2) immediate ack has not been sent in the last `IMMEDIATE_ACK_INTERVAL`
                    //     packets
                    let last_in_burst = num_pkts > 1 && i == num_pkts - 1;
                    let immediate_ack_threshold =
                        pkt_num.saturating_sub(self.last_immediate_ack) > IMMEDIATE_ACK_INTERVAL;

                    if last_in_burst || immediate_ack_threshold {
                        self.last_immediate_ack = pkt_num;

                        DataMessageBuilder::default().with_immediate_ack()
                    } else {
                        DataMessageBuilder::default()
                    }
                    .with_dst_id(self.dst_id)
                    .with_key_context(self.intro_key, &self.send_key_ctx)
                    .with_message(pkt_num, segment)
                    .with_ack(highest_seen, num_acks, ranges.as_deref())
                    .build::<R>()
                })
                .collect(),
        )
    }

    /// Drain expired packets.
    ///
    /// Packets which have not been acknowledged within `times_sent * rto` are selected (respecting
    /// window size), new packet numbers are generated and new `Data` messages are built and
    /// returned.
    pub fn drain_expired(&mut self) -> Result<Option<Vec<BytesMut>>, ()> {
        let expired = self
            .segments
            .iter()
            .filter_map(|(pkt_num, segment)| {
                (segment.sent.elapsed() > (*self.rto * segment.num_sent as u32)).then_some(*pkt_num)
            })
            .collect::<Vec<_>>();

        if expired.is_empty() {
            return Ok(None);
        }

        // reassign packet number for each segment and reinsert it into `self.segments`
        let pkts_to_resend = expired
            .into_iter()
            .map(|old_pkt_num| {
                // the segment must exist since it was just found in `self.segments`
                let Segment {
                    num_sent,
                    segment,
                    sent,
                } = self.segments.remove(&old_pkt_num).expect("to exist");

                if num_sent + 1 > RESEND_TERMINATION_THRESHOLD {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        pkt_num = ?old_pkt_num,
                        "packet has been sent over {} times, terminating session",
                        RESEND_TERMINATION_THRESHOLD,
                    );
                    return Err(());
                }

                let pkt_num = self.next_pkt_num();

                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?old_pkt_num,
                    new_pkt_num = ?pkt_num,
                    "resend packet",
                );

                self.segments.insert(
                    pkt_num,
                    Segment {
                        num_sent: num_sent + 1,
                        segment,
                        sent,
                    },
                );

                Ok(pkt_num)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // send only as many packets as the current window can take
        let pkts_to_resend = pkts_to_resend
            .into_iter()
            .take(self.window_size.saturating_sub(self.segments.len()))
            .collect::<Vec<_>>();

        if pkts_to_resend.is_empty() {
            tracing::trace!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                "one or more packets need to be resent but no window",
            );
            return Ok(None);
        }

        // halve window size because of packet loss
        {
            self.window_size /= 2;

            if self.window_size < MIN_WINDOW_SIZE {
                self.window_size = MIN_WINDOW_SIZE;
            }
        }

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            num_pkts = ?pkts_to_resend.len(),
            pkts = ?pkts_to_resend,
            window = ?self.window_size,
            "resend packets",
        );

        self.metrics.counter(RETRANSMISSION_COUNT).increment(pkts_to_resend.len());

        // update last immediate ack, used to calculate how often it should be sent
        //
        // packet number must exist since it was checked above
        self.last_immediate_ack = *pkts_to_resend.last().expect("to exist");

        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack_manager.ack_info();

        Ok(Some(
            pkts_to_resend
                .into_iter()
                .map(|pkt_num| {
                    // segment must exist since it was just inserted into `segments`
                    let segment = (&self.segments.get(&pkt_num).expect("to exist").segment).into();

                    DataMessageBuilder::default()
                        .with_dst_id(self.dst_id)
                        .with_key_context(self.intro_key, &self.send_key_ctx)
                        .with_message(pkt_num, segment)
                        .with_immediate_ack()
                        .with_ack(highest_seen, num_acks, ranges.as_deref())
                        .build::<R>()
                })
                .collect(),
        ))
    }

    // Build explicit ACK.
    pub fn build_explicit_ack(&mut self) -> BytesMut {
        let AckInfo {
            highest_seen,
            num_acks,
            ranges,
        } = self.remote_ack_manager.ack_info();

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            ?highest_seen,
            ?num_acks,
            ?ranges,
            "send explicit ack",
        );

        DataMessageBuilder::default()
            .with_dst_id(self.dst_id)
            .with_key_context(self.intro_key, &self.send_key_ctx)
            .with_pkt_num(self.next_pkt_num())
            .with_ack(highest_seen, num_acks, ranges.as_deref())
            .build::<R>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime::mock::MockRuntime,
        transport::ssu2::message::{HeaderKind, HeaderReader},
    };

    #[tokio::test]
    async fn ack_one_packet() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![1, 2, 3],
            ..Default::default()
        });
        assert_eq!(mgr.pending.len(), 1);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 1);

        mgr.register_ack(1u32, 0u8, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn ack_multiple_packets_last_packet_missing() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 3 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 4);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(4u32, 2u8, &[]);

        assert_eq!(mgr.segments.len(), 1);
        assert!(mgr.segments.contains_key(&1));
    }

    #[tokio::test]
    async fn ack_multiple_packets_first_packet_missing() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 3 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 4);
        assert_eq!(mgr.drain().unwrap().len(), 4);

        mgr.register_ack(3u32, 2u8, &[]);

        assert_eq!(mgr.segments.len(), 1);
        assert!(mgr.segments.contains_key(&4));
    }

    #[tokio::test]
    async fn ack_multiple_packets_middle_packets_nacked() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 3 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 4);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(4u32, 0u8, &[(2, 1)]);

        assert_eq!(mgr.segments.len(), 2);
        assert!(mgr.segments.contains_key(&3));
        assert!(mgr.segments.contains_key(&2));
    }

    #[tokio::test]
    async fn multiple_ranges() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 10 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 11);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 11);
        assert_eq!(mgr.segments.len(), 11);

        mgr.register_ack(11u32, 2u8, &[(3, 2), (1, 2)]);

        assert_eq!(mgr.segments.len(), 4);
        assert!((6..=8).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn alternating() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(1, 1), (1, 1), (1, 1), (1, 1), (1, 0)]);

        assert_eq!(mgr.segments.len(), 5);
        assert!((1..=9).all(|i| if i % 2 != 0 {
            mgr.segments.contains_key(&i)
        } else {
            !mgr.segments.contains_key(&i)
        }));
    }

    #[tokio::test]
    async fn no_ranges() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
    }

    #[tokio::test]
    async fn highest_pkts_not_received() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(4u32, 0u8, &[(1, 2)]);

        assert_eq!(mgr.segments.len(), 7);
        assert!((5..=10).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn invalid_nack_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(2, 0), (2, 0), (2, 0), (2, 0), (1, 0)]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn invalid_ack_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(0, 2), (0, 2), (0, 2), (0, 2), (0, 1)]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn num_acks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 128u8, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn nacks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(128u8, 0)]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
    }

    #[tokio::test]
    async fn acks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(0, 128u8), (128u8, 0u8)]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn highest_seen_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(1337u32, 10u8, &[]);

        assert_eq!(mgr.segments.len(), 10);
    }

    #[tokio::test]
    async fn num_ack_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(15u32, 255, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn nothing_to_resend() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);
        assert!(mgr.drain_expired().unwrap().is_none());
    }

    #[tokio::test]
    async fn packets_resent() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);
        assert!(mgr.drain_expired().unwrap().is_none());

        tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;

        // verify that all of the packets are sent the second time
        let pkt_nums = mgr
            .drain_expired()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();
        assert!(pkt_nums
            .into_iter()
            .all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 2));
    }

    #[tokio::test]
    async fn some_packets_resent() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 8],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 8);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 8);
        assert_eq!(mgr.segments.len(), 8);
        assert!(mgr.drain_expired().unwrap().is_none());

        tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;

        // verify that all of the packets are sent the second time
        let pkt_nums = mgr
            .drain_expired()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(pkt_nums.len(), 8);
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 2));

        // ack some of the packets and wait for another timeout
        mgr.register_ack(20, 3, &[(2, 2), (2, 0)]);
        tokio::time::sleep(2 * INITIAL_RTO + Duration::from_millis(10)).await;

        let pkt_nums = mgr
            .drain_expired()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(pkt_nums.len(), 6);
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 3));

        mgr.register_ack(24, 3, &[]);
        tokio::time::sleep(2 * INITIAL_RTO + Duration::from_millis(10)).await;

        let pkt_nums = mgr
            .drain_expired()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 4));

        mgr.register_ack(26, 4, &[]);
        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn window_size_increases() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 9 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 10);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 10);
        assert_eq!(mgr.segments.len(), 10);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE);

        mgr.register_ack(10, 3, &[(5, 1)]);

        assert_eq!(mgr.segments.len(), 5);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE + 5);

        mgr.register_ack(6, 4, &[]);

        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE + 10);
    }

    #[tokio::test]
    async fn window_size_decreases() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 15 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE);
        assert!(mgr.drain_expired().unwrap().is_none());

        mgr.register_ack(8, 7, &[]);
        assert_eq!(mgr.segments.len(), 8);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE + 8);

        // packet loss has occurred
        tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;

        // verify that all of the packets are sent the second time
        let pkt_nums = mgr
            .drain_expired()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 2));
        assert_eq!(pkt_nums.len(), 8);

        // window size has been halved
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE);

        // more packet loss, verify that window size is clamped to minimum
        tokio::time::sleep(2 * INITIAL_RTO + Duration::from_millis(10)).await;

        let pkt_nums = mgr
            .drain_expired()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 3));
        assert_eq!(pkt_nums.len(), 8);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE);
    }

    #[tokio::test]
    async fn excess_packets_stay_in_pending() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 31 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 2 * MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.pending.len(), MIN_WINDOW_SIZE);
        assert!(mgr.drain_expired().unwrap().is_none());
        assert!(!mgr.has_capacity());

        mgr.register_ack(16, 15, &[]);
        assert!(mgr.segments.is_empty());
        assert_eq!(mgr.window_size, 2 * MIN_WINDOW_SIZE);
        assert!(mgr.has_capacity());

        // get pending packets after acking previous packets
        let pkt_nums = mgr
            .drain()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();

        assert_eq!(pkt_nums.len(), 16);
        assert_eq!(mgr.segments.len(), 16);
        assert!(mgr.pending.is_empty());
        assert!(mgr.has_capacity()); // window size has grown
    }

    #[tokio::test]
    async fn pending_packets_partially_sent() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 39 + 512],
            ..Default::default()
        });

        assert_eq!(mgr.pending.len(), 40);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.pending.len(), 40 - MIN_WINDOW_SIZE);
        assert!(mgr.drain_expired().unwrap().is_none());
        assert!(!mgr.has_capacity());

        mgr.register_ack(16, 5, &[]);
        assert!(!mgr.segments.is_empty());
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE + 6);

        // no capacity since there are still pending packets
        assert!(!mgr.pending.is_empty());
        assert!(!mgr.has_capacity());

        // get pending packets after acking previous packets
        let pkt_nums = mgr
            .drain()
            .unwrap()
            .into_iter()
            .map(|mut pkt| {
                let mut reader = HeaderReader::new(mgr.intro_key, &mut pkt).unwrap();
                let _dst_id = reader.dst_id();

                match reader.parse(mgr.send_key_ctx.k_header_2).unwrap() {
                    HeaderKind::Data { pkt_num, .. } => pkt_num,
                    _ => panic!("invalid pkt"),
                }
            })
            .collect::<Vec<_>>();

        assert_eq!(pkt_nums.len(), 12);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE + 6);
        assert!(!mgr.pending.is_empty());
        assert!(!mgr.has_capacity());
    }

    #[tokio::test]
    async fn packet_resent_too_many_times() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );
        mgr.schedule(Message {
            payload: vec![0u8; 1200 * 5],
            ..Default::default()
        });
        assert_eq!(mgr.pending.len(), 5);
        assert_eq!(mgr.segments.len(), 0);
        assert_eq!(mgr.drain().unwrap().len(), 5);
        assert_eq!(mgr.segments.len(), 5);

        let future = async move {
            while let Ok(_) = mgr.drain_expired() {
                tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;
            }
        };

        match tokio::time::timeout(Duration::from_secs(15), future).await {
            Err(_) => panic!("timeout"),
            Ok(_) => {}
        }
    }

    #[tokio::test]
    async fn peer_test_with_router_info() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            1337u64,
            RouterId::random(),
            [0xaa; 32],
            KeyContext {
                k_data: [0xbb; 32],
                k_header_2: [0xcc; 32],
            },
            Arc::new(AtomicU32::new(1u32)),
            MockRuntime::register_metrics(Vec::new(), None),
        );

        let block = PeerTestBlock::AliceRequest {
            message: vec![0xaa; 20],
            signature: vec![0xbb; 64],
        };
        let max_size = 1200 - SSU2_OVERHEAD - RI_BLOCK_OVERHEAD - block.serialized_len();

        // maximum size for router info is 1200 - ssu2 overhead - peer test block len
        mgr.schedule((block, vec![0xaa; max_size]));

        // verify that peer test block and router info are sent in a single packet
        assert_eq!(mgr.pending.len(), 1);
        assert_eq!(mgr.drain().unwrap().len(), 1);

        let block = PeerTestBlock::AliceRequest {
            message: vec![0xaa; 20],
            signature: vec![0xbb; 64],
        };
        let max_size = 1200 - SSU2_OVERHEAD - RI_BLOCK_OVERHEAD - block.serialized_len();

        // router info is over the limit
        mgr.schedule((block, vec![0xaa; max_size + 1]));

        // verify that peer test block and router info are sent in a single packet
        assert_eq!(mgr.pending.len(), 2);
        assert_eq!(mgr.drain().unwrap().len(), 2);
    }
}
