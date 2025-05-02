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
    runtime::{Instant, Runtime},
    transport::ssu2::message::data::MessageKind,
};

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    cmp::{max, min},
    ops::Deref,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::active::transmission";

/// SSU2 overheader
///
/// Short header + block type + Poly1305 authentication tag.
const SSU2_OVERHEAD: usize = 16usize + 1usize + 16usize;

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
            Self::Sampled { rto, .. } => &rto,
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
}

impl<'a> From<&'a SegmentKind> for MessageKind<'a> {
    fn from(value: &'a SegmentKind) -> Self {
        match value {
            SegmentKind::UnFragmented { message } => MessageKind::UnFragmented { message },
            SegmentKind::FirstFragment {
                fragment,
                expiration,
                message_type,
                message_id,
            } => MessageKind::FirstFragment {
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
            } => MessageKind::FollowOnFragment {
                fragment,
                fragment_num: *fragment_num,
                last: *last,
                message_id: *message_id,
            },
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
    /// Next packet number.
    pkt_num: Arc<AtomicU32>,

    /// ID of the remote router.
    router_id: RouterId,

    /// RTO.
    rto: RetransmissionTimeout,

    /// In-flight segments.
    segments: BTreeMap<u32, Segment<R>>,

    /// Pending segments.
    pending: VecDeque<SegmentKind>,

    /// Window size.
    window_size: usize,
}

impl<R: Runtime> TransmissionManager<R> {
    /// Create new [`TransmissionManager`].
    pub fn new(router_id: RouterId, pkt_num: Arc<AtomicU32>) -> Self {
        Self {
            pkt_num,
            router_id,
            pending: VecDeque::new(),
            rto: RetransmissionTimeout::Unsampled,
            segments: BTreeMap::new(),
            window_size: MIN_WINDOW_SIZE,
        }
    }

    /// Get next packet number.
    pub fn next_pkt_num(&mut self) -> u32 {
        self.pkt_num.fetch_add(1u32, Ordering::Relaxed)
    }

    /// Does [`TransmissionManager`] have capacity to send more packets?
    ///
    /// Compares the current window size to the number of in-flight packets.
    pub fn has_capacity(&self) -> bool {
        self.segments.len() < self.window_size
    }

    /// Get reference to measured Round-trip time (RTT).
    pub fn round_trip_time(&self) -> Duration {
        match &self.rto {
            RetransmissionTimeout::Unsampled => INITIAL_RTO,
            RetransmissionTimeout::Sampled { rtt, .. } => *rtt,
        }
    }

    /// Split `message` into segments.
    ///
    /// The created segments are stored into [`TransmissionManager`] which keeps track of which of
    /// the segments have been ACKed and which haven't.
    ///
    /// Returns an iterator of (packet number, `MessageKind`) tuples which must be made into `Data`
    /// packets and sent to remote router.
    ///
    /// If `message` fits inside an MTU, the iterator yields one `MessageKind::Unfragmented` and if
    /// `message` doesn't find inside an MTU, the iterator yields one `MessageKind::FirstFragment`
    /// and one or more `MessageKind::FollowOnFragment`s.
    pub fn segment(&mut self, message: Message) -> Option<Vec<(u32, MessageKind<'_>)>> {
        if message.serialized_len_short() + SSU2_OVERHEAD <= 1200 {
            // no window size left to send more packets
            if !self.has_capacity() {
                self.pending.push_back(SegmentKind::UnFragmented {
                    message: message.serialize_short(),
                });

                return None;
            }
            let pkt_num = self.next_pkt_num();

            self.segments.insert(
                pkt_num,
                Segment {
                    num_sent: 1usize,
                    sent: R::now(),
                    segment: SegmentKind::UnFragmented {
                        message: message.serialize_short(),
                    },
                },
            );

            // segment must exist since it was just inserted into `segments`
            return Some(vec![(
                pkt_num,
                (&self.segments.get(&pkt_num).expect("to exist").segment).into(),
            )]);
        }

        let fragments = message.payload.chunks(1200).collect::<Vec<_>>();
        let num_fragments = fragments.len();

        let fragments = fragments
            .into_iter()
            .enumerate()
            .filter_map(|(fragment_num, fragment)| {
                let pkt_num = self.next_pkt_num();
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

                if !self.has_capacity() {
                    self.pending.push_back(segment);
                    return None;
                }

                self.segments.insert(
                    pkt_num,
                    Segment {
                        num_sent: 1usize,
                        sent: R::now(),
                        segment,
                    },
                );

                return Some(pkt_num);
            })
            .collect::<Vec<_>>();

        // all segments must exist since they were inserted into `segments` above
        let mut packets = Vec::<(u32, MessageKind<'_>)>::new();

        for pkt_num in fragments {
            packets.push((
                pkt_num,
                (&self.segments.get(&pkt_num).expect("to exist").segment).into(),
            ));
        }

        Some(packets)
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
            ?ack_through,
            ?num_acks,
            ?ranges,
            num_segments = ?self.segments.len(),
            router_id = %self.router_id,
            "handle ack",
        );

        (0..=num_acks).for_each(|i| {
            // TODO: if-let chain
            if let Some(Segment { num_sent, sent, .. }) =
                self.segments.remove(&(ack_through.saturating_sub(i as u32)))
            {
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

    /// Get pending packets, if any.
    pub fn pending_packets(&mut self) -> Option<Vec<(u32, MessageKind<'_>)>> {
        if self.pending.is_empty() {
            return None;
        }

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

        let mut packets = Vec::<(u32, MessageKind<'_>)>::new();

        for pkt_num in pkts_to_send {
            packets.push((
                pkt_num,
                (&self.segments.get(&pkt_num).expect("to exist").segment).into(),
            ));
        }

        Some(packets)
    }

    /// Go through packets and check if any of them need to be resent.
    ///
    /// Returns an iterator of `(packet number, `MessageKind`)` tuples.
    pub fn resend(&mut self) -> Result<Option<Vec<(u32, MessageKind<'_>)>>, ()> {
        // TODO: `take_while()` + reverse order
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
            .map(|pkt_num| {
                // the segment must exist since it was just found in `self.segments`
                let Segment {
                    num_sent,
                    segment,
                    sent,
                } = self.segments.remove(&pkt_num).expect("to exist");

                if num_sent + 1 > RESEND_TERMINATION_THRESHOLD {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?pkt_num,
                        "packet has been resent over {} times, terminating session",
                        RESEND_TERMINATION_THRESHOLD,
                    );
                    return Err(());
                }

                // each packet is assigned a new packet number so the ciphertext of the packet
                // will be different
                let pkt_num = self.next_pkt_num();

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
            window = ?self.window_size,
            "resend packets",
        );

        // all segments must exist since they were inserted into `self.segments` above
        let mut packets = Vec::<(u32, MessageKind<'_>)>::new();

        for pkt_num in pkts_to_resend {
            packets.push((
                pkt_num,
                (&self.segments.get(&pkt_num).expect("to exist").segment).into(),
            ));
        }

        Ok(Some(packets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn ack_one_packet() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![1, 2, 3],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 1);
        assert_eq!(mgr.segments.len(), 1);

        mgr.register_ack(1u32, 0u8, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn ack_multiple_packets_last_packet_missing() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 3 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(4u32, 2u8, &[]);

        assert_eq!(mgr.segments.len(), 1);
        assert!(mgr.segments.contains_key(&1));
    }

    #[tokio::test]
    async fn ack_multiple_packets_first_packet_missing() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 3 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(3u32, 2u8, &[]);

        assert_eq!(mgr.segments.len(), 1);
        assert!(mgr.segments.contains_key(&4));
    }

    #[tokio::test]
    async fn ack_multiple_packets_middle_packets_nacked() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 3 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(4u32, 0u8, &[(2, 1)]);

        assert_eq!(mgr.segments.len(), 2);
        assert!(mgr.segments.contains_key(&3));
        assert!(mgr.segments.contains_key(&2));
    }

    #[tokio::test]
    async fn multiple_ranges() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 10 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 11);
        assert_eq!(mgr.segments.len(), 11);

        mgr.register_ack(11u32, 2u8, &[(3, 2), (1, 2)]);

        assert_eq!(mgr.segments.len(), 4);
        assert!((6..=8).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn alternating() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
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
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
    }

    #[tokio::test]
    async fn highest_pkts_not_received() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(4u32, 0u8, &[(1, 2)]);

        assert_eq!(mgr.segments.len(), 7);
        assert!((5..=10).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn invalid_nack_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(2, 0), (2, 0), (2, 0), (2, 0), (1, 0)]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn invalid_ack_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(0, 2), (0, 2), (0, 2), (0, 2), (0, 1)]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn num_acks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 128u8, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn nacks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(128u8, 0)]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
    }

    #[tokio::test]
    async fn acks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(0, 128u8), (128u8, 0u8)]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn highest_seen_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(1337u32, 10u8, &[]);

        assert_eq!(mgr.segments.len(), 10);
    }

    #[tokio::test]
    async fn num_ack_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(15u32, 255, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn nothing_to_resend() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);
        assert!(mgr.resend().unwrap().is_none());
    }

    #[tokio::test]
    async fn packets_resent() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);
        assert!(mgr.resend().unwrap().is_none());

        tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;

        // verify that all of the packets are sent the second time
        let pkt_nums = mgr
            .resend()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();
        assert!(pkt_nums
            .into_iter()
            .all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 2));
    }

    #[tokio::test]
    async fn some_packets_resent() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);
        assert!(mgr.resend().unwrap().is_none());

        tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;

        // verify that all of the packets are sent the second time
        let pkt_nums = mgr
            .resend()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 2));

        // ack some of the packets and wait for another timeout
        mgr.register_ack(20, 3, &[(2, 2), (2, 0)]);
        tokio::time::sleep(2 * INITIAL_RTO + Duration::from_millis(10)).await;

        let pkt_nums = mgr
            .resend()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();
        assert_eq!(pkt_nums.len(), 4);
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 3));

        mgr.register_ack(24, 3, &[]);
        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn window_size_increases() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), 10);
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
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 15 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE);
        assert!(mgr.pending.is_empty());
        assert!(mgr.resend().unwrap().is_none());

        mgr.register_ack(8, 7, &[]);
        assert_eq!(mgr.segments.len(), 8);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE + 8);

        // packet loss has occurred
        tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;

        // verify that all of the packets are sent the second time
        let pkt_nums = mgr
            .resend()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 2));
        assert_eq!(pkt_nums.len(), 8);

        // window size has been halved
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE);

        // more packet loss, verify that window size is clamped to minimum
        tokio::time::sleep(2 * INITIAL_RTO + Duration::from_millis(10)).await;

        let pkt_nums = mgr
            .resend()
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();
        assert!(pkt_nums.iter().all(|pkt_num| mgr.segments.get(&pkt_num).unwrap().num_sent == 3));
        assert_eq!(pkt_nums.len(), 8);
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE);
    }

    #[tokio::test]
    async fn excess_packets_marked_as_pending() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 31 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.pending.len(), MIN_WINDOW_SIZE);
        assert!(mgr.resend().unwrap().is_none());
        assert!(!mgr.has_capacity());

        mgr.register_ack(16, 15, &[]);
        assert!(mgr.segments.is_empty());
        assert_eq!(mgr.window_size, 2 * MIN_WINDOW_SIZE);
        assert!(mgr.has_capacity());

        // get pending packets after acking previous packets
        let pkt_nums = mgr
            .pending_packets()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();

        assert_eq!(pkt_nums.len(), 16);
        assert_eq!(mgr.segments.len(), 16);
        assert!(mgr.pending.is_empty());
        assert!(mgr.has_capacity()); // window size has grown
    }

    #[tokio::test]
    async fn pending_packets_partially_sent() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 39 + 512],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(pkts.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE);
        assert_eq!(mgr.pending.len(), 40 - MIN_WINDOW_SIZE);
        assert!(mgr.resend().unwrap().is_none());
        assert!(!mgr.has_capacity());

        mgr.register_ack(16, 5, &[]);
        assert!(!mgr.segments.is_empty());
        assert_eq!(mgr.window_size, MIN_WINDOW_SIZE + 6);
        assert!(mgr.has_capacity());

        // get pending packets after acking previous packets
        let pkt_nums = mgr
            .pending_packets()
            .unwrap()
            .into_iter()
            .map(|(pkt_num, _)| pkt_num)
            .collect::<Vec<_>>();

        assert_eq!(pkt_nums.len(), 12);
        assert_eq!(mgr.segments.len(), MIN_WINDOW_SIZE + 6);
        assert!(!mgr.pending.is_empty());
        assert!(!mgr.has_capacity());
    }

    #[tokio::test]
    async fn packet_resent_too_many_times() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(
            RouterId::random(),
            Arc::new(AtomicU32::new(1u32)),
        );
        let _ = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 5],
                ..Default::default()
            })
            .unwrap();

        let future = async move {
            while let Ok(_) = mgr.resend() {
                tokio::time::sleep(INITIAL_RTO + Duration::from_millis(10)).await;
            }
        };

        match tokio::time::timeout(Duration::from_secs(15), future).await {
            Err(_) => panic!("timeout"),
            Ok(_) => {}
        }
    }
}
