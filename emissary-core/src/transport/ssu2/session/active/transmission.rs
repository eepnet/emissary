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
    runtime::Runtime,
    transport::ssu2::message::data::MessageKind,
};

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, Ordering};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::active::transmission";

/// SSU2 overheader
///
/// Short header + block type + Poly1305 authentication tag.
const SSU2_OVERHEAD: usize = 16usize + 1usize + 16usize;

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
    /// When was the packet sent.
    sent: R::Instant,

    /// Segment kind.
    ///
    /// Either an unfragmented I2NP message or a fragment of an I2NP message.
    segment: SegmentKind,
}

/// Transmission manager.
pub struct TransmissionManager<R: Runtime> {
    /// In-flight segments.
    segments: BTreeMap<u32, Segment<R>>,

    /// Next packet number.
    pkt_num: Arc<AtomicU32>,
}

impl<R: Runtime> TransmissionManager<R> {
    /// Create new [`TransmissionManager`].
    pub fn new(pkt_num: Arc<AtomicU32>) -> Self {
        Self {
            segments: BTreeMap::new(),
            pkt_num,
        }
    }

    /// Get next packet number.
    pub fn next_pkt_num(&mut self) -> u32 {
        self.pkt_num.fetch_add(1u32, Ordering::Relaxed)
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
    pub fn segment(&mut self, message: Message) -> impl Iterator<Item = (u32, MessageKind<'_>)> {
        if message.serialized_len_short() + SSU2_OVERHEAD <= 1200 {
            let pkt_num = self.next_pkt_num();

            self.segments.insert(
                pkt_num,
                Segment {
                    sent: R::now(),
                    segment: SegmentKind::UnFragmented {
                        message: message.serialize_short(),
                    },
                },
            );

            // TODO: start timer for resends

            // segment must exist since it was just inserted into `segments`
            return vec![(
                pkt_num,
                (&self.segments.get(&pkt_num).expect("to exist").segment).into(),
            )]
            .into_iter();
        }

        let fragments = message.payload.chunks(1200).collect::<Vec<_>>();
        let num_fragments = fragments.len();

        let fragments = fragments
            .into_iter()
            .enumerate()
            .map(|(fragment_num, fragment)| {
                let pkt_num = self.next_pkt_num();

                self.segments.insert(
                    pkt_num,
                    Segment {
                        sent: R::now(),
                        segment: match fragment_num {
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
                        },
                    },
                );

                pkt_num
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

        // TODO: start timer for resends

        packets.into_iter()
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
    pub fn register_ack(&mut self, ack_through: u32, mut num_acks: u8, ranges: &[(u8, u8)]) {
        (0..=num_acks).for_each(|i| {
            // TODO: rtt
            self.segments.remove(&(ack_through.saturating_sub(i as u32)));
        });

        // first packet in the ranges start at `ack_through - num_acks` and the first acked packet
        // that can be removed from `segments` starts at `ack_through - num_acks - ranges[0].0`
        let mut next_pkt = ack_through.saturating_sub(num_acks as u32);

        for (nack, ack) in ranges {
            next_pkt = next_pkt.saturating_sub(*nack as u32);

            for i in 1..=*ack {
                next_pkt = next_pkt.saturating_sub(1);

                // TODO: rtt
                self.segments.remove(&next_pkt);
            }
        }

        // TODO: if `segments` is empty, cancel timer
        // TODO: update window?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn ack_one_packet() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![1, 2, 3],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 1);
        assert_eq!(mgr.segments.len(), 1);

        mgr.register_ack(1u32, 0u8, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn ack_multiple_packets_last_packet_missing() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 3 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(4u32, 2u8, &[]);

        assert_eq!(mgr.segments.len(), 1);
        assert!(mgr.segments.contains_key(&1));
    }

    #[tokio::test]
    async fn ack_multiple_packets_first_packet_missing() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 3 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(3u32, 2u8, &[]);

        assert_eq!(mgr.segments.len(), 1);
        assert!(mgr.segments.contains_key(&4));
    }

    #[tokio::test]
    async fn ack_multiple_packets_middle_packets_nacked() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 3 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 4);
        assert_eq!(mgr.segments.len(), 4);

        mgr.register_ack(4u32, 0u8, &[(2, 1)]);

        assert_eq!(mgr.segments.len(), 2);
        assert!(mgr.segments.contains_key(&3));
        assert!(mgr.segments.contains_key(&2));
    }

    #[tokio::test]
    async fn multiple_ranges() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 10 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 11);
        assert_eq!(mgr.segments.len(), 11);

        mgr.register_ack(11u32, 2u8, &[(3, 2), (1, 2)]);

        assert_eq!(mgr.segments.len(), 4);
        assert!((6..=8).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn alternating() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

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
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
    }

    #[tokio::test]
    async fn highest_pkts_not_received() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(4u32, 0u8, &[(1, 2)]);

        assert_eq!(mgr.segments.len(), 7);
        assert!((5..=10).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn invalid_nack_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(2, 0), (2, 0), (2, 0), (2, 0), (1, 0)]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
        assert!(mgr.segments.contains_key(&3));
    }

    #[tokio::test]
    async fn invalid_ack_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(0, 2), (0, 2), (0, 2), (0, 2), (0, 1)]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn num_acks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 128u8, &[]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn nacks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(128u8, 0)]);

        assert_eq!(mgr.segments.len(), 9);
        assert!((1..=9).all(|i| mgr.segments.contains_key(&i)));
    }

    #[tokio::test]
    async fn acks_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(10u32, 0u8, &[(0, 128u8), (128u8, 0u8)]);

        assert!(mgr.segments.is_empty());
    }

    #[tokio::test]
    async fn highest_seen_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(1337u32, 10u8, &[]);

        assert_eq!(mgr.segments.len(), 10);
    }

    #[tokio::test]
    async fn num_ack_out_of_range() {
        let mut mgr = TransmissionManager::<MockRuntime>::new(Arc::new(AtomicU32::new(1u32)));
        let pkts = mgr
            .segment(Message {
                payload: vec![0u8; 1200 * 9 + 512],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        assert_eq!(pkts.len(), 10);
        assert_eq!(mgr.segments.len(), 10);

        mgr.register_ack(15u32, 255, &[]);

        assert!(mgr.segments.is_empty());
    }
}
