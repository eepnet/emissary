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

use crate::runtime::Runtime;

use futures::FutureExt;

use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use core::{
    cmp::{min, Ordering, Reverse},
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::atomic::AtomicU32,
    task::{Context, Poll},
    time::Duration,
};

/// Packet type.
#[derive(Debug)]
enum Packet {
    /// Packet is missing.
    Missing(u32),

    /// Packet has been received but is unACKed.
    Received(u32),
}

impl Deref for Packet {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Missing(value) => value,
            Self::Received(value) => value,
        }
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deref().cmp(other.deref())
    }
}

impl Eq for Packet {}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.deref().eq(other.deref())
    }
}

/// ACK info.
#[derive(Debug, PartialEq, Eq)]
pub struct AckInfo {
    /// Highest seen packet number.
    pub highest_seen: u32,

    /// Number of ACKs below `ack_through`.
    pub num_acks: u8,

    /// NACK/ACK ranges.
    ///
    /// First element of the tuple is NACKs, second is ACKs.
    ///
    /// `None` if there were no ranges.
    pub ranges: Option<Vec<(u8, u8)>>,
}

/// Remote ACK manager.
pub struct RemoteAckManager<R: Runtime> {
    /// ACK timer.
    ///
    /// `None` if there are no pending ACKs.
    ack_timer: Option<R::Timer>,

    /// Highest seen packet number.
    highest_seen: u32,

    /// Packets, either received or missing.
    packets: BTreeSet<Reverse<Packet>>,

    /// Next packet number.
    pkt_num: Arc<AtomicU32>,
}

impl<R: Runtime> RemoteAckManager<R> {
    /// Create new [`RemoteAckManager`].
    pub fn new(pkt_num: Arc<AtomicU32>) -> Self {
        Self {
            ack_timer: None,
            highest_seen: 0u32,
            packets: BTreeSet::new(),
            pkt_num,
        }
    }

    /// Register ACK-eliciting packet.
    pub fn register_pkt(&mut self, pkt_num: u32, immediate_ack: bool) {
        // next expected packet number
        if self.highest_seen + 1 == pkt_num {
            self.packets.insert(Reverse(Packet::Received(self.highest_seen)));
            self.packets.insert(Reverse(Packet::Received(pkt_num)));
            self.highest_seen = pkt_num;

            // TODO: move this to `Ssu2Session`
            if immediate_ack && self.ack_timer.is_none() {
                self.ack_timer = Some(R::timer(Duration::from_millis(3))); // TODO: correct timeout
            }

            return;
        }

        // packet with a number higher than expected has been received, meaning one or more packets
        // were dropped between the last highest packet and current highest packet
        if self.highest_seen + 1 < pkt_num {
            (self.highest_seen + 1..pkt_num).for_each(|pkt| {
                if !self.packets.contains(&Reverse(Packet::Received(pkt))) {
                    self.packets.insert(Reverse(Packet::Missing(pkt)));
                }
            });

            self.packets.insert(Reverse(Packet::Received(self.highest_seen)));
            self.highest_seen = pkt_num;
        }

        // packet with a number lower than the currently highest seen has been received
        if self.highest_seen + 1 > pkt_num {
            self.packets.remove(&Reverse(Packet::Missing(pkt_num)));
            self.packets.insert(Reverse(Packet::Received(pkt_num)));
        }

        // TODO: move this to `Ssu2Session`
        if immediate_ack && self.ack_timer.is_none() {
            self.ack_timer = Some(R::timer(Duration::from_millis(3))); // TODO: correct timeout
        }
    }

    /// Register non-ACK-eliciting packet.
    pub fn register_non_ack_eliciting_pkt(&mut self, pkt_num: u32, immediate_ack: bool) {
        self.register_pkt(pkt_num, immediate_ack);
    }

    /// Register ACK.
    ///
    /// - `ack_through` marks the highest packet that was ACKed.
    /// - `num_acks` marks the number of ACKs below `ack_through`
    /// - `range` contains a `(# of NACK, # of ACK)` tuples
    ///
    /// [`RemoteAckManager`] checks if any of the received ACKs are related to sent ACK packets,
    /// allowing it to stop tracking those packets.
    pub fn register_ack(&mut self, ack_through: u32, num_acks: u8, ranges: &[(u8, u8)]) {
        // TODO: print something if this acked our ack
    }

    /// Get ACK information added to an outbound message.
    //
    // TODO: take pkt number as parameter
    // TODO: when ack block is received
    pub fn ack_info(&mut self) -> AckInfo {
        let num_acks = min(
            self.packets
                .iter()
                .skip(1)
                .enumerate()
                .take_while(|(i, pkt)| match pkt.0 {
                    Packet::Missing(_) => false,
                    Packet::Received(value) => self.highest_seen == value + (*i as u32) + 1,
                })
                .count(),
            255,
        ) as u8;

        // check if there are any missing packets and if not, return early
        let mut iter = self.packets.iter();

        if !iter.any(|pkt| core::matches!(pkt.0, Packet::Missing(_))) {
            return AckInfo {
                highest_seen: self.highest_seen,
                num_acks,
                ranges: None,
            };
        }

        // if `packets` contained any missing packets, go through all of them until the end and
        // group them together
        //
        // what happens is that an array like
        //   [missing(6), missing(5), missing(4), received(3), received(2), missing(1), received(0)]
        //
        // gets grouped into [3, 2, 1, 1] which is then further chuncked into [(3, 2), (1, 1)]
        //
        // the last element must exist when using `expect()` since `ranges` is initialized with one
        // element before iteration starts
        //
        // note that `iter` points to the first missing packet, ensured by the check above
        let (mut ranges, _) = iter.fold((vec![1], true), |(mut ranges, missing), value| {
            match (missing, &value.0) {
                (true, Packet::Missing(_)) => {
                    *ranges.last_mut().expect("to exist") += 1;
                    (ranges, true)
                }
                (true, Packet::Received(_)) => {
                    ranges.push(1);
                    (ranges, false)
                }
                (false, Packet::Missing(_)) => {
                    ranges.push(1);
                    (ranges, true)
                }
                (false, Packet::Received(_)) => {
                    *ranges.last_mut().expect("to exist") += 1;
                    (ranges, false)
                }
            }
        });

        if ranges.len() % 2 != 0 {
            ranges.push(0);
        }

        let ranges = ranges
            .chunks(2)
            .map(|chunk| (min(chunk[0], 255) as u8, min(chunk[1], 255) as u8))
            .collect::<Vec<(_, _)>>();

        AckInfo {
            highest_seen: self.highest_seen,
            num_acks,
            ranges: Some(ranges),
        }
    }
}

impl<R: Runtime> Future for RemoteAckManager<R> {
    type Output = AckInfo;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(timer) = self.ack_timer.as_mut() else {
            return Poll::Pending;
        };

        if !timer.poll_unpin(cx).is_ready() {
            return Poll::Pending;
        }

        self.ack_timer = None;
        Poll::Ready(self.ack_info())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn ack_one_packet() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());
        manager.register_pkt(1, true);

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 1,
                num_acks: 1,
                ranges: None
            }
        );
    }

    #[tokio::test]
    async fn ack_multiple_packets() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        for i in 1..=3 {
            manager.register_pkt(i, true);
            assert_eq!(manager.highest_seen, i);
        }

        // 3 is highest seen and 2 packets below 3 are also acked
        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 3,
                num_acks: 3,
                ranges: None
            }
        );
    }

    #[tokio::test]
    async fn too_many_unacked_packets() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        for i in 1..=300 {
            manager.register_pkt(i, true);
            assert_eq!(manager.highest_seen, i);
        }

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 300,
                num_acks: 255,
                ranges: None
            }
        );
    }

    #[tokio::test]
    async fn max_acks() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        for i in 1..=256 {
            manager.register_pkt(i, true);
            assert_eq!(manager.highest_seen, i);
        }

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 256,
                num_acks: 255,
                ranges: None
            }
        );
    }

    #[tokio::test]
    async fn next_pkt_missing() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        manager.register_pkt(300, true);
        assert_eq!(manager.highest_seen, 300);
        assert_eq!(
            manager
                .packets
                .iter()
                .filter(|packet| core::matches!(packet.0, Packet::Received(_)))
                .count(),
            2,
        );
        assert_eq!(
            manager
                .packets
                .iter()
                .filter(|packet| core::matches!(packet.0, Packet::Missing(_)))
                .count(),
            299
        );

        // pkt 299 missing, no acks below 300
        for i in 1..=298 {
            manager.register_pkt(i, true);
            assert_eq!(manager.highest_seen, 300);
            assert_eq!(
                manager
                    .packets
                    .iter()
                    .filter(|packet| core::matches!(packet.0, Packet::Missing(_)))
                    .count(),
                299 - i as usize
            );
            assert_eq!(
                manager
                    .packets
                    .iter()
                    .filter(|packet| core::matches!(packet.0, Packet::Received(_)))
                    .count(),
                i as usize + 2,
            );
        }

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 300,
                num_acks: 0,
                ranges: Some(vec![(1, 255)])
            }
        );
    }

    #[tokio::test]
    async fn packet_dropped() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        manager.register_pkt(10, true);
        manager.register_pkt(9, true);
        manager.register_pkt(8, true);
        manager.register_pkt(6, true);
        manager.register_pkt(5, true);
        manager.register_pkt(2, true);
        manager.register_pkt(1, true);

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 10,
                num_acks: 2,
                ranges: Some(vec![(1, 2), (2, 3)])
            }
        );
    }

    #[tokio::test]
    async fn packet_dropped_2() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        manager.register_pkt(10, true);
        manager.register_pkt(8, true);
        manager.register_pkt(6, true);
        manager.register_pkt(4, true);
        manager.register_pkt(2, true);

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 10,
                num_acks: 0,
                ranges: Some(vec![(1, 1), (1, 1), (1, 1), (1, 1), (1, 1)])
            }
        );
    }

    #[tokio::test]
    async fn packet_dropped_3() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        for i in 2..=10 {
            manager.register_pkt(i, true);
        }

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 10,
                num_acks: 8,
                ranges: Some(vec![(1, 1)])
            }
        );
    }

    #[tokio::test]
    async fn packet_dropped_4() {
        let mut manager = RemoteAckManager::<MockRuntime>::new(Default::default());

        manager.register_pkt(10, true);

        assert_eq!(
            manager.ack_info(),
            AckInfo {
                highest_seen: 10,
                num_acks: 0,
                ranges: Some(vec![(9, 1)])
            }
        );
    }
}
