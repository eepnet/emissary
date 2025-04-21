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

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::{
    cmp::{min, Ordering, Reverse},
    ops::Deref,
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

/// Remote ACK manager.
pub struct RemoteAckManager {
    /// Highest seen packet number.
    highest_seen: u32,

    /// Packets, either received or missing.
    packets: BTreeSet<Reverse<Packet>>,
}

impl RemoteAckManager {
    /// Create new [`RemoteAckManager`].
    pub fn new() -> Self {
        Self {
            highest_seen: 0u32,
            packets: BTreeSet::new(),
        }
    }

    /// Register ACK-eliciting packet.
    //
    // TODO: return true/false if immediate ack should be sent?
    pub fn register_pkt(&mut self, pkt_num: u32) {
        // next expected packet number
        if self.highest_seen + 1 == pkt_num {
            self.packets.insert(Reverse(Packet::Received(self.highest_seen)));
            self.packets.insert(Reverse(Packet::Received(pkt_num)));
            self.highest_seen = pkt_num;
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
    }

    /// Register non-ACK-eliciting packet.
    pub fn register_non_ack_eliciting_pkt(&mut self, pkt_num: u32) {
        self.register_pkt(pkt_num);
    }

    /// Get ACK information added to an outbound message.
    pub fn ack_info(&mut self) -> (u32, u8, Option<Vec<(u8, u8)>>) {
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
            return (self.highest_seen, num_acks, None);
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

        (self.highest_seen, num_acks, Some(ranges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_one_packet() {
        let mut manager = RemoteAckManager::new();
        manager.register_pkt(1);

        assert_eq!(manager.ack_info(), (1, 1, None));
    }

    #[test]
    fn ack_multiple_packets() {
        let mut manager = RemoteAckManager::new();

        for i in 1..=3 {
            manager.register_pkt(i);
            assert_eq!(manager.highest_seen, i);
        }

        // 3 is highest seen and 2 packets below 3 are also acked
        assert_eq!(manager.ack_info(), (3, 3, None));
    }

    #[test]
    fn too_many_unacked_packets() {
        let mut manager = RemoteAckManager::new();

        for i in 1..=300 {
            manager.register_pkt(i);
            assert_eq!(manager.highest_seen, i);
        }

        assert_eq!(manager.ack_info(), (300, 255, None));
    }

    #[test]
    fn max_acks() {
        let mut manager = RemoteAckManager::new();

        for i in 1..=256 {
            manager.register_pkt(i);
            assert_eq!(manager.highest_seen, i);
        }

        assert_eq!(manager.ack_info(), (256, 255, None));
    }

    #[test]
    fn next_pkt_missing() {
        let mut manager = RemoteAckManager::new();

        manager.register_pkt(300);
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
            manager.register_pkt(i);
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

        assert_eq!(manager.ack_info(), (300, 0, Some(vec![(1, 255)])));
    }

    #[test]
    fn packet_dropped() {
        let mut manager = RemoteAckManager::new();

        manager.register_pkt(10);
        manager.register_pkt(9);
        manager.register_pkt(8);
        manager.register_pkt(6);
        manager.register_pkt(5);
        manager.register_pkt(2);
        manager.register_pkt(1);

        assert_eq!(manager.ack_info(), (10, 2, Some(vec![(1, 2), (2, 3)])));
    }

    #[test]
    fn packet_dropped_2() {
        let mut manager = RemoteAckManager::new();

        manager.register_pkt(10);
        manager.register_pkt(8);
        manager.register_pkt(6);
        manager.register_pkt(4);
        manager.register_pkt(2);

        assert_eq!(
            manager.ack_info(),
            (10, 0, Some(vec![(1, 1), (1, 1), (1, 1), (1, 1), (1, 1)]))
        );
    }

    #[test]
    fn packet_dropped_3() {
        let mut manager = RemoteAckManager::new();

        for i in 2..=10 {
            manager.register_pkt(i);
        }

        assert_eq!(manager.ack_info(), (10, 8, Some(vec![(1, 1)])));
    }

    #[test]
    fn packet_dropped_4() {
        let mut manager = RemoteAckManager::new();

        manager.register_pkt(10);

        assert_eq!(manager.ack_info(), (10, 0, Some(vec![(9, 1)])));
    }
}
