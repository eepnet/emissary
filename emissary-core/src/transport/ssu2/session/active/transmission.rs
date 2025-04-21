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
    vec::Vec,
};

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

    /// Packet number.
    pkt_num: u32,

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
    pkt_num: u32,
}

impl<R: Runtime> TransmissionManager<R> {
    /// Create new [`TransmissionManager`].
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            pkt_num: 1u32,
        }
    }

    /// Get next packet number.
    pub fn next_pkt_num(&mut self) -> u32 {
        let pkt_num = self.pkt_num;
        self.pkt_num += 1;

        pkt_num
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
        // TODO: start timer for resends

        if message.serialized_len_short() + SSU2_OVERHEAD <= 1200 {
            let pkt_num = self.next_pkt_num();

            self.segments.insert(
                pkt_num,
                Segment {
                    sent: R::now(),
                    pkt_num,
                    segment: SegmentKind::UnFragmented {
                        message: message.serialize_short(),
                    },
                },
            );

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
                        pkt_num,
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

        packets.into_iter()
    }

    /// Register ACK.
    ///
    /// - `ack_through` marks the highest packet that was ACKed.
    /// - `num_acks` marks the number of ACKs below `ack_through`
    /// - `range` contains a `(# of NACK, # of ACK)` tuples
    pub fn register_ack(&mut self, ack_through: u32, num_acks: u8, ranges: Vec<(u8, u8)>) {}
}
