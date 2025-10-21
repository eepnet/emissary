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
    error::StreamingError,
    primitives::{Destination, DestinationId},
    runtime::Runtime,
    sam::protocol::streaming::packet::{Packet, PacketBuilder},
};

use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::streaming::pending";

/// Initial window size
const INITIAL_WINDOW_SIZE: usize = 6usize;

/// Result type returned from [`PendingStream::on_packet()`].
pub enum PendingStreamResult {
    /// Inbound packet doesn't require an action because it was, e.g., a duplicate ACK.
    DoNothing,

    /// Send packet to remote peer.
    Send {
        /// Packet.
        packet: Vec<u8>,
    },

    /// Send packet to remote peer and destroy the pending stream.
    SendAndDestroy {
        /// Packet.
        packet: Vec<u8>,
    },

    /// Destroy the pending stream because, e.g., `RESET` was received.
    Destroy,
}

/// Pending stream.
///
/// Inbound stream which has been accepted by [`StreamManager`] but which hasn't been converted into
/// an active stream because there are no active listeners who could accept the stream.
///
/// Pending streams are periodically pruned ([`PENDING_STREAM_PRUNE_THRESHOLD`]) if they haven't
/// been accepted within that time window by the client. The stream is pruned before
/// [`PENDING_STREAM_PRUNE_THRESHOLD`] if a full window has been received without client accepting
/// the stream, either by register `STREAM ACCEPT` or `STREAM FORWARD`.
pub struct PendingStream<R: Runtime> {
    /// Destination ID of the remote peer.
    pub destination_id: DestinationId,

    /// When was the stream established.
    pub established: R::Instant,

    /// Pending packets.
    ///
    /// Packets that have been received and ACKed while the stream was pending.
    pub packets: VecDeque<Vec<u8>>,

    /// Receive stream ID.
    pub recv_stream_id: u32,

    /// Send stream ID.
    pub send_stream_id: u32,

    /// Current sequnce number of the remote peer.
    pub seq_nro: u32,
}

impl<R: Runtime> PendingStream<R> {
    /// Create new [`PendingStream`].
    ///
    /// `syn_payload` is the payload contained within the `SYN` message and may be empty.
    pub fn new(
        destination: Destination,
        remote_destination_id: DestinationId,
        recv_stream_id: u32,
        syn_payload: Vec<u8>,
        signing_key: &SigningPrivateKey,
    ) -> (Self, Vec<u8>) {
        let send_stream_id = R::rng().next_u32();
        let packet = PacketBuilder::new(send_stream_id)
            .with_send_stream_id(recv_stream_id)
            .with_seq_nro(0)
            .with_from_included(destination)
            .with_synchronize()
            .with_signature()
            .build_and_sign(signing_key)
            .to_vec();

        (
            Self {
                destination_id: remote_destination_id,
                established: R::now(),
                packets: match syn_payload.is_empty() {
                    true => VecDeque::new(),
                    false => VecDeque::from_iter([syn_payload]),
                },
                recv_stream_id,
                send_stream_id,
                seq_nro: 0u32,
            },
            packet,
        )
    }

    /// Handle `packet`.
    ///
    /// If the packet is valid and it requires an ACK, the function returns a serialized [`Packet`]
    /// with an ACK which must be sent to the remote peer. Duplicate ACKs do not require a response.
    ///
    /// If the packet has `CLOSE`/`RESET` flags set, inform caller that the stream has been
    /// destroyed by the remote and that it can be removed.
    ///
    /// If [`INITIAL_WINDOW_SIZE`] many packets have been received without the session owner
    /// registering a listener, reject the inbound stream by sending a packet with `RESET` flag set.
    /// [`StreamManager`] is also instructed to destroy the session after the packet has been sent.
    fn on_packet_inner(&mut self, packet: Vec<u8>) -> Result<Option<Vec<u8>>, StreamingError> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            flags,
            payload,
            ..
        } = Packet::parse::<R>(&packet).ok_or(StreamingError::Malformed)?;

        tracing::trace!(
            target: LOG_TARGET,
            remote = %self.destination_id,
            ?send_stream_id,
            ?recv_stream_id,
            payload_len = ?payload.len(),
            "inbound message",
        );

        // destroy stream if remote wants to close it
        if flags.reset() || flags.close() {
            return Err(StreamingError::Closed);
        }

        // ignore empty and duplicate packets
        if payload.is_empty() || seq_nro <= self.seq_nro {
            return Ok(None);
        }

        // reset connection because a full window of data was received
        // but the connection was not accepted by the session owner
        if self.packets.len() == INITIAL_WINDOW_SIZE {
            return Err(StreamingError::ReceiveWindowFull);
        }

        // TODO: keep track of dropped packets

        self.packets.push_back(payload.to_vec());
        self.seq_nro = seq_nro;

        Ok(Some(
            PacketBuilder::new(self.send_stream_id)
                .with_send_stream_id(self.recv_stream_id)
                .with_ack_through(seq_nro)
                .build()
                .to_vec(),
        ))
    }

    /// Handle inbound `packet` for a pending stream.
    pub fn on_packet(&mut self, packet: Vec<u8>) -> PendingStreamResult {
        match self.on_packet_inner(packet) {
            Ok(None) => PendingStreamResult::DoNothing,
            Ok(Some(packet)) => PendingStreamResult::Send { packet },
            Err(StreamingError::ReceiveWindowFull) => PendingStreamResult::SendAndDestroy {
                packet: PacketBuilder::new(self.send_stream_id)
                    .with_send_stream_id(self.recv_stream_id)
                    .with_reset()
                    .build()
                    .to_vec(),
            },
            Err(StreamingError::Closed) => PendingStreamResult::Destroy,
            Err(StreamingError::Malformed) => PendingStreamResult::DoNothing,
            Err(_) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, noop::NoopRuntime};

    #[test]
    fn ignore_duplicate_ack() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        let packet = PacketBuilder::new(stream.send_stream_id)
            .with_send_stream_id(stream.recv_stream_id)
            .with_seq_nro(0u32)
            .build()
            .to_vec();

        match stream.on_packet(packet) {
            PendingStreamResult::DoNothing => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn destroy_stream_on_close() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        let packet = PacketBuilder::new(stream.send_stream_id)
            .with_send_stream_id(stream.recv_stream_id)
            .with_seq_nro(0u32)
            .with_close()
            .build()
            .to_vec();

        match stream.on_packet(packet) {
            PendingStreamResult::Destroy => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn destroy_stream_on_reset() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        let packet = PacketBuilder::new(stream.send_stream_id)
            .with_send_stream_id(stream.recv_stream_id)
            .with_seq_nro(0u32)
            .with_reset()
            .build()
            .to_vec();

        match stream.on_packet(packet) {
            PendingStreamResult::Destroy => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn buffer_data_correctly() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        for i in 1..=3 {
            let packet = PacketBuilder::new(stream.send_stream_id)
                .with_send_stream_id(stream.recv_stream_id)
                .with_seq_nro(i as u32)
                .with_payload(b"hello, world")
                .build()
                .to_vec();

            match stream.on_packet(packet) {
                PendingStreamResult::Send { packet } => {
                    let Packet { ack_through, .. } = Packet::parse::<MockRuntime>(&packet).unwrap();
                    assert_eq!(ack_through, i as u32);
                }
                _ => panic!("invalid result"),
            }
        }
        assert_eq!(stream.packets.len(), 3);

        for packet in &stream.packets {
            assert_eq!(packet, b"hello, world");
        }

        // send duplicate ack and verify it's ignored
        let packet = PacketBuilder::new(stream.send_stream_id)
            .with_send_stream_id(stream.recv_stream_id)
            .with_seq_nro(3u32)
            .build()
            .to_vec();

        match stream.on_packet(packet) {
            PendingStreamResult::DoNothing => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn ignore_invalid_packets() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        match stream.on_packet(vec![1, 2, 3, 4]) {
            PendingStreamResult::DoNothing => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn receive_window_full() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        for i in 1..=INITIAL_WINDOW_SIZE {
            let packet = PacketBuilder::new(stream.send_stream_id)
                .with_send_stream_id(stream.recv_stream_id)
                .with_seq_nro(i as u32)
                .with_payload(b"hello, world")
                .build()
                .to_vec();

            match stream.on_packet(packet) {
                PendingStreamResult::Send { packet } => {
                    let Packet { ack_through, .. } = Packet::parse::<MockRuntime>(&packet).unwrap();
                    assert_eq!(ack_through, i as u32);
                }
                _ => panic!("invalid result"),
            }
        }
        assert_eq!(stream.packets.len(), INITIAL_WINDOW_SIZE);

        for packet in &stream.packets {
            assert_eq!(packet, b"hello, world");
        }

        let packet = PacketBuilder::new(stream.send_stream_id)
            .with_send_stream_id(stream.recv_stream_id)
            .with_seq_nro(7 as u32)
            .with_payload(b"hello, world")
            .build()
            .to_vec();

        match stream.on_packet(packet) {
            PendingStreamResult::SendAndDestroy { packet } => {
                assert!(Packet::parse::<MockRuntime>(&packet).unwrap().flags.reset());
            }
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn syn_payload_not_empty() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let (mut stream, _) = PendingStream::<NoopRuntime>::new(
            Destination::new::<NoopRuntime>(signing_key.public()),
            DestinationId::random(),
            1337u32,
            vec![1, 2, 3, 4],
            &SigningPrivateKey::random(NoopRuntime::rng()),
        );

        match stream.packets.pop_front() {
            Some(payload) => {
                assert_eq!(payload, vec![1, 2, 3, 4]);
            }
            _ => panic!("expected payload"),
        }
    }
}
