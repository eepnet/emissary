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
    constants::{self, ssu2},
    crypto::{noise::NoiseContext, sha256::Sha256, StaticPrivateKey},
    error::{ChannelError, DialError, RelayError, Ssu2Error},
    primitives::{MlKemPreference, RouterAddress, RouterId, RouterInfo},
    router::context::RouterContext,
    runtime::{Counter, Gauge, Histogram, JoinSet, MetricsHandle, Runtime, UdpSocket},
    subsystem::SubsystemEvent,
    transport::{
        ssu2::{
            detector::Detector,
            message::{handshake::RetryBuilder, HeaderKind, HeaderReader, ProtocolVersion},
            metrics::*,
            peer_test::{PeerTestManager, PeerTestManagerEvent},
            relay::{
                types::RelayTagRequested, RelayConnection, RelayManager, RelayManagerEvent,
                INTRODUCER_EXPIRATION,
            },
            session::{
                active::{Ssu2Session, Ssu2SessionContext},
                pending::{
                    inbound::{InboundSsu2Context, InboundSsu2Session},
                    outbound::{OutboundSsu2Context, OutboundSsu2Session},
                    EncryptionContext, PendingSsu2SessionStatus,
                },
                terminating::{TerminatingSsu2Session, TerminationContext},
            },
            Packet,
        },
        Direction, FirewallStatus, TerminationReason, TransportEvent,
    },
};

use bytes::BytesMut;
use futures::{Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand::Rng;
use thingbuf::mpsc::{channel, errors::TrySendError, Sender};

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    fmt, mem,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::socket";

/// Protocol name.
const PROTOCOL_NAME: &str = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Protocol name for ML-KEM-512-x25519.
const PROTOCOL_NAME_ML_KEM_512: &str =
    "Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256";

/// Protocol name for ML-KEM-768-x25519.
const PROTOCOL_NAME_ML_KEM_768: &str =
    "Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256";

/// SSU2 session channel size.
///
/// This is the channel from [`Ssu2Socket`] to a pending/active SSU2 session.
const CHANNEL_SIZE: usize = 256usize;

/// Maximum datagram size.
const DATAGRAM_MAX_SIZE: usize = 0xfff;

/// Pending session kind.
enum PendingSessionKind {
    /// Pending inbound session.
    Inbound {
        /// Initial `Data` packet that ACKs `SessionConfirmed`.
        pkt: BytesMut,

        /// Socket address of the remote router.
        address: SocketAddr,

        /// Session context.
        context: Ssu2SessionContext,

        /// Destination connection ID.
        ///
        /// This is the connection ID selected by the remote router and is used to remove pending
        /// session context in case it's rejected by the `TransportManager`.
        dst_id: u64,

        /// Relay tag request during handshake.
        relay_tag_request: RelayTagRequested,

        /// Key for decrypting the header of `SessionConfirmed` message.
        k_header_2: [u8; 32],
    },

    /// Pending outbound session.
    Outbound {
        // Socket address of the remote router.
        address: SocketAddr,

        /// Session context.
        context: Ssu2SessionContext,

        /// Relay tag, if we requested and received one.
        relay_tag: Option<u32>,

        /// Source connection ID.
        ///
        /// This is the connection ID selected by us which the remote router uses to send us
        /// messages and it will be used to remove the session context in case the connection
        /// is rejected.
        src_id: u64,
    },
}

impl fmt::Debug for PendingSessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PendingSessionKind::Inbound {
                address,
                context,
                dst_id,
                ..
            } => f
                .debug_struct("PendingSessionKind::Inbound")
                .field("address", &address)
                .field("dst_id", &dst_id)
                .field("src_id", &context.dst_id)
                .finish_non_exhaustive(),
            PendingSessionKind::Outbound {
                address,
                context,
                relay_tag,
                src_id,
            } => f
                .debug_struct("PendingSessionKind::Outbound")
                .field("address", &address)
                .field("dst_id", &context.dst_id)
                .field("src_id", &src_id)
                .field("relay_tag", &relay_tag)
                .finish_non_exhaustive(),
        }
    }
}

/// Write state.
enum WriteState {
    /// Get next packet.
    GetPacket,

    /// Send packet.
    SendPacket {
        /// Packet.
        pkt: BytesMut,

        /// Target.
        target: SocketAddr,
    },

    /// Poisoned.
    Poisoned,
}

/// Protocols state.
struct ProtocolState {
    /// Chaining key.
    chaining_key: [u8; 32],

    /// Outbound state.
    outbound_state: [u8; 32],

    /// Inbound state.
    inbound_state: [u8; 32],
}

/// SSU2 socket.
pub struct Ssu2Socket<R: Runtime> {
    /// Active sessions.
    ///
    /// The session returns a `(RouterId, destination connection ID)` tuple when it exits.
    active_sessions: R::JoinSet<TerminationContext<R>>,

    /// Disable PQ for outbound connections.
    disable_pq: bool,

    /// Introduction key.
    intro_key: [u8; 32],

    /// Firewall/external address detector.
    ipv4_detector: Detector<R>,

    /// IPv4 ML-KEM preference.
    ipv4_ml_kem: Option<MlKemPreference>,

    /// IPv4 MTU.
    ipv4_mtu: usize,

    /// IPv4 UDP socket.
    ipv4_socket: Option<R::UdpSocket>,

    /// Firewall/external address detector.
    ipv6_detector: Detector<R>,

    /// IPv6 ML-KEM preference.
    ipv6_ml_kem: Option<MlKemPreference>,

    /// IPv6 MTU.
    ipv6_mtu: usize,

    /// IPv4 UDP socket.
    ipv6_socket: Option<R::UdpSocket>,

    /// Maximum number of connections.
    max_connections: Option<NonZeroUsize>,

    /// Protocol state for ML-KEM-512-x25519.
    ml_kem_512: ProtocolState,

    /// Protocol state for ML-KEM-768-x25519.
    ml_kem_768: ProtocolState,

    /// Number of active connections.
    num_connections: usize,

    /// Peer test manager.
    peer_test_manager: PeerTestManager<R>,

    /// Pending events.
    pending_events: VecDeque<TransportEvent>,

    /// Pending outbound sessions.
    ///
    /// Remote routers' intro keys indexed by their socket addresses.
    pending_outbound: HashMap<SocketAddr, [u8; 32]>,

    /// Pending outbound packets.
    pending_pkts: VecDeque<(BytesMut, SocketAddr)>,

    /// Pending outbound relay connections.
    pending_relays: HashMap<RouterId, RelayConnection>,

    /// Pending SSU2 sessions.
    pending_sessions: R::JoinSet<PendingSsu2SessionStatus<R>>,

    /// Datagram read buffer.
    read_buffer: Vec<u8>,

    /// Relay manager.
    relay_manager: RelayManager<R>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// SSU2 sessions.
    sessions: HashMap<u64, Sender<Packet>>,

    /// Static key.
    static_key: StaticPrivateKey,

    /// Terminating sessions.
    terminating_session: R::JoinSet<(RouterId, u64)>,

    /// Tokens.
    tokens: HashSet<u64>,

    /// TX channel for sending events to `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,

    /// Unvalidated sessions.
    unvalidated_sessions: HashMap<RouterId, PendingSessionKind>,

    /// Waker.
    waker: Option<Waker>,

    /// Write state.
    write_state: WriteState,

    /// Protocol state for x25519.
    x25519: ProtocolState,
}

impl<R: Runtime> Ssu2Socket<R> {
    /// Create new [`Ssu2Socket`].
    pub fn new(
        ipv4_socket: Option<R::UdpSocket>,
        ipv4_mtu: Option<usize>,
        ipv4_ml_kem: Option<MlKemPreference>,
        ipv6_socket: Option<R::UdpSocket>,
        ipv6_mtu: Option<usize>,
        ipv6_ml_kem: Option<MlKemPreference>,
        static_key: StaticPrivateKey,
        intro_key: [u8; 32],
        transport_tx: Sender<SubsystemEvent>,
        router_ctx: RouterContext<R>,
        firewalled: bool,
        disable_pq: bool,
        max_connections: Option<NonZeroUsize>,
    ) -> Self {
        let public_key = static_key.public();
        let make_key_context = |protocol_name: &str| -> ProtocolState {
            let chaining_key = Sha256::new().update(protocol_name.as_bytes()).finalize_new();

            let outbound_state = Sha256::new().update(chaining_key).finalize_new();
            let inbound_state =
                Sha256::new().update(outbound_state).update(&public_key).finalize_new();

            ProtocolState {
                chaining_key,
                outbound_state,
                inbound_state,
            }
        };

        let x25519 = make_key_context(PROTOCOL_NAME);
        let mut ml_kem_512 = make_key_context(PROTOCOL_NAME_ML_KEM_512);
        let mut ml_kem_768 = make_key_context(PROTOCOL_NAME_ML_KEM_768);

        // update `inbound_state` to contain our router ID for spoof protection
        //
        // https://i2p.net/en/docs/specs/ssu2-hybrid/#sessionrequest-type-0
        {
            ml_kem_512.inbound_state = Sha256::new()
                .update(ml_kem_512.inbound_state)
                .update(router_ctx.router_id().to_vec())
                .finalize_new();

            ml_kem_768.inbound_state = Sha256::new()
                .update(ml_kem_768.inbound_state)
                .update(router_ctx.router_id().to_vec())
                .finalize_new();
        }

        Self {
            active_sessions: R::join_set(),
            disable_pq,
            intro_key,
            ipv4_detector: Detector::new(firewalled, router_ctx.metrics_handle().clone()),
            ipv4_mtu: ipv4_mtu.unwrap_or(ssu2::MAX_MTU),
            ipv4_ml_kem,
            ipv4_socket: ipv4_socket.clone(),
            ipv6_detector: Detector::new(firewalled, router_ctx.metrics_handle().clone()),
            ipv6_mtu: ipv6_mtu.unwrap_or(ssu2::MAX_MTU),
            ipv6_ml_kem,
            ipv6_socket: ipv6_socket.clone(),
            max_connections,
            ml_kem_512,
            ml_kem_768,
            num_connections: 0usize,
            peer_test_manager: PeerTestManager::new(
                intro_key,
                ipv4_socket.clone(),
                ipv6_socket.clone(),
                router_ctx.clone(),
                firewalled,
            ),
            pending_events: VecDeque::new(),
            pending_outbound: HashMap::new(),
            pending_pkts: VecDeque::new(),
            pending_relays: HashMap::new(),
            pending_sessions: R::join_set(),
            read_buffer: vec![0u8; DATAGRAM_MAX_SIZE],
            relay_manager: RelayManager::new(
                intro_key,
                router_ctx.clone(),
                ipv4_socket.clone(),
                ipv6_socket.clone(),
            ),
            router_ctx,
            sessions: HashMap::new(),
            static_key,
            terminating_session: R::join_set(),
            tokens: HashSet::new(),
            transport_tx,
            unvalidated_sessions: HashMap::new(),
            waker: None,
            write_state: WriteState::GetPacket,
            x25519,
        }
    }

    /// Send `Retry` containing a termination block indicating.
    fn send_termination(
        &mut self,
        encryption_ctx: EncryptionContext,
        dst_id: u64,
        src_id: u64,
        address: SocketAddr,
        reason: TerminationReason,
    ) {
        tracing::debug!(
            target: LOG_TARGET,
            ?address,
            ?dst_id,
            ?src_id,
            ?reason,
            "sending Retry with termination",
        );

        self.pending_pkts.push_back((
            RetryBuilder::default()
                .with_k_header_1(self.intro_key)
                .with_version(encryption_ctx.version())
                .with_src_id(dst_id)
                .with_dst_id(src_id)
                .with_token(0)
                .with_termination(reason)
                .with_address(address)
                .with_net_id(self.router_ctx.net_id())
                .build::<R>(),
            address,
        ));
    }

    /// Get UDP socket for `address`.
    fn socket_for_address(&self, address: &SocketAddr) -> R::UdpSocket {
        if address.is_ipv4() {
            self.ipv4_socket.as_ref().expect("ipv4 socket to exist").clone()
        } else {
            self.ipv6_socket.as_ref().expect("ipv6 socket to exist").clone()
        }
    }

    /// Get maximum payload size for a connection.
    fn max_payload_size(&self, address: &SocketAddr, remote_mtu: usize) -> usize {
        match address {
            SocketAddr::V4(_) => self.ipv4_mtu.min(remote_mtu) - ssu2::IPV4_OVERHEAD,
            SocketAddr::V6(_) => self.ipv6_mtu.min(remote_mtu) - ssu2::IPV6_OVERHEAD,
        }
    }

    /// Handle packet.
    //
    // TODO: needs as lot of refactoring
    // TODO: explain what happens here
    fn handle_packet(
        &mut self,
        mut datagram: Vec<u8>,
        address: SocketAddr,
    ) -> Result<Option<TransportEvent>, Ssu2Error> {
        let mut reader = HeaderReader::new(self.intro_key, &mut datagram)?;
        let connection_id = reader.dst_id();

        if let Some(tx) = self.sessions.get_mut(&connection_id) {
            match tx.try_send(Packet {
                pkt: datagram,
                address,
            }) {
                Ok(()) => return Ok(None),
                Err(TrySendError::Closed(_)) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?connection_id,
                        ?address,
                        "session did not exit cleanly",
                    );
                    debug_assert!(false);

                    return Err(Ssu2Error::Channel(ChannelError::Closed));
                }
                Err(_) => {
                    return Err(Ssu2Error::Channel(ChannelError::Full));
                }
            }
        }

        match reader.parse(self.intro_key) {
            Ok(HeaderKind::TokenRequest {
                net_id,
                pkt_num,
                src_id,
                version,
            }) => {
                if net_id != self.router_ctx.net_id() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        our_net_id = ?self.router_ctx.net_id(),
                        their_net_id = ?net_id,
                        "network id mismatch",
                    );
                    return Err(Ssu2Error::NetworkMismatch);
                }

                let preference = match address {
                    SocketAddr::V4(_) => (!self.disable_pq).then_some(self.ipv4_ml_kem).flatten(),
                    SocketAddr::V6(_) => (!self.disable_pq).then_some(self.ipv6_ml_kem).flatten(),
                };

                let (encryption_ctx, max_payload_size) = match (version, preference) {
                    (ProtocolVersion::V2, _) => (
                        EncryptionContext::X25519(NoiseContext::new(
                            self.x25519.chaining_key,
                            self.x25519.inbound_state,
                        )),
                        match address {
                            SocketAddr::V4(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV4_OVERHEAD,
                            SocketAddr::V6(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV6_OVERHEAD,
                        },
                    ),
                    (
                        ProtocolVersion::V3,
                        Some(
                            MlKemPreference::MlKem512
                            | MlKemPreference::MlKem512MlKem768
                            | MlKemPreference::MlKem768MlKem512,
                        ),
                    ) => (
                        EncryptionContext::MlKem512X25519(NoiseContext::new(
                            self.ml_kem_512.chaining_key,
                            self.ml_kem_512.inbound_state,
                        )),
                        match address {
                            SocketAddr::V4(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV4_OVERHEAD,
                            SocketAddr::V6(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV6_OVERHEAD,
                        },
                    ),
                    (
                        ProtocolVersion::V4,
                        Some(
                            MlKemPreference::MlKem768
                            | MlKemPreference::MlKem768MlKem512
                            | MlKemPreference::MlKem512MlKem768,
                        ),
                    ) => (
                        EncryptionContext::MlKem768X25519(NoiseContext::new(
                            self.ml_kem_768.chaining_key,
                            self.ml_kem_768.inbound_state,
                        )),
                        match address {
                            SocketAddr::V4(_) =>
                                constants::crypto::ml_kem::ML_KEM_768_IPV4_MIN_MTU
                                    - constants::ssu2::IPV4_OVERHEAD,
                            SocketAddr::V6(_) =>
                                constants::crypto::ml_kem::ML_KEM_768_IPV6_MIN_MTU
                                    - constants::ssu2::IPV6_OVERHEAD,
                        },
                    ),
                    (version, preference) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?version,
                            ?preference,
                            "remote router requested post-quantum connection but they're disabled, rejecting",
                        );
                        return Err(Ssu2Error::InvalidVersion);
                    }
                };

                if self.max_connections.is_some_and(|max| self.num_connections >= max.get()) {
                    self.send_termination(
                        encryption_ctx,
                        connection_id,
                        src_id,
                        address,
                        TerminationReason::ConnectionLimits,
                    );
                    return Err(Ssu2Error::ConnectionLimits);
                }

                let (tx, rx) = channel(CHANNEL_SIZE);
                let relay_tag = self.relay_manager.allocate_relay_tag();
                let session = InboundSsu2Session::<R>::new(InboundSsu2Context {
                    address,
                    dst_id: connection_id,
                    encryption_ctx,
                    intro_key: self.intro_key,
                    max_payload_size,
                    mtu: match address {
                        SocketAddr::V4(_) => self.ipv4_mtu,
                        SocketAddr::V6(_) => self.ipv6_mtu,
                    },
                    net_id: self.router_ctx.net_id(),
                    pkt: datagram,
                    pkt_num,
                    relay_tag,
                    rx,
                    socket: self.socket_for_address(&address),
                    src_id,
                    static_key: self.static_key.clone(),
                })?;

                self.sessions.insert(connection_id, tx);
                self.pending_sessions.push(session.run());
                self.router_ctx
                    .metrics_handle()
                    .counter(NUM_CONNECTIONS)
                    .increment_with_label(1, "kind", "inbound");

                return Ok(None);
            }
            Ok(HeaderKind::PeerTest {
                net_id,
                pkt_num,
                src_id,
                ..
            }) => {
                if net_id != self.router_ctx.net_id() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        our_net_id = ?self.router_ctx.net_id(),
                        their_net_id = ?net_id,
                        "network id mismatch",
                    );
                    return Err(Ssu2Error::NetworkMismatch);
                }

                match self.peer_test_manager.handle_peer_test(src_id, pkt_num, datagram, address) {
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?src_id,
                            ?error,
                            "failed to handle out-of-session peer test message",
                        );

                        return Err(error);
                    }
                    Ok(None) => return Ok(None),
                    Ok(Some(PeerTestManagerEvent::PeerTestResult { results })) => {
                        let mut ipv4_status = Option::<FirewallStatus>::None;
                        let mut ipv6_status = Option::<FirewallStatus>::None;

                        for result in results {
                            if result.3 {
                                let status = self
                                    .ipv4_detector
                                    .add_peer_test_result(result.0, result.1, result.2);

                                match (ipv4_status, status) {
                                    (None, None) => {}
                                    (None, Some(event)) => {
                                        ipv4_status = Some(event);
                                    }
                                    (Some(_), Some(event)) => {
                                        ipv4_status = Some(event);
                                    }
                                    (Some(_), None) => {}
                                }
                            } else {
                                let status = self
                                    .ipv6_detector
                                    .add_peer_test_result(result.0, result.1, result.2);

                                match (ipv6_status, status) {
                                    (None, None) => {}
                                    (None, Some(event)) => {
                                        ipv6_status = Some(event);
                                    }
                                    (Some(_), Some(event)) => {
                                        ipv6_status = Some(event);
                                    }
                                    (Some(_), None) => {}
                                }
                            };
                        }

                        match (ipv4_status, ipv6_status) {
                            (None, None) => return Ok(None),
                            (Some(status), None) =>
                                return Ok(Some(TransportEvent::FirewallStatus {
                                    status,
                                    ipv4: true,
                                })),
                            (None, Some(status)) =>
                                return Ok(Some(TransportEvent::FirewallStatus {
                                    status,
                                    ipv4: false,
                                })),
                            (Some(ipv4_status), Some(ipv6_status)) => {
                                self.pending_events.push_back(TransportEvent::FirewallStatus {
                                    status: ipv6_status,
                                    ipv4: false,
                                });

                                return Ok(Some(TransportEvent::FirewallStatus {
                                    status: ipv4_status,
                                    ipv4: false,
                                }));
                            }
                        }
                    }
                }
            }
            Ok(HeaderKind::HolePunch {
                net_id,
                pkt_num,
                src_id,
                ..
            }) => {
                if net_id != self.router_ctx.net_id() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        our_net_id = ?self.router_ctx.net_id(),
                        their_net_id = ?net_id,
                        "network id mismatch",
                    );
                    return Err(Ssu2Error::NetworkMismatch);
                }

                let (router_id, address, token) =
                    self.relay_manager.handle_hole_punch(datagram, pkt_num, src_id)?;
                self.send_session_request(router_id, address, token);

                return Ok(None);
            }
            Ok(HeaderKind::SessionRequest {
                token,
                pkt_num,
                ephemeral_key,
                version,
                ..
            }) if self.tokens.remove(&token) => {
                let preference = match address {
                    SocketAddr::V4(_) => (!self.disable_pq).then_some(self.ipv4_ml_kem).flatten(),
                    SocketAddr::V6(_) => (!self.disable_pq).then_some(self.ipv6_ml_kem).flatten(),
                };

                let (encryption_ctx, max_payload_size) = match (version, preference) {
                    (ProtocolVersion::V2, _) => (
                        EncryptionContext::X25519(NoiseContext::new(
                            self.x25519.chaining_key,
                            self.x25519.inbound_state,
                        )),
                        match address {
                            SocketAddr::V4(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV4_OVERHEAD,
                            SocketAddr::V6(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV6_OVERHEAD,
                        },
                    ),
                    (
                        ProtocolVersion::V3,
                        Some(
                            MlKemPreference::MlKem512
                            | MlKemPreference::MlKem512MlKem768
                            | MlKemPreference::MlKem768MlKem512,
                        ),
                    ) => (
                        EncryptionContext::MlKem512X25519(NoiseContext::new(
                            self.ml_kem_512.chaining_key,
                            self.ml_kem_512.inbound_state,
                        )),
                        match address {
                            SocketAddr::V4(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV4_OVERHEAD,
                            SocketAddr::V6(_) =>
                                constants::ssu2::MIN_MTU - constants::ssu2::IPV6_OVERHEAD,
                        },
                    ),
                    (
                        ProtocolVersion::V4,
                        Some(
                            MlKemPreference::MlKem768
                            | MlKemPreference::MlKem768MlKem512
                            | MlKemPreference::MlKem512MlKem768,
                        ),
                    ) => (
                        EncryptionContext::MlKem768X25519(NoiseContext::new(
                            self.ml_kem_768.chaining_key,
                            self.ml_kem_768.inbound_state,
                        )),
                        match address {
                            SocketAddr::V4(_) =>
                                constants::crypto::ml_kem::ML_KEM_768_IPV4_MIN_MTU
                                    - constants::ssu2::IPV4_OVERHEAD,
                            SocketAddr::V6(_) =>
                                constants::crypto::ml_kem::ML_KEM_768_IPV6_MIN_MTU
                                    - constants::ssu2::IPV6_OVERHEAD,
                        },
                    ),
                    (version, preference) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?version,
                            ?preference,
                            "remote router requested post-quantum connection but they're disabled, rejecting",
                        );
                        return Err(Ssu2Error::InvalidVersion);
                    }
                };

                if self.max_connections.is_some_and(|max| self.num_connections >= max.get()) {
                    self.send_termination(
                        encryption_ctx,
                        connection_id,
                        !connection_id,
                        address,
                        TerminationReason::ConnectionLimits,
                    );
                    return Err(Ssu2Error::ConnectionLimits);
                }

                let (tx, rx) = channel(CHANNEL_SIZE);
                let relay_tag = self.relay_manager.allocate_relay_tag();
                let session = InboundSsu2Session::<R>::from_session_request(
                    InboundSsu2Context {
                        address,
                        dst_id: connection_id,
                        encryption_ctx,
                        intro_key: self.intro_key,
                        max_payload_size,
                        mtu: match address {
                            SocketAddr::V4(_) => self.ipv4_mtu,
                            SocketAddr::V6(_) => self.ipv6_mtu,
                        },
                        net_id: self.router_ctx.net_id(),
                        pkt: datagram,
                        pkt_num,
                        relay_tag,
                        rx,
                        socket: self.socket_for_address(&address),
                        src_id: !connection_id,
                        static_key: self.static_key.clone(),
                    },
                    ephemeral_key,
                    token,
                );

                self.sessions.insert(connection_id, tx);
                self.pending_sessions.push(session.run());
                self.router_ctx
                    .metrics_handle()
                    .counter(NUM_ACTIVE_CONNECTIONS)
                    .increment_with_label(1, "kind", "inbound-relay");

                return Ok(None);
            }
            _ => {}
        }

        let Some(intro_key) = self.pending_outbound.get(&address) else {
            tracing::debug!(
                target: LOG_TARGET,
                message_type = ?datagram.get(12),
                "pending outbound connection does not exist",
            );
            return Err(Ssu2Error::NonExistentOutbound);
        };

        match self.sessions.get_mut(&reader.reset_key(*intro_key).dst_id()) {
            Some(tx) => tx
                .try_send(Packet {
                    pkt: datagram,
                    address,
                })
                .map(|_| None)
                .map_err(From::from),
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?address,
                    "pending connection found but no associated session",
                );
                Ok(None)
            }
        }
    }

    /// Send relay request to one of the introducers listed in `router_info`.
    fn send_relay_request(&mut self, router_info: RouterInfo) {
        let router_id = router_info.identity.id();

        match self.relay_manager.send_relay_request(router_info, self.disable_pq) {
            Ok(connection) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    "relay request sent",
                );

                self.pending_relays.insert(router_id, connection);
            }
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %error,
                    "failed to send relay request",
                );

                self.pending_events.push_back(TransportEvent::ConnectionFailure {
                    router_id,
                    reason: match error {
                        RelayError::NoAddress => DialError::NoAddress,
                        _ => DialError::RelayFailure,
                    },
                });
            }
        }
    }

    /// Send `SessionRequest` to router using `token`.
    fn send_session_request(&mut self, router_id: RouterId, address: SocketAddr, token: u64) {
        let Some(RelayConnection {
            dst_id,
            intro_key,
            mtu,
            src_id,
            static_key,
            verifying_key,
            version,
        }) = self.pending_relays.remove(&router_id)
        else {
            tracing::trace!(
                target: LOG_TARGET,
                ?router_id,
                ?address,
                ?token,
                "pending relay does not exist",
            );
            return;
        };

        let encryption_ctx = match version {
            ProtocolVersion::V2 => EncryptionContext::X25519(NoiseContext::new(
                self.x25519.chaining_key,
                Sha256::new()
                    .update(self.x25519.outbound_state)
                    .update(&static_key)
                    .finalize_new(),
            )),
            ProtocolVersion::V3 => EncryptionContext::MlKem512X25519(NoiseContext::new(
                self.ml_kem_512.chaining_key,
                Sha256::new()
                    .update(self.ml_kem_512.outbound_state)
                    .update(&static_key)
                    .finalize_new(),
            )),
            ProtocolVersion::V4 => EncryptionContext::MlKem768X25519(NoiseContext::new(
                self.ml_kem_768.chaining_key,
                Sha256::new()
                    .update(self.ml_kem_768.outbound_state)
                    .update(&static_key)
                    .finalize_new(),
            )),
        };

        let our_router_info = self.router_ctx.router_info();
        let transport_tx = self.transport_tx.clone();
        let max_payload_size = self.max_payload_size(&address, mtu);

        tracing::debug!(
            target: LOG_TARGET,
            %router_id,
            ?src_id,
            ?dst_id,
            ?address,
            "establish outbound session",
        );

        let (tx, rx) = channel(CHANNEL_SIZE);
        self.sessions.insert(src_id, tx);
        self.pending_outbound.insert(address, intro_key);
        self.router_ctx.metrics_handle().counter(NUM_CONNECTIONS).increment_with_label(
            1,
            "kind",
            "outbound-relay",
        );

        self.pending_sessions.push(
            OutboundSsu2Session::<R>::from_token(
                OutboundSsu2Context {
                    address,
                    dst_id,
                    encryption_ctx,
                    local_intro_key: self.intro_key,
                    local_static_key: self.static_key.clone(),
                    max_payload_size,
                    net_id: self.router_ctx.net_id(),
                    remote_intro_key: intro_key,
                    request_tag: false,
                    router_id,
                    router_info: our_router_info,
                    rx,
                    socket: self.socket_for_address(&address),
                    src_id,
                    static_key: static_key.clone(),
                    transport_tx,
                    verifying_key,
                },
                token,
            )
            .run(),
        );

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Attempt to establish outbound connection remote router.
    pub fn connect(&mut self, router_info: RouterInfo) {
        // must succeed since `TransportManager` has ensured `router_info` contains
        // a valid and reachable ssu2 router address
        let router_id = router_info.identity.id();
        let verifying_key = router_info.identity.signing_key().clone();

        // attempt to locate a router address with reachable socket address
        //
        // if none is found, attempt to dial the router with the help of an introducer
        let (static_key, intro_key, address, supports_relay, remote_mtu, ml_kem) =
            match router_info.addresses.iter().find(|address| match address {
                RouterAddress::Ssu2 {
                    socket_address: Some(address),
                    ..
                } => core::matches!(
                    (
                        address.is_ipv4(),
                        self.ipv4_socket.is_some(),
                        self.ipv6_socket.is_some(),
                    ),
                    (true, true, _) | (false, _, true)
                ),
                _ => false,
            }) {
                Some(
                    ssu2_address @ RouterAddress::Ssu2 {
                        static_key,
                        intro_key,
                        socket_address: Some(address),
                        mtu,
                        ml_kem,
                        ..
                    },
                ) => (
                    static_key,
                    intro_key,
                    address,
                    ssu2_address.supports_relay(),
                    *mtu,
                    (!self.disable_pq).then_some(*ml_kem).flatten(),
                ),
                _ => return self.send_relay_request(router_info),
            };

        let max_payload_size = self.max_payload_size(address, remote_mtu);
        let our_router_info = self.router_ctx.router_info();
        let transport_tx = self.transport_tx.clone();
        let src_id = R::rng().next_u64();
        let dst_id = R::rng().next_u64();

        tracing::debug!(
            target: LOG_TARGET,
            %router_id,
            ?src_id,
            ?dst_id,
            ?address,
            "establish outbound session",
        );

        let (tx, rx) = channel(CHANNEL_SIZE);
        self.sessions.insert(src_id, tx);
        self.pending_outbound.insert(*address, *intro_key);
        self.router_ctx
            .metrics_handle()
            .counter(NUM_CONNECTIONS)
            .increment_with_label(1, "kind", "outbound");
        let status = match address.is_ipv4() {
            true => self.ipv4_detector.status(),
            false => self.ipv4_detector.status(),
        };

        let encryption_ctx = match ml_kem {
            None => EncryptionContext::X25519(NoiseContext::new(
                self.x25519.chaining_key,
                Sha256::new()
                    .update(self.x25519.outbound_state)
                    .update(static_key)
                    .finalize_new(),
            )),
            Some(ml_kem) => match ml_kem {
                MlKemPreference::MlKem512 | MlKemPreference::MlKem512MlKem768 =>
                    EncryptionContext::MlKem512X25519(NoiseContext::new(
                        self.ml_kem_512.chaining_key,
                        Sha256::new()
                            .update(self.ml_kem_512.outbound_state)
                            .update(static_key)
                            .finalize_new(),
                    )),
                MlKemPreference::MlKem768 | MlKemPreference::MlKem768MlKem512 =>
                    EncryptionContext::MlKem768X25519(NoiseContext::new(
                        self.ml_kem_768.chaining_key,
                        Sha256::new()
                            .update(self.ml_kem_768.outbound_state)
                            .update(static_key)
                            .finalize_new(),
                    )),
            },
        };

        self.pending_sessions.push(
            OutboundSsu2Session::<R>::new(OutboundSsu2Context {
                address: *address,
                dst_id,
                encryption_ctx,
                local_intro_key: self.intro_key,
                local_static_key: self.static_key.clone(),
                max_payload_size,
                net_id: self.router_ctx.net_id(),
                remote_intro_key: *intro_key,
                request_tag: core::matches!(status, FirewallStatus::Firewalled)
                    && supports_relay
                    && self.relay_manager.needs_introducers(),
                router_id,
                router_info: our_router_info,
                rx,
                socket: self.socket_for_address(address),
                src_id,
                static_key: static_key.clone(),
                transport_tx,
                verifying_key,
            })
            .run(),
        );

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Accept inbound/outbound connection to `router_id`.
    ///
    /// Remove any state associated with a pending connection and spawn the event loop of the
    /// connection in a separate task. The channel that was used during negotiation is kept in
    /// `self.sessions` and removed only when the session is destroyed.
    pub fn accept(&mut self, router_id: &RouterId) {
        let Some(kind) = self.unvalidated_sessions.remove(router_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                "non-existent unvalidated session accepted",
            );
            debug_assert!(false);
            return;
        };

        // get handles to `PeerTestManager` and `RelayManager`
        let peer_test_handle = self.peer_test_manager.handle();
        let relay_handle = self.relay_manager.handle();

        let context = match kind {
            PendingSessionKind::Inbound {
                pkt,
                address,
                context,
                relay_tag_request,
                ..
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "inbound session accepted",
                );

                // TODO: retransmissiosn?
                self.pending_pkts.push_back((pkt, address));

                // register relay client to `RelayManager`
                match relay_tag_request {
                    RelayTagRequested::Yes(tag) => self.relay_manager.register_relay_client(
                        router_id.clone(),
                        tag,
                        relay_handle.cmd_tx(),
                    ),
                    RelayTagRequested::No(tag) => self.relay_manager.deallocate_relay_tag(tag),
                }

                context
            }
            PendingSessionKind::Outbound {
                address,
                context,
                relay_tag,
                ..
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "outbound session accepted",
                );

                self.pending_outbound.remove(&address);

                // register relay server to `RelayManager`
                if let Some(relay_tag) = relay_tag {
                    self.relay_manager.register_relay_server(
                        context.router_id.clone(),
                        relay_tag,
                        address.is_ipv4(),
                    );

                    self.pending_events.push_back(TransportEvent::IntroducerAdded {
                        relay_tag,
                        router_id: context.router_id.clone(),
                        expires: R::time_since_epoch() + INTRODUCER_EXPIRATION,
                        ipv4: address.is_ipv4(),
                    });
                }

                context
            }
        };

        // register session to `PeerTestManager`
        self.peer_test_manager
            .add_session(&context.router_id, peer_test_handle.cmd_tx());

        // register router to `RelayManager` if they support the relay protocol
        {
            let reader = self.router_ctx.profile_storage().reader();

            match reader.router_info(&context.router_id) {
                Some(router_info) =>
                    if router_info.supports_relay() {
                        self.relay_manager.add_session(
                            &context.router_id,
                            relay_handle.cmd_tx(),
                            context.address.is_ipv4(),
                        );
                    },
                None => tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %context.router_id,
                    "router doens't exist in profile storage",
                ),
            }
        }

        // socket for the session
        let socket = self.socket_for_address(&context.address);

        self.active_sessions.push(
            Ssu2Session::<R>::new(
                context,
                socket,
                self.transport_tx.clone(),
                self.router_ctx.clone(),
                peer_test_handle,
                relay_handle,
            )
            .run(),
        );
        self.router_ctx.metrics_handle().gauge(NUM_ACTIVE_CONNECTIONS).increment(1);
        self.router_ctx.metrics_handle().counter(CONNECTIONS_OPENED).increment(1);
        self.num_connections += 1;

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }

    /// Reject inbound/outbound connection to `router_id`.
    pub fn reject(&mut self, router_id: &RouterId) {
        let Some(kind) = self.unvalidated_sessions.remove(router_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                "non-existent unvalidated session rejected",
            );
            debug_assert!(false);
            return;
        };

        match kind {
            PendingSessionKind::Inbound {
                context,
                k_header_2,
                relay_tag_request,
                ..
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "inbound session rejected, send termination",
                );
                self.relay_manager.deallocate_relay_tag(relay_tag_request.tag());

                let Ssu2SessionContext {
                    address,
                    dst_id,
                    intro_key,
                    pkt_rx,
                    recv_key_ctx,
                    router_id,
                    send_key_ctx,
                    ..
                } = context;

                self.terminating_session.push(TerminatingSsu2Session::<R>::new(
                    TerminationContext {
                        address,
                        dst_id,
                        intro_key,
                        k_session_confirmed: Some(k_header_2),
                        next_pkt_num: 0,
                        reason: TerminationReason::ConnectionLimits,
                        recv_key_ctx,
                        router_id,
                        rx: pkt_rx,
                        send_key_ctx,
                        socket: self.socket_for_address(&address),
                        duration: Duration::from_secs(0),
                    },
                ))
            }
            PendingSessionKind::Outbound {
                address,
                context,
                src_id,
                ..
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = ?context.dst_id,
                    "outbound session rejected, send termination",
                );

                self.pending_outbound.remove(&address);
                self.sessions.remove(&src_id);
            }
        }

        // TODO: send termination?
    }
}

impl<R: Runtime> Stream for Ssu2Socket<R> {
    type Item = TransportEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        if let Some(event) = this.pending_events.pop_front() {
            return Poll::Ready(Some(event));
        }

        if this.ipv4_socket.is_some() {
            loop {
                let (nread, from) = {
                    // socket must exist since it was checked above
                    #[allow(clippy::unnecessary_unwrap)]
                    let socket = this.ipv4_socket.as_mut().expect("ipv4 socket to exist");

                    match Pin::new(socket).poll_recv_from(cx, &mut this.read_buffer) {
                        Poll::Pending => break,
                        Poll::Ready(None) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "socket closed",
                            );
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Some((nread, from))) => {
                            this.router_ctx
                                .metrics_handle()
                                .counter(INBOUND_BANDWIDTH)
                                .increment(nread);
                            this.router_ctx.metrics_handle().counter(INBOUND_PKTS).increment(1);
                            this.router_ctx
                                .metrics_handle()
                                .histogram(INBOUND_PKT_SIZES)
                                .record(nread as f64);

                            (nread, from)
                        }
                    }
                };

                match this.handle_packet(this.read_buffer[..nread].to_vec(), from) {
                    Err(Ssu2Error::Channel(ChannelError::Full)) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            "cannot process packet, channel is full",
                        );
                        this.router_ctx
                            .metrics_handle()
                            .counter(DROPPED_PKTS)
                            .increment_with_label(1, "reason", "channel-full");
                    }
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?from,
                            ?error,
                            "failed to handle packet (ipv4)",
                        );
                        this.router_ctx
                            .metrics_handle()
                            .counter(DROPPED_PKTS)
                            .increment_with_label(1, "reason", error.into());
                    }
                    Ok(None) => {}
                    Ok(Some(event)) => return Poll::Ready(Some(event)),
                }
            }
        }

        if this.ipv6_socket.is_some() {
            loop {
                let (nread, from) = {
                    // socket must exist since it was checked above
                    #[allow(clippy::unnecessary_unwrap)]
                    let socket = this.ipv6_socket.as_mut().expect("ipv6 socket to exist");

                    match Pin::new(socket).poll_recv_from(cx, &mut this.read_buffer) {
                        Poll::Pending => break,
                        Poll::Ready(None) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "socket closed",
                            );
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Some((nread, from))) => {
                            this.router_ctx
                                .metrics_handle()
                                .counter(INBOUND_BANDWIDTH)
                                .increment(nread);
                            this.router_ctx.metrics_handle().counter(INBOUND_PKTS).increment(1);
                            this.router_ctx
                                .metrics_handle()
                                .histogram(INBOUND_PKT_SIZES)
                                .record(nread as f64);

                            (nread, from)
                        }
                    }
                };

                match this.handle_packet(this.read_buffer[..nread].to_vec(), from) {
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?from,
                            ?error,
                            "failed to handle packet (ipv6)",
                        );
                        this.router_ctx
                            .metrics_handle()
                            .counter(DROPPED_PKTS)
                            .increment_with_label(1, "reason", error.into());
                    }
                    Ok(None) => {}
                    Ok(Some(event)) => return Poll::Ready(Some(event)),
                }
            }
        }

        match this.active_sessions.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(termination_ctx)) => {
                let router_id = termination_ctx.router_id.clone();
                let reason = termination_ctx.reason;
                let address = termination_ctx.address;
                let duration = termination_ctx.duration;

                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    connection_id = %termination_ctx.dst_id,
                    ?reason,
                    "terminate active ssu2 session",
                );

                this.peer_test_manager.remove_session(&router_id);
                if this.relay_manager.register_closed_connection(&router_id) {
                    this.pending_events.push_back(TransportEvent::IntroducerRemoved {
                        router_id: router_id.clone(),
                        ipv4: address.is_ipv4(),
                    })
                }
                this.terminating_session.push(TerminatingSsu2Session::<R>::new(termination_ctx));
                this.router_ctx.metrics_handle().gauge(NUM_ACTIVE_CONNECTIONS).decrement(1);
                this.router_ctx
                    .metrics_handle()
                    .counter(CONNECTIONS_CLOSED)
                    .increment_with_label(1, "reason", reason.into());
                this.router_ctx
                    .metrics_handle()
                    .histogram(SESSION_DURATION)
                    .record(duration.as_secs() as f64);
                this.num_connections = this.num_connections.saturating_sub(1);

                return Poll::Ready(Some(TransportEvent::ConnectionClosed { router_id, reason }));
            }
        }

        loop {
            match this.terminating_session.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some((router_id, connection_id))) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        %router_id,
                        %connection_id,
                        "active ssu2 session terminated",
                    );

                    // TODO: correct connection id for inbound?
                    this.sessions.remove(&connection_id);
                }
            }
        }

        loop {
            match this.pending_sessions.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(status)) => {
                    this.router_ctx
                        .metrics_handle()
                        .histogram(HANDSHAKE_DURATION)
                        .record(status.duration());

                    match &status {
                        PendingSsu2SessionStatus::NewInboundSession { .. }
                        | PendingSsu2SessionStatus::NewOutboundSession { .. } => this
                            .router_ctx
                            .metrics_handle()
                            .counter(NUM_HANDSHAKE_SUCCESSES)
                            .increment(1),
                        PendingSsu2SessionStatus::Timeout { .. } => {
                            this.router_ctx
                                .metrics_handle()
                                .counter(NUM_HANDSHAKE_FAILURES)
                                .increment_with_label(1, "reason", "timeout");
                        }
                        PendingSsu2SessionStatus::SessionTerminated {
                            reason,
                            address,
                            connection_id,
                            ..
                        } => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?connection_id,
                                ?address,
                                ?reason,
                                "handshake terminated",
                            );

                            this.router_ctx
                                .metrics_handle()
                                .counter(NUM_HANDSHAKE_FAILURES)
                                .increment_with_label(1, "reason", (*reason).into());
                        }
                        PendingSsu2SessionStatus::SocketClosed { .. } => {
                            this.router_ctx
                                .metrics_handle()
                                .counter(NUM_HANDSHAKE_FAILURES)
                                .increment_with_label(1, "reason", "socket");
                        }
                    }

                    match status {
                        PendingSsu2SessionStatus::NewInboundSession {
                            context,
                            dst_id,
                            pkt,
                            target,
                            k_header_2,
                            router_info,
                            serialized,
                            relay_tag_request,
                            encryption,
                            ..
                        } => {
                            let router_id = context.router_id.clone();

                            // add router to router storage so we can later on use it for outbound
                            // connections
                            this.router_ctx
                                .profile_storage()
                                .discover_router(*router_info, serialized);

                            match this.unvalidated_sessions.get(&router_id) {
                                None => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        %router_id,
                                        connection_id = ?context.dst_id,
                                        "inbound session negotiated",
                                    );

                                    this.unvalidated_sessions.insert(
                                        router_id.clone(),
                                        PendingSessionKind::Inbound {
                                            pkt,
                                            address: target,
                                            context,
                                            dst_id,
                                            k_header_2,
                                            relay_tag_request,
                                        },
                                    );

                                    return Poll::Ready(Some(
                                        TransportEvent::ConnectionEstablished {
                                            address: target,
                                            direction: Direction::Inbound,
                                            encryption,
                                            router_id,
                                        },
                                    ));
                                }
                                Some(kind) => tracing::warn!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    connection_id = ?context.dst_id,
                                    ?kind,
                                    "inbound session negotiated but already pending, rejecting",
                                ),
                            }
                        }
                        PendingSsu2SessionStatus::NewOutboundSession {
                            context,
                            src_id,
                            started: _,
                            external_address,
                            relay_tag,
                            encryption,
                        } => {
                            let router_id = context.router_id.clone();
                            let remote_address = context.address;

                            tracing::trace!(
                                target: LOG_TARGET,
                                %router_id,
                                connection_id = ?context.dst_id,
                                "outbound session negotiated",
                            );

                            if let Some(kind) = this.unvalidated_sessions.insert(
                                router_id.clone(),
                                PendingSessionKind::Outbound {
                                    address: context.address,
                                    context,
                                    src_id,
                                    relay_tag,
                                },
                            ) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    ?kind,
                                    "unvalidated session already exists",
                                );
                                debug_assert!(false);
                            }

                            // add new external address to `PeerTestManager` and `RelayManager` so
                            // it can be used in peer tests and relay processes (if needed)
                            //
                            // also report the new address to `TransportManager`
                            if let Some(address) = external_address {
                                if let Some(address) = match address.is_ipv4() {
                                    true => this.ipv4_detector.add_external_address(address),
                                    false => this.ipv6_detector.add_external_address(address),
                                } {
                                    this.peer_test_manager.add_external_address(address);
                                    this.relay_manager.add_external_address(address);

                                    this.pending_events
                                        .push_back(TransportEvent::ExternalAddress { address });
                                }
                            }

                            return Poll::Ready(Some(TransportEvent::ConnectionEstablished {
                                address: remote_address,
                                direction: Direction::Outbound,
                                encryption,
                                router_id,
                            }));
                        }
                        PendingSsu2SessionStatus::SessionTerminated {
                            address,
                            connection_id,
                            router_id,
                            relay_tag,
                            reason,
                            ..
                        } => {
                            if let Some(tag) = relay_tag {
                                this.relay_manager.deallocate_relay_tag(tag);
                            }

                            let _channel = this.sessions.remove(&connection_id);
                            debug_assert!(_channel.is_some());

                            let Some(router_id) = router_id else {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?connection_id,
                                    ?reason,
                                    "pending inbound session terminated",
                                );
                                continue;
                            };

                            tracing::debug!(
                                target: LOG_TARGET,
                                %router_id,
                                ?connection_id,
                                "pending outbound session terminated",
                            );

                            match address {
                                Some(address) => {
                                    let _key = this.pending_outbound.remove(&address);
                                    debug_assert!(_key.is_some());
                                }
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %router_id,
                                        %connection_id,
                                        "address doens't exist for a terminated outbound connection",
                                    );
                                    debug_assert!(false);
                                }
                            }

                            return Poll::Ready(Some(TransportEvent::ConnectionFailure {
                                router_id,
                                reason: DialError::SessionTerminated(reason),
                            }));
                        }
                        PendingSsu2SessionStatus::Timeout {
                            connection_id,
                            router_id,
                            started: _,
                            address,
                        } => match router_id {
                            None => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?connection_id,
                                    "pending inbound session timed out",
                                );
                            }
                            Some(router_id) => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    %router_id,
                                    ?connection_id,
                                    "pending outbound session timed out",
                                );

                                if let Some(address) = address {
                                    this.pending_outbound.remove(&address);
                                }

                                return Poll::Ready(Some(TransportEvent::ConnectionFailure {
                                    router_id,
                                    reason: DialError::Timeout,
                                }));
                            }
                        },
                        PendingSsu2SessionStatus::SocketClosed { .. } => return Poll::Ready(None),
                    }
                }
            }
        }

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetPacket => match this.pending_pkts.pop_front() {
                    None => {
                        this.write_state = WriteState::GetPacket;
                        break;
                    }
                    Some((pkt, target)) => {
                        this.write_state = WriteState::SendPacket { pkt, target };
                    }
                },
                WriteState::SendPacket { pkt, target } => {
                    let socket = match target.is_ipv4() {
                        true => this.ipv4_socket.as_mut().expect("ipv4 socket to exist"),
                        false => this.ipv6_socket.as_mut().expect("ipv4 socket to exist"),
                    };

                    match Pin::new(socket).poll_send_to(cx, &pkt, target) {
                        Poll::Ready(Some(nwritten)) => {
                            this.router_ctx
                                .metrics_handle()
                                .counter(OUTBOUND_BANDWIDTH)
                                .increment(nwritten);
                            this.router_ctx.metrics_handle().counter(OUTBOUND_PKTS).increment(1);

                            this.write_state = WriteState::GetPacket;
                        }
                        Poll::Ready(None) => return Poll::Ready(None),
                        Poll::Pending => {
                            this.write_state = WriteState::SendPacket { pkt, target };
                            break;
                        }
                    }
                }
                WriteState::Poisoned => unreachable!(),
            }
        }

        match this.peer_test_manager.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(PeerTestManagerEvent::PeerTestResult { results })) => {
                let mut ipv4_status = Option::<FirewallStatus>::None;
                let mut ipv6_status = Option::<FirewallStatus>::None;

                for result in results {
                    if result.3 {
                        let status =
                            this.ipv4_detector.add_peer_test_result(result.0, result.1, result.2);

                        match (ipv4_status, status) {
                            (None, None) => {}
                            (None, Some(event)) => {
                                ipv4_status = Some(event);
                            }
                            (Some(_), Some(event)) => {
                                ipv4_status = Some(event);
                            }
                            (Some(_), None) => {}
                        }
                    } else {
                        let status =
                            this.ipv6_detector.add_peer_test_result(result.0, result.1, result.2);

                        match (ipv6_status, status) {
                            (None, None) => {}
                            (None, Some(event)) => {
                                ipv6_status = Some(event);
                            }
                            (Some(_), Some(event)) => {
                                ipv6_status = Some(event);
                            }
                            (Some(_), None) => {}
                        }
                    };
                }

                match (ipv4_status, ipv6_status) {
                    (None, None) => {}
                    (Some(status), None) =>
                        return Poll::Ready(Some(TransportEvent::FirewallStatus {
                            status,
                            ipv4: true,
                        })),
                    (None, Some(status)) =>
                        return Poll::Ready(Some(TransportEvent::FirewallStatus {
                            status,
                            ipv4: false,
                        })),
                    (Some(ipv4_status), Some(ipv6_status)) => {
                        this.pending_events.push_back(TransportEvent::FirewallStatus {
                            status: ipv6_status,
                            ipv4: false,
                        });

                        return Poll::Ready(Some(TransportEvent::FirewallStatus {
                            status: ipv4_status,
                            ipv4: false,
                        }));
                    }
                }
            }
        }

        loop {
            match this.relay_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {}
                Poll::Ready(Some(RelayManagerEvent::SessionRequestToken { token })) => {
                    this.tokens.insert(token);
                }
                Poll::Ready(Some(RelayManagerEvent::IntroducerExpired { router_id, ipv4 })) =>
                    return Poll::Ready(Some(TransportEvent::IntroducerRemoved { router_id, ipv4 })),
                Poll::Ready(Some(RelayManagerEvent::RelayFailure { router_id })) =>
                    return Poll::Ready(Some(TransportEvent::ConnectionFailure {
                        router_id,
                        reason: DialError::RelayFailure,
                    })),
                Poll::Ready(Some(RelayManagerEvent::RelaySuccess {
                    address,
                    router_id,
                    token,
                })) => this.send_session_request(router_id, address, token),
            }
        }

        this.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
