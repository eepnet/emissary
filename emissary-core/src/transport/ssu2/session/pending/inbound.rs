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
    constants::{crypto::POLY1305_MAC_SIZE, ssu2},
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, EphemeralPrivateKey, EphemeralPublicKey,
        StaticPrivateKey, StaticPublicKey,
    },
    error::Ssu2Error,
    primitives::RouterAddress,
    runtime::{Runtime, UdpSocket},
    transport::{
        ssu2::{
            message::{
                data::DataMessageBuilder,
                handshake::{RetryBuilder, SessionCreatedBuilder},
                Block, HeaderKind, HeaderReader,
            },
            relay::types::RelayTagRequested,
            session::{
                active::Ssu2SessionContext,
                pending::{
                    EncryptionContext, PacketKind, PacketRetransmitter, PacketRetransmitterEvent,
                    PendingSsu2SessionStatus, MAX_CLOCK_SKEW,
                },
                KeyContext,
            },
            Packet,
        },
        EncryptionKind, TerminationReason,
    },
};

use futures::FutureExt;
use rand::Rng;
use thingbuf::mpsc::Receiver;
use zeroize::Zeroize;

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use core::{
    fmt,
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::pending::inbound";

/// Timeout for receicing [`SessionRequest`] from Bob.
const SESSION_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Inbound SSU2 session context.
pub struct InboundSsu2Context<R: Runtime> {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Encryption context.
    pub encryption_ctx: EncryptionContext,

    /// Local intro key.
    pub intro_key: [u8; 32],

    /// Maximum payload size.
    pub max_payload_size: usize,

    /// Our MTU size for `address`.
    pub mtu: usize,

    /// Net ID.
    pub net_id: u8,

    /// `TokenRequest` packet.
    pub pkt: Vec<u8>,

    /// Packet number.
    pub pkt_num: u32,

    /// Relay tag, if requested by remote router.
    pub relay_tag: u32,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    pub rx: Receiver<Packet>,

    /// UDP socket.
    pub socket: R::UdpSocket,

    /// Source connection ID.
    pub src_id: u64,

    /// Local static key.
    pub static_key: StaticPrivateKey,
}

/// Session request payload.
///
/// Depending on how the inbound session was started (`TokenRequest` vs `SessionRequest`),
/// `InboundSsu2Session::on_session_request()` must handle the inbound `SessionRequest` message
/// differently because if the message was received directly (as a result of a succesful relay
/// process), the header has already been decrypted and don't need to be decrypted again.
enum SessionRequestPayload {
    /// Handle `SessionRequest` from an unparsed datagram.
    Packet {
        /// Datagram.
        pkt: Vec<u8>,

        /// Token that was generated and sent in `Retry` message.
        token: u64,
    },

    /// Handle `SessionRequest` using a parsed context.
    Context {
        /// Ephemereal public key of remote router.
        ephemeral_key: EphemeralPublicKey,

        /// Datagram.
        pkt: Vec<u8>,
    },
}

/// Pending session state.
enum PendingSessionState {
    /// Handle inbound `TokenRequest`.
    HandleTokenRequest {
        /// Message blocks of `TokenRequest` message.
        blocks: Vec<Block>,
    },

    /// Handle inbound `SessionRequest` with a token
    ///
    /// This inbound session is created as a result of a succesful relay process.
    HandleSessionRequest {
        /// `SessionRequest` payload.
        payload: SessionRequestPayload,
    },

    /// Awaiting `SessionRequest` message from remote router.
    AwaitingSessionRequest {
        /// Generated token.
        token: u64,
    },

    /// Awaiting `SessionConfirmed` message from remote router.
    AwaitingSessionConfirmed {
        /// Our ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// `SessionConfirmed` fragments.
        ///
        /// Empty if `SessionConfirmed` is unfragmented.
        fragments: BTreeMap<usize, Vec<u8>>,

        /// Cipher key for decrypting the second part of the header
        k_header_2: [u8; 32],

        /// Key for decrypting the `SessionCreated` message.
        k_session_created: [u8; 32],
    },

    /// State has been poisoned.
    Poisoned,
}

impl fmt::Debug for PendingSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandleTokenRequest { .. } => f
                .debug_struct("PendingSessionState::HandleTokenRequest")
                .finish_non_exhaustive(),
            Self::HandleSessionRequest { .. } => f
                .debug_struct("PendingSessionState::HandleSessionRequest")
                .finish_non_exhaustive(),
            Self::AwaitingSessionRequest { .. } => f
                .debug_struct("PendingSessionState::AwaitingSessionRequest")
                .finish_non_exhaustive(),
            Self::AwaitingSessionConfirmed { .. } => f
                .debug_struct("PendingSessionState::AwaitingSessionConfirmed")
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("PendingSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
}

/// Pending inbound SSU2 session.
pub struct InboundSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Encryption context.
    encryption_ctx: EncryptionContext,

    /// Local intro key.
    intro_key: [u8; 32],

    /// Maximum payload size.
    max_payload_size: usize,

    /// Our MTU size for `address`.
    mtu: usize,

    /// Net ID.
    net_id: u8,

    /// Packet retransmitter.
    pkt_retransmitter: PacketRetransmitter<R>,

    /// Has remote router requested a relay tag from us?
    ///
    /// Initialized to `RelayTagRequested::No(tag)` and upgraded to `RelayTagRequested::Yes(tag)`
    /// if a tag request is received.
    relay_tag_requested: RelayTagRequested,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Source connection ID.
    src_id: u64,

    /// When was the handshake started.
    started: R::Instant,

    /// Pending session state.
    state: PendingSessionState,

    /// Local SSU2 static key.
    static_key: StaticPrivateKey,

    /// Write buffer.
    write_buffer: VecDeque<Vec<u8>>,
}

impl<R: Runtime> InboundSsu2Session<R> {
    /// Create new [`PendingSsu2Session`].
    ///
    /// Decrypt the `TokenRequest` payload, locate the `DateTime` block and check clock skew of the
    /// remote router.
    ///
    /// If the block doesn't exist or clock skew is more than `MAX_CLOCK_SKEW`, send `Retry` with a
    /// termination block and return an error, indicating that the inbound session cannot be
    /// started.
    pub fn new(context: InboundSsu2Context<R>) -> Result<Self, Ssu2Error> {
        let InboundSsu2Context {
            address,
            dst_id,
            encryption_ctx,
            intro_key,
            max_payload_size,
            mtu,
            net_id,
            pkt,
            pkt_num,
            relay_tag,
            rx,
            socket,
            src_id,
            static_key,
        } = context;

        tracing::trace!(
            target: LOG_TARGET,
            ?src_id,
            ?dst_id,
            kind = %encryption_ctx,
            "create inbound session from TokenRequest",
        );

        let mut payload = pkt[32..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&intro_key, pkt_num as u64)
            .decrypt_with_ad(&pkt[..32], &mut payload)?;

        let blocks = Block::parse::<R>(&payload).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_id,
                ?src_id,
                ?error,
                "failed to parse message blocks",
            );
            debug_assert!(false);

            Ssu2Error::Malformed
        })?;

        Ok(Self {
            address,
            dst_id,
            encryption_ctx,
            intro_key,
            max_payload_size,
            mtu,
            net_id,
            pkt_retransmitter: PacketRetransmitter::inactive(SESSION_REQUEST_TIMEOUT),
            relay_tag_requested: RelayTagRequested::No(relay_tag),
            rx: Some(rx),
            socket,
            src_id,
            started: R::now(),
            state: PendingSessionState::HandleTokenRequest { blocks },
            static_key,
            write_buffer: VecDeque::new(),
        })
    }

    /// Create new [`PendingSsu2Session`] from `SessionRequest`.
    ///
    /// The `SessionRequest` was received after a succesful relay process and the remote router used
    /// a token that was generated by the local router and sent in a `RelayResponse` message.
    ///
    /// The handshake directly proceeds to `InboundSsu2Session::on_session_request()` from which on
    /// it follows the same flow as if `TokenRequest` was received.
    pub fn from_session_request(
        context: InboundSsu2Context<R>,
        ephemeral_key: EphemeralPublicKey,
        token: u64,
    ) -> Self {
        let InboundSsu2Context {
            address,
            dst_id,
            encryption_ctx,
            intro_key,
            max_payload_size,
            mtu,
            net_id,
            pkt,
            relay_tag,
            rx,
            socket,
            src_id,
            static_key,
            ..
        } = context;

        tracing::debug!(
            target: LOG_TARGET,
            ?src_id,
            ?dst_id,
            ?token,
            kind = %encryption_ctx,
            "create inbound session from SessionRequest",
        );

        Self {
            address,
            dst_id,
            encryption_ctx,
            intro_key,
            max_payload_size,
            mtu,
            net_id,
            pkt_retransmitter: PacketRetransmitter::inactive(SESSION_REQUEST_TIMEOUT),
            relay_tag_requested: RelayTagRequested::No(relay_tag),
            rx: Some(rx),
            socket,
            src_id,
            started: R::now(),
            state: PendingSessionState::HandleSessionRequest {
                payload: SessionRequestPayload::Context { ephemeral_key, pkt },
            },
            static_key,
            write_buffer: VecDeque::new(),
        }
    }

    /// Check clock skew of remote router.
    ///
    /// If `blocks` doesn't contain `DateTime` block or the timestamp is either too far in the past
    /// or future, send `Retry` message with a termination block and return error.
    fn check_clock_skew(&mut self, blocks: &[Block]) -> Result<(), Ssu2Error> {
        let Some(Block::DateTime { timestamp }) =
            blocks.iter().find(|block| core::matches!(block, Block::DateTime { .. }))
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "date time block not found from SessionRequest",
            );
            return Err(Ssu2Error::Malformed);
        };

        let now = R::time_since_epoch();
        let remote_time = Duration::from_secs(*timestamp as u64);
        let future = remote_time.saturating_sub(now);
        let past = now.saturating_sub(remote_time);

        if past <= MAX_CLOCK_SKEW && future <= MAX_CLOCK_SKEW {
            return Ok(());
        }

        tracing::warn!(
            target: LOG_TARGET,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            our_time = ?now,
            ?remote_time,
            ?past,
            ?future,
            "excessive clock skew",
        );

        self.write_buffer.push_back(
            RetryBuilder::default()
                .with_k_header_1(self.intro_key)
                .with_version(self.encryption_ctx.version())
                .with_src_id(self.dst_id)
                .with_dst_id(self.src_id)
                .with_token(0)
                .with_termination(TerminationReason::ClockSkew)
                .with_address(self.address)
                .with_net_id(self.net_id)
                .build::<R>()
                .to_vec(),
        );

        Err(Ssu2Error::SessionTerminated(TerminationReason::ClockSkew))
    }

    /// Handle `SessionRequest` message.
    ///
    /// If `payload` is `SessionRequestPayload::Context`, extract context from pre-parsed request.
    ///
    /// If `payload` is `SessionRequestPayload::Packet`, attempt to parse `pkt` into
    /// `SessionRequest` and if it succeeds, verify that the token it contains is the once that was
    /// sent in `Retry`.
    ///
    /// Send `SessionCreated` as a reply and transition the inbound state to
    /// [`PendingSessionState::AwaitingSessionConfirmed`].
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-request>
    /// <https://geti2p.net/spec/ssu2#sessionrequest-type-0>
    fn on_session_request(
        &mut self,
        payload: SessionRequestPayload,
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        let (ephemeral_key, pkt) = match payload {
            SessionRequestPayload::Context { ephemeral_key, pkt } => (ephemeral_key, pkt),
            SessionRequestPayload::Packet { mut pkt, token } => {
                let (ephemeral_key, pkt_num, recv_token) =
                    match HeaderReader::new(self.intro_key, &mut pkt)?.parse(self.intro_key)? {
                        HeaderKind::SessionRequest {
                            ephemeral_key,
                            net_id,
                            pkt_num,
                            token,
                            ..
                        } => {
                            if self.net_id != net_id {
                                return Err(Ssu2Error::NetworkMismatch);
                            }

                            (ephemeral_key, pkt_num, token)
                        }
                        HeaderKind::TokenRequest {
                            net_id,
                            pkt_num,
                            src_id,
                            ..
                        } => {
                            if self.net_id != net_id {
                                return Err(Ssu2Error::NetworkMismatch);
                            }

                            let token = R::rng().next_u64();
                            let pkt = RetryBuilder::default()
                                .with_k_header_1(self.intro_key)
                                .with_version(self.encryption_ctx.version())
                                .with_src_id(self.dst_id)
                                .with_dst_id(src_id)
                                .with_token(token)
                                .with_address(self.address)
                                .with_net_id(self.net_id)
                                .build::<R>()
                                .to_vec();

                            tracing::debug!(
                                target: LOG_TARGET,
                                local_dst_id = ?self.dst_id,
                                local_src_id = ?self.src_id,
                                remote_src_id = ?src_id,
                                ?pkt_num,
                                ?token,
                                "received unexpected TokenRequest",
                            );

                            self.write_buffer.push_back(pkt);
                            self.state = PendingSessionState::AwaitingSessionRequest { token };

                            return Ok(None);
                        }
                        kind => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                dst_id = ?self.dst_id,
                                src_id = ?self.src_id,
                                ?kind,
                                "unexpected message, expected SessionRequest",
                            );
                            return Err(Ssu2Error::UnexpectedMessage);
                        }
                    };

                tracing::trace!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?pkt_num,
                    ?token,
                    ?recv_token,
                    "handle SessionRequest",
                );

                if token != recv_token {
                    tracing::debug!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?pkt_num,
                        ?token,
                        ?recv_token,
                        "token mismatch",
                    );

                    return Err(Ssu2Error::TokenMismatch);
                }

                (ephemeral_key, pkt)
            }
        };

        // MixHash(header), MiXHash(aepk)
        self.encryption_ctx.noise_ctx().mix_hash(&pkt[..32]).mix_hash(&pkt[32..64]);

        // MixKey(DH()), ee
        let mut cipher_key =
            self.encryption_ctx.noise_ctx().mix_key(&self.static_key, &ephemeral_key);

        // derive header encryption key for the header of `SessionCreated`
        let temp_key =
            Hmac::new(self.encryption_ctx.noise_ctx().chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize_new();

        // e1
        //
        // https://i2p.net/en/docs/specs/ssu2-hybrid/#bob-kdf-for-message-1
        let (nonce, offset, encapsulation_key) = match &mut self.encryption_ctx {
            EncryptionContext::MlKem1024X25519(_) => unreachable!(),
            EncryptionContext::X25519(_) => (0u64, 64usize, None),
            kind => {
                let encap_size = kind.encapsulation_key_size() + POLY1305_MAC_SIZE;

                if pkt.len() < encap_size + 64 {
                    tracing::debug!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        %kind,
                        size = pkt.len(),
                        expected = ?(encap_size + 64),
                        "SessionRequest is too short for ml-kem",
                    );
                    return Err(Ssu2Error::NotEnoughBytes);
                }

                let mut encap_key = pkt[64..64 + encap_size].to_vec();

                ChaChaPoly::new(&cipher_key)
                    .decrypt_with_ad(kind.noise_ctx().state(), &mut encap_key)?;

                // MixHash(encap_key_section)
                kind.noise_ctx().mix_hash(&pkt[64..64 + encap_size]);

                (1u64, 64usize + encap_size, Some(encap_key))
            }
        };

        if pkt.len() <= offset {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                size = ?pkt.len(),
                expected = ?offset,
                "SessionRequest is too small",
            );
            return Err(Ssu2Error::NotEnoughBytes);
        }

        // decrypt payload
        let mut payload = pkt[offset..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, nonce)
            .decrypt_with_ad(self.encryption_ctx.noise_ctx().state(), &mut payload)?;
        cipher_key.zeroize();

        // MixHash(ciphertext)
        self.encryption_ctx.noise_ctx().mix_hash(&pkt[offset..pkt.len()]);

        let blocks = Block::parse::<R>(&payload).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                ?error,
                "malformed SessionRequest payload",
            );
            debug_assert!(false);
            Ssu2Error::Malformed
        })?;
        self.check_clock_skew(&blocks)?;

        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public();

        // MixKey(DH()), ee
        let cipher_key = self.encryption_ctx.noise_ctx().mix_key(&sk, &ephemeral_key);

        // `SessionCreated` must be partially constructed prior to `ekem1` since
        // associated data for `kem_ciphertext` depends on the header
        let builder = SessionCreatedBuilder::default()
            .with_address(self.address)
            .with_version(self.encryption_ctx.version())
            .with_max_payload_size(self.max_payload_size)
            .with_dst_id(self.src_id)
            .with_src_id(self.dst_id)
            .with_net_id(self.net_id)
            .with_ephemeral_key(pk.clone())
            .build_header::<R>();

        // MixHash(header), MixHash(bepk)
        self.encryption_ctx.noise_ctx().mix_hash(builder.header()).mix_hash(&pk);

        // ekem1
        //
        // https://i2p.net/en/docs/specs/ssu2-hybrid/#bob-kdf-for-message-2
        let (cipher_key, builder) = match &mut self.encryption_ctx {
            EncryptionContext::MlKem1024X25519(_) => unreachable!(),
            EncryptionContext::X25519(_) => (cipher_key, builder),
            kind => {
                // `encapsulation_key` must exist since this is an ml-kem connection
                let (mut ciphertext, shared_key) = kind
                    .encapsulate::<R>(encapsulation_key.expect("to exist").as_slice())
                    .ok_or(Ssu2Error::Malformed)?;

                ChaChaPoly::new(&cipher_key)
                    .encrypt_with_ad_new(kind.noise_ctx().state(), &mut ciphertext)?;

                // MixHash(ciphertext)
                kind.noise_ctx().mix_hash(&ciphertext);

                // MixKey(kem_shared_key)
                let local_key = kind.noise_ctx().mix_key_from_shared_secret(&shared_key);

                (local_key, builder.with_kem_ciphertext(ciphertext))
            }
        };

        // check if remoted requested relay from us
        //
        // if so, include the relay tag in the `SessionCreated` message
        let mut message =
            if blocks.iter().any(|block| core::matches!(block, Block::RelayTagRequest)) {
                let relay_tag = self.relay_tag_requested.tag();
                self.relay_tag_requested = RelayTagRequested::Yes(relay_tag);

                tracing::trace!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?relay_tag,
                    "include relay tag in SessionCreated",
                );

                builder.with_relay_tag(relay_tag)
            } else {
                builder
            }
            .build::<R>();

        message.encrypt_payload(&cipher_key, 0u64, self.encryption_ctx.noise_ctx().state());
        message.encrypt_header(self.intro_key, k_header_2);

        // MixHash(ciphertext)
        self.encryption_ctx.noise_ctx().mix_hash(message.payload());

        // reset packet retransmitter to track `SessionConfirmed` and send the message to remote
        let pkt = message.build().to_vec();
        self.pkt_retransmitter = PacketRetransmitter::session_created(pkt.clone());
        self.write_buffer.push_back(pkt);

        // create new session
        let temp_key =
            Hmac::new(self.encryption_ctx.noise_ctx().chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize_new();

        self.state = PendingSessionState::AwaitingSessionConfirmed {
            ephemeral_key: sk,
            fragments: BTreeMap::new(),
            k_header_2,
            k_session_created: cipher_key,
        };

        Ok(None)
    }

    /// Handle `SessionConfirmed` message.
    ///
    /// Attempt to parse `pkt` into `SessionConfirmed` and if it succeeds, derive data phase keys
    /// and send an ACK for the message. Return context for an active session and destroy this
    /// future, allowing [`Ssu2Socket`] to create a new future for the active session.
    ///
    /// `SessionConfirmed` must contain a valid router info.
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-confirmed-part-1-using-session-created-kdf>
    /// <https://geti2p.net/spec/ssu2#sessionconfirmed-type-2>
    /// <https://geti2p.net/spec/ssu2#kdf-for-data-phase>
    fn on_session_confirmed(
        &mut self,
        mut pkt: Vec<u8>,
        mut fragments: BTreeMap<usize, Vec<u8>>,
        ephemeral_key: EphemeralPrivateKey,
        k_header_2: [u8; 32],
        k_session_created: [u8; 32],
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        let (num_fragments, fragment) =
            match HeaderReader::new(self.intro_key, &mut pkt)?.parse(k_header_2) {
                Ok(HeaderKind::SessionConfirmed {
                    fragment,
                    num_fragments,
                    ..
                }) => (num_fragments, fragment),
                kind => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?kind,
                        "unexpected message, expected SessionConfirmed",
                    );

                    self.state = PendingSessionState::AwaitingSessionConfirmed {
                        ephemeral_key,
                        fragments,
                        k_header_2,
                        k_session_created,
                    };
                    return Ok(None);
                }
            };

        // handle fragmented `SessionConfirmed`
        //
        // if all fragments have not been received, store the current fragment
        // in pending state and return early
        //
        // if all fragments have been received, reassemble `SessionConfirmed`
        // and proceed normally
        if num_fragments > 1 {
            fragments.insert(fragment, pkt);

            if fragments.len() != num_fragments {
                tracing::trace!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?num_fragments,
                    num_received = ?fragments.len(),
                    "awaiting remaining fragments for SessionConfirmed",
                );

                self.state = PendingSessionState::AwaitingSessionConfirmed {
                    ephemeral_key,
                    fragments,
                    k_header_2,
                    k_session_created,
                };
                return Ok(None);
            }

            // header of the first fragment is used as the header for the jumbo packet
            //
            // https://i2p.net/en/docs/specs/ssu2/#session-confirmed-fragmentation
            pkt = fragments.into_iter().fold(Vec::with_capacity(2048), |mut out, (i, pkt)| {
                if i == 0 {
                    out.extend(&pkt);
                } else {
                    // call to `HeaderReader` above has ensured `pkt` is at least 24 bytes long
                    out.extend(&pkt[16..]);
                }

                out
            });
        }

        tracing::trace!(
            target: LOG_TARGET,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle SessionConfirmed",
        );

        // MixHash(header)
        self.encryption_ctx.noise_ctx().mix_hash(&pkt[..16]);

        let mut static_key = pkt[16..64].to_vec();
        ChaChaPoly::with_nonce(&k_session_created, 1u64)
            .decrypt_with_ad(self.encryption_ctx.noise_ctx().state(), &mut static_key)?;

        // MixHash(apk)
        self.encryption_ctx.noise_ctx().mix_hash(&pkt[16..64]);

        // MixKey(DH())
        let mut cipher_key = self.encryption_ctx.noise_ctx().mix_key(
            &ephemeral_key,
            &StaticPublicKey::try_from_bytes(&static_key).expect("to succeed"),
        );

        // decrypt payload
        let mut payload = pkt[64..].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(self.encryption_ctx.noise_ctx().state(), &mut payload)?;
        cipher_key.zeroize();

        let blocks = Block::parse::<R>(&payload).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to parse message blocks of SessionConfirmed",
            );
            debug_assert!(false);
            Ssu2Error::Malformed
        })?;

        let Some(Block::RouterInfo {
            router_info,
            serialized,
        }) = blocks.into_iter().find(|block| core::matches!(block, Block::RouterInfo { .. }))
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "SessionConfirmed doesn't include router info block",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };

        let Some(RouterAddress::Ssu2 { intro_key, .. }) = router_info
            .addresses()
            .find(|address| core::matches!(address, RouterAddress::Ssu2 { .. }))
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "no ssu2 transport found",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };

        let verifying_key = router_info.identity.signing_key().clone();
        let temp_key =
            Hmac::new(self.encryption_ctx.noise_ctx().chaining_key()).update([]).finalize();
        let k_ab = Hmac::new(&temp_key).update([0x01]).finalize();
        let k_ba = Hmac::new(&temp_key).update(&k_ab).update([0x02]).finalize();

        let temp_key = Hmac::new(&k_ab).update([]).finalize();
        let k_data_ab =
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize_new();
        let k_header_2_ab = Hmac::new(&temp_key)
            .update(k_data_ab)
            .update(b"HKDFSSU2DataKeys")
            .update([0x02])
            .finalize_new();

        let temp_key = Hmac::new(&k_ba).update([]).finalize();
        let k_data_ba =
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize_new();
        let k_header_2_ba = Hmac::new(&temp_key)
            .update(k_data_ba)
            .update(b"HKDFSSU2DataKeys")
            .update([0x02])
            .finalize_new();

        let pkt = DataMessageBuilder::default()
            .with_dst_id(self.src_id)
            .with_pkt_num(0u32)
            .with_key_context(
                *intro_key,
                &KeyContext {
                    k_data: k_data_ba,
                    k_header_2: k_header_2_ba,
                },
            )
            .with_ack(0u32, 0u8, None)
            .build::<R>();

        // calculate maximum payload size
        let max_payload_size = {
            let remote_mtu = router_info
                .addresses()
                .find_map(|address| match address {
                    RouterAddress::Ntcp2 { .. } => None,
                    RouterAddress::Ssu2 { mtu, .. } => Some(*mtu),
                })
                .unwrap_or(1500);

            match self.address {
                SocketAddr::V4(_) => self.mtu.min(remote_mtu) - ssu2::IPV4_OVERHEAD,
                SocketAddr::V6(_) => self.mtu.min(remote_mtu) - ssu2::IPV6_OVERHEAD,
            }
        };

        Ok(Some(PendingSsu2SessionStatus::NewInboundSession {
            context: Ssu2SessionContext {
                address: self.address,
                dst_id: self.src_id,
                intro_key: *intro_key,
                max_payload_size,
                pkt_rx: self.rx.take().expect("to exist"),
                recv_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                router_id: router_info.identity.id(),
                send_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                verifying_key,
            },
            dst_id: self.dst_id,
            k_header_2,
            pkt,
            router_info,
            relay_tag_request: self.relay_tag_requested,
            serialized,
            started: self.started,
            target: self.address,
            encryption: match self.encryption_ctx {
                EncryptionContext::X25519(_) => EncryptionKind::X25519,
                EncryptionContext::MlKem512X25519(_) => EncryptionKind::MlKem512X25519,
                EncryptionContext::MlKem768X25519(_) => EncryptionKind::MlKem768X25519,
                EncryptionContext::MlKem1024X25519(_) => unreachable!(),
            },
        }))
    }

    /// Handle received packet to a pending session.
    ///
    /// `pkt` contains the full header but the first part of the header has been decrypted by the
    /// `Ssu2Socket`, meaning only the second part of the header must be decrypted by us.
    fn on_packet(
        &mut self,
        pkt: Vec<u8>,
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::AwaitingSessionRequest { token } =>
                self.on_session_request(SessionRequestPayload::Packet { pkt, token }),
            PendingSessionState::AwaitingSessionConfirmed {
                ephemeral_key,
                fragments,
                k_header_2,
                k_session_created,
            } => self.on_session_confirmed(
                pkt,
                fragments,
                ephemeral_key,
                k_header_2,
                k_session_created,
            ),
            PendingSessionState::Poisoned
            | PendingSessionState::HandleTokenRequest { .. }
            | PendingSessionState::HandleSessionRequest { .. } => {
                tracing::warn!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    "inbound session state is poisoned",
                );
                debug_assert!(false);

                Ok(Some(PendingSsu2SessionStatus::SessionTerminated {
                    address: None,
                    connection_id: self.dst_id,
                    relay_tag: Some(self.relay_tag_requested.tag()),
                    router_id: None,
                    started: self.started,
                    reason: TerminationReason::Unspecified,
                }))
            }
        }
    }

    /// Run the event loop of [`InboundSsu2Session`].
    ///
    /// Polls the inner future and after it completes, flushes all pending packets.
    pub async fn run(mut self) -> PendingSsu2SessionStatus<R> {
        {
            match core::mem::replace(&mut self.state, PendingSessionState::Poisoned) {
                PendingSessionState::HandleTokenRequest { ref blocks } => {
                    let Ok(()) = self.check_clock_skew(blocks) else {
                        // packet must exist since it was created by `check_clock_skew()`
                        let pkt = self.write_buffer.pop_back().expect("packet to exist");

                        if self.socket.send_to(&pkt, self.address).await.is_none() {
                            tracing::warn!(
                                target: LOG_TARGET,
                                dst_id = %self.dst_id,
                                src_id = %self.src_id,
                                "failed to send Retry with termination",
                            );
                        }

                        return PendingSsu2SessionStatus::SessionTerminated {
                            address: None,
                            connection_id: self.dst_id,
                            relay_tag: Some(self.relay_tag_requested.tag()),
                            router_id: None,
                            started: self.started,
                            reason: TerminationReason::ClockSkew,
                        };
                    };

                    let token = R::rng().next_u64();

                    tracing::trace!(
                        target: LOG_TARGET,
                        dst_id = %self.dst_id,
                        src_id = %self.src_id,
                        ?token,
                        "handle TokenRequest",
                    );

                    let pkt = RetryBuilder::default()
                        .with_k_header_1(self.intro_key)
                        .with_version(self.encryption_ctx.version())
                        .with_src_id(self.dst_id)
                        .with_dst_id(self.src_id)
                        .with_address(self.address)
                        .with_net_id(self.net_id)
                        .with_token(token)
                        .build::<R>();

                    if self.socket.send_to(&pkt, self.address).await.is_none() {
                        tracing::warn!(
                            target: LOG_TARGET,
                            dst_id = %self.dst_id,
                            src_id = %self.src_id,
                            ?token,
                            "failed to send Retry",
                        );
                    }

                    self.state = PendingSessionState::AwaitingSessionRequest { token };
                }
                PendingSessionState::HandleSessionRequest { payload } =>
                    match self.on_session_request(payload) {
                        Ok(None) => {}
                        Ok(Some(status)) => return status,
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                dst_id = ?self.dst_id,
                                src_id = ?self.src_id,
                                ?error,
                                "failed to handle direct session confirmed",
                            );

                            return PendingSsu2SessionStatus::SessionTerminated {
                                address: None,
                                connection_id: self.dst_id,
                                relay_tag: Some(self.relay_tag_requested.tag()),
                                router_id: None,
                                started: self.started,
                                reason: error.into(),
                            };
                        }
                    },
                _ => unreachable!(),
            }
        }

        let result = (&mut self).await;

        while let Some(pkt) = self.write_buffer.pop_front() {
            if self.socket.send_to(&pkt, self.address).await.is_none() {
                tracing::warn!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    "failed to send pending packet",
                );
            }
        }

        result
    }
}

impl<R: Runtime> Future for InboundSsu2Session<R> {
    type Output = PendingSsu2SessionStatus<R>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let pkt = match &mut self.rx {
                None =>
                    return Poll::Ready(PendingSsu2SessionStatus::SocketClosed {
                        started: self.started,
                    }),
                Some(rx) => match rx.poll_recv(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) =>
                        return Poll::Ready(PendingSsu2SessionStatus::SocketClosed {
                            started: self.started,
                        }),
                    Poll::Ready(Some(Packet { pkt, .. })) => pkt,
                },
            };

            match self.on_packet(pkt) {
                Ok(None) => {}
                Ok(Some(status)) => return Poll::Ready(status),
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?error,
                        "failed to handle packet",
                    );

                    return Poll::Ready(PendingSsu2SessionStatus::SessionTerminated {
                        address: None,
                        connection_id: self.dst_id,
                        relay_tag: Some(self.relay_tag_requested.tag()),
                        router_id: None,
                        started: self.started,
                        reason: error.into(),
                    });
                }
            }
        }

        match self.pkt_retransmitter.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(PacketRetransmitterEvent::Retransmit { pkt }) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    state = ?self.state,
                    "retransmitting packet",
                );

                match pkt {
                    PacketKind::Single(pkt) => self.write_buffer.push_back(pkt),
                    PacketKind::Multi(pkts) => self.write_buffer.extend(pkts),
                }
            }
            Poll::Ready(PacketRetransmitterEvent::Timeout) =>
                return Poll::Ready(PendingSsu2SessionStatus::Timeout {
                    connection_id: self.dst_id,
                    router_id: None,
                    started: self.started,
                    address: None,
                }),
        }

        loop {
            let Some(pkt) = self.write_buffer.pop_front() else {
                return Poll::Pending;
            };

            let address = self.address;
            match Pin::new(&mut self.socket).poll_send_to(cx, &pkt, address) {
                Poll::Pending => {
                    self.write_buffer.push_front(pkt);
                    return Poll::Pending;
                }
                Poll::Ready(None) =>
                    return Poll::Ready(PendingSsu2SessionStatus::SocketClosed {
                        started: self.started,
                    }),
                Poll::Ready(Some(_)) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base64_encode, noise::NoiseContext, sha256::Sha256},
        primitives::{RouterInfoBuilder, Str},
        runtime::mock::MockRuntime,
        subsystem::SubsystemEvent,
        timeout,
        transport::ssu2::session::pending::outbound::{OutboundSsu2Context, OutboundSsu2Session},
    };
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use thingbuf::mpsc::{channel, Sender};

    struct InboundContext {
        inbound_session: InboundSsu2Session<MockRuntime>,
        inbound_session_tx: Sender<Packet>,
        inbound_socket_rx: Receiver<Packet>,
    }

    struct OutboundContext {
        outbound_intro_key: [u8; 32],
        outbound_session: OutboundSsu2Session<MockRuntime>,
        outbound_session_tx: Sender<Packet>,
        outbound_socket_rx: Receiver<Packet>,
        transport_rx: Receiver<SubsystemEvent>,
    }

    async fn create_session(
        iters: Option<usize>,
        ml_kem: Option<usize>,
    ) -> (InboundContext, OutboundContext) {
        let src_id = MockRuntime::rng().next_u64();
        let dst_id = MockRuntime::rng().next_u64();

        let (mut inbound_socket, inbound_address) = {
            let socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = socket.local_address().unwrap();

            (socket, address)
        };
        let (mut outbound_socket, outbound_address) = {
            let socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = socket.local_address().unwrap();

            (socket, address)
        };

        let outbound_static_key = StaticPrivateKey::random(MockRuntime::rng());
        let outbound_intro_key = {
            let mut key = [0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key);

            key
        };
        let inbound_static_key = StaticPrivateKey::random(MockRuntime::rng());
        let inbound_intro_key = {
            let mut key = [0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key);

            key
        };

        let (mut router_info, _, signing_key) = RouterInfoBuilder::default()
            .with_ssu2(crate::Ssu2Config {
                max_connections: None,
                disable_pq: false,
                port: outbound_address.port(),
                ipv4_host: Some(Ipv4Addr::new(127, 0, 0, 1)),
                ipv6_host: None,
                ipv4: true,
                ipv6: false,
                publish_ipv4: true,
                publish_ipv6: true,
                static_key: TryInto::<[u8; 32]>::try_into(outbound_static_key.as_ref().to_vec())
                    .unwrap(),
                intro_key: outbound_intro_key,
                ipv4_mtu: None,
                ipv6_mtu: None,
                ml_kem: None,
            })
            .build();

        let (chaining_key, inbound_state, encryption_ctx) = {
            let state = Sha256::new()
                .update(match ml_kem {
                    None => "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256".as_bytes(),
                    Some(3) => "Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256"
                        .as_bytes(),
                    Some(4) => "Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256"
                        .as_bytes(),
                    _ => unreachable!(),
                })
                .finalize_new();

            let chaining_key = state;
            let outbound_state = Sha256::new().update(&state).finalize();
            let inbound_state = Sha256::new()
                .update(&outbound_state)
                .update(inbound_static_key.public().to_vec())
                .finalize_new();

            (
                chaining_key,
                inbound_state,
                match ml_kem {
                    None => EncryptionContext::X25519(NoiseContext::new(
                        TryInto::<[u8; 32]>::try_into(chaining_key.clone()).unwrap(),
                        TryInto::<[u8; 32]>::try_into(inbound_state.clone()).unwrap(),
                    )),
                    Some(3) => {
                        let inbound_state = Sha256::new()
                            .update(inbound_state)
                            .update(router_info.identity.id().to_vec())
                            .finalize();

                        EncryptionContext::MlKem512X25519(NoiseContext::new(
                            TryInto::<[u8; 32]>::try_into(chaining_key.clone()).unwrap(),
                            TryInto::<[u8; 32]>::try_into(inbound_state.clone()).unwrap(),
                        ))
                    }
                    Some(4) => {
                        let inbound_state = Sha256::new()
                            .update(inbound_state)
                            .update(router_info.identity.id().to_vec())
                            .finalize();

                        EncryptionContext::MlKem768X25519(NoiseContext::new(
                            TryInto::<[u8; 32]>::try_into(chaining_key.clone()).unwrap(),
                            TryInto::<[u8; 32]>::try_into(inbound_state.clone()).unwrap(),
                        ))
                    }
                    _ => unreachable!(),
                },
            )
        };

        let (inbound_socket_tx, inbound_socket_rx) = channel(128);
        let (inbound_session_tx, inbound_session_rx) = channel(128);
        let (outbound_socket_tx, outbound_socket_rx) = channel(128);
        let (outbound_session_tx, outbound_session_rx) = channel(128);
        let (transport_tx, transport_rx) = channel(128);

        if let Some(iters) = iters {
            for i in 0..iters {
                router_info.options.insert(
                    Str::from(format!("garbage{i}")),
                    Str::from(base64_encode(vec![0xaa; 128])),
                );
            }
            assert!(router_info.serialize(&signing_key).len() > 1500);
        }

        let mut outbound = OutboundSsu2Session::new(OutboundSsu2Context {
            address: inbound_address,
            encryption_ctx: match ml_kem {
                None => EncryptionContext::X25519(NoiseContext::new(
                    TryInto::<[u8; 32]>::try_into(chaining_key.clone()).unwrap(),
                    TryInto::<[u8; 32]>::try_into(inbound_state.clone()).unwrap(),
                )),
                Some(3) => EncryptionContext::MlKem512X25519(NoiseContext::new(
                    TryInto::<[u8; 32]>::try_into(chaining_key.clone()).unwrap(),
                    TryInto::<[u8; 32]>::try_into(inbound_state.clone()).unwrap(),
                )),
                Some(4) => EncryptionContext::MlKem768X25519(NoiseContext::new(
                    TryInto::<[u8; 32]>::try_into(chaining_key.clone()).unwrap(),
                    TryInto::<[u8; 32]>::try_into(inbound_state.clone()).unwrap(),
                )),
                _ => unreachable!(),
            },
            dst_id,
            local_intro_key: outbound_intro_key,
            local_static_key: outbound_static_key,
            max_payload_size: 1472,
            net_id: 2u8,
            remote_intro_key: inbound_intro_key,
            request_tag: false,
            router_id: router_info.identity.id(),
            router_info: Bytes::from(router_info.serialize(&signing_key)),
            rx: outbound_session_rx,
            socket: outbound_socket.clone(),
            src_id,
            static_key: inbound_static_key.public(),
            transport_tx,
            verifying_key: signing_key.public(),
        });

        // read `Retry` from inbound socket and relay it to `outbound_socket_rx`
        let mut buffer = vec![0u8; 0xffff];

        tokio::select! {
            _ = &mut outbound => panic!("outbound session returned"),
            event = inbound_socket.recv_from(&mut buffer) => {
                let (nread, from) = event.unwrap();
                outbound_socket_tx
                    .send(Packet {
                        pkt: buffer[..nread].to_vec(),
                        address: from,
                    })
                    .await
                    .unwrap();
            }
        }

        let (pkt, pkt_num, dst_id, src_id) = {
            let Packet { mut pkt, .. } = outbound_socket_rx.try_recv().unwrap();
            let mut reader = HeaderReader::new(inbound_intro_key, &mut pkt).unwrap();
            let dst_id = reader.dst_id();

            match reader.parse(inbound_intro_key) {
                Ok(HeaderKind::TokenRequest {
                    pkt_num, src_id, ..
                }) => (pkt, pkt_num, dst_id, src_id),
                _ => panic!("invalid message"),
            }
        };

        let inbound = InboundSsu2Session::<MockRuntime>::new(InboundSsu2Context {
            address: outbound_address,
            encryption_ctx,
            dst_id,
            max_payload_size: 1472,
            intro_key: inbound_intro_key,
            mtu: 1500,
            net_id: 2u8,
            pkt,
            pkt_num,
            relay_tag: 1337,
            rx: inbound_session_rx,
            socket: inbound_socket.clone(),
            src_id,
            static_key: inbound_static_key.clone(),
        })
        .unwrap();

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 0xffff];

            loop {
                let (nread, from) = inbound_socket.recv_from(&mut buffer).await.unwrap();
                inbound_socket_tx
                    .send(Packet {
                        pkt: buffer[..nread].to_vec(),
                        address: from,
                    })
                    .await
                    .unwrap();
            }
        });

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 0xffff];

            loop {
                let (nread, from) = outbound_socket.recv_from(&mut buffer).await.unwrap();
                outbound_socket_tx
                    .send(Packet {
                        pkt: buffer[..nread].to_vec(),
                        address: from,
                    })
                    .await
                    .unwrap();
            }
        });

        (
            InboundContext {
                inbound_socket_rx,
                inbound_session_tx,
                inbound_session: inbound,
            },
            OutboundContext {
                outbound_intro_key,
                outbound_socket_rx,
                outbound_session_tx,
                outbound_session: outbound,
                transport_rx,
            },
        )
    }

    #[tokio::test(start_paused = true)]
    async fn session_request_timeout_x25519() {
        session_request_timeout(None).await
    }

    #[tokio::test(start_paused = true)]
    async fn session_request_timeout_ml_kem_512() {
        session_request_timeout(Some(3)).await
    }

    #[tokio::test(start_paused = true)]
    async fn session_request_timeout_ml_kem_768() {
        session_request_timeout(Some(4)).await
    }

    async fn session_request_timeout(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx: _ib_socket_rx,
                inbound_session_tx: _ib_sess_tx,
                ..
            },
            OutboundContext {
                mut outbound_session,
                outbound_socket_rx,
                outbound_session_tx: _ob_session_tx,
                ..
            },
        ) = create_session(None, ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let inbound_session = tokio::spawn(inbound_session.run());

        // verify that `inbound_session` sends retry message
        let Packet { mut pkt, .. } = tokio::select! {
            _ = &mut outbound_session => panic!("outbound session returned"),
            pkt = outbound_socket_rx.recv() => pkt.unwrap(),
            _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
        };

        match HeaderReader::new(intro_key, &mut pkt).unwrap().parse(intro_key).unwrap() {
            HeaderKind::Retry { .. } => {}
            _ => panic!("invalid packet type"),
        }

        match tokio::time::timeout(Duration::from_secs(20), inbound_session)
            .await
            .expect("no timeout")
            .unwrap()
        {
            PendingSsu2SessionStatus::Timeout { .. } => {}
            _ => panic!("invalid status"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn token_request_received_again_x25519() {
        token_request_received_again(None).await
    }

    #[tokio::test(start_paused = true)]
    async fn token_request_received_again_ml_kem_512() {
        token_request_received_again(Some(3)).await
    }

    #[tokio::test(start_paused = true)]
    async fn token_request_received_again_ml_kem_768() {
        token_request_received_again(Some(4)).await
    }

    async fn token_request_received_again(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: _ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(None, ml_kem).await;
        let intro_key = inbound_session.intro_key;

        tokio::spawn(inbound_session.run());
        tokio::spawn(outbound_session);

        // verify that `inbound_session` sends retry message but don't send it to outbound_session
        let Packet { mut pkt, .. } = tokio::select! {
            pkt = outbound_socket_rx.recv() => pkt.unwrap(),
            _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
        };

        match HeaderReader::new(intro_key, &mut pkt).unwrap().parse(intro_key).unwrap() {
            HeaderKind::Retry { .. } => {}
            kind => panic!("invalid packet type: {kind:?}"),
        }

        loop {
            tokio::select! {
                pkt = inbound_socket_rx.recv() => {
                    let Packet { mut pkt, address } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
                }
                pkt = outbound_socket_rx.recv() => {
                    let Packet { mut pkt, .. } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    match reader.parse(intro_key) {
                        Ok(HeaderKind::Retry { .. }) => break,
                        _ => panic!("invalid packet"),
                    }
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn use_old_token_for_session_request_x25519() {
        use_old_token_for_session_request(None).await
    }

    #[tokio::test(start_paused = true)]
    async fn use_old_token_for_session_request_ml_kem_512() {
        use_old_token_for_session_request(Some(3)).await
    }

    #[tokio::test(start_paused = true)]
    async fn use_old_token_for_session_request_ml_kem_768() {
        use_old_token_for_session_request(Some(4)).await
    }

    async fn use_old_token_for_session_request(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                mut outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(None, ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let mut inbound_session = tokio::spawn(inbound_session.run());

        // parse and store the original retry packet
        let original_retry = tokio::select! {
            _ = &mut outbound_session => panic!("outbound session returned"),
            pkt = outbound_socket_rx.recv() => {
                let Packet { mut pkt, address } = pkt.unwrap();

                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _ = reader.dst_id();

                Packet { pkt, address }
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
        };

        // spawn outbound session in the background
        //
        // it'll send another token request and a session request using the wrong token
        tokio::spawn(outbound_session);

        loop {
            tokio::select! {
                status = &mut inbound_session => match status.unwrap() {
                    PendingSsu2SessionStatus::SessionTerminated { .. } => break,
                    _ => panic!("invalid status"),
                },
                pkt = inbound_socket_rx.recv() => {
                    let Packet { mut pkt, address } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
                }
                pkt = outbound_socket_rx.recv() => {
                    let Packet { mut pkt, .. } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    match reader.parse(intro_key) {
                        Ok(HeaderKind::Retry { .. }) => {
                            // send the original `Retry` with an expired token
                            ob_sess_tx.send(original_retry.clone()).await.unwrap();
                        },
                        _ => panic!("invalid packet"),
                    }
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn use_new_token_for_session_request_x25519() {
        use_new_token_for_session_request(None).await
    }

    #[tokio::test(start_paused = true)]
    async fn use_new_token_for_session_request_ml_kem_512() {
        use_new_token_for_session_request(Some(3)).await
    }

    #[tokio::test(start_paused = true)]
    async fn use_new_token_for_session_request_ml_kem_768() {
        use_new_token_for_session_request(Some(4)).await
    }

    async fn use_new_token_for_session_request(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                mut outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(None, ml_kem).await;
        let intro_key = inbound_session.intro_key;
        tokio::spawn(inbound_session.run());

        // read and discard first retry message
        let Packet { mut pkt, .. } = tokio::select! {
            _ = &mut outbound_session => panic!("outbound session returned"),
            pkt = outbound_socket_rx.recv() => pkt.unwrap(),
            _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
        };

        match HeaderReader::new(intro_key, &mut pkt).unwrap().parse(intro_key).unwrap() {
            HeaderKind::Retry { .. } => {}
            _ => panic!("invalid packet type"),
        }

        tokio::spawn(outbound_session);
        tokio::spawn(async move {
            while let Some(Packet { mut pkt, address }) = inbound_socket_rx.recv().await {
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();

                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }
        });

        // handle retry retransmission
        {
            tokio::select! {
                pkt = outbound_socket_rx.recv() => {
                    let Packet { mut pkt, address } = pkt.unwrap();
                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();
                    ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
                }
            }
        }

        // verify that `inbound_session` sends `SessionCreated`
        {
            let Packet { mut pkt, .. } = outbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_session_request_x25519() {
        duplicate_session_request(None).await
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_session_request_ml_kem_512() {
        duplicate_session_request(Some(3)).await
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_session_request_ml_kem_768() {
        duplicate_session_request(Some(4)).await
    }

    async fn duplicate_session_request(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_intro_key,
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                transport_rx: _transport_rx,
            },
        ) = create_session(None, ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let outbound_session = tokio::spawn(outbound_session);
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session, send it to inbound session
        // and read session created
        let _pkt = {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            tokio::select! {
                pkt = outbound_socket_rx.recv() => {
                    pkt.unwrap()
                }
            }
        };

        // don't send the created `SessionCreated` message which forces a retransmission of
        // `SessionRequest`
        let pkt = {
            // wait until `SessionRequest` is retransmitted
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            tokio::select! {
                pkt = outbound_socket_rx.recv() => {
                    pkt.unwrap()
                }
            }
        };

        // send `SessionCreated` to outbound session
        {
            let Packet { mut pkt, address } = pkt;
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read `SessionConfirmed` message from outbound session and relay it to inbound session
        {
            // wait until `SessionRequest` is retransmitted
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // wait for inbound session to finish and the first data packet to outbound session
        match inbound_session.await {
            Ok(PendingSsu2SessionStatus::NewInboundSession {
                mut pkt, target, ..
            }) => {
                let mut reader = HeaderReader::new(outbound_intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();

                ob_sess_tx
                    .send(Packet {
                        pkt: pkt.to_vec(),
                        address: target,
                    })
                    .await
                    .unwrap();
            }
            _ => panic!("invalid result"),
        }

        match outbound_session.await {
            Ok(PendingSsu2SessionStatus::NewOutboundSession { .. }) => {}
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn session_created_timeout_x25519() {
        session_created_timeout(None).await
    }

    #[tokio::test(start_paused = true)]
    async fn session_created_timeout_ml_kem_512() {
        session_created_timeout(Some(3)).await
    }

    #[tokio::test(start_paused = true)]
    async fn session_created_timeout_ml_kem_768() {
        session_created_timeout(Some(4)).await
    }

    async fn session_created_timeout(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(None, ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let _outbound_session = tokio::spawn(outbound_session);
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session, send it to inbound session
        // and read session created
        let _pkt = {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            outbound_socket_rx.recv().await.unwrap()
        };

        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(10), outbound_socket_rx.recv()).await {
                Err(_) => panic!("timeout"),
                Ok(None) => panic!("error"),
                Ok(Some(_)) => {}
            }
        }

        match tokio::time::timeout(Duration::from_secs(10), inbound_session).await {
            Err(_) => panic!("timeout"),
            Ok(Err(_)) => panic!("error"),
            Ok(Ok(PendingSsu2SessionStatus::Timeout { .. })) => {}
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn session_request_clock_skew_x25519() {
        session_request_clock_skew(None).await
    }

    #[tokio::test]
    async fn session_request_clock_skew_ml_kem_512() {
        session_request_clock_skew(Some(3)).await
    }

    #[tokio::test]
    async fn session_request_clock_skew_ml_kem_768() {
        session_request_clock_skew(Some(4)).await
    }

    async fn session_request_clock_skew(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(None, ml_kem).await;
        let intro_key = inbound_session.intro_key;

        // spawn outbound session in a separate thread and modify its
        // clock to be behind 2x maximum clock skew
        let _handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                MockRuntime::set_time(Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("to succeed")
                        - 2 * MAX_CLOCK_SKEW,
                ));

                outbound_session.await;
            })
        });
        let handle = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session and verify inbound session is terminated
        let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _connection_id = reader.dst_id();
        ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

        match handle.await.unwrap() {
            PendingSsu2SessionStatus::SessionTerminated { .. } => {}
            _ => panic!("invalid session status"),
        }

        let Packet { mut pkt, .. } = outbound_socket_rx.recv().await.unwrap();
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _connection_id = reader.dst_id();
        match reader.parse(intro_key).unwrap() {
            HeaderKind::Retry { token, .. } => {
                assert_eq!(token, 0);
            }
            _ => panic!("invalid header type"),
        }
    }

    #[tokio::test]
    async fn token_request_clock_skew_x25519() {
        token_request_clock_skew(None).await
    }

    #[tokio::test]
    async fn token_request_clock_skew_ml_kem_512() {
        token_request_clock_skew(Some(3)).await
    }

    #[tokio::test]
    async fn token_request_clock_skew_ml_kem_768() {
        token_request_clock_skew(Some(4)).await
    }

    async fn token_request_clock_skew(ml_kem: Option<usize>) {
        // set time backwards by 2 * `MAX_CLOCK_SKEW` so the `Retry` message has an invalid time
        MockRuntime::set_time(Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("to succeed")
                - 2 * MAX_CLOCK_SKEW,
        ));

        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx: _inbound_socket_rx,
                inbound_session_tx: _ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(None, ml_kem).await;
        let intro_key = inbound_session.intro_key;

        // reset time back to normal
        MockRuntime::set_time(None);

        // spawn outbound session in a separate thread and modify its
        // clock to be behind 2x maximum clock skew
        let ob_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                MockRuntime::set_time(Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("to succeed")
                        - 2 * MAX_CLOCK_SKEW,
                ));

                outbound_session.await
            })
        });
        let ib_handle = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        match tokio::time::timeout(Duration::from_secs(5), ib_handle).await.unwrap().unwrap() {
            PendingSsu2SessionStatus::SessionTerminated { .. } => {}
            status => panic!("unexpected status: {status:?}"),
        }

        let future = tokio::task::spawn_blocking(move || ob_handle.join().unwrap());
        match tokio::time::timeout(Duration::from_secs(5), future).await.unwrap().unwrap() {
            PendingSsu2SessionStatus::SessionTerminated { .. } => {}
            status => panic!("unexpected status: {status:?}"),
        }
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_x25519() {
        fragmented_session_confirmed(None).await
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_ml_kem_512() {
        fragmented_session_confirmed(Some(3)).await
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_ml_kem_768() {
        fragmented_session_confirmed(Some(4)).await
    }

    async fn fragmented_session_confirmed(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(Some(10), ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let _outbound_session = tokio::spawn(outbound_session);
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session, send it to inbound session
        // and read session created
        let pkt = {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            outbound_socket_rx.recv().await.unwrap()
        };

        // send `SessionCreated` to outbound session
        {
            let Packet { mut pkt, address } = pkt;
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read `SessionConfirmed` from outbound session
        {
            // two fragments are expected
            for _ in 0..3 {
                let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();
                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }
        }

        match timeout!(inbound_session).await.unwrap().unwrap() {
            PendingSsu2SessionStatus::NewInboundSession { .. } => {}
            res => panic!("unexpected result: {res:?}"),
        }
    }

    #[tokio::test]
    async fn multi_fragment_session_confirmed_x25519() {
        multi_fragment_session_confirmed(None).await
    }

    #[tokio::test]
    async fn multi_fragment_session_confirmed_ml_kem_512() {
        multi_fragment_session_confirmed(Some(3)).await
    }

    #[tokio::test]
    async fn multi_fragment_session_confirmed_ml_kem_768() {
        multi_fragment_session_confirmed(Some(4)).await
    }

    async fn multi_fragment_session_confirmed(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(Some(20), ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let _outbound_session = tokio::spawn(outbound_session);
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session, send it to inbound session
        // and read session created
        let pkt = {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            outbound_socket_rx.recv().await.unwrap()
        };

        // send `SessionCreated` to outbound session
        {
            let Packet { mut pkt, address } = pkt;
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read `SessionConfirmed` from outbound session
        {
            // four fragments are expected
            for _ in 0..4 {
                let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();
                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }
        }

        match timeout!(inbound_session).await.unwrap().unwrap() {
            PendingSsu2SessionStatus::NewInboundSession { .. } => {}
            res => panic!("unexpected result: {res:?}"),
        }
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_out_of_order_x25519() {
        fragmented_session_confirmed_out_of_order(None).await
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_out_of_order_ml_kem_512() {
        fragmented_session_confirmed_out_of_order(Some(3)).await
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_out_of_order_ml_kem_768() {
        fragmented_session_confirmed_out_of_order(Some(4)).await
    }

    async fn fragmented_session_confirmed_out_of_order(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(Some(20), ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let _outbound_session = tokio::spawn(outbound_session);
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session, send it to inbound session
        // and read session created
        let pkt = {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            outbound_socket_rx.recv().await.unwrap()
        };

        // send `SessionCreated` to outbound session
        {
            let Packet { mut pkt, address } = pkt;
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read `SessionConfirmed` from outbound session
        {
            // four fragments are expected
            let mut pkts = vec![];

            for _ in 0..4 {
                let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();

                pkts.push((pkt, address));
            }

            // send the packets in reverse order
            for (pkt, address) in pkts.into_iter().rev() {
                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }
        }

        match timeout!(inbound_session).await.unwrap().unwrap() {
            PendingSsu2SessionStatus::NewInboundSession { .. } => {}
            res => panic!("unexpected result: {res:?}"),
        }
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_retransmitted_x25519() {
        fragmented_session_confirmed_retransmitted(None).await
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_retransmitted_ml_kem_512() {
        fragmented_session_confirmed_retransmitted(Some(3)).await
    }

    #[tokio::test]
    async fn fragmented_session_confirmed_retransmitted_ml_kem_768() {
        fragmented_session_confirmed_retransmitted(Some(4)).await
    }

    async fn fragmented_session_confirmed_retransmitted(ml_kem: Option<usize>) {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                ..
            },
        ) = create_session(Some(20), ml_kem).await;

        let intro_key = inbound_session.intro_key;
        let _outbound_session = tokio::spawn(outbound_session);
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                pkt = outbound_socket_rx.recv() => pkt.unwrap(),
                _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout"),
            };
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session, send it to inbound session
        // and read session created
        let pkt = {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();

            outbound_socket_rx.recv().await.unwrap()
        };

        // send `SessionCreated` to outbound session
        {
            let Packet { mut pkt, address } = pkt;
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read `SessionConfirmed` from outbound session
        {
            // four fragments are expected
            let mut pkts = vec![];

            for _ in 0..4 {
                let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();

                pkts.push((pkt, address));
            }

            // drop one fragmet
            for (pkt, address) in pkts.into_iter().skip(1) {
                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }

            // all four fragments are retransmitted
            let mut pkts = vec![];

            for _ in 0..4 {
                let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();

                pkts.push((pkt, address));
            }

            for (pkt, address) in pkts.into_iter() {
                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }
        }

        match timeout!(inbound_session).await.unwrap().unwrap() {
            PendingSsu2SessionStatus::NewInboundSession { .. } => {}
            res => panic!("unexpected result: {res:?}"),
        }
    }
}
