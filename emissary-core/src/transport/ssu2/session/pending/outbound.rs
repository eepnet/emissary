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
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, noise::NoiseContext, EphemeralPrivateKey,
        SigningPublicKey, StaticPrivateKey, StaticPublicKey,
    },
    error::Ssu2Error,
    primitives::RouterId,
    runtime::{Runtime, UdpSocket},
    subsystem::SubsystemEvent,
    transport::{
        ssu2::{
            message::{
                handshake::{SessionConfirmedBuilder, SessionRequestBuilder, TokenRequestBuilder},
                Block, HeaderKind, HeaderReader,
            },
            session::{
                active::Ssu2SessionContext,
                pending::{
                    PacketRetransmitter, PacketRetransmitterEvent, PendingSsu2SessionStatus,
                },
                KeyContext,
            },
            Packet,
        },
        TerminationReason,
    },
};

use bytes::Bytes;
use futures::FutureExt;
use thingbuf::mpsc::{Receiver, Sender};
use zeroize::Zeroize;

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    fmt,
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::pending::outbound";

/// Outbound SSU2 session context.
pub struct OutboundSsu2Context<R: Runtime> {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Chaining key.
    pub chaining_key: Bytes,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Local router intro key.
    pub local_intro_key: [u8; 32],

    /// Local static key.
    pub local_static_key: StaticPrivateKey,

    /// Network ID.
    pub net_id: u8,

    /// Remote router intro key.
    pub remote_intro_key: [u8; 32],

    /// ID of the remote router.
    pub router_id: RouterId,

    /// Serialized local router info.
    pub router_info: Bytes,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    pub rx: Receiver<Packet>,

    /// Verifying key of remote router.
    pub verifying_key: SigningPublicKey,

    /// UDP socket.
    pub socket: R::UdpSocket,

    /// Source connection ID.
    pub src_id: u64,

    /// AEAD state.
    pub state: Vec<u8>,

    /// Remote router's static key.
    pub static_key: StaticPublicKey,

    /// TX channel for communicating with `SubsystemManager`.
    pub transport_tx: Sender<SubsystemEvent>,
}

/// State for a pending outbound SSU2 session.
enum PendingSessionState {
    /// Awaiting `Retry` from remote router.
    AwaitingRetry {
        /// Local static key.
        local_static_key: StaticPrivateKey,

        /// Serialized local router info.
        router_info: Bytes,

        /// Remote router's static key.
        static_key: StaticPublicKey,
    },

    /// Awaiting `SessionCreated` message from remote router.
    AwaitingSessionCreated {
        /// Local ephemeral key.
        ephemeral_key: EphemeralPrivateKey,

        /// Local static key.
        local_static_key: StaticPrivateKey,

        /// Serialized local router info.
        router_info: Bytes,
    },

    /// Awaiting first ACK to be received.
    AwaitingFirstAck,

    /// State has been poisoned.
    Poisoned,
}

impl fmt::Debug for PendingSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PendingSessionState::AwaitingRetry { .. } =>
                f.debug_struct("PendingSessionState::AwaitingRetry").finish_non_exhaustive(),
            PendingSessionState::AwaitingSessionCreated { .. } => f
                .debug_struct("PendingSessionState::AwaitingSessionCreated")
                .finish_non_exhaustive(),
            PendingSessionState::AwaitingFirstAck =>
                f.debug_struct("PendingSessionState::AwaitingFirstAck").finish(),
            PendingSessionState::Poisoned =>
                f.debug_struct("PendingSessionState::Poisoned").finish(),
        }
    }
}

/// Pending outbound SSU2 session.
pub struct OutboundSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Local router intro key.
    local_intro_key: [u8; 32],

    /// Network ID.
    net_id: u8,

    /// Noise context.
    noise_ctx: NoiseContext,

    /// Packet retransmitter.
    pkt_retransmitter: PacketRetransmitter<R>,

    /// Remote router intro key.
    remote_intro_key: [u8; 32],

    /// ID of the remote router.
    router_id: RouterId,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// Verifying key of remote router.
    verifying_key: SigningPublicKey,

    /// UDP socket.
    socket: R::UdpSocket,

    /// Source connection ID.
    src_id: u64,

    /// When was the handshake started.
    started: R::Instant,

    /// Pending session state.
    state: PendingSessionState,

    /// TX channel for communicating with `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,

    /// Write buffer.
    write_buffer: VecDeque<Vec<u8>>,
}

impl<R: Runtime> OutboundSsu2Session<R> {
    /// Create new [`OutboundSsu2Session`].
    pub fn new(context: OutboundSsu2Context<R>) -> Self {
        let OutboundSsu2Context {
            address,
            chaining_key,
            dst_id,
            local_intro_key,
            local_static_key,
            net_id,
            remote_intro_key,
            router_id,
            router_info,
            rx,
            verifying_key,
            socket,
            src_id,
            state,
            static_key,
            transport_tx,
        } = context;

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            ?dst_id,
            ?src_id,
            "send TokenRequest",
        );

        let pkt = TokenRequestBuilder::default()
            .with_dst_id(dst_id)
            .with_src_id(src_id)
            .with_intro_key(remote_intro_key)
            .with_net_id(net_id)
            .build::<R>()
            .to_vec();
        Self {
            address,
            dst_id,
            local_intro_key,
            net_id,
            noise_ctx: NoiseContext::new(
                TryInto::<[u8; 32]>::try_into(chaining_key.to_vec()).expect("to succeed"),
                TryInto::<[u8; 32]>::try_into(state.to_vec()).expect("to succeed"),
            ),
            pkt_retransmitter: PacketRetransmitter::token_request(pkt.clone()),
            remote_intro_key,
            router_id,
            rx: Some(rx),
            verifying_key,
            socket,
            src_id,
            started: R::now(),
            state: PendingSessionState::AwaitingRetry {
                local_static_key,
                router_info,
                static_key,
            },
            transport_tx,
            write_buffer: VecDeque::from([pkt]),
        }
    }

    /// Handle `Retry`.
    ///
    /// Attempt to parse the header into `Retry` and if it succeeds, send a `SessionRequest` to
    /// remote using the token that was received in the `Retry` message. The state of the outbound
    /// connection proceeds to `AwaitingSessionCreated` which is handled by
    /// [`OutboundSsu2Session::on_session_created()`].
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-retry>
    /// <https://geti2p.net/spec/ssu2#retry-type-9>
    fn on_retry(
        &mut self,
        mut pkt: Vec<u8>,
        local_static_key: StaticPrivateKey,
        router_info: Bytes,
        static_key: StaticPublicKey,
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        let (pkt_num, token) = match HeaderReader::new(self.remote_intro_key, &mut pkt)?
            .parse(self.remote_intro_key)?
        {
            HeaderKind::Retry {
                net_id,
                pkt_num,
                token,
            } => {
                if self.net_id != net_id {
                    return Err(Ssu2Error::NetworkMismatch);
                }

                (pkt_num, token)
            }
            kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?kind,
                    "unexpected message, expected Retry",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        };

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            ?pkt_num,
            ?token,
            "handle Retry",
        );

        let mut payload = pkt[32..].to_vec();
        ChaChaPoly::with_nonce(&self.remote_intro_key, pkt_num as u64)
            .decrypt_with_ad(&pkt[..32], &mut payload)?;

        // check if the message contains a termination block
        let blocks = Block::parse(&payload).map_err(|error| {
            tracing::trace!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                ?error,
                "failed to parse message blocks of Retry",
            );
            Ssu2Error::Malformed
        })?;

        // check if remote sent termination block in `Retry` and if so, exit early
        if let Some(Block::Termination { reason, .. }) =
            blocks.iter().find(|block| core::matches!(block, Block::Termination { .. }))
        {
            tracing::debug!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                ?reason,
                "Retry contains a termination block",
            );

            return Err(Ssu2Error::SessionTerminated(TerminationReason::ssu2(
                *reason,
            )));
        }

        // MixKey(DH())
        let ephemeral_key = EphemeralPrivateKey::random(R::rng());
        let cipher_key = self.noise_ctx.mix_key(&ephemeral_key, &static_key);

        let mut message = SessionRequestBuilder::default()
            .with_dst_id(self.dst_id)
            .with_src_id(self.src_id)
            .with_net_id(self.net_id)
            .with_ephemeral_key(ephemeral_key.public())
            .with_token(token)
            .build::<R>();

        // MixHash(header), MixHash(aepk)
        self.noise_ctx.mix_hash(message.header()).mix_hash(ephemeral_key.public());

        message.encrypt_payload(&cipher_key, 0u64, self.noise_ctx.state());
        message.encrypt_header(self.remote_intro_key, self.remote_intro_key);

        // MixHash(ciphertext)
        self.noise_ctx.mix_hash(message.payload());

        // reset packet retransmitter to track `SessionRequest` and send the message to remote
        let pkt = message.build().to_vec();
        self.pkt_retransmitter = PacketRetransmitter::session_request(pkt.clone());
        self.write_buffer.push_back(pkt);

        self.state = PendingSessionState::AwaitingSessionCreated {
            ephemeral_key,
            local_static_key,
            router_info,
        };

        Ok(None)
    }

    /// Handle `SessionCreated`.
    ///
    /// Attempt to parse the header into `SessionCrated` and if it succeeds, send a
    /// `SessionConfirmed` to remote. The state of the outbound connection proceeds to
    /// `AwaitingFirstAck` which is handled by [`OutboundSsu2Session::on_data()`]. Once an ACK for
    /// the `SessionConfirmed` message has been received, data phase keys are derived and the
    /// session is considered established
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-created-and-session-confirmed-part-1>
    /// <https://geti2p.net/spec/ssu2#sessioncreated-type-1>
    fn on_session_created(
        &mut self,
        mut pkt: Vec<u8>,
        ephemeral_key: EphemeralPrivateKey,
        local_static_key: StaticPrivateKey,
        router_info: Bytes,
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize_new();

        let remote_ephemeral_key =
            match HeaderReader::new(self.remote_intro_key, &mut pkt)?.parse(k_header_2)? {
                HeaderKind::SessionCreated {
                    ephemeral_key,
                    net_id,
                    ..
                } => {
                    if self.net_id != net_id {
                        return Err(Ssu2Error::NetworkMismatch);
                    }

                    ephemeral_key
                }
                kind => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?kind,
                        "unexpected message, expected SessionCreated",
                    );

                    self.state = PendingSessionState::AwaitingSessionCreated {
                        ephemeral_key,
                        local_static_key,
                        router_info,
                    };
                    return Ok(None);
                }
            };

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle SessionCreated",
        );

        // MixHash(header), MixHash(bepk)
        self.noise_ctx.mix_hash(&pkt[..32]).mix_hash(&pkt[32..64]);

        // MixKey(DH())
        let cipher_key = self.noise_ctx.mix_key(&ephemeral_key, &remote_ephemeral_key);

        // decrypt payload
        let mut payload = pkt[64..].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut payload)?;

        // MixHash(ciphertext)
        self.noise_ctx.mix_hash(&pkt[64..]);

        // TODO: validate datetime
        // TODO: get our address

        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize_new();

        let mut message = SessionConfirmedBuilder::default()
            .with_dst_id(self.dst_id)
            .with_src_id(self.src_id)
            .with_static_key(local_static_key.public())
            .with_router_info(router_info)
            .build();

        // MixHash(header) & encrypt public key
        self.noise_ctx.mix_hash(message.header());
        message.encrypt_public_key(&cipher_key, 1u64, self.noise_ctx.state());

        // MixHash(apk)
        self.noise_ctx.mix_hash(message.public_key());

        // MixKey(DH())
        let mut cipher_key = self.noise_ctx.mix_key(&local_static_key, &remote_ephemeral_key);

        message.encrypt_payload(&cipher_key, 0u64, self.noise_ctx.state());
        message.encrypt_header(self.remote_intro_key, k_header_2);
        cipher_key.zeroize();

        // reset packet retransmitter to track `SessionConfirmed` and send the message to remote
        let pkt = message.build().to_vec();
        self.pkt_retransmitter = PacketRetransmitter::session_confirmed(pkt.clone());
        self.write_buffer.push_back(pkt);

        self.state = PendingSessionState::AwaitingFirstAck;
        Ok(None)
    }

    /// Handle `Data`, in other words an ACK for the `SessionConfirmed` message.
    ///
    /// Verify that a valid message was received, derive data phase keys and return session context
    /// for [`Ssu2Socket`] which starts an active session.
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-confirmed-part-1-using-session-created-kdf>
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-confirmed-part-2>
    /// <https://geti2p.net/spec/ssu2#sessionconfirmed-type-2>
    /// <https://geti2p.net/spec/ssu2#kdf-for-data-phase>
    fn on_data(
        &mut self,
        mut pkt: Vec<u8>,
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_ab = Hmac::new(&temp_key).update([0x01]).finalize();
        let k_ba = Hmac::new(&temp_key).update(&k_ab).update([0x02]).finalize();

        let temp_key = Hmac::new(&k_ab).update([]).finalize();
        let k_data_ab =
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize_new();
        let k_header_2_ab = TryInto::<[u8; 32]>::try_into(
            Hmac::new(&temp_key)
                .update(k_data_ab)
                .update(b"HKDFSSU2DataKeys")
                .update([0x02])
                .finalize(),
        )
        .expect("to succeed");

        let temp_key = Hmac::new(&k_ba).update([]).finalize();
        let k_data_ba =
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize_new();
        let k_header_2_ba = Hmac::new(&temp_key)
            .update(k_data_ba)
            .update(b"HKDFSSU2DataKeys")
            .update([0x02])
            .finalize_new();

        let payload = match HeaderReader::new(self.local_intro_key, &mut pkt)?.parse(k_header_2_ba)
        {
            Ok(HeaderKind::Data { pkt_num, .. }) => {
                // ensure the data packet decrypts correctly
                //
                // failure to decrypt the payload could indicate that an incorrect packet was
                // received and that `OutboundSession` should resend `SessionConfirmed`
                //
                // TODO: unneeded clone
                let mut payload = pkt[16..].to_vec();
                if ChaChaPoly::with_nonce(&k_data_ba, pkt_num as u64)
                    .decrypt_with_ad(&pkt[..16], &mut payload)
                    .is_err()
                {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        "failed to decrypt Data message, ignoring",
                    );

                    self.state = PendingSessionState::AwaitingFirstAck;
                    return Ok(None);
                }

                payload
            }
            kind => {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?kind,
                    "unexpected message, expected Data",
                );

                self.state = PendingSessionState::AwaitingFirstAck;
                return Ok(None);
            }
        };

        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle Data (first ack)",
        );

        match Block::parse(&payload) {
            Ok(blocks) => {
                if let Some(Block::Termination { reason, .. }) =
                    blocks.iter().find(|block| core::matches!(block, Block::Termination { .. }))
                {
                    tracing::debug!(
                        router_id = %self.router_id,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        reason = ?TerminationReason::ssu2(*reason),
                        "first ack contains termination, aborting",
                    );

                    return Err(Ssu2Error::SessionTerminated(TerminationReason::ssu2(
                        *reason,
                    )));
                }
            }
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?error,
                    "failed to parse Data message, ignoring",
                );

                self.state = PendingSessionState::AwaitingFirstAck;
                return Ok(None);
            }
        }

        Ok(Some(PendingSsu2SessionStatus::NewOutboundSession {
            context: Ssu2SessionContext {
                address: self.address,
                dst_id: self.dst_id,
                intro_key: self.remote_intro_key,
                recv_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                send_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                router_id: self.router_id.clone(),
                pkt_rx: self.rx.take().expect("to exist"),
                verifying_key: self.verifying_key.clone(),
            },
            src_id: self.src_id,
            started: self.started,
        }))
    }

    /// Handle `pkt`.
    ///
    /// If the packet is the next in expected sequnce, the outbound session advances to the next
    /// state and if an ACK for `SessionConfirmed` has been received,
    /// [`PendingSsu2SessionStatus::NewOutboundSession`] is returned to the caller, shutting down
    /// this future and allowing [`Ssu2Socket`] to start a new future for the active session.
    ///
    /// If a fatal error occurs during handling of the packet,
    /// [`PendingSsu2SessionStatus::SessionTerminated`] is returned.
    fn on_packet(
        &mut self,
        pkt: Vec<u8>,
    ) -> Result<Option<PendingSsu2SessionStatus<R>>, Ssu2Error> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::AwaitingRetry {
                local_static_key,
                router_info,
                static_key,
            } => self.on_retry(pkt, local_static_key, router_info, static_key),
            PendingSessionState::AwaitingSessionCreated {
                ephemeral_key,
                local_static_key,
                router_info,
            } => self.on_session_created(pkt, ephemeral_key, local_static_key, router_info),
            PendingSessionState::AwaitingFirstAck => self.on_data(pkt),
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    "outbound session state is poisoned",
                );
                debug_assert!(false);

                Ok(Some(PendingSsu2SessionStatus::SessionTerminated {
                    address: Some(self.address),
                    connection_id: self.src_id,
                    router_id: Some(self.router_id.clone()),
                    started: self.started,
                }))
            }
        }
    }

    /// Run the event loop of [`OutboundSsu2Session`].
    ///
    /// Convenient function for calling `OutboundSsu2Session::poll()` which, if an error occurred
    /// during negotiation, reports a connection failure to installed subsystems and returns the
    /// session status.
    pub async fn run(mut self) -> PendingSsu2SessionStatus<R> {
        let status = (&mut self).await;

        if core::matches!(
            status,
            PendingSsu2SessionStatus::SessionTerminated { .. }
                | PendingSsu2SessionStatus::Timeout { .. }
                | PendingSsu2SessionStatus::SocketClosed { .. }
        ) {
            if let Err(error) = self
                .transport_tx
                .send(SubsystemEvent::ConnectionFailure {
                    router_id: self.router_id.clone(),
                })
                .await
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?error,
                    "failed to report connection failure to subsystem manager",
                );
            }
        }

        status
    }
}

impl<R: Runtime> Future for OutboundSsu2Session<R> {
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
                        router_id = %self.router_id,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?error,
                        "failed to handle packet",
                    );

                    return Poll::Ready(PendingSsu2SessionStatus::SessionTerminated {
                        address: Some(self.address),
                        connection_id: self.src_id,
                        router_id: Some(self.router_id.clone()),
                        started: self.started,
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
                self.write_buffer.push_back(pkt);
            }
            Poll::Ready(PacketRetransmitterEvent::Timeout) =>
                return Poll::Ready(PendingSsu2SessionStatus::Timeout {
                    connection_id: self.src_id,
                    router_id: Some(self.router_id.clone()),
                    started: self.started,
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
        crypto::sha256::Sha256,
        primitives::RouterInfoBuilder,
        runtime::mock::MockRuntime,
        transport::ssu2::session::pending::inbound::{InboundSsu2Context, InboundSsu2Session},
    };
    use rand_core::RngCore;
    use std::{net::Ipv4Addr, time::Duration};
    use thingbuf::mpsc::channel;

    struct InboundContext {
        inbound_session: InboundSsu2Session<MockRuntime>,
        inbound_session_tx: Sender<Packet>,
        inbound_socket_rx: Receiver<Packet>,
    }

    struct OutboundContext {
        outbound_session: OutboundSsu2Session<MockRuntime>,
        outbound_session_tx: Sender<Packet>,
        outbound_socket_rx: Receiver<Packet>,
        transport_rx: Receiver<SubsystemEvent>,
    }

    async fn create_session() -> (InboundContext, OutboundContext) {
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

        let state = Sha256::new()
            .update("Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256".as_bytes())
            .finalize();
        let chaining_key = state.clone();
        let outbound_state = Sha256::new().update(&state).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(inbound_static_key.public().to_vec())
            .finalize();

        let (inbound_socket_tx, inbound_socket_rx) = channel(128);
        let (inbound_session_tx, inbound_session_rx) = channel(128);
        let (outbound_socket_tx, outbound_socket_rx) = channel(128);
        let (outbound_session_tx, outbound_session_rx) = channel(128);
        let (transport_tx, transport_rx) = channel(128);

        let (router_info, _, signing_key) = RouterInfoBuilder::default()
            .with_ssu2(crate::Ssu2Config {
                port: 8889,
                host: Some(Ipv4Addr::new(127, 0, 0, 1)),
                publish: true,
                static_key: TryInto::<[u8; 32]>::try_into(outbound_static_key.as_ref().to_vec())
                    .unwrap(),
                intro_key: outbound_intro_key,
            })
            .build();

        let mut outbound = OutboundSsu2Session::new(OutboundSsu2Context {
            address: inbound_address,
            chaining_key: Bytes::from(chaining_key.clone()),
            dst_id,
            local_intro_key: outbound_intro_key,
            local_static_key: outbound_static_key,
            net_id: 2u8,
            remote_intro_key: inbound_intro_key,
            router_id: router_info.identity.id(),
            router_info: Bytes::from(router_info.serialize(&signing_key)),
            rx: outbound_session_rx,
            verifying_key: signing_key.public(),
            socket: outbound_socket.clone(),
            src_id,
            state: inbound_state.clone(),
            static_key: inbound_static_key.public(),
            transport_tx,
        });

        // read `Retry` from inbound socket and relay it to `outbound_socket_rx`
        let mut buffer = vec![0u8; 0xffff];

        tokio::select! {
            _ = &mut outbound => panic!("outbound sessionr returned"),
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
            chaining_key: Bytes::from(chaining_key),
            dst_id,
            intro_key: inbound_intro_key,
            net_id: 2u8,
            pkt,
            pkt_num,
            socket: inbound_socket.clone(),
            rx: inbound_session_rx,
            src_id,
            state: Bytes::from(inbound_state),
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
                transport_rx,
                outbound_session: outbound,
                outbound_session_tx,
                outbound_socket_rx,
            },
        )
    }

    #[tokio::test]
    async fn token_request_timeout() {
        let (
            InboundContext {
                inbound_session_tx: _inbound_session_tx,
                inbound_socket_rx,
                ..
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: _ob_sess_tx,
                outbound_socket_rx: _outbound_socket_rx,
                transport_rx,
            },
        ) = create_session().await;
        let router_id = outbound_session.router_id.clone();
        let outbound_session = tokio::spawn(outbound_session.run());

        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(10), inbound_socket_rx.recv()).await {
                Err(_) => panic!("timeout"),
                Ok(None) => panic!("error"),
                Ok(Some(_)) => {}
            }
        }

        match tokio::time::timeout(Duration::from_secs(10), outbound_session).await {
            Err(_) => panic!("timeout"),
            Ok(Err(_)) => panic!("error"),
            Ok(Ok(PendingSsu2SessionStatus::Timeout { .. })) => {}
            _ => panic!("invalid result"),
        }

        match tokio::time::timeout(Duration::from_secs(5), transport_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SubsystemEvent::ConnectionFailure { router_id: router } => {
                assert_eq!(router, router_id)
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn session_request_timeout() {
        let (
            InboundContext {
                inbound_session,
                inbound_socket_rx,
                inbound_session_tx: _ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
                transport_rx,
            },
        ) = create_session().await;

        let intro_key = outbound_session.remote_intro_key;
        let router_id = outbound_session.router_id.clone();
        let outbound_session = tokio::spawn(outbound_session.run());
        let _inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = outbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(10), inbound_socket_rx.recv()).await {
                Err(_) => panic!("timeout"),
                Ok(None) => panic!("error"),
                Ok(Some(_)) => {}
            }
        }

        match tokio::time::timeout(Duration::from_secs(20), outbound_session).await {
            Err(_) => panic!("timeout"),
            Ok(Err(_)) => panic!("error"),
            Ok(Ok(PendingSsu2SessionStatus::Timeout { .. })) => {}
            _ => panic!("invalid result"),
        }

        match tokio::time::timeout(Duration::from_secs(5), transport_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SubsystemEvent::ConnectionFailure { router_id: router } => {
                assert_eq!(router, router_id)
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn session_confirmed_timeout() {
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
                transport_rx,
            },
        ) = create_session().await;

        let intro_key = outbound_session.remote_intro_key;
        let router_id = outbound_session.router_id.clone();
        let outbound_session = tokio::spawn(outbound_session.run());
        let _inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = outbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session and send it to inbound session
        {
            let Packet { mut pkt, address } = inbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // send session created to outbound session
        {
            let Packet { mut pkt, address } = outbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(10), inbound_socket_rx.recv()).await {
                Err(_) => panic!("timeout"),
                Ok(None) => panic!("error"),
                Ok(Some(_)) => {}
            }
        }

        match tokio::time::timeout(Duration::from_secs(20), outbound_session).await {
            Err(_) => panic!("timeout"),
            Ok(Err(_)) => panic!("error"),
            Ok(Ok(PendingSsu2SessionStatus::Timeout { .. })) => {}
            _ => panic!("invalid result"),
        }

        match tokio::time::timeout(Duration::from_secs(5), transport_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            SubsystemEvent::ConnectionFailure { router_id: router } => {
                assert_eq!(router, router_id)
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn duplicate_session_created_received() {
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
                transport_rx: _transport_rx,
            },
        ) = create_session().await;

        let intro_key = outbound_session.remote_intro_key;
        let outbound_intro_key = outbound_session.local_intro_key;
        let inbound_session = tokio::spawn(inbound_session.run());

        // send retry message to outbound session
        {
            let Packet { mut pkt, address } = outbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();

            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session request from outbound session and send it to inbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                _ = &mut outbound_session => unreachable!(),
                pkt = inbound_socket_rx.recv() => {
                    pkt.unwrap()
                }
            };

            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read `SessionCreated` from inbound session twice and relay it to outbound session
        //
        // verify that outbound session handles the duplicate packet gracefully and keeps waiting
        // for the first ack packet
        for _ in 0..2 {
            {
                let Packet { mut pkt, address } = outbound_socket_rx.recv().await.unwrap();
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();
                ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }

            // verify that outbound session responds
            let _pkt = tokio::select! {
                _ = &mut outbound_session => unreachable!(),
                pkt = inbound_socket_rx.recv() => {
                    pkt.unwrap()
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            };

            match outbound_session.state {
                PendingSessionState::AwaitingFirstAck => {}
                _ => panic!("invalid state"),
            }
        }

        // read session created from inbound session and relay it to outbound session
        {
            let Packet { mut pkt, address } = outbound_socket_rx.recv().await.unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // read session confirmed from outbound session and relay it to inbound session
        {
            let Packet { mut pkt, address } = tokio::select! {
                _ = &mut outbound_session => unreachable!(),
                pkt = inbound_socket_rx.recv() => {
                    pkt.unwrap()
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            };

            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _connection_id = reader.dst_id();
            ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
        }

        // verify that inbound session considers the connection opened
        //
        // relay the first ack packet to outbound session
        match tokio::time::timeout(Duration::from_secs(5), inbound_session)
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            PendingSsu2SessionStatus::NewInboundSession {
                mut pkt, target, ..
            } => {
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
            _ => panic!("invalid session state"),
        }

        match tokio::time::timeout(Duration::from_secs(5), outbound_session)
            .await
            .expect("no timeout")
        {
            PendingSsu2SessionStatus::NewOutboundSession { .. } => {}
            _ => panic!("invalid session state"),
        }
    }
}
