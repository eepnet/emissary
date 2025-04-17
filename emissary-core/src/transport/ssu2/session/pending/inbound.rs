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
        StaticPrivateKey, StaticPublicKey,
    },
    error::Ssu2Error,
    runtime::Runtime,
    transport::ssu2::{
        message::{
            Block, DataMessageBuilder, HeaderKind, HeaderReader, RetryBuilder,
            SessionCreatedBuilder,
        },
        session::{
            active::Ssu2SessionContext,
            pending::{PacketRetransmitter, PacketRetransmitterEvent, PendingSsu2SessionStatus},
            KeyContext,
        },
        Packet,
    },
};

use bytes::Bytes;
use futures::FutureExt;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::inbound";

/// Timeout for receicing [`SessionRequest`] from Bob.
const SESSION_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Inbound SSU2 session context.
pub struct InboundSsu2Context {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Chaining key.
    pub chaining_key: Bytes,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Local intro key.
    pub intro_key: [u8; 32],

    /// `TokenRequest` packet.
    pub pkt: Vec<u8>,

    /// Packet number.
    pub pkt_num: u32,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: make `R::UdpSocket` clonable
    pub pkt_tx: Sender<Packet>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    pub rx: Receiver<Packet>,

    /// Source connection ID.
    pub src_id: u64,

    /// AEAD state.
    pub state: Bytes,

    /// Local static key.
    pub static_key: StaticPrivateKey,
}

/// Pending session state.
enum PendingSessionState {
    /// Awaiting `SessionRequest` message from remote router.
    AwaitingSessionRequest {
        /// Generated token.
        token: u64,
    },

    /// Awaiting `SessionConfirmed` message from remote router.
    AwaitingSessionConfirmed {
        /// Our ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// Cipher key for decrypting the second part of the header
        k_header_2: [u8; 32],

        /// Key for decrypting the `SessionCreated` message.
        k_session_created: [u8; 32],
    },

    /// State has been poisoned.
    Poisoned,
}

/// Pending inbound SSU2 session.
pub struct InboundSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Local intro key.
    intro_key: [u8; 32],

    /// Noise context.
    noise_ctx: NoiseContext,

    /// Packet retransmitter.
    pkt_retransmitter: PacketRetransmitter<R>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: make `R::UdpSocket` clonable
    pkt_tx: Sender<Packet>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// Source connection ID.
    src_id: u64,

    /// Pending session state.
    state: PendingSessionState,

    /// Local SSU2 static key.
    static_key: StaticPrivateKey,
}

impl<R: Runtime> InboundSsu2Session<R> {
    /// Create new [`PendingSsu2Session`].
    //
    // TODO: explain what happens here
    pub fn new(context: InboundSsu2Context) -> Result<Self, Ssu2Error> {
        let InboundSsu2Context {
            address,
            chaining_key,
            dst_id,
            intro_key,
            pkt,
            pkt_num,
            pkt_tx,
            rx,
            src_id,
            state,
            static_key,
        } = context;

        let mut payload = pkt[32..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&intro_key, pkt_num as u64)
            .decrypt_with_ad(&pkt[..32], &mut payload)?;

        Block::parse(&payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_id,
                ?src_id,
                "failed to parse message blocks",
            );
            debug_assert!(false);

            Ssu2Error::Malformed
        })?;

        let token = R::rng().next_u64();
        let pkt = RetryBuilder::default()
            .with_k_header_1(intro_key)
            .with_src_id(dst_id)
            .with_dst_id(src_id)
            .with_token(token)
            .with_address(address)
            .build::<R>()
            .to_vec();

        tracing::trace!(
            target: LOG_TARGET,
            ?dst_id,
            ?src_id,
            ?pkt_num,
            ?token,
            "handle `TokenRequest`",
        );

        // retry messages are not retransmitted
        if let Err(error) = pkt_tx.try_send(Packet { pkt, address }) {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_id,
                ?src_id,
                ?address,
                ?error,
                "failed to send `Retry`",
            );
        }

        Ok(Self {
            address,
            dst_id,
            intro_key,
            noise_ctx: NoiseContext::new(
                TryInto::<[u8; 32]>::try_into(chaining_key.to_vec()).expect("to succeed"),
                TryInto::<[u8; 32]>::try_into(state.to_vec()).expect("to succeed"),
            ),
            pkt_retransmitter: PacketRetransmitter::inactive(SESSION_REQUEST_TIMEOUT),
            pkt_tx,
            rx: Some(rx),
            src_id,
            state: PendingSessionState::AwaitingSessionRequest { token },
            static_key,
        })
    }

    /// Handle `SessionRequest` message.
    ///
    /// Attempt to parse `pkt` into `SessionRequest` and if it succeeds, verify that the token it
    /// contains is the once that was sent in `Retry`, send `SessionCreated` as a reply and
    /// transition the inbound state to [`PendingSessionState::AwaitingSessionConfirmed`].
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-request>
    /// <https://geti2p.net/spec/ssu2#sessionrequest-type-0>
    fn on_session_request(
        &mut self,
        mut pkt: Vec<u8>,
        token: u64,
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        let (ephemeral_key, pkt_num, recv_token) = match HeaderReader::new(self.intro_key, &mut pkt)?
                .parse(self.intro_key)
                .ok_or(Ssu2Error::InvalidVersion)? // TODO: could be other error
            {
                HeaderKind::SessionRequest {
                    ephemeral_key,
                    net_id: _,
                    pkt_num,
                    token,
                    ..
                } => {
                    // TODO: check net id

                    (ephemeral_key, pkt_num, token)
                }
                HeaderKind::TokenRequest { net_id: _ , pkt_num, src_id } => {
                    // TODO: check net id

                    let token = R::rng().next_u64();
                    let pkt = RetryBuilder::default()
                        .with_k_header_1(self.intro_key)
                        .with_src_id(self.dst_id)
                        .with_dst_id(src_id)
                        .with_token(token)
                        .with_address(self.address)
                        .build::<R>()
                        .to_vec();

                    tracing::debug!(
                        target: LOG_TARGET,
                        local_dst_id = ?self.dst_id,
                        local_src_id = ?self.src_id,
                        remote_src_id = ?src_id,
                        ?pkt_num,
                        ?token,
                        "received unexpected `TokenRequest`",
                    );

                    if let Err(error) = self.pkt_tx.try_send(Packet { pkt, address: self.address }) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local_dst_id = ?self.dst_id,
                            local_src_id = ?self.src_id,
                            remote_src_id = ?src_id,
                            address = ?self.address,
                            ?error,
                            "failed to send `Retry`",
                        );
                    }

                    self.state = PendingSessionState::AwaitingSessionRequest { token };
                    return Ok(None);
                }
                kind => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?kind,
                        "invalid message, expected `SessionRequest`",
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
            "handle `SessionRequest`",
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

            return Ok(Some(PendingSsu2SessionStatus::SessionTermianted {
                connection_id: self.dst_id,
                router_id: None,
            }));
        }

        // MixHash(header), MiXHash(aepk)
        self.noise_ctx.mix_hash(&pkt[..32]).mix_hash(&pkt[32..64]);

        // MixKey(DH())
        let mut cipher_key = self.noise_ctx.mix_key(&self.static_key, &ephemeral_key);

        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize_new();

        // decrypt payload
        let mut payload = pkt[64..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut payload)?;
        cipher_key.zeroize();

        // MixHash(ciphertext)
        self.noise_ctx.mix_hash(&pkt[64..pkt.len()]);

        if Block::parse(&payload).is_none() {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                "malformed `SessionRequest` payload",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        }

        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public();

        // MixKey(DH())
        let cipher_key = self.noise_ctx.mix_key(&sk, &ephemeral_key);

        let mut message = SessionCreatedBuilder::default()
            .with_address(self.address)
            .with_dst_id(self.src_id)
            .with_src_id(self.dst_id)
            .with_ephemeral_key(pk.clone())
            .build::<R>();

        // MixHash(header), MixHash(bepk)
        self.noise_ctx.mix_hash(message.header()).mix_hash(&pk);

        message.encrypt_payload(&cipher_key, 0u64, self.noise_ctx.state());
        message.encrypt_header(self.intro_key, k_header_2);

        // MixHash(ciphertext)
        self.noise_ctx.mix_hash(message.payload());

        // reset packet retransmitter to track `SessionConfirmed` and send the message to remote
        let pkt = message.build().to_vec();
        self.pkt_retransmitter = PacketRetransmitter::session_created(pkt.clone());

        if let Err(error) = self.pkt_tx.try_send(Packet {
            pkt,
            address: self.address,
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                address = ?self.address,
                ?error,
                "failed to send `SessionCreated`",
            );
        }

        // create new session
        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize_new();

        self.state = PendingSessionState::AwaitingSessionConfirmed {
            ephemeral_key: sk,
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
        ephemeral_key: EphemeralPrivateKey,
        k_header_2: [u8; 32],
        k_session_created: [u8; 32],
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        match HeaderReader::new(self.intro_key, &mut pkt)?
            .parse(k_header_2)
            .ok_or(Ssu2Error::InvalidVersion)? // TODO: could be other error
        {
            HeaderKind::SessionConfirmed { pkt_num } =>
                if pkt_num != 0 {
                    tracing::warn!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?pkt_num,
                        "`SessionConfirmed` contains non-zero packet number",
                    );
                    return Err(Ssu2Error::Malformed);
                },
            kind => {
                tracing::trace!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?kind,
                    "invalid message, expected `SessionRequest`",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        }

        tracing::trace!(
            target: LOG_TARGET,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle `SessionConfirmed`",
        );

        // MixHash(header)
        self.noise_ctx.mix_hash(&pkt[..16]);

        let mut static_key = pkt[16..64].to_vec();
        ChaChaPoly::with_nonce(&k_session_created, 1u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut static_key)?;

        // MixHash(apk)
        self.noise_ctx.mix_hash(&pkt[16..64]);

        // MixKey(DH())
        let mut cipher_key = self.noise_ctx.mix_key(
            &ephemeral_key,
            &StaticPublicKey::from_bytes(&static_key).expect("to succeed"),
        );

        // decrypt payload
        let mut payload = pkt[64..].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut payload)?;
        cipher_key.zeroize();

        let Some(blocks) = Block::parse(&payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                "failed to parse message blocks of `SessionConfirmed`",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };

        let Some(Block::RouterInfo { router_info }) =
            blocks.iter().find(|block| core::matches!(block, Block::RouterInfo { .. }))
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "`SessionConfirmed` doesn't include router info block",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };

        let Some(intro_key) = router_info.ssu2_intro_key() else {
            tracing::warn!(
                target: LOG_TARGET,
                "router info doesn't contain ssu2 intro key",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };
        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
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
                intro_key,
                &KeyContext {
                    k_data: k_data_ba,
                    k_header_2: k_header_2_ba,
                },
            )
            .with_ack(0u32, 0u8, None)
            .build();

        Ok(Some(PendingSsu2SessionStatus::NewInboundSession {
            context: Ssu2SessionContext {
                address: self.address,
                dst_id: self.src_id,
                intro_key,
                recv_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                send_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                router_id: router_info.identity.id(),
                pkt_rx: self.rx.take().expect("to exist"),
            },
            pkt,
            target: self.address,
        }))
    }

    /// Handle received packet to a pending session.
    ///
    /// `pkt` contains the full header but the first part of the header has been decrypted by the
    /// `Ssu2Socket`, meaning only the second part of the header must be decrypted by us.
    //
    // TODO: on error reset state back to what it was
    fn on_packet(&mut self, pkt: Vec<u8>) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::AwaitingSessionRequest { token } =>
                self.on_session_request(pkt, token),
            PendingSessionState::AwaitingSessionConfirmed {
                ephemeral_key,
                k_header_2,
                k_session_created,
            } => self.on_session_confirmed(pkt, ephemeral_key, k_header_2, k_session_created),
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    "inbound session state is poisoned",
                );
                debug_assert!(false);
                Ok(Some(PendingSsu2SessionStatus::SessionTermianted {
                    connection_id: self.dst_id,
                    router_id: None,
                }))
            }
        }
    }
}

impl<R: Runtime> Future for InboundSsu2Session<R> {
    type Output = PendingSsu2SessionStatus;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let pkt = match &mut self.rx {
                None => return Poll::Ready(PendingSsu2SessionStatus::SocketClosed),
                Some(rx) => match rx.poll_recv(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) =>
                        return Poll::Ready(PendingSsu2SessionStatus::SocketClosed),
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
                }
            }
        }

        match futures::ready!(self.pkt_retransmitter.poll_unpin(cx)) {
            PacketRetransmitterEvent::Retransmit { pkt } => {
                if let Err(error) = self.pkt_tx.try_send(Packet {
                    pkt: pkt.clone(),
                    address: self.address,
                }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?error,
                        "failed to send packet for retransmission",
                    );
                }

                Poll::Pending
            }
            PacketRetransmitterEvent::Timeout => Poll::Ready(PendingSsu2SessionStatus::Timeout {
                connection_id: self.dst_id,
                router_id: None,
            }),
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
        transport::ssu2::session::pending::outbound::{OutboundSsu2Context, OutboundSsu2Session},
    };
    use std::net::{IpAddr, Ipv4Addr};
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
    }

    fn create_session() -> (InboundContext, OutboundContext) {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888);
        let src_id = MockRuntime::rng().next_u64();
        let dst_id = MockRuntime::rng().next_u64();

        let outbound_static_key = StaticPrivateKey::random(MockRuntime::rng());
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

        let (router_info, _, signing_key) = RouterInfoBuilder::default()
            .with_ssu2(crate::Ssu2Config {
                port: 8889,
                host: Some(Ipv4Addr::new(127, 0, 0, 1)),
                publish: true,
                static_key: TryInto::<[u8; 32]>::try_into(outbound_static_key.as_ref().to_vec())
                    .unwrap(),
                intro_key: {
                    let mut key = [0u8; 32];
                    MockRuntime::rng().fill_bytes(&mut key);

                    key
                },
            })
            .build();

        let outbound = OutboundSsu2Session::new(OutboundSsu2Context {
            address,
            chaining_key: Bytes::from(chaining_key.clone()),
            dst_id,
            intro_key: inbound_intro_key,
            local_static_key: outbound_static_key,
            pkt_tx: outbound_socket_tx,
            router_id: router_info.identity.id(),
            router_info: Bytes::from(router_info.serialize(&signing_key)),
            rx: outbound_session_rx,
            src_id,
            state: inbound_state.clone(),
            static_key: inbound_static_key.public(),
        });

        let (pkt, pkt_num, dst_id, src_id) = {
            let Packet { mut pkt, .. } = outbound_socket_rx.try_recv().unwrap();
            let mut reader = HeaderReader::new(inbound_intro_key, &mut pkt).unwrap();
            let dst_id = reader.dst_id();

            match reader.parse(inbound_intro_key) {
                Some(HeaderKind::TokenRequest {
                    pkt_num, src_id, ..
                }) => (pkt, pkt_num, dst_id, src_id),
                _ => panic!("invalid message"),
            }
        };

        let inbound = InboundSsu2Session::<MockRuntime>::new(InboundSsu2Context {
            address,
            chaining_key: Bytes::from(chaining_key),
            dst_id,
            intro_key: inbound_intro_key,
            pkt,
            pkt_num,
            pkt_tx: inbound_socket_tx,
            rx: inbound_session_rx,
            src_id,
            state: Bytes::from(inbound_state),
            static_key: inbound_static_key.clone(),
        })
        .unwrap();

        (
            InboundContext {
                inbound_socket_rx,
                inbound_session_tx,
                inbound_session: inbound,
            },
            OutboundContext {
                outbound_socket_rx,
                outbound_session_tx,
                outbound_session: outbound,
            },
        )
    }

    #[tokio::test]
    async fn session_request_timeout() {
        let (
            InboundContext {
                mut inbound_session,
                inbound_socket_rx,
                inbound_session_tx: _ib_sess_tx,
                ..
            },
            OutboundContext { .. },
        ) = create_session();

        // verify that `inbound_session` sends retry message
        let Packet { mut pkt, .. } = inbound_socket_rx.try_recv().unwrap();

        match HeaderReader::new(inbound_session.intro_key, &mut pkt)
            .unwrap()
            .parse(inbound_session.intro_key)
            .unwrap()
        {
            HeaderKind::Retry { .. } => {}
            _ => panic!("invalid packet type"),
        }

        match tokio::time::timeout(Duration::from_secs(20), &mut inbound_session)
            .await
            .expect("no timeout")
        {
            PendingSsu2SessionStatus::Timeout { .. } => {}
            _ => panic!("invalid status"),
        }
    }

    #[tokio::test]
    async fn token_request_received_again() {
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
            },
        ) = create_session();
        let intro_key = inbound_session.intro_key;

        // verify that `inbound_session` sends retry message but don't send it to `outbound_session`
        let Packet { mut pkt, .. } = inbound_socket_rx.try_recv().unwrap();

        match HeaderReader::new(inbound_session.intro_key, &mut pkt)
            .unwrap()
            .parse(inbound_session.intro_key)
            .unwrap()
        {
            HeaderKind::Retry { .. } => {}
            _ => panic!("invalid packet type"),
        }

        tokio::spawn(inbound_session);
        tokio::spawn(outbound_session);

        loop {
            tokio::select! {
                pkt = outbound_socket_rx.recv() => {
                    let Packet { mut pkt, address } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
                }
                pkt = inbound_socket_rx.recv() => {
                    let Packet { mut pkt, .. } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    match reader.parse(intro_key) {
                        Some(HeaderKind::Retry { .. }) => break,
                        _ => panic!("invalid packet"),
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn use_old_token_for_session_request() {
        let (
            InboundContext {
                mut inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
            },
        ) = create_session();
        let intro_key = inbound_session.intro_key;

        // parse and store the original retry packet
        let original_retry = {
            let Packet { mut pkt, address } = inbound_socket_rx.try_recv().unwrap();
            let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
            let _ = reader.dst_id();

            Packet { pkt, address }
        };

        // spawn outbound session in the background
        //
        // it'll send another token request and a session request using the wrong token
        tokio::spawn(outbound_session);

        loop {
            tokio::select! {
                status = &mut inbound_session => match status {
                    PendingSsu2SessionStatus::SessionTermianted { .. } => break,
                    _ => panic!("invalid status"),
                },
                pkt = outbound_socket_rx.recv() => {
                    let Packet { mut pkt, address } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
                }
                pkt = inbound_socket_rx.recv() => {
                    let Packet { mut pkt, .. } = pkt.unwrap();

                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();

                    match reader.parse(intro_key) {
                        Some(HeaderKind::Retry { .. }) => {
                            // send the original `Retry` with an expired token
                            ob_sess_tx.send(original_retry.clone()).await.unwrap();
                        },
                        _ => panic!("invalid packet"),
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn use_new_token_for_session_request() {
        crate::util::init_logger();

        let (
            InboundContext {
                mut inbound_session,
                inbound_socket_rx,
                inbound_session_tx: ib_sess_tx,
            },
            OutboundContext {
                outbound_session,
                outbound_session_tx: ob_sess_tx,
                outbound_socket_rx,
            },
        ) = create_session();
        let intro_key = inbound_session.intro_key;

        // read and discard first retry message
        let Packet { mut pkt, .. } = inbound_socket_rx.try_recv().unwrap();

        match HeaderReader::new(intro_key, &mut pkt).unwrap().parse(intro_key).unwrap() {
            HeaderKind::Retry { .. } => {}
            _ => panic!("invalid packet type"),
        }

        tokio::spawn(outbound_session);
        tokio::spawn(async move {
            while let Some(Packet { mut pkt, address }) = outbound_socket_rx.recv().await {
                let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                let _connection_id = reader.dst_id();

                ib_sess_tx.send(Packet { pkt, address }).await.unwrap();
            }
        });

        // handle retry retransmission
        {
            tokio::select! {
                _ = &mut inbound_session => {}
                pkt = inbound_socket_rx.recv() => {
                    let Packet { mut pkt, address } = pkt.unwrap();
                    let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
                    let _connection_id = reader.dst_id();
                    ob_sess_tx.send(Packet { pkt, address }).await.unwrap();
                }
            }
        }

        // verify that `inbound_session` sends `SessionCreated`
        {
            tokio::select! {
                _ = &mut inbound_session => unreachable!(),
                _ = inbound_socket_rx.recv() => {}
            }

            match inbound_session.state {
                PendingSessionState::AwaitingSessionConfirmed { .. } => {}
                _ => panic!("invalid state"),
            }
        }
    }
}
