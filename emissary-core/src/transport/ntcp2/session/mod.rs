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

//! NTCP2 Noise handshake implementation.
//!
//! https://geti2p.net/spec/ntcp2#overview
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.
//1 This implementation also refers to Alice as initiator and to Bob as responder.
//!
//! [`SessionManager::create_session()`] and [`SessionManager::create_session()`]
//! return futures which negotiate connection for initiators and responders, respectively.
//!
//! These two functions do not themselves implement code from the specification in order
//! to prevent mixing that code with I/O code. Handshake implementations for initiator
//! and responder can be found from `initiator.rs` and `responder.rs`.

use crate::{
    crypto::{noise::NoiseContext, sha256::Sha256, siphash::SipHash, StaticPrivateKey},
    error::Error,
    events::EventHandle,
    primitives::{RouterId, RouterInfo, TransportKind},
    profile::ProfileStorage,
    router::context::RouterContext,
    runtime::{Runtime, TcpStream},
    subsystem::SubsystemEvent,
    transport::{
        ntcp2::session::{initiator::Initiator, responder::Responder},
        Direction,
    },
    util::{is_global, AsyncReadExt, AsyncWriteExt},
};

use bytes::Bytes;

use alloc::{vec, vec::Vec};
use core::{future::Future, net::IpAddr, time::Duration};
use thingbuf::mpsc::Sender;

mod active;
mod initiator;
mod responder;

pub use active::Ntcp2Session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ntcp2::session";

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Maximum allowed clock skew.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Role of the session.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    /// Initiator (Alice).
    Initiator,

    /// Responder (Bob).
    Responder,
}

/// Key context.
pub(super) struct KeyContext {
    /// Key used to encrypt outbound messages.
    pub send_key: Vec<u8>,

    /// Key used to decrypt inbound messages.
    pub recv_key: Vec<u8>,

    /// SipHash context for (de)obfuscating message lengths.
    pub sip: SipHash,
}

impl KeyContext {
    /// Create new [`KeyContext`].
    pub fn new(send_key: Vec<u8>, recv_key: Vec<u8>, sip: SipHash) -> Self {
        Self {
            send_key,
            recv_key,
            sip,
        }
    }
}

/// Session manager.
///
/// Responsible for creating context for inbound and outboudn NTCP2 sessions.
pub struct SessionManager<R: Runtime> {
    /// Allow local addresses.
    allow_local: bool,

    /// Chaining key.
    chaining_key: [u8; 32],

    /// State that is common for all inbound connections.
    inbound_initial_state: [u8; 32],

    /// Local NTCP2 IV.
    local_iv: [u8; 16],

    /// Local NTCP2 static key.
    local_key: StaticPrivateKey,

    /// State that is common for all outbound connections.
    outbound_initial_state: [u8; 32],

    /// Router context.
    router_ctx: RouterContext<R>,

    /// TX channel for sending events to `SubsystemManager`.
    transport_tx: Sender<SubsystemEvent>,
}

impl<R: Runtime> SessionManager<R> {
    /// Create new [`SessionManager`].
    ///
    /// This function initializes the common state for both inbound and outbound connections.
    ///
    /// See the beginning of [1] for steps on generating start state.
    ///
    /// [1]: https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1
    pub fn new(
        local_key: [u8; 32],
        local_iv: [u8; 16],
        router_ctx: RouterContext<R>,
        allow_local: bool,
        transport_tx: Sender<SubsystemEvent>,
    ) -> Self {
        let local_key = StaticPrivateKey::from(local_key);
        let state = Sha256::new().update(PROTOCOL_NAME.as_bytes()).finalize_new();
        let chaining_key = state;
        let outbound_initial_state = Sha256::new().update(state).finalize_new();
        let inbound_initial_state = Sha256::new()
            .update(outbound_initial_state)
            .update(local_key.public().to_vec())
            .finalize_new();

        Self {
            allow_local,
            chaining_key,
            inbound_initial_state,
            local_iv,
            local_key,
            outbound_initial_state,
            router_ctx,
            transport_tx,
        }
    }

    /// Called by [`SessionManager::create_session()`] to open outbound session to `router`.
    async fn create_session_inner(
        router: RouterInfo,
        net_id: u8,
        local_info: Bytes,
        local_key: StaticPrivateKey,
        noise_ctx: NoiseContext,
        allow_local: bool,
        event_handle: EventHandle<R>,
        transport_tx: Sender<SubsystemEvent>,
    ) -> crate::Result<Ntcp2Session<R>> {
        let router_id = router.identity.id();

        let (remote_key, iv, socket_address) = {
            let static_key = router.ntcp2_static_key().ok_or_else(|| {
                tracing::warn!(target: LOG_TARGET, "static key missing from ntcp2 info");
                Error::InvalidData
            })?;
            let iv = router.ntcp2_iv().ok_or_else(|| {
                tracing::warn!(target: LOG_TARGET, "iv missing from ntcp2 info");
                Error::InvalidData
            })?;

            // transprot must exist since static key and iv were found
            let socket_address = router
                .addresses
                .get(&TransportKind::Ntcp2)
                .expect("to exist")
                .socket_address
                .ok_or_else(|| {
                    tracing::debug!(target: LOG_TARGET, "router doesn't have socket address");
                    Error::InvalidData
                })?;

            match socket_address.ip() {
                IpAddr::V4(address) if !is_global(address) && !allow_local => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?address,
                        "tried to dial local address but local addresses were disabled",
                    );
                    return Err(Error::InvalidData);
                }
                _ => {}
            }

            (static_key, iv, socket_address)
        };

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            ?socket_address,
            "start dialing remote peer",
        );

        let Some(mut stream) = R::TcpStream::connect(socket_address).await else {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "failed to dial router",
            );
            return Err(Error::DialFailure);
        };
        let router_hash = router.identity.hash().to_vec();

        // create `SessionRequest` message and send it remote peer
        let (mut initiator, message) = Initiator::new::<R>(
            noise_ctx,
            local_info,
            local_key,
            &remote_key,
            router_hash,
            iv,
            net_id,
        )?;
        stream.write_all(&message).await?;

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            "`SessionRequest` sent, read `SessonCreated`",
        );

        // read `SessionCreated` and decrypt & parse it to find padding length
        let mut reply = alloc::vec![0u8; 64];
        stream.read_exact::<R>(&mut reply).await?;

        let padding_len = initiator.register_session_created::<R>(&reply)?;

        // read padding and finalize session by sending `SessionConfirmed`
        let mut reply = alloc::vec![0u8; padding_len];
        stream.read_exact::<R>(&mut reply).await?;

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            "padding for `SessionCreated` read, create and send `SessionConfirmed`",
        );

        let (key_context, message) = initiator.finalize(&reply)?;
        stream.write_all(&message).await?;

        Ok(Ntcp2Session::<R>::new(
            Role::Initiator,
            router,
            stream,
            key_context,
            Direction::Outbound,
            event_handle,
            transport_tx,
        ))
    }

    /// Create new [`Handshaker`] for initiator (Alice).
    ///
    /// Implements the key generation from [1], creates a `SessionRequest` message and returns
    /// that message together with an [`Initiator`] object which allows the call to drive progress
    /// on the opening connection.
    ///
    /// [1]: https://geti2p.net/spec/ntcp2#key-derivation-function-kdf-for-handshake-message-1
    pub fn create_session(
        &self,
        router: RouterInfo,
    ) -> impl Future<Output = Result<Ntcp2Session<R>, (Option<RouterId>, Error)>> {
        let net_id = self.router_ctx.net_id();
        let local_info = self.router_ctx.router_info();
        let local_key = self.local_key.clone();
        let outbound_initial_state = self.outbound_initial_state;
        let chaining_key = self.chaining_key;
        let allow_local = self.allow_local;
        let event_handle = self.router_ctx.event_handle().clone();
        let router_id = router.identity.id();
        let transport_tx = self.transport_tx.clone();

        async move {
            match Self::create_session_inner(
                router,
                net_id,
                local_info,
                local_key,
                NoiseContext::new(chaining_key, outbound_initial_state),
                allow_local,
                event_handle,
                transport_tx.clone(),
            )
            .await
            {
                Ok(session) => Ok(session),
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to handshake with remote router",
                    );

                    if let Err(error) = transport_tx
                        .send(SubsystemEvent::ConnectionFailure {
                            router_id: router_id.clone(),
                        })
                        .await
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %router_id,
                            ?error,
                            "failed to report connection failure to subsystem manager",
                        );
                    }

                    Err((Some(router_id), error))
                }
            }
        }
    }

    /// Called by [`SessionManager::accept_session()`] to accept an inbound session.
    async fn accept_session_inner(
        mut stream: R::TcpStream,
        net_id: u8,
        local_router_hash: Vec<u8>,
        noise_ctx: NoiseContext,
        local_key: StaticPrivateKey,
        iv: [u8; 16],
        profile_storage: ProfileStorage<R>,
        event_handle: EventHandle<R>,
        transport_tx: Sender<SubsystemEvent>,
    ) -> crate::Result<Ntcp2Session<R>> {
        tracing::trace!(
            target: LOG_TARGET,
            "read `SessionRequest` from socket",
        );

        // read first part of `SessionRequest` which has fixed length
        let mut message = vec![0u8; 64];
        stream.read_exact::<R>(&mut message).await?;

        let (mut responder, padding_len) = Responder::new::<R>(
            noise_ctx,
            local_router_hash,
            local_key.clone(),
            iv,
            message,
            net_id,
        )?;

        // read padding and create session if the peer is accepted
        let mut padding = alloc::vec![0u8; padding_len];
        stream.read_exact::<R>(&mut padding).await?;

        let (message, message_len) = responder.create_session::<R>(padding)?;
        stream.write_all(&message).await?;

        // read `SessionConfirmed` message and finalize session
        let mut message = alloc::vec![0u8; message_len];
        stream.read_exact::<R>(&mut message).await?;

        match responder.finalize(message) {
            Ok((key_context, router)) => {
                if router.net_id() != net_id {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local_net_id = ?net_id,
                        remote_net_id = ?router.net_id(),
                        "remote router is part of a different network",
                    );

                    let _ = stream.close().await;
                    return Err(Error::NetworkMismatch);
                }

                profile_storage.add_router(router.clone());

                Ok(Ntcp2Session::new(
                    Role::Responder,
                    router,
                    stream,
                    key_context,
                    Direction::Inbound,
                    event_handle,
                    transport_tx,
                ))
            }
            Err(error) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to accept session",
                );
                let _ = stream.close().await;

                Err(error)
            }
        }
    }

    /// Accept inbound TCP connection and negotiate NTCP2 session parameters for it.
    pub fn accept_session(
        &self,
        stream: R::TcpStream,
    ) -> impl Future<Output = Result<Ntcp2Session<R>, (Option<RouterId>, Error)>> {
        let net_id = self.router_ctx.net_id();
        let local_router_hash = self.router_ctx.router_id().to_vec();
        let inbound_initial_state = self.inbound_initial_state;
        let chaining_key = self.chaining_key;
        let local_key = self.local_key.clone();
        let iv = self.local_iv;
        let profile_storage = self.router_ctx.profile_storage().clone();
        let event_handle = self.router_ctx.event_handle().clone();
        let transport_tx = self.transport_tx.clone();

        async move {
            Self::accept_session_inner(
                stream,
                net_id,
                local_router_hash,
                NoiseContext::new(chaining_key, inbound_initial_state),
                local_key,
                iv,
                profile_storage,
                event_handle,
                transport_tx,
            )
            .await
            .map_err(|error| (None, error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{SigningPrivateKey, StaticPrivateKey},
        events::EventManager,
        i2np::{Message, MessageType, I2NP_MESSAGE_EXPIRATION},
        primitives::{
            Capabilities, Date, Mapping, RouterAddress, RouterIdentity, RouterInfo, Str,
            TransportKind,
        },
        profile::ProfileStorage,
        runtime::{
            mock::{MockRuntime, MockTcpListener, MockTcpStream},
            Runtime, TcpListener as _,
        },
        subsystem::OutboundMessage,
        transport::ntcp2::{listener::Ntcp2Listener, session::SessionManager},
    };
    use bytes::Bytes;
    use futures::StreamExt;
    use hashbrown::HashMap;
    use rand::{thread_rng, RngCore};
    use std::time::Duration;
    use thingbuf::mpsc::channel;
    use tokio::net::TcpListener;

    struct Ntcp2Builder {
        net_id: u8,
        router_address: Option<RouterAddress>,
        ntcp2_iv: [u8; 16],
        ntcp2_key: [u8; 32],
    }

    impl Ntcp2Builder {
        fn new() -> Self {
            let ntcp2_key = {
                let mut local_key = [0u8; 32];
                thread_rng().fill_bytes(&mut local_key);
                local_key
            };
            let ntcp2_iv = {
                let mut local_iv = [0u8; 16];
                thread_rng().fill_bytes(&mut local_iv);
                local_iv
            };

            Self {
                net_id: 2u8,
                router_address: None,
                ntcp2_iv,
                ntcp2_key,
            }
        }

        fn with_net_id(mut self, net_id: u8) -> Self {
            self.net_id = net_id;
            self
        }

        fn with_router_address(mut self, port: u16) -> Self {
            self.router_address = Some(RouterAddress::new_published_ntcp2(
                self.ntcp2_key.clone(),
                self.ntcp2_iv,
                port,
                "127.0.0.1".parse().unwrap(),
            ));
            self
        }

        fn build(mut self) -> Ntcp2 {
            let signing_key = SigningPrivateKey::random(thread_rng());
            let static_key = StaticPrivateKey::random(thread_rng());
            let identity =
                RouterIdentity::from_keys::<MockRuntime>(&static_key, &signing_key).unwrap();
            let router_info = RouterInfo {
                identity,
                published: Date::new(
                    (MockRuntime::time_since_epoch() - Duration::from_secs(2 * 60)).as_millis()
                        as u64,
                ),
                addresses: HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    self.router_address.take().unwrap_or(RouterAddress::new_unpublished_ntcp2(
                        self.ntcp2_key.clone(),
                        8888,
                    )),
                )]),
                options: Mapping::from_iter([
                    (Str::from("netId"), Str::from(self.net_id.to_string())),
                    (Str::from("caps"), Str::from("L")),
                ]),
                net_id: self.net_id,
                capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
            };

            Ntcp2 {
                ntcp2_iv: self.ntcp2_iv,
                ntcp2_key: self.ntcp2_key,
                router_info,
                signing_key,
                static_key,
            }
        }
    }

    struct Ntcp2 {
        ntcp2_iv: [u8; 16],
        ntcp2_key: [u8; 32],
        router_info: RouterInfo,
        signing_key: SigningPrivateKey,
        static_key: StaticPrivateKey,
    }

    #[tokio::test]
    async fn connection_succeeds() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (transport_tx1, _transport_rx1) = channel(16);
        let local = Ntcp2Builder::new().build();
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                local.router_info.identity.id(),
                Bytes::from(local.router_info.serialize(&local.signing_key)),
                local.static_key,
                local.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx1,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let (transport_tx2, _transport_rx2) = channel(16);
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx2,
        );

        let handle =
            tokio::spawn(
                async move { local_manager.create_session(remote.router_info.clone()).await },
            );

        let stream = MockTcpStream::new(
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        );
        let (res1, res2) = tokio::join!(remote_manager.accept_session(stream), handle);

        assert!(res1.is_ok());
        assert!(res2.unwrap().is_ok());
    }

    #[tokio::test]
    async fn invalid_network_id_initiator() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let local = Ntcp2Builder::new().with_net_id(128).build();
        let (transport_tx1, _transport_rx1) = channel(16);
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                local.router_info.identity.id(),
                Bytes::from(local.router_info.serialize(&local.signing_key)),
                local.static_key,
                local.signing_key,
                128,
                event_handle.clone(),
            ),
            true,
            transport_tx1,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (transport_tx2, _transport_rx2) = channel(16);
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx2,
        );

        let handle = tokio::spawn(async move {
            let stream = MockTcpStream::new(
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            );
            remote_manager.accept_session(stream).await
        });

        assert!(local_manager.create_session(remote.router_info.clone()).await.is_err());
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn invalid_network_id_responder() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let local = Ntcp2Builder::new().build();
        let (transport_tx1, _transport_rx1) = channel(16);
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                local.router_info.identity.id(),
                Bytes::from(local.router_info.serialize(&local.signing_key)),
                local.static_key,
                local.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx1,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_net_id(128)
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let (transport_tx2, _transport_rx2) = channel(16);
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                128u8,
                event_handle.clone(),
            ),
            true,
            transport_tx2,
        );

        let handle = tokio::spawn(async move {
            let stream = MockTcpStream::new(
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            );
            remote_manager.accept_session(stream).await
        });

        assert!(local_manager.create_session(remote.router_info.clone()).await.is_err());
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn dialer_local_addresses_disabled() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (transport_tx1, _transport_rx1) = channel(16);
        let local = Ntcp2Builder::new().build();
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                local.router_info.identity.id(),
                Bytes::from(local.router_info.serialize(&local.signing_key)),
                local.static_key,
                local.signing_key,
                2u8,
                event_handle.clone(),
            ),
            false,
            transport_tx1,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_net_id(128)
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let (transport_tx2, _transport_rx2) = channel(16);
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx2,
        );

        tokio::spawn(async move {
            let stream = MockTcpStream::new(
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
            );
            remote_manager.accept_session(stream).await.unwrap();
        });

        assert!(local_manager.create_session(remote.router_info.clone()).await.is_err());
    }

    #[tokio::test]
    async fn listener_local_addresses_disabled() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (transport_tx1, _transport_rx1) = channel(16);
        let local = Ntcp2Builder::new().build();
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                local.router_info.identity.id(),
                Bytes::from(local.router_info.serialize(&local.signing_key)),
                local.static_key,
                local.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx1,
        );

        let listener = MockTcpListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut listener = Ntcp2Listener::<MockRuntime>::new(listener, false);
        let remote = Ntcp2Builder::new()
            .with_net_id(128)
            .with_router_address(listener.local_address().port())
            .build();

        tokio::spawn(async move { while let Some(_) = listener.next().await {} });

        assert!(local_manager.create_session(remote.router_info.clone()).await.is_err());
    }

    #[tokio::test]
    async fn received_expired_message() {
        let local = Ntcp2Builder::new().build();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (local_tx, local_rx) = channel(16);
        let local_manager = SessionManager::new(
            local.ntcp2_key,
            local.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                local.router_info.identity.id(),
                Bytes::from(local.router_info.serialize(&local.signing_key)),
                local.static_key,
                local.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            local_tx,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let (remote_tx, remote_rx) = channel(16);

        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            remote_tx,
        );

        let handle =
            tokio::spawn(
                async move { local_manager.create_session(remote.router_info.clone()).await },
            );

        let stream = MockTcpStream::new(
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        );
        let (res1, res2) = tokio::join!(remote_manager.accept_session(stream), handle);

        tokio::spawn(res1.unwrap().run());
        tokio::spawn(res2.unwrap().unwrap().run());

        let (_local_router, remote_command_tx) =
            tokio::time::timeout(Duration::from_secs(5), async {
                match remote_rx.recv().await {
                    Some(SubsystemEvent::ConnectionEstablished { router_id, tx }) =>
                        (router_id, tx),
                    _ => panic!("invalid event received"),
                }
            })
            .await
            .expect("no timeout");
        let (_remote_router, _local_command_tx) =
            tokio::time::timeout(Duration::from_secs(5), async {
                match local_rx.recv().await {
                    Some(SubsystemEvent::ConnectionEstablished { router_id, tx }) =>
                        (router_id, tx),
                    _ => panic!("invalid event received"),
                }
            })
            .await
            .expect("no timeout");

        // send non-expired database message
        remote_command_tx
            .send(OutboundMessage::Message(Message {
                expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                message_type: MessageType::DatabaseStore,
                message_id: 1337u32,
                payload: vec![1, 1, 1, 1],
            }))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            match local_rx.recv().await {
                Some(SubsystemEvent::Message { mut messages }) => {
                    assert_eq!(messages.len(), 1);
                    let (_, message) = messages.pop().unwrap();

                    assert_eq!(message.message_type, MessageType::DatabaseStore);
                    assert_eq!(message.message_id, 1337u32);
                    assert_eq!(message.payload, vec![1, 1, 1, 1]);
                }
                _ => panic!("invalid event received"),
            }
        })
        .await
        .expect("no timeout");

        // send expired database message
        remote_command_tx
            .send(OutboundMessage::Message(Message {
                expiration: MockRuntime::time_since_epoch() - Duration::from_secs(5),
                message_type: MessageType::DatabaseStore,
                message_id: 1338u32,
                payload: vec![2, 2, 2, 2],
            }))
            .await
            .unwrap();

        // operation times out because the message was expired
        tokio::time::timeout(Duration::from_secs(5), async {
            match local_rx.recv().await {
                _ => panic!("didn't expect to receive anything"),
            }
        })
        .await
        .unwrap_err();

        // send another non-expired database message
        remote_command_tx
            .send(OutboundMessage::Message(Message {
                expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                message_type: MessageType::DatabaseStore,
                message_id: 1339u32,
                payload: vec![3, 3, 3, 3],
            }))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            match local_rx.recv().await {
                Some(SubsystemEvent::Message { mut messages }) => {
                    assert_eq!(messages.len(), 1);
                    let (_, message) = messages.pop().unwrap();

                    assert_eq!(message.message_type, MessageType::DatabaseStore);
                    assert_eq!(message.message_id, 1339u32);
                    assert_eq!(message.payload, vec![3, 3, 3, 3]);
                }
                _ => panic!("invalid event received"),
            }
        })
        .await
        .expect("no timeout");
    }

    #[tokio::test]
    async fn clock_skew_too_far_in_the_future() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (transport_tx1, _transport_rx1) = channel(16);
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx1,
        );

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                MockRuntime::set_time(Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("to succeed")
                        + 2 * MAX_CLOCK_SKEW,
                ));

                let (transport_tx1, _transport_rx1) = channel(16);
                let local = Ntcp2Builder::new().build();
                let local_manager = SessionManager::new(
                    local.ntcp2_key,
                    local.ntcp2_iv,
                    RouterContext::new(
                        MockRuntime::register_metrics(Vec::new(), None),
                        ProfileStorage::<MockRuntime>::new(&[], &[]),
                        local.router_info.identity.id(),
                        Bytes::from(local.router_info.serialize(&local.signing_key)),
                        local.static_key,
                        local.signing_key,
                        2u8,
                        event_handle.clone(),
                    ),
                    true,
                    transport_tx1,
                );

                local_manager.create_session(remote.router_info.clone()).await
            })
        });

        let stream = MockTcpStream::new(
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        );
        let future = tokio::task::spawn_blocking(move || handle.join().unwrap());
        let (res1, _res2) = tokio::join!(remote_manager.accept_session(stream), future);

        assert!(res1.is_err());
    }

    #[tokio::test]
    async fn clock_skew_too_far_in_the_past() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (transport_tx1, _transport_rx1) = channel(16);
        let remote = Ntcp2Builder::new()
            .with_router_address(listener.local_addr().unwrap().port())
            .build();
        let remote_manager = SessionManager::new(
            remote.ntcp2_key,
            remote.ntcp2_iv,
            RouterContext::new(
                MockRuntime::register_metrics(Vec::new(), None),
                ProfileStorage::<MockRuntime>::new(&[], &[]),
                remote.router_info.identity.id(),
                Bytes::from(remote.router_info.serialize(&remote.signing_key)),
                remote.static_key,
                remote.signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
            transport_tx1,
        );

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                MockRuntime::set_time(Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("to succeed")
                        - 2 * MAX_CLOCK_SKEW,
                ));

                let (transport_tx1, _transport_rx1) = channel(16);
                let local = Ntcp2Builder::new().build();
                let local_manager = SessionManager::new(
                    local.ntcp2_key,
                    local.ntcp2_iv,
                    RouterContext::new(
                        MockRuntime::register_metrics(Vec::new(), None),
                        ProfileStorage::<MockRuntime>::new(&[], &[]),
                        local.router_info.identity.id(),
                        Bytes::from(local.router_info.serialize(&local.signing_key)),
                        local.static_key,
                        local.signing_key,
                        2u8,
                        event_handle.clone(),
                    ),
                    true,
                    transport_tx1,
                );

                local_manager.create_session(remote.router_info.clone()).await
            })
        });

        let stream = MockTcpStream::new(
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
                .0,
        );
        let future = tokio::task::spawn_blocking(move || handle.join().unwrap());
        let (res1, _res2) = tokio::join!(remote_manager.accept_session(stream), future);

        assert!(res1.is_err());
    }
}
