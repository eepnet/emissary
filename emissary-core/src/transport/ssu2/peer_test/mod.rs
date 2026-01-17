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

#![allow(unused)]

use crate::{
    primitives::{RouterId, TransportKind},
    profile::ProfileStorage,
    runtime::Runtime,
    transport::ssu2::{
        message::PeerTestMessage,
        peer_test::types::{
            PeerTestCommand, PeerTestEvent, PeerTestEventRecycle, PeerTestHandle, RejectionReason,
        },
    },
};

use hashbrown::HashMap;
use thingbuf::mpsc::{with_recycle, Receiver, Sender};

use core::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

pub mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::peer-test";

/// Peer test candidate.
///
/// Used for resolving inbound peer tests.
struct PeerTestCandiate {
    /// Router ID.
    router_id: RouterId,

    /// Does the router support IPv4.
    supports_ipv4: bool,

    /// Does the router support IPv6.
    supports_ipv6: bool,

    /// TX channel for sending commands to the active session.
    tx: Sender<PeerTestCommand>,
}

/// Peer test context.
#[derive(Debug)]
struct PeerTestContext {
    /// Socket address of Alice.
    address: SocketAddr,

    /// Router ID of Alice.
    alice_router_id: RouterId,

    /// TX channel for sending commands to Alice.
    alice_tx: Sender<PeerTestCommand>,

    /// Router ID of Charlie.
    charlie_router_id: RouterId,

    /// Session ID of Charlie.
    charlie_session_id: u64,
}

/// Peer test manager.
///
/// Manager both inbound and outbound peer tests.
pub struct PeerTestManager<R: Runtime> {
    /// Active sessions.
    active: HashMap<u64, PeerTestCandiate>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// Active, remote-initiated peer tests.
    remote_tests: HashMap<u32, PeerTestContext>,

    /// RX channel for receiving peer test-related messages from active sessions.
    rx: Receiver<PeerTestEvent, PeerTestEventRecycle>,

    /// RX channel for receiving peer test-related messages from active sessions.
    tx: Sender<PeerTestEvent, PeerTestEventRecycle>,
}

impl<R: Runtime> PeerTestManager<R> {
    /// Create new `PeerTestManager`.
    pub fn new(profile_storage: ProfileStorage<R>) -> Self {
        let (tx, rx) = with_recycle(256, PeerTestEventRecycle::default());

        Self {
            active: HashMap::new(),
            profile_storage,
            remote_tests: HashMap::new(),
            rx,
            tx,
        }
    }

    /// Get handle to `PeerTestManager`.
    pub fn handle(&self) -> PeerTestHandle {
        PeerTestHandle::new(self.tx.clone())
    }

    /// Add new active session to `PeerTestManager`.
    ///
    /// The session is added only if the router supports both peer testing and IPv4 or IPv6.
    ///
    /// The router may be chosen to acts as Charlie during an inbound peer test process.
    pub fn add_session(
        &mut self,
        router_id: &RouterId,
        connection_id: u64,
        tx: Sender<PeerTestCommand>,
    ) {
        let Some(router_info) = self.profile_storage.get(router_id) else {
            tracing::error!(
                target: LOG_TARGET,
                %router_id,
                %connection_id,
                "router doesn't exist in profile storage",
            );
            debug_assert!(false);
            return;
        };

        let Some(address) = router_info.addresses.get(&TransportKind::Ssu2) else {
            tracing::error!(
                target: LOG_TARGET,
                %router_id,
                %connection_id,
                "router doesn't support ssu2",
            );
            debug_assert!(false);
            return;
        };

        if !address.supports_peer_testing() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                %connection_id,
                "router doesn't support peer testing, ignoring",
            );
            return;
        }

        let supports_ipv4 = address.supports_ipv4();
        let supports_ipv6 = address.supports_ipv6();

        if !supports_ipv4 && !supports_ipv6 {
            tracing::warn!(
                target: LOG_TARGET,
                %router_id,
                %connection_id,
                "router doesn't support ipv4 or ipv6",
            );
            return;
        }

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            %connection_id,
            %supports_ipv4,
            %supports_ipv6,
            "add new peer test candidate"
        );

        self.active.insert(
            connection_id,
            PeerTestCandiate {
                router_id: router_id.clone(),
                supports_ipv4,
                supports_ipv6,
                tx,
            },
        );
    }

    /// Remove terminated session from `PeerTestManager`.
    pub fn remove_session(&mut self, session: &u64) {
        self.active.remove(session);
    }

    /// Handle peer test message 1, i.e., a peer test request from Alice to Bob.
    ///
    /// First attempt to find an active session with compatible transport (IPv4/IPv6) and if none is
    /// found, send rejection over the channel to the session.
    ///
    /// If a compatible session is found, create a new peer test entry and send the router info of
    /// Alice to the active session (Charlie).
    ///
    /// Once a response is received from Charlie, relay that back to the session from which the
    /// original peer test originated from through `tx`.
    fn handle_peer_test_message_1(
        &mut self,
        alice_router_id: RouterId,
        nonce: u32,
        address: SocketAddr,
        alice_tx: Sender<PeerTestCommand>,
    ) {
        tracing::trace!(
            target: LOG_TARGET,
            %alice_router_id,
            %nonce,
            ?address,
            "inbound peer test request",
        );

        // TODO: more random
        let Some((
            charlie_session_id,
            PeerTestCandiate {
                router_id: charlie_router_id,
                tx: charlie_tx,
                ..
            },
        )) = self.active.iter().find(
            |(
                _,
                PeerTestCandiate {
                    supports_ipv4,
                    supports_ipv6,
                    router_id: charlie_router_id,
                    ..
                },
            )| {
                ((address.is_ipv4() == *supports_ipv4 || address.is_ipv6() == *supports_ipv6)
                    && charlie_router_id != &alice_router_id)
            },
        )
        else {
            tracing::debug!(
                target: LOG_TARGET,
                ipv4 = %address.is_ipv4(),
                "no compatible router found for peer test message 1",
            );
            if let Err(error) = alice_tx.try_send(PeerTestCommand::Reject {
                nonce,
                reason: RejectionReason::NoRouterAvailable,
            }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    %alice_router_id,
                    ?nonce,
                    ?error,
                    "failed to send rejection to alice",
                );
            }

            return;
        };

        // router info for alice should exist since we just received a peer test request from them
        let Some(router_info) = self.profile_storage.get_raw(&alice_router_id) else {
            tracing::error!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                "router info for alice not found",
            );
            debug_assert!(false);
            return;
        };

        // attempt to send peer test request to charlie with alice's information
        //
        // the send might fail if charlie is overloaded or the connection has already closed but
        // `PeerTestManager` was not notified of it yet
        match charlie_tx.try_send(PeerTestCommand::TestPeer {
            address,
            nonce,
            router_info,
        }) {
            Ok(()) => {}
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %alice_router_id,
                    %charlie_router_id,
                    ?error,
                    "failed to send peer test request to charlie"
                );

                if let Err(error) = alice_tx.try_send(PeerTestCommand::Reject {
                    nonce,
                    reason: RejectionReason::Unspecified,
                }) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %alice_router_id,
                        ?nonce,
                        ?error,
                        "failed to send rejection to alice",
                    );
                }

                return;
            }
        }

        tracing::debug!(
            target: LOG_TARGET,
            %alice_router_id,
            %charlie_router_id,
            "started peer test",
        );

        if let Some(context) = self.remote_tests.insert(
            nonce,
            PeerTestContext {
                address,
                alice_router_id: alice_router_id.clone(),
                alice_tx,
                charlie_router_id: charlie_router_id.clone(),
                charlie_session_id: *charlie_session_id,
            },
        ) {
            tracing::warn!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                ?context,
                "overwrote previous context",
            );
        }
    }
}

impl<R: Runtime> Future for PeerTestManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(PeerTestEvent::Message1 {
                    address,
                    nonce,
                    router_id,
                    tx,
                })) => self.handle_peer_test_message_1(router_id, nonce, address, tx),
                Poll::Ready(Some(PeerTestEvent::Dummy)) => unreachable!(),
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{
            Capabilities, Date, Mapping, RouterAddress, RouterIdentity, RouterInfo,
            RouterInfoBuilder, Str,
        },
        runtime::mock::MockRuntime,
        Ssu2Config,
    };
    use bytes::Bytes;
    use rand::RngCore;
    use thingbuf::mpsc::channel;

    fn make_router_info(caps: Str) -> (RouterId, RouterInfo, Bytes) {
        let ssu2 = RouterAddress {
            cost: 8,
            expires: Date::new(0),
            transport: TransportKind::Ssu2,
            options: Mapping::from_iter([(Str::from("caps"), caps)]),
            socket_address: None,
        };
        let (identity, _, signing_key) = RouterIdentity::random();
        let router_id = identity.id();
        let router_info = RouterInfo {
            addresses: HashMap::from_iter([(TransportKind::Ssu2, ssu2)]),
            capabilities: Capabilities::parse(&Str::from("XR")).unwrap(),
            identity,
            net_id: 2,
            options: Mapping::from_iter([
                (Str::from("caps"), Str::from("XR")),
                (Str::from("netId"), Str::from("2")),
            ]),
            published: Date::new(MockRuntime::rng().next_u64()),
        };
        let serialized = Bytes::from(router_info.serialize(&signing_key));

        (router_id, router_info, serialized)
    }

    #[tokio::test]
    #[should_panic]
    async fn session_doesnt_exist_in_profile_storage() {
        let mut manager = PeerTestManager::new(ProfileStorage::<MockRuntime>::new(&[], &[]));
        let (tx, _rx) = channel(16);
        manager.add_session(&RouterId::random(), 1337u64, tx);
    }

    #[tokio::test]
    #[should_panic]
    async fn session_doesnt_support_ssu2() {
        let (router_info, _, _) = RouterInfoBuilder::default().build();
        let router_id = router_info.identity.id();
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, 1337u64, tx);
    }

    #[tokio::test]
    async fn router_doesnt_support_peer_testing() {
        let (router_id, router_info, _) = make_router_info(Str::from("C64"));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, 1337u64, tx);

        assert!(!manager.active.contains_key(&1337));
    }

    #[tokio::test]
    async fn router_doesnt_support_ipv4_or_ipv6() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC"));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, 1337u64, tx);

        assert!(!manager.active.contains_key(&1337));
    }

    #[tokio::test]
    async fn router_supports_peer_testing_over_ipv4() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC4"));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, 1337u64, tx);

        let PeerTestCandiate {
            supports_ipv4,
            supports_ipv6,
            ..
        } = manager.active.get(&1337).unwrap();
        assert!(supports_ipv4);
        assert!(!supports_ipv6);
    }

    #[tokio::test]
    async fn router_supports_peer_testing_over_ipv6() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC6"));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, 1337u64, tx);

        let PeerTestCandiate {
            supports_ipv4,
            supports_ipv6,
            ..
        } = manager.active.get(&1337).unwrap();
        assert!(!supports_ipv4);
        assert!(supports_ipv6);
    }

    #[tokio::test]
    async fn router_supports_peer_testing_over_ipv4_and_ipv6() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC46"));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, 1337u64, tx);

        let PeerTestCandiate {
            supports_ipv4,
            supports_ipv6,
            ..
        } = manager.active.get(&1337).unwrap();
        assert!(supports_ipv4);
        assert!(supports_ipv6);
    }

    #[tokio::test]
    #[should_panic]
    async fn inbound_request_alice_doesnt_exist() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id, router_info, _) = make_router_info(Str::from("BC46"));
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, rx) = channel(16);
        manager.add_session(&router_id, 1337, tx);

        let (alice_tx, _alice_rx) = channel(16);
        manager.handle_peer_test_message_1(
            RouterId::random(),
            1338,
            "127.0.0.1:8888".parse().unwrap(),
            alice_tx,
        );
    }

    // alice is the only router with an active session
    //
    // make sure it's not chosen as charlie
    #[tokio::test]
    async fn inbound_request_alice_is_not_chosen() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id, router_info, _) = make_router_info(Str::from("BC46"));
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(storage);
        let (tx, rx) = channel(16);
        manager.add_session(&router_id, 1337, tx.clone());

        manager.handle_peer_test_message_1(
            router_id.clone(),
            1338,
            "127.0.0.1:8888".parse().unwrap(),
            tx.clone(),
        );

        match rx.try_recv().unwrap() {
            PeerTestCommand::Reject {
                nonce: 1338,
                reason: RejectionReason::NoRouterAvailable,
            } => {}
            _ => panic!("invalid command"),
        }
        assert!(manager.remote_tests.is_empty());
    }

    #[tokio::test]
    async fn inbound_request_rejected_no_ipv4_routers() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id1, router_info1, _) = make_router_info(Str::from("BC46"));
        let (router_id2, router_info2, _) = make_router_info(Str::from("BC6"));
        storage.add_router(router_info1);
        storage.add_router(router_info2);

        let mut manager = PeerTestManager::new(storage);
        let (tx, rx) = channel(16);
        manager.add_session(&router_id1, 1337, tx.clone());

        manager.handle_peer_test_message_1(
            router_id1.clone(),
            1338,
            "127.0.0.1:8888".parse().unwrap(),
            tx.clone(),
        );

        match rx.try_recv().unwrap() {
            PeerTestCommand::Reject {
                nonce: 1338,
                reason: RejectionReason::NoRouterAvailable,
            } => {}
            _ => panic!("invalid command"),
        }
        assert!(manager.remote_tests.is_empty());
    }

    #[tokio::test]
    async fn inbound_request_rejected_no_ipv6_routers() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id1, router_info1, _) = make_router_info(Str::from("BC46"));
        let (router_id2, router_info2, _) = make_router_info(Str::from("BC4"));
        storage.add_router(router_info1);
        storage.add_router(router_info2);

        let mut manager = PeerTestManager::new(storage);
        let (tx, rx) = channel(16);
        manager.add_session(&router_id1, 1337, tx.clone());

        manager.handle_peer_test_message_1(
            router_id1.clone(),
            1338,
            "[::]:8888".parse().unwrap(),
            tx.clone(),
        );

        match rx.try_recv().unwrap() {
            PeerTestCommand::Reject {
                nonce: 1338,
                reason: RejectionReason::NoRouterAvailable,
            } => {}
            _ => panic!("invalid command"),
        }
        assert!(manager.remote_tests.is_empty());
    }

    #[tokio::test]
    async fn inbound_request_accepted() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id1, router_info1, serialized1) = make_router_info(Str::from("BC46"));
        let (router_id2, router_info2, serialized2) = make_router_info(Str::from("BC46"));
        storage.discover_router(router_info1, serialized1);
        storage.discover_router(router_info2, serialized2);

        let mut manager = PeerTestManager::new(storage);
        let (charlie_tx, charlie_rx) = channel(16);
        manager.add_session(&router_id2, 1337, charlie_tx.clone());

        let (alice_tx, alice_rx) = channel(16);
        manager.handle_peer_test_message_1(
            router_id1.clone(),
            1338,
            "127.0.0.1:8888".parse().unwrap(),
            alice_tx.clone(),
        );

        match charlie_rx.try_recv().unwrap() {
            PeerTestCommand::TestPeer {
                address,
                nonce,
                router_info,
            } => {
                assert_eq!(address, "127.0.0.1:8888".parse().unwrap());
                assert_eq!(nonce, 1338);
                assert_eq!(
                    RouterInfo::parse(router_info).unwrap().identity.id(),
                    router_id1
                );
            }
            _ => panic!("invalid command"),
        }
        assert!(alice_rx.try_recv().is_err());

        let PeerTestContext {
            address,
            alice_router_id,
            charlie_router_id,
            charlie_session_id,
            ..
        } = manager.remote_tests.remove(&1338).unwrap();

        assert_eq!(address, "127.0.0.1:8888".parse().unwrap());
        assert_eq!(alice_router_id, router_id1);
        assert_eq!(charlie_router_id, router_id2);
        assert_eq!(charlie_session_id, 1337);
    }
}
