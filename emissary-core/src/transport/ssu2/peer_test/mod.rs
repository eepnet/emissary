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
    crypto::chachapoly::ChaChaPoly,
    error::{PeerTestError, Ssu2Error},
    primitives::{RouterId, RouterInfo, TransportKind},
    profile::ProfileStorage,
    router::context::RouterContext,
    runtime::{Instant, Runtime, UdpSocket},
    transport::ssu2::{
        message::{Block, PeerTestBuilder, PeerTestMessage},
        peer_test::types::{
            PeerTestCommand, PeerTestEvent, PeerTestEventRecycle, PeerTestHandle, RejectionReason,
        },
    },
};

use bytes::{BufMut, BytesMut};
use futures::FutureExt;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc::{with_recycle, Receiver, Sender};

use alloc::collections::VecDeque;
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::peer-test";

/// Maintenance interval for `PeerTestManager`.
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(5000);

/// After how long is peer test considered stale.
const PEER_TEST_EXPIRATION: Duration = Duration::from_secs(30);

/// Peer test candidate.
///
/// Used for resolving inbound peer tests.
struct PeerTestCandiate {
    /// Does the router support IPv4.
    supports_ipv4: bool,

    /// Does the router support IPv6.
    supports_ipv6: bool,

    /// TX channel for sending commands to the active session.
    tx: Sender<PeerTestCommand>,
}

/// Context for pending peer test initiated by a remote router.
#[derive(Debug)]
struct PendingRemoteTest {
    /// Socket address of Alice.
    address: SocketAddr,

    /// Router ID of Alice.
    alice_router_id: RouterId,

    /// TX channel for sending commands to Alice.
    alice_tx: Sender<PeerTestCommand>,

    /// Router ID of Charlie.
    charlie_router_id: RouterId,
}

/// Context for active peer test initiated by a remote router.
#[derive(Debug)]
struct ActiveRemoteTest {
    /// Socket address that Alice requested be used.
    address: SocketAddr,

    /// Intro key of Alice.
    alice_intro_key: [u8; 32],

    /// Destination connection ID.
    dst_id: u64,

    /// Message from Alice's original peer test request (message 1).
    message: Vec<u8>,

    /// Source connection ID.
    src_id: u64,
}

/// Context for an active peer test initiated by a local router.
#[derive(Debug)]
enum ActiveTest<R: Runtime> {
    Pending {
        /// Router ID of Bob.
        bob_router_id: RouterId,

        /// Test nonce.
        nonce: u32,

        /// Message + signature from message 1.
        message: Vec<u8>,

        /// Source connection ID.
        src_id: u64,

        /// When was the test started.
        started: R::Instant,

        /// Has message 5 been received.
        message_5_received: bool,

        /// Charlie's address.
        charlie_address: Option<SocketAddr>,
    },

    /// Active peer test
    Active {
        /// Router ID of Bob.
        bob_router_id: RouterId,

        /// Message + signature received from Charlie.
        message: Vec<u8>,

        /// Router ID of Charlie.
        charlie_router_id: RouterId,

        /// Test nonce.
        nonce: u32,

        /// Source connection ID.
        src_id: u64,

        /// When was the test started.
        started: R::Instant,
    },
}

impl<R: Runtime> ActiveTest<R> {
    /// Is the test still considered active.
    ///
    /// The test is considered stale if it's pending or active after 20 seconds of getting started.
    fn is_active(&self) -> bool {
        match self {
            Self::Pending { started, .. } | Self::Active { started, .. } =>
                started.elapsed() < PEER_TEST_EXPIRATION,
        }
    }
}

/// Peer test manager.
///
/// Manager both inbound and outbound peer tests.
pub struct PeerTestManager<R: Runtime> {
    /// Active sessions.
    ///
    /// These are the routers that could partake in peer tests, not all connected routers.
    active: HashMap<RouterId, PeerTestCandiate>,

    /// Active, outbound peer test.
    active_outbound: Option<ActiveTest<R>>,

    /// Active peer test, out-of-session peer tests.
    active_tests: HashMap<u64, ActiveRemoteTest>,

    /// Port where the socket was bound to
    bind_port: u16,

    /// All connected routers.
    connected: HashSet<RouterId>,

    /// External address.
    external_address: Option<SocketAddr>,

    /// Our intro key.
    intro_key: [u8; 32],

    /// Timer for maintaining local peer tests.
    maintenance_timer: R::Timer,

    /// Pending, remote-initiated peer tests.
    pending_tests: HashMap<u32, PendingRemoteTest>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// RX channel for receiving peer test-related messages from active sessions.
    rx: Receiver<PeerTestEvent, PeerTestEventRecycle>,

    /// UDP socket.
    socket: R::UdpSocket,

    /// RX channel for receiving peer test-related messages from active sessions.
    tx: Sender<PeerTestEvent, PeerTestEventRecycle>,

    /// Write buffer.
    write_buffer: VecDeque<(BytesMut, SocketAddr)>,
    enabled: bool,
}

impl<R: Runtime> PeerTestManager<R> {
    /// Create new `PeerTestManager`.
    pub fn new(intro_key: [u8; 32], socket: R::UdpSocket, router_ctx: RouterContext<R>) -> Self {
        let (tx, rx) = with_recycle(256, PeerTestEventRecycle::default());

        Self {
            enabled: format!("{}", router_ctx.router_id()).starts_with("1Cpm"),
            active: HashMap::new(),
            active_outbound: None,
            active_tests: HashMap::new(),
            bind_port: socket.local_address().expect("to exist").port(),
            connected: HashSet::new(),
            external_address: None,
            intro_key,
            maintenance_timer: R::timer(MAINTENANCE_INTERVAL),
            pending_tests: HashMap::new(),
            router_ctx,
            rx,
            socket,
            tx,
            write_buffer: VecDeque::new(),
        }
    }

    /// Get handle to `PeerTestManager`.
    pub fn handle(&self) -> PeerTestHandle {
        PeerTestHandle::new(self.tx.clone())
    }

    /// Add an external address discovered during an outbound handshake.
    pub fn add_external_address(&mut self, address: SocketAddr) {
        if self.external_address.is_none() {
            tracing::info!(
                target: LOG_TARGET,
                ?address,
                "discovered external address",
            );
        }

        self.external_address = Some(address);
    }

    /// Add new active session to `PeerTestManager`.
    ///
    /// The session is added only if the router supports both peer testing and IPv4 or IPv6.
    ///
    /// The router may be chosen to acts as Charlie during an inbound peer test process.
    pub fn add_session(&mut self, router_id: &RouterId, tx: Sender<PeerTestCommand>) {
        self.connected.insert(router_id.clone());

        // inbound connection from an unknown router
        let Some(router_info) = self.router_ctx.profile_storage().get(router_id) else {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "cannot add candidate, router doesn't exist in profile storage",
            );
            return;
        };

        let Some(address) = router_info.addresses.get(&TransportKind::Ssu2) else {
            tracing::error!(
                target: LOG_TARGET,
                %router_id,
                "router doesn't support ssu2",
            );
            debug_assert!(false);
            return;
        };

        if !address.supports_peer_testing() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
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
                "router doesn't support ipv4 or ipv6",
            );
            return;
        }

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            %supports_ipv4,
            %supports_ipv6,
            "add new peer test candidate"
        );

        self.active.insert(
            router_id.clone(),
            PeerTestCandiate {
                supports_ipv4,
                supports_ipv6,
                tx,
            },
        );
    }

    /// Remove terminated session from `PeerTestManager`.
    pub fn remove_session(&mut self, router_id: &RouterId) {
        self.connected.remove(router_id);
        self.active.remove(router_id);
    }

    /// Attempt to select a peer test candidate, ignoring all routers in `ignore` and either
    /// selecting a candidate that supports IPv4 if `ipv4` is true and IPv6 if `ipv4` is false.
    ///
    /// Returns `None` if there are no candidates.
    fn select_router(
        &self,
        ipv4: bool,
        ignore: &HashSet<RouterId>,
    ) -> Option<(&RouterId, &PeerTestCandiate)> {
        if self.active.is_empty() {
            return None;
        }

        let start = (R::rng().next_u32() as usize) % self.active.len();

        let mut router = self.active.iter().skip(start).find(
            |(
                router_id,
                PeerTestCandiate {
                    supports_ipv4,
                    supports_ipv6,
                    tx,
                },
            )| { (ipv4 == *supports_ipv4 && !ignore.contains(*router_id)) },
        );

        router.or_else(|| {
            self.active.iter().find(
                |(
                    router_id,
                    PeerTestCandiate {
                        supports_ipv4,
                        supports_ipv6,
                        tx,
                    },
                )| { (ipv4 == *supports_ipv4 && !ignore.contains(*router_id)) },
            )
        })
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
    fn handle_alice_request(
        &mut self,
        alice_router_id: RouterId,
        nonce: u32,
        message: Vec<u8>,
        address: SocketAddr,
        alice_tx: Sender<PeerTestCommand>,
    ) {
        tracing::trace!(
            target: LOG_TARGET,
            %alice_router_id,
            %nonce,
            ?address,
            "inbound peer test request (alice -> bob)",
        );

        let Some((charlie_router_id, PeerTestCandiate { tx: charlie_tx, .. })) =
            self.select_router(address.is_ipv4(), &HashSet::from([alice_router_id.clone()]))
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
        let Some(router_info) = self.router_ctx.profile_storage().get_raw(&alice_router_id) else {
            tracing::error!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                "router info for alice not found",
            );
            debug_assert!(false);
            return;
        };

        match crate::primitives::RouterInfo::parse(&router_info) {
            Err(error) => {
                tracing::error!(
                    target: LOG_TARGET,
                    %alice_router_id,
                    ?error,
                    "failed to parse alice's router info??",
                );
                debug_assert!(false);
            }
            Ok(_) => {}
        }

        // attempt to send peer test request to charlie with alice's information
        //
        // the send might fail if charlie is overloaded or the connection has already closed but
        // `PeerTestManager` was not notified of it yet
        match charlie_tx.try_send(PeerTestCommand::RequestCharlie {
            address,
            message,
            nonce,
            router_id: alice_router_id.clone(),
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

        tracing::trace!(
            target: LOG_TARGET,
            %alice_router_id,
            %charlie_router_id,
            ?nonce,
            "started peer test",
        );

        if let Some(context) = self.pending_tests.insert(
            nonce,
            PendingRemoteTest {
                address,
                alice_router_id: alice_router_id.clone(),
                alice_tx,
                charlie_router_id: charlie_router_id.clone(),
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

    /// Handle peer test message 2, i.e., a peer test request from Bob to Charlie.
    ///
    /// Attempt to locate Alice's router info from `ProfileStorage` and reject the peer test request
    /// if it's not found. If the router info is found, verify that Charlie doesn't have an active
    /// connection to Charlie and that Alice's requested test address matches the address that
    /// Charlie supports.
    ///
    /// If all conditions are met, inform Bob that the peer test request was accepted, create an
    /// active test entry for Alice and send the peer test message 5 immediately.
    fn handle_bob_request(
        &mut self,
        alice_router_id: RouterId,
        nonce: u32,
        address: SocketAddr,
        message: Vec<u8>,
        router_info: Option<Box<RouterInfo>>,
    ) -> Option<PeerTestCommand> {
        tracing::trace!(
            target: LOG_TARGET,
            %alice_router_id,
            ?nonce,
            ?address,
            "inbound peer test request (bob -> charlie)",
        );

        let router_info = match router_info {
            Some(router_info) => *router_info,
            None => match self.router_ctx.profile_storage().get(&alice_router_id) {
                Some(router_info) => router_info,
                None => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %alice_router_id,
                        ?nonce,
                        "alice not found from local storage, unable to perform peer test",
                    );

                    return Some(PeerTestCommand::SendCharlieResponse {
                        nonce,
                        router_id: alice_router_id,
                        rejection: Some(RejectionReason::RouterUnknown),
                    });
                }
            },
        };

        // TODO: this doesn't make any sense
        let Some(intro_key) = router_info.ssu2_intro_key() else {
            tracing::warn!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                "no intro key for in alice's router info, rejecting",
            );
            debug_assert!(false);
            return None;
        };

        // ensure alice is not connected
        if self.connected.contains(&alice_router_id) {
            tracing::debug!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                "alice already connected, rejecting",
            );

            return Some(PeerTestCommand::SendCharlieResponse {
                nonce,
                router_id: alice_router_id.clone(),
                rejection: Some(RejectionReason::AlreadyConnected),
            });
        }

        // only ipv4 is supported for now
        if address.is_ipv6() {
            tracing::debug!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                "ipv6 not supported, rejecting",
            );

            return Some(PeerTestCommand::SendCharlieResponse {
                nonce,
                router_id: alice_router_id.clone(),
                rejection: Some(RejectionReason::UnsupportedAddress),
            });
        }

        tracing::trace!(
            target: LOG_TARGET,
            %alice_router_id,
            ?nonce,
            ?address,
            "send peer test message 5 to alice",
        );

        let dst_id = (((nonce as u64) << 32) | (nonce as u64)).to_be();
        let src_id = (!(((nonce as u64) << 32) | (nonce as u64))).to_be();

        let pkt = PeerTestBuilder::new(5, &message)
            .with_src_id(src_id)
            .with_dst_id(dst_id)
            .with_intro_key(intro_key)
            .with_addres(address)
            .build::<R>();

        self.write_buffer.push_back((pkt, address));
        self.active_tests.insert(
            dst_id,
            ActiveRemoteTest {
                address,
                alice_intro_key: intro_key,
                dst_id,
                message,
                src_id,
            },
        );

        Some(PeerTestCommand::SendCharlieResponse {
            nonce,
            router_id: alice_router_id.clone(),
            rejection: None,
        })
    }

    /// Handle peer test response from Charlie.
    ///
    /// This is the peer test message 3 received from Charlie to Bob which must be relayed
    /// as-is to Alice, with whom Bob has an active connection.
    fn handle_charlie_response(
        &mut self,
        nonce: u32,
        rejection: Option<RejectionReason>,
        message: Vec<u8>,
    ) {
        tracing::trace!(
            target: LOG_TARGET,
            ?nonce,
            ?rejection,
            "handle peer test response from charlie",
        );

        let Some(PendingRemoteTest {
            address,
            alice_router_id,
            alice_tx,
            charlie_router_id,
        }) = self.pending_tests.get(&nonce)
        else {
            tracing::warn!(
                target: LOG_TARGET,
                ?nonce,
                "peer test record doesn't exist",
            );
            return;
        };

        let Some(router_info) = self.router_ctx.profile_storage().get_raw(&charlie_router_id)
        else {
            tracing::error!(
                target: LOG_TARGET,
                %alice_router_id,
                ?nonce,
                "router info for charlie not found",
            );
            debug_assert!(false);
            return;
        };

        if let Err(error) = alice_tx.try_send(PeerTestCommand::RelayCharlieResponse {
            message,
            nonce,
            rejection,
            router_id: charlie_router_id.clone(),
            router_info,
        }) {
            tracing::debug!(
                target: LOG_TARGET,
                %alice_router_id,
                %charlie_router_id,
                ?nonce,
                "failed to relay peer test response from charlie to alice"
            );
        }
    }

    /// Handle out-of-session peer test message.
    ///
    /// These are messages 5, 6, and 7 which are sent out-of-session between Alice and Charlie.
    ///
    /// If the recipient is Charlie, ensure there exists an active test for the test nonce which
    /// is used to derive `src_id`. If so, decrypt the packet and ensure it has a peer test block
    /// with message 6 in it and if so, send message 7 as a response which includes an address block
    /// for Alice's observed address.
    ///
    /// TODO: alice flow
    pub fn handle_peer_test(
        &mut self,
        src_id: u64,
        pkt_num: u32,
        datagram: Vec<u8>,
        address: SocketAddr,
    ) -> Result<(), Ssu2Error> {
        tracing::trace!(
            target: LOG_TARGET,
            ?src_id,
            ?pkt_num,
            "handle out-of-session peer test message",
        );

        if datagram.len() <= 32 {
            return Err(Ssu2Error::NotEnoughBytes);
        }

        match self.active_tests.get(&src_id) {
            Some(ActiveRemoteTest {
                alice_intro_key,
                dst_id,
                src_id,
                message,
                address: requested_address,
            }) => {
                // decrypt peer test message with our intro key
                let ad = datagram[..32].to_vec();
                let mut datagram = datagram[32..].to_vec();

                ChaChaPoly::with_nonce(&self.intro_key, pkt_num as u64)
                    .decrypt_with_ad(&ad, &mut datagram)?;

                let Some(Block::PeerTest {
                    message: PeerTestMessage::Message6 { .. },
                }) = Block::parse(&datagram)
                    .map_err(|_| Ssu2Error::Malformed)?
                    .iter()
                    .find(|block| core::matches!(block, Block::PeerTest { .. }))
                else {
                    return Err(Ssu2Error::PeerTest(PeerTestError::UnexpectedMessage(6)));
                };

                // create peer test message 7 which is the final message in the peer test sequence
                let pkt = PeerTestBuilder::new(7, message)
                    .with_src_id(*src_id)
                    .with_dst_id(*dst_id)
                    .with_intro_key(*alice_intro_key)
                    .with_addres(address)
                    .build::<R>();

                tracing::error!(target: LOG_TARGET, "send response (msg 7)!");

                self.write_buffer.push_back((pkt, *requested_address));
            }
            None => match self.active_outbound.take() {
                None =>
                    return Err(Ssu2Error::PeerTest(
                        PeerTestError::NonExistentPeerTestSession(src_id),
                    )),
                Some(test) => match test {
                    ActiveTest::Pending {
                        bob_router_id,
                        nonce,
                        src_id: expected_src_id,
                        started,
                        message,
                        ..
                    } => {
                        if src_id != expected_src_id {
                            panic!("uneexpcted src id pending");
                            return Err(Ssu2Error::PeerTest(
                                PeerTestError::NonExistentPeerTestSession(src_id),
                            ));
                        }

                        let ad = datagram[..32].to_vec();
                        let mut datagram = datagram[32..].to_vec();

                        ChaChaPoly::with_nonce(&self.intro_key, pkt_num as u64)
                            .decrypt_with_ad(&ad, &mut datagram)
                            .unwrap();

                        let Some(Block::PeerTest {
                            message: PeerTestMessage::Message5 { .. },
                        }) = Block::parse(&datagram)
                            .map_err(|_| Ssu2Error::Malformed)?
                            .iter()
                            .find(|block| core::matches!(block, Block::PeerTest { .. }))
                        else {
                            return Err(Ssu2Error::PeerTest(PeerTestError::UnexpectedMessage(5)));
                        };

                        tracing::trace!(
                            target: LOG_TARGET,
                            ?nonce,
                            %bob_router_id,
                            "received peer test message for a pending test",
                        );

                        // TODO: send peer test message 6

                        self.active_outbound = Some(ActiveTest::Pending {
                            bob_router_id,
                            nonce,
                            message,
                            src_id,
                            started,
                            message_5_received: true,
                            charlie_address: Some(address),
                        });
                    }
                    ActiveTest::Active {
                        bob_router_id,
                        charlie_router_id,
                        nonce,
                        src_id: expected_src_id,
                        started,
                        ..
                    } => {
                        if src_id != expected_src_id {
                            panic!("uneexpcted src id active");
                            return Err(Ssu2Error::PeerTest(
                                PeerTestError::NonExistentPeerTestSession(src_id),
                            ));
                        }

                        let ad = datagram[..32].to_vec();
                        let mut datagram = datagram[32..].to_vec();

                        ChaChaPoly::with_nonce(&self.intro_key, pkt_num as u64)
                            .decrypt_with_ad(&ad, &mut datagram)
                            .unwrap();

                        let Some(Block::PeerTest {
                            message: PeerTestMessage::Message7 { .. },
                        }) = Block::parse(&datagram)
                            .map_err(|_| Ssu2Error::Malformed)?
                            .iter()
                            .find(|block| core::matches!(block, Block::PeerTest { .. }))
                        else {
                            return Err(Ssu2Error::PeerTest(PeerTestError::UnexpectedMessage(7)));
                        };

                        tracing::info!(
                            target: LOG_TARGET,
                            ?nonce,
                            %charlie_router_id,
                            "PEER TEST SUCCESSFULLY EXECUTED",
                        );
                    }
                },
            },
        }

        Ok(())
    }

    /// Maintain the state of `PeerTestManager`.
    fn maintain(&mut self) {
        if !self.enabled {
            return;
        }

        // skip peer test since we don't know what our external address is
        if self.external_address.is_none() {
            return;
        }

        match &self.active_outbound {
            None => {}
            Some(test) if test.is_active() => return,
            Some(ActiveTest::Pending {
                nonce,
                started,
                bob_router_id,
                ..
            }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?nonce,
                    %bob_router_id,
                    elapsed = ?started.elapsed(),
                    "pending peer test has expired, starting a new test",
                );
            }
            Some(ActiveTest::Active {
                bob_router_id,
                charlie_router_id,
                nonce,
                started,
                ..
            }) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?nonce,
                    %bob_router_id,
                    %charlie_router_id,
                    elapsed = ?started.elapsed(),
                    "active peer test has expired, starting a new test",
                )
            }
        }

        // attempt to find peer test candidate and bail early if none is found
        let Some((bob_router_id, PeerTestCandiate { tx, .. })) =
            self.select_router(true, &HashSet::new())
        else {
            tracing::debug!(
                target: LOG_TARGET,
                num_active = ?self.active.len(),
                "cannot perform peer test, no available candidates",
            );
            return;
        };

        let (message, nonce) = {
            let mut out = BytesMut::with_capacity(128);
            let nonce = R::rng().next_u32();

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(R::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(self.bind_port);

            // address must exist since it was checked at the beginning of the function
            match self.external_address.expect("to exist").ip() {
                IpAddr::V4(address) => out.put_slice(&address.octets()),
                IpAddr::V6(address) => out.put_slice(&address.octets()),
            }

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id.to_vec());
            payload.put_slice(&message);

            self.router_ctx.signing_key().sign(&payload)
        };
        let src_id = (!(((nonce as u64) << 32) | (nonce as u64))).to_be();
        let combined = {
            let mut combined = message.clone();
            combined.extend(&signature);
            combined
        };

        tracing::debug!(
            target: LOG_TARGET,
            %bob_router_id,
            ?nonce,
            ?src_id,
            "send peer test request to bob",
        );

        match tx.try_send(PeerTestCommand::RequestBob {
            nonce,
            message,
            signature,
        }) {
            Ok(()) => {
                self.active_outbound = Some(ActiveTest::Pending {
                    bob_router_id: bob_router_id.clone(),
                    charlie_address: None,
                    message_5_received: false,
                    message: combined,
                    nonce,
                    src_id,
                    started: R::now(),
                });
            }
            Err(error) => tracing::warn!(
                target: LOG_TARGET,
                %bob_router_id,
                ?nonce,
                ?error,
                "failed to send peer test request to bob",
            ),
        }
    }

    /// Handle peer test response from either Bob or Charlie.
    ///
    /// If `rejection` is `None`, the request was accepted.
    ///
    /// If `router_hash` is `[0; 32]`, the request was rejected by Bob, otherwise it contains
    /// Charlie's hash.
    fn handle_peer_test_response(
        &mut self,
        received_nonce: u32,
        rejection: Option<RejectionReason>,
        router_hash: Vec<u8>,
        charlie_router_info: Option<Box<RouterInfo>>,
    ) {
        let Some(active_test) = self.active_outbound.take() else {
            tracing::warn!(
                target: LOG_TARGET,
                nonce = ?received_nonce,
                ?rejection,
                ?router_hash,
                "received peer test response for a non-existent test",
            );
            return;
        };

        if let Some(rejection) = rejection {
            match &active_test {
                ActiveTest::Pending {
                    bob_router_id,
                    nonce: test_nonce,
                    started,
                    ..
                } => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        ?test_nonce,
                        nonce = ?received_nonce,
                        ?rejection,
                        bob_rejected = (&router_hash == &[0u8; 32]),
                        %bob_router_id,
                        time_taken = ?started.elapsed(),
                        "peer test was rejected, trying again later",
                    );
                }
                ActiveTest::Active {
                    nonce: active_nonce,
                    ..
                } => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?active_nonce,
                        nonce = ?received_nonce,
                        "peer test rejection received for an active test, ignoring",
                    );
                }
            }

            return;
        }

        // TODO: charlie intro key
        let charlie_router_info = match charlie_router_info {
            Some(router_info) => *router_info,
            None => match self.router_ctx.profile_storage().get(&RouterId::from(&router_hash)) {
                Some(router_info) => router_info,
                None => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        nonce = ?received_nonce,
                        "unable to perform peer test, charlie router info not available",
                    );
                    return;
                }
            },
        };

        let charlie_address = match charlie_router_info.addresses.get(&TransportKind::Ssu2) {
            Some(address) => match address.socket_address {
                Some(address) => address,
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "charlie doesn't have a published ssu2 address",
                    );
                    debug_assert!(false);
                    return;
                }
            },
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "charlie doesn't support ssu2",
                );
                debug_assert!(false);
                return;
            }
        };

        let Some(charlie_intro_key) = charlie_router_info.ssu2_intro_key() else {
            tracing::warn!(
                target: LOG_TARGET,
                nonce = ?received_nonce,
                charlie_router_id = %RouterId::from(router_hash),
                "no intro key for in charlie's router info, rejecting",
            );
            debug_assert!(false);
            return;
        };

        match active_test {
            ActiveTest::Pending {
                bob_router_id,
                nonce: test_nonce,
                started,
                src_id,
                message_5_received,
                message,
                ..
            } =>
                if test_nonce != received_nonce {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?test_nonce,
                        nonce = ?received_nonce,
                        %bob_router_id,
                        time_taken = ?started.elapsed(),
                        "nonce mismatch for peer test response, ignoring",
                    );
                } else {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?test_nonce,
                        nonce = ?received_nonce,
                        %bob_router_id,
                        time_taken = ?started.elapsed(),
                        "peer test request accepted",
                    );

                    let pkt = PeerTestBuilder::new(6, &message)
                        .with_dst_id(src_id)
                        .with_src_id(!src_id)
                        .with_intro_key(charlie_intro_key)
                        .with_addres(charlie_address)
                        .build::<R>();

                    if message_5_received {
                        // TODO: send message 6 to charlie
                        tracing::warn!(
                            target: LOG_TARGET,
                            "MESSAGE 5 HAS ALREADY BEEN RECEIVED, NOT FIREWALLED",
                        );

                        self.write_buffer.push_back((pkt, charlie_address));
                    } else {
                        panic!("start timer");
                        // TODO: start timer
                    }

                    self.active_outbound = Some(ActiveTest::Active {
                        bob_router_id,
                        charlie_router_id: RouterId::from(router_hash),
                        nonce: test_nonce,
                        message,
                        src_id,
                        started,
                    });
                },
            ActiveTest::Active {
                nonce: active_nonce,
                ..
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?active_nonce,
                    nonce = ?received_nonce,
                    "peer test already in progress, ignoring peer test response",
                );
            }
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
                Poll::Ready(Some(PeerTestEvent::AliceRequest {
                    address,
                    message,
                    nonce,
                    router_id,
                    tx,
                })) => self.handle_alice_request(router_id, nonce, message, address, tx),
                Poll::Ready(Some(PeerTestEvent::BobRequest {
                    address,
                    message,
                    nonce,
                    router_id,
                    router_info,
                    tx,
                })) =>
                    if let Some(command) =
                        self.handle_bob_request(router_id, nonce, address, message, router_info)
                    {
                        if let Err(error) = tx.try_send(command) {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?nonce,
                                ?error,
                                "failed to send command to bob",
                            );
                        }
                    },
                Poll::Ready(Some(PeerTestEvent::CharlieResponse {
                    nonce,
                    rejection,
                    message,
                })) => self.handle_charlie_response(nonce, rejection, message),
                Poll::Ready(Some(PeerTestEvent::PeerTestResponse {
                    nonce,
                    rejection,
                    router_hash,
                    router_info,
                })) => self.handle_peer_test_response(nonce, rejection, router_hash, router_info),
                Poll::Ready(Some(PeerTestEvent::Dummy)) => unreachable!(),
            }
        }

        if self.maintenance_timer.poll_unpin(cx).is_ready() {
            // create new timer and register it into the executor
            {
                self.maintenance_timer = R::timer(MAINTENANCE_INTERVAL);
                let _ = self.maintenance_timer.poll_unpin(cx);
            }

            self.maintain();
        }

        while let Some((pkt, address)) = self.write_buffer.pop_front() {
            match Pin::new(&mut self.socket).poll_send_to(cx, &pkt, address) {
                Poll::Pending => {
                    self.write_buffer.push_front((pkt, address));
                    break;
                }
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(_)) => {}
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        crypto::{base64_encode, chachapoly::ChaChaPoly},
        primitives::{
            Capabilities, Date, Mapping, RouterAddress, RouterIdentity, RouterInfo,
            RouterInfoBuilder, Str,
        },
        router::context::builder::RouterContextBuilder,
        runtime::mock::MockRuntime,
        timeout,
        transport::ssu2::message::{
            handshake::TokenRequestBuilder, Block, HeaderKind, HeaderReader,
        },
        Ssu2Config,
    };
    use bytes::{BufMut, Bytes};
    use futures::FutureExt;
    use rand::RngCore;
    use thingbuf::mpsc::channel;

    fn make_router_info(caps: Str, ipv4: Option<bool>) -> (RouterId, RouterInfo, Bytes) {
        let ssu2 = RouterAddress {
            cost: 8,
            expires: Date::new(0),
            transport: TransportKind::Ssu2,
            options: Mapping::from_iter([
                (Str::from("caps"), caps),
                (Str::from("i"), Str::from(base64_encode([0xbb; 32]))),
            ]),
            socket_address: ipv4.map(|ipv4| {
                if ipv4 {
                    "127.0.0.1:8888".parse().unwrap()
                } else {
                    "[::]:8888".parse().unwrap()
                }
            }),
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
    async fn session_doesnt_exist_in_profile_storage() {
        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().build(),
        );
        let (tx, _rx) = channel(16);
        let router_id = RouterId::random();
        manager.add_session(&router_id, tx);
        assert!(!manager.active.contains_key(&router_id));
    }

    #[tokio::test]
    #[should_panic]
    async fn session_doesnt_support_ssu2() {
        let (router_info, _, _) = RouterInfoBuilder::default().build();
        let router_id = router_info.identity.id();
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, tx);
    }

    #[tokio::test]
    async fn router_doesnt_support_peer_testing() {
        let (router_id, router_info, _) = make_router_info(Str::from("C"), Some(true));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, tx);

        assert!(!manager.active.contains_key(&router_id));
    }

    #[tokio::test]
    async fn router_doesnt_support_ipv4_or_ipv6() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC"), None);
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, tx);

        assert!(!manager.active.contains_key(&router_id));
    }

    #[tokio::test]
    async fn router_supports_peer_testing_over_ipv4() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC"), Some(true));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, tx);

        let PeerTestCandiate {
            supports_ipv4,
            supports_ipv6,
            ..
        } = manager.active.get(&router_id).unwrap();
        assert!(supports_ipv4);
        assert!(!supports_ipv6);
    }

    #[tokio::test]
    async fn router_supports_peer_testing_over_ipv6() {
        let (router_id, router_info, _) = make_router_info(Str::from("BC"), Some(false));
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, _rx) = channel(16);
        manager.add_session(&router_id, tx);

        let PeerTestCandiate {
            supports_ipv4,
            supports_ipv6,
            ..
        } = manager.active.get(&router_id).unwrap();
        assert!(!supports_ipv4);
        assert!(supports_ipv6);
    }

    #[tokio::test]
    #[should_panic]
    async fn inbound_request_alice_doesnt_exist() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id, router_info, _) = make_router_info(Str::from("BC"), Some(true));
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, rx) = channel(16);
        manager.add_session(&router_id, tx);

        let (alice_tx, _alice_rx) = channel(16);
        manager.handle_alice_request(
            RouterId::random(),
            1338,
            b"message".to_vec(),
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
        let (router_id, router_info, _) = make_router_info(Str::from("BC"), Some(true));
        storage.add_router(router_info);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, rx) = channel(16);
        manager.add_session(&router_id, tx.clone());

        manager.handle_alice_request(
            router_id.clone(),
            1338,
            b"message".to_vec(),
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
        assert!(manager.pending_tests.is_empty());
    }

    #[tokio::test]
    async fn inbound_request_rejected_no_ipv4_routers() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id1, router_info1, _) = make_router_info(Str::from("BC"), Some(true));
        let (router_id2, router_info2, _) = make_router_info(Str::from("BC"), Some(false));
        storage.add_router(router_info1);
        storage.add_router(router_info2);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, rx) = channel(16);
        manager.add_session(&router_id1, tx.clone());

        manager.handle_alice_request(
            router_id1.clone(),
            1338,
            b"message".to_vec(),
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
        assert!(manager.pending_tests.is_empty());
    }

    #[tokio::test]
    async fn inbound_request_rejected_no_ipv6_routers() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id1, router_info1, _) = make_router_info(Str::from("BC"), Some(false));
        let (router_id2, router_info2, _) = make_router_info(Str::from("BC"), Some(true));
        storage.add_router(router_info1);
        storage.add_router(router_info2);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (tx, rx) = channel(16);
        manager.add_session(&router_id1, tx.clone());

        manager.handle_alice_request(
            router_id1.clone(),
            1338,
            b"message".to_vec(),
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
        assert!(manager.pending_tests.is_empty());
    }

    #[tokio::test]
    async fn inbound_request_accepted() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (router_id1, router_info1, serialized1) = make_router_info(Str::from("BC"), Some(true));
        let (router_id2, router_info2, serialized2) = make_router_info(Str::from("BC"), Some(true));
        storage.discover_router(router_info1, serialized1);
        storage.discover_router(router_info2, serialized2);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let (charlie_tx, charlie_rx) = channel(16);
        manager.add_session(&router_id2, charlie_tx.clone());

        let (alice_tx, alice_rx) = channel(16);
        manager.handle_alice_request(
            router_id1.clone(),
            1338,
            b"message".to_vec(),
            "127.0.0.1:8888".parse().unwrap(),
            alice_tx.clone(),
        );

        match charlie_rx.try_recv().unwrap() {
            PeerTestCommand::RequestCharlie {
                address,
                nonce,
                message,
                router_id,
                router_info,
            } => {
                assert_eq!(address, "127.0.0.1:8888".parse().unwrap());
                assert_eq!(message, b"message".to_vec());
                assert_eq!(nonce, 1338);
                assert_eq!(router_id, router_id1);
                assert_eq!(
                    RouterInfo::parse(router_info).unwrap().identity.id(),
                    router_id1
                );
            }
            _ => panic!("invalid command"),
        }
        assert!(alice_rx.try_recv().is_err());

        let PendingRemoteTest {
            address,
            alice_router_id,
            charlie_router_id,
            ..
        } = manager.pending_tests.remove(&1338).unwrap();

        assert_eq!(address, "127.0.0.1:8888".parse().unwrap());
        assert_eq!(alice_router_id, router_id1);
        assert_eq!(charlie_router_id, router_id2);
    }

    #[tokio::test]
    async fn bob_request_rejected_already_connected() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (alice_router_id, alice_router_info, alice_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        let (bob_router_id, bob_router_info, bob_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        storage.discover_router(alice_router_info, alice_serialized);
        storage.discover_router(bob_router_info, bob_serialized);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let manager_tx = manager.tx.clone();
        let (alice_tx, alice_rx) = channel(16);
        let (bob_tx, bob_rx) = channel(16);

        manager.add_session(&alice_router_id, alice_tx.clone());
        manager.add_session(&bob_router_id, bob_tx.clone());

        manager_tx
            .try_send(PeerTestEvent::BobRequest {
                address: "127.0.0.1:8888".parse().unwrap(),
                nonce: 1337,
                message: b"message".to_vec(),
                router_id: alice_router_id,
                router_info: None,
                tx: bob_tx,
            })
            .unwrap();
        futures::future::poll_fn(|cx| {
            let _ = manager.poll_unpin(cx);
            Poll::Ready(())
        })
        .await;

        match bob_rx.try_recv().unwrap() {
            PeerTestCommand::SendCharlieResponse {
                nonce: 1337,
                rejection: Some(RejectionReason::AlreadyConnected),
                router_id: alice_router_id,
            } => {}
            command => panic!("unexpected command: {command:?}"),
        }
    }

    #[tokio::test]
    async fn bob_request_rejected_address_not_supported() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (alice_router_id, alice_router_info, alice_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        let (bob_router_id, bob_router_info, bob_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        storage.discover_router(alice_router_info, alice_serialized);
        storage.discover_router(bob_router_info, bob_serialized);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let manager_tx = manager.tx.clone();
        let (bob_tx, bob_rx) = channel(16);

        manager.add_session(&bob_router_id, bob_tx.clone());

        manager_tx
            .try_send(PeerTestEvent::BobRequest {
                address: "[::]:8888".parse().unwrap(),
                nonce: 1337,
                router_info: None,
                message: b"message".to_vec(),
                router_id: alice_router_id,
                tx: bob_tx,
            })
            .unwrap();
        futures::future::poll_fn(|cx| {
            let _ = manager.poll_unpin(cx);
            Poll::Ready(())
        })
        .await;

        match bob_rx.try_recv().unwrap() {
            PeerTestCommand::SendCharlieResponse {
                nonce: 1337,
                rejection: Some(RejectionReason::UnsupportedAddress),
                router_id: alice_router_id,
            } => {}
            command => panic!("unexpected command: {command:?}"),
        }
    }

    #[tokio::test]
    async fn bob_request_accepted() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (alice_router_id, alice_router_info, alice_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        let (bob_router_id, bob_router_info, bob_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        storage.discover_router(alice_router_info, alice_serialized);
        storage.discover_router(bob_router_info, bob_serialized);

        // create udp socket for alice
        let mut recv_socket =
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        let address = recv_socket.local_address().unwrap();

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let manager_tx = manager.tx.clone();
        let (bob_tx, bob_rx) = channel(16);

        manager.add_session(&bob_router_id, bob_tx.clone());
        tokio::spawn(manager);

        let message = {
            let mut out = BytesMut::with_capacity(128);
            out.put_u8(2); // version
            out.put_u32(1337);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6); // ipv4
            out.put_u16(address.port());
            out.put_slice(&[127, 0, 0, 1]);

            out.to_vec()
        };

        manager_tx
            .try_send(PeerTestEvent::BobRequest {
                address,
                nonce: 1337,
                router_info: None,
                message,
                router_id: alice_router_id,
                tx: bob_tx,
            })
            .unwrap();

        match timeout!(bob_rx.recv()).await.unwrap().unwrap() {
            PeerTestCommand::SendCharlieResponse {
                nonce: 1337,
                rejection: None,
                router_id: alice_router_id,
            } => {}
            command => panic!("unexpected command: {command:?}"),
        }

        let mut buf = vec![0u8; 1500];
        let (nread, _from) = recv_socket.recv_from(&mut buf).await.unwrap();
        let mut pkt = buf[..nread].to_vec();
        let mut reader = HeaderReader::new([0xbb; 32], &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let (pkt_num, src_id) = match reader.parse([0xbb; 32]).unwrap() {
            HeaderKind::PeerTest {
                pkt_num, src_id, ..
            } => (pkt_num, src_id),
            _ => panic!("invalid header kind"),
        };
        assert_eq!(src_id, (!(((1337u64) << 32) | (1337u64))).to_be());

        let ad = pkt[..32].to_vec();
        let mut pkt = pkt[32..].to_vec();

        ChaChaPoly::with_nonce(&[0xbb; 32], pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        assert!(Block::parse(&pkt).unwrap().iter().any(|block| match block {
            Block::PeerTest {
                message: PeerTestMessage::Message5 { nonce: 1337 },
            } => true,
            _ => false,
        }));
    }

    #[tokio::test]
    async fn alice_request_charlie_no_longer_connected() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (charlie_router_id, charlie_router_info, charlie_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        let (alice_router_id, alice_router_info, alice_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        storage.discover_router(alice_router_info, alice_serialized);
        storage.discover_router(charlie_router_info, charlie_serialized);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let manager_tx = manager.tx.clone();
        let (alice_tx, alice_rx) = channel(16);
        let (charlie_tx, charlie_rx) = channel(16);

        manager.add_session(&charlie_router_id, charlie_tx.clone());
        tokio::spawn(manager);

        // drop charlie tx, simulating the connection closed
        //
        // `PeerTestManager` hasn't been notified of it yet
        drop(charlie_rx);

        let message = {
            let mut out = BytesMut::with_capacity(128);
            out.put_u8(2); // version
            out.put_u32(1337);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6); // ipv4
            out.put_u16(8888);
            out.put_slice(&[127, 0, 0, 1]);

            out.to_vec()
        };

        manager_tx
            .try_send(PeerTestEvent::AliceRequest {
                address: "127.0.0.1:8888".parse().unwrap(),
                message: message.clone(),
                nonce: 1337,
                router_id: alice_router_id.clone(),
                tx: alice_tx.clone(),
            })
            .unwrap();

        // verify charlie receives the peer test request
        match timeout!(alice_rx.recv()).await.unwrap().unwrap() {
            PeerTestCommand::Reject {
                nonce,
                reason: RejectionReason::Unspecified,
            } => {}
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn charlie_response_relayed() {
        let storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (charlie_router_id, charlie_router_info, charlie_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        let (alice_router_id, alice_router_info, alice_serialized) =
            make_router_info(Str::from("BC"), Some(true));
        storage.discover_router(alice_router_info, alice_serialized);
        storage.discover_router(charlie_router_info, charlie_serialized);

        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().with_profile_storage(storage).build(),
        );
        let manager_tx = manager.tx.clone();
        let (alice_tx, alice_rx) = channel(16);
        let (charlie_tx, charlie_rx) = channel(16);

        manager.add_session(&charlie_router_id, charlie_tx.clone());
        tokio::spawn(manager);

        let message = {
            let mut out = BytesMut::with_capacity(128);
            out.put_u8(2); // version
            out.put_u32(1337);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6); // ipv4
            out.put_u16(8888);
            out.put_slice(&[127, 0, 0, 1]);

            out.to_vec()
        };

        manager_tx
            .try_send(PeerTestEvent::AliceRequest {
                address: "127.0.0.1:8888".parse().unwrap(),
                message: message.clone(),
                nonce: 1337,
                router_id: alice_router_id.clone(),
                tx: alice_tx.clone(),
            })
            .unwrap();

        // verify charlie receives the peer test request
        match timeout!(charlie_rx.recv()).await.unwrap().unwrap() {
            PeerTestCommand::RequestCharlie { .. } => {}
            _ => panic!("invalid event"),
        }

        // send response from charlie to bob so it can be relayed to alice
        manager_tx
            .try_send(PeerTestEvent::CharlieResponse {
                nonce: 1337,
                rejection: None,
                message,
            })
            .unwrap();

        // verify alice receives the response from charlie
        match timeout!(alice_rx.recv()).await.unwrap().unwrap() {
            PeerTestCommand::RelayCharlieResponse {
                nonce: 1337,
                rejection: None,
                ..
            } => {}
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn out_of_session_too_short_packet() {
        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().build(),
        );

        match manager.handle_peer_test(
            1337,
            1338,
            vec![1, 2, 3, 4],
            "127.0.0.1:8888".parse().unwrap(),
        ) {
            Err(Ssu2Error::NotEnoughBytes) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn out_of_session_no_active_test() {
        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().build(),
        );

        match manager.handle_peer_test(1337, 1338, vec![0u8; 40], "127.0.0.1:8888".parse().unwrap())
        {
            Err(Ssu2Error::PeerTest(PeerTestError::NonExistentPeerTestSession(1337))) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn out_of_session_peer_test_block_missing() {
        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().build(),
        );
        let mut socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = socket.local_address().unwrap();
        let src_id = (!(((1337u64) << 32) | (1337u64))).to_be();
        let dst_id = (((1337u64) << 32) | (1337u64)).to_be();

        manager.active_tests.insert(
            dst_id,
            ActiveRemoteTest {
                address: address,
                alice_intro_key: [0xbb; 32],
                dst_id,
                message: b"hello, world".to_vec(),
                src_id,
            },
        );

        let mut pkt = TokenRequestBuilder::default()
            .with_src_id(src_id)
            .with_dst_id(dst_id)
            .with_intro_key([0xaa; 32])
            .build::<MockRuntime>()
            .to_vec();

        let mut reader = HeaderReader::new([0xaa; 32], &mut pkt).unwrap();
        let _id = reader.dst_id();
        let pkt_num = match reader.parse([0xaa; 32]).unwrap() {
            HeaderKind::TokenRequest { pkt_num, .. } => pkt_num,
            _ => panic!("here"),
        };

        match manager.handle_peer_test(dst_id, pkt_num, pkt, address) {
            Err(Ssu2Error::PeerTest(PeerTestError::UnexpectedMessage(6))) => {}
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn out_of_session_invalid_peer_test_block() {
        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().build(),
        );
        let mut socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = socket.local_address().unwrap();
        let src_id = (!(((1337u64) << 32) | (1337u64))).to_be();
        let dst_id = (((1337u64) << 32) | (1337u64)).to_be();

        manager.active_tests.insert(
            dst_id,
            ActiveRemoteTest {
                address: address,
                alice_intro_key: [0xbb; 32],
                dst_id,
                message: b"hello, world".to_vec(),
                src_id,
            },
        );

        let message = {
            let mut out = BytesMut::with_capacity(128);
            out.put_u8(2); // version
            out.put_u32(1337);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6); // ipv4
            out.put_u16(address.port());
            out.put_slice(&[127, 0, 0, 1]);

            out.to_vec()
        };

        // invalid message, manager expects message 5
        let mut pkt = PeerTestBuilder::new(5, &message)
            .with_src_id(src_id)
            .with_dst_id(dst_id)
            .with_intro_key([0xaa; 32])
            .build::<MockRuntime>()
            .to_vec();

        let mut reader = HeaderReader::new([0xaa; 32], &mut pkt).unwrap();
        let _id = reader.dst_id();
        let pkt_num = match reader.parse([0xaa; 32]).unwrap() {
            HeaderKind::PeerTest { pkt_num, .. } => pkt_num,
            _ => panic!("here"),
        };

        match manager.handle_peer_test(dst_id, pkt_num, pkt, address) {
            Err(Ssu2Error::PeerTest(PeerTestError::UnexpectedMessage(6))) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn out_of_session_response() {
        let mut manager = PeerTestManager::new(
            [0xaa; 32],
            <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            RouterContextBuilder::default().build(),
        );
        let mut socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = socket.local_address().unwrap();
        let src_id = (!(((1337u64) << 32) | (1337u64))).to_be();
        let dst_id = (((1337u64) << 32) | (1337u64)).to_be();

        let message = {
            let mut out = BytesMut::with_capacity(128);
            out.put_u8(2); // version
            out.put_u32(1337);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6); // ipv4
            out.put_u16(address.port());
            out.put_slice(&[127, 0, 0, 1]);

            out.to_vec()
        };

        manager.active_tests.insert(
            dst_id,
            ActiveRemoteTest {
                address: address,
                alice_intro_key: [0xbb; 32],
                dst_id,
                message: message.clone(),
                src_id,
            },
        );

        // invalid message, manager expects message 5
        let mut pkt = PeerTestBuilder::new(6, &message)
            .with_src_id(src_id)
            .with_dst_id(dst_id)
            .with_intro_key([0xaa; 32])
            .build::<MockRuntime>()
            .to_vec();

        let mut reader = HeaderReader::new([0xaa; 32], &mut pkt).unwrap();
        let _id = reader.dst_id();
        let pkt_num = match reader.parse([0xaa; 32]).unwrap() {
            HeaderKind::PeerTest { pkt_num, .. } => pkt_num,
            _ => panic!("here"),
        };

        match manager.handle_peer_test(dst_id, pkt_num, pkt, address) {
            Ok(()) => {}
            error => panic!("invalid error: {error:?}"),
        }

        // spawn manager in the background so the datagram is sent
        tokio::spawn(manager);

        let mut buf = vec![0u8; 1500];
        let (nread, _from) = timeout!(socket.recv_from(&mut buf)).await.unwrap().unwrap();
        let mut pkt = buf[..nread].to_vec();

        let mut reader = HeaderReader::new([0xbb; 32], &mut pkt).unwrap();
        let _id = reader.dst_id();
        let pkt_num = match reader.parse([0xbb; 32]).unwrap() {
            HeaderKind::PeerTest { pkt_num, .. } => pkt_num,
            _ => panic!("here"),
        };
        let ad = pkt[..32].to_vec();
        let mut pkt = pkt[32..].to_vec();

        ChaChaPoly::with_nonce(&[0xbb; 32], pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        assert!(Block::parse(&pkt).unwrap().iter().any(|block| match block {
            Block::PeerTest {
                message: PeerTestMessage::Message7 { nonce: 1337 },
            } => true,
            _ => false,
        }));
    }
}
