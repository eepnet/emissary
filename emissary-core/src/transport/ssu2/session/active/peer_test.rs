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

//! Peer test protocol for an active SSU2 session.

use crate::{
    crypto::SigningPublicKey,
    error::PeerTestError,
    primitives::RouterId,
    runtime::{Counter, MetricsHandle, Runtime},
    transport::ssu2::{
        message::{data::PeerTestBlock, PeerTestMessage},
        metrics::DUPLICATE_PKT_COUNT,
        peer_test::types::{PeerTestCommand, RejectionReason},
        session::active::Ssu2Session,
    },
};

use alloc::vec::Vec;
use core::net::SocketAddr;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::active::peer-test";

impl<R: Runtime> Ssu2Session<R> {
    /// Check if peer test request is valid by ensuring `address` matches `self.address` and
    /// that signature verification for `message` passes.
    fn validate_peer_test_request(
        &self,
        nonce: u32,
        address: SocketAddr,
        router_id: &RouterId,
        message: &[u8],
        signature: &[u8],
        verifying_key: &SigningPublicKey,
    ) -> Result<(), PeerTestError> {
        // verify signature
        {
            let mut signed_data = Vec::<u8>::new();
            signed_data.extend(b"PeerTestValidate");
            signed_data.extend(router_id.to_vec());
            signed_data.extend(message);

            if verifying_key.verify(&signed_data, signature).is_err() {
                return Err(PeerTestError::InvalidSignature);
            }
        }

        // validate address
        {
            if address.ip() != self.address.ip() {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    specified_address = ?address,
                    current_address = ?self.address,
                    "ip address mismatch for peer test request, rejecting"
                );
                return Err(PeerTestError::InvalidAddress);
            }

            if address.port() <= 1023 {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    port = ?address.port(),
                    "invalid port for peer test request, rejecting",
                );
                return Err(PeerTestError::InvalidAddress);
            }
        }

        Ok(())
    }

    /// Handle peer test message.
    pub fn handle_peer_test_message(&mut self, message: PeerTestMessage) {
        // ignore duplicate messages
        //
        // duplicate messages may be received due to retransmissions
        match message.nonce() {
            Some(nonce) =>
                if !self.duplicate_filter.insert(nonce) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?nonce,
                        "ignoring duplicate message",
                    );
                    self.router_ctx.metrics_handle().counter(DUPLICATE_PKT_COUNT).increment(1);
                    return;
                },
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?message,
                    "received an unexpected peer test message to an active session",
                );
                debug_assert!(false);
                return;
            }
        }

        match message {
            // handle peer test message 1, i.e., peer test request from alice to bob (we're bob and
            // this is an active session with alice)
            //
            // current active session is with alice and if the request is accepted by bob, it must
            // be relayed to `PeerTestManager` for further processing which either results in a
            // rejection (no available peers) or accept.
            //
            // if the request is accepted, the request is relayed to charlie and once a response is
            // received from charlie, it's relayed back to alice in `PeerTestMssage::Message1`
            PeerTestMessage::Message1 {
                address,
                message,
                nonce,
                signature,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    ?address,
                    "handle peer test request from alice"
                );

                match self.validate_peer_test_request(
                    nonce,
                    address,
                    self.router_ctx.router_id(),
                    &message,
                    &signature,
                    &self.verifying_key,
                ) {
                    Ok(()) => {
                        self.peer_test_handle.handle_alice_request(
                            self.router_id.clone(),
                            nonce,
                            address,
                            message,
                            signature,
                        );
                    }
                    Err(PeerTestError::InvalidSignature) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            router_id = %self.router_id,
                            ?nonce,
                            "failed to verify signature of peer test message 1",
                        );

                        self.transmission.schedule(PeerTestBlock::BobReject {
                            reason: RejectionReason::SignatureFailure,
                            message,
                            signature,
                        });
                    }
                    Err(PeerTestError::InvalidAddress) => {
                        self.transmission.schedule(PeerTestBlock::BobReject {
                            reason: RejectionReason::UnsupportedAddress,
                            message,
                            signature,
                        });
                    }
                    Err(_) => {}
                }
            }
            // handle peer test message 2, i.e., peer test request from alice relayed by bob to
            // charlie (we're charlie and this is an active session with bob)
            //
            // if the request is valid (signature and address), it's relayed to `PeerTestManager`
            // for further verification which resultsin `PeerTestCommand::SendCharlieResponse` that
            // get relayed to bob.
            PeerTestMessage::Message2 {
                router_id,
                nonce,
                address,
                mut message,
                signature,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    alice_router_id = %router_id,
                    bob_router_id = %self.router_id,
                    ?nonce,
                    ?address,
                    "handle peer test request from bob"
                );

                // attempt to get alice's verifying key
                //
                // if the router info set by bob was in a router info block, `Ssu2Session` has kept
                // it in a temporary storage and if the router info was sent in a database store
                // message, attempt to fetch it from profile storage.
                let verifying_key = match self.pending_router_info.as_ref() {
                    Some(router_info) => Some(router_info.identity.signing_key().clone()),
                    None => self
                        .router_ctx
                        .profile_storage()
                        .get(&router_id)
                        .map(|router_info| router_info.identity.signing_key().clone()),
                };

                let Some(verifying_key) = verifying_key else {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        alice_router_id = %router_id,
                        ?nonce,
                        "alice verifying get not available, rejecting",
                    );
                    message.extend(&signature);

                    return self.transmission.schedule(PeerTestBlock::CharlieResponse {
                        message,
                        rejection: Some(RejectionReason::RouterUnknown),
                    });
                };

                match self.validate_peer_test_request(
                    nonce,
                    address,
                    &self.router_id,
                    &message,
                    &signature,
                    &verifying_key,
                ) {
                    Ok(()) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            router_id = %self.router_id,
                            alice_router_id = %router_id,
                            ?nonce,
                            "received peer test message 2",
                        );

                        self.peer_test_handle.handle_bob_request(
                            router_id,
                            nonce,
                            address,
                            message,
                            self.pending_router_info.take(),
                        );
                    }
                    Err(PeerTestError::InvalidSignature) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            router_id = %self.router_id,
                            ?nonce,
                            "failed to verify signature of peer test message 2",
                        );
                        message.extend(&signature);

                        self.transmission.schedule(PeerTestBlock::CharlieResponse {
                            message,
                            rejection: Some(RejectionReason::SignatureFailure),
                        });
                    }
                    Err(PeerTestError::InvalidAddress) => {
                        message.extend(&signature);

                        self.transmission.schedule(PeerTestBlock::CharlieResponse {
                            message,
                            rejection: Some(RejectionReason::UnsupportedAddress),
                        });
                    }
                    Err(_) => {}
                }
            }
            // handle peer test message 3, i.e., response from charlie for alice through bob (we're
            // bob and this is an active connection with charlie)
            //
            // the response is routed to `PeerTestManager` which relays it to alice (if connected)
            PeerTestMessage::Message3 {
                mut message,
                nonce,
                rejection,
                signature,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    ?rejection,
                    "peer test response from charlie, relay to alice"
                );

                message.extend(&signature);

                self.peer_test_handle.handle_charlie_response(nonce, rejection, message);
            }
            PeerTestMessage::Message4 {
                nonce,
                rejection,
                router_hash,
                message,
                signature,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    ?rejection,
                    "relay peer test message 4 to manager",
                );

                self.peer_test_handle.handle_peer_test_response(
                    nonce,
                    rejection,
                    router_hash,
                    self.pending_router_info.take(),
                    message,
                    signature,
                );
            }
            message => {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?message,
                    "received an unexpected peer test message to an active session",
                );
                debug_assert!(false);
            }
        }
    }

    /// Handle peer test command received from `PeerTestManager`.
    pub fn handle_peer_test_command(&mut self, command: PeerTestCommand) {
        match command {
            // send peer test request to bob, asking them to partake in a peer test (we're alice and
            // this is an active session with bob)
            PeerTestCommand::RequestBob {
                nonce,
                message,
                signature,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    "send peer test request to bob",
                );

                self.transmission.schedule(PeerTestBlock::AliceRequest { message, signature });
            }
            // reject peer test request (message 1) received from alice (we're bob and this is an
            // active connection with alice)
            PeerTestCommand::Reject { nonce, reason } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    ?nonce,
                    ?reason,
                    "send peer test rejection for alice",
                );

                let Some((message, signature)) = self.peer_test_handle.take_alice_request(&nonce)
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?nonce,
                        "message for peer test 1 does not exist",
                    );
                    debug_assert!(false);
                    return;
                };

                self.transmission.schedule(PeerTestBlock::BobReject {
                    reason,
                    message,
                    signature,
                });
            }
            // send request to charlie to participate in a peer test process for alice (we're bob
            // and this is an active connection with charlie)
            PeerTestCommand::RequestCharlie {
                message,
                nonce,
                router_id,
                router_info,
                signature,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    alice_router_id = %router_id,
                    ?nonce,
                    "send peer test request to charlie",
                );

                self.transmission.schedule((
                    PeerTestBlock::RequestCharlie {
                        router_id,
                        message,
                        signature,
                    },
                    router_info,
                ));
            }
            PeerTestCommand::SendCharlieResponse {
                nonce,
                rejection,
                router_id,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    alice_router_id = %router_id,
                    ?nonce,
                    ?rejection,
                    "send peer test response to bob",
                );

                let Some(mut message) = self.peer_test_handle.take_message(&nonce) else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        alice_router_id = %router_id,
                        router_id = %self.router_id,
                        ?nonce,
                        "message for peer test 2 does not exist",
                    );
                    debug_assert!(false);
                    return;
                };

                // create signature as charlie
                //
                // https://geti2p.net/spec/ssu2#peertest
                let signature = {
                    let mut data_to_sign = Vec::<u8>::new();
                    data_to_sign.extend(b"PeerTestValidate");
                    data_to_sign.extend(&self.router_id.to_vec());
                    data_to_sign.extend(&router_id.to_vec());
                    data_to_sign.extend(&message);

                    self.router_ctx.signing_key().sign(&data_to_sign)
                };

                // append signature at the end of the message
                message.extend(&signature);

                self.transmission
                    .schedule(PeerTestBlock::CharlieResponse { message, rejection });
            }
            PeerTestCommand::RelayCharlieResponse {
                nonce,
                rejection,
                router_id,
                message,
                router_info,
            } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    charlie_router_id = %router_id,
                    ?nonce,
                    "relay charlie peer test response to alice",
                );

                self.transmission.schedule((
                    PeerTestBlock::RelayCharlieResponse {
                        message,
                        router_id,
                        rejection,
                    },
                    router_info,
                ));
            }
            PeerTestCommand::Dummy => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{chachapoly::ChaChaPoly, SigningPrivateKey},
        events::EventManager,
        primitives::{RouterId, RouterInfo, RouterInfoBuilder},
        profile::ProfileStorage,
        router::context::RouterContext,
        runtime::{
            mock::{MockRuntime, MockUdpSocket},
            UdpSocket,
        },
        subsystem::SubsystemEvent,
        timeout,
        transport::ssu2::{
            message::{
                data::{DataMessageBuilder, MessageKind},
                Block, HeaderKind, HeaderReader,
            },
            peer_test::types::{PeerTestEvent, PeerTestEventRecycle, PeerTestHandle},
            session::{active::Ssu2SessionContext, KeyContext},
            Packet,
        },
    };
    use bytes::{BufMut, Bytes, BytesMut};
    use rand_core::RngCore;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };
    use thingbuf::mpsc::{channel, with_recycle, Receiver, Sender};

    #[allow(unused)]
    struct ActiveSessionContext {
        alice_router_id: RouterId,
        alice_router_info: RouterInfo,
        cmd_tx: Sender<PeerTestCommand>,
        event_rx: Receiver<PeerTestEvent, PeerTestEventRecycle>,
        pkt_tx: Sender<Packet>,
        recv_socket: MockUdpSocket,
        router_id: Vec<u8>,
        session: Ssu2Session<MockRuntime>,
        signing_key: SigningPrivateKey,
        transport_rx: Receiver<SubsystemEvent>,
    }

    // fake address used for testing
    const ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888);

    async fn make_active_session() -> ActiveSessionContext {
        let (from_socket_tx, from_socket_rx) = channel(128);
        let socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let recv_socket = <MockRuntime as Runtime>::UdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let (alice_router_info, _static_key, alice_signing_key) =
            RouterInfoBuilder::default().build();
        let alice_router_id = alice_router_info.identity.id();

        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let router_id = router_info.identity.id();
        let (_event_mgr, _event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let router_ctx = RouterContext::new(
            MockRuntime::register_metrics(vec![], None),
            ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new()),
            router_info.identity.id(),
            Bytes::from(router_info.serialize(&signing_key)),
            static_key.clone(),
            signing_key,
            2u8,
            event_handle.clone(),
        );

        let ctx = Ssu2SessionContext {
            address: recv_socket.local_address().unwrap(),
            dst_id: 1337u64,
            intro_key: [1u8; 32],
            pkt_rx: from_socket_rx,
            recv_key_ctx: KeyContext {
                k_data: [2u8; 32],
                k_header_2: [3u8; 32],
            },
            router_id: alice_router_id.clone(),
            send_key_ctx: KeyContext {
                k_data: [3u8; 32],
                k_header_2: [2u8; 32],
            },
            verifying_key: alice_signing_key.public(),
        };
        let (event_tx, event_rx) = with_recycle(16, PeerTestEventRecycle::default());
        let handle = PeerTestHandle::new(event_tx);
        let cmd_tx = handle.cmd_tx();
        let (transport_tx, transport_rx) = channel(16);

        let session =
            Ssu2Session::<MockRuntime>::new(ctx, socket, transport_tx, router_ctx, handle);

        ActiveSessionContext {
            alice_router_id,
            alice_router_info,
            cmd_tx,
            event_rx,
            pkt_tx: from_socket_tx,
            recv_socket,
            router_id: router_id.to_vec(),
            session,
            signing_key: alice_signing_key,
            transport_rx,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_1_relayed_to_manager_alice_rejected() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            router_id: bob_router_id,
            cmd_tx,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let alice_intro_key = [1; 32];

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(8888);
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::AliceRequest { message, signature },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        match timeout!(event_rx.recv()).await.unwrap().unwrap() {
            PeerTestEvent::AliceRequest {
                address,
                nonce: received_nonce,
                router_id,
                ..
            } => {
                assert_eq!(router_id, alice_router_id);
                assert_eq!(received_nonce, nonce);
                assert_eq!(address, ADDRESS);
            }
            _ => panic!("unexpected event"),
        }

        // send rejection for alice from `PeerTestManager`
        cmd_tx
            .try_send(PeerTestCommand::Reject {
                nonce,
                reason: RejectionReason::NoRouterAvailable,
            })
            .unwrap();

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(alice_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message4 {
                        nonce: received_nonce,
                        rejection,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::NoRouterAvailable));
            }
            _ => panic!("peer test message 3 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_1_invalid_signature() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let alice_intro_key = [1u8; 32];

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            // omit bob's router hash, producing an invalid signature
            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::AliceRequest { message, signature },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        // verify `PeerTestManager` is not notified
        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(alice_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message4 {
                        nonce: received_nonce,
                        rejection,
                        router_hash,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::SignatureFailure));
                assert_eq!(router_hash, &vec![0u8; 32]);
            }
            _ => panic!("peer test message 4 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_1_invalid_address() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            router_id: bob_router_id,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let alice_intro_key = [1u8; 32];

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(8888);

            // address is different from the one that the session has in memory
            out.put_slice(&[8, 8, 8, 8]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::AliceRequest { message, signature },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        // verify `PeerTestManager` is not notified
        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(alice_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message4 {
                        nonce: received_nonce,
                        rejection,
                        router_hash,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::UnsupportedAddress));
                assert_eq!(router_hash, &vec![0u8; 32]);
            }
            _ => panic!("peer test message 4 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_1_invalid_port() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            router_id: bob_router_id,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let alice_intro_key = [1u8; 32];

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);

            // port is below 1024
            out.put_u16(512);
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::AliceRequest { message, signature },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        // verify `PeerTestManager` is not notified
        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(alice_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message4 {
                        nonce: received_nonce,
                        rejection,
                        router_hash,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::UnsupportedAddress));
                assert_eq!(router_hash, &vec![0u8; 32]);
            }
            _ => panic!("peer test message 4 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_2_alice_alice_accepted() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            alice_router_info,
            mut recv_socket,
            cmd_tx,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let bob_intro_key = [1u8; 32];
        let charlie_verifying_key = session.router_ctx.signing_key().public();
        let router_id = alice_router_info.identity.id().to_vec();

        // store alice's router info into storage
        session.router_ctx.profile_storage().add_router(alice_router_info);

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::RequestCharlie {
                        router_id: alice_router_id.clone(),
                        message,
                        signature,
                    },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        let (nonce, alice_router_id) = match timeout!(event_rx.recv()).await.unwrap().unwrap() {
            PeerTestEvent::BobRequest {
                nonce: alice_nonce,
                router_id,
                ..
            } => {
                assert_eq!(alice_nonce, nonce);
                assert_eq!(router_id, alice_router_id);

                (alice_nonce, router_id)
            }
            _ => panic!("invalid event"),
        };

        cmd_tx
            .try_send(PeerTestCommand::SendCharlieResponse {
                nonce,
                rejection: None,
                router_id: alice_router_id.clone(),
            })
            .unwrap();

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(bob_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message3 {
                        nonce: received_nonce,
                        message,
                        rejection,
                        signature,
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, None);

                let mut payload = BytesMut::with_capacity(128);
                payload.put_slice(b"PeerTestValidate");
                payload.put_slice(&alice_router_id.to_vec());
                payload.put_slice(&alice_router_id.to_vec());
                payload.put_slice(&message);

                assert!(charlie_verifying_key.verify(&payload, signature).is_ok());
            }
            _ => panic!("peer test message 3 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_2_alice_verifying_key_not_found() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            router_id: bob_router_id,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let bob_intro_key = [1u8; 32];

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::RequestCharlie {
                        router_id: alice_router_id.clone(),
                        message,
                        signature,
                    },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(bob_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message3 {
                        nonce: received_nonce,
                        rejection,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::RouterUnknown));
            }
            _ => panic!("peer test message 3 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_2_invalid_signature() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            alice_router_info,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let bob_intro_key = [1u8; 32];

        // store alice's router info into storage
        session.router_ctx.profile_storage().add_router(alice_router_info);

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            // bob's router hash is omitted so the router hash fails
            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::RequestCharlie {
                        router_id: alice_router_id.clone(),
                        message,
                        signature,
                    },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        tracing::error!("pkt lne = {}", pkt.len());
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(bob_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message3 {
                        nonce: received_nonce,
                        rejection,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::SignatureFailure));
            }
            _ => panic!("peer test message 3 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_2_invalid_address() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            alice_router_info,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let bob_intro_key = [1u8; 32];
        let router_id = alice_router_info.identity.id().to_vec();

        // store alice's router info into storage
        session.router_ctx.profile_storage().add_router(alice_router_info);

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());

            // ip is different from what the active session has
            out.put_slice(&[8, 8, 8, 8]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::RequestCharlie {
                        router_id: alice_router_id.clone(),
                        message,
                        signature,
                    },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(bob_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message3 {
                        nonce: received_nonce,
                        rejection,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::UnsupportedAddress));
            }
            _ => panic!("peer test message 3 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_2_invalid_port() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            alice_router_info,
            mut recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let recv_key_ctx = KeyContext {
            k_data: session.send_key_ctx.k_data,
            k_header_2: session.send_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let bob_intro_key = [1u8; 32];
        let router_id = alice_router_info.identity.id().to_vec();

        // store alice's router info into storage
        session.router_ctx.profile_storage().add_router(alice_router_info);

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);

            // port is different from what the active session has
            out.put_u16(0);
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::RequestCharlie {
                        router_id: alice_router_id.clone(),
                        message,
                        signature,
                    },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        assert!(timeout!(event_rx.recv(), Duration::from_secs(1)).await.is_err());

        let mut buffer = vec![0u8; 1500];
        let (nread, _from) = timeout!(recv_socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        let mut pkt = buffer[..nread].to_vec();

        let mut reader = HeaderReader::new(bob_intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();

        let pkt_num = match reader.parse(recv_key_ctx.k_header_2).unwrap() {
            HeaderKind::Data { pkt_num, .. } => pkt_num,
            _ => panic!("invalid pkt"),
        };

        let ad = pkt[..16].to_vec();
        let mut pkt = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&ad, &mut pkt)
            .unwrap();

        match Block::parse(&pkt)
            .unwrap()
            .iter()
            .find(|block| core::matches!(block, Block::PeerTest { .. }))
        {
            Some(Block::PeerTest {
                message:
                    PeerTestMessage::Message3 {
                        nonce: received_nonce,
                        rejection,
                        ..
                    },
            }) => {
                assert_eq!(*received_nonce, nonce);
                assert_eq!(*rejection, Some(RejectionReason::UnsupportedAddress));
            }
            _ => panic!("peer test message 3 block not found"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_2_alice_verifying_from_router_block() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            alice_router_info,
            recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];
        let router_id = alice_router_info.identity.id().to_vec();

        // serialize alice's router info so it can be sent in an in-session router info block
        let serialized = alice_router_info.serialize(&signing_key);

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::RequestCharlie {
                        router_id: alice_router_id.clone(),
                        message,
                        signature,
                    },
                    router_info: Some(&serialized),
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        match timeout!(event_rx.recv()).await.unwrap().unwrap() {
            PeerTestEvent::BobRequest {
                nonce: alice_nonce,
                router_id,
                ..
            } => {
                assert_eq!(alice_nonce, nonce);
                assert_eq!(router_id, alice_router_id);
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_test_message_3_routed_to_manager() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            router_id: bob_router_id,
            recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let send_key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];

        tokio::spawn(session);

        // create message for alice
        let (mut message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(recv_socket.local_address().unwrap().port());
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::CharlieResponse {
                        message: {
                            message.extend(&signature);
                            message
                        },
                        rejection: None,
                    },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &send_key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        match timeout!(event_rx.recv()).await.unwrap().unwrap() {
            PeerTestEvent::CharlieResponse {
                nonce: alice_nonce,
                rejection,
                ..
            } => {
                assert_eq!(alice_nonce, nonce);
                assert_eq!(rejection, None);
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_message_ignored() {
        let ActiveSessionContext {
            session,
            event_rx,
            pkt_tx,
            signing_key,
            alice_router_id,
            router_id: bob_router_id,
            cmd_tx: _cmd_tx,
            recv_socket: _recv_socket,
            ..
        } = make_active_session().await;
        let dst_id = session.dst_id;
        let key_ctx = KeyContext {
            k_data: session.recv_key_ctx.k_data,
            k_header_2: session.recv_key_ctx.k_header_2,
        };
        let intro_key = [0xaa; 32];

        tokio::spawn(session);

        // create message for alice
        let (message, nonce) = {
            let nonce = MockRuntime::rng().next_u32();
            let mut out = BytesMut::with_capacity(128);

            out.put_u8(2);
            out.put_u32(nonce);
            out.put_u32(MockRuntime::time_since_epoch().as_secs() as u32);
            out.put_u8(6u8);
            out.put_u16(8888);
            out.put_slice(&[127, 0, 0, 1]);

            (out.to_vec(), nonce)
        };
        let signature = {
            let mut payload = BytesMut::with_capacity(128);

            payload.put_slice(b"PeerTestValidate");
            payload.put_slice(&bob_router_id);
            payload.put_slice(&message);

            signing_key.sign(&payload)
        };

        let mut pkt = DataMessageBuilder::default()
            .with_dst_id(dst_id)
            .with_message(
                1,
                MessageKind::PeerTest {
                    peer_test_block: &PeerTestBlock::AliceRequest { message, signature },
                    router_info: None,
                },
            )
            .with_key_context(intro_key, &key_ctx)
            .build::<MockRuntime>();

        // decrypt header and send packet to active session
        let mut reader = HeaderReader::new(intro_key, &mut pkt).unwrap();
        let _dst_id = reader.dst_id();
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        // verify the message is routed to `PeerTestManager`
        match timeout!(event_rx.recv()).await.unwrap().unwrap() {
            PeerTestEvent::AliceRequest {
                address,
                nonce: received_nonce,
                router_id,
                ..
            } => {
                assert_eq!(router_id, alice_router_id);
                assert_eq!(received_nonce, nonce);
                assert_eq!(address, ADDRESS);
            }
            _ => panic!("unexpected event"),
        }

        // send the message again
        pkt_tx
            .try_send(Packet {
                pkt: pkt.to_vec(),
                address: ADDRESS,
            })
            .unwrap();

        // verify the message is not not relayed to `PeerTestManager`
        assert!(timeout!(event_rx.recv()).await.is_err());
    }
}
