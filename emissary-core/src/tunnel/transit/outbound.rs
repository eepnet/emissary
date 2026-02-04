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
    crypto::sha256::Sha256,
    error::{Error, RejectionReason, TunnelError},
    events::EventHandle,
    i2np::{
        tunnel::{
            data::{EncryptedTunnelData, MessageKind, TunnelData},
            gateway::TunnelGateway,
        },
        Message, MessageBuilder, MessageType,
    },
    primitives::{MessageId, RouterId, TunnelId},
    runtime::{Instant, Runtime},
    tunnel::{
        fragment::{FragmentHandler, OwnedDeliveryInstructions},
        noise::TunnelKeys,
        routing_table::RoutingTable,
        transit::{TransitTunnel, TRANSIT_TUNNEL_EXPIRATION},
    },
};

use futures::FutureExt;
use rand_core::RngCore;

use alloc::vec::Vec;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thingbuf::mpsc::Receiver;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::obep";

/// Outbound endpoint.
pub struct OutboundEndpoint<R: Runtime> {
    /// Event handle.
    event_handle: EventHandle<R>,

    /// Tunnel expiration timer.
    expiration_timer: R::Timer,

    /// Fragment handler.
    fragment: FragmentHandler<R>,

    /// Used inbound bandwidth.
    inbound_bandwidth: usize,

    /// RX channel for receiving messages.
    message_rx: Receiver<Message>,

    /// Metrics handle.
    #[allow(unused)]
    metrics_handle: R::MetricsHandle,

    /// Used outbound bandwidth.
    outbound_bandwidth: usize,

    /// Routing table.
    routing_table: RoutingTable,

    // When was the tunnel started.
    started: Option<R::Instant>,

    /// Total bandwidth.
    total_bandwidth: usize,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel keys.
    tunnel_keys: TunnelKeys,
}

impl<R: Runtime> OutboundEndpoint<R> {
    /// Find paylod start by locating the 0x00 byte at the end of the padding section and verify
    /// the checksum of the message before returning the index where the payload section starts.
    ///
    /// https://geti2p.net/spec/tunnel-message#tunnel-message-decrypted
    fn find_payload_start(&self, ciphertext: &[u8], iv: &[u8]) -> crate::Result<usize> {
        let padding_end =
            ciphertext[4..].iter().enumerate().find(|(_, byte)| byte == &&0x0).ok_or_else(
                || {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "decrypted tunnel data doesn't contain zero byte",
                    );

                    Error::Tunnel(TunnelError::InvalidMessage)
                },
            )?;
        let checksum =
            Sha256::new().update(&ciphertext[4 + padding_end.0 + 1..]).update(iv).finalize();

        if ciphertext[..4] != checksum[..4] {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                checksum = ?ciphertext[..4],
                calculated = ?checksum[..4],
                "tunnel data checksum mismatch",
            );

            return Err(Error::Tunnel(TunnelError::MessageRejected(
                RejectionReason::InvalidChecksum,
            )));
        }

        // neither checksum (+4) nor zero byte (+1) are part of the checksum
        let payload_start = padding_end.0 + 1 + 4;

        if payload_start >= ciphertext.len() {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                "decrypted tunnel data doesn't contain zero byte",
            );

            return Err(Error::Tunnel(TunnelError::InvalidMessage));
        }

        Ok(payload_start)
    }

    /// Handle tunnel data.
    ///
    /// Return `RouterId` of the next hop and the message that needs to be forwarded
    /// to them on success.
    fn handle_tunnel_data(
        &mut self,
        tunnel_data: &EncryptedTunnelData,
    ) -> crate::Result<impl Iterator<Item = (RouterId, Vec<u8>)>> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            "outbound endpoint tunnel data",
        );

        // decrypt the tunnel data record into plaintext,
        // find where the payload starts and verify the checksum
        let (ciphertext, iv) = self.tunnel_keys.decrypt_record(tunnel_data);
        let payload_start = self.find_payload_start(&ciphertext, &iv)?;

        let our_message = ciphertext[payload_start..].to_vec();
        let _ = TunnelData::parse(&our_message).map_err(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                ?error,
                "malformed tunnel data message",
            );

            Error::Tunnel(TunnelError::InvalidMessage)
        })?;

        // parse messages and fragments and return an iterator of ready messages
        let messages = TunnelData::parse(&ciphertext[payload_start..])
            .map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    ?error,
                    "malformed tunnel data message",
                );

                Error::Tunnel(TunnelError::InvalidMessage)
            })?
            .messages
            .into_iter()
            .filter_map(|message| {
                let (message, delivery_instructions) = match message.message_kind {
                    MessageKind::Unfragmented {
                        delivery_instructions,
                    } => (
                        Message::parse_standard(message.message)
                            .inspect_err(|error| {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    tunnel_id = %self.tunnel_id,
                                    ?error,
                                    "invalid i2np message"
                                );
                            })
                            .ok()?,
                        OwnedDeliveryInstructions::from(&delivery_instructions),
                    ),
                    MessageKind::FirstFragment {
                        message_id,
                        delivery_instructions,
                    } => self.fragment.first_fragment(
                        MessageId::from(message_id),
                        &delivery_instructions,
                        message.message,
                    )?,
                    MessageKind::MiddleFragment {
                        message_id,
                        sequence_number,
                    } => self.fragment.middle_fragment(
                        MessageId::from(message_id),
                        sequence_number,
                        message.message,
                    )?,
                    MessageKind::LastFragment {
                        message_id,
                        sequence_number,
                    } => self.fragment.last_fragment(
                        MessageId::from(message_id),
                        sequence_number,
                        message.message,
                    )?,
                };

                if message.expiration < R::time_since_epoch() {
                    tracing::debug!(
                        target: LOG_TARGET,
                        message_id = ?message.message_id,
                        message_type = ?message.message_type,
                        "dropping expired i2np message",
                    );
                    return None;
                }

                match delivery_instructions {
                    OwnedDeliveryInstructions::Local => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "local delivery not supported",
                        );

                        None
                    }
                    OwnedDeliveryInstructions::Router { hash } => {
                        let router = RouterId::from(hash);

                        tracing::trace!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            %router,
                            message_type = ?message.message_type,
                            "router delivery",
                        );

                        let message = MessageBuilder::short()
                            .with_message_type(message.message_type)
                            .with_message_id(message.message_id)
                            .with_expiration(message.expiration)
                            .with_payload(&message.payload)
                            .build();

                        Some((router, message))
                    }
                    OwnedDeliveryInstructions::Tunnel { tunnel_id, hash } => {
                        let router = RouterId::from(hash);

                        tracing::trace!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            %router,
                            delivery_tunnel = ?tunnel_id,
                            message_type = ?message.message_type,
                            "tunnel delivery",
                        );

                        let payload = TunnelGateway {
                            tunnel_id: TunnelId::from(tunnel_id),
                            payload: &message.serialize_standard(),
                        }
                        .serialize();

                        let message = MessageBuilder::short()
                            .with_message_type(MessageType::TunnelGateway)
                            .with_message_id(R::rng().next_u32())
                            .with_expiration(R::time_since_epoch() + Duration::from_secs(8))
                            .with_payload(&payload)
                            .build();

                        Some((router, message))
                    }
                }
            })
            .collect::<Vec<(RouterId, Vec<u8>)>>();

        Ok(messages.into_iter())
    }
}

impl<R: Runtime> TransitTunnel<R> for OutboundEndpoint<R> {
    /// Create new [`OutboundEndpoint`].
    fn new(
        tunnel_id: TunnelId,
        _next_tunnel_id: TunnelId,
        _next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
        event_handle: EventHandle<R>,
    ) -> Self {
        OutboundEndpoint {
            event_handle,
            expiration_timer: R::timer(TRANSIT_TUNNEL_EXPIRATION),
            fragment: FragmentHandler::new(),
            inbound_bandwidth: 0usize,
            message_rx,
            metrics_handle,
            outbound_bandwidth: 0usize,
            routing_table,
            started: Some(R::now()),
            total_bandwidth: 0usize,
            tunnel_id,
            tunnel_keys,
        }
    }
}

impl<R: Runtime> Future for OutboundEndpoint<R> {
    type Output = TunnelId;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "message channel closed",
                    );
                    return Poll::Ready(self.tunnel_id);
                }
                Some(message) => {
                    self.inbound_bandwidth += message.serialized_len_short();
                    self.total_bandwidth += message.serialized_len_short();

                    let MessageType::TunnelData = message.message_type else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            message_type = ?message.message_type,
                            "unsupported message",
                        );
                        debug_assert!(false);
                        continue;
                    };

                    let Some(message) = EncryptedTunnelData::parse(&message.payload) else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "malformed `TunnelData` message",
                        );
                        debug_assert!(false);
                        continue;
                    };

                    match self.handle_tunnel_data(&message) {
                        Ok(messages) => messages.into_iter().for_each(|(router, message)| {
                            self.outbound_bandwidth += message.len();
                            self.total_bandwidth += message.len();

                            if let Err(error) = self.routing_table.send_message(router, message) {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    tunnel_id = %self.tunnel_id,
                                    ?error,
                                    "failed to send message",
                                )
                            }
                        }),
                        Err(error) => tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            ?error,
                            "failed to handle tunnel data",
                        ),
                    }
                }
            }
        }

        // if the tunnel hasn't had any activity in the first two minutes, terminate it early
        if let Some(ref started) = self.started {
            if started.elapsed() > Duration::from_secs(2 * 60) {
                if self.total_bandwidth == 0 {
                    tracing::debug!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "shutting down tunnel after 2 minutes of inactivity",
                    );
                    return Poll::Ready(self.tunnel_id);
                } else {
                    self.started = None;
                }
            }
        }

        if self.event_handle.poll_unpin(cx).is_ready() {
            self.event_handle.transit_inbound_bandwidth(self.inbound_bandwidth);
            self.event_handle.transit_outbound_bandwidth(self.outbound_bandwidth);
            self.inbound_bandwidth = 0;
            self.outbound_bandwidth = 0;
        }

        if self.expiration_timer.poll_unpin(cx).is_ready() {
            return Poll::Ready(self.tunnel_id);
        }

        // poll fragment handler
        //
        // the futures don't return anything but must be polled so they make progress
        let _ = self.fragment.poll_unpin(cx);

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{EphemeralPublicKey, StaticPrivateKey},
        events::EventManager,
        i2np::HopRole,
        primitives::Str,
        runtime::mock::MockRuntime,
        tunnel::{
            hop::{
                outbound::OutboundTunnel, pending::PendingTunnel, ReceiverKind,
                TunnelBuildParameters, TunnelInfo,
            },
            noise::NoiseContext,
            routing_table::RoutingKindRecycle,
        },
    };
    use bytes::Bytes;
    use thingbuf::mpsc::{channel, with_recycle};

    // outbound endpoint and the target router are the same router
    //
    // verify that the payload inside the `TunnelData` message gets routed correctly TunnelManager
    #[tokio::test]
    async fn obep_routes_message_to_self() {
        let (_tx, rx) = channel(64);
        let (transit_tx, transit_rx) = channel(64);
        let (manager_tx, manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let router_id = RouterId::from(vec![1, 2, 3, 4]);
        let routing_table = RoutingTable::new(router_id.clone(), manager_tx, transit_tx);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let obep_key = StaticPrivateKey::random(MockRuntime::rng());
        let obep_router_id = RouterId::random();

        let obgw_key = StaticPrivateKey::random(MockRuntime::rng());
        let obgw_router_id = RouterId::random();

        let (pending, router_id, mut message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: vec![(
                        Bytes::from(Into::<Vec<u8>>::into(obep_router_id.clone())),
                        obep_key.public(),
                    )],
                    name: Str::from("tunnel-pool"),
                    noise: NoiseContext::new(
                        obgw_key,
                        Bytes::from(Into::<Vec<u8>>::into(obgw_router_id.clone())),
                    ),
                    message_id: MessageId::from(MockRuntime::rng().next_u32()),
                    tunnel_info: TunnelInfo::Outbound {
                        gateway: TunnelId::random(),
                        tunnel_id: TunnelId::random(),
                        router_id: Bytes::from(Into::<Vec<u8>>::into(obgw_router_id.clone())),
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(router_id, obep_router_id);

        // build 1-hop tunnel
        let (obep_keys, obgw) = {
            let obep_noise = NoiseContext::new(
                obep_key.clone(),
                Bytes::from(Into::<Vec<u8>>::into(obep_router_id.clone())),
            );

            // create tunnel session
            let mut obep_session = obep_noise.create_short_inbound_session(
                EphemeralPublicKey::from_bytes(
                    pending.hops()[0].outbound_session().ephemeral_key(),
                )
                .unwrap(),
            );

            let router_id = Into::<Vec<u8>>::into(obep_router_id.clone());
            let (idx, record) = message.payload[1..]
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &router_id[..16])
                .unwrap();
            let _decrypted_record = obep_session.decrypt_build_record(record[48..].to_vec());
            obep_session.create_tunnel_keys(HopRole::OutboundEndpoint).unwrap();

            record[48] = 0x00;
            record[49] = 0x00;
            record[201] = 0x00;

            obep_session.encrypt_build_records(&mut message.payload, idx).unwrap();
            let keys = obep_session.finalize().unwrap();

            let msg = MessageBuilder::standard()
                .with_message_type(MessageType::OutboundTunnelBuildReply)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(5))
                .with_payload(&message.payload)
                .build();
            let message = Message::parse_standard(&msg).unwrap();

            (keys, pending.try_build_tunnel(message).unwrap())
        };

        let message = MessageBuilder::standard()
            .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(5))
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(MockRuntime::rng().next_u32())
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        let (_to_router, mut messages) = obgw.send_to_router(obep_router_id.clone(), message);
        let message = messages.next().expect("to exist");

        let message = Message::parse_short(&message).unwrap();
        let parsed = EncryptedTunnelData::parse(&message.payload).unwrap();

        let mut tunnel = OutboundEndpoint::<MockRuntime>::new(
            TunnelId::random(),
            TunnelId::random(),
            RouterId::random(),
            obep_keys,
            routing_table,
            MockRuntime::register_metrics(vec![], None),
            rx,
            event_handle.clone(),
        );

        let (router_id, message) = tunnel.handle_tunnel_data(&parsed).unwrap().next().unwrap();
        assert_eq!(router_id, obep_router_id);

        tunnel.routing_table.send_message(router_id, message).unwrap();
        assert!(manager_rx.try_recv().is_ok());
        assert!(transit_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn expired_unfragmented_message() {
        let (_tx, rx) = channel(64);
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let router_id = RouterId::from(vec![1, 2, 3, 4]);
        let routing_table = RoutingTable::new(router_id.clone(), manager_tx, transit_tx);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let obep_key = StaticPrivateKey::random(MockRuntime::rng());
        let obep_router_id = RouterId::random();

        let obgw_key = StaticPrivateKey::random(MockRuntime::rng());
        let obgw_router_id = RouterId::random();

        let (pending, router_id, mut message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: vec![(
                        Bytes::from(Into::<Vec<u8>>::into(obep_router_id.clone())),
                        obep_key.public(),
                    )],
                    name: Str::from("tunnel-pool"),
                    noise: NoiseContext::new(
                        obgw_key,
                        Bytes::from(Into::<Vec<u8>>::into(obgw_router_id.clone())),
                    ),
                    message_id: MessageId::from(MockRuntime::rng().next_u32()),
                    tunnel_info: TunnelInfo::Outbound {
                        gateway: TunnelId::random(),
                        tunnel_id: TunnelId::random(),
                        router_id: Bytes::from(Into::<Vec<u8>>::into(obgw_router_id.clone())),
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(router_id, obep_router_id);

        // build 1-hop tunnel
        let (obep_keys, obgw) = {
            let obep_noise = NoiseContext::new(
                obep_key.clone(),
                Bytes::from(Into::<Vec<u8>>::into(obep_router_id.clone())),
            );

            // create tunnel session
            let mut obep_session = obep_noise.create_short_inbound_session(
                EphemeralPublicKey::from_bytes(
                    pending.hops()[0].outbound_session().ephemeral_key(),
                )
                .unwrap(),
            );

            let router_id = Into::<Vec<u8>>::into(obep_router_id.clone());
            let (idx, record) = message.payload[1..]
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &router_id[..16])
                .unwrap();
            let _decrypted_record = obep_session.decrypt_build_record(record[48..].to_vec());
            obep_session.create_tunnel_keys(HopRole::OutboundEndpoint).unwrap();

            record[48] = 0x00;
            record[49] = 0x00;
            record[201] = 0x00;

            obep_session.encrypt_build_records(&mut message.payload, idx).unwrap();
            let keys = obep_session.finalize().unwrap();

            let msg = MessageBuilder::standard()
                .with_message_type(MessageType::OutboundTunnelBuildReply)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(5))
                .with_payload(&message.payload)
                .build();
            let message = Message::parse_standard(&msg).unwrap();

            (keys, pending.try_build_tunnel(message).unwrap())
        };

        let message = MessageBuilder::standard()
            .with_expiration(MockRuntime::time_since_epoch() - Duration::from_secs(5))
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(MockRuntime::rng().next_u32())
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        let (_to_router, mut messages) = obgw.send_to_router(obep_router_id.clone(), message);
        let message = messages.next().expect("to exist");

        let message = Message::parse_short(&message).unwrap();
        let parsed = EncryptedTunnelData::parse(&message.payload).unwrap();

        let mut tunnel = OutboundEndpoint::<MockRuntime>::new(
            TunnelId::random(),
            TunnelId::random(),
            RouterId::random(),
            obep_keys,
            routing_table,
            MockRuntime::register_metrics(vec![], None),
            rx,
            event_handle.clone(),
        );
        assert!(tunnel.handle_tunnel_data(&parsed).unwrap().collect::<Vec<_>>().is_empty());
    }

    #[tokio::test]
    async fn expired_fragmented_message() {
        let (_tx, rx) = channel(64);
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let router_id = RouterId::from(vec![1, 2, 3, 4]);
        let routing_table = RoutingTable::new(router_id.clone(), manager_tx, transit_tx);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let obep_key = StaticPrivateKey::random(MockRuntime::rng());
        let obep_router_id = RouterId::random();

        let obgw_key = StaticPrivateKey::random(MockRuntime::rng());
        let obgw_router_id = RouterId::random();

        let (pending, router_id, mut message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: vec![(
                        Bytes::from(Into::<Vec<u8>>::into(obep_router_id.clone())),
                        obep_key.public(),
                    )],
                    name: Str::from("tunnel-pool"),
                    noise: NoiseContext::new(
                        obgw_key,
                        Bytes::from(Into::<Vec<u8>>::into(obgw_router_id.clone())),
                    ),
                    message_id: MessageId::from(MockRuntime::rng().next_u32()),
                    tunnel_info: TunnelInfo::Outbound {
                        gateway: TunnelId::random(),
                        tunnel_id: TunnelId::random(),
                        router_id: Bytes::from(Into::<Vec<u8>>::into(obgw_router_id.clone())),
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(router_id, obep_router_id);

        // build 1-hop tunnel
        let (obep_keys, obgw) = {
            let obep_noise = NoiseContext::new(
                obep_key.clone(),
                Bytes::from(Into::<Vec<u8>>::into(obep_router_id.clone())),
            );

            // create tunnel session
            let mut obep_session = obep_noise.create_short_inbound_session(
                EphemeralPublicKey::from_bytes(
                    pending.hops()[0].outbound_session().ephemeral_key(),
                )
                .unwrap(),
            );

            let router_id = Into::<Vec<u8>>::into(obep_router_id.clone());
            let (idx, record) = message.payload[1..]
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &router_id[..16])
                .unwrap();
            let _decrypted_record = obep_session.decrypt_build_record(record[48..].to_vec());
            obep_session.create_tunnel_keys(HopRole::OutboundEndpoint).unwrap();

            record[48] = 0x00;
            record[49] = 0x00;
            record[201] = 0x00;

            obep_session.encrypt_build_records(&mut message.payload, idx).unwrap();
            let keys = obep_session.finalize().unwrap();

            let msg = MessageBuilder::standard()
                .with_message_type(MessageType::OutboundTunnelBuildReply)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(5))
                .with_payload(&message.payload)
                .build();
            let message = Message::parse_standard(&msg).unwrap();

            (keys, pending.try_build_tunnel(message).unwrap())
        };

        // message expires in one second
        let message = MessageBuilder::standard()
            .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(1))
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(MockRuntime::rng().next_u32())
            .with_payload(&vec![0xaa; 2048])
            .build();

        let mut tunnel = OutboundEndpoint::<MockRuntime>::new(
            TunnelId::random(),
            TunnelId::random(),
            RouterId::random(),
            obep_keys,
            routing_table,
            MockRuntime::register_metrics(vec![], None),
            rx,
            event_handle.clone(),
        );

        let (_to_router, messages) = obgw.send_to_router(obep_router_id.clone(), message);
        let messages = messages.collect::<Vec<_>>();
        assert_eq!(messages.len(), 3);

        // send first two fragments and verify there's no output
        for i in 0..2 {
            let message = Message::parse_short(&messages[i]).unwrap();
            let parsed = EncryptedTunnelData::parse(&message.payload).unwrap();

            assert!(tunnel.handle_tunnel_data(&parsed).unwrap().collect::<Vec<_>>().is_empty());
        }

        // sleep for two seconds and allow the fragments to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // send third message and verify there's no output because the fragments were expired
        let message = Message::parse_short(&messages[2]).unwrap();
        let parsed = EncryptedTunnelData::parse(&message.payload).unwrap();

        assert!(tunnel.handle_tunnel_data(&parsed).unwrap().collect::<Vec<_>>().is_empty());
    }
}
