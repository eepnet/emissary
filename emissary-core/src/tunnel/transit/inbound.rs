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
    crypto::aes::{cbc, ecb},
    error::Error,
    events::EventHandle,
    i2np::{
        tunnel::{data::TunnelDataBuilder, gateway::TunnelGateway},
        Message, MessageBuilder, MessageType,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        noise::TunnelKeys,
        routing_table::RoutingTable,
        transit::{TransitTunnel, TRANSIT_TUNNEL_EXPIRATION},
    },
};

use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;
use thingbuf::mpsc::Receiver;

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    ops::{Range, RangeFrom},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::ibgw";

/// AES IV offset inside the `TunnelData` message.
const AES_IV_OFFSET: Range<usize> = 4..20;

/// Payload offset inside the `TunnelData` message.
const PAYLOAD_OFFSET: RangeFrom<usize> = 20..;

/// Inbound gateway.
pub struct InboundGateway<R: Runtime> {
    /// Event handle.
    event_handle: EventHandle<R>,

    /// Tunnel expiration timer.
    expiration_timer: BoxFuture<'static, ()>,

    /// Used bandwidth.
    bandwidth: usize,

    /// RX channel for receiving messages.
    message_rx: Receiver<Message>,

    /// Metrics handle.
    #[allow(unused)]
    metrics_handle: R::MetricsHandle,

    /// Next router ID.
    next_router: RouterId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Random bytes used for tunnel data padding.
    padding_bytes: [u8; 1028],

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel key context.
    tunnel_keys: TunnelKeys,
}

impl<R: Runtime> InboundGateway<R> {
    fn handle_tunnel_gateway(
        &self,
        tunnel_gateway: &TunnelGateway,
    ) -> crate::Result<(RouterId, impl Iterator<Item = Vec<u8>> + '_)> {
        match Message::parse_standard(tunnel_gateway.payload) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    gateway_tunnel_id = %tunnel_gateway.tunnel_id,
                    message_len = ?tunnel_gateway.payload.len(),
                    "malformed i2np message",
                );
                return Err(Error::InvalidData);
            }
            Some(message) if message.is_expired::<R>() => {
                tracing::debug!(
                    target: LOG_TARGET,
                    message_id = ?message.message_id,
                    message_type = ?message.message_type,
                    "dropping expired i2np message",
                );
                return Err(Error::Expired);
            }
            Some(message) => tracing::trace!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                message_type = ?message.message_type,
                "tunnel gateway",
            ),
        }

        let messages = TunnelDataBuilder::new(self.next_tunnel_id)
            .with_local_delivery(tunnel_gateway.payload)
            .build::<R>(&self.padding_bytes)
            .map(|mut message| {
                let mut aes = ecb::Aes::new_encryptor(self.tunnel_keys.iv_key());
                let iv = aes.encrypt(&message[AES_IV_OFFSET]);

                let mut aes = cbc::Aes::new_encryptor(self.tunnel_keys.layer_key(), &iv);
                let ciphertext = aes.encrypt(&message[PAYLOAD_OFFSET]);

                let mut aes = ecb::Aes::new_encryptor(self.tunnel_keys.iv_key());
                let iv = aes.encrypt(iv);

                message[AES_IV_OFFSET].copy_from_slice(&iv);
                message[PAYLOAD_OFFSET].copy_from_slice(&ciphertext);

                MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(R::rng().next_u32())
                    .with_expiration(R::time_since_epoch() + Duration::from_secs(8))
                    .with_payload(&message)
                    .build()
            });

        Ok((self.next_router.clone(), messages))
    }
}

impl<R: Runtime> TransitTunnel<R> for InboundGateway<R> {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
        event_handle: EventHandle<R>,
    ) -> Self {
        // generate random padding bytes used in `TunnelData` messages
        let padding_bytes = {
            let mut padding_bytes = [0u8; 1028];
            R::rng().fill_bytes(&mut padding_bytes);

            padding_bytes = TryInto::<[u8; 1028]>::try_into(
                padding_bytes
                    .into_iter()
                    .map(|byte| if byte == 0 { 1u8 } else { byte })
                    .collect::<Vec<_>>(),
            )
            .expect("to succeed");

            padding_bytes
        };

        InboundGateway {
            event_handle,
            expiration_timer: Box::pin(R::delay(TRANSIT_TUNNEL_EXPIRATION)),
            bandwidth: 0usize,
            message_rx,
            metrics_handle,
            next_router,
            next_tunnel_id,
            padding_bytes,
            routing_table,
            tunnel_id,
            tunnel_keys,
        }
    }
}

impl<R: Runtime> Future for InboundGateway<R> {
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
                    self.bandwidth += message.serialized_len_short();

                    let MessageType::TunnelGateway = message.message_type else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            message_type = ?message.message_type,
                            "unsupported message",
                        );
                        debug_assert!(false);
                        continue;
                    };

                    let Some(message) = TunnelGateway::parse(&message.payload) else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            tunnel_id = %self.tunnel_id,
                            "malformed tunnel gateway message",
                        );
                        debug_assert!(false);
                        continue;
                    };

                    let (router, messages) = match self.handle_tunnel_gateway(&message) {
                        Ok((router, messages)) => (router, messages),
                        Err(Error::Expired) => continue,
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                tunnel_id = %self.tunnel_id,
                                ?error,
                                "failed to handle tunnel gateway",
                            );
                            continue;
                        }
                    };

                    self.bandwidth += messages.into_iter().fold(0usize, |mut acc, message| {
                        acc += message.len();

                        if let Err(error) = self.routing_table.send_message(router.clone(), message)
                        {
                            tracing::error!(
                                target: LOG_TARGET,
                                tunnel_id = %self.tunnel_id,
                                ?error,
                                "failed to send message",
                            )
                        }

                        acc
                    });
                }
            }
        }

        if self.event_handle.poll_unpin(cx).is_ready() {
            self.event_handle.transit_tunnel_bandwidth(self.bandwidth);
            self.bandwidth = 0;
        }

        if self.expiration_timer.poll_unpin(cx).is_ready() {
            return Poll::Ready(self.tunnel_id);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::EphemeralPublicKey,
        events::EventManager,
        i2np::HopRole,
        primitives::{MessageId, Str},
        runtime::mock::MockRuntime,
        tunnel::{
            garlic::{DeliveryInstructions, GarlicHandler},
            hop::{
                inbound::InboundTunnel, pending::PendingTunnel, ReceiverKind,
                TunnelBuildParameters, TunnelInfo,
            },
            pool::TunnelPoolBuildParameters,
            routing_table::RoutingKindRecycle,
            tests::make_router,
        },
    };
    use bytes::Bytes;
    use thingbuf::mpsc::{channel, with_recycle};

    #[tokio::test]
    async fn expired_tunnel_gateway_payload() {
        let (ibgw_router_hash, ibgw_static_key, _, ibgw_noise, ibgw_router_info) =
            make_router(false);
        let mut ibgw_garlic = GarlicHandler::<MockRuntime>::new(
            ibgw_noise.clone(),
            MockRuntime::register_metrics(vec![], None),
        );
        let (_ibep_router_hash, _ibep_public_key, _, ibep_noise, ibep_router_info) =
            make_router(false);

        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(ibep_router_info.identity.id(), manager_tx, transit_tx);

        let (_tx, rx) = channel(64);
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());

        let (pending, router_id, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: vec![(ibgw_router_hash.clone(), ibgw_static_key.public())],
                    name: Str::from("tunnel-pool"),
                    noise: ibep_noise.clone(),
                    message_id: MessageId::from(MockRuntime::rng().next_u32()),
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id: TunnelId::random(),
                        router_id: Bytes::from(RouterId::random().to_vec()),
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        assert_eq!(router_id, ibgw_router_info.identity.id());
        assert_eq!(message.message_type, MessageType::Garlic);

        let mut message = match ibgw_garlic.handle_message(message).unwrap().next() {
            Some(DeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        assert_eq!(message.payload[1..].len() % 218, 0);

        // build 1-hop tunnel
        let (ibgw_keys, _) = {
            // create tunnel session
            let mut ibgw_session = ibgw_noise.create_short_inbound_session(
                EphemeralPublicKey::from_bytes(
                    pending.hops()[0].outbound_session().ephemeral_key(),
                )
                .unwrap(),
            );

            let router_id = ibgw_router_hash;
            let (idx, record) = message.payload[1..]
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &router_id[..16])
                .unwrap();
            let _decrypted_record = ibgw_session.decrypt_build_record(record[48..].to_vec());
            ibgw_session.create_tunnel_keys(HopRole::InboundGateway).unwrap();

            record[48] = 0x00;
            record[49] = 0x00;
            record[201] = 0x00;

            ibgw_session.encrypt_build_records(&mut message.payload, idx).unwrap();
            let keys = ibgw_session.finalize().unwrap();

            let msg = MessageBuilder::standard()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(5))
                .with_payload(&message.payload)
                .build();
            let message = Message::parse_standard(&msg).unwrap();

            (
                keys,
                pending.try_build_tunnel::<MockRuntime>(message).unwrap(),
            )
        };

        let (_msg_tx, msg_rx) = channel(64);
        let tunnel = InboundGateway::<MockRuntime>::new(
            TunnelId::random(),
            TunnelId::random(),
            RouterId::random(),
            ibgw_keys,
            routing_table,
            MockRuntime::register_metrics(vec![], None),
            msg_rx,
            event_handle.clone(),
        );

        let message = MessageBuilder::standard()
            .with_expiration(MockRuntime::time_since_epoch() - Duration::from_secs(5))
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(MockRuntime::rng().next_u32())
            .with_payload(&vec![1, 2, 3, 4])
            .build();

        let tunnel_gateway = TunnelGateway {
            tunnel_id: tunnel.tunnel_id,
            payload: &message,
        };

        match tunnel.handle_tunnel_gateway(&tunnel_gateway) {
            Err(Error::Expired) => {}
            _ => panic!("invalid result"),
        };
    }

    #[tokio::test]
    async fn invalid_tunnel_gateway_payload() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (ibgw_router_hash, ibgw_static_key, _, ibgw_noise, ibgw_router_info) =
            make_router(false);
        let mut ibgw_garlic = GarlicHandler::<MockRuntime>::new(
            ibgw_noise.clone(),
            MockRuntime::register_metrics(vec![], None),
        );
        let (_ibep_router_hash, _ibep_public_key, _, ibep_noise, ibep_router_info) =
            make_router(false);

        let (transit_tx, _transit_rx) = channel(64);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table =
            RoutingTable::new(ibep_router_info.identity.id(), manager_tx, transit_tx);

        let (_tx, rx) = channel(64);
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());

        let (pending, router_id, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: vec![(ibgw_router_hash.clone(), ibgw_static_key.public())],
                    name: Str::from("tunnel-pool"),
                    noise: ibep_noise.clone(),
                    message_id: MessageId::from(MockRuntime::rng().next_u32()),
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id: TunnelId::random(),
                        router_id: Bytes::from(RouterId::random().to_vec()),
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        assert_eq!(router_id, ibgw_router_info.identity.id());
        assert_eq!(message.message_type, MessageType::Garlic);

        let mut message = match ibgw_garlic.handle_message(message).unwrap().next() {
            Some(DeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert_eq!(message.message_type, MessageType::ShortTunnelBuild);
        assert_eq!(message.payload[1..].len() % 218, 0);

        // build 1-hop tunnel
        let (ibgw_keys, _) = {
            // create tunnel session
            let mut ibgw_session = ibgw_noise.create_short_inbound_session(
                EphemeralPublicKey::from_bytes(
                    pending.hops()[0].outbound_session().ephemeral_key(),
                )
                .unwrap(),
            );

            let router_id = ibgw_router_hash;
            let (idx, record) = message.payload[1..]
                .chunks_mut(218)
                .enumerate()
                .find(|(_, chunk)| &chunk[..16] == &router_id[..16])
                .unwrap();
            let _decrypted_record = ibgw_session.decrypt_build_record(record[48..].to_vec());
            ibgw_session.create_tunnel_keys(HopRole::InboundGateway).unwrap();

            record[48] = 0x00;
            record[49] = 0x00;
            record[201] = 0x00;

            ibgw_session.encrypt_build_records(&mut message.payload, idx).unwrap();
            let keys = ibgw_session.finalize().unwrap();

            let msg = MessageBuilder::standard()
                .with_message_type(MessageType::ShortTunnelBuild)
                .with_message_id(MockRuntime::rng().next_u32())
                .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(5))
                .with_payload(&message.payload)
                .build();
            let message = Message::parse_standard(&msg).unwrap();

            (
                keys,
                pending.try_build_tunnel::<MockRuntime>(message).unwrap(),
            )
        };

        let (_msg_tx, msg_rx) = channel(64);
        let tunnel = InboundGateway::<MockRuntime>::new(
            TunnelId::random(),
            TunnelId::random(),
            RouterId::random(),
            ibgw_keys,
            routing_table,
            MockRuntime::register_metrics(vec![], None),
            msg_rx,
            event_handle.clone(),
        );

        let tunnel_gateway = TunnelGateway {
            tunnel_id: tunnel.tunnel_id,
            payload: &vec![0xaa, 0xaa, 0xaa],
        };

        match tunnel.handle_tunnel_gateway(&tunnel_gateway) {
            Err(Error::InvalidData) => {}
            _ => panic!("invalid result"),
        };
    }
}
