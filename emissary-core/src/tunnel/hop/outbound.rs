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
    i2np::{tunnel::data::TunnelDataBuilder, HopRole, MessageBuilder, MessageType},
    primitives::{RouterId, Str, TunnelId},
    runtime::Runtime,
    tunnel::hop::{ReceiverKind, Tunnel, TunnelDirection, TunnelHop},
};

use hashbrown::HashSet;
use rand_core::RngCore;

use alloc::vec::Vec;
use core::{
    iter,
    marker::PhantomData,
    num::NonZeroUsize,
    ops::{Range, RangeFrom},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::obgw";

/// AES IV offset inside the `TunnelData` message.
const AES_IV_OFFSET: Range<usize> = 4..20;

/// Payload offset inside the `TunnelData` message.
const PAYLOAD_OFFSET: RangeFrom<usize> = 20..;

/// Outbound tunnel.
#[derive(Debug)]
pub struct OutboundTunnel<R: Runtime> {
    /// Tunnel hops.
    hops: Vec<TunnelHop>,

    /// Name of the tunnel pool is tunnel belongs to.
    name: Str,

    /// Random bytes used for tunnel data padding.
    padding_bytes: [u8; 1028],

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Marker for `Runtime`.
    _marker: PhantomData<R>,
}

impl<R: Runtime> OutboundTunnel<R> {
    /// Send `message` to `router`
    pub fn send_to_router(
        &self,
        router: RouterId,
        message: Vec<u8>,
    ) -> (RouterId, impl Iterator<Item = Vec<u8>> + '_) {
        tracing::trace!(
            target: LOG_TARGET,
            name = %self.name,
            tunnel = %self.tunnel_id,
            %router,
            message_len = ?message.len(),
            "router delivery",
        );

        // hop must exist since the tunnel is created by us
        let next_hop = self.hops.first().expect("tunnel to exist");
        let router: Vec<u8> = router.into();

        // split `message` into one or more i2np message fragments
        // and iteratively decrypt each fragment with each hop's tunnel keys
        let messages = TunnelDataBuilder::new(next_hop.tunnel_id)
            .with_router_delivery(&router, &message)
            .build::<R>(&self.padding_bytes)
            .map(|mut message| {
                let (iv, ciphertext) = self.hops.iter().rev().fold(
                    (
                        message[AES_IV_OFFSET].to_vec(),
                        message[PAYLOAD_OFFSET].to_vec(),
                    ),
                    |(iv, message), hop| {
                        let mut aes = ecb::Aes::new_decryptor(hop.key_context.iv_key());
                        let iv = aes.decrypt(&iv);

                        let mut aes = cbc::Aes::new_decryptor(hop.key_context.layer_key(), &iv);
                        let ciphertext = aes.decrypt(message);

                        let mut aes = ecb::Aes::new_decryptor(hop.key_context.iv_key());
                        let iv = aes.decrypt(iv);

                        (iv, ciphertext)
                    },
                );

                message[AES_IV_OFFSET].copy_from_slice(&iv);
                message[PAYLOAD_OFFSET].copy_from_slice(&ciphertext);

                let message_id = R::rng().next_u32();

                MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(message_id)
                    .with_expiration(R::time_since_epoch() + Duration::from_secs(8))
                    .with_payload(&message)
                    .build()
            });

        (next_hop.router.clone(), messages.into_iter())
    }

    /// Send `message` to tunnel identified by the (`router`, `gateway`) tuple.
    pub fn send_to_tunnel(
        &self,
        router: RouterId,
        gateway: TunnelId,
        message: Vec<u8>,
    ) -> (RouterId, impl Iterator<Item = Vec<u8>> + '_) {
        tracing::trace!(
            target: LOG_TARGET,
            name = %self.name,
            tunnel = %self.tunnel_id,
            %router,
            %gateway,
            message_len = ?message.len(),
            "tunnel delivery",
        );

        // hop must exist since the tunnel is created by us
        let next_hop = self.hops.first().expect("tunnel to exist");
        let router: Vec<u8> = router.into();

        // split `message` into one or more i2np message fragments
        // and iteratively decrypt each fragment with each hop's tunnel keys
        let messages = TunnelDataBuilder::new(next_hop.tunnel_id)
            .with_tunnel_delivery(&router, gateway, &message)
            .build::<R>(&self.padding_bytes)
            .map(|mut message| {
                let (iv, ciphertext) = self.hops.iter().rev().fold(
                    (
                        message[AES_IV_OFFSET].to_vec(),
                        message[PAYLOAD_OFFSET].to_vec(),
                    ),
                    |(iv, message), hop| {
                        let mut aes = ecb::Aes::new_decryptor(hop.key_context.iv_key());
                        let iv = aes.decrypt(&iv);

                        let mut aes = cbc::Aes::new_decryptor(hop.key_context.layer_key(), &iv);
                        let ciphertext = aes.decrypt(message);

                        let mut aes = ecb::Aes::new_decryptor(hop.key_context.iv_key());
                        let iv = aes.decrypt(iv);

                        (iv, ciphertext)
                    },
                );

                message[AES_IV_OFFSET].copy_from_slice(&iv);
                message[PAYLOAD_OFFSET].copy_from_slice(&ciphertext);

                let message_id = R::rng().next_u32();

                MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(message_id)
                    .with_expiration(R::time_since_epoch() + Duration::from_secs(8))
                    .with_payload(&message)
                    .build()
            });

        (next_hop.router.clone(), messages)
    }
}

impl<R: Runtime> Tunnel for OutboundTunnel<R> {
    fn new(name: Str, tunnel_id: TunnelId, _receiver: ReceiverKind, hops: Vec<TunnelHop>) -> Self {
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

        OutboundTunnel::<R> {
            hops,
            name,
            padding_bytes,
            tunnel_id,
            _marker: Default::default(),
        }
    }

    fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }

    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole> {
        (0..num_hops.get() - 1)
            .map(|_| HopRole::Participant)
            .chain(iter::once(HopRole::OutboundEndpoint))
    }

    fn direction() -> TunnelDirection {
        TunnelDirection::Outbound
    }

    fn hops(&self) -> HashSet<RouterId> {
        self.hops.iter().map(|hop| hop.router.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::Message,
        runtime::mock::MockRuntime,
        tunnel::{
            routing_table::RoutingKind,
            tests::{build_inbound_tunnel, build_outbound_tunnel},
        },
    };

    #[test]
    fn hop_roles() {
        assert_eq!(
            OutboundTunnel::<MockRuntime>::hop_roles(NonZeroUsize::new(1).unwrap())
                .collect::<Vec<_>>(),
            vec![HopRole::OutboundEndpoint]
        );

        assert_eq!(
            OutboundTunnel::<MockRuntime>::hop_roles(NonZeroUsize::new(3).unwrap())
                .collect::<Vec<_>>(),
            vec![
                HopRole::Participant,
                HopRole::Participant,
                HopRole::OutboundEndpoint
            ]
        );
    }

    #[tokio::test]
    async fn send_tunnel_message() {
        let (_local_outbound_hash, outbound, mut outbound_transit) =
            build_outbound_tunnel(true, 2usize);
        let (local_inbound_hash, mut inbound, mut inbound_transit) =
            build_inbound_tunnel(true, 2usize);

        let (gateway_router, gateway_tunnel) = inbound.gateway();

        let message = MessageBuilder::standard()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(13371338u32)
            .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(8))
            .with_payload(b"hello, world")
            .build();

        let (next_router, mut messages) =
            outbound.send_to_tunnel(gateway_router, gateway_tunnel, message);
        assert_eq!(outbound_transit[0].router(), next_router);

        // first outbound hop (participant)
        let message = Message::parse_short(&messages.next().unwrap()).unwrap();
        assert!(outbound_transit[0].routing_table().route_message(message).is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut outbound_transit[0])
                .await
                .is_err()
        );
        let RoutingKind::External {
            router_id: next_router,
            message,
        } = outbound_transit[0].message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };
        assert_eq!(outbound_transit[1].router(), next_router);

        // second outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        assert!(outbound_transit[1].routing_table().route_message(message).is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut outbound_transit[1])
                .await
                .is_err()
        );
        let RoutingKind::External {
            router_id: next_router,
            message,
        } = outbound_transit[1].message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };
        assert_eq!(inbound_transit[0].router(), next_router);

        // first inbound hop (ibgw)
        let message = Message::parse_short(&message).unwrap();
        assert!(inbound_transit[0].routing_table().route_message(message).is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut inbound_transit[0])
                .await
                .is_err()
        );
        let RoutingKind::External {
            router_id: next_router,
            message,
        } = inbound_transit[0].message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };
        assert_eq!(inbound_transit[1].router(), next_router);

        // second inbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        assert!(inbound_transit[1].routing_table().route_message(message).is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut inbound_transit[1])
                .await
                .is_err()
        );
        let RoutingKind::External {
            router_id: next_router,
            message,
        } = inbound_transit[1].message_rx().try_recv().unwrap()
        else {
            panic!("invalid routing kind");
        };
        assert_eq!(RouterId::from(local_inbound_hash), next_router);

        // inbound endpoint
        let message = Message::parse_short(&message).unwrap();
        let message = inbound.handle_tunnel_data(&message).unwrap().collect::<Vec<_>>();
        assert_eq!(message[0].payload, b"hello, world".to_vec());
    }

    #[tokio::test]
    async fn send_tunnel_message_fragmented() {
        let original = (0..4 * 1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let (_local_outbound_hash, outbound, mut outbound_transit) =
            build_outbound_tunnel(true, 3usize);
        let (_local_inbound_hash, mut inbound, mut inbound_transit) =
            build_inbound_tunnel(true, 3usize);

        let (gateway_router, gateway_tunnel) = inbound.gateway();

        let message = MessageBuilder::standard()
            .with_message_type(MessageType::Data)
            .with_message_id(13371338u32)
            .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(8))
            .with_payload(&original)
            .build();

        // 1st outbound hop (participant)
        let (next_router, messages) =
            outbound.send_to_tunnel(gateway_router, gateway_tunnel, message);
        assert_eq!(outbound_transit[0].router(), next_router);

        for message in messages {
            let message = Message::parse_short(&message).unwrap();
            assert!(outbound_transit[0].routing_table().route_message(message).is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut outbound_transit[0])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];

            while let Ok(RoutingKind::External { router_id, message }) =
                outbound_transit[0].message_rx().try_recv()
            {
                assert_eq!(outbound_transit[1].router(), router_id);
                messages.push((router_id, message));
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 2nd outbound hop (participant)
        for (_router, message) in messages {
            let message = Message::parse_short(&message).unwrap();
            assert!(outbound_transit[1].routing_table().route_message(message).is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut outbound_transit[1])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];

            while let Ok(RoutingKind::External { router_id, message }) =
                outbound_transit[1].message_rx().try_recv()
            {
                assert_eq!(outbound_transit[2].router(), router_id);
                messages.push((router_id, message));
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 3rd outbound hop (obep)
        for (_router, message) in messages {
            let message = Message::parse_short(&message).unwrap();
            assert!(outbound_transit[2].routing_table().route_message(message).is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut outbound_transit[2])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];

            while let Ok(RoutingKind::External { router_id, message }) =
                outbound_transit[2].message_rx().try_recv()
            {
                messages.push((router_id, message));
            }

            messages
        };

        // reconstructed message
        assert_eq!(messages.len(), 1);
        let (next_router, message) = messages.first().unwrap();

        // first hop is inbound gateway
        assert_eq!(&inbound_transit[0].router(), next_router);

        // 1st inbound hop (ibgw)
        let message = Message::parse_short(&message).unwrap();
        assert!(inbound_transit[0].routing_table().route_message(message).is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut inbound_transit[0])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];

            while let Ok(RoutingKind::External { router_id, message }) =
                inbound_transit[0].message_rx().try_recv()
            {
                messages.push((router_id, message));
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 2nd inbound hop (participant)
        for (_router, message) in messages {
            let message = Message::parse_short(&message).unwrap();
            assert!(inbound_transit[1].routing_table().route_message(message).is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut inbound_transit[1])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];

            while let Ok(RoutingKind::External { router_id, message }) =
                inbound_transit[1].message_rx().try_recv()
            {
                messages.push((router_id, message));
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 3rd inbound hop (participant)
        for (_router, message) in messages {
            let message = Message::parse_short(&message).unwrap();
            assert!(inbound_transit[2].routing_table().route_message(message).is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut inbound_transit[2])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];

            while let Ok(RoutingKind::External { router_id, message }) =
                inbound_transit[2].message_rx().try_recv()
            {
                messages.push((router_id, message));
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        let messages = messages
            .into_iter()
            .map(|(_, message)| Message::parse_short(&message).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(inbound.handle_tunnel_data(&messages[0]).unwrap().count(), 0);
        assert_eq!(inbound.handle_tunnel_data(&messages[1]).unwrap().count(), 0);
        assert_eq!(inbound.handle_tunnel_data(&messages[2]).unwrap().count(), 0);
        assert_eq!(inbound.handle_tunnel_data(&messages[3]).unwrap().count(), 0);

        let Message {
            message_type: MessageType::Data,
            payload,
            ..
        } = inbound.handle_tunnel_data(&messages[4]).unwrap().next().unwrap()
        else {
            panic!("invalid message");
        };

        assert_eq!(payload, original);
    }
}
