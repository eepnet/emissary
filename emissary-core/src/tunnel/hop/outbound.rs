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
    i2np::{tunnel::data::TunnelDataBuilder, HopRole, Message, MessageType},
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
    ) -> (RouterId, impl Iterator<Item = Message> + '_) {
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

                Message {
                    message_type: MessageType::TunnelData,
                    message_id: R::rng().next_u32(),
                    expiration: R::time_since_epoch() + Duration::from_secs(8),
                    payload: message,
                }
            });

        (next_hop.router.clone(), messages.into_iter())
    }

    /// Send `message` to tunnel identified by the (`router`, `gateway`) tuple.
    pub fn send_to_tunnel(
        &self,
        router: RouterId,
        gateway: TunnelId,
        message: Vec<u8>,
    ) -> (RouterId, impl Iterator<Item = Message> + '_) {
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

                Message {
                    message_type: MessageType::TunnelData,
                    message_id: R::rng().next_u32(),
                    expiration: R::time_since_epoch() + Duration::from_secs(8),
                    payload: message,
                }
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
        i2np::{Message, MessageBuilder},
        runtime::mock::MockRuntime,
        subsystem::OutboundMessage,
        tunnel::tests::{build_inbound_tunnel, build_outbound_tunnel, connect_routers},
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
        let local_router_id = RouterId::from(local_inbound_hash.clone());

        // connect all transit routers together and connect local router to last hop
        connect_routers(outbound_transit.iter_mut().chain(inbound_transit.iter_mut()));
        inbound_transit[1].connect_router(&local_router_id);
        tokio::time::sleep(Duration::from_millis(500)).await;

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
        let message = messages.next().unwrap().clone();
        assert!(outbound_transit[0]
            .subsystem_handle()
            .send(&outbound_transit[0].router(), message)
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut outbound_transit[0])
                .await
                .is_err()
        );
        let message = {
            let rx = outbound_transit[0].router_rx(&outbound_transit[1].router()).unwrap();

            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
                OutboundMessage::Message(message) => message,
                _ => panic!("invalid message"),
            }
        };

        // second outbound hop (obep)
        assert!(outbound_transit[1]
            .subsystem_handle()
            .send(&outbound_transit[1].router(), message)
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut outbound_transit[1])
                .await
                .is_err()
        );
        let message = {
            let rx = outbound_transit[1].router_rx(&inbound_transit[0].router()).unwrap();

            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
                OutboundMessage::Message(message) => message,
                _ => panic!("invalid message"),
            }
        };

        // first inbound hop (ibgw)
        assert!(inbound_transit[0]
            .subsystem_handle()
            .send(&inbound_transit[0].router(), message)
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut inbound_transit[0])
                .await
                .is_err()
        );
        let message = {
            let rx = inbound_transit[0].router_rx(&inbound_transit[1].router()).unwrap();

            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
                OutboundMessage::Message(message) => message,
                _ => panic!("invalid message"),
            }
        };

        // second inbound hop (participant)
        assert!(inbound_transit[1]
            .subsystem_handle()
            .send(&inbound_transit[1].router(), message)
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut inbound_transit[1])
                .await
                .is_err()
        );
        let message = {
            let rx = inbound_transit[1].router_rx(&local_router_id).unwrap();

            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
                OutboundMessage::Message(message) => message,
                _ => panic!("invalid message"),
            }
        };

        // inbound endpoint
        let message = inbound.handle_tunnel_data(&message).unwrap().collect::<Vec<_>>();
        assert_eq!(message[0].payload, b"hello, world".to_vec());
    }

    #[tokio::test]
    async fn send_tunnel_message_fragmented() {
        let original = (0..4 * 1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let (_local_outbound_hash, outbound, mut outbound_transit) =
            build_outbound_tunnel(true, 3usize);
        let (local_inbound_hash, mut inbound, mut inbound_transit) =
            build_inbound_tunnel(true, 3usize);
        let local_router_id = RouterId::from(local_inbound_hash);

        // connect all transit routers together
        connect_routers(outbound_transit.iter_mut().chain(inbound_transit.iter_mut()));
        inbound_transit[2].connect_router(&local_router_id);

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
            assert!(outbound_transit[0]
                .subsystem_handle()
                .send(&next_router.clone(), message)
                .is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut outbound_transit[0])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];
            let rx = outbound_transit[0].router_rx(&outbound_transit[1].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push(message);
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 2nd outbound hop (participant)
        for message in messages {
            assert!(outbound_transit[1]
                .subsystem_handle()
                .send(&outbound_transit[1].router(), message)
                .is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut outbound_transit[1])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];
            let rx = outbound_transit[1].router_rx(&outbound_transit[2].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push(message);
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 3rd outbound hop (obep)
        for message in messages {
            assert!(outbound_transit[2]
                .subsystem_handle()
                .send(&outbound_transit[2].router(), message)
                .is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut outbound_transit[2])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];
            let rx = outbound_transit[2].router_rx(&inbound_transit[0].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push(message);
            }

            messages
        };

        // reconstructed message
        assert_eq!(messages.len(), 1);
        let message = messages.first().unwrap();

        // 1st inbound hop (ibgw)
        assert!(inbound_transit[0]
            .subsystem_handle()
            .send(&inbound_transit[0].router(), message.clone())
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut inbound_transit[0])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];
            let rx = inbound_transit[0].router_rx(&inbound_transit[1].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push(message);
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 2nd inbound hop (participant)
        for message in messages {
            assert!(inbound_transit[1]
                .subsystem_handle()
                .send(&inbound_transit[1].router(), message)
                .is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut inbound_transit[1])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];
            let rx = inbound_transit[1].router_rx(&inbound_transit[2].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push(message);
            }

            messages
        };
        assert_eq!(messages.len(), 5);

        // 3rd inbound hop (participant)
        for message in messages {
            assert!(inbound_transit[2]
                .subsystem_handle()
                .send(&inbound_transit[2].router(), message)
                .is_ok());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut inbound_transit[2])
                .await
                .is_err()
        );
        let messages = {
            let mut messages = vec![];
            let rx = inbound_transit[2].router_rx(&local_router_id).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push(message);
            }

            messages
        };
        assert_eq!(messages.len(), 5);

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
