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
    i2np::Message,
    primitives::{RouterId, TunnelId},
};

#[cfg(test)]
use crate::{
    crypto::{chachapoly::ChaChaPoly, EphemeralPublicKey},
    error::{Error, TunnelError},
    i2np::{
        garlic::{
            DeliveryInstructions as CloveDeliveryInstructions, GarlicMessage, GarlicMessageBlock,
        },
        tunnel::gateway::TunnelGateway,
        MessageBuilder, MessageType,
    },
    runtime::Runtime,
    tunnel::noise::NoiseContext,
};

#[cfg(test)]
use rand_core::RngCore;
#[cfg(test)]
use zeroize::Zeroize;

#[cfg(test)]
use alloc::vec::Vec;

/// Logging target for the file.
#[cfg(test)]
const LOG_TARGET: &str = "emissary::tunnel::garlic";

/// Garlic clove delivery instructions
pub enum DeliveryInstructions {
    /// Message meant for the local router.
    Local {
        /// I2NP message
        message: Message,
    },

    /// Message meant for router delivery.
    Router {
        /// Router.
        router: RouterId,

        /// Serialized I2NP message.
        message: Message,
    },

    /// Message meant for tunnel delivery.
    Tunnel {
        /// Tunnel ID.
        #[allow(unused)]
        tunnel: TunnelId,

        /// Router.
        router: RouterId,

        /// Serialized I2NP message wrapped in `TunnelGateway` message.
        message: Message,
    },

    /// Unimplemented.
    #[allow(unused)]
    Destination,
}

/// Garlic message handler.
#[cfg(test)]
pub struct GarlicHandler<R: Runtime> {
    /// Noise context.
    noise: NoiseContext,

    /// Metrics handle.
    #[allow(unused)]
    metrics_handle: R::MetricsHandle,
}

#[cfg(test)]
impl<R: Runtime> GarlicHandler<R> {
    /// Create new [`GarlicHandler`].
    pub fn new(noise: NoiseContext, metrics_handle: R::MetricsHandle) -> Self {
        Self {
            noise,
            metrics_handle,
        }
    }

    /// Handle garlic message.
    pub fn handle_message(
        &mut self,
        message: Message,
    ) -> crate::Result<impl Iterator<Item = DeliveryInstructions>> {
        let Message {
            message_id,
            expiration,
            payload,
            ..
        } = message;

        tracing::trace!(
            target: LOG_TARGET,
            ?message_id,
            ?expiration,
            "garlic message",
        );

        if payload.len() < 36 {
            tracing::warn!(
                target: LOG_TARGET,
                ?message_id,
                ?expiration,
                "garlic message is too short",
            );

            return Err(Error::Tunnel(TunnelError::InvalidMessage));
        }

        // derive cipher key and associated data and decrypt the garlic message
        let message = {
            let (mut cipher_key, associated_data) = self.noise.derive_inbound_garlic_key(
                EphemeralPublicKey::from_bytes(&payload[4..36]).ok_or(Error::InvalidData)?,
            );

            let mut message = payload[36..].to_vec();
            ChaChaPoly::new(&cipher_key).decrypt_with_ad(&associated_data, &mut message)?;

            cipher_key.zeroize();

            message
        };

        let messages = GarlicMessage::parse(&message)
            .map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_id,
                    ?error,
                    "invalid garlic message",
                );
                Error::Tunnel(TunnelError::InvalidMessage)
            })?
            .blocks
            .into_iter()
            .filter_map(|block| match block {
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => {
                    if expiration < R::time_since_epoch() {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?message_id,
                            ?message_type,
                            ?delivery_instructions,
                            "dropping expired i2np message",
                        );
                        return None;
                    }

                    match delivery_instructions {
                        CloveDeliveryInstructions::Local => Some(DeliveryInstructions::Local {
                            message: Message {
                                message_type,
                                message_id: *message_id,
                                expiration,
                                payload: message_body.to_vec(),
                            },
                        }),
                        CloveDeliveryInstructions::Router { hash } =>
                            Some(DeliveryInstructions::Router {
                                router: RouterId::from(hash),
                                message: Message {
                                    message_type,
                                    message_id: *message_id,
                                    expiration,
                                    payload: message_body.to_vec(),
                                },
                            }),
                        CloveDeliveryInstructions::Tunnel { hash, tunnel_id } => {
                            let message = MessageBuilder::standard()
                                .with_message_type(message_type)
                                .with_message_id(message_id)
                                .with_expiration(expiration)
                                .with_payload(message_body)
                                .build();

                            let message = TunnelGateway {
                                tunnel_id: tunnel_id.into(),
                                payload: &message,
                            }
                            .serialize();

                            Some(DeliveryInstructions::Tunnel {
                                tunnel: TunnelId::from(tunnel_id),
                                router: RouterId::from(hash),
                                message: Message {
                                    message_type: MessageType::TunnelGateway,
                                    message_id: R::rng().next_u32(),
                                    expiration,
                                    payload: message.to_vec(),
                                },
                            })
                        }
                        CloveDeliveryInstructions::Destination { hash } => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?hash,
                                "ignoring destination",
                            );
                            None
                        }
                    }
                }
                block => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        ?block,
                        "ignoring garlic block",
                    );
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(messages.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{EphemeralPrivateKey, StaticPrivateKey},
        i2np::{garlic::GarlicMessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION},
        primitives::{DestinationId, MessageId, RouterId},
        runtime::mock::MockRuntime,
    };
    use bytes::{BufMut, Bytes, BytesMut};
    use rand_core::RngCore;
    use std::time::Duration;

    #[test]
    fn serialize_deserialize() {
        let remote_key = StaticPrivateKey::random(rand::thread_rng());
        let remote_router_id = Bytes::from(RouterId::random().to_vec());

        let local_key = StaticPrivateKey::random(rand::thread_rng());
        let local_router_id = Bytes::from(RouterId::random().to_vec());

        let mut garlic = GarlicHandler::<MockRuntime>::new(
            NoiseContext::new(remote_key.clone(), remote_router_id),
            MockRuntime::register_metrics(vec![], None),
        );

        // construct garlic message
        let message_id_1 = MessageId::from(MockRuntime::rng().next_u32());
        let message_id_2 = MessageId::from(MockRuntime::rng().next_u32());
        let message_id_3 = MessageId::from(MockRuntime::rng().next_u32());
        let message_id_4 = MessageId::from(MockRuntime::rng().next_u32());

        let router_delivery_router = RouterId::random();
        let tunnel_delivery_router = RouterId::random();
        let tunnel_delivery_tunnel = TunnelId::random();
        let destination_id = DestinationId::random();

        let mut message = GarlicMessageBuilder::default()
            .with_date_time(MockRuntime::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::Data,
                message_id_1,
                MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                CloveDeliveryInstructions::Local,
                &vec![1, 1, 1, 1],
            )
            .with_garlic_clove(
                MessageType::Data,
                message_id_2,
                MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                CloveDeliveryInstructions::Router {
                    hash: &router_delivery_router.to_vec(),
                },
                &vec![2, 2, 2, 2],
            )
            .with_garlic_clove(
                MessageType::Data,
                message_id_3,
                MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                CloveDeliveryInstructions::Tunnel {
                    hash: &tunnel_delivery_router.to_vec(),
                    tunnel_id: *tunnel_delivery_tunnel,
                },
                &vec![3, 3, 3, 3],
            )
            .with_garlic_clove(
                MessageType::Data,
                message_id_4,
                MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                CloveDeliveryInstructions::Destination {
                    hash: &destination_id.to_vec(),
                },
                &vec![4, 4, 4, 4],
            )
            .build();

        let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

        // derive outbound garlic context
        let local_noise = NoiseContext::new(local_key, local_router_id);
        let ephemeral_secret = EphemeralPrivateKey::random(rand::thread_rng());
        let ephemeral_public = ephemeral_secret.public();
        let (local_key, local_state) =
            local_noise.derive_outbound_garlic_key(remote_key.public(), ephemeral_secret);

        ChaChaPoly::new(&local_key)
            .encrypt_with_ad_new(&local_state, &mut message)
            .unwrap();

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        let message = Message {
            message_type: MessageType::Garlic,
            message_id: MockRuntime::rng().next_u32(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: out.to_vec(),
        };

        let mut blocks = garlic.handle_message(message).unwrap();

        match blocks.next().unwrap() {
            DeliveryInstructions::Local { message } => {
                assert_eq!(message.message_type, MessageType::Data);
                assert_eq!(message.message_id, *message_id_1);
                assert_eq!(message.payload, vec![1, 1, 1, 1]);
            }
            _ => panic!("invalid delivery type"),
        }

        match blocks.next().unwrap() {
            DeliveryInstructions::Router { router, message } => {
                assert_eq!(router, router_delivery_router);

                assert_eq!(message.message_type, MessageType::Data);
                assert_eq!(message.message_id, *message_id_2);
                assert_eq!(message.payload, vec![2, 2, 2, 2]);
            }
            _ => panic!("invalid delivery type"),
        }

        match blocks.next().unwrap() {
            DeliveryInstructions::Tunnel {
                tunnel,
                router,
                message,
            } => {
                assert_eq!(router, tunnel_delivery_router);
                assert_eq!(tunnel, tunnel_delivery_tunnel);

                assert_eq!(message.message_type, MessageType::TunnelGateway);

                let TunnelGateway { tunnel_id, payload } =
                    TunnelGateway::parse(&message.payload).unwrap();
                assert_eq!(tunnel_id, tunnel_delivery_tunnel);

                let message = Message::parse_standard(&payload).unwrap();
                assert_eq!(message.message_type, MessageType::Data);
                assert_eq!(message.message_id, *message_id_3);
                assert_eq!(message.payload, vec![3, 3, 3, 3]);
            }
            _ => panic!("invalid delivery type"),
        }
    }

    #[test]
    fn expired_garlic_clove() {
        let remote_key = StaticPrivateKey::random(rand::thread_rng());
        let remote_router_id = Bytes::from(RouterId::random().to_vec());

        let local_key = StaticPrivateKey::random(rand::thread_rng());
        let local_router_id = Bytes::from(RouterId::random().to_vec());

        let mut garlic = GarlicHandler::<MockRuntime>::new(
            NoiseContext::new(remote_key.clone(), remote_router_id),
            MockRuntime::register_metrics(vec![], None),
        );

        // construct garlic message
        let message_id_1 = MessageId::from(MockRuntime::rng().next_u32());
        let message_id_2 = MessageId::from(MockRuntime::rng().next_u32());

        let router_delivery_router = RouterId::random();

        let mut message = GarlicMessageBuilder::default()
            .with_date_time(MockRuntime::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::Data,
                message_id_1,
                MockRuntime::time_since_epoch() - Duration::from_secs(5),
                CloveDeliveryInstructions::Local,
                &vec![1, 1, 1, 1],
            )
            .with_garlic_clove(
                MessageType::Data,
                message_id_2,
                MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                CloveDeliveryInstructions::Router {
                    hash: &router_delivery_router.to_vec(),
                },
                &vec![2, 2, 2, 2],
            )
            .build();

        let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

        // derive outbound garlic context
        let local_noise = NoiseContext::new(local_key, local_router_id);
        let ephemeral_secret = EphemeralPrivateKey::random(rand::thread_rng());
        let ephemeral_public = ephemeral_secret.public();
        let (local_key, local_state) =
            local_noise.derive_outbound_garlic_key(remote_key.public(), ephemeral_secret);

        ChaChaPoly::new(&local_key)
            .encrypt_with_ad_new(&local_state, &mut message)
            .unwrap();

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        let message = Message {
            message_type: MessageType::Garlic,
            message_id: MockRuntime::rng().next_u32(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: out.to_vec(),
        };

        let mut blocks = garlic.handle_message(message).unwrap();

        match blocks.next().unwrap() {
            DeliveryInstructions::Router { router, message } => {
                assert_eq!(router, router_delivery_router);

                assert_eq!(message.message_type, MessageType::Data);
                assert_eq!(message.message_id, *message_id_2);
                assert_eq!(message.payload, vec![2, 2, 2, 2]);
            }
            _ => panic!("invalid delivery type"),
        }
        assert!(blocks.next().is_none());
    }
}
