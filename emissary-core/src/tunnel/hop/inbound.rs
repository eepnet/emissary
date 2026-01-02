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
        aes::{cbc, ecb},
        sha256::Sha256,
    },
    error::{RejectionReason, TunnelError},
    i2np::{
        tunnel::data::{DeliveryInstructions, EncryptedTunnelData, MessageKind, TunnelData},
        HopRole, Message,
    },
    primitives::{MessageId, RouterId, Str, TunnelId},
    runtime::Runtime,
    tunnel::{
        fragment::{FragmentHandler, OwnedDeliveryInstructions},
        hop::{ReceiverKind, Tunnel, TunnelDirection, TunnelHop},
        pool::TunnelPoolContextHandle,
        TUNNEL_EXPIRATION,
    },
    Error,
};

use futures::{future::BoxFuture, FutureExt};
use hashbrown::HashSet;
use thingbuf::mpsc::Receiver;

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    iter,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::ibep";

/// Inbound tunnel.
pub struct InboundTunnel<R: Runtime> {
    /// Tunnel expiration timer.
    expiration_timer: BoxFuture<'static, (TunnelId, TunnelId)>,

    /// Fragment handler.
    fragment: FragmentHandler<R>,

    /// Tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Tunnel hops.
    hops: Vec<TunnelHop>,

    /// RX channel for receiving messages.
    message_rx: Receiver<Message>,

    /// Name of the tunnel pool this tunnel belongs to.
    name: Str,

    /// Tunnel ID.
    tunnel_id: TunnelId,
}

impl<R: Runtime> InboundTunnel<R> {
    /// Get gateway information of the inbound tunnel.
    ///
    /// Returns a `(RouterId, TunnelId)` tuple, allowing OBEP to route the message correctly.
    pub fn gateway(&self) -> (RouterId, TunnelId) {
        // tunnel must exist since it was created by us
        let hop = &self.hops.first().expect("tunnel to exist");

        (hop.router.clone(), hop.tunnel_id)
    }

    fn find_payload_start(&self, ciphertext: &[u8], iv: &[u8]) -> crate::Result<usize> {
        let padding_end =
            ciphertext[4..].iter().enumerate().find(|(_, byte)| byte == &&0x0).ok_or_else(
                || {
                    tracing::warn!(
                        target: LOG_TARGET,
                        name = %self.name,
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
                name = %self.name,
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
                name = %self.name,
                tunnel_id = %self.tunnel_id,
                "decrypted tunnel data doesn't contain zero byte",
            );

            return Err(Error::Tunnel(TunnelError::InvalidMessage));
        }

        Ok(payload_start)
    }

    /// Handle tunnel data.
    pub fn handle_tunnel_data(
        &mut self,
        message: &Message,
    ) -> crate::Result<impl Iterator<Item = Message>> {
        let tunnel_data = EncryptedTunnelData::parse(&message.payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                name = %self.name,
                tunnel_id = %self.tunnel_id,
                message_id = %message.message_id,
                "malformed tunnel data message",
            );

            Error::InvalidData
        })?;

        tracing::trace!(
            target: LOG_TARGET,
            name = %self.name,
            tunnel = %self.tunnel_id,
            message_len = ?tunnel_data.ciphertext().len(),
            "tunnel data",
        );

        // iterative decrypt the tunnel data message and aes iv
        let iv = tunnel_data.iv().to_vec();
        let ciphertext = tunnel_data.ciphertext().to_vec();

        let (iv, ciphertext) =
            self.hops.iter().rev().fold((iv, ciphertext), |(iv, message), hop| {
                let mut aes = ecb::Aes::new_decryptor(hop.key_context.iv_key());
                let iv = aes.decrypt(&iv);

                let mut aes = cbc::Aes::new_decryptor(hop.key_context.layer_key(), &iv);
                let ciphertext = aes.decrypt(message);

                let mut aes = ecb::Aes::new_decryptor(hop.key_context.iv_key());
                let iv = aes.decrypt(iv);

                (iv, ciphertext)
            });

        // find where the payload starts and verify the checksum
        let payload_start = self.find_payload_start(&ciphertext, &iv)?;

        // parse messages and fragments and return an iterator of ready messages
        let messages = TunnelData::parse(&ciphertext[payload_start..])
            .map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    name = %self.name,
                    tunnel_id = %self.tunnel_id,
                    ?error,
                    "malformed tunnel data message",
                );

                Error::Tunnel(TunnelError::InvalidMessage)
            })?
            .messages
            .into_iter()
            .filter_map(|message| {
                if let MessageKind::Unfragmented {
                    delivery_instructions,
                } = message.message_kind
                {
                    match delivery_instructions {
                        DeliveryInstructions::Local =>
                            return Message::parse_standard(message.message)
                                .inspect_err(|error| {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        name = %self.name,
                                        tunnel = %self.tunnel_id,
                                        ?error,
                                        "invalid i2np message",
                                    );
                                })
                                .ok(),
                        delivery_instructions => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                name = %self.name,
                                tunnel = %self.tunnel_id,
                                ?delivery_instructions,
                                "unsupported delivery instructions",
                            );
                            return None;
                        }
                    }
                }

                let (message, delivery_instructions) = match message.message_kind {
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
                    MessageKind::Unfragmented { .. } => unreachable!(),
                };

                match delivery_instructions {
                    OwnedDeliveryInstructions::Local => Some(message),
                    delivery_instructions => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            name = %self.name,
                            tunnel = %self.tunnel_id,
                            ?delivery_instructions,
                            "unsupported delivery instructions",
                        );
                        None
                    }
                }
            })
            .collect::<Vec<Message>>();

        Ok(messages.into_iter())
    }
}

impl<R: Runtime> Tunnel for InboundTunnel<R> {
    fn new(name: Str, tunnel_id: TunnelId, receiver: ReceiverKind, hops: Vec<TunnelHop>) -> Self {
        let (message_rx, handle) = receiver.inbound();

        // hop must exist since it was created by us
        let gateway_tunnel_id = hops.first().expect("hop to exist").tunnel_id;

        InboundTunnel {
            expiration_timer: Box::pin(async move {
                R::delay(TUNNEL_EXPIRATION).await;
                (tunnel_id, gateway_tunnel_id)
            }),
            fragment: FragmentHandler::new(),
            handle,
            hops,
            message_rx,
            name,
            tunnel_id,
        }
    }

    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole> {
        iter::once(HopRole::InboundGateway)
            .chain((0..num_hops.get() - 1).map(|_| HopRole::Participant))
    }

    fn direction() -> TunnelDirection {
        TunnelDirection::Inbound
    }

    fn tunnel_id(&self) -> &TunnelId {
        &self.tunnel_id
    }

    fn hops(&self) -> HashSet<RouterId> {
        self.hops.iter().map(|hop| hop.router.clone()).collect()
    }
}

impl<R: Runtime> Future for InboundTunnel<R> {
    type Output = (TunnelId, TunnelId);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        name = %self.name,
                        tunnel_id = %self.tunnel_id,
                        "message channel closed",
                    );
                    return Poll::Ready((self.tunnel_id, self.gateway().1));
                }
                Some(message) => match self.handle_tunnel_data(&message) {
                    Err(error) => tracing::warn!(
                        target: LOG_TARGET,
                        name = %self.name,
                        tunnel = %self.tunnel_id,
                        ?error,
                        "failed to handle tunnel data",
                    ),
                    Ok(messages) => messages.for_each(|message| {
                        if let Err(error) = self.handle.route_message(message) {
                            tracing::debug!(
                                target: LOG_TARGET,
                                name = %self.name,
                                tunnel = %self.tunnel_id,
                                ?error,
                                "failed to route message",
                            );
                        }
                    }),
                },
            }
        }

        // poll fragment handler
        //
        // the futures don't return anything but must be polled so they make progress
        let _ = self.fragment.poll_unpin(cx);

        self.expiration_timer.poll_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::{tunnel::gateway::TunnelGateway, MessageBuilder, MessageType},
        runtime::{mock::MockRuntime, Runtime},
        subsystem::OutboundMessage,
        tunnel::tests::{build_inbound_tunnel, connect_routers},
    };
    use core::time::Duration;
    use rand_core::RngCore;

    #[test]
    fn hop_roles() {
        assert_eq!(
            InboundTunnel::<MockRuntime>::hop_roles(NonZeroUsize::new(1).unwrap())
                .collect::<Vec<_>>(),
            vec![HopRole::InboundGateway]
        );

        assert_eq!(
            InboundTunnel::<MockRuntime>::hop_roles(NonZeroUsize::new(3).unwrap())
                .collect::<Vec<_>>(),
            vec![
                HopRole::InboundGateway,
                HopRole::Participant,
                HopRole::Participant,
            ]
        );
    }

    #[tokio::test]
    async fn fragment_reception_works() {
        let (local_hash, mut tunnel, mut hops) = build_inbound_tunnel(true, 3usize);
        let local_router_id = RouterId::from(local_hash);
        let original = (0..3 * 1028usize).map(|i| (i % 256) as u8).collect::<Vec<_>>();

        // connect all transit routers together
        connect_routers(hops.iter_mut());
        hops[2].connect_router(&local_router_id);

        let message = MessageBuilder::standard()
            .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(8))
            .with_message_type(MessageType::Data)
            .with_message_id(MessageId::from(MockRuntime::rng().next_u32()))
            .with_payload(&original)
            .build();

        let message = TunnelGateway {
            tunnel_id: tunnel.gateway().1,
            payload: &message,
        }
        .serialize();

        let message = Message {
            message_type: MessageType::TunnelGateway,
            message_id: MockRuntime::rng().next_u32(),
            expiration: MockRuntime::time_since_epoch() + Duration::from_secs(8),
            payload: message,
        };

        // 1st hop (ibgw)
        let messages = {
            let _ = hops[0].routing_table().send_message(hops[0].router(), message).unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(1), &mut hops[0]).await.is_err());

            let mut messages = vec![];
            let rx = hops[0].router_rx(&hops[1].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push((hops[1].router(), message));
            }

            messages
        };
        assert_eq!(messages.len(), 4);

        // 2nd hop (participant)
        let messages = {
            for (router, message) in messages {
                assert_eq!(router, RouterId::from(hops[1].router_hash()));

                let _ = hops[1].routing_table().send_message(hops[1].router(), message).unwrap();
            }
            assert!(tokio::time::timeout(Duration::from_secs(1), &mut hops[1]).await.is_err());

            let mut messages = vec![];
            let rx = hops[1].router_rx(&hops[2].router()).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push((hops[2].router(), message));
            }

            messages
        };
        assert_eq!(messages.len(), 4);

        // 3rd hop (participant)
        let messages = {
            for (router, message) in messages {
                assert_eq!(router, RouterId::from(hops[2].router_hash()));

                let _ = hops[2].routing_table().send_message(hops[2].router(), message).unwrap();
            }
            assert!(tokio::time::timeout(Duration::from_secs(1), &mut hops[2]).await.is_err());

            let mut messages = vec![];
            let rx = hops[2].router_rx(&local_router_id).unwrap();

            while let Ok(OutboundMessage::Message(message)) = rx.try_recv() {
                messages.push((local_router_id.clone(), message));
            }

            messages
        };
        assert_eq!(messages.len(), 4);

        let messages = messages.into_iter().map(|(_, message)| message).collect::<Vec<_>>();

        assert_eq!(tunnel.handle_tunnel_data(&messages[0]).unwrap().count(), 0);
        assert_eq!(tunnel.handle_tunnel_data(&messages[1]).unwrap().count(), 0);
        assert_eq!(tunnel.handle_tunnel_data(&messages[2]).unwrap().count(), 0);

        let Message {
            message_type: MessageType::Data,
            payload,
            ..
        } = tunnel.handle_tunnel_data(&messages[3]).unwrap().next().unwrap()
        else {
            panic!("invalid message");
        };

        assert_eq!(payload, original);
    }
}
