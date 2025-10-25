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
    config::TransitConfig,
    crypto::{chachapoly::ChaChaPoly, EphemeralPublicKey},
    error::TunnelError,
    events::EventHandle,
    i2np::{
        garlic::{DeliveryInstructions, GarlicMessage, GarlicMessageBuilder},
        tunnel::{
            build::{short, variable},
            gateway::TunnelGateway,
        },
        HopRole, Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    primitives::{RouterId, TunnelId},
    router::context::RouterContext,
    runtime::{Counter, Gauge, JoinSet, MetricsHandle, Runtime},
    shutdown::ShutdownHandle,
    tunnel::{
        metrics::*,
        noise::TunnelKeys,
        routing_table::RoutingTable,
        transit::{inbound::InboundGateway, outbound::OutboundEndpoint, participant::Participant},
    },
    Error,
};

use bytes::{BufMut, BytesMut};
use futures::{
    future::{select, Either},
    FutureExt, StreamExt,
};
use futures_channel::oneshot;
use thingbuf::mpsc::Receiver;

use alloc::{string::ToString, vec::Vec};
use core::{
    future::Future,
    ops::{Range, RangeFrom},
    pin::{pin, Pin},
    task::{Context, Poll},
    time::Duration,
};

mod inbound;
mod outbound;
mod participant;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit";

/// Short tunnel build request record size.
const SHORT_RECORD_LEN: usize = 218;

/// Variable tunnel build request record size.
const VARIABLE_RECORD_LEN: usize = 528;

/// Public key offset in the build request record.
const PUBLIC_KEY_OFFSET: Range<usize> = 16..48;

/// Start offset for the build request record payload.
const RECORD_START_OFFSET: RangeFrom<usize> = 48..;

/// Transit tunnel channel size.
const TUNNEL_CHANNEL_SIZE: usize = 64usize;

/// Transit tunnel expiration.
///
/// Tunnels expire in 10 minutes but the expiration timer for transit tunnels are started as soon as
/// the tunnel build requets is accepted. Tunnel creator might not start the timer quite as soon
/// which could result in tunnel messages getting dropped towards the end of the tunnel's life time.
///
/// In order to prevent this from happening, increase the transit tunnel expiration by an additional
/// 20 seconds to allow remaining traffic pass through the tunnel before it is destroyed.
const TRANSIT_TUNNEL_EXPIRATION: Duration = Duration::from_secs(10 * 60 + 20);

/// Common interface for transit tunnels.
pub trait TransitTunnel<R: Runtime>: Future<Output = TunnelId> + Send {
    /// Create new [`TransitTunnel`].
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
        event_handle: EventHandle<R>,
    ) -> Self;
}

/// Transit tunnel manager.
pub struct TransitTunnelManager<R: Runtime> {
    /// Transit configuration.
    config: Option<TransitConfig>,

    /// Event handle.
    event_handle: EventHandle<R>,

    /// RX channel for receiving messages from `TunnelManager`.
    message_rx: Receiver<Message>,

    /// Router context.
    router_ctx: RouterContext<R>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Shutdown handle.
    shutdown_handle: ShutdownHandle,

    /// Active transit tunnels.
    tunnels: R::JoinSet<Result<TunnelId, TunnelId>>,
}

impl<R: Runtime> TransitTunnelManager<R> {
    /// Create new [`TransitTunnelManager`].
    pub fn new(
        config: Option<TransitConfig>,
        router_ctx: RouterContext<R>,
        routing_table: RoutingTable,
        message_rx: Receiver<Message>,
        shutdown_handle: ShutdownHandle,
    ) -> Self {
        match &config {
            Some(TransitConfig { max_tunnels }) => tracing::info!(
                target: LOG_TARGET,
                max_tunnels = %max_tunnels.map_or(
                    "unlimited".to_string(),
                    |max_tunnels| max_tunnels.to_string(),
                ),
                "starting transit tunnel manager",
            ),
            None => tracing::info!(
                target: LOG_TARGET,
                "starting transit tunnel manager, transit tunnels disabled",
            ),
        }

        Self {
            config,
            event_handle: router_ctx.event_handle().clone(),
            message_rx,
            router_ctx,
            routing_table,
            shutdown_handle,
            tunnels: R::join_set(),
        }
    }

    /// Check if a transit tunnel can be accepted.
    ///
    /// If the router is shutting down, all transit tunnels are rejected.
    ///
    /// If router is active but transit tunnels have either been disabled completely or the router
    /// already has a maximum amount of transit tunnels, the new transit tunnel is rejected.
    fn can_accept_transit_tunnel(&self) -> bool {
        if self.shutdown_handle.is_shutting_down() {
            tracing::debug!(
                target: LOG_TARGET,
                num_tunnels = ?self.tunnels.len(),
                "router is shutting down, cannot accept transit tunnel",
            );
            return false;
        }

        let Some(config) = &self.config else {
            tracing::trace!(
                target: LOG_TARGET,
                "transit tunnels have been disabled, cannot accept transit tunnel",
            );
            return false;
        };

        match config.max_tunnels {
            Some(max_tunnels) if max_tunnels <= self.tunnels.len() => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?max_tunnels,
                    num_tunnels = ?self.tunnels.len(),
                    "number of transit tunnels already at maximum, cannot accept transit tunnel",
                );
                false
            }
            _ => true,
        }
    }

    /// Return mutable reference to local build record and its index in the build request message.
    fn find_local_record<'a, const RECORD_SIZE: usize>(
        &self,
        payload: &'a mut [u8],
    ) -> Option<(usize, &'a mut [u8])> {
        (payload.len() > RECORD_SIZE && (payload.len() - 1).is_multiple_of(RECORD_SIZE))
            .then(|| {
                payload[1..].chunks_mut(RECORD_SIZE).enumerate().find(|(_, chunk)| {
                    chunk[..16] == self.router_ctx.noise().local_router_hash()[..16]
                })
            })
            .flatten()
    }

    /// Handle variable tunnel build request.
    pub fn handle_variable_tunnel_build(
        &mut self,
        message: Message,
    ) -> crate::Result<(RouterId, Vec<u8>, Option<oneshot::Sender<()>>)> {
        let Message {
            message_id,
            expiration,
            mut payload,
            ..
        } = message;

        let (_, record) = self
            .find_local_record::<VARIABLE_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self.router_ctx.noise().create_long_inbound_session(
            EphemeralPublicKey::from_bytes(&record[PUBLIC_KEY_OFFSET]).ok_or(Error::InvalidData)?,
        );
        let decrypted_record =
            session.decrypt_build_record(record[RECORD_START_OFFSET].to_vec())?;

        let build_record =
            variable::TunnelBuildRecord::parse(&decrypted_record).map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_id,
                    ?error,
                    "malformed variable tunnel build request",
                );

                Error::InvalidData
            })?;

        let role = build_record.role();
        let tunnel_id = build_record.tunnel_id();
        let next_tunnel_id = build_record.next_tunnel_id();
        let next_message_id = build_record.next_message_id();
        let next_router = build_record.next_router();

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            %tunnel_id,
            %next_router,
            "variable tunnel build request",
        );

        // check if the tunnel can be accepted
        //
        // if the router is active and capable of accepting a transit tunnel, check if a new
        // receiver can be added to routing table and if so, create new receiver for the transit
        // tunnel and add it to routing table
        //
        // NOTE: currently only OBEPs are supported because tunnel context (used to encrypt the
        // records) doesn't have aes-cbc support
        let maybe_receiver = if self.can_accept_transit_tunnel()
            && core::matches!(role, HopRole::OutboundEndpoint)
        {
            match self.routing_table.try_add_tunnel::<TUNNEL_CHANNEL_SIZE>(tunnel_id) {
                Ok(receiver) => Some(receiver),
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        ?error,
                        "tunnel already exists in routing table, rejecting",
                    );
                    None
                }
            }
        } else {
            None
        };

        let maybe_feedback_tx = match maybe_receiver {
            None => {
                self.router_ctx
                    .metrics_handle()
                    .counter(NUM_TRANSIT_TUNNELS_REJECTED)
                    .increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[511] = 30; // reject

                session.encrypt_build_record(record)?;

                None
            }
            Some(receiver) => {
                self.router_ctx
                    .metrics_handle()
                    .counter(NUM_TRANSIT_TUNNELS_ACCEPTED)
                    .increment(1);
                self.router_ctx.metrics_handle().gauge(NUM_TRANSIT_TUNNELS).increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[511] = 0x00; // accept

                session.encrypt_build_record(record)?;

                // start tunnel event loop
                //
                // an accepted tunnel must be maintained for 10 minutes as we won't know
                // if another participant of the tunnel rejected it
                //
                // the tunnel build reply is sent with a feedback tx to `TunnelManager` and if we're
                // unable to dial the next hop, `TunnelManager` will drop the feedabck tx which the
                // transit tunnel start will catch and exit from the event loop
                //
                // this allows detecting transit tunnel failures that originate from our router and
                // prevent these inactive transit tunnels from consuming available transit tunnels
                // slots
                let routing_table = self.routing_table.clone();
                let metrics = self.router_ctx.metrics_handle().clone();
                let next_router_id = next_router.clone();
                let tunnel_keys = session.finalize(
                    build_record.tunnel_layer_key().to_vec(),
                    build_record.tunnel_iv_key().to_vec(),
                )?;
                let (tx, rx) = oneshot::channel::<()>();
                let event_handle = self.router_ctx.event_handle().clone();

                match role {
                    HopRole::InboundGateway => self.tunnels.push(async move {
                        match select(rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                            Either::Left((Ok(_), _)) => {}
                            Either::Left((Err(_), _)) => return Err(tunnel_id),
                            Either::Right(_) => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %tunnel_id,
                                    "failed to receive dial result after 2 minutes",
                                );
                                debug_assert!(false);
                                return Err(tunnel_id);
                            }
                        }

                        Ok(InboundGateway::<R>::new(
                            tunnel_id,
                            next_tunnel_id,
                            next_router_id,
                            tunnel_keys,
                            routing_table,
                            metrics,
                            receiver,
                            event_handle,
                        )
                        .await)
                    }),
                    HopRole::Participant => self.tunnels.push(async move {
                        match select(rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                            Either::Left((Ok(_), _)) => {}
                            Either::Left((Err(_), _)) => return Err(tunnel_id),
                            Either::Right(_) => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %tunnel_id,
                                    "failed to receive dial result after 2 minutes",
                                );
                                debug_assert!(false);
                                return Err(tunnel_id);
                            }
                        }

                        Ok(Participant::<R>::new(
                            tunnel_id,
                            next_tunnel_id,
                            next_router_id,
                            tunnel_keys,
                            routing_table,
                            metrics,
                            receiver,
                            event_handle,
                        )
                        .await)
                    }),
                    HopRole::OutboundEndpoint => self.tunnels.push(async move {
                        match select(rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                            Either::Left((Ok(_), _)) => {}
                            Either::Left((Err(_), _)) => return Err(tunnel_id),
                            Either::Right(_) => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %tunnel_id,
                                    "failed to receive dial result after 2 minutes",
                                );
                                debug_assert!(false);
                                return Err(tunnel_id);
                            }
                        }

                        Ok(OutboundEndpoint::<R>::new(
                            tunnel_id,
                            next_tunnel_id,
                            next_router_id,
                            tunnel_keys,
                            routing_table,
                            metrics,
                            receiver,
                            event_handle,
                        )
                        .await)
                    }),
                }

                Some(tx)
            }
        };

        match role {
            HopRole::InboundGateway | HopRole::Participant => {
                let message = MessageBuilder::short()
                    .with_message_type(MessageType::VariableTunnelBuild)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&payload)
                    .build();

                Ok((next_router, message, maybe_feedback_tx))
            }
            HopRole::OutboundEndpoint => {
                let message = MessageBuilder::standard()
                    .with_message_type(MessageType::VariableTunnelBuildReply)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&payload)
                    .build();

                let msg = TunnelGateway {
                    tunnel_id: next_tunnel_id,
                    payload: &message,
                }
                .serialize();

                let message = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&msg)
                    .build();

                Ok((next_router, message, maybe_feedback_tx))
            }
        }
    }

    /// Handle short tunnel build request.
    pub fn handle_short_tunnel_build(
        &mut self,
        message: Message,
    ) -> crate::Result<(RouterId, Vec<u8>, Option<oneshot::Sender<()>>)> {
        let Message {
            message_id,
            expiration,
            mut payload,
            ..
        } = message;

        let (record_idx, record) = self
            .find_local_record::<SHORT_RECORD_LEN>(&mut payload)
            .ok_or(Error::Tunnel(TunnelError::RecordNotFound))?;

        let mut session = self.router_ctx.noise().create_short_inbound_session(
            EphemeralPublicKey::from_bytes(&record[PUBLIC_KEY_OFFSET]).ok_or(Error::InvalidData)?,
        );
        let decrypted_record =
            session.decrypt_build_record(record[RECORD_START_OFFSET].to_vec())?;

        let build_record = short::TunnelBuildRecord::parse(&decrypted_record).map_err(|error| {
            tracing::debug!(
                target: LOG_TARGET,
                ?message_id,
                ?error,
                "malformed short tunnel build request",
            );

            Error::InvalidData
        })?;

        let role = build_record.role();
        let tunnel_id = build_record.tunnel_id();
        let next_tunnel_id = build_record.next_tunnel_id();
        let next_message_id = build_record.next_message_id();
        let next_router = build_record.next_router();

        tracing::trace!(
            target: LOG_TARGET,
            ?role,
            %tunnel_id,
            %next_router,
            "short tunnel build request",
        );

        // check if the tunnel can be accepted
        //
        // if the router is active and capable of accepting a transit tunnel, check if a new
        // receiver can be added to routing table and if so, create new receiver for the transit
        // tunnel and add it to routing table
        let maybe_receiver = match self.can_accept_transit_tunnel() {
            false => None,
            true => match self.routing_table.try_add_tunnel::<TUNNEL_CHANNEL_SIZE>(tunnel_id) {
                Ok(receiver) => Some(receiver),
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        ?error,
                        "tunnel already exists in routing table, rejecting",
                    );
                    None
                }
            },
        };

        // create tunnel build reply, either accept or reject, depending on whether the tunnel could
        // be accepted or not
        //
        // if assigned role is OBEP, generate keys for garlic-encrypting the TBRM
        //
        // if the tunnel is accepted, an event loop for the tunnel is started right away since we
        // won't know if another participant of the tunnel rejected the tunnel or not
        let (garlic_key, garlic_tag, maybe_feedback_tx) = match maybe_receiver {
            None => {
                self.router_ctx
                    .metrics_handle()
                    .counter(NUM_TRANSIT_TUNNELS_REJECTED)
                    .increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[201] = 30; // reject

                session.create_tunnel_keys(role)?;
                session.encrypt_build_records(&mut payload, record_idx)?;

                match role {
                    HopRole::OutboundEndpoint => {
                        let tunnel_keys = session.finalize()?;

                        (
                            Some(tunnel_keys.garlic_key()),
                            Some(tunnel_keys.garlic_tag()),
                            None,
                        )
                    }
                    _ => (None, None, None),
                }
            }
            Some(receiver) => {
                self.router_ctx
                    .metrics_handle()
                    .counter(NUM_TRANSIT_TUNNELS_ACCEPTED)
                    .increment(1);
                self.router_ctx.metrics_handle().gauge(NUM_TRANSIT_TUNNELS).increment(1);

                record[48] = 0x00; // no options
                record[49] = 0x00;
                record[201] = 0x00; // accept

                session.create_tunnel_keys(role)?;
                session.encrypt_build_records(&mut payload, record_idx)?;

                // start tunnel event loop
                //
                // an accepted tunnel must be maintained for 10 minutes as we won't know
                // if another participant of the tunnel rejected it
                //
                // the tunnel build reply is sent with a feedback tx to `TunnelManager` and if we're
                // unable to dial the next hop, `TunnelManager` will drop the feedabck tx which the
                // transit tunnel start will catch and exit from the event loop
                //
                // this allows detecting transit tunnel failures that originate from our router and
                // prevent these inactive transit tunnels from consuming available transit tunnels
                // slots
                let routing_table = self.routing_table.clone();
                let metrics = self.router_ctx.metrics_handle().clone();
                let next_router_id = next_router.clone();
                let tunnel_keys = session.finalize()?;
                let (tx, rx) = oneshot::channel::<()>();
                let event_handle = self.router_ctx.event_handle().clone();

                match role {
                    HopRole::InboundGateway => {
                        self.tunnels.push(async move {
                            match select(rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                                Either::Left((Ok(_), _)) => {}
                                Either::Left((Err(_), _)) => return Err(tunnel_id),
                                Either::Right(_) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %tunnel_id,
                                        "failed to receive dial result after 2 minutes",
                                    );
                                    debug_assert!(false);
                                    return Err(tunnel_id);
                                }
                            }

                            Ok(InboundGateway::<R>::new(
                                tunnel_id,
                                next_tunnel_id,
                                next_router_id,
                                tunnel_keys,
                                routing_table,
                                metrics,
                                receiver,
                                event_handle,
                            )
                            .await)
                        });

                        (None, None, Some(tx))
                    }
                    HopRole::Participant => {
                        self.tunnels.push(async move {
                            match select(rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                                Either::Left((Ok(_), _)) => {}
                                Either::Left((Err(_), _)) => return Err(tunnel_id),
                                Either::Right(_) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %tunnel_id,
                                        "failed to receive dial result after 2 minutes",
                                    );
                                    debug_assert!(false);
                                    return Err(tunnel_id);
                                }
                            }

                            Ok(Participant::<R>::new(
                                tunnel_id,
                                next_tunnel_id,
                                next_router_id,
                                tunnel_keys,
                                routing_table,
                                metrics,
                                receiver,
                                event_handle,
                            )
                            .await)
                        });

                        (None, None, Some(tx))
                    }
                    HopRole::OutboundEndpoint => {
                        let garlic_key = tunnel_keys.garlic_key();
                        let garlic_tag = tunnel_keys.garlic_tag();

                        self.tunnels.push(async move {
                            match select(rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                                Either::Left((Ok(_), _)) => {}
                                Either::Left((Err(_), _)) => return Err(tunnel_id),
                                Either::Right(_) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %tunnel_id,
                                        "failed to receive dial result after 2 minutes",
                                    );
                                    debug_assert!(false);
                                    return Err(tunnel_id);
                                }
                            }

                            Ok(OutboundEndpoint::<R>::new(
                                tunnel_id,
                                next_tunnel_id,
                                next_router_id,
                                tunnel_keys,
                                routing_table,
                                metrics,
                                receiver,
                                event_handle,
                            )
                            .await)
                        });

                        (Some(garlic_key), Some(garlic_tag), Some(tx))
                    }
                }
            }
        };

        match role {
            // IBGWs and participants just forward the build request as-is to the next hop
            HopRole::InboundGateway | HopRole::Participant => {
                let msg = MessageBuilder::short()
                    .with_message_type(MessageType::ShortTunnelBuild)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&payload)
                    .build();

                Ok((next_router, msg, maybe_feedback_tx))
            }
            // OBEP wraps the `OutboundBuildTunnelReply` in a `TunnelGateway` in order for
            // the recipient IBGW to be able to forward the tunnel build reply correctly
            HopRole::OutboundEndpoint => {
                // garlic tag and key must exist since this is a response for an OBEP
                let garlic_key = garlic_key.expect("to exist");
                let garlic_tag = garlic_tag.expect("to exist");

                let mut message = GarlicMessageBuilder::default()
                    .with_garlic_clove(
                        MessageType::OutboundTunnelBuildReply,
                        next_message_id,
                        R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                        DeliveryInstructions::Local,
                        &payload,
                    )
                    .with_date_time(R::time_since_epoch().as_secs() as u32)
                    .build();

                // message length + poly13055 tag + garlic tag + garlic message length
                let mut out = BytesMut::with_capacity(message.len() + 16 + 8 + 4);

                // encryption must succeed since the parameters are managed by us
                ChaChaPoly::new(&garlic_key)
                    .encrypt_with_ad_new(&garlic_tag, &mut message)
                    .expect("to succeed");

                out.put_u32(message.len() as u32 + 8);
                out.put_slice(&garlic_tag);
                out.put_slice(&message);

                let message = MessageBuilder::standard()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(MessageType::Garlic)
                    .with_message_id(next_message_id)
                    .with_payload(&out)
                    .build();

                let msg = TunnelGateway {
                    tunnel_id: next_tunnel_id,
                    payload: &message,
                }
                .serialize();

                let message = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(next_message_id)
                    .with_expiration(expiration)
                    .with_payload(&msg)
                    .build();

                Ok((next_router, message, maybe_feedback_tx))
            }
        }
    }
}

impl<R: Runtime> Future for TransitTunnelManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            let result = match event {
                None => return Poll::Ready(()),
                Some(message) => match message.message_type {
                    MessageType::ShortTunnelBuild => self.handle_short_tunnel_build(message),
                    MessageType::VariableTunnelBuild => self.handle_variable_tunnel_build(message),
                    MessageType::Garlic => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            parsed = ?GarlicMessage::parse(&message.payload[..12]),
                            "garlic message received to obep",
                        );
                        continue;
                    }
                    message_type => {
                        tracing::warn!(?message_type, "unsupported message type");
                        continue;
                    }
                },
            };

            match result {
                Ok((router, message, maybe_feedback_tx)) => match maybe_feedback_tx {
                    None =>
                        if let Err(error) = self.routing_table.send_message(router, message) {
                            tracing::error!(target: LOG_TARGET, ?error, "failed to send message");
                        },
                    Some(tx) => {
                        if let Err(error) = self.routing_table.send_message_with_feedback(
                            router.clone(),
                            message,
                            tx,
                        ) {
                            tracing::error!(target: LOG_TARGET, ?error, "failed to send message");
                        }
                    }
                },
                Err(error) => tracing::debug!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to handle message",
                ),
            }
        }

        if self.shutdown_handle.poll_unpin(cx).is_ready() {
            tracing::info!(
                target: LOG_TARGET,
                "graceful shutdown requested",
            );

            if self.tunnels.is_empty() {
                self.shutdown_handle.shutdown();
                return Poll::Ready(());
            } else {
                tracing::info!(
                    target: LOG_TARGET,
                    num_tunnels = ?self.tunnels.len(),
                    "waiting for transit tunnels to expire",
                );
            }
        }

        while let Poll::Ready(event) = self.tunnels.poll_next_unpin(cx) {
            let Some(result) = event else {
                return Poll::Ready(());
            };

            let tunnel_id = match result {
                Ok(tunnel_id) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "transit tunnel expired",
                    );

                    tunnel_id
                }
                Err(tunnel_id) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %tunnel_id,
                        "failed to dial next hop, unable to start transit tunnel",
                    );

                    tunnel_id
                }
            };

            self.routing_table.remove_tunnel(&tunnel_id);
            self.router_ctx.metrics_handle().gauge(NUM_TRANSIT_TUNNELS).decrement(1);

            if self.tunnels.is_empty() && self.shutdown_handle.is_shutting_down() {
                tracing::info!(
                    target: LOG_TARGET,
                    "shutting down",
                );
                self.shutdown_handle.shutdown();
                return Poll::Ready(());
            }
        }

        if self.event_handle.poll_unpin(cx).is_ready() {
            self.router_ctx.event_handle().num_transit_tunnels(self.tunnels.len());
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{StaticPrivateKey, StaticPublicKey},
        events::EventManager,
        primitives::{MessageId, Str},
        profile::ProfileStorage,
        runtime::mock::MockRuntime,
        shutdown::ShutdownContext,
        tunnel::{
            garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler},
            hop::{
                inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel,
                ReceiverKind, TunnelBuildParameters, TunnelInfo,
            },
            pool::TunnelPoolBuildParameters,
            routing_table::RoutingKindRecycle,
            tests::make_router,
        },
    };
    use bytes::Bytes;
    use rand_core::RngCore;
    use thingbuf::mpsc::{channel, with_recycle};

    #[tokio::test]
    async fn accept_tunnel_build_request_participant() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, _noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        TransitTunnelManager::new(
                            Some(TransitConfig {
                                max_tunnels: Some(5000),
                            }),
                            RouterContext::new(
                                handle.clone(),
                                ProfileStorage::new(&[], &[]),
                                router_info.identity.id(),
                                Bytes::from(router_info.serialize(&signing_key)),
                                static_key,
                                signing_key,
                                2u8,
                                event_handle.clone(),
                            ),
                            routing_table,
                            transit_rx,
                            shutdown_handle,
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert!(transit_managers[0].handle_short_tunnel_build(message).is_ok());
    }

    #[tokio::test]
    async fn accept_tunnel_build_request_ibgw() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<(
                GarlicHandler<MockRuntime>,
                TransitTunnelManager<MockRuntime>,
            )>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        (
                            GarlicHandler::new(noise_context.clone(), handle.clone()),
                            TransitTunnelManager::new(
                                Some(TransitConfig {
                                    max_tunnels: Some(5000),
                                }),
                                RouterContext::new(
                                    handle.clone(),
                                    ProfileStorage::new(&[], &[]),
                                    router_info.identity.id(),
                                    Bytes::from(router_info.serialize(&signing_key)),
                                    static_key,
                                    signing_key,
                                    2u8,
                                    event_handle.clone(),
                                ),
                                routing_table,
                                transit_rx,
                                shutdown_handle,
                            ),
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let TunnelPoolBuildParameters {
            context_handle: handle,
            ..
        } = TunnelPoolBuildParameters::new(Default::default());
        let (_tx, rx) = channel(64);
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<InboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Inbound {
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Inbound {
                        message_rx: rx,
                        handle,
                    },
                },
            )
            .unwrap();

        let message = match transit_managers[0].0.handle_message(message).unwrap().next() {
            Some(GarlicDeliveryInstructions::Local { message }) => message,
            _ => panic!("invalid delivery instructions"),
        };

        assert!(transit_managers[0].1.handle_short_tunnel_build(message).is_ok());
    }

    #[tokio::test]
    async fn accept_tunnel_build_request_obep() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, _noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        TransitTunnelManager::new(
                            Some(TransitConfig {
                                max_tunnels: Some(5000),
                            }),
                            RouterContext::new(
                                handle.clone(),
                                ProfileStorage::new(&[], &[]),
                                router_info.identity.id(),
                                Bytes::from(router_info.serialize(&signing_key)),
                                static_key,
                                signing_key,
                                2u8,
                                event_handle.clone(),
                            ),
                            routing_table,
                            transit_rx,
                            shutdown_handle,
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg, _) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg, _) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        pending_tunnel.try_build_tunnel(message).unwrap();
    }

    #[tokio::test]
    async fn local_record_not_found() {
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let handle = MockRuntime::register_metrics(vec![], None);
        let (hops, _transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, _noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        TransitTunnelManager::new(
                            Some(TransitConfig {
                                max_tunnels: Some(5000),
                            }),
                            RouterContext::new(
                                handle.clone(),
                                ProfileStorage::new(&[], &[]),
                                router_info.identity.id(),
                                Bytes::from(router_info.serialize(&signing_key)),
                                static_key,
                                signing_key,
                                2u8,
                                event_handle.clone(),
                            ),
                            routing_table,
                            transit_rx,
                            shutdown_handle,
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash.clone(),
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        // make new router which is not part of the tunnel build request
        let (_, static_key, signing_key, _noise, router_info) = make_router(true);
        let (transit_tx, transit_rx) = channel(16);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table = RoutingTable::new(RouterId::from(&local_hash), manager_tx, transit_tx);
        let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
        let shutdown_handle = shutdown_ctx.handle();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let mut transit_manager = TransitTunnelManager::<MockRuntime>::new(
            None,
            RouterContext::new(
                handle.clone(),
                ProfileStorage::new(&[], &[]),
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            routing_table,
            transit_rx,
            shutdown_handle,
        );

        match transit_manager.handle_short_tunnel_build(message).unwrap_err() {
            Error::Tunnel(TunnelError::RecordNotFound) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_public_key_used() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (mut hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(|(router_hash, static_key, signing_key, _, router_info)| {
                let (transit_tx, transit_rx) = channel(16);
                let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                let shutdown_handle = shutdown_ctx.handle();
                let routing_table =
                    RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                (
                    (router_hash, static_key.public(), shutdown_ctx),
                    TransitTunnelManager::new(
                        Some(TransitConfig {
                            max_tunnels: Some(5000),
                        }),
                        RouterContext::new(
                            handle.clone(),
                            ProfileStorage::new(&[], &[]),
                            router_info.identity.id(),
                            Bytes::from(router_info.serialize(&signing_key)),
                            static_key,
                            signing_key,
                            2u8,
                            event_handle.clone(),
                        ),
                        routing_table,
                        transit_rx,
                        shutdown_handle,
                    ),
                )
            })
            .unzip();

        let (local_hash, _local_pk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        // replace the first hop's public key with a random public key
        let new_pubkey = {
            let mut key_bytes = [0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);
            let key = StaticPrivateKey::from_bytes(&key_bytes).unwrap();

            key.public()
        };
        hops[0].1 = new_pubkey;
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        match transit_managers[0].handle_short_tunnel_build(message).unwrap_err() {
            Error::Chacha20Poly1305(_) => {}
            error => panic!("invalid error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn router_shutting_down_tunnel_rejected() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let mut hops = Vec::<(Bytes, StaticPublicKey)>::new();
        let mut ctxs = Vec::<ShutdownContext<MockRuntime>>::new();
        let mut transit_managers = Vec::<TransitTunnelManager<MockRuntime>>::new();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        for i in 0..3 {
            let (router_hash, static_key, signing_key, _, router_info) = make_router(true);

            let (transit_tx, transit_rx) = channel(16);
            let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
            let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
            let mut shutdown_handle = shutdown_ctx.handle();

            if i % 2 == 0 {
                shutdown_ctx.shutdown();
                tokio::time::timeout(Duration::from_secs(2), &mut shutdown_handle)
                    .await
                    .expect("no timeout");
            }

            let routing_table =
                RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

            hops.push((router_hash, static_key.public()));
            ctxs.push(shutdown_ctx);
            transit_managers.push(TransitTunnelManager::new(
                Some(TransitConfig {
                    max_tunnels: Some(5000),
                }),
                RouterContext::new(
                    handle.clone(),
                    ProfileStorage::new(&[], &[]),
                    router_info.identity.id(),
                    Bytes::from(router_info.serialize(&signing_key)),
                    static_key,
                    signing_key,
                    2u8,
                    event_handle.clone(),
                ),
                routing_table,
                transit_rx,
                shutdown_handle,
            ));
        }

        let (local_hash, _, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg, _) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg, _) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::TunnelRejected(30))));
                assert_eq!(error[1].1, Some(Ok(())));
                assert_eq!(error[2].1, Some(Err(TunnelError::TunnelRejected(30))));
            }
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn transit_manager_exits_after_all_tunnels_have_expired() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (router_hash, static_key, signing_key, _noise_context, router_info) = make_router(true);
        let (transit_tx, transit_rx) = channel(16);
        let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
        let routing_table = RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);
        let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
        let shutdown_handle = shutdown_ctx.handle();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        let mut transit_manager = TransitTunnelManager::<MockRuntime>::new(
            None,
            RouterContext::new(
                handle.clone(),
                ProfileStorage::new(&[], &[]),
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            routing_table,
            transit_rx,
            shutdown_handle,
        );

        let handle = tokio::spawn(async move {
            transit_manager.tunnels.push(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(TunnelId::random())
            });

            let _ = (&mut transit_manager).await;
        });

        shutdown_ctx.shutdown();

        // wait for 5 seconds and verify the operation times out because the transit tunnel expires
        // in 10 seconds
        assert!(tokio::time::timeout(Duration::from_secs(5), &mut shutdown_ctx).await.is_err());

        // wait until the transit tunnel expires and transit tunnel manager exits
        assert!(tokio::time::timeout(Duration::from_secs(10), &mut shutdown_ctx).await.is_ok());
        assert!(handle.await.is_ok());
    }

    #[tokio::test]
    async fn transit_tunnels_disabled() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let mut hops = Vec::<(Bytes, StaticPublicKey)>::new();
        let mut ctxs = Vec::<ShutdownContext<MockRuntime>>::new();
        let mut transit_managers = Vec::<TransitTunnelManager<MockRuntime>>::new();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        for i in 0..3 {
            let (router_hash, static_key, signing_key, _, router_info) = make_router(true);

            let (transit_tx, transit_rx) = channel(16);
            let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
            let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
            let shutdown_handle = shutdown_ctx.handle();

            let routing_table =
                RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

            hops.push((router_hash, static_key.public()));
            ctxs.push(shutdown_ctx);
            transit_managers.push(TransitTunnelManager::new(
                if i == 0 {
                    None
                } else {
                    Some(TransitConfig {
                        max_tunnels: Some(5000),
                    })
                },
                RouterContext::new(
                    handle.clone(),
                    ProfileStorage::new(&[], &[]),
                    router_info.identity.id(),
                    Bytes::from(router_info.serialize(&signing_key)),
                    static_key,
                    signing_key,
                    2u8,
                    event_handle.clone(),
                ),
                routing_table,
                transit_rx,
                shutdown_handle,
            ));
        }

        let (local_hash, _, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg, _) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg, _) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::TunnelRejected(30))));
                assert_eq!(error[1].1, Some(Ok(())));
                assert_eq!(error[2].1, Some(Ok(())));
            }
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn maximum_transit_tunnels() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let mut hops = Vec::<(Bytes, StaticPublicKey)>::new();
        let mut ctxs = Vec::<ShutdownContext<MockRuntime>>::new();
        let mut transit_managers = Vec::<TransitTunnelManager<MockRuntime>>::new();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);

        for i in 0..3 {
            let (router_hash, static_key, signing_key, _, router_info) = make_router(true);

            let (transit_tx, transit_rx) = channel(16);
            let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
            let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
            let shutdown_handle = shutdown_ctx.handle();

            let routing_table =
                RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

            hops.push((router_hash, static_key.public()));
            ctxs.push(shutdown_ctx);
            transit_managers.push(TransitTunnelManager::new(
                if i == 0 {
                    Some(TransitConfig {
                        max_tunnels: Some(0),
                    })
                } else {
                    Some(TransitConfig {
                        max_tunnels: Some(5000),
                    })
                },
                RouterContext::new(
                    handle.clone(),
                    ProfileStorage::new(&[], &[]),
                    router_info.identity.id(),
                    Bytes::from(router_info.serialize(&signing_key)),
                    static_key,
                    signing_key,
                    2u8,
                    event_handle.clone(),
                ),
                routing_table,
                transit_rx,
                shutdown_handle,
            ));
        }

        let (local_hash, _, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise.clone(),
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        let message = (0..transit_managers.len() - 1).fold(message, |message, i| {
            let (_, msg, _) = transit_managers[i].handle_short_tunnel_build(message).unwrap();

            Message::parse_short(&msg).unwrap()
        });

        let (_, msg, _) = transit_managers[2].handle_short_tunnel_build(message).unwrap();

        let Message {
            message_type,
            payload,
            ..
        } = Message::parse_short(&msg).unwrap();

        assert_eq!(message_type, MessageType::TunnelGateway);

        let TunnelGateway {
            tunnel_id: recv_tunnel_id,
            payload,
        } = TunnelGateway::parse(&payload).unwrap();

        assert_eq!(TunnelId::from(recv_tunnel_id), gateway);
        let message = Message::parse_standard(&payload).unwrap();
        assert_eq!(message.message_type, MessageType::Garlic);

        match pending_tunnel.try_build_tunnel(message) {
            Err(error) => {
                assert_eq!(error[0].1, Some(Err(TunnelError::TunnelRejected(30))));
                assert_eq!(error[1].1, Some(Ok(())));
                assert_eq!(error[2].1, Some(Ok(())));
            }
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn next_hop_dial_failure() {
        let handle = MockRuntime::register_metrics(vec![], None);
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let (hops, mut transit_managers): (
            Vec<(Bytes, StaticPublicKey, ShutdownContext<MockRuntime>)>,
            Vec<TransitTunnelManager<MockRuntime>>,
        ) = (0..3)
            .map(|_| make_router(true))
            .into_iter()
            .map(
                |(router_hash, static_key, signing_key, _noise_context, router_info)| {
                    let (transit_tx, transit_rx) = channel(16);
                    let (manager_tx, _manager_rx) = with_recycle(64, RoutingKindRecycle::default());
                    let mut shutdown_ctx = ShutdownContext::<MockRuntime>::new();
                    let shutdown_handle = shutdown_ctx.handle();
                    let routing_table =
                        RoutingTable::new(RouterId::from(&router_hash), manager_tx, transit_tx);

                    (
                        (router_hash, static_key.public(), shutdown_ctx),
                        TransitTunnelManager::new(
                            Some(TransitConfig {
                                max_tunnels: Some(5000),
                            }),
                            RouterContext::new(
                                handle.clone(),
                                ProfileStorage::new(&[], &[]),
                                router_info.identity.id(),
                                Bytes::from(router_info.serialize(&signing_key)),
                                static_key,
                                signing_key,
                                2u8,
                                event_handle.clone(),
                            ),
                            routing_table,
                            transit_rx,
                            shutdown_handle,
                        ),
                    )
                },
            )
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());
        let (hops, _handles): (Vec<_>, Vec<_>) = hops
            .into_iter()
            .map(|(router_id, public_key, context)| ((router_id, public_key), context))
            .unzip();

        let (_pending_tunnel, _next_router, message) =
            PendingTunnel::<OutboundTunnel<MockRuntime>>::create_tunnel::<MockRuntime>(
                TunnelBuildParameters {
                    hops: hops.clone(),
                    name: Str::from("tunnel-pool"),
                    noise: local_noise,
                    message_id,
                    tunnel_info: TunnelInfo::Outbound {
                        gateway,
                        tunnel_id,
                        router_id: local_hash,
                    },
                    receiver: ReceiverKind::Outbound,
                },
            )
            .unwrap();

        assert_eq!(transit_managers[0].tunnels.len(), 0);
        let (_, _, tx) = transit_managers[0].handle_short_tunnel_build(message).unwrap();
        assert_eq!(transit_managers[0].tunnels.len(), 1);

        // drop `tx` to indicate that there was a next hop dial failure and ensure that the transit
        // tunnel no longer exist in `TransitTunnelManager`
        drop(tx);

        assert!(
            tokio::time::timeout(Duration::from_secs(5), &mut transit_managers[0])
                .await
                .is_err()
        );
        assert_eq!(transit_managers[0].tunnels.len(), 0);
    }
}
