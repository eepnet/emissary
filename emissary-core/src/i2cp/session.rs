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
    crypto::base64_decode,
    destination::{DeliveryStyle, Destination, DestinationEvent, LeaseSetStatus},
    i2cp::{
        message::{
            BandwidthLimits, HostReply, HostReplyKind, Message, MessagePayload, RequestKind,
            RequestVariableLeaseSet, SessionId, SessionStatus, SessionStatusKind, SetDate,
        },
        payload::I2cpParameters,
        pending::I2cpSessionContext,
        socket::I2cpSocket,
    },
    netdb::NetDbHandle,
    primitives::{Date, DestinationId, Mapping, Str},
    runtime::{AddressBook, JoinSet, Runtime},
};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use hashbrown::HashMap;

use alloc::{collections::VecDeque, string::ToString, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::session";

/// Context for a pending outbound message.
///
/// Message is marked as outbound because a lease set query for the remote destination is pending.
struct PendingMessage {
    /// I2CP protocol parameters.
    #[allow(unused)]
    parameters: I2cpParameters,

    /// Payload.
    payload: Vec<u8>,

    /// Session ID.
    #[allow(unused)]
    session_id: SessionId,
}

/// I2CP client session.
pub struct I2cpSession<R: Runtime> {
    /// Address book.
    address_book: Option<Arc<dyn AddressBook>>,

    /// Destination.
    destination: Destination<R>,

    /// Pending host lookups.
    host_lookups: R::JoinSet<(SessionId, u32, Option<Bytes>)>,

    /// Next message ID.
    next_message_id: u32,

    /// Session options.
    #[allow(unused)]
    options: Mapping,

    /// Pending outbound connections.
    pending_connections: HashMap<DestinationId, VecDeque<PendingMessage>>,

    /// Pending lease set lookups.
    pending_lookups: HashMap<DestinationId, (SessionId, u32)>,

    /// Session ID.
    session_id: u16,

    /// I2CP socket.
    socket: I2cpSocket<R>,
}

impl<R: Runtime> I2cpSession<R> {
    /// Create new [`I2cpSession`] from `stream`.
    pub fn new(netdb_handle: NetDbHandle, context: I2cpSessionContext<R>) -> Self {
        let I2cpSessionContext {
            address_book,
            destination_id,
            inbound,
            leaseset,
            options,
            outbound,
            private_keys,
            profile_storage,
            session_id,
            socket,
            tunnel_pool_handle,
        } = context;

        tracing::info!(
            target: LOG_TARGET,
            ?session_id,
            num_inbound_tunnels = ?inbound.len(),
            num_outbound_tunnels = ?outbound.len(),
            "start active i2cp session",
        );

        // TODO: remove
        for (key, value) in options.iter() {
            tracing::info!("{key}={value}");
        }

        let mut destination = Destination::new(
            destination_id.clone(),
            private_keys[0].clone(),
            leaseset.clone(),
            netdb_handle,
            tunnel_pool_handle,
            outbound.into_iter().collect(),
            inbound.into_values().collect(),
            options
                .get(&Str::from("i2cp.dontPublishLeaseSet"))
                .map(|value| value.parse::<bool>().unwrap_or(true))
                .unwrap_or(true),
            profile_storage,
        );
        destination.publish_lease_set(leaseset);

        Self {
            address_book,
            destination,
            host_lookups: R::join_set(),
            next_message_id: 0u32,
            options,
            pending_connections: HashMap::new(),
            pending_lookups: HashMap::new(),
            session_id,
            socket,
        }
    }

    /// Send `MessagePayload` message to client.
    fn send_payload_message(&mut self, payload: Vec<u8>) {
        let message_id = {
            let message_id = self.next_message_id;
            self.next_message_id = self.next_message_id.wrapping_add(1);

            message_id
        };

        self.socket
            .send_message(MessagePayload::new(self.session_id, message_id, payload));
    }

    /// Handle I2CP message received from the client.
    fn on_message(&mut self, message: Message) {
        match message {
            Message::GetDate { version, options } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %version,
                    ?options,
                    "get date, send set date",
                );

                self.socket.send_message(SetDate::new(
                    Date::new(R::time_since_epoch().as_millis() as u64),
                    Str::from_str("0.9.63").expect("to succeed"),
                ));
            }
            Message::GetBandwidthLimits => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "handle bandwidth limit request",
                );

                self.socket.send_message(BandwidthLimits::new());
            }
            Message::DestroySession { session_id } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?session_id,
                    "destroy session",
                );

                self.socket
                    .send_message(SessionStatus::new(session_id, SessionStatusKind::Destroyed));
            }
            Message::CreateSession {
                destination,
                date,
                options,
            } => {
                tracing::warn!(
                    target: LOG_TARGET,
                    destination = %destination.id(),
                    ?date,
                    num_options = ?options.len(),
                    "received `CreateSession` for an active session",
                );

                self.socket.send_message(SessionStatus::new(
                    SessionId::Session(self.session_id),
                    SessionStatusKind::Refused,
                ));
            }
            Message::HostLookup {
                session_id,
                request_id,
                timeout,
                kind,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?session_id,
                    ?request_id,
                    ?timeout,
                    ?kind,
                    "lookup host",
                );

                match (self.address_book.clone(), kind) {
                    (Some(address_book), RequestKind::HostName { host_name }) => {
                        self.host_lookups.push(async move {
                            let destination = address_book
                                .resolve(host_name.to_string())
                                .await
                                .and_then(base64_decode);

                            (
                                session_id,
                                request_id,
                                destination
                                    .map(|destination| BytesMut::from(&destination[..]).freeze()),
                            )
                        });
                    }
                    (None, kind) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?kind,
                            "address book doesn't exist",
                        );

                        self.socket.send_message(HostReply::new(
                            session_id.as_u16(),
                            request_id,
                            HostReplyKind::Failure,
                        ));
                    }
                    (Some(_), RequestKind::Hash { hash }) => {
                        let destination_id = DestinationId::from(hash);

                        match self.destination.query_lease_set(&destination_id) {
                            LeaseSetStatus::Found => {
                                let destination = self
                                    .destination
                                    .lease_set(&destination_id)
                                    .header
                                    .destination
                                    .serialized()
                                    .clone();

                                self.socket.send_message(HostReply::new(
                                    session_id.as_u16(),
                                    request_id,
                                    HostReplyKind::Success { destination },
                                ));
                            }
                            LeaseSetStatus::NotFound => {
                                tracing::trace!(
                                    target: LOG_TARGET,
                                    %destination_id,
                                    "lease set lookup started for hash-based host lookup",
                                );
                                self.pending_lookups
                                    .insert(destination_id, (session_id, request_id));
                            }
                            LeaseSetStatus::Pending => tracing::warn!(
                                target: LOG_TARGET,
                                %destination_id,
                                "hash-based host lookup is already pending",
                            ),
                        }
                    }
                }
            }
            Message::CreateLeaseSet2 {
                session_id,
                leaseset,
                private_keys,
                ..
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?session_id,
                    num_private_keys = ?private_keys.len(),
                    "store lease set",
                );

                self.destination.publish_lease_set(leaseset);
            }
            Message::SendMessageExpires {
                session_id,
                destination,
                parameters:
                    I2cpParameters {
                        dst_port,
                        protocol,
                        src_port,
                    },
                payload,
                ..
            } => {
                let destination_id = destination.id();

                match self.destination.query_lease_set(&destination_id) {
                    LeaseSetStatus::Found => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            ?session_id,
                            %destination_id,
                            ?protocol,
                            "send message with expiration",
                        );

                        if let Err(error) = self.destination.send_message(
                            DeliveryStyle::Unspecified {
                                destination_id: destination.id(),
                            },
                            payload,
                        ) {
                            tracing::error!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                ?error,
                                "failed to encrypt message",
                            );
                        }
                    }
                    LeaseSetStatus::NotFound => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %destination_id,
                            "cannot send message, lease set doesn't exist",
                        );

                        // `Destination` has started a lease set query and will notify
                        // `I2cpConnection` once the query has completed
                        //
                        // pending messages will be sent if the lease set is found
                        self.pending_connections.insert(
                            destination_id,
                            VecDeque::from_iter([PendingMessage {
                                parameters: I2cpParameters {
                                    dst_port,
                                    protocol,
                                    src_port,
                                },
                                payload,
                                session_id,
                            }]),
                        );
                    }
                    LeaseSetStatus::Pending => {
                        match self.pending_connections.get_mut(&destination_id) {
                            Some(messages) => messages.push_back(PendingMessage {
                                parameters: I2cpParameters {
                                    dst_port,
                                    protocol,
                                    src_port,
                                },
                                payload,
                                session_id,
                            }),
                            None => {
                                // TODO: fix this, could be pending lookup as well
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %destination_id,
                                    "pending connection doesn't exist",
                                );
                                // debug_assert!(false);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

impl<R: Runtime> Future for I2cpSession<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.socket.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) => self.on_message(message),
            }
        }

        loop {
            match self.destination.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(DestinationEvent::Messages { messages })) =>
                    messages.into_iter().for_each(|message| {
                        tracing::trace!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            "send messages to i2cp client",
                        );

                        self.send_payload_message(message)
                    }),
                Poll::Ready(Some(DestinationEvent::LeaseSetFound { destination_id })) =>
                    match self.pending_connections.remove(&destination_id) {
                        Some(messages) => messages.into_iter().for_each(|message| {
                            if let Err(error) = self.destination.send_message(
                                DeliveryStyle::Unspecified {
                                    destination_id: destination_id.clone(),
                                },
                                message.payload,
                            ) {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?error,
                                    "failed to encrypt message",
                                );
                            }
                        }),
                        None => match self.pending_lookups.remove(&destination_id) {
                            Some((session_id, request_id)) => {
                                let destination = self
                                    .destination
                                    .lease_set(&destination_id)
                                    .header
                                    .destination
                                    .serialized()
                                    .clone();

                                self.socket.send_message(HostReply::new(
                                    session_id.as_u16(),
                                    request_id,
                                    HostReplyKind::Success { destination },
                                ));
                            }
                            None => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %destination_id,
                                    "lease set query completed for a connection that doesn't exist",
                                );
                            }
                        },
                    },
                Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                    destination_id,
                    error,
                })) => match self.pending_connections.remove(&destination_id) {
                    Some(_) => tracing::warn!(
                        target: LOG_TARGET,
                        %destination_id,
                        ?error,
                        "lease set query failed",
                    ),
                    None => match self.pending_lookups.remove(&destination_id) {
                        Some((session_id, request_id)) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                %destination_id,
                                ?error,
                                "lease set lookup failed for host-based lookup",
                            );

                            self.socket.send_message(HostReply::new(
                                session_id.as_u16(),
                                request_id,
                                HostReplyKind::Failure,
                            ));
                        }
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            %destination_id,
                            ?error,
                            "unknown lease set lookup failed",
                        ),
                    },
                },
                Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "tunnel pool shut down, shutting down session",
                    );

                    return Poll::Ready(());
                }
                Poll::Ready(Some(DestinationEvent::CreateLeaseSet { leases })) => {
                    let session_id = self.session_id;
                    self.socket.send_message(RequestVariableLeaseSet::new(session_id, leases));

                    // wake the task so that the socket is polled and the message is sent to client
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Some(DestinationEvent::SessionTerminated { destination_id })) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        destination_id = %destination_id,
                        "session terminated with remote",
                    );

                    // TODO: implement
                }
            }
        }

        loop {
            match self.host_lookups.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((session_id, request_id, None))) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?session_id,
                        ?request_id,
                        "host lookup failed",
                    );
                    self.socket.send_message(HostReply::new(
                        session_id.as_u16(),
                        request_id,
                        HostReplyKind::Failure,
                    ));
                }
                Poll::Ready(Some((session_id, request_id, Some(destination)))) => {
                    self.socket.send_message(HostReply::new(
                        session_id.as_u16(),
                        request_id,
                        HostReplyKind::Success { destination },
                    ));
                }
            }
        }

        Poll::Pending
    }
}
