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
    error::ChannelError,
    i2np::Message,
    primitives::{MessageId, TunnelId},
    profile::ProfileStorage,
    runtime::{JoinSet, Runtime},
    subsystem::SubsystemHandle,
    tunnel::{
        hop::{pending::PendingTunnel, Tunnel},
        pool::{context::TunnelPoolContextHandle, TUNNEL_BUILD_EXPIRATION},
    },
    Error,
};

use futures::{
    future::{select, Either},
    Stream, StreamExt,
};
use futures_channel::oneshot;

use core::{
    pin::{pin, Pin},
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pool::listener";

/// Receive kind.
pub enum ReceiveKind {
    /// Reply is received through a fake 0-hop inbound tunnel.
    ZeroHop,

    /// Message is received through the routing table.
    RoutingTable {
        /// Message ID.
        message_id: MessageId,
    },

    /// Message is received through a tunnel.
    Tunnel {
        /// Message ID.
        message_id: MessageId,

        /// Tunnel pool handle.
        handle: TunnelPoolContextHandle,
    },
}

/// Tunnel build listener.
pub struct TunnelBuildListener<R: Runtime, T: Tunnel<R> + 'static> {
    /// Pending tunnels.
    pending: R::JoinSet<(TunnelId, crate::Result<(T, R::Instant)>)>,

    /// Profile storage.
    profile: ProfileStorage<R>,

    /// Routing table.
    subsystem_handle: SubsystemHandle,
}

impl<R: Runtime, T: Tunnel<R>> TunnelBuildListener<R, T> {
    /// Create new [`TunnelBuildListener`].
    pub fn new(subsystem_handle: SubsystemHandle, profile: ProfileStorage<R>) -> Self {
        Self {
            pending: R::join_set(),
            profile,
            subsystem_handle,
        }
    }

    /// Get the number of pending tunnels.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Add pending tunnel into set of tunnels that are being waited.
    pub fn add_pending_tunnel(
        &mut self,
        tunnel: PendingTunnel<R, T>,
        receive_kind: ReceiveKind,
        message_rx: oneshot::Receiver<Message>,
        dial_rx: oneshot::Receiver<()>,
    ) {
        let subsystem_handle = self.subsystem_handle.clone();
        let profile = self.profile.clone();
        let now = R::now();

        self.pending.push(async move {
            match select(dial_rx, pin!(R::delay(Duration::from_secs(2 * 60)))).await {
                Either::Left((Ok(_), _)) => {}
                Either::Left((Err(_), _)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        direction = ?T::direction(),
                        tunnel_id = %tunnel.tunnel_id(),
                        "failed to dial next hop",
                    );

                    return (*tunnel.tunnel_id(), Err(Error::DialFailure));
                }
                Either::Right(_) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        direction = ?T::direction(),
                        tunnel_id = %tunnel.tunnel_id(),
                        "failed to receive dial result after 2 minutes",
                    );
                    debug_assert!(false);
                    return (*tunnel.tunnel_id(), Err(Error::DialFailure));
                }
            }

            match select(message_rx, pin!(R::delay(TUNNEL_BUILD_EXPIRATION))).await {
                Either::Right((_, _)) => {
                    match receive_kind {
                        ReceiveKind::RoutingTable { message_id } =>
                            subsystem_handle.remove_listener(&message_id),
                        ReceiveKind::Tunnel { message_id, handle } =>
                            handle.remove_listener(&message_id),
                        ReceiveKind::ZeroHop => {}
                    }

                    tunnel.hops().iter().for_each(|hop| {
                        profile.tunnel_not_answered(hop.router_id());
                    });

                    (*tunnel.tunnel_id(), Err(Error::Timeout))
                }
                Either::Left((Err(_), _)) => {
                    match receive_kind {
                        ReceiveKind::RoutingTable { message_id } =>
                            subsystem_handle.remove_listener(&message_id),
                        ReceiveKind::Tunnel { message_id, handle } =>
                            handle.remove_listener(&message_id),
                        ReceiveKind::ZeroHop => {}
                    }

                    tunnel.hops().iter().for_each(|hop| {
                        profile.tunnel_not_answered(hop.router_id());
                    });

                    (
                        *tunnel.tunnel_id(),
                        Err(Error::Channel(ChannelError::Closed)),
                    )
                }
                Either::Left((Ok(message), _)) => {
                    let tunnel_id = *tunnel.tunnel_id();

                    match tunnel.try_build_tunnel(message) {
                        Err(routers) => (
                            tunnel_id,
                            routers
                                .into_iter()
                                .fold(None, |acc, (router_id, maybe_error)| match maybe_error {
                                    // tunnel participation could not be determined
                                    None => {
                                        profile.unselected_for_tunnel(&router_id);
                                        acc
                                    }
                                    // tunnel couldn't be built even though this router
                                    // accepted the tunnel
                                    Some(Ok(())) => {
                                        profile.tunnel_accepted(&router_id);
                                        acc
                                    }
                                    // router rejected tunnel or decryption/parsing failed
                                    Some(Err(error)) => {
                                        profile.tunnel_rejected(&router_id);
                                        Some(Err(Error::Tunnel(error)))
                                    }
                                })
                                // the error value must exist since an error was returned
                                .expect("error value"),
                        ),
                        Ok(tunnel) => {
                            tunnel.hops().iter().for_each(|router_id| {
                                profile.tunnel_accepted(router_id);
                            });

                            (tunnel_id, Ok((tunnel, now)))
                        }
                    }
                }
            }
        });
    }
}

impl<R: Runtime, T: Tunnel<R>> Stream for TunnelBuildListener<R, T> {
    type Item = (TunnelId, crate::Result<(T, R::Instant)>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.pending.poll_next_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::StaticPublicKey,
        primitives::{MessageId, Str, TunnelId},
        runtime::mock::MockRuntime,
        subsystem::SubsystemHandle,
        tunnel::{
            hop::{
                outbound::OutboundTunnel, pending::PendingTunnel, ReceiverKind,
                TunnelBuildParameters, TunnelInfo,
            },
            tests::make_router,
            NoiseContext,
        },
    };
    use bytes::Bytes;
    use rand_core::RngCore;
    use std::time::Duration;

    #[tokio::test]
    async fn response_channel_closed() {
        let profile_storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, router_info)| {
                profile_storage.add_router(router_info);

                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, _message) =
            PendingTunnel::<_, OutboundTunnel<MockRuntime>>::create_tunnel(TunnelBuildParameters {
                hops: hops.clone(),
                metrics_handle: MockRuntime::register_metrics(vec![], None),
                name: Str::from("tunnel-pool"),
                noise: local_noise,
                message_id,
                tunnel_info: TunnelInfo::Outbound {
                    gateway,
                    tunnel_id,
                    router_id: local_hash,
                },
                receiver: ReceiverKind::Outbound,
            })
            .unwrap();

        let (handle, _event_rx) = SubsystemHandle::new();
        let mut listener = TunnelBuildListener::new(handle, profile_storage);

        let (tx, rx) = oneshot::channel();
        let (dial_tx, dial_rx) = oneshot::channel();
        listener.add_pending_tunnel(pending_tunnel, ReceiveKind::ZeroHop, rx, dial_rx);
        dial_tx.send(()).unwrap();
        drop(tx);

        match tokio::time::timeout(Duration::from_secs(2), listener.next())
            .await
            .expect("no timeout")
        {
            Some((_, Err(Error::Channel(ChannelError::Closed)))) => {}
            _ => panic!("invalid return value"),
        }
    }

    #[tokio::test]
    async fn tunnel_build_timeouts() {
        let profile_storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, router_info)| {
                profile_storage.add_router(router_info);

                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, _message) =
            PendingTunnel::<_, OutboundTunnel<MockRuntime>>::create_tunnel(TunnelBuildParameters {
                hops: hops.clone(),
                metrics_handle: MockRuntime::register_metrics(vec![], None),
                name: Str::from("tunnel-pool"),
                noise: local_noise,
                message_id,
                tunnel_info: TunnelInfo::Outbound {
                    gateway,
                    tunnel_id,
                    router_id: local_hash,
                },
                receiver: ReceiverKind::Outbound,
            })
            .unwrap();

        let (handle, _event_rx) = SubsystemHandle::new();
        let mut listener = TunnelBuildListener::new(handle, profile_storage);

        let (tx, rx) = oneshot::channel();
        let (dial_tx, dial_rx) = oneshot::channel();
        listener.add_pending_tunnel(pending_tunnel, ReceiveKind::ZeroHop, rx, dial_rx);
        dial_tx.send(()).unwrap();
        drop(tx);

        match tokio::time::timeout(Duration::from_secs(2), listener.next())
            .await
            .expect("no timeout")
        {
            Some((_, Err(Error::Channel(ChannelError::Closed)))) => {}
            _ => panic!("invalid return value"),
        }
    }

    #[tokio::test]
    async fn tunnel_build_dial_failure() {
        let profile_storage = ProfileStorage::<MockRuntime>::new(&[], &[]);
        let (hops, _noise_contexts): (Vec<(Bytes, StaticPublicKey)>, Vec<NoiseContext>) = (0..3)
            .map(|i| make_router(if i % 2 == 0 { true } else { false }))
            .into_iter()
            .map(|(router_hash, sk, _, noise_context, router_info)| {
                profile_storage.add_router(router_info);

                ((router_hash, sk.public()), noise_context)
            })
            .unzip();

        let (local_hash, _local_sk, _, local_noise, _) = make_router(true);
        let message_id = MessageId::from(MockRuntime::rng().next_u32());
        let tunnel_id = TunnelId::from(MockRuntime::rng().next_u32());
        let gateway = TunnelId::from(MockRuntime::rng().next_u32());

        let (pending_tunnel, _next_router, _message) =
            PendingTunnel::<_, OutboundTunnel<MockRuntime>>::create_tunnel(TunnelBuildParameters {
                hops: hops.clone(),
                metrics_handle: MockRuntime::register_metrics(vec![], None),
                name: Str::from("tunnel-pool"),
                noise: local_noise,
                message_id,
                tunnel_info: TunnelInfo::Outbound {
                    gateway,
                    tunnel_id,
                    router_id: local_hash,
                },
                receiver: ReceiverKind::Outbound,
            })
            .unwrap();

        let (handle, _event_rx) = SubsystemHandle::new();
        let mut listener = TunnelBuildListener::new(handle, profile_storage);

        let (_tx, rx) = oneshot::channel();
        let (dial_tx, dial_rx) = oneshot::channel();
        listener.add_pending_tunnel(pending_tunnel, ReceiveKind::ZeroHop, rx, dial_rx);
        drop(dial_tx);

        match tokio::time::timeout(Duration::from_secs(2), listener.next())
            .await
            .expect("no timeout")
        {
            Some((_, Err(Error::DialFailure))) => {}
            _ => panic!("invalid return value"),
        }
    }
}
