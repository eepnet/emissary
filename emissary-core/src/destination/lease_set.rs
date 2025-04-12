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
    crypto::{chachapoly::ChaChaPoly, EphemeralPrivateKey, StaticPublicKey},
    error::QueryError,
    i2np::{
        database::{
            lookup::{DatabaseLookupBuilder, LookupType, ReplyType as LookupReplyType},
            store::{DatabaseStoreBuilder, DatabaseStoreKind, ReplyType},
        },
        garlic::{DeliveryInstructions, GarlicMessageBuilder, GARLIC_MESSAGE_OVERHEAD},
        MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::{Dht, NetDbHandle},
    primitives::{DestinationId, Lease, MessageId, RouterId, TunnelId},
    profile::ProfileStorage,
    runtime::{Instant, JoinSet, Runtime},
    tunnel::{NoiseContext, TunnelMessageSender},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{future::BoxFuture, FutureExt, StreamExt};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::lease-set";

/// How many closest floodfills does [`LeaseSetManager`] store
const NUM_CLOSEST_FLOODFILLS: usize = 10usize;

/// How long [`LeaseSetManager`] awaits new tunnels before forcibly publishing an new [`LeaseSet`].
const TUNNEL_BUILD_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long should [`LeaseSetPublisher`] wait before retry a failed operation.
const RETRY_TIMEOUT: Duration = Duration::from_secs(1);

/// Time to wait before the lease set storage is verified.
///
/// `LeaseSet Storage Verification` in https://geti2p.net/en/docs/how/network-database
const STORAGE_VERIFICATION_START_TIMEOUT: Duration = Duration::from_secs(10);

/// How long is a `DatabaseStore` waited for before it's considered failed.
///
/// Once deemed failed, new `DatabaseStore` is sent if there is still time left.
const STORAGE_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(2);

/// How long is lease set storage verification awaited in total before it's considered failed.
///
/// Once deemed as failed, local lease set is republished to `NetDb`.
const STORAGE_VERIFICATION_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

enum RetryKind<R: Runtime> {
    /// Get floodfills closet to [`Destination`].
    GetClosestFloodfills,

    /// Publish lease set to [`NetDb`].
    PublishLeaseSet,

    /// Verify lease set storage.
    VerifyStorage {
        /// When was the lease set storage verification started.
        started: R::Instant,
    },
}

/// [`LeaseSet2`] publish state.
enum PublishState<R: Runtime> {
    /// Publish state is inactive because there are no pending changes to the [`Destination`]'s
    /// inbound tunnels.
    Inactive,

    /// Awaiting [`LeaseSet2`] from SAM/I2CP so it can publish it to `NetDb`.
    AwaitingLeaseSet,

    /// Awaiting more inbound tunnels to be built.
    ///
    /// If new inbound tunnels have not been built before the timer expires, an "incomplete" lease
    /// set is published do `NetDb`.
    AwaitingTunnels {
        /// Timer for forcibly republishing the lease set.
        timer: BoxFuture<'static, ()>,
    },

    /// Retry previously failed operation.
    Retry {
        /// Operation to retry.
        kind: RetryKind<R>,

        /// Timer for retrying the operation.
        timer: BoxFuture<'static, ()>,
    },

    /// Get floodfills closest to [`Destination`].
    GetClosestFloodfills {
        /// RX channel for receiving the floodfills and their public keys.
        rx: oneshot::Receiver<Vec<(RouterId, StaticPublicKey)>>,
    },

    /// Publish local lease set to `NetDb`.
    PublishLeaseSet,

    /// Awaiting flooding to complete so storage verification can start.
    AwaitingFlooding {
        /// Timer that expires after lease set flooding is assumed to be finished.
        timer: BoxFuture<'static, ()>,
    },

    /// Verify that the lease set was flooded to other floodfills close to the key.
    VerifyStorage {
        /// When was the lease set storage verification started.
        started: R::Instant,

        /// Expiration timer for current [`DatabaseLookupMessage`], if it has been sent.
        timer: Option<BoxFuture<'static, ()>>,
    },

    /// [`LeaseSetPublisherState`] has been poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for PublishState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishState::Inactive => f.debug_struct("PublishState::Inactive").finish(),
            PublishState::AwaitingLeaseSet =>
                f.debug_struct("PublishState::AwaitingLeaseSet").finish(),
            PublishState::AwaitingTunnels { .. } =>
                f.debug_struct("PublishState::AwaitingTunnels").finish(),
            PublishState::Retry { .. } => f.debug_struct("PublishState::Retry").finish(),
            PublishState::GetClosestFloodfills { .. } =>
                f.debug_struct("PublishState::GetClosestFloodfills").finish(),
            PublishState::PublishLeaseSet =>
                f.debug_struct("PublishState::PublishLeaseSet").finish(),
            PublishState::AwaitingFlooding { .. } =>
                f.debug_struct("PublishState::AwaitingFlooding").finish(),
            PublishState::VerifyStorage { .. } =>
                f.debug_struct("PublishState::VerifyStorage").finish(),
            PublishState::Poisoned => f.debug_struct("PublishState::Poisoned").finish(),
        }
    }
}

/// Local lease set manager.
pub struct LeaseSetManager<R: Runtime> {
    /// ID of the local destination.
    destination_id: DestinationId,

    /// Expiring inbound tunnels.
    expiring_tunnels: HashSet<TunnelId>,

    /// Floodfills closest to [`Destination`] and their public keys.
    floodfills: HashMap<RouterId, StaticPublicKey>,

    /// Key of [`Destination`].
    key: Bytes,

    /// Local lease set.
    lease_set: Bytes,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Noise context.
    noise_ctx: NoiseContext,

    /// How many inbound tunnels is the [`Destination`] configured to have.
    ///
    /// Used to gauge when to publish new lease set to `NetDb`.
    num_inbound: usize,

    /// Pending floodfills.
    ///
    /// Flooofills which have been learned through `DatabaseSearchReply` messages but whose
    /// `RouterInfo`s are currently not available and cannot be used for storage or lookups.
    ///
    /// Floodfills are moved to `floodfills` once their `RouterInfo`s have been found.
    pending_floodfills: HashSet<RouterId>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// Router IDs of the floodfills that have been used to query the lease set.
    queried_floodfills: HashSet<RouterId>,

    /// Router info queries.
    router_info_queries: R::JoinSet<(RouterId, Result<(), QueryError>)>,

    /// [`LeaseSet2`] publish state.
    state: PublishState<R>,

    /// Router IDs of the floodfills that unsuccessfully used to store the lease set.
    storage_floodfills: HashSet<RouterId>,

    /// Tunnel message sender.
    tunnel_message_sender: TunnelMessageSender,

    /// Active inbound tunnels.
    tunnels: HashMap<TunnelId, Lease>,

    /// Is the [`Destination`] unpublished.
    unpublished: bool,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> LeaseSetManager<R> {
    /// Create new [`LeaseSetManager`].
    ///
    /// `tunnels` contains the currently built tunnels and a lease set for these tunnels have
    /// already been created and published if the [`Destination`] is not unpublished.
    pub fn new(
        tunnels: Vec<Lease>,
        destination_id: DestinationId,
        tunnel_message_sender: TunnelMessageSender,
        num_inbound: usize,
        netdb_handle: NetDbHandle,
        noise_ctx: NoiseContext,
        profile_storage: ProfileStorage<R>,
        unpublished: bool,
        lease_set: Bytes,
    ) -> Self {
        let key = Bytes::from(destination_id.to_vec());
        let state = if unpublished {
            PublishState::Inactive
        } else {
            match netdb_handle.get_closest_floodfills(key.clone()) {
                Err(_) => PublishState::Retry {
                    kind: RetryKind::GetClosestFloodfills,
                    timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                },
                Ok(rx) => PublishState::GetClosestFloodfills { rx },
            }
        };

        Self {
            destination_id: destination_id.clone(),
            expiring_tunnels: HashSet::new(),
            floodfills: HashMap::new(),
            key,
            lease_set,
            netdb_handle,
            noise_ctx,
            num_inbound,
            pending_floodfills: HashSet::new(),
            profile_storage,
            queried_floodfills: HashSet::new(),
            router_info_queries: R::join_set(),
            state,
            storage_floodfills: HashSet::new(),
            tunnel_message_sender,
            tunnels: HashMap::from_iter(tunnels.into_iter().map(|lease| (lease.tunnel_id, lease))),
            unpublished,
            waker: None,
        }
    }

    fn get_closest_floodfills(&mut self) {
        match self.netdb_handle.get_closest_floodfills(self.key.clone()) {
            Err(_) => {
                self.state = PublishState::Retry {
                    kind: RetryKind::GetClosestFloodfills,
                    timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                };
            }
            Ok(rx) => {
                self.state = PublishState::GetClosestFloodfills { rx };
            }
        }
    }

    /// Register new lease set for the [`Destination`].
    pub fn register_lease_set(&mut self, lease_set: Bytes) {
        self.lease_set = lease_set;

        if self.unpublished {
            return;
        }

        if let PublishState::AwaitingLeaseSet = &self.state {
            self.get_closest_floodfills();

            if let Some(waker) = self.waker.take() {
                waker.wake_by_ref();
            }
        }
    }

    /// Register [`DatabaseStore`] message.
    pub fn register_database_store(&mut self, key: Bytes) {
        if self.key != key {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                key = ?key.to_vec(),
                "received DSM for an unknown key",
            );
            return;
        }

        match &self.state {
            PublishState::VerifyStorage { .. } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "lease set storage verified",
                );

                self.state = PublishState::Inactive;
                self.storage_floodfills.clear();
                self.queried_floodfills.clear();
            }
            state => tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                ?state,
                "received an unexpected DSM",
            ),
        }
    }

    /// Register [`DatabaseSearchReply`].
    pub fn register_database_search_reply(&mut self, key: Bytes, floodfills: Vec<RouterId>) {
        if self.unpublished {
            return;
        }

        if self.key != key {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                key = ?key.to_vec(),
                "received DSRM for an unknown key",
            );
            return;
        }

        let floodfills_to_query = {
            let reader = self.profile_storage.reader();

            floodfills
                .into_iter()
                .filter_map(|router_id| match reader.router_info(&router_id) {
                    Some(info) => {
                        self.floodfills.insert(router_id, info.identity.static_key().clone());
                        None
                    }
                    None => (!self.pending_floodfills.contains(&router_id)).then_some(router_id),
                })
                .collect::<HashSet<_>>()
        };

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            new_floodfills = ?floodfills_to_query,
            "received DSRM for lease set storage verification",
        );

        // start router info lookups in the background
        //
        // send DLM for the router info of each unknown floodfill and poll the
        // results until all queries have completed, either successfully or not
        //
        // `LeaseSetPublisher` decides whether to restart lookups if they failed
        if !floodfills_to_query.is_empty() {
            for router_id in floodfills_to_query {
                if let Ok(rx) = self.netdb_handle.try_query_router_info(router_id.clone()) {
                    // mark the floodfill as pending so lease set republish is postponed until the
                    // router info lookup has finished
                    self.pending_floodfills.insert(router_id.clone());

                    self.router_info_queries.push(async move {
                        (router_id, rx.await.unwrap_or(Err(QueryError::RetryFailure)))
                    });
                }
            }
        }
    }

    /// Register [`Lease`] for a newly built inbound tunnel.
    pub fn register_inbound_tunnel(&mut self, lease: Lease) -> Vec<Lease> {
        self.tunnels.insert(lease.tunnel_id, lease.clone());

        if self.unpublished {
            return self.tunnels.values().cloned().collect();
        }

        match self.tunnels.len() == self.num_inbound {
            true => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    num_tunnels = %self.num_inbound,
                    "all inbound tunnels have been built, awaiting new lease set",
                );

                self.state = PublishState::AwaitingLeaseSet;
            }
            false => {
                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    num_tunnels = %self.tunnels.len(),
                    num_needed = %self.num_inbound,
                    "waiting for inbound tunnels to be built",
                );

                self.state = PublishState::AwaitingTunnels {
                    timer: Box::pin(R::delay(TUNNEL_BUILD_WAIT_TIMEOUT)),
                };

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
        }

        self.tunnels.values().cloned().collect()
    }

    /// Register the tunnel ID of a local inbound tunnel that's about to expire
    pub fn register_expiring_inbound_tunnel(&mut self, tunnel_id: TunnelId) {
        match self.tunnels.remove(&tunnel_id) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?tunnel_id,
                    "non-existent inbound tunnel about to expire",
                );
                debug_assert!(false);
            }
            Some(_) => {
                self.expiring_tunnels.insert(tunnel_id);
            }
        }
    }

    /// Register the tunnel ID of a local inbound tunnel that has expired.
    pub fn register_expired_inbound_tunnel(&mut self, tunnel_id: TunnelId) {
        self.expiring_tunnels.remove(&tunnel_id);
    }

    /// Create [`DatabaseStore`] message for the leaset set and return the message and ID
    /// of the selected floodfill to whom the message should be sent.
    ///
    /// Returns `None` if there are no inbound tunnels or no floofills to choose from. This means
    /// that the `DatabaseStore` message cannot be sent.
    fn create_database_store(&self) -> Option<(RouterId, Vec<u8>)> {
        if self.tunnels.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "cannot publish lease set, no inbound tunnels",
            );
            return None;
        }

        // create database store and send it to a floodfill router over
        // one of the destination's outbound tunnels
        let reply_token = R::rng().next_u32();

        // select floodfill closest to us
        //
        // if the previous database store failed, try to excluse that floodfill
        //
        // if there are no other floodfills available, retry to failing floodfill
        let floodfill = match Dht::<R>::get_closest(
            &self.key,
            &self
                .floodfills
                .keys()
                .filter(|router_id| !self.storage_floodfills.contains(*router_id))
                .cloned()
                .collect::<HashSet<_>>(),
        ) {
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "no floodfills for lease set publication, trying a failing floodfill",
                );

                Dht::<R>::get_closest(
                    &self.key,
                    &self.floodfills.keys().cloned().collect::<HashSet<_>>(),
                )?
            }
            Some(floodfill) => floodfill,
        };

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            %floodfill,
            num_floodfills = ?self.floodfills.len(),
            "publish lease set",
        );

        // key must exist since the floodfill was selected from `self.floodfills`
        let floodfill_public_key = self.floodfills.get(&floodfill).expect("to exist");

        // select random tunnel for `DeliveryStatus`
        //
        // lease must exist since the random index is ensured to be within range
        // and `tunnels` is ensured to contain at least one tunnels
        let (
            _,
            Lease {
                router_id: ref gateway_router_id,
                tunnel_id: ref gateway_tunnel_id,
                ..
            },
        ) = self
            .tunnels
            .iter()
            .nth(R::rng().next_u32() as usize % self.tunnels.len())
            .expect("index to be within bounds");

        let message = DatabaseStoreBuilder::new(
            self.key.clone(),
            DatabaseStoreKind::LeaseSet2 {
                lease_set: self.lease_set.clone(),
            },
        )
        .with_reply_type(ReplyType::Tunnel {
            reply_token,
            tunnel_id: *gateway_tunnel_id,
            router_id: gateway_router_id.clone(),
        })
        .build();

        let mut message = GarlicMessageBuilder::default()
            .with_date_time(R::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::DatabaseStore,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                DeliveryInstructions::Local,
                &message,
            )
            .build();

        let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
        let ephemeral_public = ephemeral_secret.public();
        let (garlic_key, garlic_tag) = self
            .noise_ctx
            .derive_outbound_garlic_key(floodfill_public_key.clone(), ephemeral_secret);

        let mut out = BytesMut::with_capacity(message.len() + GARLIC_MESSAGE_OVERHEAD);

        // encryption must succeed since the parameters are managed by us
        ChaChaPoly::new(&garlic_key)
            .encrypt_with_ad_new(&garlic_tag, &mut message)
            .expect("to succeed");

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        Some((
            floodfill,
            MessageBuilder::standard()
                .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                .with_message_type(MessageType::Garlic)
                .with_message_id(R::rng().next_u32())
                .with_payload(&out)
                .build(),
        ))
    }

    /// Create [`DatabaseLookup`] message for lease set storage verification.
    ///
    /// On success, [`DatabaseLookup`] message and router ID of the floofill to whom the message
    /// must be sent.
    ///
    /// Returns `None` if there aren't enough floodfills for lease set storage verification or if
    /// there are no inbound tunnels available for `DatabaseStore`.
    fn create_database_lookup(&self) -> Option<(RouterId, Vec<u8>)> {
        if self.tunnels.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "cannot verify lease set storage, no inbound tunnels",
            );
            return None;
        }

        let Some(floodfill) = Dht::<R>::get_closest(
            &self.key,
            &self
                .floodfills
                .keys()
                .filter(|router_id| !self.queried_floodfills.contains(*router_id))
                .cloned()
                .collect::<HashSet<_>>(),
        ) else {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "not enough floodfills for lease set storage verification",
            );
            return None;
        };

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            %floodfill,
            "send lease set storage verification",
        );

        // must succeed since `floodfill` was selected from `self.floodfills`
        let floodfill_public_key = self.floodfills.get(&floodfill).expect("to exist");

        // select random tunnel for DSM
        //
        // lease must exist since the random index is ensured to be within range
        // and `tunnels` is ensured to contain at least one tunnels
        let (
            _,
            Lease {
                router_id: ref gateway_router_id,
                tunnel_id: ref gateway_tunnel_id,
                ..
            },
        ) = self
            .tunnels
            .iter()
            .nth(R::rng().next_u32() as usize % self.tunnels.len())
            .expect("index to be within bounds");

        let message = DatabaseLookupBuilder::new(self.key.clone(), LookupType::LeaseSet)
            .with_reply_type(LookupReplyType::Tunnel {
                tunnel_id: *gateway_tunnel_id,
                router_id: gateway_router_id.clone(),
            })
            .build();

        let mut message = GarlicMessageBuilder::default()
            .with_date_time(R::time_since_epoch().as_secs() as u32)
            .with_garlic_clove(
                MessageType::DatabaseLookup,
                MessageId::from(R::rng().next_u32()),
                R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
                DeliveryInstructions::Local,
                &message,
            )
            .build();

        let ephemeral_secret = EphemeralPrivateKey::random(R::rng());
        let ephemeral_public = ephemeral_secret.public();
        let (garlic_key, garlic_tag) = self
            .noise_ctx
            .derive_outbound_garlic_key(floodfill_public_key.clone(), ephemeral_secret);

        // message length + poly13055 tg + ephemeral key + garlic message length
        let mut out = BytesMut::with_capacity(message.len() + 16 + 32 + 4);

        // encryption must succeed since the parameters are managed by us
        ChaChaPoly::new(&garlic_key)
            .encrypt_with_ad_new(&garlic_tag, &mut message)
            .expect("to succeed");

        out.put_u32(message.len() as u32 + 32);
        out.put_slice(&ephemeral_public.to_vec());
        out.put_slice(&message);

        let message = MessageBuilder::standard()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::Garlic)
            .with_message_id(R::rng().next_u32())
            .with_payload(&out)
            .build();

        Some((floodfill, message))
    }
}

impl<R: Runtime> Future for LeaseSetManager<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match mem::replace(&mut self.state, PublishState::Poisoned) {
                PublishState::AwaitingTunnels { mut timer } => match timer.poll_unpin(cx) {
                    Poll::Pending => {
                        self.state = PublishState::AwaitingTunnels { timer };
                        break;
                    }
                    Poll::Ready(()) => self.get_closest_floodfills(),
                },
                PublishState::Retry { kind, mut timer } => match timer.poll_unpin(cx) {
                    Poll::Pending => {
                        self.state = PublishState::Retry { kind, timer };
                        break;
                    }
                    Poll::Ready(_) => match kind {
                        RetryKind::GetClosestFloodfills => self.get_closest_floodfills(),
                        RetryKind::PublishLeaseSet => {
                            self.state = PublishState::PublishLeaseSet;
                        }
                        RetryKind::VerifyStorage { started } => {
                            self.state = PublishState::VerifyStorage {
                                started,
                                timer: None,
                            };
                        }
                    },
                },
                PublishState::GetClosestFloodfills { mut rx } => match rx.poll_unpin(cx) {
                    Poll::Pending => {
                        self.state = PublishState::GetClosestFloodfills { rx };
                        break;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Ready(Ok(floodfills)) => {
                        self.floodfills.extend(floodfills);

                        let closest = Dht::<R>::get_n_closest(
                            &self.key,
                            &self.floodfills.keys().cloned().collect(),
                            NUM_CLOSEST_FLOODFILLS,
                        );
                        self.floodfills.retain(|router_id, _| closest.contains(router_id));

                        if self.floodfills.is_empty() {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                "no floodfills, trying again later",
                            );

                            self.state = PublishState::Retry {
                                kind: RetryKind::GetClosestFloodfills,
                                timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                            };
                            continue;
                        }

                        self.state = PublishState::PublishLeaseSet;
                    }
                },
                PublishState::PublishLeaseSet => match self.create_database_store() {
                    None => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "failed to create DSM, trying again later",
                        );

                        self.state = PublishState::Retry {
                            kind: RetryKind::PublishLeaseSet,
                            timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                        };
                    }
                    Some((floodfill, message)) => match self
                        .tunnel_message_sender
                        .send_message(message.clone())
                        .router_delivery(floodfill.clone())
                        .try_send()
                    {
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                ?error,
                                "failed to send DSM to floodfill, trying again later",
                            );

                            self.state = PublishState::Retry {
                                kind: RetryKind::PublishLeaseSet,
                                timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                            };
                        }
                        Ok(()) => {
                            self.storage_floodfills.insert(floodfill.clone());
                            self.queried_floodfills.insert(floodfill);

                            self.state = PublishState::AwaitingFlooding {
                                timer: Box::pin(R::delay(STORAGE_VERIFICATION_START_TIMEOUT)),
                            };
                        }
                    },
                },
                PublishState::AwaitingFlooding { mut timer } => match timer.poll_unpin(cx) {
                    Poll::Pending => {
                        self.state = PublishState::AwaitingFlooding { timer };
                        break;
                    }
                    Poll::Ready(()) => {
                        self.state = PublishState::VerifyStorage {
                            started: R::now(),
                            timer: None,
                        };
                    }
                },
                PublishState::VerifyStorage { started, timer } => {
                    if started.elapsed() >= STORAGE_VERIFICATION_TOTAL_TIMEOUT {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "lease set verification timed out, republishing lease set",
                        );

                        self.queried_floodfills.clear();
                        self.state = PublishState::PublishLeaseSet;
                        continue;
                    }

                    match timer {
                        None => match self.create_database_lookup() {
                            None => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    "failed to create DLM, trying again later",
                                );

                                self.state = PublishState::Retry {
                                    kind: RetryKind::VerifyStorage { started },
                                    timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                                };
                            }
                            Some((floodfill, message)) => match self
                                .tunnel_message_sender
                                .send_message(message.clone())
                                .router_delivery(floodfill.clone())
                                .try_send()
                            {
                                Err(error) => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        local = %self.destination_id,
                                        ?error,
                                        "failed to send DLM to floodfill, trying again later",
                                    );

                                    self.state = PublishState::Retry {
                                        kind: RetryKind::VerifyStorage { started },
                                        timer: Box::pin(R::delay(RETRY_TIMEOUT)),
                                    };
                                }
                                Ok(()) => {
                                    self.queried_floodfills.insert(floodfill);
                                    self.state = PublishState::VerifyStorage {
                                        started,
                                        timer: Some(Box::pin(R::delay(
                                            STORAGE_VERIFICATION_TIMEOUT,
                                        ))),
                                    };
                                    continue;
                                }
                            },
                        },
                        Some(mut timer) => match timer.poll_unpin(cx) {
                            Poll::Pending => {
                                self.state = PublishState::VerifyStorage {
                                    started,
                                    timer: Some(timer),
                                };
                                break;
                            }
                            Poll::Ready(()) => {
                                tracing::trace!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    "lease set verification DLM timed out, resending verification DLM",
                                );

                                self.state = PublishState::VerifyStorage {
                                    started,
                                    timer: None,
                                };
                            }
                        },
                    }
                }
                PublishState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "lease set manager has been poisoned",
                    );
                    debug_assert!(false);
                    break;
                }
                state @ (PublishState::Inactive | PublishState::AwaitingLeaseSet) => {
                    self.state = state;
                    break;
                }
            }
        }

        loop {
            match self.router_info_queries.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some((router_id, result))) => {
                    if !self.pending_floodfills.remove(&router_id) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            %router_id,
                            ?result,
                            "router info query concluded for unknown router",
                        );
                        debug_assert!(false);
                    }

                    match result {
                        Err(error) => tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            %router_id,
                            ?error,
                            "failed to find router info for requested floodfill",
                        ),
                        Ok(()) => {
                            let public_key = {
                                let reader = self.profile_storage.reader();
                                reader
                                    .router_info(&router_id)
                                    .map(|router_info| router_info.identity.static_key().clone())
                            };

                            match public_key {
                                Some(public_key) => {
                                    tracing::trace!(
                                        target: LOG_TARGET,
                                        local = %self.destination_id,
                                        %router_id,
                                        "router info lookup succeeded for requested floodfill",
                                    );

                                    self.floodfills.insert(router_id, public_key);
                                }
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        local = %self.destination_id,
                                        %router_id,
                                        "router info lookup succeeded but router if not found in storage",
                                    );
                                    debug_assert!(false);
                                }
                            }
                        }
                    }
                }
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::StaticPrivateKey,
        i2np::{
            database::{lookup::DatabaseLookup, store::DatabaseStore},
            Message,
        },
        netdb::NetDbAction,
        primitives::{LeaseSet2, RouterInfo, RouterInfoBuilder},
        runtime::mock::MockRuntime,
        tunnel::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicHandler, TunnelMessage,
            TunnelPoolHandle,
        },
    };
    use std::collections::VecDeque;

    #[tokio::test]
    async fn lease_set_published_and_storage_verified() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        // remove the floodfill from the set of floodfills since is shouldn't be for
                        // verification
                        let key = floodfills.remove(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.remove(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database store to lease set publisher
                                manager.register_database_store(lookup_key);
                            }
                            _ => panic!("invalid message type"),
                        }

                        break;
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(20)) => panic!("timeout"),
            }
        }

        // verify there's no more activity coming from lease set manager
        loop {
            tokio::select! {
                _ = &mut manager => {},
                _ = tm_rx.recv() => panic!("unexpected event"),
                _ = netdb_rx.recv() => panic!("unexpected event"),
                _ = tokio::time::sleep(Duration::from_secs(15)) => break,
            }
        }

        assert!(std::matches!(manager.state, PublishState::Inactive));
    }

    #[tokio::test]
    async fn lease_set_storage_reverified() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        // remove the floodfill from the set of floodfills since is shouldn't be for
                        // verification
                        let key = floodfills.remove(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        // process database lookup messages
        //
        // the first lookup is ignored which causes the manager to send a second lookup
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.remove(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send reply only for the last floodfill
                                if floodfills.is_empty() {
                                    // send database store to lease set publisher
                                    manager.register_database_store(lookup_key);
                                    break;
                                }
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(20)) => panic!("timeout"),
            }
        }

        // verify there's no more activity coming from lease set manager
        loop {
            tokio::select! {
                _ = &mut manager => {},
                _ = tm_rx.recv() => panic!("unexpected event"),
                _ = netdb_rx.recv() => panic!("unexpected event"),
                _ = tokio::time::sleep(Duration::from_secs(15)) => break,
            }
        }

        assert!(std::matches!(manager.state, PublishState::Inactive));
    }

    #[tokio::test]
    async fn lease_set_republished_after_timeout() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        let selected_floodfill = loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        // remove the floodfill from the set of floodfills since is shouldn't be for
                        // verification
                        let key = floodfills.get(&router_id).unwrap().clone();
                        lookup_floodfills.remove(&router_id);

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                                break router_id;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        };

        // process database lookup messages
        //
        // both lookups are ignored which causes the manager to send a new DSM
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                if lookup_floodfills.is_empty() {
                                    // send database store to lease set publisher
                                    manager.register_database_store(lookup_key);
                                    break;
                                } else {
                                    lookup_floodfills.remove(&router_id);
                                }
                            }
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                                assert_ne!(selected_floodfill, router_id);
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // verify there's no more activity coming from lease set manager
        loop {
            tokio::select! {
                _ = &mut manager => {},
                _ = tm_rx.recv() => panic!("unexpected event"),
                _ = netdb_rx.recv() => panic!("unexpected event"),
                _ = tokio::time::sleep(Duration::from_secs(15)) => break,
            }
        }

        assert!(std::matches!(manager.state, PublishState::Inactive));
    }

    #[tokio::test]
    async fn database_search_reply_with_locally_available_routers() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                    // remove the floodfill from the set of floodfills since is shouldn't be for
                    // verification
                    let key = floodfills.get(&router_id).unwrap().clone();
                    assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        // read first database lookup and send database search reply
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database search reply with random routers
                                let floodfills = (0..2)
                                    .map(|_| {
                                        let (floodfill, static_key, _) =
                                            RouterInfoBuilder::default().as_floodfill().build();
                                        let router_id = floodfill.identity.id();

                                        floodfills.insert(router_id.clone(), static_key.clone());
                                        lookup_floodfills.insert(router_id.clone(), static_key);
                                        profile_storage.add_router(floodfill);

                                        router_id
                                    })
                                    .collect();

                                manager.register_database_search_reply(lookup_key, floodfills);
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        let _ = lookup_floodfills.remove(&router_id);

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }
    }

    #[tokio::test]
    async fn router_info_lookup_started_for_new_floodfills_all_queries_succeed() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();
        let mut new_floodfills = HashMap::<RouterId, (RouterInfo, StaticPrivateKey)>::new();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                    // remove the floodfill from the set of floodfills since is shouldn't be for
                    // verification
                    let key = floodfills.get(&router_id).unwrap().clone();
                    assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        // read first database lookup and send database search reply
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database search reply with random routers but don't add them to
                                // profile storage meaning `LeaseSetPublishe` must issue RI lookups for
                                // these floodfills
                                let floodfills = (0..2)
                                    .map(|_| {
                                        let (floodfill, static_key, _) =
                                            RouterInfoBuilder::default().as_floodfill().build();
                                        let router_id = floodfill.identity.id();
                                        new_floodfills.insert(router_id.clone(), (floodfill, static_key));

                                        router_id
                                    })
                                    .collect();
                                    manager.register_database_search_reply(lookup_key, floodfills);

                                    break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        // let _ = lookup_floodfills.remove(&router_id);

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key,
                                    lookup,
                                    ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(lookup, LookupType::LeaseSet);
                                assert_eq!(key.as_ref(), &lookup_key);
                                assert!(lookup_floodfills.remove(&router_id).is_some());
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::QueryRouterInfo { router_id, tx } => {
                        let (router_info, static_key) = new_floodfills.remove(&router_id).unwrap();

                        floodfills.insert(router_id.clone(), static_key.clone());
                        lookup_floodfills.insert(router_id.clone(), static_key.clone());
                        profile_storage.add_router(router_info);

                        tx.send(Ok(())).unwrap();
                    }
                    _ => panic!("unexpected netdb action"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }
    }

    #[tokio::test]
    async fn router_info_lookup_started_for_new_floodfills_one_query_succeeds() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let mut floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();
        let mut new_floodfills = HashMap::<RouterId, (RouterInfo, StaticPrivateKey)>::new();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                    // remove the floodfill from the set of floodfills since is shouldn't be for
                    // verification
                    let key = floodfills.get(&router_id).unwrap().clone();
                    assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        // read first database lookup and send database search reply
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database search reply with random routers but don't add them to
                                // profile storage meaning `LeaseSetPublishe` must issue RI lookups for
                                // these floodfills
                                let floodfills = (0..3)
                                    .map(|_| {
                                        let (floodfill, static_key, _) =
                                            RouterInfoBuilder::default().as_floodfill().build();
                                        let router_id = floodfill.identity.id();
                                        new_floodfills.insert(router_id.clone(), (floodfill, static_key));

                                        router_id
                                    })
                                    .collect();

                                manager.register_database_search_reply(lookup_key, floodfills);

                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        // let _ = lookup_floodfills.remove(&router_id);

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key,
                                    lookup,
                                    ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(lookup, LookupType::LeaseSet);
                                assert_eq!(key.as_ref(), &lookup_key);
                                assert!(lookup_floodfills.remove(&router_id).is_some());
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::QueryRouterInfo { router_id, tx } => {
                        // only respond to the first query and let the two others timeout
                        if new_floodfills.len() == 3 {
                            let (router_info, static_key) = new_floodfills.remove(&router_id).unwrap();

                            floodfills.insert(router_id.clone(), static_key.clone());
                            lookup_floodfills.insert(router_id.clone(), static_key.clone());
                            profile_storage.add_router(router_info);

                            tx.send(Ok(())).unwrap();
                        } else {
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(3)).await;
                                tx.send(Err(QueryError::Timeout)).unwrap();
                            });
                        }
                    }
                    _ => panic!("unexpected netdb action"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }
    }

    #[tokio::test]
    async fn router_info_lookups_fail_lease_set_republished() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut lookup_floodfills = floodfills.clone();
        let mut new_floodfills = HashMap::<RouterId, (RouterInfo, StaticPrivateKey)>::new();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                    // remove the floodfill from the set of floodfills since is shouldn't be for
                    // verification
                    let key = floodfills.get(&router_id).unwrap().clone();
                    assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key, Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        // read first database lookup and send database search reply
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        assert!(lookup_floodfills.remove(&router_id).is_some());

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database search reply with random routers but don't add them to
                                // profile storage meaning `LeaseSetPublishe` must issue RI lookups for
                                // these floodfills
                                let floodfills = (0..3)
                                    .map(|_| {
                                        let (floodfill, static_key, _) =
                                            RouterInfoBuilder::default().as_floodfill().build();
                                        let router_id = floodfill.identity.id();
                                        new_floodfills.insert(router_id.clone(), (floodfill, static_key));

                                        router_id
                                    })
                                    .collect();

                                manager.register_database_search_reply(lookup_key, floodfills);

                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // keep reading database lookups and ignore them until the lease set is republished
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();
                        // let _ = lookup_floodfills.remove(&router_id);

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        // ensure that database lookup was receveid but don't respond to it
                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key,
                                    lookup,
                                    ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(lookup, LookupType::LeaseSet);
                                assert_eq!(key.as_ref(), &lookup_key);
                                assert!(lookup_floodfills.remove(&router_id).is_some());
                            }
                            MessageType::DatabaseStore => {
                                assert!(lookup_floodfills.is_empty());
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::QueryRouterInfo { router_id, tx } => {
                        let _ = new_floodfills.remove(&router_id);
                        let sleep = Duration::from_secs((new_floodfills.len() + 1) as u64 * 2);

                        tokio::spawn(async move {
                            tokio::time::sleep(sleep).await;
                            tx.send(Err(QueryError::Timeout)).unwrap();
                        });
                    }
                    _ => panic!("unexpected netdb action"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }
    }

    #[tokio::test]
    async fn floodfills_rerequested() {
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        tokio::spawn(manager);

        // send empty response
        match tokio::time::timeout(Duration::from_secs(20), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(vec![]).unwrap();
            }
            _ => panic!("invalid action received"),
        }

        // verify another floodfill request is sent
        match tokio::time::timeout(Duration::from_secs(20), netdb_rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            NetDbAction::GetClosestFloodfills { tx, .. } => {
                tx.send(
                    floodfills
                        .iter()
                        .map(|(router_id, key)| (router_id.clone(), key.public()))
                        .collect(),
                )
                .unwrap();
            }
            _ => panic!("invalid action received"),
        }

        assert!(tokio::time::timeout(Duration::from_secs(5), netdb_rx.recv()).await.is_err());
    }

    #[tokio::test]
    async fn all_floodfills_used_for_store() {
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            ProfileStorage::new(&[], &[]),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..3)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut store_floodfills = floodfills.clone();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(40)) => panic!("timeout"),
            }
        }

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        // remove the floodfill from the set of floodfills since is shouldn't be for
                        // verification
                        let key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                                assert!(store_floodfills.remove(&router_id).is_some());
                            }
                            _ => panic!("invalid message type"),
                        }

                        break
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timeout"),
            }
        }

        // process lookup messages by ignoring them and verify that store is sent to two more
        // floodfills
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);
                            }
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                                assert!(store_floodfills.remove(&router_id).is_some());

                                if store_floodfills.is_empty() {
                                    break
                                }
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("invalid event"),
                },
                _ = tokio::time::sleep(Duration::from_secs(60)) => panic!("timeout"),
            }
        }
    }

    #[tokio::test]
    async fn extra_floodfills_removed() {
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels,
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized),
        );

        let floodfills = (0..20)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));
        assert!(manager.floodfills.is_empty());

        // process the initial floodfill request
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                    }
                    _ => panic!("invalid action received"),
                },
                _ = tokio::time::sleep(Duration::from_secs(20)) => break,
            }
        }

        assert_eq!(manager.floodfills.len(), NUM_CLOSEST_FLOODFILLS);
    }

    #[tokio::test]
    async fn new_lease_set_published() {
        crate::util::init_logger();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let sender = tp_handle.sender();
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let noise_ctx = NoiseContext::new(
            StaticPrivateKey::random(MockRuntime::rng()),
            Bytes::from(RouterId::random().to_vec()),
        );
        let (lease_set, signing_key) = LeaseSet2::random();
        let tunnels = lease_set.leases.clone();
        let destination_id = lease_set.header.destination.id();
        let key = Bytes::from(destination_id.to_vec());
        let serialized = lease_set.serialize(&signing_key);
        let profile_storage = ProfileStorage::new(&[], &[]);
        let mut manager = LeaseSetManager::<MockRuntime>::new(
            tunnels.clone(),
            destination_id,
            sender,
            3usize,
            netdb_handle,
            noise_ctx,
            profile_storage.clone(),
            false,
            Bytes::from(serialized.clone()),
        );

        let floodfills = (0..5)
            .map(|_| {
                (
                    RouterId::random(),
                    StaticPrivateKey::random(MockRuntime::rng()),
                )
            })
            .collect::<HashMap<_, _>>();

        // process initial database store message
        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                    }
                    _ => panic!("invalid action received"),
                },
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        // remove the floodfill from the set of floodfills since is shouldn't be for
                        // verification
                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database store to lease set publisher
                                manager.register_database_store(lookup_key);
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(30)) => panic!("timeout"),
            }
        }

        assert!(std::matches!(manager.state, PublishState::Inactive));

        // mark current tunnels as expiring
        assert_eq!(manager.tunnels.len(), tunnels.len());

        for Lease { tunnel_id, .. } in &tunnels {
            manager.register_expiring_inbound_tunnel(*tunnel_id);
        }
        assert!(manager.tunnels.is_empty());
        assert_eq!(manager.expiring_tunnels.len(), tunnels.len());

        // register new inbound tunnels
        let new_tunnels = vec![Lease::random(), Lease::random(), Lease::random()];
        manager.register_inbound_tunnel(new_tunnels[0].clone());
        assert!(std::matches!(
            manager.state,
            PublishState::AwaitingTunnels { .. }
        ));

        manager.register_inbound_tunnel(new_tunnels[1].clone());
        assert!(std::matches!(
            manager.state,
            PublishState::AwaitingTunnels { .. }
        ));

        manager.register_inbound_tunnel(new_tunnels[2].clone());
        assert!(std::matches!(manager.state, PublishState::AwaitingLeaseSet));

        // register lease set and verify it's published
        manager.register_lease_set(Bytes::from(serialized));
        assert!(std::matches!(
            manager.state,
            PublishState::GetClosestFloodfills { .. }
        ));

        loop {
            tokio::select! {
                _ = &mut manager => {}
                event = netdb_rx.recv() => match event.unwrap() {
                    NetDbAction::GetClosestFloodfills { tx, .. } => {
                        tx.send(
                            floodfills
                                .iter()
                                .map(|(router_id, key)| (router_id.clone(), key.public()))
                                .collect(),
                        )
                        .unwrap();
                    }
                    _ => panic!("invalid action received"),
                },
                event = tm_rx.recv() => match event.unwrap() {
                    TunnelMessage::RouterDeliveryViaRoute {
                        outbound_tunnel: None,
                        router_id,
                        message,
                    } => {
                        let message = Message::parse_standard(&message).unwrap();
                        assert_eq!(message.message_type, MessageType::Garlic);

                        // remove the floodfill from the set of floodfills since is shouldn't be for
                        // verification
                        let static_key = floodfills.get(&router_id).unwrap();

                        let mut garlic = GarlicHandler::<MockRuntime>::new(
                            NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                            MockRuntime::register_metrics(vec![], None),
                        );
                        let GarlicDeliveryInstructions::Local { message } = garlic
                            .handle_message(message)
                            .unwrap()
                            .filter(|message| {
                                std::matches!(message, GarlicDeliveryInstructions::Local { .. })
                            })
                            .collect::<VecDeque<_>>()
                            .pop_front()
                            .expect("to exist")
                        else {
                            panic!("invalid type");
                        };

                        match message.message_type {
                            MessageType::DatabaseStore => {
                                let DatabaseStore { .. } =
                                    DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();
                            }
                            MessageType::DatabaseLookup => {
                                let DatabaseLookup {
                                    key: lookup_key, ..
                                } = DatabaseLookup::parse(&message.payload).unwrap();

                                assert_eq!(key.as_ref(), &lookup_key);

                                // send database store to lease set publisher
                                manager.register_database_store(lookup_key);
                                break;
                            }
                            _ => panic!("invalid message type"),
                        }
                    }
                    _ => panic!("unexpected tunnel message"),
                },
                _ = tokio::time::sleep(Duration::from_secs(30)) => panic!("timeout"),
            }
        }

        assert!(std::matches!(manager.state, PublishState::Inactive));
    }
}
