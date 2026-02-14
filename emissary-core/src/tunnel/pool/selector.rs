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

//! Tunnel/hop selector for exploratory/client tunnels.

use crate::{
    crypto::StaticPublicKey,
    primitives::{RouterId, TransportKind, TunnelId},
    profile::{Bucket, ProfileStorage},
    runtime::Runtime,
    tunnel::pool::TunnelPoolContextHandle,
    util::shuffle,
};

use bytes::Bytes;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{sync::Arc, vec::Vec};
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::selector";

/// Maximum router participation.
const MAX_PARTICIPATION: f64 = 0.33f64;

/// Tunnel selector for a tunnel pool.
///
/// This trait has two implementations: [`ExploratorySelector`] for exploratory tunnel pools and
/// [`ClientSelector`] for client tunnel pools.
///
/// [`ClientSelector`] takes [`ExploratorySelector`] in its constructor, allowing it to utilize
/// exploratory tunnels for tunnel building.
pub trait TunnelSelector: Send + Unpin {
    /// Attempt to select an outbound tunnel for delivery of an inbound tunnel build request.
    ///
    /// Returns `None` if there are no outbound tunnels available.
    fn select_outbound_tunnel(&self) -> Option<(TunnelId, &TunnelPoolContextHandle)>;

    /// Attempt to select an inbound tunnel for reception of an outbound tunnel build reply.
    ///
    /// Returns `None` if there are no inbound tunnels available.
    fn select_inbound_tunnel(&self) -> Option<(TunnelId, RouterId, &TunnelPoolContextHandle)>;

    /// Add a new tunnel into the set of active outbound tunnels.
    fn add_outbound_tunnel(&mut self, tunnel_id: TunnelId, hops: HashSet<RouterId>);

    /// Add a new tunnel into the set of active inbound tunnels.
    fn add_inbound_tunnel(
        &mut self,
        tunnel_id: TunnelId,
        router_id: RouterId,
        hops: HashSet<RouterId>,
    );

    /// Remove tunnel from the set of active outbound tunnels.
    fn remove_outbound_tunnel(&mut self, tunnel_id: &TunnelId);

    /// Remove tunnel from the set of active inbound tunnels.
    fn remove_inbound_tunnel(&mut self, tunnel_id: &TunnelId);

    /// Register tunnel test failure.
    fn register_tunnel_test_failure(&mut self, outbound: &TunnelId, inbound: &TunnelId);

    /// Register tunnel test success.
    fn register_tunnel_test_success(&mut self, outbound: &TunnelId, inbound: &TunnelId);
}

/// Hop selector for a tunnel pool.
///
/// This trait has two implementations: [`ExploratorySelector`] for exploratory tunnel pools and
/// [`ClientSelector`] for client tunnel pools.
pub trait HopSelector: Send + Unpin {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>>;
}

/// Tunnel/hop selector for the exploratory tunnel pool.
///
/// For inbound tunnel builds, an active outbound tunnel from the same pool is used
/// to deliver the build request. For outbound tunnel builds, an active inbound
/// tunnel is selected for the reception of the tunnel build reply.
///
/// If there are no active tunnels, a fake 0-hop inbound/outbound tunnel is used for
/// reception/delivery.
#[derive(Clone)]
pub struct ExploratorySelector<R: Runtime> {
    /// Exploratory tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashMap<TunnelId, (RouterId, HashSet<RouterId>)>>>,

    /// Are tunnels insecure.
    insecure: bool,

    /// Total number of inbound and outbound tunnels, both exploratory and client tunnels.
    num_tunnels: Arc<AtomicUsize>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashMap<TunnelId, HashSet<RouterId>>>>,

    /// Router storage for selecting hops.
    profile_storage: ProfileStorage<R>,

    /// Router participation.
    router_participation: Arc<RwLock<HashMap<RouterId, usize>>>,
}

impl<R: Runtime> ExploratorySelector<R> {
    /// Create new [`ExploratorySelector`].
    pub fn new(
        profile_storage: ProfileStorage<R>,
        handle: TunnelPoolContextHandle,
        insecure: bool,
    ) -> Self {
        Self {
            handle,
            inbound: Default::default(),
            insecure,
            num_tunnels: Default::default(),
            outbound: Default::default(),
            profile_storage,
            router_participation: Default::default(),
        }
    }

    /// Group router addresses of `router_ids` by /16 subnet.
    fn group_by_subnet(&self, router_ids: Vec<RouterId>) -> HashMap<(u8, u8), Vec<RouterId>> {
        // fetch ipv4 addresses of all routers
        let addresses = {
            let reader = self.profile_storage.reader();

            router_ids
                .into_iter()
                .filter_map(|router_id| {
                    // address must exist since the `router_info.is_reachable()` check
                    // above has ensured the router has at least one published address
                    //
                    let addresses = [
                        reader
                            .router_info(&router_id)?
                            .addresses
                            .get(&TransportKind::Ntcp2)
                            .and_then(|address| address.socket_address),
                        reader
                            .router_info(&router_id)?
                            .addresses
                            .get(&TransportKind::Ssu2)
                            .and_then(|address| address.socket_address),
                    ];

                    let addresses = addresses
                        .into_iter()
                        .filter_map(|address| match address? {
                            SocketAddr::V4(address) => Some(*address.ip()),
                            SocketAddr::V6(_) => None,
                        })
                        .collect::<HashSet<_>>();

                    (!addresses.is_empty()).then_some((router_id, addresses))
                })
                .collect::<Vec<_>>()
        };

        // group addresses by /16 subnet
        addresses.into_iter().fold(
            HashMap::<(u8, u8), Vec<RouterId>>::new(),
            |mut grouped, (router_id, addresses)| {
                for address in addresses {
                    let octets = address.octets();
                    grouped.entry((octets[0], octets[1])).or_default().push(router_id.clone());
                }

                grouped
            },
        )
    }

    fn add_tunnel(&self, hops: &HashSet<RouterId>) {
        self.num_tunnels.fetch_add(1usize, Ordering::SeqCst);

        let mut inner = self.router_participation.write();

        hops.iter().for_each(|router_id| {
            *inner.entry(router_id.clone()).or_default() += 1usize;
        });
    }

    fn remove_tunnel(&self, hops: &HashSet<RouterId>) {
        if self.num_tunnels.fetch_sub(1usize, Ordering::SeqCst) == 0 {
            tracing::warn!(
                target: LOG_TARGET,
                ?hops,
                "tried to remove tunnel but no tunnels available",
            );
            debug_assert!(false);
        }

        let mut inner = self.router_participation.write();

        hops.iter().for_each(|router_id| match inner.get_mut(router_id) {
            Some(value) if value == &1 => {
                inner.remove(router_id);
            }
            Some(value) => {
                *value -= 1;
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %router_id,
                    "router doesn't exist in tunenl selector",
                );
                debug_assert!(false);
            }
        });
    }

    fn can_participate(&self, router_id: &RouterId) -> bool {
        let total_tunnels = self.num_tunnels.load(Ordering::SeqCst) as f64;
        if total_tunnels == 0f64 {
            return true;
        }

        let participation = {
            let inner = self.router_participation.read();

            inner.get(router_id).map_or(0f64, |participation| *participation as f64)
        };

        (participation / total_tunnels) < MAX_PARTICIPATION
    }
}

impl<R: Runtime> TunnelSelector for ExploratorySelector<R> {
    fn select_outbound_tunnel(&self) -> Option<(TunnelId, &TunnelPoolContextHandle)> {
        self.outbound.read().keys().next().map(|tunnel_id| (*tunnel_id, &self.handle))
    }

    fn select_inbound_tunnel(&self) -> Option<(TunnelId, RouterId, &TunnelPoolContextHandle)> {
        self.inbound
            .read()
            .iter()
            .next()
            .map(|(tunnel_id, (router_id, _))| (*tunnel_id, router_id.clone(), &self.handle))
    }

    fn add_outbound_tunnel(&mut self, tunnel_id: TunnelId, hops: HashSet<RouterId>) {
        self.add_tunnel(&hops);
        self.outbound.write().insert(tunnel_id, hops);
    }

    fn add_inbound_tunnel(
        &mut self,
        tunnel_id: TunnelId,
        router_id: RouterId,
        hops: HashSet<RouterId>,
    ) {
        self.add_tunnel(&hops);
        self.inbound.write().insert(tunnel_id, (router_id, hops));
    }

    fn remove_outbound_tunnel(&mut self, tunnel_id: &TunnelId) {
        if let Some(hops) = self.outbound.write().remove(tunnel_id) {
            self.remove_tunnel(&hops);
        }
    }

    fn remove_inbound_tunnel(&mut self, tunnel_id: &TunnelId) {
        if let Some((_, hops)) = self.inbound.write().remove(tunnel_id) {
            self.remove_tunnel(&hops);
        }
    }

    fn register_tunnel_test_failure(&mut self, outbound: &TunnelId, inbound: &TunnelId) {
        {
            let inner = self.outbound.read();

            match inner.get(outbound) {
                Some(hops) => hops.iter().for_each(|router_id| {
                    self.profile_storage.tunnel_test_failed(router_id);
                }),
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?outbound,
                        "cannot register tunnel test failure, outbound tunnel doesn't exist",
                    );
                    debug_assert!(false);
                }
            }
        }

        {
            let inner = self.inbound.read();

            match inner.get(inbound) {
                Some((_, hops)) => hops.iter().for_each(|router_id| {
                    self.profile_storage.tunnel_test_failed(router_id);
                }),
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?inbound,
                        "cannot register tunnel test failure, inbound tunnel doesn't exist",
                    );
                    debug_assert!(false);
                }
            }
        }
    }

    fn register_tunnel_test_success(&mut self, outbound: &TunnelId, inbound: &TunnelId) {
        {
            let inner = self.outbound.read();

            match inner.get(outbound) {
                Some(hops) => hops.iter().for_each(|router_id| {
                    self.profile_storage.tunnel_test_succeeded(router_id);
                }),
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?outbound,
                        "cannot register tunnel test succeeded, outbound tunnel doesn't exist",
                    );
                    debug_assert!(false);
                }
            }
        }

        {
            let inner = self.inbound.read();

            match inner.get(inbound) {
                Some((_, hops)) => hops.iter().for_each(|router_id| {
                    self.profile_storage.tunnel_test_succeeded(router_id);
                }),
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?inbound,
                        "cannot register tunnel test success, inbound tunnel doesn't exist",
                    );
                    debug_assert!(false);
                }
            }
        }
    }
}

impl<R: Runtime> HopSelector for ExploratorySelector<R> {
    // TODO: refactor
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let mut router_ids = self.profile_storage.get_router_ids(
            Bucket::Standard,
            |router_id, router_info, profile| {
                !profile.is_failing::<R>()
                    && router_info.is_reachable()
                    && router_info.is_usable()
                    && (self.insecure || self.can_participate(router_id))
            },
        );

        // insecure tunnels are allowed, don't do safety checks
        if self.insecure {
            shuffle(&mut router_ids, &mut R::rng());

            if router_ids.len() < num_hops {
                let mut extra_router_ids =
                    self.profile_storage.get_router_ids(Bucket::Fast, |_, router_info, profile| {
                        !profile.is_failing::<R>()
                            && router_info.is_reachable()
                            && router_info.is_usable()
                    });

                // if there aren't enough routers in the fast bucket,
                // attempt to use untracked routers
                let num_needed = num_hops - router_ids.len();

                if num_needed > extra_router_ids.len() {
                    let untracked = self.profile_storage.get_router_ids(
                        Bucket::Untracked,
                        |_, router_info, profile| {
                            !profile.is_failing::<R>()
                                && router_info.is_reachable()
                                && router_info.is_usable()
                        },
                    );

                    extra_router_ids.extend(untracked);
                    extra_router_ids = extra_router_ids
                        .into_iter()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                }

                // if there aren't enough routers, use failing routers
                if num_needed > extra_router_ids.len() {
                    let failing =
                        self.profile_storage.get_router_ids(Bucket::Any, |_, router_info, _| {
                            router_info.is_reachable()
                        });

                    extra_router_ids.extend(failing);
                    extra_router_ids = extra_router_ids
                        .into_iter()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                }

                if num_needed > extra_router_ids.len() {
                    return None;
                }

                shuffle(&mut extra_router_ids, &mut R::rng());
                router_ids.extend(extra_router_ids.into_iter().take(num_needed));
            }

            router_ids.iter().take(num_hops).for_each(|router_id| {
                self.profile_storage.selected_for_tunnel(router_id);
            });

            let reader = self.profile_storage.reader();
            return Some(
                (0..num_hops)
                    .map(|i| {
                        // router info must exist since it was iterated over above
                        let router_info = reader.router_info(&router_ids[i]).expect("to exist");

                        (
                            // router info
                            router_info.identity.hash().clone(),
                            router_info.identity.static_key().clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
            );
        }

        // group addresses by /16 subnet to prevent having two routers
        // from the same subnet in the same tunnel
        let mut addresses = self.group_by_subnet(router_ids);

        let router_ids = if addresses.len() < num_hops {
            let routers = addresses
                .iter_mut()
                .map(|(subnet, addresses)| {
                    (
                        subnet,
                        addresses[R::rng().next_u32() as usize % addresses.len()].clone(),
                    )
                })
                .collect::<HashMap<_, _>>();

            let fast_router_ids = self.profile_storage.get_router_ids(
                Bucket::Fast,
                |router_id, router_info, profile| {
                    !profile.is_failing::<R>()
                        && router_info.is_reachable()
                        && router_info.is_usable()
                        && self.can_participate(router_id)
                },
            );

            // group fast routers by subnet and filter out subnets which the already-selected
            // routers are part of
            let fast_router_addresses = self
                .group_by_subnet(fast_router_ids)
                .into_iter()
                .filter_map(|(subnet, fast_routers)| {
                    (!routers.contains_key(&subnet)).then_some((subnet, fast_routers))
                })
                .collect::<HashMap<_, _>>();

            let untracked = (routers.len() + fast_router_addresses.len() < num_hops).then(|| {
                let untracked_router_ids = self.profile_storage.get_router_ids(
                    Bucket::Untracked,
                    |router_id, router_info, profile| {
                        !profile.is_failing::<R>()
                            && router_info.is_reachable()
                            && router_info.is_usable()
                            && self.can_participate(router_id)
                    },
                );

                // group untracked routers by subnet and filter out subnets which the
                // already-selected routers are part of
                self.group_by_subnet(untracked_router_ids)
                    .into_iter()
                    .filter_map(|(subnet, untracked_routers)| {
                        (!routers.contains_key(&subnet)
                            && !fast_router_addresses.contains_key(&subnet))
                        .then_some((subnet, untracked_routers))
                    })
                    .collect::<HashMap<_, _>>()
            });

            let failing = (routers.len()
                + fast_router_addresses.len()
                + untracked.as_ref().map_or(0usize, |untracked| untracked.len())
                < num_hops)
                .then(|| {
                    let failing_router_ids = self.profile_storage.get_router_ids(
                        Bucket::Any,
                        |router_id, router_info, _| {
                            router_info.is_reachable() && self.can_participate(router_id)
                        },
                    );

                    // group routers by subnet and filter out subnets which the
                    // already-selected routers are part of
                    self.group_by_subnet(failing_router_ids)
                        .into_iter()
                        .filter_map(|(subnet, failing_routers)| {
                            (!routers.contains_key(&subnet)
                                && !fast_router_addresses.contains_key(&subnet)
                                && !untracked.as_ref().expect("to exist").contains_key(&subnet))
                            .then_some((subnet, failing_routers))
                        })
                        .collect::<HashMap<_, _>>()
                });

            if routers.len()
                + fast_router_addresses.len()
                + untracked.as_ref().map_or(0usize, |untracked| untracked.len())
                + failing.as_ref().map_or(0usize, |failing| failing.len())
                < num_hops
            {
                return None;
            }

            let mut fast_router_addresses: Vec<RouterId> = fast_router_addresses
                .into_iter()
                .map(|(_, mut routers)| routers.pop().expect("to exist"))
                .collect::<Vec<_>>();
            let mut routers = routers.into_iter().map(|(_, router)| router).collect::<Vec<_>>();

            shuffle(&mut routers, &mut R::rng());
            shuffle(&mut fast_router_addresses, &mut R::rng());

            routers.extend(fast_router_addresses);

            if let Some(untracked) = untracked {
                let mut untracked: Vec<RouterId> = untracked
                    .into_iter()
                    .map(|(_, mut routers)| routers.pop().expect("to exist"))
                    .collect::<Vec<_>>();

                shuffle(&mut untracked, &mut R::rng());
                routers.extend(untracked);
            }

            if let Some(failing) = failing {
                let mut failing: Vec<RouterId> = failing
                    .into_iter()
                    .map(|(_, mut routers)| routers.pop().expect("to exist"))
                    .collect::<Vec<_>>();

                shuffle(&mut failing, &mut R::rng());
                routers.extend(failing);
            }

            routers
        } else {
            // select random router from each subnet and shuffle selected routers
            let mut routers = addresses
                .into_iter()
                .map(|(_, addresses)| {
                    addresses[R::rng().next_u32() as usize % addresses.len()].clone()
                })
                .collect::<Vec<_>>();

            shuffle(&mut routers, &mut R::rng());
            routers
        };

        // register tunnel selection in each router's profile
        //
        // these are used to calculate the participation ratio, i.e., how often each router
        // accepts/rejects a tunnel
        router_ids.iter().take(num_hops).for_each(|router_id| {
            self.profile_storage.selected_for_tunnel(router_id);
        });

        let reader = self.profile_storage.reader();
        Some(
            (0..num_hops)
                .map(|i| {
                    // router info must exist since it was iterated over above
                    let router_info = reader.router_info(&router_ids[i]).expect("to exist");

                    (
                        router_info.identity.hash().clone(),
                        router_info.identity.static_key().clone(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    }
}

/// Tunnel/hop selector for a client tunnel pool.
///
/// For inbound tunnel builds, an active outbound tunnel from the same pool is selected for build
/// request delivery. For outbound tunnel builds, an active inbound tunnel is selected for reception
/// of the tunnel build reply.
///
/// If there are no active inbound/outbound tunnels, a tunnel from the exploratory tunnel pool is
/// selected for reception/delivery.
///
/// If there are no active tunnels in the exploratory pool, a fake 0-hop tunnel is used instead.
#[derive(Clone)]
pub struct ClientSelector<R: Runtime> {
    /// Exploratory tunnel pool selector.
    exploratory: ExploratorySelector<R>,

    /// Client tunnel pool handle.
    handle: TunnelPoolContextHandle,

    /// Active inbound tunnels.
    inbound: HashMap<TunnelId, (RouterId, HashSet<RouterId>)>,

    /// Active outbound tunnels.
    outbound: HashMap<TunnelId, HashSet<RouterId>>,
}

impl<R: Runtime> ClientSelector<R> {
    /// Create new [`ClientSelector`].
    pub fn new(exploratory: ExploratorySelector<R>, handle: TunnelPoolContextHandle) -> Self {
        Self {
            exploratory,
            handle,
            inbound: Default::default(),
            outbound: Default::default(),
        }
    }
}

impl<R: Runtime> TunnelSelector for ClientSelector<R> {
    fn select_outbound_tunnel(&self) -> Option<(TunnelId, &TunnelPoolContextHandle)> {
        self.outbound.keys().next().map_or_else(
            || self.exploratory.select_outbound_tunnel(),
            |tunnel_id| Some((*tunnel_id, &self.handle)),
        )
    }

    fn select_inbound_tunnel(&self) -> Option<(TunnelId, RouterId, &TunnelPoolContextHandle)> {
        self.inbound.iter().next().map_or_else(
            || self.exploratory.select_inbound_tunnel(),
            |(tunnel_id, (router_id, _))| Some((*tunnel_id, router_id.clone(), &self.handle)),
        )
    }

    fn add_outbound_tunnel(&mut self, tunnel_id: TunnelId, hops: HashSet<RouterId>) {
        self.exploratory.add_tunnel(&hops);
        self.outbound.insert(tunnel_id, hops);
    }

    fn add_inbound_tunnel(
        &mut self,
        tunnel_id: TunnelId,
        router_id: RouterId,
        hops: HashSet<RouterId>,
    ) {
        self.exploratory.add_tunnel(&hops);
        self.inbound.insert(tunnel_id, (router_id, hops));
    }

    fn remove_outbound_tunnel(&mut self, tunnel_id: &TunnelId) {
        if let Some(hops) = self.outbound.remove(tunnel_id) {
            self.exploratory.remove_tunnel(&hops);
        }
    }

    fn remove_inbound_tunnel(&mut self, tunnel_id: &TunnelId) {
        if let Some((_, hops)) = self.inbound.remove(tunnel_id) {
            self.exploratory.remove_tunnel(&hops);
        }
    }

    fn register_tunnel_test_failure(&mut self, outbound: &TunnelId, inbound: &TunnelId) {
        match self.outbound.get(outbound) {
            Some(hops) => hops.iter().for_each(|router_id| {
                self.exploratory.profile_storage.tunnel_test_failed(router_id);
            }),
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?outbound,
                    "cannot register tunnel test failure, outbound tunnel doesn't exist",
                );
                debug_assert!(false);
            }
        }

        match self.inbound.get(inbound) {
            Some((_, hops)) => hops.iter().for_each(|router_id| {
                self.exploratory.profile_storage.tunnel_test_failed(router_id);
            }),
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?inbound,
                    "cannot register tunnel test failure, inbound tunnel doesn't exist",
                );
                debug_assert!(false);
            }
        }
    }

    fn register_tunnel_test_success(&mut self, outbound: &TunnelId, inbound: &TunnelId) {
        match self.outbound.get(outbound) {
            Some(hops) => hops.iter().for_each(|router_id| {
                self.exploratory.profile_storage.tunnel_test_succeeded(router_id);
            }),
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?outbound,
                    "cannot register tunnel test succeeded, outbound tunnel doesn't exist",
                );
                debug_assert!(false);
            }
        }

        match self.inbound.get(inbound) {
            Some((_, hops)) => hops.iter().for_each(|router_id| {
                self.exploratory.profile_storage.tunnel_test_succeeded(router_id);
            }),
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?inbound,
                    "cannot register tunnel test success, inbound tunnel doesn't exist",
                );
                debug_assert!(false);
            }
        }
    }
}

impl<R: Runtime> HopSelector for ClientSelector<R> {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let mut router_ids = self.exploratory.profile_storage.get_router_ids(
            Bucket::Fast,
            |router_id, router_info, profile| {
                !profile.is_failing::<R>()
                    && router_info.is_reachable()
                    && router_info.is_usable()
                    && (self.exploratory.insecure || self.exploratory.can_participate(router_id))
            },
        );

        // insecure tunnels are allowed, don't do safety checks
        if self.exploratory.insecure {
            shuffle(&mut router_ids, &mut R::rng());

            if router_ids.len() < num_hops {
                let mut extra_router_ids = self.exploratory.profile_storage.get_router_ids(
                    Bucket::Standard,
                    |_, router_info, profile| {
                        !profile.is_failing::<R>()
                            && router_info.is_reachable()
                            && router_info.is_usable()
                    },
                );

                // if there aren't enough routers in the fast bucket,
                // attempt to use untracked routers
                let num_needed = num_hops - router_ids.len();

                if num_needed > extra_router_ids.len() {
                    let untracked = self.exploratory.profile_storage.get_router_ids(
                        Bucket::Untracked,
                        |_, router_info, profile| {
                            !profile.is_failing::<R>()
                                && router_info.is_reachable()
                                && router_info.is_usable()
                        },
                    );

                    extra_router_ids.extend(untracked);
                    extra_router_ids = extra_router_ids
                        .into_iter()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                }

                // if there aren't enough routers, use failing routers
                if num_needed > extra_router_ids.len() {
                    let failing = self
                        .exploratory
                        .profile_storage
                        .get_router_ids(Bucket::Any, |_, router_info, _| {
                            router_info.is_reachable()
                        });

                    extra_router_ids.extend(failing);
                    extra_router_ids = extra_router_ids
                        .into_iter()
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                }

                if num_needed > extra_router_ids.len() {
                    return None;
                }

                router_ids.extend(extra_router_ids.into_iter().take(num_needed));
            }

            router_ids.iter().take(num_hops).for_each(|router_id| {
                self.exploratory.profile_storage.selected_for_tunnel(router_id);
            });

            let reader = self.exploratory.profile_storage.reader();
            return Some(
                (0..num_hops)
                    .map(|i| {
                        // router info must exist since it was iterated over above
                        let router_info = reader.router_info(&router_ids[i]).expect("to exist");

                        (
                            router_info.identity.hash().clone(),
                            router_info.identity.static_key().clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
            );
        }

        // group addresses by /16 subnet to prevent having two routers
        // from the same subnet in the same tunnel
        let mut addresses = self.exploratory.group_by_subnet(router_ids);

        let router_ids = if addresses.len() < num_hops {
            let routers = addresses
                .iter_mut()
                .map(|(subnet, addresses)| {
                    (
                        subnet,
                        addresses[R::rng().next_u32() as usize % addresses.len()].clone(),
                    )
                })
                .collect::<HashMap<_, _>>();

            let standard_router_ids = self.exploratory.profile_storage.get_router_ids(
                Bucket::Standard,
                |router_id, router_info, profile| {
                    !profile.is_failing::<R>()
                        && router_info.is_reachable()
                        && router_info.is_usable()
                        && self.exploratory.can_participate(router_id)
                },
            );

            // group standard routers by subnet and filter out subnets which the already-selected
            // routers are part of
            let standard_router_addresses = self
                .exploratory
                .group_by_subnet(standard_router_ids)
                .into_iter()
                .filter_map(|(subnet, standard_routers)| {
                    (!routers.contains_key(&subnet)).then_some((subnet, standard_routers))
                })
                .collect::<HashMap<_, _>>();

            let untracked =
                (routers.len() + standard_router_addresses.len() < num_hops).then(|| {
                    let untracked_router_ids = self.exploratory.profile_storage.get_router_ids(
                        Bucket::Untracked,
                        |router_id, router_info, profile| {
                            !profile.is_failing::<R>()
                                && router_info.is_reachable()
                                && router_info.is_usable()
                                && self.exploratory.can_participate(router_id)
                        },
                    );

                    // group untracked routers by subnet and filter out subnets which the
                    // already-selected routers are part of
                    self.exploratory
                        .group_by_subnet(untracked_router_ids)
                        .into_iter()
                        .filter_map(|(subnet, untracked_routers)| {
                            (!routers.contains_key(&subnet)
                                && !standard_router_addresses.contains_key(&subnet))
                            .then_some((subnet, untracked_routers))
                        })
                        .collect::<HashMap<_, _>>()
                });

            let failing = (routers.len()
                + standard_router_addresses.len()
                + untracked.as_ref().map_or(0usize, |untracked| untracked.len())
                < num_hops)
                .then(|| {
                    let failing_router_ids = self.exploratory.profile_storage.get_router_ids(
                        Bucket::Any,
                        |router_id, router_info, _| {
                            router_info.is_reachable()
                                && self.exploratory.can_participate(router_id)
                        },
                    );

                    // group routers by subnet and filter out subnets which the
                    // already-selected routers are part of
                    self.exploratory
                        .group_by_subnet(failing_router_ids)
                        .into_iter()
                        .filter_map(|(subnet, failing_routers)| {
                            (!routers.contains_key(&subnet)
                                && !standard_router_addresses.contains_key(&subnet)
                                && !untracked.as_ref().expect("to exist").contains_key(&subnet))
                            .then_some((subnet, failing_routers))
                        })
                        .collect::<HashMap<_, _>>()
                });

            if routers.len()
                + standard_router_addresses.len()
                + untracked.as_ref().map_or(0usize, |untracked| untracked.len())
                + failing.as_ref().map_or(0usize, |failing| failing.len())
                < num_hops
            {
                return None;
            }

            let mut standard_router_addresses: Vec<RouterId> = standard_router_addresses
                .into_iter()
                .map(|(_, mut routers)| routers.pop().expect("to exist"))
                .collect::<Vec<_>>();
            let mut routers = routers.into_iter().map(|(_, router)| router).collect::<Vec<_>>();

            shuffle(&mut routers, &mut R::rng());
            shuffle(&mut standard_router_addresses, &mut R::rng());

            routers.extend(standard_router_addresses);

            if let Some(untracked) = untracked {
                let mut untracked: Vec<RouterId> = untracked
                    .into_iter()
                    .map(|(_, mut routers)| routers.pop().expect("to exist"))
                    .collect::<Vec<_>>();

                shuffle(&mut untracked, &mut R::rng());
                routers.extend(untracked);
            }

            if let Some(failing) = failing {
                let mut failing: Vec<RouterId> = failing
                    .into_iter()
                    .map(|(_, mut routers)| routers.pop().expect("to exist"))
                    .collect::<Vec<_>>();

                shuffle(&mut failing, &mut R::rng());
                routers.extend(failing);
            }

            routers
        } else {
            // select random router from each subnet and shuffle selected routers
            let mut routers = addresses
                .into_iter()
                .map(|(_, addresses)| {
                    addresses[R::rng().next_u32() as usize % addresses.len()].clone()
                })
                .collect::<Vec<_>>();

            shuffle(&mut routers, &mut R::rng());
            routers
        };

        // register tunnel selection in each router's profile
        //
        // these are used to calculate the participation ratio, i.e., how often each router
        // accepts/rejects a tunnel
        router_ids.iter().take(num_hops).for_each(|router_id| {
            self.exploratory.profile_storage.selected_for_tunnel(router_id);
        });

        let reader = self.exploratory.profile_storage.reader();
        Some(
            (0..num_hops)
                .map(|i| {
                    // router info must exist since it was iterated over above
                    let router_info = reader.router_info(&router_ids[i]).expect("to exist");

                    (
                        router_info.identity.hash().clone(),
                        router_info.identity.static_key().clone(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{Capabilities, RouterAddress, RouterInfoBuilder, Str},
        runtime::mock::MockRuntime,
        tunnel::pool::TunnelPoolBuildParameters,
    };

    #[tokio::test]
    async fn not_enough_routers_for_exploratory_tunnel() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );
        assert!(selector.select_hops(5).is_none());
    }

    #[tokio::test]
    async fn select_exploratory_hops() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..10 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );

        // select hops 5 times and verify that the same set of hops is not selected every time
        let hops = selector.select_hops(3).unwrap();

        let (num_same, _) = (0..5).fold((0usize, hops), |(count, prev), _| {
            let hops = selector.select_hops(3).unwrap();
            if prev
                .iter()
                .zip(hops.iter())
                .all(|(a, b)| a.0 == b.0 && a.1.to_vec() == b.1.to_vec())
            {
                (count + 1, hops)
            } else {
                (count, hops)
            }
        });
        assert_ne!(num_same, 5);
    }

    #[tokio::test]
    async fn use_fast_routers_as_fallback() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for i in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.16{i}.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XfR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.17{i}.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );

        // there are only 3 standard routers so 2 routers must be fast
        let mut standard = 0usize;
        let mut fast = 0usize;
        let hops = selector.select_hops(5).unwrap();
        let reader = profile_storage.reader();

        for (hash, _) in hops {
            let router_info = reader.router_info(&RouterId::from(hash)).unwrap();

            if router_info.capabilities.is_fast() {
                fast += 1;
            } else {
                standard += 1;
            }
        }

        assert_eq!(standard, 3);
        assert_eq!(fast, 2);
    }

    #[tokio::test]
    async fn not_enough_routers_for_client_tunnel() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("X")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());
        assert!(selector.select_hops(5).is_none());
    }

    #[tokio::test]
    async fn select_client_hops() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..10 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("OR")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        // select hops 5 times and verify that the same set of hops is not selected every time
        let hops = selector.select_hops(3).unwrap();

        let (num_same, _) = (0..5).fold((0usize, hops), |(count, prev), _| {
            let hops = selector.select_hops(3).unwrap();
            if prev
                .iter()
                .zip(hops.iter())
                .all(|(a, b)| a.0 == b.0 && a.1.to_vec() == b.1.to_vec())
            {
                (count + 1, hops)
            } else {
                (count, hops)
            }
        });
        assert_ne!(num_same, 5);
    }

    #[tokio::test]
    async fn use_standard_routers_as_fallback() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XRf")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        // there are only 3 fast routers so 2 routers must be standard
        let mut standard = 0usize;
        let mut fast = 0usize;
        let hops = selector.select_hops(5).unwrap();
        let reader = profile_storage.reader();

        for (hash, _) in hops {
            let router_info = reader.router_info(&RouterId::from(hash)).unwrap();

            if router_info.capabilities.is_fast() {
                fast += 1;
            } else {
                standard += 1;
            }
        }

        assert_eq!(standard, 2);
        assert_eq!(fast, 3);
    }

    #[tokio::test]
    async fn exploratory_not_enough_routers_in_distinct_subnets() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 addresses from 192.168.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.168.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        // 5 addresses from 172.20.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("172.10.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );

        // since three hops were requested but there were only two subnets,
        // the request cannot be fulfilled
        assert!(selector.select_hops(3).is_none());
    }

    #[tokio::test]
    async fn client_not_enough_routers_in_distinct_subnets() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 addresses from 192.168.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.168.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        // 5 addresses from 172.20.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XfR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("172.10.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        // since three hops were requested but there were only two subnets,
        // the request cannot be fulfilled
        assert!(selector.select_hops(3).is_none());
    }

    #[tokio::test]
    async fn exploratory_not_enough_reachable_routers() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 unreachable standard routers
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LU")).unwrap();
                info.addresses.insert(
                    TransportKind::Ntcp2,
                    RouterAddress::new_unpublished_ntcp2([i as u8; 32], 2000 + i),
                );
                info
            });
        }

        // 3 reachable fast routers
        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("OR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );

        // 5 hops requested but only 3 routers in the standard category
        assert!(selector.select_hops(5).is_none());
    }

    #[tokio::test]
    async fn client_not_enough_standard_or_fast_routers() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 3 reachable standard routers
        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        // 5 unreachable fast routers
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("OU")).unwrap();
                info.addresses.insert(
                    TransportKind::Ntcp2,
                    RouterAddress::new_unpublished_ntcp2([i as u8; 32], 2000 + i),
                );
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        // 5 hops requested but only 3 routers in the standard category
        assert!(selector.select_hops(5).is_none());
    }

    #[tokio::test]
    async fn exploratory_insecure_tunnels_not_enough_distinct_subnets() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 addresses from 192.168.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.168.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        // 5 addresses from 172.20.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("172.10.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            true,
        );

        let hops = selector.select_hops(3).unwrap();
        let reader = profile_storage.reader();
        assert!(hops.into_iter().all(|(hash, _)| reader
            .router_info(&RouterId::from(hash))
            .unwrap()
            .capabilities
            .is_standard()));
    }

    #[tokio::test]
    async fn client_insecure_tunnels_not_enough_distinct_subnets() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 addresses from 192.168.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.168.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        // 5 addresses from 172.20.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XfR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("172.10.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            true,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        let hops = selector.select_hops(3).unwrap();
        let reader = profile_storage.reader();
        assert!(hops.into_iter().all(|(hash, _)| reader
            .router_info(&RouterId::from(hash))
            .unwrap()
            .capabilities
            .is_fast()));
    }

    #[tokio::test]
    async fn exploratory_insecure_tunnels_not_enough_distinct_subnets_or_standard_peers() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 addresses from 192.168.x.x subnet
        for i in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.168.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        // 5 addresses from 172.20.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XfR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("172.10.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            true,
        );

        let hops = selector.select_hops(5usize).unwrap();
        let (num_same, _) = (0..5).fold((0usize, hops), |(count, prev), _| {
            let mut standard = 0usize;
            let mut fast = 0usize;
            let hops = selector.select_hops(5).unwrap();
            let reader = profile_storage.reader();

            for (hash, _) in &hops {
                let router_info = reader.router_info(&RouterId::from(hash)).unwrap();

                if router_info.capabilities.is_fast() {
                    fast += 1;
                } else {
                    standard += 1;
                }
            }

            assert_eq!(standard, 3);
            assert_eq!(fast, 2);

            if prev
                .iter()
                .zip(hops.iter())
                .all(|(a, b)| a.0 == b.0 && a.1.to_vec() == b.1.to_vec())
            {
                (count + 1, hops)
            } else {
                (count, hops)
            }
        });
        assert_ne!(num_same, 5);
    }

    #[tokio::test]
    async fn client_insecure_tunnels_not_enough_distinct_subnets_or_fast_peers() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        // 5 addresses from 192.168.x.x subnet
        for i in 0..5 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("192.168.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        // 5 addresses from 172.20.x.x subnet
        for i in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XfR")).unwrap();
                info.addresses = HashMap::from_iter([(
                    TransportKind::Ntcp2,
                    RouterAddress::new_published_ntcp2(
                        [1u8; 32],
                        [1u8; 16],
                        8888,
                        format!("172.10.{}.{}", i + 5, i + 10).parse().unwrap(),
                    ),
                )]);
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            true,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        let hops = selector.select_hops(5usize).unwrap();
        let (num_same, _) = (0..5).fold((0usize, hops), |(count, prev), _| {
            let mut standard = 0usize;
            let mut fast = 0usize;
            let hops = selector.select_hops(5).unwrap();
            let reader = profile_storage.reader();

            for (hash, _) in &hops {
                let router_info = reader.router_info(&RouterId::from(hash)).unwrap();

                if router_info.capabilities.is_fast() {
                    fast += 1;
                } else {
                    standard += 1;
                }
            }

            assert_eq!(fast, 3);
            assert_eq!(standard, 2);

            if prev
                .iter()
                .zip(hops.iter())
                .all(|(a, b)| a.0 == b.0 && a.1.to_vec() == b.1.to_vec())
            {
                (count + 1, hops)
            } else {
                (count, hops)
            }
        });
        assert_ne!(num_same, 5);
    }

    #[tokio::test]
    async fn router_participation() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());
        let routers = (0..11).map(|_| RouterId::random()).collect::<Vec<_>>();

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );
        assert!(routers.iter().all(|router_id| selector.can_participate(router_id)));

        selector.add_tunnel(&HashSet::from_iter([
            routers[0].clone(),
            routers[1].clone(),
            routers[2].clone(),
        ]));
        for (i, router_id) in routers.iter().enumerate() {
            if i < 3 {
                assert!(!selector.can_participate(router_id));
            } else {
                assert!(selector.can_participate(router_id));
            }
        }

        selector.add_tunnel(&HashSet::from_iter([
            routers[3].clone(),
            routers[4].clone(),
            routers[5].clone(),
        ]));
        for (i, router_id) in routers.iter().enumerate() {
            if i < 6 {
                assert!(!selector.can_participate(router_id));
            } else {
                assert!(selector.can_participate(router_id));
            }
        }

        selector.add_tunnel(&HashSet::from_iter([
            routers[6].clone(),
            routers[7].clone(),
            routers[8].clone(),
        ]));
        for (i, router_id) in routers.iter().enumerate() {
            if i < 9 {
                assert!(!selector.can_participate(router_id));
            } else {
                assert!(selector.can_participate(router_id));
            }
        }

        // add shorter tunnel with the remaining two routers
        // and verify that after it, routers can participate again

        selector.add_tunnel(&HashSet::from_iter([
            routers[9].clone(),
            routers[10].clone(),
        ]));
        for (_, router_id) in routers.iter().enumerate() {
            assert!(selector.can_participate(router_id));
        }

        // remove the first tunnel, verify those hops can participate
        // whereas other routers cannot
        selector.remove_tunnel(&HashSet::from_iter([
            routers[0].clone(),
            routers[1].clone(),
            routers[2].clone(),
        ]));
        for (i, router_id) in routers.iter().enumerate() {
            if i < 3 {
                assert!(selector.can_participate(router_id));
            } else {
                assert!(!selector.can_participate(router_id));
            }
        }
    }

    #[tokio::test]
    async fn exploratory_enforce_max_participation() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..6 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );

        let hops1 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops1);

        let hops2 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops2);

        assert!(hops1.iter().all(|key| !hops2.contains(key)));
        assert!(selector.select_hops(3).is_none());
    }

    #[tokio::test]
    async fn exploratory_ignore_max_participation_for_insecure_tunnels() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..6 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            true,
        );

        let hops1 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops1);

        let hops2 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops2);

        assert!(selector.select_hops(3).is_some());
    }

    #[tokio::test]
    async fn exploratory_enforce_max_participation_with_fast_fallbacks() {
        let build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..6 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XR")).unwrap();
                info
            });
        }

        let selector = ExploratorySelector::new(
            profile_storage.clone(),
            build_parameters.context_handle.clone(),
            false,
        );

        let hops1 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops1);
        let hops2 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops2);
        let hops3 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.add_tunnel(&hops3);

        assert!(hops1.iter().all(|router_id| selector
            .profile_storage
            .get(router_id)
            .unwrap()
            .capabilities
            .is_standard()));
        assert!(hops2.iter().all(|router_id| selector
            .profile_storage
            .get(router_id)
            .unwrap()
            .capabilities
            .is_standard()));
        assert!(hops3.iter().all(|router_id| selector
            .profile_storage
            .get(router_id)
            .unwrap()
            .capabilities
            .is_fast()));

        assert!(hops1.iter().all(|key| !hops2.contains(key)));
        assert!(hops1.iter().all(|key| !hops3.contains(key)));
        assert!(hops2.iter().all(|key| !hops3.contains(key)));
        assert!(selector.select_hops(3).is_none());
    }

    #[tokio::test]
    async fn client_enforce_max_participation() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..6 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XR")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        let hops1 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops1);

        let hops2 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops2);

        assert!(hops1.iter().all(|key| !hops2.contains(key)));
        assert!(selector.select_hops(3).is_none());
    }

    #[tokio::test]
    async fn client_ignore_max_participation_for_insecure_tunnels() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..6 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XR")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            true,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        let hops1 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops1);

        let hops2 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops2);

        assert!(selector.select_hops(3).is_some());
    }

    #[tokio::test]
    async fn client_enforce_max_participation_with_fast_fallbacks() {
        let exploratory_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let client_build_parameters = TunnelPoolBuildParameters::new(Default::default());
        let profile_storage = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());

        for _ in 0..3 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("LR")).unwrap();
                info
            });
        }

        for _ in 0..6 {
            profile_storage.add_router({
                let mut info = RouterInfoBuilder::default().build().0;
                info.capabilities = Capabilities::parse(&Str::from("XR")).unwrap();
                info
            });
        }

        let exploratory = ExploratorySelector::new(
            profile_storage.clone(),
            exploratory_build_parameters.context_handle.clone(),
            false,
        );
        let selector =
            ClientSelector::new(exploratory, client_build_parameters.context_handle.clone());

        let hops1 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops1);
        let hops2 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops2);
        let hops3 = selector
            .select_hops(3)
            .unwrap()
            .into_iter()
            .map(|(key, _)| RouterId::from(key))
            .collect::<HashSet<_>>();
        selector.exploratory.add_tunnel(&hops3);

        assert!(hops1.iter().all(|router_id| selector
            .exploratory
            .profile_storage
            .get(router_id)
            .unwrap()
            .capabilities
            .is_fast()));
        assert!(hops2.iter().all(|router_id| selector
            .exploratory
            .profile_storage
            .get(router_id)
            .unwrap()
            .capabilities
            .is_fast()));
        assert!(hops3.iter().all(|router_id| selector
            .exploratory
            .profile_storage
            .get(router_id)
            .unwrap()
            .capabilities
            .is_standard()));

        assert!(hops1.iter().all(|key| !hops2.contains(key)));
        assert!(hops1.iter().all(|key| !hops3.contains(key)));
        assert!(hops2.iter().all(|key| !hops3.contains(key)));
        assert!(selector.select_hops(3).is_none());
    }
}
