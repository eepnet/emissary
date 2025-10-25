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
    crypto::{base64_decode, base64_encode},
    primitives::{RouterId, RouterInfo},
    runtime::Runtime,
};

use bytes::Bytes;
use hashbrown::{HashMap, HashSet};

#[cfg(feature = "std")]
use parking_lot::{RwLock, RwLockReadGuard};
#[cfg(feature = "no_std")]
use spin::rwlock::{RwLock, RwLockReadGuard};

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{marker::PhantomData, time::Duration};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::profile";

/// Last decline threshold.
///
/// TODO: explain
const LAST_DECLINE_THRESHOLD: Duration = Duration::from_secs(180);

/// How long the router is considered unreachable after last dial failure.
const UNREACHABILITY_THRESHOLD: Duration = Duration::from_secs(180);

/// How often [`ProfileManager`] sorts profiles.
const PROFILE_STORAGE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// How many routers does the high capacity bucket hold.
const NUM_HIGH_CAPACITY_ROUTERS: usize = 100usize;

/// How many routers does the standard bucket hold.
const NUM_STANDARD_ROUTERS: usize = 300usize;

/// Router bucket.
pub enum Bucket {
    /// Any bucket.
    Any,

    /// Fast bucket.
    Fast,

    /// Standard bucket.
    Standard,

    /// Untracked bucket.
    Untracked,
}

/// Router profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Last activity, duration since UNIX epoch.
    pub last_activity: Duration,

    /// Last time a tunnel was declined.
    ///
    /// `None` if there is no information.
    pub last_declined: Option<Duration>,

    /// Last time a dial failed.
    ///
    /// `None` if there is no information.
    pub last_dial_failure: Option<Duration>,

    /// Number of accepted tunnels.
    pub num_accepted: usize,

    /// Number of successful connections.
    pub num_connection: usize,

    /// Number of dial failures.
    pub num_dial_failures: usize,

    /// How many [`DatabaseSearchReply`]s have been received.
    pub num_lookup_failures: usize,

    /// How many [`DatabaseLookup`]s have gone unaswered.
    pub num_lookup_no_responses: usize,

    /// How many [`DatabaseStore`]s have been received.
    pub num_lookup_successes: usize,

    /// Number of rejected tunnels.
    pub num_rejected: usize,

    /// Number of times the router has been selecte for a tunnel.
    pub num_selected: usize,

    /// Number of test failures for tunnels where the router was a selected hop.
    pub num_test_failures: usize,

    /// Number of test successes for tunnels where the router was a selected hop.
    pub num_test_successes: usize,

    /// Number of tunnel build request timeouts where this router was a selected hop.
    pub num_unaswered: usize,
}

impl Profile {
    /// Create new [`Profile`].
    fn new() -> Self {
        Self {
            last_activity: Duration::from_secs(0),
            last_declined: None,
            last_dial_failure: None,
            num_accepted: 0usize,
            num_connection: 0usize,
            num_dial_failures: 0usize,
            num_lookup_failures: 0usize,
            num_lookup_no_responses: 0usize,
            num_lookup_successes: 0usize,
            num_rejected: 0usize,
            num_selected: 0usize,
            num_test_failures: 0usize,
            num_test_successes: 0usize,
            num_unaswered: 0usize,
        }
    }

    /// Has the router recently declined a tunnel.
    ///
    /// Decline is either an actual declination or a failure to respond to a request.
    fn has_recently_declined<R: Runtime>(&self) -> bool {
        self.last_declined.map_or_else(
            || false,
            |last_declined| R::time_since_epoch() - last_declined < LAST_DECLINE_THRESHOLD,
        )
    }

    /// Does the router have low participation rate.
    fn has_low_participation_rate(&self) -> bool {
        4 * self.num_accepted < self.num_rejected
    }

    /// Calculate participation rate for the router.
    fn participation_rate(&self) -> Option<f64> {
        if self.num_accepted + self.num_rejected + self.num_unaswered == 0 {
            return None;
        }

        Some(
            self.num_accepted as f64
                / ((self.num_accepted + self.num_rejected + self.num_unaswered) as f64),
        )
    }

    /// Calculate weighted participation rate for the router.
    fn weighted_participation_rate(&self, avg: f64) -> f64 {
        (self.num_accepted as f64 + 10f64 * avg)
            / ((self.num_accepted + self.num_rejected + self.num_unaswered + 10) as f64)
    }

    /// Is the router considered unreachable.
    fn is_unreachable<R: Runtime>(&self) -> bool {
        self.last_dial_failure.map_or_else(
            || false,
            |last_dial_failure| {
                R::time_since_epoch() - last_dial_failure > UNREACHABILITY_THRESHOLD
            },
        )
    }

    /// Is the router always declining tunnels.
    fn is_always_declining(&self) -> bool {
        self.num_accepted == 0 && self.num_rejected >= 5
    }

    /// Is the router considered failing.
    pub fn is_failing<R: Runtime>(&self) -> bool {
        self.has_recently_declined::<R>()
            || self.is_unreachable::<R>()
            || self.is_always_declining()
            || self.has_low_participation_rate()
    }

    /// Calculate floodfill score from the profile.
    pub fn floodfill_score(&self) -> isize {
        self.num_lookup_failures as isize
            + (self.num_lookup_no_responses as isize * -5isize)
            + (self.num_lookup_successes as isize * 10isize)
    }
}

/// Router info/profile reader.
pub struct Reader<'a> {
    /// Read access to router infos.
    router_infos: RwLockReadGuard<'a, HashMap<RouterId, RouterInfo>>,

    /// Read access to profiles.
    profiles: RwLockReadGuard<'a, HashMap<RouterId, Profile>>,
}

impl Reader<'_> {
    /// Get reference to [`RouterInfo`].
    pub fn router_info(&self, router_id: &RouterId) -> Option<&RouterInfo> {
        self.router_infos.get(router_id)
    }

    /// Get reference to [`Profile`]
    pub fn profile(&self, router_id: &RouterId) -> Option<&Profile> {
        self.profiles.get(router_id)
    }
}

/// Profile storage.
#[derive(Clone)]
pub struct ProfileStorage<R: Runtime> {
    /// Discovered routers.
    discovered_routers: Arc<RwLock<HashMap<RouterId, Vec<u8>>>>,

    /// Untracked routers.
    untracked: Arc<RwLock<HashSet<RouterId>>>,

    /// Fast routers.
    fast: Arc<RwLock<HashSet<RouterId>>>,

    /// Router profiles.
    profiles: Arc<RwLock<HashMap<RouterId, Profile>>>,

    /// Router infos.
    routers: Arc<RwLock<HashMap<RouterId, RouterInfo>>>,

    /// Standard routers.
    standard: Arc<RwLock<HashSet<RouterId>>>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> ProfileStorage<R> {
    /// Create new [`ProfileStorage`].
    pub fn new(routers: &[Vec<u8>], profiles: &[(String, Profile)]) -> Self {
        tracing::info!(
            target: LOG_TARGET,
            num_routers = ?routers.len(),
            num_profiles = ?profiles.len(),
            "initialize profile storage",
        );

        let routers = routers
            .iter()
            .filter_map(|router| {
                RouterInfo::parse(router).map(|router| (router.identity.id(), router)).ok()
            })
            .collect::<HashMap<_, _>>();

        let mut profiles = profiles
            .iter()
            .filter_map(|(router_id, profile)| {
                let router_id =
                    RouterId::from(base64_decode(router_id).expect("valid base64 name"));

                routers.contains_key(&router_id).then_some((router_id, *profile))
            })
            .collect::<HashMap<_, _>>();

        // empty profiles for all routers whose profiles were not found
        routers.keys().for_each(|router_id| {
            if !profiles.contains_key(router_id) {
                profiles.insert(router_id.clone(), Profile::new());
            }
        });

        // split router infos into fast and standard buckets and filter out unusable routers
        let (fast, standard): (Vec<_>, Vec<_>) = routers
            .iter()
            .filter_map(|(router_id, router_info)| {
                if !router_info.is_reachable() || !router_info.capabilities.is_usable() {
                    return None;
                }

                match router_info.capabilities.is_fast() {
                    true => Some((Some(router_id.clone()), None)),
                    false => Some((None, Some(router_id.clone()))),
                }
            })
            .unzip();

        let (fast, untracked) = {
            let (total, routers, untracked) = fast.iter().flatten().fold(
                (0f64, HashSet::<RouterId>::new(), HashSet::<RouterId>::new()),
                |(mut total, mut fast, mut untracked), router_id| {
                    match profiles.get(router_id).expect("to exist").participation_rate() {
                        Some(rate) => {
                            total += rate;
                            fast.insert(router_id.clone());
                        }
                        None => {
                            untracked.insert(router_id.clone());
                        }
                    }

                    (total, fast, untracked)
                },
            );

            if routers.is_empty() {
                (HashSet::new(), untracked)
            } else {
                let avg = total / routers.len() as f64;
                let mut routers = routers
                    .into_iter()
                    .map(|router_id| {
                        // profile must exist since the router's participation rate was calculated
                        let rate = profiles
                            .get(&router_id)
                            .expect("to exist")
                            .weighted_participation_rate(avg);

                        (router_id, rate)
                    })
                    .collect::<Vec<_>>();

                routers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
                let fast = routers
                    .iter()
                    .take(NUM_HIGH_CAPACITY_ROUTERS)
                    .map(|(router_id, _)| router_id.clone())
                    .collect::<HashSet<_>>();
                let untracked = routers
                    .into_iter()
                    .filter_map(|(router_id, _)| (!fast.contains(&router_id)).then_some(router_id))
                    .collect();

                (fast, untracked)
            }
        };

        let standard = standard.into_iter().flatten().chain(untracked).collect::<HashSet<_>>();

        let (standard, untracked) = {
            let (total, routers, untracked) = standard.iter().fold(
                (0f64, HashSet::<RouterId>::new(), HashSet::<RouterId>::new()),
                |(mut total, mut routers, mut untracked), router_id| {
                    match profiles.get(router_id).expect("to exist").participation_rate() {
                        Some(rate) => {
                            total += rate;
                            routers.insert(router_id.clone());
                        }
                        None => {
                            untracked.insert(router_id.clone());
                        }
                    }

                    (total, routers, untracked)
                },
            );

            if routers.is_empty() {
                (HashSet::new(), untracked)
            } else {
                let avg = total / routers.len() as f64;
                let mut routers = routers
                    .into_iter()
                    .map(|router_id| {
                        // profile must exist since the router's participation rate was calculated
                        let rate = profiles
                            .get(&router_id)
                            .expect("to exist")
                            .weighted_participation_rate(avg);

                        (router_id, rate)
                    })
                    .collect::<Vec<_>>();

                routers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
                let standard = routers
                    .iter()
                    .take(NUM_STANDARD_ROUTERS)
                    .map(|(router_id, _)| router_id.clone())
                    .collect::<HashSet<_>>();
                let untracked = routers
                    .into_iter()
                    .filter_map(|(router_id, _)| {
                        (!standard.contains(&router_id)).then_some(router_id)
                    })
                    .collect();

                (standard, untracked)
            }
        };

        let storage = Self {
            discovered_routers: Default::default(),
            fast: Arc::new(RwLock::new(fast)),
            profiles: Arc::new(RwLock::new(profiles)),
            routers: Arc::new(RwLock::new(routers)),
            standard: Arc::new(RwLock::new(standard)),
            untracked: Arc::new(RwLock::new(untracked)),
            _runtime: Default::default(),
        };

        R::spawn(ProfileManager::<R>::new(storage.clone()).run());

        storage
    }

    /// Insert `router` into [`ProfileStorage`].
    pub fn add_router(&self, router_info: RouterInfo) -> bool {
        let router_id = router_info.identity.id();

        {
            let mut fast = self.fast.write();
            let mut standard = self.standard.write();

            if router_info.capabilities.is_fast() {
                fast.insert(router_id.clone());
                standard.remove(&router_id);
            } else {
                standard.insert(router_id.clone());
                fast.remove(&router_id);
            }
        }

        if self.routers.write().insert(router_id.clone(), router_info).is_none() {
            self.profiles.write().insert(router_id, Profile::new());
        }

        true
    }

    /// Register [`RouterInfo`] discovered via `NetDb` queries or direct `DatabaseStore` messages.
    pub fn discover_router(&self, router_info: RouterInfo, serialized: Bytes) -> bool {
        let router_id = router_info.identity.id();

        // if the router was accepted to profile storage, store the serialized router info
        // which is used to make a backup of the router
        if self.add_router(router_info) {
            self.discovered_routers.write().insert(router_id, serialized.to_vec());
            return true;
        }

        false
    }

    /// Get the number of routers currently stored in [`ProfileStorage`].
    pub fn num_routers(&self) -> usize {
        self.routers.read().len()
    }

    // TODO: remove
    // TODO: why?
    pub fn get(&self, router: &RouterId) -> Option<RouterInfo> {
        self.routers.read().get(router).cloned()
    }

    /// Check if [`ProfileStorage`] contains `router_id`.
    pub fn contains(&self, router_id: &RouterId) -> bool {
        self.routers.read().contains_key(router_id)
    }

    /// Get `RouterId`s of those routers that pass `filter`.
    pub fn get_router_ids(
        &self,
        bucket: Bucket,
        filter: impl Fn(&RouterId, &RouterInfo, &Profile) -> bool,
    ) -> Vec<RouterId> {
        let routers = self.routers.read();
        let profiles = self.profiles.read();

        match bucket {
            Bucket::Any => {
                let fast = self.fast.read();
                let standard = self.standard.read();
                let untracked = self.untracked.read();

                fast.iter()
                    .chain(standard.iter())
                    .chain(untracked.iter())
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
            Bucket::Untracked => {
                let untracked = self.untracked.read();

                untracked
                    .iter()
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
            Bucket::Fast => {
                let fast = self.fast.read();

                fast.iter()
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
            Bucket::Standard => {
                let standard = self.standard.read();

                standard
                    .iter()
                    .filter_map(|router_id| {
                        // profile & router info must exist since they're managed by us
                        let profile = profiles.get(router_id).expect("to exist");
                        let router_info = routers.get(router_id).expect("to exist");

                        filter(router_id, router_info, profile).then_some(router_id.clone())
                    })
                    .collect()
            }
        }
    }

    /// Get [`Reader`].
    pub fn reader(&self) -> Reader<'_> {
        Reader {
            router_infos: self.routers.read(),
            profiles: self.profiles.read(),
        }
    }

    /// Returns `true` if router identified by `RouterId` is a floodfill router.
    ///
    /// Returns `false` if it's not or if the router is not found in [`ProfileManager`].
    pub fn is_floodfill(&self, router_id: &RouterId) -> bool {
        self.routers
            .read()
            .get(router_id)
            .is_some_and(|router_info| router_info.is_floodfill())
    }

    /// Record that `router_id` was selected for a tunnel.
    pub fn selected_for_tunnel(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_selected += 1;
    }

    /// Record that `router_id`'s participation for a tunnel could not be determined.
    ///
    /// This happens when a build record fails to decrypt, causing the entire build response to be
    /// unparseable and hops following the malformed hop cannot be decrypted and parsed.
    pub fn unselected_for_tunnel(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_selected = profile.num_selected.saturating_sub(1);
    }

    /// Record that `router_id` accepted a tunnel build request.
    pub fn tunnel_accepted(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_accepted += 1;
        profile.last_activity = R::time_since_epoch();
        profile.last_declined = None;
    }

    /// Record that `router_id` rejected a tunnel build request.
    pub fn tunnel_rejected(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_rejected += 1;
        profile.last_activity = R::time_since_epoch();
        profile.last_declined = Some(R::time_since_epoch());
    }

    /// Record that `router_id` failed to answer a tunnel build request.
    pub fn tunnel_not_answered(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_unaswered += 1;
        profile.last_activity = R::time_since_epoch();
        profile.last_declined = Some(R::time_since_epoch());
    }

    /// Record test success for a tunnel that `router_id` was a participant of.
    pub fn tunnel_test_succeeded(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_test_successes += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record test failure for a tunnel that `router_id` was a participant of.
    pub fn tunnel_test_failed(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        // profile must exist since it's controlled by us
        let profile = inner.get_mut(router_id).expect("to exist");

        profile.num_test_failures += 1;
        profile.last_activity = R::time_since_epoch();
    }

    /// Record dial success for `router_id`.
    ///
    /// Profile might not exist if this is an inbound connection.
    pub fn dial_succeeded(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        match inner.get_mut(router_id) {
            Some(profile) => {
                profile.num_connection += 1;
                profile.last_activity = R::time_since_epoch();
            }
            None => {
                let mut profile = Profile::new();
                profile.num_connection += 1;
                profile.last_activity = R::time_since_epoch();

                inner.insert(router_id.clone(), profile);
            }
        }
    }

    /// Record dial failure for `router_id`.
    ///
    /// Profile might not exist if this is an inbound connection.
    pub fn dial_failed(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        match inner.get_mut(router_id) {
            Some(profile) => {
                profile.num_dial_failures += 1;
                profile.last_activity = R::time_since_epoch();
                profile.last_dial_failure = Some(profile.last_activity);
            }
            None => {
                let mut profile = Profile::new();
                profile.num_dial_failures += 1;
                profile.last_activity = R::time_since_epoch();
                profile.last_dial_failure = Some(profile.last_activity);

                inner.insert(router_id.clone(), profile);
            }
        }
    }

    /// Record a non-respone to a lease set/router info query.
    pub fn database_lookup_no_response(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        if let Some(profile) = inner.get_mut(router_id) {
            profile.num_lookup_no_responses += 1;
        }
    }

    /// Record non-respones to a lease set/router info query.
    pub fn database_lookup_success(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        if let Some(profile) = inner.get_mut(router_id) {
            profile.num_lookup_successes += 1;
        }
    }

    /// Record non-respones to a lease set/router
    pub fn database_lookup_failure(&self, router_id: &RouterId) {
        let mut inner = self.profiles.write();

        if let Some(profile) = inner.get_mut(router_id) {
            profile.num_lookup_failures += 1;
        }
    }

    /// Get backup of [`ProfileStorage`].
    pub fn backup(&self) -> Vec<(String, Option<Vec<u8>>, Profile)> {
        let profiles = self.profiles.read().clone();
        let mut inner = self.discovered_routers.write();

        profiles
            .into_iter()
            .map(|(router_id, profile)| {
                (
                    base64_encode(router_id.to_vec()),
                    inner.remove(&router_id),
                    profile,
                )
            })
            .collect::<Vec<_>>()
    }

    /// Create new [`ProfileStorage`] from random `routers`.
    ///
    /// Only used in tests.
    #[cfg(test)]
    pub fn from_random(routers: Vec<RouterInfo>) -> Self {
        let routers = routers
            .into_iter()
            .map(|router| (router.identity.id(), router))
            .collect::<HashMap<_, _>>();

        let profiles =
            routers.keys().map(|router_id| (router_id.clone(), Profile::new())).collect();

        // split router infos into fast and standard buckets and filter out unusable routers
        let (fast, standard): (Vec<_>, Vec<_>) = routers
            .iter()
            .filter_map(|(router_id, router_info)| {
                if !router_info.is_reachable() || !router_info.capabilities.is_usable() {
                    return None;
                }

                match router_info.capabilities.is_fast() {
                    true => Some((Some(router_id.clone()), None)),
                    false => Some((None, Some(router_id.clone()))),
                }
            })
            .unzip();

        Self {
            discovered_routers: Default::default(),
            fast: Arc::new(RwLock::new(fast.into_iter().flatten().collect())),
            profiles: Arc::new(RwLock::new(profiles)),
            routers: Arc::new(RwLock::new(routers)),
            standard: Arc::new(RwLock::new(standard.into_iter().flatten().collect())),
            untracked: Default::default(),
            _runtime: Default::default(),
        }
    }
}

/// Profile manager.
struct ProfileManager<R: Runtime> {
    /// Profile storage.
    profile_storage: ProfileStorage<R>,
}

impl<R: Runtime> ProfileManager<R> {
    /// Create new [`ProfileManager`].
    fn new(profile_storage: ProfileStorage<R>) -> Self {
        Self { profile_storage }
    }

    /// Run the event loop of profile manager.
    async fn run(self) {
        loop {
            R::delay(PROFILE_STORAGE_MAINTENANCE_INTERVAL).await;

            let profiles = self.profile_storage.profiles.read();

            let (total, routers, no_profile_routers) = {
                let fast = self.profile_storage.fast.read();
                let standard = self.profile_storage.standard.read();
                let untracked = self.profile_storage.untracked.read();

                fast.iter().chain(standard.iter()).chain(untracked.iter()).fold(
                    (0f64, HashSet::<RouterId>::new(), HashSet::<RouterId>::new()),
                    |(mut total, mut routers, mut untracked), router_id| {
                        match profiles.get(router_id).expect("to exist").participation_rate() {
                            Some(rate) => {
                                total += rate;
                                routers.insert(router_id.clone());
                            }
                            None => {
                                untracked.insert(router_id.clone());
                            }
                        }
                        (total, routers, untracked)
                    },
                )
            };

            // if there are no statistics yet, leave the groups unmodified
            if routers.is_empty() {
                continue;
            }

            // calculate weighted capacity for each router
            let avg = total / routers.len() as f64;
            let mut routers = routers
                .into_iter()
                .map(|router_id| {
                    // profile must exist since the router's participation rate was calculated
                    let rate = profiles
                        .get(&router_id)
                        .expect("to exist")
                        .weighted_participation_rate(avg);

                    (router_id, rate)
                })
                .collect::<Vec<_>>();

            // sort by capacity in descending order
            routers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

            // split routers into fast, standard and untracked buckets
            let router_infos = self.profile_storage.routers.read();

            let mut fast = HashSet::<RouterId>::new();
            let mut standard = HashSet::<RouterId>::new();
            let mut untracked = HashSet::<RouterId>::new();

            for (router_id, _) in routers {
                let Some(router_info) = router_infos.get(&router_id) else {
                    continue;
                };

                if !router_info.is_reachable() {
                    continue;
                }

                if router_info.capabilities.is_fast() && fast.len() < NUM_HIGH_CAPACITY_ROUTERS {
                    fast.insert(router_id);
                    continue;
                }

                if standard.len() < NUM_STANDARD_ROUTERS {
                    standard.insert(router_id);
                    continue;
                }

                untracked.insert(router_id);
            }

            untracked.extend(no_profile_routers);

            // replace old groups with new groups
            *self.profile_storage.fast.write() = fast;
            *self.profile_storage.standard.write() = standard;
            *self.profile_storage.untracked.write() = untracked;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::base64_encode, primitives::RouterInfoBuilder, runtime::mock::MockRuntime};

    #[tokio::test]
    async fn initialize_with_infos_without_profiles() {
        let (_, infos): (Vec<_>, Vec<_>) = (0..5)
            .map(|_| {
                let (info, _, sgn_key) = RouterInfoBuilder::default().build();
                let router_id = info.identity.id();

                (router_id, info.serialize(&sgn_key))
            })
            .unzip();

        let profiles = ProfileStorage::<MockRuntime>::new(&infos, &Vec::new());

        assert_eq!(profiles.routers.read().len(), 5);
        assert_eq!(profiles.profiles.read().len(), 5);
        assert!(profiles
            .routers
            .read()
            .keys()
            .all(|key| profiles.profiles.read().contains_key(key)));
        assert!(profiles.profiles.read().values().all(|profile| profile == &Profile::new()));
    }

    #[tokio::test]
    async fn initialize_with_infos_and_profiles() {
        let (router_ids, infos): (Vec<_>, Vec<_>) = (0..5)
            .map(|_| {
                let (info, _, sgn_key) = RouterInfoBuilder::default().build();
                let router_id = info.identity.id();

                (router_id, info.serialize(&sgn_key))
            })
            .unzip();

        let profiles = (0..3)
            .map(|i| {
                let router_id = base64_encode(router_ids[i].to_vec());

                (
                    router_id,
                    Profile {
                        last_activity: Duration::from_secs((i as u64 + 1) * 10000),
                        last_declined: None,
                        last_dial_failure: None,
                        num_accepted: i + 1,
                        num_connection: i + 1,
                        num_dial_failures: i + 1,
                        num_lookup_failures: i + 1,
                        num_lookup_no_responses: i + 1,
                        num_lookup_successes: i + 1,
                        num_rejected: i + 1,
                        num_selected: i + 1,
                        num_test_failures: i + 1,
                        num_test_successes: i + 1,
                        num_unaswered: i + 1,
                    },
                )
            })
            .collect::<Vec<_>>();

        let profiles = ProfileStorage::<MockRuntime>::new(&infos, &profiles);

        assert_eq!(profiles.routers.read().len(), 5);
        assert_eq!(profiles.profiles.read().len(), 5);
        assert!(profiles
            .routers
            .read()
            .keys()
            .all(|key| profiles.profiles.read().contains_key(key)));

        for i in 0..3 {
            assert_ne!(
                profiles.profiles.read().get(&router_ids[i]).unwrap(),
                &Profile::new()
            );
        }

        for i in 3..5 {
            assert_eq!(
                profiles.profiles.read().get(&router_ids[i]).unwrap(),
                &Profile::new()
            );
        }
    }

    #[tokio::test]
    async fn profile_without_router_info() {
        let profiles = (0..3)
            .map(|i| {
                let router_id = base64_encode(RouterId::random().to_vec());

                (
                    router_id,
                    Profile {
                        last_activity: Duration::from_secs((i as u64 + 1) * 10000),
                        last_declined: None,
                        last_dial_failure: None,
                        num_accepted: i + 1,
                        num_connection: i + 1,
                        num_dial_failures: i + 1,
                        num_lookup_failures: i + 1,
                        num_lookup_no_responses: i + 1,
                        num_lookup_successes: i + 1,
                        num_rejected: i + 1,
                        num_selected: i + 1,
                        num_test_failures: i + 1,
                        num_test_successes: i + 1,
                        num_unaswered: i + 1,
                    },
                )
            })
            .collect::<Vec<_>>();

        let profiles = ProfileStorage::<MockRuntime>::new(&Vec::new(), &profiles);

        assert!(profiles.routers.read().is_empty());
        assert!(profiles.profiles.read().is_empty());
    }

    #[tokio::test]
    async fn create_profile_if_it_doesnt_exist() {
        let profiles = ProfileStorage::<MockRuntime>::new(&Vec::new(), &Vec::new());
        let router_id = RouterId::random();

        assert!(profiles.routers.read().is_empty());
        assert!(profiles.profiles.read().is_empty());

        profiles.dial_succeeded(&router_id);

        let reader = profiles.reader();
        assert_eq!(
            reader.profiles.get(&router_id).unwrap().num_connection,
            1usize
        );
    }
}
