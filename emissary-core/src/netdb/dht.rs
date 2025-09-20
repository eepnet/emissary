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
    crypto::sha256::Sha256,
    netdb::{routing_table::RoutingTable, types::Key},
    primitives::RouterId,
    router::context::RouterContext,
    runtime::Runtime,
};

use hashbrown::HashSet;

use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// Score adjustment when floodfill doesn't answer to a query.
const LOOKUP_REPLY_NOT_RECEIVED_SCORE: isize = -5isize;

/// Score adjustment when a [`DatabaseStore`] is received from a floodfill as a response to a
/// [`DatabaseLookUp`].
const LOOKUP_SUCCEEDED_SCORE: isize = 10isize;

/// Score adjustment when a [`DatabaseSearchReply`] is received from a floodfill as a response to a
/// [`DatabaseLookUp`].
///
/// Note that this is a positive number even though the lookup failed. Reason for this is that even
/// though the value was not found from the floodfill, receiving a response from them means that
/// they're at least responsive.
const LOOKUP_FAILED_SCORE: isize = 1isize;

/// Kademlia DHT implementation.
pub struct Dht<R: Runtime> {
    /// Kademlia routing table.
    routing_table: RoutingTable,

    /// Router context.
    router_ctx: RouterContext<R>,
}

impl<R: Runtime> Dht<R> {
    /// Create new [`Dht`].
    ///
    /// `floodfill` denotes whether this is a [`Dht`] for floodfills or not.
    pub(super) fn new(
        local_router_id: RouterId,
        routers: HashSet<RouterId>,
        router_ctx: RouterContext<R>,
        floodfill: bool,
    ) -> Self {
        let routing_table = if floodfill {
            let mut routing_table = RoutingTable::new(Key::from(local_router_id));
            let reader = router_ctx.profile_storage().reader();

            // sort floodfills by their measured performance and insert them in the order of highest
            // performance into the routing table
            //
            // the floodfills with lowest performance are left out, unless the bucket has space
            let mut scores = routers
                .into_iter()
                .map(|router_id| match reader.profile(&router_id) {
                    Some(profile) => (router_id, profile.floodfill_score()),
                    None => (router_id, 0isize),
                })
                .collect::<Vec<_>>();

            scores.sort_by(|(_, a), (_, b)| b.cmp(a));
            scores.into_iter().for_each(|(router_id, _)| {
                routing_table.add_router(router_id);
            });

            routing_table
        } else {
            let mut routing_table = RoutingTable::new(Key::from(local_router_id));

            routers.into_iter().for_each(|router_id| {
                routing_table.add_router(router_id);
            });

            routing_table
        };

        Self {
            routing_table,
            router_ctx,
        }
    }

    /// Get UTC date from the unix timestamp.
    fn utc_date(unix_timestamp: u64) -> String {
        const DAYS_PER_YEAR: u64 = 365;
        const DAYS_PER_4_YEARS: u64 = 4 * DAYS_PER_YEAR + 1;
        const DAYS_PER_100_YEARS: u64 = 25 * DAYS_PER_4_YEARS - 1;
        const DAYS_PER_400_YEARS: u64 = 4 * DAYS_PER_100_YEARS + 1;
        const SECONDS_PER_DAY: u64 = 86_400;
        const CUMUL_NORMAL: [u16; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        const CUMUL_LEAP: [u16; 12] = [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335];

        let mut days = unix_timestamp / SECONDS_PER_DAY;
        let mut year = 1970;

        // Advance by 400-year chunks
        {
            let num_400_years = days / DAYS_PER_400_YEARS;
            year += num_400_years * 400;
            days -= num_400_years * DAYS_PER_400_YEARS;
        }

        // Advance by 100-year chunks (up to 3 to avoid leap overcount)
        while days >= DAYS_PER_100_YEARS {
            if (year % 400) / 100 == 3 {
                break;
            }

            year += 100;
            days -= DAYS_PER_100_YEARS;
        }

        // Advance by 4-year chunks (up to 24 to avoid century years overcount)
        while days >= DAYS_PER_4_YEARS {
            if (year % 100) / 4 == 24 && (year % 400) / 100 != 3 {
                break;
            }

            year += 4;
            days -= DAYS_PER_4_YEARS;
        }

        let is_leap_year = |year: u64| -> bool {
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
        };

        // Advance by single year
        loop {
            let days_in_year = if is_leap_year(year) {
                DAYS_PER_YEAR + 1
            } else {
                DAYS_PER_YEAR
            };

            if days < days_in_year {
                break;
            }

            days -= days_in_year;
            year += 1;
        }

        let cumul_days = if is_leap_year(year) {
            &CUMUL_LEAP
        } else {
            &CUMUL_NORMAL
        };

        let month = (0..11).find(|&m| cumul_days[m + 1] > days as u16).unwrap_or(11);

        alloc::format!(
            "{:04}{:02}{:02}",
            year,
            month + 1,
            days as u16 - cumul_days[month] + 1
        )
    }

    /// Insert new router into [`Dht`].
    pub(super) fn add_router(&mut self, router_id: RouterId) {
        self.routing_table.add_router(router_id);
    }

    /// Register lookup success for `router_id`.
    pub(super) fn register_lookup_success(&mut self, router_id: &RouterId) {
        self.routing_table.adjust_score(router_id, LOOKUP_SUCCEEDED_SCORE);
        self.router_ctx.profile_storage().database_lookup_success(router_id);
    }

    /// Register lookup failure for `router_id`.
    pub(super) fn register_lookup_failure(&mut self, router_id: &RouterId) {
        self.routing_table.adjust_score(router_id, LOOKUP_FAILED_SCORE);
        self.router_ctx.profile_storage().database_lookup_failure(router_id);
    }

    /// Register lookup timeout for `router_id`.
    pub(super) fn register_lookup_timeout(&mut self, router_id: &RouterId) {
        self.routing_table.adjust_score(router_id, LOOKUP_REPLY_NOT_RECEIVED_SCORE);
        self.router_ctx.profile_storage().database_lookup_no_response(router_id);
    }

    /// Get `limit` many routers clost to `key`.
    pub(super) fn closest(
        &mut self,
        key: impl AsRef<[u8]>,
        limit: usize,
    ) -> impl Iterator<Item = RouterId> + '_ {
        let target = Key::from(
            Sha256::new()
                .update(&key)
                .update(Self::utc_date(R::time_since_epoch().as_secs()).as_str())
                .finalize(),
        );

        self.routing_table.closest(target, limit)
    }

    /// Get closest routers to `key`.
    pub(super) fn closest_with_ignore<'a>(
        &'a self,
        key: impl AsRef<[u8]>,
        limit: usize,
        ignore: &'a HashSet<RouterId>,
    ) -> impl Iterator<Item = RouterId> + 'a {
        let target = Key::from(
            Sha256::new()
                .update(&key)
                .update(Self::utc_date(R::time_since_epoch().as_secs()).as_str())
                .finalize(),
        );

        self.routing_table.closest_with_ignore(target, limit, ignore)
    }

    /// Get ID of the router from `routers` closest to `key`.
    pub fn get_closest(key: impl AsRef<[u8]>, routers: &HashSet<RouterId>) -> Option<RouterId> {
        if routers.is_empty() {
            return None;
        }

        let target = Key::from(
            Sha256::new()
                .update(&key)
                .update(Self::utc_date(R::time_since_epoch().as_secs()).as_str())
                .finalize(),
        );
        let mut routers = routers
            .iter()
            .map(|router_id| {
                let distance = target.distance(&Key::from(router_id.clone()));

                (distance, router_id)
            })
            .collect::<BTreeMap<_, _>>();

        routers.pop_first().map(|(_, router_id)| router_id.clone())
    }

    /// Get `limit` many routers closest to `key` from `routers`.
    pub fn get_n_closest(
        key: impl AsRef<[u8]>,
        routers: &HashSet<RouterId>,
        limit: usize,
    ) -> HashSet<RouterId> {
        if routers.is_empty() {
            return HashSet::new();
        }

        let target = Key::from(
            Sha256::new()
                .update(&key)
                .update(Self::utc_date(R::time_since_epoch().as_secs()).as_str())
                .finalize(),
        );
        let routers = routers
            .iter()
            .map(|router_id| {
                let distance = target.distance(&Key::from(router_id.clone()));

                (distance, router_id)
            })
            .collect::<BTreeMap<_, _>>();

        routers
            .into_iter()
            .take(limit)
            .map(|(_, router_id)| router_id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base32_decode, base64_decode},
        events::EventManager,
        primitives::RouterInfoBuilder,
        profile::ProfileStorage,
        runtime::mock::MockRuntime,
    };
    use bytes::Bytes;

    #[tokio::test]
    async fn lookup() {
        let routers = HashSet::from_iter([
            RouterId::from(&base64_decode("4wlqrFG46mv7ujZi18KwEf9uJz2MgOIebdMMxDHsh~0=").unwrap()),
            RouterId::from(&base64_decode("909NkRdvZz4UnYKrEdkcPR0-nyjgIyXfcltdus3KbvI=").unwrap()),
            RouterId::from(&base64_decode("9FpLdQFPuslwleztm87UKZm9voRCErVkC5tQIzTIveE=").unwrap()),
            RouterId::from(&base64_decode("A27bo5gy~L8C9dMPm24YNVkQkkPUqr3jz74-zkHjr4E=").unwrap()),
            RouterId::from(&base64_decode("AFHNc~4qEeDC0pX35aKVZXlJYejqXlwIavJkb51X7Hw=").unwrap()),
            RouterId::from(&base64_decode("gOcHmAy4wEnAwiB5MGdVZUFMSd8R4xVXShLlLMK33ak=").unwrap()),
            RouterId::from(&base64_decode("-HrTE27w0UKFx98GgdKhZDtNzFAaqquctMvuUjwqKnw=").unwrap()),
            RouterId::from(&base64_decode("JT58CgCdJNk9Y9PiykRx7wz9cZIEI7a68sDNV8MBsLk=").unwrap()),
            RouterId::from(&base64_decode("o6~ANVCIdIiUomPN-GxHscI6KetllgsecHFFWNIzFYM=").unwrap()),
            RouterId::from(&base64_decode("o6Ax4-AapSSlKGTzDW8R6qUldj7sg9AszSYlvTxApwI=").unwrap()),
            RouterId::from(&base64_decode("O8Ih-eljywJJ-mQpn4Al1y~GQKU25nvlPRzktoeRnPQ=").unwrap()),
            RouterId::from(&base64_decode("o8qvvGZroVu1Jlo-9ICTamn5t8XlnNq49oJ2QywLVUQ=").unwrap()),
            RouterId::from(&base64_decode("QRbIdWrPvAp58Qf~asFdm1s-oz9NDmwimu61pndVpNY=").unwrap()),
            RouterId::from(&base64_decode("QVGqliH7Pdye7P7UAtM~fKQIfjKOzKbMVvhdKVSGlQ8=").unwrap()),
            RouterId::from(&base64_decode("x4Q9dpbvHfyUuIhK9xDiy1XL9lvrpe9Kmmy9Gg~wFeQ=").unwrap()),
        ]);
        let (router_info, static_key, signing_key) = RouterInfoBuilder::default().build();
        let (_event_mgr, _event_subscriber, event_handle) = EventManager::new(None);
        let mut dht = Dht::<MockRuntime>::new(
            router_info.identity.id(),
            routers,
            RouterContext::new(
                MockRuntime::register_metrics(vec![], None),
                ProfileStorage::new(&[], &[]),
                router_info.identity.id(),
                Bytes::from(router_info.serialize(&signing_key)),
                static_key,
                signing_key,
                2u8,
                event_handle.clone(),
            ),
            true,
        );

        let key = Bytes::from(
            base32_decode("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa").unwrap(),
        );
        let target = Key::from(Sha256::new().update(&key).update("20250105").finalize());
        let closest = dht.routing_table.closest(target, 3usize).collect::<Vec<_>>();

        assert_eq!(
            closest[0],
            RouterId::from(&base64_decode("o6~ANVCIdIiUomPN-GxHscI6KetllgsecHFFWNIzFYM=").unwrap())
        );
        assert_eq!(
            closest[1],
            RouterId::from(&base64_decode("o6Ax4-AapSSlKGTzDW8R6qUldj7sg9AszSYlvTxApwI=").unwrap())
        );
        assert_eq!(
            closest[2],
            RouterId::from(&base64_decode("o8qvvGZroVu1Jlo-9ICTamn5t8XlnNq49oJ2QywLVUQ=").unwrap())
        );
    }

    #[tokio::test]
    async fn utc_date() {
        type D = Dht<MockRuntime>;

        assert_eq!("19700101", D::utc_date(0));
        assert_eq!("19700101", D::utc_date(1));
        assert_eq!("19700101", D::utc_date(59));
        assert_eq!("19700101", D::utc_date(86399));
        assert_eq!("19700102", D::utc_date(86400));

        assert_eq!("5845540512231109", D::utc_date(u64::MAX));
        assert_eq!("2922770265961204", D::utc_date(i64::MAX as u64));

        assert_eq!("20290724", D::utc_date(1879574397));
        assert_eq!("20250531", D::utc_date(1748652952));
        assert_eq!("19801231", D::utc_date(347081248));

        assert_eq!("20231130", D::utc_date(1701388799));
        assert_eq!("20231201", D::utc_date(1701388800));
        assert_eq!("20241212", D::utc_date(1733998283));

        assert_eq!("20240228", D::utc_date(1709164799));
        assert_eq!("20240229", D::utc_date(1709164800));
        assert_eq!("20000228", D::utc_date(951782399));
        assert_eq!("20000229", D::utc_date(951782400));
        assert_eq!("20230228", D::utc_date(1677628799));
        assert_eq!("20230301", D::utc_date(1677628800));

        assert_eq!("20991231", D::utc_date(4102444799));
        assert_eq!("21000101", D::utc_date(4102444800));
    }
}
