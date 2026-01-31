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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    events::EventHandle,
    primitives::RouterId,
    profile::ProfileStorage,
    runtime::Runtime,
    tunnel::NoiseContext,
};

use bytes::Bytes;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::sync::Arc;

/// Inner router context.
struct InnerRouterContext<R: Runtime> {
    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Network ID.
    net_id: u8,

    /// Noise context.
    #[allow(unused)]
    noise: NoiseContext,

    /// Local router ID.
    router_id: RouterId,

    /// Local, serialized and uncompressed [`RouterInfo`].
    ///
    /// Periodically updated by [`TransportManager`].
    router_info: Arc<RwLock<Bytes>>,

    /// Local signing key.
    #[allow(unused)]
    signing_key: SigningPrivateKey,

    /// Local static key.
    #[allow(unused)]
    static_key: StaticPrivateKey,
}

/// Router context.
///
/// Passed onto different subsystems of emissary.
#[derive(Clone)]
pub struct RouterContext<R: Runtime> {
    /// Router context.
    inner: Arc<InnerRouterContext<R>>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// Event handle.
    event_handle: EventHandle<R>,
}

impl<R: Runtime> RouterContext<R> {
    /// Create new [`RouterContext`].
    pub(crate) fn new(
        metrics_handle: R::MetricsHandle,
        profile_storage: ProfileStorage<R>,
        router_id: RouterId,
        router_info: Bytes,
        static_key: StaticPrivateKey,
        signing_key: SigningPrivateKey,
        net_id: u8,
        event_handle: EventHandle<R>,
    ) -> Self {
        Self {
            event_handle,
            inner: Arc::new(InnerRouterContext {
                metrics_handle,
                net_id,
                noise: NoiseContext::new(static_key.clone(), Bytes::from(router_id.to_vec())),
                router_id,
                router_info: Arc::new(RwLock::new(router_info)),
                signing_key,
                static_key,
            }),
            profile_storage,
        }
    }

    /// Get copy of serialized local [`RouterInfo`].
    ///
    /// Note that the returned [`RouterInfo`] is uncompressed.
    pub fn router_info(&self) -> Bytes {
        self.inner.router_info.read().clone()
    }

    /// Get reference to local router ID.
    pub fn router_id(&self) -> &RouterId {
        &self.inner.router_id
    }

    /// Get network ID.
    pub fn net_id(&self) -> u8 {
        self.inner.net_id
    }

    /// Set new local [`RouterInfo`].
    pub fn set_router_info(&self, router_info: Bytes) {
        let mut inner = self.inner.router_info.write();
        *inner = router_info;
    }

    /// Get reference to metrics handle.
    pub fn metrics_handle(&self) -> &R::MetricsHandle {
        &self.inner.metrics_handle
    }

    /// Get reference to [`ProfileStorage`].
    pub fn profile_storage(&self) -> &ProfileStorage<R> {
        &self.profile_storage
    }

    /// Get reference to [`NoiseContext`].
    pub fn noise(&self) -> &NoiseContext {
        &self.inner.noise
    }

    /// Get reference to [`SigningPrivateKey`].
    pub fn signing_key(&self) -> &SigningPrivateKey {
        &self.inner.signing_key
    }

    /// Get reference to [`EventHandle`].
    pub(crate) fn event_handle(&self) -> &EventHandle<R> {
        &self.event_handle
    }
}

#[cfg(test)]
#[allow(unused)]
pub(crate) mod builder {
    use crate::{
        crypto::{SigningPrivateKey, StaticPrivateKey},
        events::EventHandle,
        primitives::{RouterInfo, RouterInfoBuilder},
        profile::ProfileStorage,
        router::context::RouterContext,
        runtime::{
            mock::{MockMetricsHandle, MockRuntime},
            Runtime,
        },
    };
    use bytes::Bytes;

    #[derive(Default)]
    #[allow(unused)]
    pub struct RouterContextBuilder {
        metrics_handle: Option<MockMetricsHandle>,
        net_id: u8,
        router_info: Option<(RouterInfo, StaticPrivateKey, SigningPrivateKey)>,
        profile_storage: Option<ProfileStorage<MockRuntime>>,
        event_handle: Option<EventHandle<MockRuntime>>,
    }

    impl RouterContextBuilder {
        /// Provid metrics handle.
        pub fn with_metrics_handle(mut self, metrics_handle: MockMetricsHandle) -> Self {
            self.metrics_handle = Some(metrics_handle);
            self
        }

        /// Specify network ID.
        pub fn with_net_id(mut self, net_id: u8) -> Self {
            self.net_id = net_id;
            self
        }

        /// Provide router information.
        pub fn with_router_info(
            mut self,
            router_info: RouterInfo,
            static_key: StaticPrivateKey,
            signing_key: SigningPrivateKey,
        ) -> Self {
            self.router_info = Some((router_info, static_key, signing_key));
            self
        }

        /// Provide profile
        pub fn with_profile_storage(
            mut self,
            profile_storage: ProfileStorage<MockRuntime>,
        ) -> Self {
            self.profile_storage = Some(profile_storage);
            self
        }

        /// Provide
        pub fn with_event_handle(mut self, event_handle: EventHandle<MockRuntime>) -> Self {
            self.event_handle = Some(event_handle);
            self
        }

        /// Build `RouterContextBuilder` into `RouterContext`.
        pub fn build(self) -> RouterContext<MockRuntime> {
            let metrics_handle = self
                .metrics_handle
                .unwrap_or_else(|| <MockRuntime as Runtime>::register_metrics(vec![], None));
            let profile_storage =
                self.profile_storage.unwrap_or_else(|| ProfileStorage::new(&[], &[]));
            let (router_info, static_key, signing_key) =
                self.router_info.unwrap_or_else(|| RouterInfoBuilder::default().build());
            let event_handle = self.event_handle.unwrap_or_else(EventHandle::new_for_tests);
            let serialized = Bytes::from(router_info.serialize(&signing_key));
            let router_id = router_info.identity.id();

            RouterContext::new(
                metrics_handle,
                profile_storage,
                router_id,
                serialized,
                static_key,
                signing_key,
                self.net_id,
                event_handle,
            )
        }
    }
}
