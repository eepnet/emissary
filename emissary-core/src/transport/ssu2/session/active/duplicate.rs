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

use crate::runtime::Runtime;

use futures::FutureExt;
use hashbrown::HashSet;

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::active::duplicate-filter";

/// Duplicate filter decay interval.
const DUPLICATE_FILTER_DECAY_INTERVAL: Duration = Duration::from_secs(60);

/// Duplicate message filter.
pub struct DuplicateFilter<R: Runtime> {
    /// Current filter.
    current: HashSet<u32>,

    /// Decay timer.
    decay_timer: R::Timer,

    /// Previous filter.
    previous: HashSet<u32>,
}

impl<R: Runtime> DuplicateFilter<R> {
    /// Create new [`DuplicateFilter`].
    pub fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            decay_timer: R::timer(DUPLICATE_FILTER_DECAY_INTERVAL),
        }
    }

    /// Attempt to insert `message_id` into [`DuplicateFilter`].
    ///
    /// Returns `true` if `bytes` doesn't exist in the filter and `false` if it does.
    pub fn insert(&mut self, message_id: u32) -> bool {
        if self.current.contains(&message_id) || self.previous.contains(&message_id) {
            return false;
        }

        self.current.insert(message_id);
        true
    }

    /// Decay [`BloomFilter`].
    fn decay(&mut self) {
        self.previous = core::mem::take(&mut self.current);
    }
}

impl<R: Runtime> Future for DuplicateFilter<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        futures::ready!(self.decay_timer.poll_unpin(cx));

        // create new timer and register it into the executor
        {
            tracing::trace!(
                target: LOG_TARGET,
                "decaying ssu2 duplicate filter",
            );

            self.decay();
            self.decay_timer = R::timer(DUPLICATE_FILTER_DECAY_INTERVAL);
            let _ = self.decay_timer.poll_unpin(cx);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[tokio::test]
    async fn insert_duplicate_and_decay() {
        let mut filter = DuplicateFilter::<MockRuntime>::new();

        // insert first time and verify that second insert rejects the message
        assert!(filter.insert(1337));
        assert!(!filter.insert(1337));

        // decay the filter and verify the message is still rejected
        filter.decay();
        assert!(!filter.insert(1337));

        // decay again and verify that the message is accepted
        filter.decay();
        assert!(filter.insert(1337));
        assert!(!filter.insert(1337));
    }

    #[tokio::test]
    async fn decay_timer_works() {
        let mut filter = DuplicateFilter::<MockRuntime>::new();
        filter.decay_timer = MockRuntime::timer(Duration::from_secs(5));

        // insert first time and verify that second insert rejects the message
        assert!(filter.insert(1337));
        assert!(!filter.insert(1337));
        assert_eq!(filter.current.len(), 1);

        // wait until the decay timer expires and verify state
        assert!(tokio::time::timeout(Duration::from_secs(8), &mut filter).await.is_err());
        assert!(filter.current.is_empty());
        assert_eq!(filter.previous.len(), 1);
        assert!(!filter.insert(1337));

        // poll it until the filter decays the second time and verify that the message is accepted
        filter.decay_timer = MockRuntime::timer(Duration::from_secs(5));
        assert!(tokio::time::timeout(Duration::from_secs(8), &mut filter).await.is_err());
        assert!(filter.current.is_empty());
        assert!(filter.current.is_empty());
        assert!(filter.insert(1337));
    }
}
