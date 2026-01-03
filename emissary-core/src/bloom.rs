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

#![allow(unused)]

use ethbloom::{Bloom, Input};

/// Tunnel message bloom filter.
///
/// Idea taken from `ire` which is licensed under MIT.
///
/// Credits to str4d.
#[derive(Default)]
pub struct BloomFilter {
    /// Current filter.
    current: Bloom,

    /// Previous filter.
    previous: Bloom,
}

impl BloomFilter {
    /// Attempt to insert `bytes` into [`BloomFilter`].
    ///
    /// Returns `true` if `bytes` doesn't exist in the filter and `false` if it does.
    pub fn insert(&mut self, bytes: &[u8]) -> bool {
        if self.current.contains_input(Input::Raw(bytes))
            || self.previous.contains_input(Input::Raw(bytes))
        {
            return false;
        }

        self.current.accrue(Input::Raw(bytes));
        true
    }

    /// Decay [`BloomFilter`].
    pub fn decay(&mut self) {
        self.previous = core::mem::take(&mut self.current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{mock::MockRuntime, Runtime};
    use rand_core::RngCore;

    #[test]
    fn insert_and_decay() {
        let messages = (0..5)
            .map(|_| {
                let mut message = [0u8; 1008];
                MockRuntime::rng().fill_bytes(&mut message);

                message
            })
            .collect::<Vec<_>>();

        let mut bloom = BloomFilter::default();

        // insert all messages and verify they're all in the bloom filter
        assert!(messages.iter().all(|message| bloom.insert(message.as_ref())));
        assert!(messages.iter().all(|message| !bloom.insert(message.as_ref())));

        // deacy the filter and verify that all the messages are still part of the bloom filter
        bloom.decay();
        assert!(messages.iter().all(|message| !bloom.insert(message.as_ref())));

        // decay filter again and verify that the messages are no longer part of it
        bloom.decay();
        assert!(messages.iter().all(|message| bloom.insert(message.as_ref())));
        assert!(messages.iter().all(|message| !bloom.insert(message.as_ref())));
    }
}
