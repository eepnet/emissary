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
    i2np::{Message, MessageType},
    primitives::MessageId,
    runtime::{Instant, Runtime},
};

use futures::FutureExt;
use hashbrown::HashMap;

use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Message expiration threshold.
///
/// If all the fragments of a message have not been received within 30 seconds,
/// the [`Fragment`] is destroyed.
///
/// This is to prevent unbounded accumulation of incomplete I2NP messages.
const MSG_EXPIRATION_THRESHOLD: Duration = Duration::from_secs(30);

/// Garbage collection interval.
const GARBAGE_COLLECTION_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Fragmented I2NP message.
struct Fragment<R: Runtime> {
    /// Fragments.
    fragments: BTreeMap<u8, Vec<u8>>,

    /// Total of fragments.
    ///
    /// `None` if last fragment hasn't been received.
    num_fragments: Option<usize>,

    /// Message info.
    ///
    /// `None` if the first fragment hasn't been received.
    info: Option<(MessageType, MessageId, u32)>,

    /// Total size of the I2NP message.
    total_size: usize,

    /// When was the [`Fragment`] created.
    created: R::Instant,
}

impl<R: Runtime> Default for Fragment<R> {
    fn default() -> Self {
        Self {
            fragments: BTreeMap::new(),
            num_fragments: None,
            info: None,
            total_size: 0usize,
            created: R::now(),
        }
    }
}

impl<R: Runtime> Fragment<R> {
    /// Check if [`Fragment`] is ready for assembly.
    pub fn is_ready(&self) -> bool {
        self.num_fragments.is_some()
            && self.info.is_some()
            && self.num_fragments == Some(self.fragments.len())
    }

    /// Construct I2NP message from received fragments.
    pub fn construct(mut self) -> Option<Message> {
        let (message_type, message_id, expiration) = self.info.take()?;
        let payload = self.fragments.into_values().fold(
            Vec::<u8>::with_capacity(self.total_size),
            |mut payload, fragment| {
                payload.extend_from_slice(&fragment);
                payload
            },
        );

        Some(Message {
            message_type,
            message_id: *message_id,
            expiration: Duration::from_secs(expiration as u64),
            payload,
        })
    }
}

/// Fragment handler.
pub struct FragmentHandler<R: Runtime> {
    /// Fragmented messages.
    messages: HashMap<MessageId, Fragment<R>>,

    /// Garbage collection timer.
    gc_timer: R::Delayer,
}

impl<R: Runtime> FragmentHandler<R> {
    /// Create new [`FragmentHandler`].
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            gc_timer: R::delayer(GARBAGE_COLLECTION_INTERVAL),
        }
    }

    /// Handle first fragment.
    ///
    /// If all fragments have been received, the constructed message is received.
    pub fn first_fragment(
        &mut self,
        message_type: MessageType,
        message_id: MessageId,
        expiration: u32,
        payload: Vec<u8>,
    ) -> Option<Message> {
        let message = self.messages.entry(message_id).or_default();

        message.total_size += payload.len();
        message.fragments.insert(0u8, payload.to_vec());
        message.info = Some((message_type, message_id, expiration));

        message
            .is_ready()
            .then(|| self.messages.remove(&message_id).expect("message to exist").construct())
            .flatten()
    }

    /// Handle follow-on fragment.
    ///
    /// If all fragments have been received, the constructed message is received.
    pub fn follow_on_fragment(
        &mut self,
        message_id: MessageId,
        sequence: u8,
        last: bool,
        payload: Vec<u8>,
    ) -> Option<Message> {
        let message = self.messages.entry(message_id).or_default();

        message.total_size += payload.len();
        message.fragments.insert(sequence, payload.to_vec());

        if last {
            // +1 one for the first fragment
            message.num_fragments = Some(sequence as usize + 1usize);
        }

        message
            .is_ready()
            .then(|| self.messages.remove(&message_id).expect("message to exist").construct())
            .flatten()
    }
}

impl<R: Runtime> Future for FragmentHandler<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        futures::ready!(self.gc_timer.poll_unpin(cx));

        self.messages
            .iter()
            .filter_map(|(key, value)| {
                (value.created.elapsed() >= MSG_EXPIRATION_THRESHOLD).then_some(*key)
            })
            .collect::<Vec<_>>()
            .iter()
            .for_each(|key| {
                self.messages.remove(key);
            });

        self.gc_timer = R::delayer(GARBAGE_COLLECTION_INTERVAL);
        let _ = self.gc_timer.poll_unpin(cx);

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        i2np::MessageType,
        runtime::{mock::MockRuntime, Runtime},
    };
    use alloc::collections::VecDeque;
    use std::time::Duration;

    fn split(num_fragments: usize, message: Vec<u8>) -> VecDeque<Vec<u8>> {
        let _remainder = message.len() % num_fragments;
        let fragment_len = message.len() / num_fragments;

        let mut fragments = message
            .chunks(fragment_len)
            .map(|chunk| chunk.to_vec())
            .collect::<VecDeque<_>>();

        let last = fragments.pop_back().unwrap();
        let mut second_to_last = fragments.pop_back().unwrap();

        second_to_last.extend_from_slice(&last);
        fragments.push_back(second_to_last);

        fragments
    }

    #[tokio::test]
    async fn simple_fragmentation() {
        let expiration = MockRuntime::time_since_epoch();
        let message_id = MessageId::from(1338);
        let mut handler = FragmentHandler::<MockRuntime>::new();
        let mut fragments = split(4, vec![0u8; 1337]);

        assert_eq!(fragments.len(), 4);
        assert!(handler
            .first_fragment(
                MessageType::Data,
                message_id,
                expiration.as_secs() as u32,
                fragments.pop_front().unwrap(),
            )
            .is_none());

        for i in 1..=2 {
            assert!(handler
                .follow_on_fragment(message_id, i, false, fragments.pop_front().unwrap())
                .is_none());
        }

        let message = handler
            .follow_on_fragment(message_id, 3, true, fragments.pop_front().unwrap())
            .unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_secs(expiration.as_secs() as u64)
        );
        assert_eq!(message.message_id, 1338u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0u8; 1337]);
    }

    #[tokio::test]
    async fn first_and_last_fragment() {
        let expiration = MockRuntime::time_since_epoch();
        let message_id = MessageId::from(1339);
        let data = {
            let mut data = vec![0u8; 1337];

            for i in 0..1337 {
                data[i] = i as u8;
            }

            data
        };
        let mut fragments = split(2, data.clone());
        let mut handler = FragmentHandler::<MockRuntime>::new();

        assert_eq!(fragments.len(), 2);
        assert!(handler
            .first_fragment(
                MessageType::Data,
                message_id,
                expiration.as_secs() as u32,
                fragments.pop_front().unwrap(),
            )
            .is_none());

        let message = handler
            .follow_on_fragment(message_id, 1, true, fragments.pop_front().unwrap())
            .unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_secs(expiration.as_secs() as u64)
        );
        assert_eq!(message.message_id, 1339u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, data);
    }

    #[tokio::test]
    async fn out_of_order_last_is_first() {
        let expiration = MockRuntime::time_since_epoch();
        let message_id = MessageId::from(1338);
        let mut fragments = split(4, vec![0u8; 30_005]);
        let mut handler = FragmentHandler::<MockRuntime>::new();
        assert_eq!(fragments.len(), 4);

        let first = fragments.pop_front().unwrap();

        // last fragment is delivered first
        assert!(handler
            .follow_on_fragment(message_id, 3, true, fragments.pop_back().unwrap())
            .is_none());

        for i in 1..=2 {
            assert!(handler
                .follow_on_fragment(message_id, i, false, fragments.pop_front().unwrap())
                .is_none());
        }

        let message = handler
            .first_fragment(
                MessageType::Data,
                message_id,
                expiration.as_secs() as u32,
                first,
            )
            .unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_secs(expiration.as_secs() as u64)
        );
        assert_eq!(message.message_id, 1338u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0u8; 30_005]);
    }

    #[tokio::test]
    async fn middle_fragment_delivered_last() {
        let expiration = MockRuntime::time_since_epoch();
        let mut fragments = split(4, vec![0u8; 1337]);
        let message_id = MessageId::from(1338);
        let mut handler = FragmentHandler::<MockRuntime>::new();

        assert_eq!(fragments.len(), 4);
        assert!(handler
            .first_fragment(
                MessageType::Data,
                message_id,
                expiration.as_secs() as u32,
                fragments.pop_front().unwrap(),
            )
            .is_none());

        assert!(handler
            .follow_on_fragment(message_id, 1, false, fragments.pop_front().unwrap())
            .is_none());

        assert!(handler
            .follow_on_fragment(message_id, 3, true, fragments.pop_back().unwrap())
            .is_none());

        let message = handler
            .follow_on_fragment(message_id, 2, false, fragments.pop_front().unwrap())
            .unwrap();

        assert_eq!(
            message.expiration,
            Duration::from_secs(expiration.as_secs() as u64)
        );
        assert_eq!(message.message_id, 1338u32);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.payload, vec![0u8; 1337]);
    }

    #[tokio::test]
    async fn garbage_collection_works() {
        let message_id = MessageId::from(1338);
        let mut fragments = split(4, vec![0u8; 30_005]);
        let mut handler = FragmentHandler::<MockRuntime>::new();
        assert_eq!(fragments.len(), 4);

        // last fragment is delivered first
        assert!(handler
            .follow_on_fragment(message_id, 3, true, fragments.pop_back().unwrap())
            .is_none());

        for i in 1..=2 {
            assert!(handler
                .follow_on_fragment(message_id, i, false, fragments.pop_front().unwrap())
                .is_none());
        }
        assert_eq!(handler.messages.len(), 1);

        // sleep for a while so that the message expires
        tokio::time::sleep(MSG_EXPIRATION_THRESHOLD + Duration::from_secs(2)).await;

        // set the gc period to a shorter time and poll it for a while
        handler.gc_timer = MockRuntime::delayer(Duration::from_secs(5));
        assert!(tokio::time::timeout(Duration::from_secs(8), &mut handler).await.is_err());
        assert!(handler.messages.is_empty());
    }
}
