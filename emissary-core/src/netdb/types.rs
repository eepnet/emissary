// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// Copyright 2023 litep2p developers
//
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

//! Kademlia types.

use crate::primitives::RouterId;

use sha2::digest::generic_array::{typenum::U32, GenericArray};
use uint::construct_uint;

use alloc::vec::Vec;
use core::{
    borrow::Borrow,
    hash::{Hash, Hasher},
};

construct_uint! {
    /// 256-bit unsigned integer.
    pub(super) struct U256(4);
}

/// A `Key` in the DHT keyspace with preserved preimage.
///
/// Keys in the DHT keyspace identify both the participating nodes, as well as
/// the records stored in the DHT.
///
/// `Key`s have an XOR metric as defined in the Kademlia paper, i.e. the bitwise XOR of
/// the hash digests, interpreted as an integer. See [`Key::distance`].
#[derive(Clone, Debug)]
pub struct Key<T: Clone> {
    /// Preimage of the key.
    preimage: T,

    /// Key bytes.
    bytes: KeyBytes,
}

impl<T: Clone> Key<T> {
    /// Constructs a new `Key` by running the given value through a random
    /// oracle.
    ///
    /// The preimage of type `T` is preserved.
    /// See [`Key::into_preimage`] for more details.
    pub fn new(preimage: T) -> Key<T>
    where
        T: Borrow<[u8]>,
    {
        let bytes = KeyBytes::new(preimage.borrow());
        Key { preimage, bytes }
    }

    /// Get preimage of the key.
    pub fn preimage(&self) -> &T {
        &self.preimage
    }

    /// Computes the distance of the keys according to the XOR metric.
    pub fn distance<U>(&self, other: &U) -> Distance
    where
        U: AsRef<KeyBytes>,
    {
        self.bytes.distance(other)
    }
}

impl<T: Clone> From<Key<T>> for KeyBytes {
    fn from(key: Key<T>) -> KeyBytes {
        key.bytes
    }
}

impl From<RouterId> for Key<RouterId> {
    fn from(router_id: RouterId) -> Self {
        let bytes = KeyBytes(*GenericArray::from_slice(&router_id.to_vec()));

        Key {
            preimage: router_id,
            bytes,
        }
    }
}

impl From<Vec<u8>> for Key<Vec<u8>> {
    fn from(b: Vec<u8>) -> Self {
        Key::new(b)
    }
}

impl<T: Clone> AsRef<KeyBytes> for Key<T> {
    fn as_ref(&self) -> &KeyBytes {
        &self.bytes
    }
}

impl<T: Clone, U: Clone> PartialEq<Key<U>> for Key<T> {
    fn eq(&self, other: &Key<U>) -> bool {
        self.bytes == other.bytes
    }
}

impl<T: Clone> Eq for Key<T> {}

impl<T: Clone> Hash for Key<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.0.hash(state);
    }
}

/// The raw bytes of a key in the DHT keyspace.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct KeyBytes(GenericArray<u8, U32>);

impl KeyBytes {
    /// Creates a new key in the DHT keyspace by running the given
    /// value through a random oracle.
    pub fn new<T>(value: T) -> Self
    where
        T: Borrow<[u8]>,
    {
        KeyBytes(*GenericArray::from_slice(value.borrow()))
    }

    /// Computes the distance of the keys according to the XOR metric.
    pub fn distance<U>(&self, other: &U) -> Distance
    where
        U: AsRef<KeyBytes>,
    {
        let a = U256::from_big_endian(self.0.as_slice());
        let b = U256::from_big_endian(other.as_ref().0.as_slice());
        Distance(a ^ b)
    }
}

impl AsRef<KeyBytes> for KeyBytes {
    fn as_ref(&self) -> &KeyBytes {
        self
    }
}

/// A distance between two keys in the DHT keyspace.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Debug)]
pub struct Distance(pub(super) U256);

impl Distance {
    /// Returns the integer part of the base 2 logarithm of the [`Distance`].
    ///
    /// Returns `None` if the distance is zero.
    pub fn ilog2(&self) -> Option<u32> {
        (256 - self.0.leading_zeros()).checked_sub(1)
    }
}

/// Kademlia peer.
#[derive(Debug, Clone)]
pub struct FloodFill {
    /// Router key.
    pub(super) key: Key<RouterId>,

    /// Score of the floodfill.
    pub(super) score: isize,
}

impl FloodFill {
    /// Create new [`FloodFill`].
    pub fn new(router_id: RouterId) -> Self {
        Self {
            key: Key::from(router_id),
            score: 0isize,
        }
    }
}

impl PartialEq for FloodFill {
    fn eq(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }
}

impl Eq for FloodFill {}

impl Ord for FloodFill {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.score.cmp(&other.score)
    }
}

impl PartialOrd for FloodFill {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
