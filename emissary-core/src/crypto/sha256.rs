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

use sha2::Digest;

use alloc::vec::Vec;

/// Sha256 hasher.
pub struct Sha256 {
    /// Inner hasher.
    hasher: sha2::Sha256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            hasher: sha2::Sha256::new(),
        }
    }
}

impl Sha256 {
    /// Crete new [`Sha256`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Update hasher state.
    pub fn update<T: AsRef<[u8]>>(mut self, bytes: T) -> Self {
        self.hasher.update(bytes.as_ref());
        self
    }

    /// Finalize and return digest.
    //
    // TODO: remove
    pub fn finalize(self) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }

    // TODO: rename
    pub fn finalize_new(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256() {
        let digest1 = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&b"hello, world"[..]);
            hasher.finalize().to_vec()
        };

        assert_eq!(
            digest1,
            Sha256::new().update(&b"hello, world"[..]).finalize()
        )
    }
}
