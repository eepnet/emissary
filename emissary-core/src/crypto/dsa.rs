// Copyright (c) 2017-2023 The Ire Developers. The canonical list of project
// contributors who hold copyright over the project can be found at:
//
// https://github.com/str4d/ire/blob/master/AUTHORS.md
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

use num_bigint::BigUint;
use num_traits::{Num, One, Zero};
use sha1::{Digest, Sha1};
use subtle::{Choice, ConstantTimeEq};

use alloc::{vec, vec::Vec};
use core::ops::Sub;

/// From https://geti2p.net/spec/cryptography#dsa
pub const I2P_DSA_P: &str = "\
                             9C05B2AA_960D9B97_B8931963_C9CC9E8C_3026E9B8_ED92FAD0\
                             A69CC886_D5BF8015_FCADAE31_A0AD18FA_B3F01B00_A358DE23\
                             7655C496_4AFAA2B3_37E96AD3_16B9FB1C_C564B5AE_C5B69A9F\
                             F6C3E454_8707FEF8_503D91DD_8602E867_E6D35D22_35C1869C\
                             E2479C3B_9D5401DE_04E0727F_B33D6511_285D4CF2_9538D9E3\
                             B6051F5B_22CC1C93";

/// From https://geti2p.net/spec/cryptography#dsa
pub const I2P_DSA_Q: &str = "A5DFC28F_EF4CA1E2_86744CD8_EED9D29D_684046B7";

/// From https://geti2p.net/spec/cryptography#dsa
pub const I2P_DSA_G: &str = "\
                             0C1F4D27_D40093B4_29E962D7_223824E0_BBC47E7C_832A3923\
                             6FC683AF_84889581_075FF908_2ED32353_D4374D73_01CDA1D2\
                             3C431F46_98599DDA_02451824_FF369752_593647CC_3DDC197D\
                             E985E43D_136CDCFC_6BD5409C_D2F45082_1142A5E6_F8EB1C3A\
                             B5D0484B_8129FCF1_7BCE4F7F_33321C3C_B3DBB14A_905E7B2B\
                             3E93BE47_08CBCC82";

lazy_static::lazy_static! {
    pub static ref DSA_P: BigUint = BigUint::from_str_radix(I2P_DSA_P, 16).unwrap();
    pub static ref DSA_Q: BigUint = BigUint::from_str_radix(I2P_DSA_Q, 16).unwrap();
    pub static ref DSA_QM2: BigUint = (&(*DSA_Q)).sub(BigUint::one()).sub(BigUint::one());
    pub static ref DSA_G: BigUint = BigUint::from_str_radix(I2P_DSA_G, 16).unwrap();
}

/// Converts the given number into an array of exactly len bytes, padding with
/// zeroes if necessary.
///
/// The Java implementation handles the fact that Java BigInteger prepends a
/// sign bit, which can create an extra leading zero-byte. BigUint does not do
/// this, so we simplify the logic.
pub fn rectify(bi: &BigUint, len: usize) -> Vec<u8> {
    let mut b = bi.to_bytes_be();
    match b.len() {
        sz if sz == len => b,
        sz if sz > len => panic!("key too big ({sz}) max is {len}"),
        0 => {
            vec![0u8; len]
        }
        _ => {
            // Smaller than needed
            let mut ret = vec![0u8; len];
            ret.truncate(len - b.len());
            ret.append(&mut b);
            ret
        }
    }
}

#[derive(Clone, Debug)]
pub struct DsaSignature {
    rbar: [u8; 20],
    sbar: [u8; 20],
}

impl ConstantTimeEq for DsaSignature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.rbar.ct_eq(&other.rbar) & self.sbar.ct_eq(&other.sbar)
    }
}

impl PartialEq for DsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl DsaSignature {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        Some(DsaSignature {
            rbar: TryInto::<[u8; 20]>::try_into(&data[..20]).ok()?,
            sbar: TryInto::<[u8; 20]>::try_into(&data[20..40]).ok()?,
        })
    }
}

impl ConstantTimeEq for DsaPublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl PartialEq for DsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[derive(Clone, Debug, Eq)]
pub struct DsaPublicKey {
    bi: BigUint,
    bytes: Vec<u8>,
}

impl DsaPublicKey {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let bi = BigUint::from_bytes_be(data);
        let bytes = rectify(&bi, 128);

        Some(DsaPublicKey { bi, bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// DSA signature verification, following algorithm 11.56 2).
    #[allow(clippy::many_single_char_names)]
    pub fn verify(&self, msg: &[u8], sig: &DsaSignature) -> bool {
        let p = &(*DSA_P);
        let q = &(*DSA_Q);

        let r = BigUint::from_bytes_be(&sig.rbar);
        let s = BigUint::from_bytes_be(&sig.sbar);

        // Verify that 0 < r < q and 0 < s < q
        if r.is_zero() || r >= *DSA_Q || s.is_zero() || s >= *DSA_Q {
            return false;
        }

        // w = s^{-1} mod q = s^{q-2} mod q
        let w = s.modpow(&DSA_QM2, q);

        // h(m) = SHA1(msg)
        let hm = BigUint::from_bytes_be(&Sha1::digest(msg));

        // u_1 = w * h(m) mod q
        let u1 = &w * hm % q;

        // u_2 = r * w mod q
        let u2 = &r * &w % q;

        // v = (α^{u_1} * y^{u_2} mod p) mod q
        let v = (DSA_G.modpow(&u1, p) * self.bi.modpow(&u2, p) % p) % q;

        // Accept iff v == r
        v == r
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    use super::rectify;

    #[test]
    fn rectify_zero() {
        assert_eq!(&rectify(&BigUint::zero(), 1), &[0]);
        assert_eq!(&rectify(&BigUint::zero(), 8), &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&rectify(&BigUint::zero(), 32), &[0u8; 32]);
    }

    #[test]
    fn rectify_one() {
        assert_eq!(&rectify(&BigUint::one(), 1), &[1]);
        assert_eq!(&rectify(&BigUint::one(), 4), &[0, 0, 0, 1]);
        assert_eq!(&rectify(&BigUint::one(), 8), &[0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn rectify_value() {
        let val = [0xff, 0xab, 0xcd, 0xef];
        assert_eq!(&rectify(&BigUint::from_bytes_be(&val), 4), &val);
        assert_eq!(
            &rectify(&BigUint::from_bytes_be(&val), 5),
            &[0x00, 0xff, 0xab, 0xcd, 0xef]
        );
    }
}
