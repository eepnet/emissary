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
    crypto::SigningPublicKey, error::parser::OfflineSignatureParseError, runtime::Runtime,
};

use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
    Err, IResult,
};

/// Signature kind for `EdDSA_SHA512_Ed25519`.
///
/// https://geti2p.net/spec/common-structures#key-certificates
const SIGNATURE_KIND_EDDSA_SHA512_ED25519: u16 = 0x0007;

/// Signature kind for `ECDSA_SHA256_P256`.
///
/// https://geti2p.net/spec/common-structures#key-certificates
const SIGNATURE_KIND_ECDSA_SHA256_P256: u16 = 0x0001;

/// Offline signature.
pub struct OfflineSignature;

impl OfflineSignature {
    /// Attempt to parse [`OfflineSignature`] from `input` and verify the signature using `key`
    pub fn parse_frame<'a, R: Runtime>(
        input: &'a [u8],
        key: &SigningPublicKey,
    ) -> IResult<&'a [u8], SigningPublicKey, OfflineSignatureParseError> {
        // save start of the signed segment so the offline signature can be verified
        let signed_segment = input;

        let (rest, expires) = be_u32(input)?;

        if R::time_since_epoch().as_secs() > expires as u64 {
            return Err(Err::Error(OfflineSignatureParseError::Expired));
        }

        let (rest, signature_kind) = be_u16(rest)?;

        // extract verifying key from the offline signature
        //
        // this key is used to verify the lease set's signature
        let (rest, verifying_key, verifying_key_len) = match signature_kind {
            SIGNATURE_KIND_EDDSA_SHA512_ED25519 => {
                let (rest, key) = take(32usize)(rest)?;

                // must succeed since `key` has sufficient length
                let verifying_key = SigningPublicKey::from_bytes(
                    &TryInto::<[u8; 32]>::try_into(key).expect("to succeed"),
                )
                .ok_or(Err::Error(OfflineSignatureParseError::InvalidPublicKey))?;

                (rest, verifying_key, 32usize)
            }
            SIGNATURE_KIND_ECDSA_SHA256_P256 => {
                let (rest, key) = take(64usize)(rest)?;
                let verifying_key = SigningPublicKey::p256(key)
                    .ok_or(Err::Error(OfflineSignatureParseError::InvalidPublicKey))?;

                (rest, verifying_key, 64usize)
            }
            _ => {
                return Err(Err::Error(
                    OfflineSignatureParseError::UnsupportedPublicKey(signature_kind),
                ));
            }
        };

        // extract offline signature and verify it with the destination's verifying key
        //
        // the signed portion covers expiration + signature kind + verifying key
        let (rest, signature) = take(verifying_key.signature_len())(rest)?;

        key.verify(&signed_segment[..(6 + verifying_key_len)], signature)
            .map_err(|_| Err::Error(OfflineSignatureParseError::InvalidSignature))?;

        Ok((rest, verifying_key))
    }
}
