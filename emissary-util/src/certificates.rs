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

use rsa::{BigUint, RsaPublicKey};
use x509_parser::public_key::PublicKey;

use std::{collections::HashMap, sync::LazyLock};

const ACETONE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/acetone_at_mail.i2p.crt"
));
const CREATIVECOWPAT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/creativecowpat_at_mail.i2p.crt"
));
const HOTTUNA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/hottuna_at_mail.i2p.crt"
));
const LAZYGRAVY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/lazygravy_at_mail.i2p.crt"
));
const RAMBLER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/rambler_at_mail.i2p.crt"
));
const ADMIN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/admin_at_stormycloud.org.crt"
));
const ECHELON3: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/echelon3_at_mail.i2p.crt"
));
const I2P_RESEED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/i2p-reseed_at_mk16.de.crt"
));
const ORIGNAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/orignal_at_mail.i2p.crt"
));
const RESEED_DIVA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/reseed_at_diva.exchange.crt"
));
const ARNAVBHATT288: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/arnavbhatt288_at_mail.i2p.crt"
));
const HANKHILL19580: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/hankhill19580_at_gmail.com.crt"
));
const IGOR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/igor_at_novg.net.crt"
));
const R4SAS_RESEED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/r4sas-reseed_at_mail.i2p.crt"
));
const CUBIC_CHAOS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/unixeno_at_cubicchaos.net"
));

pub const CREATIVECOWPAT_SSL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/i2pseed.creativecowpat.net.crt"
));
pub const CUBICCHAOS_SSL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/cubicchaos.net.crt"
));

/// Certificates of the reseed bundle signers.
pub const CERTIFICATES: &[(&str, &str); 14] = &[
    ("acetone@mail.i2p", ACETONE),
    ("creativecowpat@mail.i2p", CREATIVECOWPAT),
    ("hottuna@mail.i2p", HOTTUNA),
    ("lazygravy@mail.i2p", LAZYGRAVY),
    ("rambler@mail.i2p", RAMBLER),
    ("admin@stormycloud.org", ADMIN),
    ("echelon3@mail.i2p", ECHELON3),
    ("i2p-reseed@mk16.de", I2P_RESEED),
    ("orignal@mail.i2p", ORIGNAL),
    ("reseed@diva.exchange", RESEED_DIVA),
    ("arnavbhatt288@mail.i2p", ARNAVBHATT288),
    ("hankhill19580@gmail.com", HANKHILL19580),
    ("igor@novg.net", IGOR),
    ("r4sas-reseed@mail.i2p", R4SAS_RESEED),
    ("unixeno@cubicchaos.net", CUBIC_CHAOS),
];

/// Public keys of the reseed bundle signers.
pub static PUBLIC_KEYS: LazyLock<HashMap<&'static str, RsaPublicKey>> = LazyLock::new(|| {
    CERTIFICATES
        .iter()
        .filter_map(|(key, value)| {
            let cert = pem::parse(value).ok()?.into_contents();
            let (_, cert) = x509_parser::parse_x509_certificate(&cert).ok()?;

            if !cert.tbs_certificate.validity.is_valid() {
                tracing::warn!(
                    target: "emissary-util::certificate",
                    %key,
                    not_before = ?cert.tbs_certificate.validity.not_before,
                    not_after = ?cert.tbs_certificate.validity.not_after,
                    "self-signed certificate is no longer valid",
                );

                return None;
            }

            match cert.public_key().parsed().ok()? {
                PublicKey::RSA(public_key) => {
                    let modulus = BigUint::from_bytes_be(public_key.modulus);
                    let exponent = BigUint::from_bytes_be(public_key.exponent);

                    Some((*key, RsaPublicKey::new(modulus, exponent).ok()?))
                }
                _ => None,
            }
        })
        .collect()
});
