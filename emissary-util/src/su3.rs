// Copyright (c) 2017-2023 The Ire Developers. The canonical list of project
// contributors who hold copyright over the project can be found at:
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

use crate::certificates::PUBLIC_KEYS;

use nom::{
    bytes::complete::{tag, take},
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u64, be_u8},
    Err, IResult,
};
use rsa::{
    sha2::{Digest, Sha512},
    traits::SignatureScheme,
};
use tempfile::TempDir;

use std::{
    fs::File,
    io::{copy, Write},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::su3";

/// SU3 magic.
const SU3_MAGIC: &[u8] = b"I2Psu3";

/// Router info.
pub struct ReseedRouterInfo {
    /// File name.
    pub name: String,

    /// Serialized router info.
    pub router_info: Vec<u8>,
}

/// Signature kind.
#[derive(Debug, PartialEq)]
pub enum SignatureKind {
    DsaSha1,
    EcDsaSha256P256,
    EcDsaSha384P384,
    EcDsaSha512P521,
    RsaSha256_2048,
    RsaSha384_3072,
    RsaSha512_4096,
    EdDsaSha512Ed25519ph,
}

impl TryFrom<u16> for SignatureKind {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::DsaSha1),
            0x0001 => Ok(Self::EcDsaSha256P256),
            0x0002 => Ok(Self::EcDsaSha384P384),
            0x0003 => Ok(Self::EcDsaSha512P521),
            0x0004 => Ok(Self::RsaSha256_2048),
            0x0005 => Ok(Self::RsaSha384_3072),
            0x0006 => Ok(Self::RsaSha512_4096),
            0x0008 => Ok(Self::EdDsaSha512Ed25519ph),
            _ => Err(()),
        }
    }
}

/// File kind.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileKind {
    Zip,
    Xml,
    Html,
    XmlGz,
    TxtGz,
    Dmg,
    Exe,
}

impl TryFrom<u8> for FileKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Zip),
            0x01 => Ok(Self::Xml),
            0x02 => Ok(Self::Html),
            0x03 => Ok(Self::XmlGz),
            0x04 => Ok(Self::TxtGz),
            0x05 => Ok(Self::Dmg),
            0x06 => Ok(Self::Exe),
            _ => Err(()),
        }
    }
}

/// Content kind.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentKind {
    Unknown,
    RouterUpdate,
    PluginUpdate,
    ReseedData,
    NewsFeed,
    BlocklistFeed,
}

impl TryFrom<u8> for ContentKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Unknown),
            0x01 => Ok(Self::RouterUpdate),
            0x02 => Ok(Self::PluginUpdate),
            0x03 => Ok(Self::ReseedData),
            0x04 => Ok(Self::NewsFeed),
            0x05 => Ok(Self::BlocklistFeed),

            _ => Err(()),
        }
    }
}

/// Software update.
#[allow(unused)]
pub struct Su3<'a> {
    /// Content.
    content: &'a [u8],

    /// Content kind.
    content_kind: ContentKind,

    /// File kind.
    file_kind: FileKind,

    /// Contents of SU3, excluding signature.
    message: &'a [u8],

    /// Signature.
    signature: &'a [u8],

    /// Signature kind.
    signature_kind: SignatureKind,

    /// Signer ID.
    signer_id: &'a [u8],

    /// Version.
    version: &'a [u8],
}

impl<'a> Su3<'a> {
    /// Attempt to parse reseed data from `input`.
    fn parse_inner(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (rest, _) = tag(SU3_MAGIC)(input)?;
        let (rest, _) = be_u8(rest)?; // unused
        let (rest, _) = be_u8(rest)?; // su3 file format version

        let (rest, signature_kind) = be_u16(rest)?;
        let signature_kind = SignatureKind::try_from(signature_kind)
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?;
        let (rest, signature_len) = be_u16(rest)?;

        let (rest, _) = be_u8(rest)?; // unused
        let (rest, version_len) = be_u8(rest)?;
        debug_assert!(version_len >= 0x10, "invalid version length {version_len}");

        let (rest, _) = be_u8(rest)?; // unused
        let (rest, signer_id_len) = be_u8(rest)?;

        let (rest, content_len) = be_u64(rest)?;
        let (rest, _) = be_u8(rest)?; // unused

        let (rest, file_kind) = be_u8(rest)?;
        let file_kind = FileKind::try_from(file_kind)
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?;

        let (rest, _) = be_u8(rest)?; // unused
        let (rest, content_kind) = be_u8(rest)?;

        let content_kind = ContentKind::try_from(content_kind)
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?;
        let (rest, _) = take(12usize)(rest)?; // unused

        let (rest, version) = take(version_len)(rest)?;
        let (rest, signer_id) = take(signer_id_len)(rest)?;
        let (rest, content) = take(content_len)(rest)?;

        // header + version + signer id + content
        let message_len = 40 + version_len as usize + signer_id_len as usize + content_len as usize;
        let message = &input[..message_len];

        let (rest, signature) = take(signature_len)(rest)?;

        Ok((
            rest,
            Self {
                content,
                content_kind,
                file_kind,
                message,
                signature,
                signature_kind,
                signer_id,
                version,
            },
        ))
    }

    /// Attempt to parse reseed data from `input`.
    pub fn parse_reseed(input: &'a [u8], verify: bool) -> Option<Vec<ReseedRouterInfo>> {
        let (_, su3) = Self::parse_inner(input).ok()?;

        if verify {
            let Ok(signer_id) = std::str::from_utf8(su3.signer_id) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    "invalid signer id",
                );
                return None;
            };

            let Some(key) = PUBLIC_KEYS.get(signer_id) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?signer_id,
                    "public key for signer id not found",
                );
                return None;
            };

            // taken from ire
            rsa::Pkcs1v15Sign::new_unprefixed()
                .verify(key, &Sha512::digest(su3.message), &su3.signature)
                .ok()?;
        }

        match (su3.file_kind, su3.content_kind) {
            (FileKind::Zip, ContentKind::ReseedData) => {}
            (file_kind, content_kind) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?file_kind,
                    ?content_kind,
                    "failed to parse reseed data, invalid file/content kind",
                );
                return None;
            }
        }

        let temp_dir = TempDir::new().ok()?;
        let mut zip_file = File::create_new(temp_dir.path().join("routers.zip")).ok()?;
        File::write_all(&mut zip_file, su3.content).ok()?;

        let mut archive = zip::ZipArchive::new(zip_file).ok()?;
        let router_infos = (0..archive.len())
            .filter_map(|i| {
                let mut file = archive.by_index(i).expect("to exist");
                let outpath = file.enclosed_name()?;

                if !file.is_file() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "non-file encountered in router info, ignoring",
                    );
                    return None;
                }

                let mut router_info = Vec::new();
                copy(&mut file, &mut router_info).ok()?;

                Some(ReseedRouterInfo {
                    name: outpath.display().to_string(),
                    router_info,
                })
            })
            .collect::<Vec<_>>();

        drop(archive);
        temp_dir.close().ok()?;

        Some(router_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SU3: &'static [u8] = include_bytes!("../assets/i2pseeds.su3");

    #[test]
    fn parse_su3() {
        assert!(Su3::parse_reseed(SU3, true).is_some());
    }

    #[test]
    fn parse_su3_invalid_signature() {
        let mut bytes = SU3.to_vec();
        for i in bytes.len() - 10..bytes.len() {
            bytes[i] = bytes[i].overflowing_add(1).0;
        }

        assert!(Su3::parse_reseed(&bytes, true).is_none());
    }

    #[test]
    fn parse_su3_invalid_signature_verify_skipped() {
        let mut bytes = SU3.to_vec();
        for i in bytes.len() - 10..bytes.len() {
            bytes[i] = bytes[i].overflowing_add(1).0;
        }

        assert!(Su3::parse_reseed(&bytes, false).is_some());
    }
}
