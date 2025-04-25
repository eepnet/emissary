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
    crypto::{base64_encode, SigningPrivateKey, SigningPublicKey},
    error::Error,
    i2cp::I2cpPayload,
    primitives::Destination,
    protocol::Protocol,
    runtime::Runtime,
    sam::parser::SessionKind,
};

use bytes::{BufMut, BytesMut};
use hashbrown::HashMap;
use nom::bytes::complete::take;
use sha2::Digest;
use thingbuf::mpsc::Sender;

use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

/// Datagram manager.
pub struct DatagramManager<R: Runtime> {
    /// TX channel which can be used to send datagrams to clients.
    datagram_tx: Sender<(u16, Vec<u8>)>,

    /// Local destination.
    destination: Destination,

    /// Session options.
    options: HashMap<String, String>,

    /// Session kind.
    session_kind: SessionKind,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Marker for `Runtime`
    _runtime: PhantomData<R>,
}

impl<R: Runtime> DatagramManager<R> {
    /// Create new [`DatagramManager`].
    pub fn new(
        destination: Destination,
        datagram_tx: Sender<(u16, Vec<u8>)>,
        options: HashMap<String, String>,
        signing_key: SigningPrivateKey,
        session_kind: SessionKind,
    ) -> Self {
        Self {
            datagram_tx,
            destination,
            options,
            session_kind,
            signing_key,
            _runtime: Default::default(),
        }
    }

    /// Make repliable datagram.
    pub fn make_datagram(&mut self, datagram: Vec<u8>) -> Vec<u8> {
        match self.session_kind {
            SessionKind::Datagram => {
                let signature = self.signing_key.sign(&datagram);
                let destination = self.destination.serialize();

                let mut out =
                    BytesMut::with_capacity(destination.len() + signature.len() + datagram.len());
                out.put_slice(&destination);
                out.put_slice(&signature);
                out.put_slice(&datagram);

                out.to_vec()
            }
            SessionKind::Anonymous => datagram,
            SessionKind::Stream => unreachable!(), // TODO: technically not unreachable
        }
    }

    /// Handle inbound datagram.
    pub fn on_datagram(&self, payload: I2cpPayload) -> crate::Result<()> {
        let I2cpPayload {
            dst_port,
            payload,
            protocol,
            src_port,
        } = payload;

        match protocol {
            Protocol::Datagram => {
                let (rest, destination) =
                    Destination::parse_frame(&payload).map_err(|_| Error::InvalidData)?;
                let (rest, signature) =
                    take::<_, _, ()>(destination.verifying_key().signature_len())(rest)
                        .map_err(|_| Error::InvalidData)?;

                if let SigningPublicKey::DsaSha1(_) = destination.verifying_key() {
                    destination.verifying_key().verify(&sha1::Sha1::digest(rest), signature)?;
                } else {
                    destination.verifying_key().verify(rest, signature)?;
                }

                // TODO: ensure there is a listener in `src_port`
                let port = self.options.get("PORT").ok_or(Error::InvalidState)?;

                let info = format!(
                    "{} FROM_PORT={dst_port} TO_PORT={src_port}\n",
                    base64_encode(destination.serialize())
                );

                let info = info.as_bytes();

                let mut out = BytesMut::with_capacity(info.len() + rest.len());
                out.put_slice(info);
                out.put_slice(rest);

                let _ = self
                    .datagram_tx
                    .try_send((port.parse::<u16>().expect("to succeed"), out.to_vec()));

                Ok(())
            }
            Protocol::Anonymous => {
                let port = self.options.get("PORT").ok_or(Error::InvalidState)?;

                let _ =
                    self.datagram_tx.try_send((port.parse::<u16>().expect("to succeed"), payload));

                Ok(())
            }
            Protocol::Streaming => unreachable!(),
        }
    }
}
