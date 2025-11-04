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
    primitives::{DatagramFlags, Destination, OfflineSignature},
    protocol::Protocol,
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use hashbrown::HashMap;
use nom::{bytes::complete::take, Err};
use thingbuf::mpsc::Sender;

use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::datagram";

/// Datagram manager.
pub struct DatagramManager<R: Runtime> {
    /// TX channel which can be used to send datagrams to clients.
    datagram_tx: Sender<(u16, Vec<u8>)>,

    /// Local destination.
    destination: Destination,

    /// Listeners.
    listeners: HashMap<u16, u16>,

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
    ) -> Self {
        Self {
            datagram_tx,
            destination,
            listeners: {
                let port = options.get("PORT").and_then(|port| port.parse::<u16>().ok());
                let dst_port = options.get("FROM_PORT").and_then(|port| port.parse::<u16>().ok());

                // `port` may not exist if `DatagramManager` is owned by a primary session
                port.map_or_else(HashMap::new, |port| {
                    HashMap::from_iter([(dst_port.unwrap_or(0), port)])
                })
            },
            signing_key,
            _runtime: Default::default(),
        }
    }

    /// Make repliable datagram.
    ///
    /// Caller must ensure to call this function with correct `protocol`.
    pub fn make_datagram(&mut self, protocol: Protocol, datagram: Vec<u8>) -> Vec<u8> {
        match protocol {
            Protocol::Datagram => {
                let signature = self.signing_key.sign(&datagram);
                let destination = self.destination.serialize();

                let mut out =
                    BytesMut::with_capacity(destination.len() + signature.len() + datagram.len());
                out.put_slice(&destination);
                out.put_slice(&signature);
                out.put_slice(&datagram);

                out.to_vec()
            }
            Protocol::Datagram2 => todo!("make datagram2"),
            Protocol::Anonymous => datagram,
            Protocol::Streaming => unreachable!(),
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

        let Some(port) = self.listeners.get(&dst_port) else {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_port,
                "no datagram listener for destination port",
            );
            return Err(Error::InvalidState);
        };

        match protocol {
            Protocol::Datagram => {
                let (rest, destination) =
                    Destination::parse_frame(&payload).map_err(|_| Error::InvalidData)?;
                let (rest, signature) =
                    take::<_, _, ()>(destination.verifying_key().signature_len())(rest)
                        .map_err(|_| Error::InvalidData)?;

                match destination.verifying_key() {
                    SigningPublicKey::DsaSha1(_) => return Err(Error::NotSupported),
                    verifying_key => verifying_key.verify(rest, signature)?,
                }

                let info = format!(
                    "{} FROM_PORT={src_port} TO_PORT={dst_port}\n",
                    base64_encode(destination.serialize())
                );

                let info = info.as_bytes();

                let mut out = BytesMut::with_capacity(info.len() + rest.len());
                out.put_slice(info);
                out.put_slice(rest);

                let _ = self.datagram_tx.try_send((*port, out.to_vec()));

                Ok(())
            }
            Protocol::Datagram2 => {
                let (rest, destination) =
                    Destination::parse_frame(&payload).map_err(|_| Error::InvalidData)?;

                let (rest, flags) =
                    DatagramFlags::parse_frame(rest).map_err(|_| Error::InvalidData)?;

                let (options, has_offsig) = match flags {
                    DatagramFlags::V2 {
                        options,
                        has_offsig,
                    } => (options, has_offsig),
                    _ => return Err(Error::InvalidData),
                };

                if has_offsig {
                    todo!("parse datagram offsig")
                }

                todo!()
            }
            Protocol::Anonymous => {
                let _ = self.datagram_tx.try_send((*port, payload));

                Ok(())
            }
            Protocol::Streaming => unreachable!(),
        }
    }

    /// Attempt add datagram listener.
    ///
    /// The SAMv3 `PORT` and `FROM_PORT` are parsed from `options` and if a listener for the same
    /// port already exists in [`DatagramManager`], the listener is not added to the set of
    /// listeners and `Err(())` is returned.
    ///
    /// If `PORT` doesn't exist in `options`, `Err(())` is return and if `FROM_PORT` is not
    /// specified in `options`, it defaults to `0`.
    pub fn add_listener(&mut self, options: HashMap<String, String>) -> Result<(), ()> {
        let dst_port = options
            .get("FROM_PORT")
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(0u16);
        let port = options.get("PORT").ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?options,
                "tried to register datagram listener without specifying `PORT`",
            );
        })?;

        if let Some(port) = self.listeners.get(&dst_port) {
            tracing::warn!(
                target: LOG_TARGET,
                ?port,
                ?dst_port,
                "listener for the specified destination port already exists",
            );
            return Err(());
        }

        match port.parse::<u16>() {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?port,
                    ?error,
                    "invalid `PORT` for datagram listener",
                );
                Err(())
            }
            Ok(port) => {
                self.listeners.insert(dst_port, port);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use thingbuf::mpsc::channel;

    #[test]
    fn create_datagram_session() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let manager = DatagramManager::<MockRuntime>::new(
            destination,
            tx,
            HashMap::from_iter([("PORT".to_string(), "8888".to_string())]),
            signing_key,
        );

        assert_eq!(manager.listeners.get(&0), Some(&8888));
    }

    #[test]
    fn create_datagram_session_with_dst_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let manager = DatagramManager::<MockRuntime>::new(
            destination,
            tx,
            HashMap::from_iter([
                ("PORT".to_string(), "1337".to_string()),
                ("FROM_PORT".to_string(), "8889".to_string()),
            ]),
            signing_key,
        );

        assert_eq!(manager.listeners.get(&8889), Some(&1337));
    }

    #[test]
    fn create_primary_session() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        assert!(manager.listeners.is_empty());
    }

    #[test]
    fn receive_datagram_on_non_existent_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        match manager.on_datagram(I2cpPayload {
            dst_port: 0,
            payload: vec![1, 3, 3, 7],
            protocol: Protocol::Datagram,
            src_port: 0,
        }) {
            Err(Error::InvalidState) => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn add_listener() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        assert!(manager
            .add_listener(HashMap::from_iter([
                ("PORT".to_string(), "2048".to_string()),
                ("FROM_PORT".to_string(), "7777".to_string()),
            ]))
            .is_ok());
        assert_eq!(manager.listeners.get(&7777), Some(&2048));
    }

    #[test]
    fn add_listener_with_default_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        assert!(manager
            .add_listener(HashMap::from_iter([(
                "PORT".to_string(),
                "2048".to_string()
            ),]))
            .is_ok());
        assert_eq!(manager.listeners.get(&0), Some(&2048));
    }

    #[test]
    fn add_listener_invalid_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        assert!(manager
            .add_listener(HashMap::from_iter([(
                "PORT".to_string(),
                "hello, world".to_string()
            ),]))
            .is_err());
    }

    #[test]
    fn add_listener_port_missing() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        assert!(manager
            .add_listener(HashMap::from_iter([(
                "FROM_PORT".to_string(),
                "1337".to_string()
            ),]))
            .is_err());
    }

    #[test]
    fn add_listener_invalid_src_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager =
            DatagramManager::<MockRuntime>::new(destination, tx, HashMap::new(), signing_key);

        assert!(manager
            .add_listener(HashMap::from_iter([
                ("PORT".to_string(), "2048".to_string()),
                ("FROM_PORT".to_string(), "hello, world".to_string()),
            ]))
            .is_ok());
    }

    #[test]
    fn add_listener_src_port_already_taken() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(
            destination,
            tx,
            HashMap::from_iter([("PORT".to_string(), "1337".to_string())]),
            signing_key,
        );
        assert_eq!(manager.listeners.get(&0), Some(&1337));

        assert!(manager
            .add_listener(HashMap::from_iter([(
                "PORT".to_string(),
                "2048".to_string()
            ),]))
            .is_err());
        assert_eq!(manager.listeners.get(&0), Some(&1337));
    }
}
