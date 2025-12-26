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

use crate::{
    error::ChannelError,
    runtime::{Runtime, UdpSocket as _},
};

use futures::{
    future::{select, Either},
    Stream,
};
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{vec, vec::Vec};
use core::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::{pin, Pin},
    task::{Context, Poll},
};

/// Datagram channel size.
const CHANNEL_SIZE: usize = 512usize;

/// Datagram.
#[derive(Clone)]
struct Datagram {
    /// Datagram bytes.
    datagram: Vec<u8>,

    /// Address of remote peer.
    target: SocketAddr,
}

impl Default for Datagram {
    fn default() -> Self {
        Self {
            datagram: Vec::new(),
            target: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
        }
    }
}

/// UDP socket handle.
///
/// Allows sending and receiving datagrams in a non-blocking manner.
pub struct UdpSocketHandle {
    /// Local address of the UDP socket.
    local_address: Option<SocketAddr>,

    /// RX channel for receiving datagrams.
    rx: Receiver<Datagram>,

    /// TX channel for sending datagrams.
    tx: Sender<Datagram>,
}

impl UdpSocketHandle {
    /// Attempt to send `datagram` to `target`.
    ///
    /// Internally the datagram is sent to [`UdpSocket`] which attempts to send the datagram to
    /// remote peer.
    pub fn try_send_to(
        &mut self,
        datagram: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), ChannelError> {
        self.tx.try_send(Datagram { datagram, target }).map_err(From::from)
    }

    /// Get local address of the UDP socket.
    pub fn local_address(&self) -> Option<SocketAddr> {
        self.local_address
    }
}

impl Stream for UdpSocketHandle {
    type Item = (Vec<u8>, SocketAddr);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(
            futures::ready!(self.rx.poll_recv(cx))
                .map(|Datagram { datagram, target }| (datagram, target)),
        )
    }
}

/// UDP socket.
///
/// Helps bridging between async/await and `Future` interfaces.
pub struct UdpSocket<R: Runtime> {
    /// RX channel for receiving datagrams from [`UdpSocketHandle`].
    rx: Receiver<Datagram>,

    /// Runtime UDP socket.
    socket: R::UdpSocket,

    /// TX channel for sending received datagrams to [`UdpSocketHandle`].
    tx: Sender<Datagram>,
}

impl<R: Runtime> UdpSocket<R> {
    /// Create new [`UdpSocket`].
    pub fn new(socket: R::UdpSocket) -> (Self, UdpSocketHandle) {
        let (recv_tx, recv_rx) = channel(CHANNEL_SIZE);
        let (send_tx, send_rx) = channel(CHANNEL_SIZE);
        let local_address = socket.local_address();

        (
            Self {
                rx: send_rx,
                socket,
                tx: recv_tx,
            },
            UdpSocketHandle {
                local_address,
                rx: recv_rx,
                tx: send_tx,
            },
        )
    }

    /// Run the event loop of [`UdpSocket`].
    pub async fn run(mut self) {
        let mut buffer = vec![0u8; 8192];

        loop {
            let result =
                match select(pin!(self.socket.recv_from(&mut buffer)), self.rx.recv()).await {
                    Either::Left((Some((size, address)), _)) => Either::Left((size, address)),
                    Either::Right((Some(Datagram { datagram, target }), _)) =>
                        Either::Right((datagram, target)),
                    _ => return,
                };

            if match result {
                Either::Left((size, address)) => self
                    .tx
                    .send(Datagram {
                        datagram: buffer[..size].to_vec(),
                        target: address,
                    })
                    .await
                    .ok(),
                Either::Right((datagram, target)) =>
                    self.socket.send_to(&datagram, target).await.map(|_| ()),
            }
            .is_none()
            {
                return;
            }
        }
    }
}
