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
    error::ConnectionError,
    runtime::{AsyncRead, AsyncWrite, Runtime},
    Error,
};

use futures::FutureExt;
use rand_core::RngCore;

use core::{
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub mod udp;

pub trait AsyncReadExt: AsyncRead + Unpin {
    fn read_exact<R: Runtime>(
        &mut self,
        buffer: &mut [u8],
    ) -> impl Future<Output = crate::Result<()>>;
}

struct ReadExact<'a, T: AsyncRead + Unpin, R: Runtime> {
    inner: &'a mut T,
    buffer: &'a mut [u8],
    timer: R::Timer,
}

impl<'a, T: AsyncRead + Unpin, R: Runtime> ReadExact<'a, T, R> {
    pub fn new(inner: &'a mut T, buffer: &'a mut [u8]) -> Self {
        Self {
            inner,
            buffer,
            timer: R::timer(Duration::from_secs(10)),
        }
    }
}

impl<T: AsyncRead + Unpin, R: Runtime> Future for ReadExact<'_, T, R> {
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut *this.inner);

        if this.timer.poll_unpin(cx).is_ready() {
            return Poll::Ready(Err(Error::Connection(ConnectionError::ReadTimeout)));
        }

        while !this.buffer.is_empty() {
            let n = match stream.as_mut().poll_read(cx, this.buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(nread)) => nread,
            };

            {
                let (_, rest) = core::mem::take(&mut this.buffer).split_at_mut(n);
                this.buffer = rest;
            }
            if n == 0 {
                return Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed)));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncReadExt for T {
    fn read_exact<R: Runtime>(
        &mut self,
        buffer: &mut [u8],
    ) -> impl Future<Output = crate::Result<()>> {
        async move { ReadExact::<T, R>::new(self, buffer).await }
    }
}

pub trait AsyncWriteExt: AsyncWrite {
    fn write_all(&mut self, buffer: &[u8]) -> impl Future<Output = crate::Result<()>>;
    fn close(&mut self) -> impl Future<Output = crate::Result<()>>;
}

pub struct WriteAll<'a, T> {
    inner: &'a mut T,
    buffer: &'a [u8],
}

impl<'a, T: AsyncWrite + Unpin> WriteAll<'a, T> {
    fn new(inner: &'a mut T, buffer: &'a [u8]) -> Self {
        Self { inner, buffer }
    }
}

impl<T: AsyncWrite + Unpin> Future for WriteAll<'_, T> {
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut stream = Pin::new(&mut *this.inner);

        while !this.buffer.is_empty() {
            let n = match stream.as_mut().poll_write(cx, this.buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(nread)) => nread,
            };

            {
                let (_, rest) = core::mem::take(&mut this.buffer).split_at(n);
                this.buffer = rest;
            }
            if n == 0 {
                return Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed)));
            }
        }

        Poll::Ready(Ok(()))
    }
}

pub struct Close<'a, T> {
    inner: &'a mut T,
}

impl<'a, T: AsyncWrite + Unpin> Close<'a, T> {
    fn new(inner: &'a mut T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncWrite + Unpin> Future for Close<'_, T> {
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.inner).poll_close(cx)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWriteExt for T {
    fn write_all(&mut self, buffer: &[u8]) -> impl Future<Output = crate::Result<()>> {
        async move { WriteAll::new(self, buffer).await }
    }

    fn close(&mut self) -> impl Future<Output = crate::Result<()>> {
        Close::new(self)
    }
}

/// Fisher-Yates shuffle.
pub fn shuffle<T>(array: &mut [T], rng: &mut impl RngCore) {
    let len = array.len();

    for i in (1..len).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        array.swap(i, j);
    }
}

#[cfg(test)]
#[allow(unused)]
pub fn init_logger() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "trace");
        }
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

/// Check if an address is globally routable.
pub fn is_global(address: Ipv4Addr) -> bool {
    !((address >= Ipv4Addr::new(240, 0, 0, 0) && address <= Ipv4Addr::new(255, 255, 255, 254))
        || address.is_private()
        || (address >= Ipv4Addr::new(100, 64, 0, 0)
            && address <= Ipv4Addr::new(100, 127, 255, 255))
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_documentation()
        || (address >= Ipv4Addr::new(198, 18, 0, 0) && address <= Ipv4Addr::new(198, 19, 255, 255))
        || address.is_broadcast())
}

#[cfg(test)]
#[macro_export]
macro_rules! timeout {
    ($future:expr) => {
        tokio::time::timeout(std::time::Duration::from_secs(5), $future)
    };
    ($future:expr, $timeout:expr) => {
        tokio::time::timeout($timeout, $future)
    };
}
