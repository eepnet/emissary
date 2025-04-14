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

// TODO: documentation

use futures::Stream;
use rand_core::{CryptoRng, RngCore};

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

#[cfg(test)]
pub mod mock;
#[cfg(test)]
pub mod noop;

pub trait AsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<crate::Result<usize>>;
}

pub trait AsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<crate::Result<usize>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>>;
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>>;
}

pub trait TcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Sized + 'static {
    /// Establish connection to remote peer at `address`.
    fn connect(address: SocketAddr) -> impl Future<Output = Option<Self>> + Send;
}

pub trait TcpListener<TcpStream>: Unpin + Send + Sized + 'static {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>>;
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Option<(TcpStream, SocketAddr)>>;
    fn local_address(&self) -> Option<SocketAddr>;
}

pub trait UdpSocket: Unpin + Send + Sized {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>>;
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Option<usize>>;
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>>;
    fn local_address(&self) -> Option<SocketAddr>;
}

pub trait JoinSet<T>: Stream<Item = T> + Unpin + Send {
    /// Returns whether the `JoinSet` is empty.
    fn is_empty(&self) -> bool;

    /// Get the number of elements in `JoinSet`.
    fn len(&self) -> usize;

    /// Pushes `future` to `JoinSet`.
    fn push<F>(&mut self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send;
}

pub trait Instant: fmt::Debug + Copy + Clone + Send + Unpin + Sync {
    /// Return much time has passed since an `Instant` was created.
    fn elapsed(&self) -> Duration;
}

pub trait Counter {
    fn increment(&mut self, value: usize);
}

pub trait Gauge {
    fn increment(&mut self, value: usize);
    fn decrement(&mut self, value: usize);
}

pub trait Histogram {
    fn record(&mut self, record: f64);
}

pub trait MetricsHandle: Clone + Send + Sync + Unpin {
    fn counter(&self, name: &'static str) -> impl Counter;
    fn gauge(&self, name: &'static str) -> impl Gauge;
    fn histogram(&self, name: &'static str) -> impl Histogram;
}

/// Metric type.
pub enum MetricType {
    /// Counter.
    Counter {
        /// Counter name.
        name: &'static str,

        /// Counter description.
        description: &'static str,
    },

    /// Gauge.
    Gauge {
        /// Gauge name.
        name: &'static str,

        /// Gauge description.
        description: &'static str,
    },

    /// Histogram
    Histogram {
        /// Histogram name.
        name: &'static str,

        /// Histogram description.
        description: &'static str,

        /// Buckets.
        buckets: Vec<f64>,
    },
}

pub trait Runtime: Clone + Unpin + Send + 'static {
    type TcpStream: TcpStream;
    type UdpSocket: UdpSocket;
    type TcpListener: TcpListener<Self::TcpStream>;
    type JoinSet<T: Send + 'static>: JoinSet<T>;
    type MetricsHandle: MetricsHandle;
    type Instant: Instant;
    type Delayer: Future<Output = ()> + Send + Unpin;

    /// Spawn `future` in the background.
    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send;

    /// Return duration since Unix epoch.
    fn time_since_epoch() -> Duration;

    /// Get current time.
    fn now() -> Self::Instant;

    /// Return opaque type for generating random bytes.
    fn rng() -> impl RngCore + CryptoRng;

    /// Create new instance of a join set which contains a collection
    /// of futures that are polled together.
    ///
    /// For `tokio` this would be `tokio::task::join_set::JoinSet` and
    /// for `futures` this would be `future::stream::FuturesUnordered`
    fn join_set<T: Send + 'static>() -> Self::JoinSet<T>;

    /// Register `metrics` and return handle for registering metrics.
    ///
    /// An optional port can be specified for the metrics server and if none is specified, the
    /// runtime will bind to a default port or ignore it alltogether if it doesn't need it.
    fn register_metrics(metrics: Vec<MetricType>, port: Option<u16>) -> Self::MetricsHandle;

    /// Return pinned future which blocks for `duration` before returning.
    fn delayer(duration: Duration) -> Self::Delayer;

    /// Return a future which blocks for `duration` before returning.
    fn delay(duration: Duration) -> impl Future<Output = ()> + Send;

    /// GZIP-compress `bytes` and return the compressed byte vector.
    fn gzip_compress(bytes: impl AsRef<[u8]>) -> Option<Vec<u8>>;

    /// GZIP-decompress `bytes` and return the decompressed byte vector.
    fn gzip_decompress(bytes: impl AsRef<[u8]>) -> Option<Vec<u8>>;
}

pub trait AddressBook: Unpin + Send + Sync + 'static {
    /// Attempt to resolve `host` into a base64-encoded `Destination`.
    fn resolve(&self, host: String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>>;
}

pub trait Storage: Unpin + Send + Sync + 'static {
    /// Save routers and their profiles to disk.
    fn save_to_disk(&self, routers: Vec<(String, Option<Vec<u8>>, crate::Profile)>);
}
