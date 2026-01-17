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
    error::{ConnectionError, Error},
    runtime::{
        AsyncRead, AsyncWrite, Counter, Gauge, Histogram, Instant as InstantT, JoinSet,
        MetricsHandle, Runtime, TcpListener, UdpSocket,
    },
};

use flate2::{
    write::{GzDecoder, GzEncoder},
    Compression,
};
use futures::Stream;
use futures_io::{AsyncRead as _, AsyncWrite as _};
use parking_lot::RwLock;
use rand_core::{CryptoRng, RngCore};
use tokio::{io::ReadBuf, net, task, time::Sleep};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use std::{
    collections::HashMap,
    future::Future,
    io::Write,
    net::SocketAddr,
    pin::{pin, Pin},
    sync::{Arc, LazyLock},
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

pub struct MockTcpStream(Compat<net::TcpStream>);

impl MockTcpStream {
    pub fn new(stream: net::TcpStream) -> Self {
        let stream = TokioAsyncReadCompatExt::compat(stream).into_inner();
        let stream = TokioAsyncWriteCompatExt::compat_write(stream);

        Self(stream)
    }
}

impl AsyncRead for MockTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<crate::Result<usize>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_read(cx, buf)) {
            Ok(nread) => Poll::Ready(Ok(nread)),
            Err(_) => Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed))),
        }
    }
}

impl AsyncWrite for MockTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<crate::Result<usize>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_write(cx, buf)) {
            Ok(nwritten) => Poll::Ready(Ok(nwritten)),
            Err(_) => Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed))),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_close(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed))),
        }
    }
}

impl crate::runtime::TcpStream for MockTcpStream {
    fn connect(address: SocketAddr) -> impl Future<Output = Option<Self>> + Send {
        async move {
            net::TcpStream::connect(address).await.ok().map(|stream| {
                let stream = TokioAsyncReadCompatExt::compat(stream).into_inner();
                let stream = TokioAsyncWriteCompatExt::compat_write(stream);

                MockTcpStream(stream)
            })
        }
    }
}

pub struct MockTcpListener(net::TcpListener);

impl TcpListener<MockTcpStream> for MockTcpListener {
    async fn bind(address: SocketAddr) -> Option<Self> {
        net::TcpListener::bind(&address).await.ok().map(MockTcpListener)
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Option<(MockTcpStream, SocketAddr)>> {
        match futures::ready!(self.0.poll_accept(cx)) {
            Err(_) => Poll::Ready(None),
            Ok((stream, address)) => Poll::Ready(Some((MockTcpStream::new(stream), address))),
        }
    }

    fn local_address(&self) -> Option<SocketAddr> {
        self.0.local_addr().ok()
    }
}

#[derive(Clone)]
pub struct MockUdpSocket(Arc<net::UdpSocket>);

impl UdpSocket for MockUdpSocket {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>> {
        async move { net::UdpSocket::bind(address).await.ok().map(|socket| Self(Arc::new(socket))) }
    }

    fn send_to(&mut self, buf: &[u8], target: SocketAddr) -> impl Future<Output = Option<usize>> {
        async move { self.0.send_to(buf, target).await.ok() }
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> impl Future<Output = Option<(usize, SocketAddr)>> {
        async move { self.0.recv_from(buf).await.ok() }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Option<usize>> {
        Poll::Ready(futures::ready!(self.0.poll_send_to(cx, buf, target)).ok())
    }

    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>> {
        let mut buf = ReadBuf::new(buf);

        match futures::ready!(self.0.poll_recv_from(cx, &mut buf)) {
            Err(_) => return Poll::Ready(None),
            Ok(from) => {
                let nread = buf.filled().len();
                Poll::Ready(Some((nread, from)))
            }
        }
    }

    fn local_address(&self) -> Option<SocketAddr> {
        self.0.local_addr().ok()
    }
}

thread_local! {
    /// Counters and their values.
    static COUNTERS: LazyLock<Arc<RwLock<HashMap<&'static str, usize>>>> = LazyLock::new(|| Default::default());

    /// Gauges and their values.
    static GAUGES: LazyLock<Arc<RwLock<HashMap<&'static str, usize>>>> = LazyLock::new(|| Default::default());

    /// Custom timestamp for testing
    static CUSTOM_TIME: LazyLock<Arc<RwLock<Option<Duration>>>> = LazyLock::new(|| Default::default());
}

pub struct MockMetricsCounter {
    name: &'static str,
}

impl Counter for MockMetricsCounter {
    fn increment(&mut self, value: usize) {
        COUNTERS.with(|v| {
            let mut inner = v.write();
            *inner.entry(self.name).or_default() += value;
        });
    }
}

pub struct MockMetricsGauge {
    name: &'static str,
}

impl Gauge for MockMetricsGauge {
    fn increment(&mut self, value: usize) {
        GAUGES.with(|v| {
            let mut inner = v.write();
            *inner.entry(self.name).or_default() += value;
        });
    }

    fn decrement(&mut self, value: usize) {
        GAUGES.with(|v| {
            let mut inner = v.write();
            let entry = inner.entry(self.name).or_default();
            *entry = value.saturating_sub(value);
        });
    }
}

pub struct MockMetricsHistogram {}

impl Histogram for MockMetricsHistogram {
    fn record(&mut self, _: f64) {}
}

#[derive(Debug, Clone)]
pub struct MockMetricsHandle {}

impl MetricsHandle for MockMetricsHandle {
    fn counter(&self, name: &'static str) -> impl Counter {
        MockMetricsCounter { name }
    }

    fn gauge(&self, name: &'static str) -> impl Gauge {
        MockMetricsGauge { name }
    }

    fn histogram(&self, _: &'static str) -> impl Histogram {
        MockMetricsHistogram {}
    }
}

pub struct MockJoinSet<T>(task::JoinSet<T>, Option<Waker>);

impl<T: Send + 'static> JoinSet<T> for MockJoinSet<T> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn push<F>(&mut self, future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send,
    {
        let _ = self.0.spawn(future);
        self.1.as_mut().map(|waker| waker.wake_by_ref());
    }
}

impl<T: Send + 'static> Stream for MockJoinSet<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_join_next(cx) {
            Poll::Pending | Poll::Ready(None) => {
                self.1 = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Some(Err(_))) => Poll::Ready(None),
            Poll::Ready(Some(Ok(value))) => Poll::Ready(Some(value)),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MockInstant(Instant);

impl MockInstant {
    /// Subtract `value` from inner `Instant`.
    pub fn subtract(mut self, value: Duration) -> Self {
        self.0 = self.0.checked_sub(value).unwrap();
        self
    }
}

impl InstantT for MockInstant {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRuntime {}

impl MockRuntime {
    pub fn get_counter_value(name: &'static str) -> Option<usize> {
        COUNTERS.with(|v| v.read().get(name).copied())
    }

    pub fn get_gauge_value(name: &'static str) -> Option<usize> {
        GAUGES.with(|v| v.read().get(name).copied())
    }

    /// Set a custom timestamp to be returned by `Runtime::time_since_epoch()`.
    pub fn set_time(duration: Option<Duration>) {
        CUSTOM_TIME.with(|v| {
            *v.write() = duration;
        });
    }
}

impl Runtime for MockRuntime {
    type TcpStream = MockTcpStream;
    type UdpSocket = MockUdpSocket;
    type TcpListener = MockTcpListener;
    type JoinSet<T: Send + 'static> = MockJoinSet<T>;
    type MetricsHandle = MockMetricsHandle;
    type Instant = MockInstant;
    type Timer = Pin<Box<Sleep>>;

    /// Spawn `future` in the background.
    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        tokio::spawn(future);
    }

    /// Return duration since Unix epoch.
    fn time_since_epoch() -> Duration {
        CUSTOM_TIME.with(|v| {
            v.read().as_ref().copied().unwrap_or_else(|| {
                SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed")
            })
        })
    }

    /// Get current time.
    fn now() -> Self::Instant {
        MockInstant(Instant::now())
    }

    /// Return opaque type for generating random bytes.
    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    /// Create new instance of a join set which contains a collection
    /// of futures that are polled together.
    ///
    /// For `tokio` this would be `tokio::task::join_set::JoinSet` and
    /// for `futures` this would be `future::stream::FuturesUnordered`
    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        MockJoinSet(task::JoinSet::<T>::new(), None)
    }

    /// Register `metrics` and return handle for registering metrics.
    fn register_metrics(_: Vec<crate::runtime::MetricType>, _: Option<u16>) -> Self::MetricsHandle {
        MockMetricsHandle {}
    }

    /// Return future which blocks for `duration` before returning.
    fn timer(duration: Duration) -> Self::Timer {
        Box::pin(tokio::time::sleep(duration))
    }

    async fn delay(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    fn gzip_compress(bytes: impl AsRef<[u8]>) -> Option<Vec<u8>> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(bytes.as_ref()).ok()?;

        e.finish().ok()
    }

    fn gzip_decompress(bytes: impl AsRef<[u8]>) -> Option<Vec<u8>> {
        let mut e = GzDecoder::new(Vec::new());
        e.write_all(bytes.as_ref()).ok()?;

        e.finish().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_time() {
        // Default behavior returns system time
        let system_time = MockRuntime::time_since_epoch();
        assert!(system_time.as_secs() > 0);

        // Set custom time
        let custom_duration = Duration::from_secs(12345);
        MockRuntime::set_time(Some(custom_duration));
        assert_eq!(MockRuntime::time_since_epoch(), custom_duration);

        // Clear custom time
        MockRuntime::set_time(None);
        assert!(MockRuntime::time_since_epoch() >= system_time);
    }
}
