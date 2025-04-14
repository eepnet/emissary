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

use crate::runtime::{
    AsyncRead, AsyncWrite, Counter, Gauge, Histogram, Instant as InstantT, JoinSet, MetricsHandle,
    Runtime, TcpListener, UdpSocket,
};

use futures::Stream;
use rand_core::{CryptoRng, RngCore};
use tokio::task;

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

pub struct NoopTcpStream(());

impl NoopTcpStream {
    pub fn new() -> Self {
        Self(())
    }
}

impl AsyncRead for NoopTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<crate::Result<usize>> {
        Poll::Pending
    }
}

impl AsyncWrite for NoopTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<crate::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        Poll::Pending
    }
}

impl crate::runtime::TcpStream for NoopTcpStream {
    fn connect(_address: SocketAddr) -> impl Future<Output = Option<Self>> + Send {
        std::future::pending()
    }
}

#[derive(Debug)]
pub struct NoopTcpListener {}

impl TcpListener<NoopTcpStream> for NoopTcpListener {
    fn bind(_address: SocketAddr) -> impl Future<Output = Option<Self>> {
        std::future::pending()
    }

    fn poll_accept(&mut self, _cx: &mut Context<'_>) -> Poll<Option<(NoopTcpStream, SocketAddr)>> {
        Poll::Pending
    }

    fn local_address(&self) -> Option<SocketAddr> {
        None
    }
}

pub struct NoopUdpSocket();

impl UdpSocket for NoopUdpSocket {
    fn bind(_address: SocketAddr) -> impl Future<Output = Option<Self>> {
        std::future::pending()
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _target: SocketAddr,
    ) -> Poll<Option<usize>> {
        Poll::Pending
    }

    fn poll_recv_from(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>> {
        Poll::Pending
    }

    fn local_address(&self) -> Option<SocketAddr> {
        None
    }
}

pub struct NoopMetricsCounter {}

impl Counter for NoopMetricsCounter {
    fn increment(&mut self, _value: usize) {}
}

pub struct NoopMetricsGauge {}

impl Gauge for NoopMetricsGauge {
    fn increment(&mut self, _value: usize) {}

    fn decrement(&mut self, _value: usize) {}
}

pub struct NoopMetricsHistogram {}

impl Histogram for NoopMetricsHistogram {
    fn record(&mut self, _record: f64) {}
}

#[derive(Debug, Clone)]
pub struct NoopMetricsHandle {}

impl MetricsHandle for NoopMetricsHandle {
    fn counter(&self, _name: &'static str) -> impl Counter {
        NoopMetricsCounter {}
    }

    fn gauge(&self, _name: &'static str) -> impl Gauge {
        NoopMetricsGauge {}
    }

    fn histogram(&self, _name: &'static str) -> impl Histogram {
        NoopMetricsHistogram {}
    }
}

#[allow(unused)]
pub struct NoopJoinSet<T>(task::JoinSet<T>);

impl<T: Send + 'static> JoinSet<T> for NoopJoinSet<T> {
    fn is_empty(&self) -> bool {
        true
    }

    fn len(&self) -> usize {
        0usize
    }

    fn push<F>(&mut self, _future: F)
    where
        F: Future<Output = T> + Send + 'static,
        F::Output: Send,
    {
    }
}

impl<T: Send + 'static> Stream for NoopJoinSet<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

#[derive(Debug, Copy, Clone)]
pub struct NoopInstant(Instant);

impl NoopInstant {
    /// Subtract `value` from inner `Instant`.
    pub fn subtract(mut self, value: Duration) -> Self {
        self.0 = self.0.checked_sub(value).unwrap();
        self
    }
}

impl InstantT for NoopInstant {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoopRuntime {}

impl NoopRuntime {
    pub fn get_counter_value(_name: &'static str) -> Option<usize> {
        None
    }

    pub fn get_gauge_value(_name: &'static str) -> Option<usize> {
        None
    }
}

impl Runtime for NoopRuntime {
    type TcpStream = NoopTcpStream;
    type UdpSocket = NoopUdpSocket;
    type TcpListener = NoopTcpListener;
    type JoinSet<T: Send + 'static> = NoopJoinSet<T>;
    type MetricsHandle = NoopMetricsHandle;
    type Instant = NoopInstant;
    type Delayer = std::future::Pending<()>;

    fn spawn<F>(_future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
    }

    fn time_since_epoch() -> Duration {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed")
    }

    fn now() -> Self::Instant {
        NoopInstant(Instant::now())
    }

    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        NoopJoinSet(task::JoinSet::<T>::new())
    }

    fn register_metrics(
        _metrics: Vec<crate::runtime::MetricType>,
        _: Option<u16>,
    ) -> Self::MetricsHandle {
        NoopMetricsHandle {}
    }

    fn delayer(_duration: Duration) -> Self::Delayer {
        std::future::pending()
    }

    async fn delay(_duration: Duration) {
        std::future::pending().await
    }

    fn gzip_compress(_bytes: impl AsRef<[u8]>) -> Option<Vec<u8>> {
        None
    }

    fn gzip_decompress(_bytes: impl AsRef<[u8]>) -> Option<Vec<u8>> {
        None
    }
}
