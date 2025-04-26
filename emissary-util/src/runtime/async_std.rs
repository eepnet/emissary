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

use async_std::net;
use emissary_core::runtime::{
    AsyncRead, AsyncWrite, Counter, Gauge, Histogram, Instant as InstantT, JoinSet, MetricType,
    MetricsHandle, Runtime as RuntimeT, TcpListener, TcpStream, UdpSocket,
};
use flate2::{
    write::{GzDecoder, GzEncoder},
    Compression,
};
use futures::{
    future::BoxFuture,
    stream::{BoxStream, FuturesUnordered},
    AsyncRead as _, Stream, StreamExt,
};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use rand_core::{CryptoRng, RngCore};

use std::{
    future::Future,
    io::Write,
    net::SocketAddr,
    pin::{pin, Pin},
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::runtime::async-std";

#[derive(Clone)]
pub struct Runtime {}

impl Runtime {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AsyncStdTcpStream(net::TcpStream);

impl AsyncStdTcpStream {
    fn new(stream: net::TcpStream) -> Self {
        Self(stream)
    }
}

impl AsyncRead for AsyncStdTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<emissary_core::Result<usize>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_read(cx, buf)) {
            Ok(nread) => Poll::Ready(Ok(nread)),
            Err(error) => Poll::Ready(Err(emissary_core::Error::Custom(error.to_string()))),
        }
    }
}

impl AsyncWrite for AsyncStdTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<emissary_core::Result<usize>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_write(cx, buf)) {
            Ok(nwritten) => Poll::Ready(Ok(nwritten)),
            Err(error) => Poll::Ready(Err(emissary_core::Error::Custom(error.to_string()))),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<emissary_core::Result<()>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(emissary_core::Error::Custom(error.to_string()))),
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<emissary_core::Result<()>> {
        let pinned = pin!(&mut self.0);

        match futures::ready!(pinned.poll_close(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(emissary_core::Error::Custom(error.to_string()))),
        }
    }
}

impl TcpStream for AsyncStdTcpStream {
    async fn connect(address: SocketAddr) -> Option<Self> {
        match async_std::future::timeout(Duration::from_secs(10), net::TcpStream::connect(address))
            .await
        {
            Err(_) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?address,
                    "timeout while dialing address",
                );
                None
            }
            Ok(Err(error)) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?address,
                    error = ?error.kind(),
                    "failed to connect"
                );
                None
            }
            Ok(Ok(stream)) => Some(Self::new(stream)),
        }
    }
}

pub struct AsyncStdTcpListener(
    (
        SocketAddr,
        BoxStream<'static, async_std::io::Result<net::TcpStream>>,
    ),
);

impl TcpListener<AsyncStdTcpStream> for AsyncStdTcpListener {
    // TODO: can be made sync with `socket2`
    async fn bind(address: SocketAddr) -> Option<Self> {
        net::TcpListener::bind(&address)
            .await
            .map_err(|error| {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?address,
                    ?error,
                    "failed to bind"
                );
            })
            .ok()
            .map(|listener| {
                let address = listener.local_addr().expect("to succeed");

                AsyncStdTcpListener((address, Box::pin(listener.into_incoming())))
            })
    }

    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(AsyncStdTcpStream, SocketAddr)>> {
        loop {
            match futures::ready!(self.0 .1.poll_next_unpin(cx)) {
                Some(Ok(stream)) => match stream.local_addr() {
                    Ok(address) => return Poll::Ready(Some((AsyncStdTcpStream(stream), address))),
                    Err(_) => continue,
                },
                Some(Err(error)) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to accept connection",
                    );
                    return Poll::Ready(None);
                }
                None => {
                    return Poll::Ready(None);
                }
            }
        }
    }

    fn local_address(&self) -> Option<SocketAddr> {
        Some(self.0 .0)
    }
}

#[derive(Clone)]
pub struct AsyncStdUdpSocket {
    socket: Arc<net::UdpSocket>,
    local_address: Option<SocketAddr>,
}

impl UdpSocket for AsyncStdUdpSocket {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>> {
        async move {
            net::UdpSocket::bind(address).await.ok().map(|socket| Self {
                local_address: socket.local_addr().ok(),
                socket: Arc::new(socket),
            })
        }
    }

    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Option<usize>> {
        Poll::Ready(futures::ready!(pin!(self.socket.send_to(buf, target)).poll(cx)).ok())
    }

    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>> {
        match futures::ready!(pin!(self.socket.recv_from(buf)).poll(cx)) {
            Err(_) => Poll::Ready(None),
            Ok((nread, from)) => Poll::Ready(Some((nread, from))),
        }
    }

    fn local_address(&self) -> Option<SocketAddr> {
        self.local_address
    }
}

#[derive(Default)]
pub struct FuturesJoinSet<T>(FuturesUnordered<BoxFuture<'static, T>>);

impl<T> FuturesJoinSet<T> {
    fn new() -> Self {
        Self(FuturesUnordered::new())
    }
}

impl<T: Send + 'static> JoinSet<T> for FuturesJoinSet<T> {
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
        let handle = async_std::task::spawn(future);

        self.0.push(Box::pin(handle));
    }
}

impl<T: Send + 'static> Stream for FuturesJoinSet<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.is_empty() {
            false => self.0.poll_next_unpin(cx),
            true => Poll::Pending,
        }
    }
}

pub struct AsyncStdJoinSet<T>(FuturesJoinSet<T>, Option<Waker>);

impl<T: Send + 'static> JoinSet<T> for AsyncStdJoinSet<T> {
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
        self.0.push(future);

        if let Some(waker) = self.1.take() {
            waker.wake_by_ref()
        }
    }
}

impl<T: Send + 'static> Stream for AsyncStdJoinSet<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_next_unpin(cx) {
            Poll::Pending | Poll::Ready(None) => {
                self.1 = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Some(value)) => Poll::Ready(Some(value)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AsyncStdInstant(Instant);

impl InstantT for AsyncStdInstant {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Clone)]
struct AsyncStdMetricsCounter(&'static str);

impl Counter for AsyncStdMetricsCounter {
    fn increment(&mut self, value: usize) {
        counter!(self.0).increment(value as u64);
    }
}

#[derive(Clone)]
struct AsyncStdMetricsGauge(&'static str);

impl Gauge for AsyncStdMetricsGauge {
    fn increment(&mut self, value: usize) {
        gauge!(self.0).increment(value as f64);
    }

    fn decrement(&mut self, value: usize) {
        gauge!(self.0).decrement(value as f64);
    }
}

#[derive(Clone)]
struct AsyncStdMetricsHistogram(&'static str);

impl Histogram for AsyncStdMetricsHistogram {
    fn record(&mut self, record: f64) {
        histogram!(self.0).record(record);
    }
}

#[derive(Clone)]
pub struct AsyncStdMetricsHandle;

impl MetricsHandle for AsyncStdMetricsHandle {
    fn counter(&self, name: &'static str) -> impl Counter {
        AsyncStdMetricsCounter(name)
    }

    fn gauge(&self, name: &'static str) -> impl Gauge {
        AsyncStdMetricsGauge(name)
    }

    fn histogram(&self, name: &'static str) -> impl Histogram {
        AsyncStdMetricsHistogram(name)
    }
}

impl RuntimeT for Runtime {
    type TcpStream = AsyncStdTcpStream;
    type UdpSocket = AsyncStdUdpSocket;
    type TcpListener = AsyncStdTcpListener;
    type JoinSet<T: Send + 'static> = AsyncStdJoinSet<T>;
    type MetricsHandle = AsyncStdMetricsHandle;
    type Instant = AsyncStdInstant;
    type Timer = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        async_std::task::spawn(future);
    }

    fn time_since_epoch() -> Duration {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed")
    }

    fn now() -> Self::Instant {
        AsyncStdInstant(Instant::now())
    }

    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        AsyncStdJoinSet(FuturesJoinSet::<T>::new(), None)
    }

    fn register_metrics(metrics: Vec<MetricType>, port: Option<u16>) -> Self::MetricsHandle {
        if metrics.is_empty() {
            return AsyncStdMetricsHandle {};
        }

        let builder = PrometheusBuilder::new().with_http_listener(
            format!("0.0.0.0:{}", port.unwrap_or(12842)).parse::<SocketAddr>().expect(""),
        );

        metrics
            .into_iter()
            .fold(builder, |builder, metric| match metric {
                MetricType::Counter { name, description } => {
                    describe_counter!(name, description);
                    builder
                }
                MetricType::Gauge { name, description } => {
                    describe_gauge!(name, description);
                    builder
                }
                MetricType::Histogram {
                    name,
                    description,
                    buckets,
                } => {
                    describe_histogram!(name, description);
                    builder
                        .set_buckets_for_metric(Matcher::Full(name.to_string()), &buckets)
                        .expect("to succeed")
                }
            })
            .install()
            .expect("to succeed");

        AsyncStdMetricsHandle {}
    }

    fn timer(duration: Duration) -> Self::Timer {
        Box::pin(async_std::task::sleep(duration))
    }

    async fn delay(duration: Duration) {
        async_std::task::sleep(duration).await
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
