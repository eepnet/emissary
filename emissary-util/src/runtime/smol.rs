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

use emissary_core::runtime::{
    AsyncRead, AsyncWrite, Counter, Gauge, Histogram, Instant as InstantT, JoinSet, MetricType,
    MetricsHandle, Runtime as RuntimeT, TcpListener, TcpStream, UdpSocket,
};
use flate2::{
    write::{GzDecoder, GzEncoder},
    Compression,
};
use futures::{
    future::BoxFuture, stream::FuturesUnordered, AsyncRead as _, AsyncWrite as _, FutureExt, Stream,
};
use rand_core::{CryptoRng, RngCore};
use smol::{net, stream::StreamExt, Async};

#[cfg(feature = "metrics")]
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
#[cfg(feature = "metrics")]
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

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
const LOG_TARGET: &str = "emissary::runtime::smol";

#[derive(Default, Clone)]
pub struct Runtime {}

impl Runtime {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct SmolTcpStream(net::TcpStream);

impl SmolTcpStream {
    fn new(stream: net::TcpStream) -> Self {
        Self(stream)
    }
}

impl AsyncRead for SmolTcpStream {
    #[inline]
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

impl AsyncWrite for SmolTcpStream {
    #[inline]
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

    #[inline]
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

    #[inline]
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

impl TcpStream for SmolTcpStream {
    async fn connect(address: SocketAddr) -> Option<Self> {
        match async {
            futures::select! {
                res = net::TcpStream::connect(address).fuse() => Some(res),
                _ = futures::FutureExt::fuse(smol::Timer::after(Duration::from_secs(10))) => None,
            }
        }
        .await
        {
            Some(Ok(stream)) => {
                stream.set_nodelay(true).ok()?;
                Some(Self::new(stream))
            }
            Some(Err(error)) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?address,
                    error = ?error.kind(),
                    "failed to connect"
                );
                None
            }
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?address,
                    "timeout while dialing address",
                );
                None
            }
        }
    }
}

pub struct SmolTcpListener(net::TcpListener);

impl TcpListener<SmolTcpStream> for SmolTcpListener {
    // TODO: can be made sync with `socket2`
    async fn bind(address: SocketAddr) -> Option<Self> {
        net::TcpListener::bind(address)
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
            .map(SmolTcpListener)
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Option<(SmolTcpStream, SocketAddr)>> {
        loop {
            match futures::ready!(self.0.incoming().poll_next(cx)) {
                Some(Ok(stream)) => match stream.local_addr() {
                    Ok(address) => return Poll::Ready(Some((SmolTcpStream(stream), address))),
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
        self.0.local_addr().ok()
    }
}

#[derive(Clone)]
pub struct SmolUdpSocket(Arc<Async<std::net::UdpSocket>>);

impl UdpSocket for SmolUdpSocket {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>> {
        async move {
            Async::<std::net::UdpSocket>::bind(address)
                .ok()
                .map(|socket| Self(Arc::new(socket)))
        }
    }

    #[inline]
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Option<usize>> {
        loop {
            match self.0.poll_writable(cx) {
                Poll::Ready(Ok(_)) => match self.0.get_ref().send_to(buf, target) {
                    Ok(n) => return Poll::Ready(Some(n)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => return Poll::Ready(None),
                },
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    #[inline]
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>> {
        loop {
            match self.0.poll_readable(cx) {
                Poll::Ready(Ok(_)) => match self.0.get_ref().recv_from(buf) {
                    Ok((n, addr)) => return Poll::Ready(Some((n, addr))),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => return Poll::Ready(None),
                },
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_address(&self) -> Option<SocketAddr> {
        self.0.get_ref().local_addr().ok()
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
        let handle = smol::spawn(future);

        self.0.push(Box::pin(handle));
    }
}

impl<T: Send + 'static> Stream for FuturesJoinSet<T> {
    type Item = T;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.is_empty() {
            false => self.0.poll_next(cx),
            true => Poll::Pending,
        }
    }
}

pub struct SmolJoinSet<T>(FuturesJoinSet<T>, Option<Waker>);

impl<T: Send + 'static> JoinSet<T> for SmolJoinSet<T> {
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

impl<T: Send + 'static> Stream for SmolJoinSet<T> {
    type Item = T;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_next(cx) {
            Poll::Pending | Poll::Ready(None) => {
                self.1 = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Some(value)) => Poll::Ready(Some(value)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SmolInstant(Instant);

impl InstantT for SmolInstant {
    #[inline]
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Clone)]
#[allow(unused)]
struct SmolMetricsCounter(&'static str);

impl Counter for SmolMetricsCounter {
    #[cfg(feature = "metrics")]
    #[inline]
    fn increment(&mut self, value: usize) {
        counter!(self.0).increment(value as u64);
    }

    #[cfg(not(feature = "metrics"))]
    fn increment(&mut self, _: usize) {}
}

#[derive(Clone)]
#[allow(unused)]
struct SmolMetricsGauge(&'static str);

impl Gauge for SmolMetricsGauge {
    #[cfg(feature = "metrics")]
    #[inline]
    fn increment(&mut self, value: usize) {
        gauge!(self.0).increment(value as f64);
    }

    #[cfg(feature = "metrics")]
    #[inline]
    fn decrement(&mut self, value: usize) {
        gauge!(self.0).decrement(value as f64);
    }

    #[cfg(not(feature = "metrics"))]
    fn increment(&mut self, _: usize) {}

    #[cfg(not(feature = "metrics"))]
    fn decrement(&mut self, _: usize) {}
}

#[derive(Clone)]
#[allow(unused)]
struct SmolMetricsHistogram(&'static str);

impl Histogram for SmolMetricsHistogram {
    #[cfg(feature = "metrics")]
    #[inline]
    fn record(&mut self, record: f64) {
        histogram!(self.0).record(record);
    }

    #[cfg(not(feature = "metrics"))]
    fn record(&mut self, _: f64) {}
}

#[derive(Clone)]
pub struct SmolMetricsHandle;

impl MetricsHandle for SmolMetricsHandle {
    #[inline]
    fn counter(&self, name: &'static str) -> impl Counter {
        SmolMetricsCounter(name)
    }

    #[inline]
    fn gauge(&self, name: &'static str) -> impl Gauge {
        SmolMetricsGauge(name)
    }

    #[inline]
    fn histogram(&self, name: &'static str) -> impl Histogram {
        SmolMetricsHistogram(name)
    }
}

impl RuntimeT for Runtime {
    type TcpStream = SmolTcpStream;
    type UdpSocket = SmolUdpSocket;
    type TcpListener = SmolTcpListener;
    type JoinSet<T: Send + 'static> = SmolJoinSet<T>;
    type MetricsHandle = SmolMetricsHandle;
    type Instant = SmolInstant;
    type Timer = Pin<Box<dyn Future<Output = ()> + Send>>;

    #[inline]
    fn spawn<F>(future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        smol::spawn(future).detach();
    }

    #[inline]
    fn time_since_epoch() -> Duration {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("to succeed")
    }

    #[inline]
    fn now() -> Self::Instant {
        SmolInstant(Instant::now())
    }

    #[inline]
    fn rng() -> impl RngCore + CryptoRng {
        rand_core::OsRng
    }

    #[inline]
    fn join_set<T: Send + 'static>() -> Self::JoinSet<T> {
        SmolJoinSet(FuturesJoinSet::<T>::new(), None)
    }

    #[cfg(feature = "metrics")]
    fn register_metrics(metrics: Vec<MetricType>, port: Option<u16>) -> Self::MetricsHandle {
        if metrics.is_empty() {
            return SmolMetricsHandle {};
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

        SmolMetricsHandle {}
    }

    #[cfg(not(feature = "metrics"))]
    fn register_metrics(_: Vec<MetricType>, _: Option<u16>) -> Self::MetricsHandle {
        SmolMetricsHandle {}
    }

    #[inline]
    fn timer(duration: Duration) -> Self::Timer {
        Box::pin(async move {
            smol::Timer::after(duration).await;
        })
    }

    #[inline]
    async fn delay(duration: Duration) {
        smol::Timer::after(duration).await;
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
