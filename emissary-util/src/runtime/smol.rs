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
    channel::mpsc::{channel, Receiver, Sender},
    future::BoxFuture,
    stream::FuturesUnordered,
    AsyncRead as _, AsyncWrite as _, FutureExt, Stream,
};
use rand_core::{CryptoRng, RngCore};
use smol::{net, stream::StreamExt, Timer};

#[cfg(feature = "metrics")]
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
#[cfg(feature = "metrics")]
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

use std::{
    future::Future,
    io::Write,
    net::SocketAddr,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

/// Logging targer for the file.
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

pub struct SmolUdpSocket {
    dgram_tx: Sender<(Vec<u8>, SocketAddr)>,
    dgram_rx: Receiver<(Vec<u8>, SocketAddr)>,
    local_address: Option<SocketAddr>,
}

impl SmolUdpSocket {
    fn new(socket: net::UdpSocket) -> Self {
        let (send_tx, mut send_rx): (Sender<(Vec<u8>, SocketAddr)>, _) = channel(2048);
        let (mut recv_tx, recv_rx) = channel(2048);
        let local_address = socket.local_addr().ok();

        smol::spawn(async move {
            let mut buffer = vec![0u8; 0xffff];

            loop {
                futures::select! {
                    event = send_rx.next().fuse() => match event {
                        Some((datagram, target)) => {
                            if let Err(error) = socket.send_to(&datagram, target).await {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?target,
                                    ?error,
                                    "failed to send datagram",
                                );
                            }
                        }
                        None => return,
                    },
                    event = socket.recv_from(&mut buffer).fuse() => match event {
                        Ok((nread, sender)) => {
                            if let Err(error) = recv_tx.try_send((buffer[..nread].to_vec(), sender)) {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    ?sender,
                                    ?error,
                                    "failed to forward datagram",
                                );
                            }
                        }
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "socket error",
                            );
                            return;
                        }
                    }
                }
            }
        }).detach();

        Self {
            dgram_tx: send_tx,
            dgram_rx: recv_rx,
            local_address,
        }
    }
}

impl UdpSocket for SmolUdpSocket {
    fn bind(address: SocketAddr) -> impl Future<Output = Option<Self>> {
        async move { net::UdpSocket::bind(address).await.ok().map(Self::new) }
    }

    #[inline]
    fn poll_send_to(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Option<usize>> {
        let len = buf.len();
        match self.dgram_tx.try_send((buf.to_vec(), target)) {
            Ok(_) => Poll::Ready(Some(len)),
            Err(error) => {
                if error.is_full() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "datagram channel clogged",
                    );
                    return Poll::Ready(Some(len));
                }

                Poll::Ready(None)
            }
        }
    }

    #[inline]
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>> {
        match self.dgram_rx.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some((datagram, from))) =>
                if buf.len() < datagram.len() {
                    tracing::warn!(
                        target: LOG_TARGET,
                        datagram_len = ?datagram.len(),
                        buffer_len = ?buf.len(),
                        "truncating datagram",
                    );
                    debug_assert!(false);
                    buf.copy_from_slice(&datagram[..buf.len()]);

                    Poll::Ready(Some((buf.len(), from)))
                } else {
                    buf[..datagram.len()].copy_from_slice(&datagram);
                    Poll::Ready(Some((datagram.len(), from)))
                },
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
        Box::pin(smol::Timer::after(duration))
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
