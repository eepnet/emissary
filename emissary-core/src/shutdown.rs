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

use crate::runtime::{JoinSet, Runtime};

use futures::{FutureExt, StreamExt};
use futures_channel::oneshot::{channel, Receiver, Sender};

use alloc::vec::Vec;
use core::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Handle given to subsystems which notifies them when the router needs to shut down.
///
/// Router is notified via [`ShutdownHandle::poll_next()`] when a shutdown has been requested,
/// allowing them to gracefully shut down themselves before notifying [`Router`] that they're ready
/// by calling [`ShutdownHandle::shutdow()`].
pub struct ShutdownHandle {
    /// Is the router shutting down.
    shutting_down: bool,

    /// RX channel for receiving a notification from [`Router`] that the subsystem should shut
    /// down.
    rx: Option<Receiver<Sender<()>>>,

    /// TX channel to notify [`Router`] that the subsystem is ready to shut down.
    tx: Option<Sender<()>>,
}

impl ShutdownHandle {
    /// Is the router shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    /// Shut down the subsystem.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Future for ShutdownHandle {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(ref mut rx) = self.rx {
            match futures::ready!(rx.poll_unpin(cx)) {
                Err(_) => {}
                Ok(tx) => {
                    self.shutting_down = true;
                    self.tx = Some(tx);
                    self.rx = None;

                    return Poll::Ready(());
                }
            }
        }

        Poll::Pending
    }
}

/// Shutdown context.
pub struct ShutdownContext<R: Runtime> {
    /// Shutdown futures.
    futures: R::JoinSet<()>,

    /// Handles.
    handles: Vec<Sender<Sender<()>>>,

    /// Has shutdown been initiated.
    shutting_down: bool,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> ShutdownContext<R> {
    /// Create new [`ShutdownContext`].
    pub fn new() -> Self {
        Self {
            futures: R::join_set(),
            handles: Vec::new(),
            shutting_down: false,
            waker: None,
        }
    }

    /// Allocate new [`ShutdownHandle`].
    pub fn handle(&mut self) -> ShutdownHandle {
        let (tx, rx) = channel();
        self.handles.push(tx);

        ShutdownHandle {
            shutting_down: false,
            rx: Some(rx),
            tx: None,
        }
    }

    /// Shut down the router.
    pub fn shutdown(&mut self) {
        self.shutting_down = true;

        mem::take(&mut self.handles).into_iter().for_each(|handle_tx| {
            let (tx, rx) = channel();

            // subsystem behind `handle_tx` may not be active any more so only register
            // it into `futures` if the send succeeds
            if let Ok(()) = handle_tx.send(tx) {
                self.futures.push(async move {
                    let _ = rx.await;
                });
            }
        });

        if let Some(waker) = self.waker.take() {
            waker.wake_by_ref();
        }
    }
}

impl<R: Runtime> Future for ShutdownContext<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.futures.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(Some(_)) => {}
                Poll::Ready(None) => return Poll::Ready(()),
            }
        }

        if self.futures.is_empty() && self.shutting_down {
            return Poll::Ready(());
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use std::time::Duration;

    #[tokio::test]
    async fn immediate_shutdown() {
        let mut context = ShutdownContext::<MockRuntime>::new();

        futures::future::poll_fn(|cx| match context.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            _ => panic!("shut down context ready"),
        })
        .await;

        for _ in 0..3 {
            let mut handle = context.handle();

            tokio::spawn(async move {
                let _ = (&mut handle).await;
                assert!(handle.is_shutting_down());
                handle.shutdown();
            });
        }

        context.shutdown();
        tokio::time::timeout(Duration::from_secs(5), &mut context)
            .await
            .expect("no timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_shutdown() {
        let mut context = ShutdownContext::<MockRuntime>::new();

        futures::future::poll_fn(|cx| match context.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            _ => panic!("shut down context ready"),
        })
        .await;

        for i in 2..5 {
            let mut handle = context.handle();

            tokio::spawn(async move {
                let _ = (&mut handle).await;
                assert!(handle.is_shutting_down());

                tokio::time::sleep(Duration::from_secs(i)).await;
                handle.shutdown();
            });
        }

        context.shutdown();
        tokio::time::timeout(Duration::from_secs(10), &mut context)
            .await
            .expect("no timeout");
    }

    #[tokio::test]
    async fn subsystem_already_shut_down() {
        let mut context = ShutdownContext::<MockRuntime>::new();

        futures::future::poll_fn(|cx| match context.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            _ => panic!("shut down context ready"),
        })
        .await;

        for i in 2..5 {
            let mut handle = context.handle();

            if i % 2 == 0 {
                drop(handle)
            } else {
                tokio::spawn(async move {
                    let _ = (&mut handle).await;
                    assert!(handle.is_shutting_down());
                    handle.shutdown();
                });
            }
        }

        context.shutdown();
        tokio::time::timeout(Duration::from_secs(5), &mut context)
            .await
            .expect("no timeout");
    }
}
