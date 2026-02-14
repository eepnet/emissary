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
    destination::routing_path::{PendingRoutingPathHandle, RoutingPathHandle},
    error::StreamingError,
    primitives::DestinationId,
    runtime::{JoinSet, Runtime, TcpStream},
    sam::socket::SamSocket,
    util::AsyncWriteExt,
};

use futures::{future::BoxFuture, StreamExt};

use alloc::{boxed::Box, collections::VecDeque};
use core::{
    fmt, mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::streaming::listener";

/// Events emitted by [`StreamListener`].
pub enum StreamListenerEvent {
    /// Listener is ready.
    ///
    /// This event is used to notify [`StreamManager`] of a listener in case there are pending
    /// inbound streams.
    ListenerReady,
}

/// Virtual stream listener kind.
pub enum ListenerKind<R: Runtime> {
    /// Listener used to accept one inbound virtual stream (`STREAM ACCEPT`).
    Ephemeral {
        /// Pending routing path handle.
        ///
        /// Bound to a `DestinationId` once an inbound connection has been estasblished.
        pending_routing_path_handle: PendingRoutingPathHandle,

        /// Has the stream configured to be silent.
        silent: bool,

        /// SAMv3 socket used to communicate with the client.
        socket: Box<SamSocket<R>>,
    },

    /// Listener used to accept all inbound virtual stream (`STREAM FORWARD`).
    Persistent {
        /// Pending routing path handle.
        ///
        /// Bound to a `DestinationId` once an inbound connection has been estasblished.
        pending_routing_path_handle: PendingRoutingPathHandle,

        /// Port which the persistent TCP listener is listening on.
        port: u16,

        /// Has the stream configured to be silent.
        silent: bool,

        /// SAMv3 socket used the client used to send the `STREAM FORWARD` command.
        socket: Box<SamSocket<R>>,
    },
}

impl<R: Runtime> fmt::Debug for ListenerKind<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ephemeral { .. } =>
                f.debug_struct("ListenerKind::Ephemeral").finish_non_exhaustive(),
            Self::Persistent { port, .. } => f
                .debug_struct("ListenerKind::Persistent")
                .field("port", &port)
                .finish_non_exhaustive(),
        }
    }
}

/// Socket kind for a SAMV3 socket.
pub enum SocketKind<R: Runtime> {
    /// Direct connection opened with `STREAM CONNECT`.
    Connect {
        /// Underlying TCP stream of the SAMv3 socket.
        socket: R::TcpStream,

        /// Has the stream configured to be silent.
        silent: bool,

        /// Routing path handle.
        routing_path_handle: RoutingPathHandle<R>,
    },

    /// Direct connection opened with `STREAM ACCEPT`.
    Accept {
        /// Pending routing path handle.
        pending_routing_path_handle: PendingRoutingPathHandle,

        /// Underlying TCP stream of the SAMv3 socket.
        socket: R::TcpStream,

        /// Has the stream configured to be silent.
        silent: bool,
    },

    /// Forwarded connection open with `STREAM FORWARD`.
    ///
    /// Returns a future which attempts to open a TCP stream to the listener.
    Forwarded {
        /// Pending routing path handle.
        pending_routing_path_handle: PendingRoutingPathHandle,

        /// Future which attempts to open a new connection to the TCP listener.
        future: BoxFuture<'static, Option<R::TcpStream>>,

        /// Has the stream configured to be silent.
        silent: bool,
    },
}

/// Listener kind while it's being initialized.
enum PendingListenerKind {
    /// Ephemeral listener (`STREAM ACCEPT`).
    Ephemeral,

    /// Persistent listener (`STREAM FORWARD`).
    Persistent {
        /// Port where the TCP listener is listening on.
        port: u16,

        /// Have the streams been configured to be silent.
        silent: bool,
    },
}

impl fmt::Debug for PendingListenerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ephemeral { .. } => f.debug_struct("PendingListenerKind::Ephemeral").finish(),
            Self::Persistent { port, silent, .. } => f
                .debug_struct("PendingListenerKind::Persistent")
                .field("port", &port)
                .field("silent", &silent)
                .finish(),
        }
    }
}

/// Listener state.
///
/// [`StreamListener`] can alter between uninitialized, ephemeral and persisten states, depending on
/// which kind(s) of socket(s) are/is active. If all ephemeral sockets are consumed by incomming
/// connections, the state switches to uninitialized. Client can then register a new ephemeral or a
/// persisten listener. if a persistent listener is active, ephemeral listener is not allowed to be
/// registered until the socket that keeps the persistent listener open is closed. Then state
/// switches back to uninitialized and client can register another persistent or ephemeral socket.
enum ListenerState<R: Runtime> {
    /// Listener state is uninitialized.
    Uninitialized,

    /// Listener state is being initialized.
    ///
    /// Essentially this means that the connected client is being notified that the accept/forward
    /// request has been accepted and the socket is busy writing the message to client. Once the
    /// write has finished, [`StreamListener`] initializes itself to either
    /// [`ListenerState::Ephemeral`] (`STREAM ACCEPT`) or [`ListenerState::Persistent`] (`STREAM
    /// FORWARD`).
    Initializing {
        /// Listener kind.
        ///
        /// Which state shall [`StreamListener`] take after it has been initialized.
        kind: PendingListenerKind,
    },

    /// Listener is configured to be ephemeral.
    Ephemeral {
        /// Ephemeral sockest and their silence configuration.
        ///
        /// Each ephemeral socket is able to accept one stream.
        sockets: VecDeque<(Box<SamSocket<R>>, bool, PendingRoutingPathHandle)>,
    },

    /// Listener is configured to be persistent.
    Persistent {
        /// Pending routing path handle.
        pending_routing_path_handle: PendingRoutingPathHandle,

        /// Port of the active TCP listener.
        port: u16,

        /// Have the inbound streams been configured to be silent.
        silent: bool,

        /// Socket that was used to send the `STREAM FORWARD` command.
        #[allow(unused)]
        socket: Box<SamSocket<R>>,
    },

    /// Listener state has been poisoned.
    Poisoned,
}

impl<R: Runtime> fmt::Debug for ListenerState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => f.debug_struct("ListenerState::Uninitialized").finish(),
            Self::Initializing { kind } =>
                f.debug_struct("ListenerState::Initialzing").field("kind", &kind).finish(),
            Self::Ephemeral { sockets } => f
                .debug_struct("ListenerState::Ephemeral")
                .field("num_listeners", &sockets.len())
                .finish(),
            Self::Persistent { port, .. } => f
                .debug_struct("ListenerState::Persistent")
                .field("port", &port)
                .finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("ListenerState::Poisoned").finish(),
        }
    }
}

/// I2P virtual stream listener.
pub struct StreamListener<R: Runtime> {
    /// ID of the local destination.
    destination_id: DestinationId,

    /// Pending sockets.
    pending_sockets: R::JoinSet<crate::Result<(Box<SamSocket<R>>, PendingRoutingPathHandle)>>,

    /// Listener state.
    state: ListenerState<R>,

    /// Waker, if any.
    waker: Option<Waker>,
}

impl<R: Runtime> StreamListener<R> {
    /// Create new [`StreamListener`].
    pub fn new(destination_id: DestinationId) -> Self {
        Self {
            destination_id,
            pending_sockets: R::join_set(),
            state: ListenerState::Uninitialized,
            waker: None,
        }
    }

    /// Attempt to acquire a socket for an active listener.
    ///
    /// If there is a ready listener, it's returned to the caller via [`SocketKind`] which has
    /// slightly different initialization semantics, based on whether the listener is ephemeral or
    /// persistent. Ephemeral listeners are ready for use immediately as the same socket that was
    /// used to register the listener is also used for data path whereas if the listener was
    /// persistent, the caller must first poll a future which opens a new TCP stream to the
    /// forwarded TCP listener before starting the actual stream event loop.
    pub fn pop_socket(&mut self) -> Option<SocketKind<R>> {
        match &mut self.state {
            ListenerState::Ephemeral { ref mut sockets } => {
                // socket must exist since state is `Ephemeral` and not `Uninitialized`
                let (socket, silent, pending_routing_path_handle) =
                    sockets.pop_front().expect("to exist");

                if sockets.is_empty() {
                    self.state = ListenerState::Uninitialized;
                }

                Some(SocketKind::Accept {
                    pending_routing_path_handle,
                    silent,
                    socket: socket.into_inner(),
                })
            }
            ListenerState::Persistent {
                port,
                silent,
                pending_routing_path_handle,
                ..
            } => {
                let port = *port;
                let silent = *silent;

                Some(SocketKind::Forwarded {
                    pending_routing_path_handle: pending_routing_path_handle.clone(),
                    silent,
                    future: Box::pin(async move {
                        R::TcpStream::connect(SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                            port,
                        ))
                        .await
                    }),
                })
            }
            state => {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?state,
                    "no stream available",
                );
                None
            }
        }
    }

    /// Validate that `kind` is an approriate listener kind with the current state.
    ///
    /// `STREAM ACCEPT` and `STREAM FORWARD` are mutually exclusive and the second socket for the
    /// incompatible kind is rejected. Multiple `STREAM FORWARD`s are also not supported.
    ///
    /// On success the function returns `kind` so the caller can process it normally and on error
    /// the function returns `None` and sends a rejection message to the client.
    fn validate_listener(&mut self, kind: ListenerKind<R>) -> Option<ListenerKind<R>> {
        match (&self.state, kind) {
            // state can be either uninitialized or initializing/initialized to be ephemeral
            (
                ListenerState::Ephemeral { .. }
                | ListenerState::Uninitialized
                | ListenerState::Initializing {
                    kind: PendingListenerKind::Ephemeral,
                },
                kind @ ListenerKind::Ephemeral { .. },
            ) => Some(kind),

            // only an unitialized listener can accept `STREAM FORWARD`
            (ListenerState::Uninitialized, kind @ ListenerKind::Persistent { .. }) => Some(kind),

            // all other states are invalid and the accept requested is rejected
            (state, kind @ (ListenerKind::Ephemeral { .. } | ListenerKind::Persistent { .. })) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    ?kind,
                    "invalid (state, kind) combination for listener",
                );

                match kind {
                    ListenerKind::Ephemeral { mut socket, .. }
                    | ListenerKind::Persistent { mut socket, .. } => {
                        R::spawn(async move {
                            let _ = socket
                                .send_message_blocking(
                                    "STREAM STATUS RESULT=I2P_ERROR\n".as_bytes().to_vec(),
                                )
                                .await;
                            let _ = socket.into_inner().close().await;
                        });
                    }
                }

                None
            }
        }
    }

    /// Register new listener `kind`.
    ///
    /// If `kind` is [`ListenerKind::Ephemeral`], push the listener into a set of pending listeners
    /// from which it will be taken when an inbound stream is received.
    ///
    /// If `kind` is [`ListenerKind::Persistent`], the store the port of the active TCP listener (on
    /// client side) into [`StreamManager`]'s context and when an inbond stream is received,
    /// establish new connection to the TCP listener.
    ///
    /// Active `STREAM ACCEPT` and `STREAM FORWARD` are mutually exclusive as per the specification.
    /// If user sent `STREAM ACCEPT` while there was an active `STREAM FORWARD` or vice versa, the
    /// follow-up listener kind is rejected.
    ///
    /// If there was a pending listener while a `STREAM ACCEPT` was received, the pending stream is
    /// associated with the new listener and any remaining listeners will remain in the pending
    /// state. If there were one or more pending streams while a `STREAM FORWARD` was received, the
    /// pending streams are associated with the active TCP listener and dispatched into background.
    ///
    /// On success, if the registered listener was ephemeral and configured to be silent, this
    /// function returns `Ok(true)` to indicate a listener ready for immediate use in case there is
    /// a pending stream waiting for a listener. If the registered listener wasn't configured to be
    /// silent or is a persistent listener, it's readiness is reported via
    /// [`StreamListener::poll_next_unpin`].
    pub fn register_listener(&mut self, kind: ListenerKind<R>) -> Result<bool, StreamingError> {
        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?kind,
            "register listener",
        );

        // ensure `kind` is valid with listener's current state
        let kind = self.validate_listener(kind).ok_or(StreamingError::ListenerMismatch)?;

        // initialize socket if it needs to be and update listener state
        //
        // if `SILENT` was set to false (default), send acceptance notification in a new future
        // and update listener state
        //
        // if the state is uninitialize and a message must be sent to user, the listener is put into
        // `Initializing` state which indicates that at least one socket is being initialized for
        // accepting a new connection
        match (&mut self.state, kind) {
            (
                ListenerState::Uninitialized,
                ListenerKind::Ephemeral {
                    mut socket,
                    silent,
                    pending_routing_path_handle,
                },
            ) => match silent {
                true => {
                    self.state = ListenerState::Ephemeral {
                        sockets: VecDeque::from_iter([(
                            socket,
                            silent,
                            pending_routing_path_handle,
                        )]),
                    };

                    Ok(true)
                }
                false => {
                    self.state = ListenerState::Initializing {
                        kind: PendingListenerKind::Ephemeral,
                    };

                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| (socket, pending_routing_path_handle))
                    });

                    if let Some(waker) = self.waker.take() {
                        waker.wake_by_ref();
                    }

                    Ok(false)
                }
            },
            (
                ListenerState::Initializing {
                    kind: PendingListenerKind::Ephemeral,
                },
                ListenerKind::Ephemeral {
                    mut socket,
                    silent,
                    pending_routing_path_handle,
                },
            ) => match silent {
                true => {
                    self.state = ListenerState::Ephemeral {
                        sockets: VecDeque::from_iter([(
                            socket,
                            silent,
                            pending_routing_path_handle,
                        )]),
                    };

                    Ok(true)
                }
                false => {
                    self.state = ListenerState::Initializing {
                        kind: PendingListenerKind::Ephemeral,
                    };

                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| (socket, pending_routing_path_handle))
                    });

                    if let Some(waker) = self.waker.take() {
                        waker.wake_by_ref();
                    }

                    Ok(false)
                }
            },
            (
                ListenerState::Ephemeral { ref mut sockets },
                ListenerKind::Ephemeral {
                    mut socket,
                    silent,
                    pending_routing_path_handle,
                },
            ) => match silent {
                true => {
                    sockets.push_back((socket, silent, pending_routing_path_handle));
                    Ok(true)
                }
                false => {
                    self.pending_sockets.push(async move {
                        socket
                            .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                            .await
                            .map(|()| (socket, pending_routing_path_handle))
                    });

                    if let Some(waker) = self.waker.take() {
                        waker.wake_by_ref();
                    }

                    Ok(false)
                }
            },
            (
                ListenerState::Uninitialized,
                ListenerKind::Persistent {
                    mut socket,
                    port,
                    silent,
                    pending_routing_path_handle,
                },
            ) => {
                self.state = ListenerState::Initializing {
                    kind: PendingListenerKind::Persistent { port, silent },
                };

                // from specification:
                //
                // "Whether SILENT is true or false, the SAM bridge always answers with a STREAM
                // STATUS message. Note that this is a different behavior from STREAM ACCEPT and
                // STREAM CONNECT when SILENT=true"
                //
                // https://geti2p.net/en/docs/api/samv3
                self.pending_sockets.push(async move {
                    socket
                        .send_message_blocking("STREAM STATUS RESULT=OK\n".as_bytes().to_vec())
                        .await
                        .map(|()| (socket, pending_routing_path_handle))
                });

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }

                Ok(false)
            }
            state => todo!("not implemented: {state:?}"),
        }
    }
}

impl<R: Runtime> futures::Stream for StreamListener<R> {
    type Item = StreamListenerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.pending_sockets.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(error))) => tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to send status message",
                ),
                Poll::Ready(Some(Ok((socket, pending_routing_path_handle)))) => {
                    match mem::replace(&mut self.state, ListenerState::Poisoned) {
                        ListenerState::Uninitialized => {
                            // connection wasn't configured to be silent because
                            // a status message was sent to the client
                            self.state = ListenerState::Ephemeral {
                                sockets: VecDeque::from_iter([(
                                    socket,
                                    false,
                                    pending_routing_path_handle,
                                )]),
                            };
                        }
                        ListenerState::Ephemeral { mut sockets } => {
                            sockets.push_back((socket, false, pending_routing_path_handle));
                            self.state = ListenerState::Ephemeral { sockets };
                        }
                        ListenerState::Initializing { kind } => match kind {
                            PendingListenerKind::Ephemeral => {
                                self.state = ListenerState::Ephemeral {
                                    sockets: VecDeque::from_iter([(
                                        socket,
                                        false,
                                        pending_routing_path_handle,
                                    )]),
                                };
                            }
                            PendingListenerKind::Persistent { port, silent } => {
                                self.state = ListenerState::Persistent {
                                    socket,
                                    port,
                                    silent,
                                    pending_routing_path_handle,
                                };
                            }
                        },
                        state => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                ?state,
                                "invalid listener state for ready socket",
                            );
                            debug_assert!(false);
                            return Poll::Ready(None);
                        }
                    }

                    return Poll::Ready(Some(StreamListenerEvent::ListenerReady));
                }
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        mock::{MockRuntime, MockTcpStream},
        noop::{NoopRuntime, NoopTcpStream},
    };
    use tokio::net::TcpListener;

    #[test]
    fn register_persistent_when_ephemeral_is_active() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                port: 1337,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Err(StreamingError::ListenerMismatch)
        );
    }

    #[test]
    fn register_ephemeral_when_persistent_is_active() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                port: 1337,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Err(StreamingError::ListenerMismatch)
        );
    }

    #[test]
    fn register_multiple_ephemeral_listeners() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }
    }

    #[test]
    fn register_multiple_silent_ephemeral_listeners() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(true)
        );

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(true)
        );

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 2 => {}
            _ => panic!("invalid state"),
        }
    }

    #[test]
    fn register_multiple_persistent_listeners() {
        let mut listener = StreamListener::<NoopRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                port: 1337,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: Box::new(SamSocket::new(NoopTcpStream::new())),
                port: 1338,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Err(StreamingError::ListenerMismatch)
        );
    }

    #[tokio::test]
    async fn pending_socket_initialized() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: Box::new(SamSocket::new(stream2.unwrap())),
                port: 1337,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        match &listener.state {
            ListenerState::Initializing {
                kind:
                    PendingListenerKind::Persistent {
                        port: 1337,
                        silent: false,
                    },
            } => {}
            _ => panic!("invalid state"),
        }

        let Some(StreamListenerEvent::ListenerReady) = listener.next().await else {
            panic!("stream listener exited");
        };

        match &listener.state {
            ListenerState::Persistent {
                port: 1337,
                silent: false,
                ..
            } => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn register_silent_and_non_silent_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_stream1, eph1) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (_stream2, eph2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(eph1.unwrap())),
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }

        // register another ephemeral listener but this time it's silent
        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(eph2.unwrap())),
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(true)
        );

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        // poll the other pending socket until it's ready
        let Some(StreamListenerEvent::ListenerReady) = listener.next().await else {
            panic!("stream listener exited");
        };

        // verify there are two listeners
        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 2 => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn register_stream_while_listener_is_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_stream1, eph1) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (_stream2, eph2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(eph1.unwrap())),
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        match &listener.state {
            ListenerState::Initializing {
                kind: PendingListenerKind::Ephemeral,
            } => {}
            _ => panic!("invalid state"),
        }

        // register another ephemeral listener but this time it's silent
        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(eph2.unwrap())),
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(true)
        );

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        assert!(listener.pop_socket().is_some());
        match &listener.state {
            ListenerState::Uninitialized { .. } => {}
            _ => panic!("invalid state"),
        }

        // poll the other pending socket until it's ready
        let Some(StreamListenerEvent::ListenerReady) = listener.next().await else {
            panic!("stream listener exited");
        };

        // verify there are two listeners
        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn two_active_listeners() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_stream1, eph1) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (_stream2, eph2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(eph1.unwrap())),
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(true)
        );

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Ephemeral {
                socket: Box::new(SamSocket::new(eph2.unwrap())),
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(true)
        );

        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 2 => {}
            _ => panic!("invalid state"),
        }

        assert!(listener.pop_socket().is_some());
        match &listener.state {
            ListenerState::Ephemeral { sockets } if sockets.len() == 1 => {}
            _ => panic!("invalid state"),
        }

        assert!(listener.pop_socket().is_some());
        match &listener.state {
            ListenerState::Uninitialized { .. } => {}
            _ => panic!("invalid state"),
        }
    }

    #[tokio::test]
    async fn persistent_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut listener = StreamListener::<MockRuntime>::new(DestinationId::random());
        match &listener.state {
            ListenerState::Uninitialized => {}
            _ => panic!("invalid state"),
        }

        assert_eq!(
            listener.register_listener(ListenerKind::Persistent {
                socket: Box::new(SamSocket::new(stream2.unwrap())),
                port: 1337,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            }),
            Ok(false)
        );

        match &listener.state {
            ListenerState::Initializing {
                kind:
                    PendingListenerKind::Persistent {
                        port: 1337,
                        silent: false,
                    },
            } => {}
            _ => panic!("invalid state"),
        }

        let Some(StreamListenerEvent::ListenerReady) = listener.next().await else {
            panic!("stream listener exited");
        };

        match &listener.state {
            ListenerState::Persistent {
                port: 1337,
                silent: false,
                ..
            } => {}
            _ => panic!("invalid state"),
        }

        // multiple streams can be registered
        for _ in 0..5 {
            assert!(listener.pop_socket().is_some());

            match &listener.state {
                ListenerState::Persistent {
                    port: 1337,
                    silent: false,
                    ..
                } => {}
                _ => panic!("invalid state"),
            }
        }
    }
}
