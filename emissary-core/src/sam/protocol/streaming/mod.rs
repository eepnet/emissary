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
    crypto::{base64_encode, SigningPrivateKey},
    destination::{routing_path::RoutingPathHandle, DeliveryStyle},
    error::{parser::PacketParseError, StreamingError},
    i2cp::I2cpPayload,
    primitives::{Destination, DestinationId},
    runtime::{Instant, JoinSet, Runtime},
    sam::{
        protocol::streaming::{
            config::StreamConfig,
            listener::{SocketKind, StreamListener, StreamListenerEvent},
            packet::{Packet, PacketBuilder},
            stream::{
                active::{Stream, StreamContext, StreamEvent, StreamKind},
                pending::{PendingStream, PendingStreamResult},
            },
        },
        socket::SamSocket,
    },
};

use bytes::{BufMut, BytesMut};
use futures::{FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc::{channel, Receiver, Sender};

use alloc::{boxed::Box, collections::VecDeque, format, string::String, vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod config;
mod listener;
mod packet;
mod stream;

pub use listener::ListenerKind;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::streaming";

/// [`StreamManager`]'s message channel size.
///
/// Size of the channel used by all virtual streams to send messages to the network.
const STREAM_MANAGER_CHANNEL_SIZE: usize = 4096;

/// [`Stream`]'s message channel size.
///
/// Size of the channel used to send messages received from the network to a virtual stream.
const STREAM_CHANNEL_SIZE: usize = 512;

/// How long are streams kept in the pending state before they are pruned and rejected.
const PENDING_STREAM_PRUNE_THRESHOLD: Duration = Duration::from_secs(30);

/// How long should a pending outbound stream wait before sending another `SYN`.
const SYN_RETRY_TIMEOUT: Duration = Duration::from_millis(2500);

/// Timeout for graceful shutdown.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum `SYN` retries before the remote destination is considered unreachable.
const MAX_SYN_RETRIES: usize = 5usize;

/// Direction of stream.
pub enum Direction {
    /// Inbound stream.
    Inbound,

    /// Outbound stream.
    Outbound,
}

/// Events emitted by [`StreamManager`].
pub enum StreamManagerEvent {
    /// Stream opened.
    StreamOpened {
        /// ID of remote destination.
        destination_id: DestinationId,

        /// Direction of the stream.
        direction: Direction,
    },

    /// Stream closed.
    StreamClosed {
        /// ID of remote destination.
        destination_id: DestinationId,
    },

    /// Outbound stream rejected.
    StreamRejected {
        /// ID of remote destination.
        destination_id: DestinationId,
    },

    /// Send packet.
    SendPacket {
        /// Delivery style.
        delivery_style: DeliveryStyle,

        /// Destination port.
        dst_port: u16,

        /// Packet.
        packet: Vec<u8>,

        /// Source port.
        src_port: u16,
    },

    /// [`StreamManager`] has been shut down.
    ShutDown,
}

/// Shutdown handler.
enum ShutdownHandler<R: Runtime> {
    /// Shutdown has not been requested.
    Idle,

    /// Shutdown has been requested and a timer for forcible shutdown has been started.
    ShutdownRequested {
        /// Shutdown timer.
        ///
        /// See [`GRACEFUL_SHUTDOWN_TIMEOUT`] for more details.
        timer: R::Timer,
    },

    /// [`StreamManager`] has been shut down.
    ShutDown,
}

impl<R: Runtime> ShutdownHandler<R> {
    /// Create new [`ShutdownHandler`].
    fn new() -> Self {
        ShutdownHandler::Idle
    }

    /// Is [`StreamManager`] shutting down.
    fn shutting_down(&self) -> bool {
        core::matches!(self, Self::ShutdownRequested { .. })
    }

    /// Shut down [`StreamManager`].
    fn start_shutdown(&mut self) {
        *self = ShutdownHandler::ShutdownRequested {
            timer: R::timer(GRACEFUL_SHUTDOWN_TIMEOUT),
        };
    }

    /// Mark [`StreamManager`] as shut down.
    ///
    /// Any further calls to [`StreamManger::poll_next()`] will return `Poll::Pending`.
    fn set_as_shutdown(&mut self) {
        *self = ShutdownHandler::ShutDown;
    }
}

/// Shutdown event.
enum ShutdownEvent {
    /// Forcibly shut down [`StreamManager`].
    ShutDown,

    /// [`StreamManager`] has already been shutdown.
    AlreadyShutDown,
}

impl<R: Runtime> Future for ShutdownHandler<R> {
    type Output = ShutdownEvent;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::into_inner(self);

        match this {
            ShutdownHandler::Idle => Poll::Pending,
            ShutdownHandler::ShutdownRequested { timer } => match timer.poll_unpin(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(_) => {
                    this.set_as_shutdown();
                    Poll::Ready(ShutdownEvent::ShutDown)
                }
            },
            ShutdownHandler::ShutDown => Poll::Ready(ShutdownEvent::AlreadyShutDown),
        }
    }
}

/// Pending outbound stream.
struct PendingOutboundStream<R: Runtime> {
    /// ID of the remote destination.
    destination_id: DestinationId,

    /// Destination port.
    dst_port: u16,

    /// Number of `SYN`s sent thus far.
    num_sent: usize,

    /// Serialised `SYN` packet.
    packet: Vec<u8>,

    /// Routing path handle.
    routing_path_handle: RoutingPathHandle<R>,

    /// Has the stream configured to be silent.
    silent: bool,

    /// SAMv3 client socket that was used to send `STREAM CONNECT` command.
    socket: Box<SamSocket<R>>,

    /// Source port.
    src_port: u16,
}

/// I2P virtual stream manager.
pub struct StreamManager<R: Runtime> {
    /// TX channels for sending [`Packet`]'s to active streams.
    ///
    /// Indexed with receive stream ID.
    active: HashMap<u32, (DestinationId, Sender<StreamEvent>)>,

    /// Destination of the session the stream manager is bound to.
    destination: Destination,

    /// ID of the `Destination` the stream manager is bound to.
    destination_id: DestinationId,

    /// Destination ID -> stream ID mappings.
    destination_streams: HashMap<DestinationId, HashSet<u32>>,

    /// Stream listener.
    listener: StreamListener<R>,

    /// RX channel for receiving [`Packet`]s from active streams.
    outbound_rx: Receiver<(DeliveryStyle, Vec<u8>, u16, u16)>,

    /// Timers for outbound streams.
    outbound_timers: R::JoinSet<u32>,

    /// TX channel given to active streams they use for sending messages to the network.
    outbound_tx: Sender<(DeliveryStyle, Vec<u8>, u16, u16)>,

    /// Pending events.
    pending_events: VecDeque<StreamManagerEvent>,

    /// Pending inbound streams.
    ///
    /// Indexed by the remote-selected receive stream ID.
    pending_inbound: HashMap<u32, PendingStream<R>>,

    /// Pending outbound streams.
    pending_outbound: HashMap<u32, PendingOutboundStream<R>>,

    /// Timer for pruning stale pending streams.
    prune_timer: R::Timer,

    /// Shutdown handler.
    shutdown_handler: ShutdownHandler<R>,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Active streams.
    streams: R::JoinSet<u32>,
}

impl<R: Runtime> StreamManager<R> {
    /// Create new [`StreamManager`].
    pub fn new(destination: Destination, signing_key: SigningPrivateKey) -> Self {
        let (outbound_tx, outbound_rx) = channel(STREAM_MANAGER_CHANNEL_SIZE);
        let destination_id = destination.id();

        Self {
            active: HashMap::new(),
            destination,
            destination_id: destination_id.clone(),
            destination_streams: HashMap::new(),
            listener: StreamListener::new(destination_id),
            outbound_rx,
            outbound_timers: R::join_set(),
            outbound_tx,
            pending_events: VecDeque::new(),
            pending_inbound: HashMap::new(),
            pending_outbound: HashMap::new(),
            prune_timer: R::timer(PENDING_STREAM_PRUNE_THRESHOLD),
            shutdown_handler: ShutdownHandler::new(),
            signing_key,
            streams: R::join_set(),
        }
    }

    /// Handle message with `SYN`.
    ///
    /// If this a response to an outbound stream sent by us, convert the pending stream to an active
    /// stream by allocating it a new channel and spawning it in a background task.
    ///
    /// If this a new inbound stream ensure that signature and destination are in the message and
    /// verify their validity. Additionally ensure that the NACK field contains local destination's
    /// ID. If validity checks pass, send the message to a listener if it exists. If there are no
    /// active listeners, mark the stream as pending and start a timer for waiting for a new
    /// listener to be registered. If no listener is registered within the time window, the stream
    /// is closed.
    fn on_synchronize(
        &mut self,
        packet: Vec<u8>,
        src_port: u16,
        dst_port: u16,
    ) -> Result<(), StreamingError> {
        let Packet {
            send_stream_id,
            recv_stream_id,
            nacks,
            flags,
            payload,
            ..
        } = Packet::parse::<R>(&packet)?;

        // verify signature
        let signature = flags.signature().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?recv_stream_id,
                ?send_stream_id,
                "signature missing from syn packet",
            );

            StreamingError::SignatureMissing
        })?;
        let destination = flags.from_included().as_ref().ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?recv_stream_id,
                ?send_stream_id,
                "destination missing from syn packet",
            );
            StreamingError::DestinationMissing
        })?;
        let destination_id = destination.id();

        {
            // if the packet included an offline signature, use the verifying key specified in the
            // offline signature to verify the packet's signature
            //
            // otherwise use the verifying key specified in the destination
            let verifying_key = match flags.offline_signature() {
                None => destination.verifying_key(),
                Some(key) => key,
            };

            // signature field is the last field of options, meaning it starts at
            // `original.len() - payload.len() - verifying_key.signature_len()`
            //
            // in order to verify the signature, the calculated signature must be filled
            // with zeros
            let mut original = packet.to_vec();

            if original.len() < payload.len() + verifying_key.signature_len() {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    remote = %destination_id,
                    ?recv_stream_id,
                    ?send_stream_id,
                    "cannot verify signature, packet is too short",
                );
                return Err(StreamingError::Malformed(PacketParseError::PacketTooShort));
            }

            let signature_start = original.len() - payload.len() - verifying_key.signature_len();
            original[signature_start..signature_start + verifying_key.signature_len()]
                .copy_from_slice(&vec![0u8; verifying_key.signature_len()]);

            verifying_key.verify(&original, signature).map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    remote = %destination_id,
                    ?recv_stream_id,
                    ?send_stream_id,
                    ?error,
                    "failed to verify packet signature"
                );

                StreamingError::InvalidSignature
            })?;
        }

        // if this is a syn-ack for an outbound stream, initialize state
        // for a new stream future and spawn it in the background
        if let Some(PendingOutboundStream {
            destination_id,
            silent,
            socket,
            dst_port,
            src_port,
            routing_path_handle,
            ..
        }) = self.pending_outbound.remove(&send_stream_id)
        {
            tracing::trace!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %destination_id,
                ?recv_stream_id,
                ?send_stream_id,
                "outbound stream accepted",
            );

            self.spawn_stream(
                SocketKind::Connect {
                    routing_path_handle,
                    silent,
                    socket: socket.into_inner(),
                },
                recv_stream_id,
                destination_id.clone(),
                None,
                StreamKind::Outbound {
                    dst_port,
                    send_stream_id,
                    src_port,
                    payload: payload.to_vec(),
                },
            );

            return Ok(());
        }

        // verify that the nacks field contains local destination id for replay protection
        if nacks.len() != 8 {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %destination_id,
                ?recv_stream_id,
                ?send_stream_id,
                "destination id for replay protection not set",
            );
            return Err(StreamingError::ReplayProtectionCheckFailed);
        }

        let constructed_destination_id = nacks
            .into_iter()
            .fold(BytesMut::with_capacity(32), |mut acc, x| {
                acc.put_slice(&x.to_be_bytes());
                acc
            })
            .freeze()
            .to_vec();

        if constructed_destination_id != self.destination_id.to_vec() {
            return Err(StreamingError::ReplayProtectionCheckFailed);
        }

        tracing::info!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            ?recv_stream_id,
            ?send_stream_id,
            payload_len = ?payload.len(),
            "inbound stream accepted",
        );

        // attempt to acquire a socket from `StreamListener`
        //
        // if no listener exists, the stream is marked as pending
        match self.listener.pop_socket() {
            Some(socket) => self.spawn_stream(
                socket,
                recv_stream_id,
                destination.id(),
                Some(destination.clone()),
                StreamKind::Inbound {
                    payload: payload.to_vec(),
                },
            ),
            None => {
                tracing::info!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    remote = %destination_id,
                    ?recv_stream_id,
                    ?send_stream_id,
                    "inbound stream but no available listeners",
                );

                // create new pending stream and send syn-ack for it
                let destination_id = destination.id();

                let (pending, packet) = PendingStream::new(
                    &self.destination,
                    destination.clone(),
                    recv_stream_id,
                    payload.to_vec(),
                    &self.signing_key,
                );

                let _ = self.outbound_tx.try_send((
                    DeliveryStyle::Unspecified {
                        destination_id: destination_id.clone(),
                    },
                    packet,
                    dst_port,
                    src_port,
                ));

                self.pending_inbound.insert(recv_stream_id, pending);
                self.destination_streams
                    .entry(destination_id.clone())
                    .or_default()
                    .insert(recv_stream_id);
            }
        }

        Ok(())
    }

    /// Spawn new [`Stream`] in the background.
    ///
    /// This function can spawn streams of two different kinds:
    ///  - streams where no packet exchange has happened yet (fresh streams)
    ///  - streams where packet exchange has happened (pending streams)
    ///
    /// If the stream is fresh,
    fn spawn_stream(
        &mut self,
        socket: SocketKind<R>,
        recv_stream_id: u32,
        destination_id: DestinationId,
        destination: Option<Destination>,
        stream_kind: StreamKind,
    ) {
        // create context for the stream
        //
        // since this is an inbound stream, the stream will be indexed in `active` by the
        // remote-chosen receive stream id and the local stream will generate itself a random id
        // when it starts and uses that for sending
        let (tx, rx) = channel(STREAM_CHANNEL_SIZE);
        let context = StreamContext {
            destination: self.destination.clone(),
            cmd_rx: rx,
            event_tx: self.outbound_tx.clone(),
            local: self.destination_id.clone(),
            recv_stream_id,
            remote: destination_id.clone(),
            signing_key: self.signing_key.clone(),
        };

        // if the socket wasn't configured to be silent, send the remote's destination
        // to client before the socket is convered into a regural tcp stream
        let initial_message = match &socket {
            // `destination` must exist if this is an inbound stream
            SocketKind::Accept { silent, .. } | SocketKind::Forwarded { silent, .. } if !silent =>
                Some(
                    format!(
                        "{}\n",
                        base64_encode(destination.expect("to exist").serialized())
                    )
                    .into_bytes(),
                ),
            SocketKind::Connect { silent, .. } if !silent =>
                Some(b"STREAM STATUS RESULT=OK\n".to_vec()),
            _ => None,
        };

        // store the tx channel of the stream in `StreamManager`'s context
        //
        // `StreamManager` sends all inbound messages with `recv_stream_id` to this stream and all
        // outbound messages from the stream to remote peer are send through `event_tx`
        self.active.insert(recv_stream_id, (destination_id.clone(), tx));
        self.destination_streams
            .entry(destination_id.clone())
            .or_default()
            .insert(recv_stream_id);

        // if socket kind is `Connect` this is an outbound stream
        //
        // accept/forward indicates an inbound stream
        match &socket {
            SocketKind::Connect { .. } =>
                self.pending_events.push_back(StreamManagerEvent::StreamOpened {
                    destination_id: destination_id.clone(),
                    direction: Direction::Outbound,
                }),
            SocketKind::Accept { .. } | SocketKind::Forwarded { .. } =>
                self.pending_events.push_back(StreamManagerEvent::StreamOpened {
                    destination_id: destination_id.clone(),
                    direction: Direction::Inbound,
                }),
        }

        // start new future for the stream in the background
        //
        // if `SILENT` was set to false, the first message `Stream` sends to the connected
        // client is the destination id of the remote peer after which it transfers to send
        // anything that was received from the remote peer via `StreamManager`
        //
        // if the listener was created with `STREAM FORWARD`, a new tcp connection must be opened to
        // the forwarded listener before the stream can be started and if the listener is not
        // active, the stream is closed immediately
        match socket {
            SocketKind::Connect {
                socket,
                routing_path_handle,
                ..
            } => self.streams.push(Stream::<R>::new(
                socket,
                initial_message,
                context,
                StreamConfig::default(),
                stream_kind,
                routing_path_handle,
            )),
            SocketKind::Accept {
                pending_routing_path_handle,
                socket,
                ..
            } => {
                self.streams.push(async move {
                    let Some(routing_path_handle) =
                        pending_routing_path_handle.bind::<R>(destination_id).await
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "failed to bind routing path handle, cannot accept inbound stream",
                        );
                        return context.recv_stream_id;
                    };

                    Stream::<R>::new(
                        socket,
                        initial_message,
                        context,
                        StreamConfig::default(),
                        stream_kind,
                        routing_path_handle,
                    )
                    .await
                });
            }
            SocketKind::Forwarded {
                future,
                pending_routing_path_handle,
                ..
            } => self.streams.push(async move {
                let Some(routing_path_handle) =
                    pending_routing_path_handle.bind::<R>(destination_id).await
                else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "failed to bind routing path handle, cannot accept inbound stream",
                    );
                    return context.recv_stream_id;
                };

                let Some(stream) = future.await else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "failed to open tcp stream to forwarded listener",
                    );
                    return context.recv_stream_id;
                };

                Stream::<R>::new(
                    stream,
                    initial_message,
                    context,
                    StreamConfig::default(),
                    stream_kind,
                    routing_path_handle,
                )
                .await
            }),
        }
    }

    /// Handle ready listener.
    ///
    /// An inbound stream may be received while there are no listeners or the listeners are busy
    /// sending status messages to the connected client. In those cases the inbound streams are put
    /// in a pending state where they remain waiting for a listener to be registered for a period of
    /// time before they're destroyed as session owner is apparently not interested in accepting
    /// inbound streams.
    ///
    /// When a listener is registered and it is ready to serve an inbound stream, [`StreamListener`]
    /// emits an event informing the [`StreamManager`] of it and the stream manager must check if
    /// there are any pending streams and if so, start event loops for the streams. If there are no
    /// pending streams, the event is ignored.
    fn on_listener_ready(&mut self) {
        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            num_pending = ?self.pending_inbound.len(),
            "listener ready",
        );

        // loop through all pending streams until either:
        //  a) there are no more pending streams
        //  b) there are no more available listeners
        loop {
            let Some(stream_id) = self.pending_inbound.keys().next().copied() else {
                return;
            };

            let Some(socket) = self.listener.pop_socket() else {
                return;
            };

            // stream must exist since it was checked earlier that it's in the map
            let PendingStream {
                remote_destination,
                destination_id,
                send_stream_id,
                packets,
                seq_nro,
                ..
            } = self.pending_inbound.remove(&stream_id).expect("to exist");

            // spawn new task for the stream in the background
            self.spawn_stream(
                socket,
                stream_id,
                destination_id,
                Some(remote_destination),
                StreamKind::InboundPending {
                    send_stream_id,
                    seq_nro,
                    packets,
                },
            );
        }
    }

    /// Register listener into [`StreamManager`].
    ///
    /// This function calls [`StreamListener::register_listener()`] which either rejects `kind`
    /// because it's in conflict with an active listener kind, accepts the listener and possibly
    /// notifies the client of if it the socket wasn't configured to be silent. Client notification
    /// happens in the background, making the listener temporarily inactive. Once the client has
    /// been notified of listener acceptance, [`StreamManager`] is notified via
    /// [`StreamListener::poll_next()`] that there is an active listener.
    ///
    /// If the listener was configured to be silent and it was of type [`ListenerKind::Ephemeral`],
    /// the listener is immediately available for use. In these cases,
    /// [`StreamListener::register_listener()`] returns `Ok(true)` to indicate that
    /// [`StreamManager`] can accept a pending inbound stream using the registered listener,
    /// if a pending stream exists.
    pub fn register_listener(&mut self, kind: ListenerKind<R>) -> Result<(), StreamingError> {
        if self.listener.register_listener(kind)? {
            self.on_listener_ready();
        }

        Ok(())
    }

    /// Handle `payload` received from `src_port` to `dst_port`.
    pub fn on_packet(&mut self, payload: I2cpPayload) -> Result<(), StreamingError> {
        let I2cpPayload {
            payload,
            dst_port,
            src_port,
            ..
        } = payload;

        let packet = Packet::peek(&payload).ok_or(StreamingError::Malformed(
            PacketParseError::InvalidBitstream,
        ))?;

        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            send_stream_id = ?packet.send_stream_id(),
            recv_stream_id = ?packet.recv_stream_id(),
            seq_nro = ?packet.seq_nro(),
            "inbound message",
        );

        // forward received packet to an active handler if it exists
        if let Some((_, tx)) = self.active.get(&packet.recv_stream_id()) {
            if let Err(error) = tx.try_send(StreamEvent::Packet { packet: payload }) {
                tracing::debug!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    send_stream_id = ?packet.send_stream_id(),
                    recv_stream_id = ?packet.recv_stream_id(),
                    seq_nro = ?packet.seq_nro(),
                    ?error,
                    "failed to send packet to stream, dropping",
                );
            }

            return Ok(());
        }

        if let Some(stream) = self.pending_inbound.get_mut(&packet.recv_stream_id()) {
            match stream.on_packet(payload) {
                PendingStreamResult::DoNothing => {}
                PendingStreamResult::Send { packet } => {
                    let _ = self.outbound_tx.try_send((
                        DeliveryStyle::Unspecified {
                            destination_id: stream.destination_id.clone(),
                        },
                        packet,
                        dst_port,
                        src_port,
                    ));
                }
                PendingStreamResult::SendAndDestroy { packet: pkt } => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        recv_stream_id = ?packet.recv_stream_id(),
                        "send packet and destroy pending stream",
                    );
                    let _ = self.outbound_tx.try_send((
                        DeliveryStyle::Unspecified {
                            destination_id: stream.destination_id.clone(),
                        },
                        pkt,
                        dst_port,
                        src_port,
                    ));

                    if let Some(PendingStream { destination_id, .. }) =
                        self.pending_inbound.remove(&packet.recv_stream_id())
                    {
                        if let Some(stream) = self.destination_streams.get_mut(&destination_id) {
                            stream.remove(&packet.recv_stream_id());
                        }
                    }
                }
                PendingStreamResult::Destroy => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        recv_stream_id = ?packet.recv_stream_id(),
                        "destroy pending stream",
                    );

                    if let Some(PendingStream { destination_id, .. }) =
                        self.pending_inbound.remove(&packet.recv_stream_id())
                    {
                        if let Some(stream) = self.destination_streams.get_mut(&destination_id) {
                            stream.remove(&packet.recv_stream_id());
                        }
                    }
                }
            }

            return Ok(());
        }

        // handle new stream
        //
        // both deserialized packet and the original payload are returned
        // so the included signature can be verified
        //
        // any new streams are ignored if stream manager is shutting down
        if packet.synchronize() && !self.shutdown_handler.shutting_down() {
            return self.on_synchronize(payload, src_port, dst_port);
        }

        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            nacks,
            resend_delay,
            flags,
            payload,
        } = Packet::parse::<R>(&payload)?;

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            ?send_stream_id,
            ?recv_stream_id,
            ?seq_nro,
            ?ack_through,
            ?nacks,
            ?resend_delay,
            %flags,
            payload_len = ?payload.len(),
            "ignoring unrecognized packet",
        );

        Ok(())
    }

    /// Create outbound stream to remote peer identfied by `destination_id`.
    ///
    /// Construct initial `SYN` packet and create pending outbound stream.
    ///
    /// Returns the initial packet and the selected receive stream ID which the caller
    /// can use to remove the pending stream if the session is rejected at a lower layer.
    pub fn create_stream(
        &mut self,
        destination_id: DestinationId,
        mut routing_path_handle: RoutingPathHandle<R>,
        socket: Box<SamSocket<R>>,
        options: HashMap<String, String>,
    ) -> (u32, BytesMut, DeliveryStyle, u16, u16) {
        let silent = options
            .get("SILENT")
            .is_some_and(|value| value.parse::<bool>().unwrap_or(false));
        let src_port = options
            .get("FROM_PORT")
            .map_or(0u16, |value| value.parse::<u16>().unwrap_or(0u16));
        let dst_port = options
            .get("TO_PORT")
            .map_or(0u16, |value| value.parse::<u16>().unwrap_or(0u16));

        // generate free receive stream id
        let recv_stream_id = {
            let mut rng = R::rng();

            loop {
                let stream_id = rng.next_u32();

                if !self.active.contains_key(&stream_id)
                    && !self.pending_outbound.contains_key(&stream_id)
                {
                    break stream_id;
                }
            }
        };

        let packet = PacketBuilder::new(recv_stream_id)
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_synchronize()
            .with_signature()
            .with_from_included(&self.destination)
            .build_and_sign(&self.signing_key);

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            ?recv_stream_id,
            "open stream",
        );

        let delivery_style = match routing_path_handle.routing_path() {
            None => DeliveryStyle::Unspecified {
                destination_id: destination_id.clone(),
            },
            Some(routing_path) => DeliveryStyle::ViaRoute { routing_path },
        };

        // create pending stream and start timer for retrying `SYN` if the remote doesn't respond to
        // the first packet
        //
        // `SYN` is retried 3 times before the remote destination is considered unreachable
        self.pending_outbound.insert(
            recv_stream_id,
            PendingOutboundStream {
                destination_id: destination_id.clone(),
                dst_port,
                num_sent: 1usize,
                packet: packet.clone().to_vec(),
                routing_path_handle,
                silent,
                socket,
                src_port,
            },
        );
        self.destination_streams
            .entry(destination_id)
            .or_default()
            .insert(recv_stream_id);
        self.outbound_timers.push(async move {
            R::delay(SYN_RETRY_TIMEOUT).await;
            recv_stream_id
        });

        (recv_stream_id, packet, delivery_style, src_port, dst_port)
    }

    /// Remove all streaming context associated with `destination_id`.
    pub fn remove_session(&mut self, destination_id: &DestinationId) {
        let Some(streams) = self.destination_streams.remove(destination_id) else {
            return;
        };

        tracing::debug!(
            target: LOG_TARGET,
            local = %self.destination_id,
            remote = %destination_id,
            num_streams = ?streams.len(),
            "remove session"
        );

        streams.into_iter().for_each(|stream_id| {
            self.active.remove(&stream_id);
            self.pending_inbound.remove(&stream_id);
            self.pending_outbound.remove(&stream_id);
        });
    }

    /// Shut down [`StreamManager`].
    ///
    /// Send shutdown signal for each active stream which causes them to send a `CLOSE` packet to
    /// remote. After all streams have exited, the stream manager can be shut down.
    ///
    /// A timer is also started which
    ///
    /// If there are no active streams, the stream manager is shut down right away.
    pub fn shutdown(&mut self) {
        tracing::info!(
            target: LOG_TARGET,
            local = %self.destination_id,
            "shut down stream manager",
        );

        self.active.values().for_each(|(_, tx)| {
            if let Err(error) = tx.try_send(StreamEvent::ShutDown) {
                tracing::error!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    ?error,
                    "failed to send shutdown signal to active stream",
                );
            }
        });

        self.shutdown_handler.start_shutdown();
    }
}

impl<R: Runtime> futures::Stream for StreamManager<R> {
    type Item = StreamManagerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(Some(event));
        }

        // poll shutdown handler
        //
        // if shutdown hasn't been requested or the graceful shutdown timer is active,
        // `shutdown_handler` keeps returning `Poll::Pending`
        //
        // once the timer expires, a graceful shutdown is skipped and stream manager is forcibly
        // shut down, without gracefully closing all open streams
        //
        // after that (or after all streams have been gracefully shut down), the `shutdown_handler`
        // is set to a shut down state and it keeps returning [`ShutdownEvent::AlreadyShutdown`]
        // which short-circuits this stream implementation and keeps returning `Poll::Pending`
        //
        // this is done so that stream manager doesn't get polled after it has been shut down which
        // might happen because the stream manager is shut down before the sam session that owns the
        // manager is shut down
        match self.shutdown_handler.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(ShutdownEvent::ShutDown) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    num_active = ?self.active.len(),
                    "forcibly shutting down stream manager",
                );
                return Poll::Ready(Some(StreamManagerEvent::ShutDown));
            }
            Poll::Ready(ShutdownEvent::AlreadyShutDown) => return Poll::Pending,
        }

        match self.outbound_rx.poll_recv(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some((delivery_style, packet, src_port, dst_port))) =>
                return Poll::Ready(Some(StreamManagerEvent::SendPacket {
                    delivery_style,
                    dst_port,
                    packet,
                    src_port,
                })),
        }

        loop {
            match self.streams.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(stream_id)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        ?stream_id,
                        "stream closed"
                    );

                    // active stream may not exist if it was removed by calling
                    // `StreamManager::remove_session()`
                    let Some((destination_id, _)) = self.active.remove(&stream_id) else {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?stream_id,
                            "active stream doesn't exist",
                        );
                        continue;
                    };

                    if self.streams.is_empty() && self.shutdown_handler.shutting_down() {
                        tracing::info!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "stream manager has been shut down",
                        );

                        self.shutdown_handler.set_as_shutdown();
                        self.pending_events.push_back(StreamManagerEvent::ShutDown);
                    }

                    return Poll::Ready(Some(StreamManagerEvent::StreamClosed { destination_id }));
                }
            }
        }

        loop {
            match self.listener.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(StreamListenerEvent::ListenerReady)) => self.on_listener_ready(),
            }
        }

        loop {
            match self.outbound_timers.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(stream_id)) => {
                    let Some(PendingOutboundStream {
                        destination_id,
                        packet,
                        ref mut num_sent,
                        dst_port,
                        src_port,
                        routing_path_handle,
                        ..
                    }) = self.pending_outbound.get_mut(&stream_id)
                    else {
                        continue;
                    };

                    // pending stream still exists, check if the packet should be resent
                    // or if the stream should be destroyed
                    if *num_sent < MAX_SYN_RETRIES {
                        let dst_port = *dst_port;
                        let src_port = *src_port;
                        let packet = packet.clone();
                        *num_sent += 1;

                        // poll routing path to get any tunnel updates
                        let _ = routing_path_handle.poll_unpin(cx);

                        let Some(routing_path) = routing_path_handle.recreate_routing_path() else {
                            tracing::debug!(
                                target: LOG_TARGET,
                                %destination_id,
                                %num_sent,
                                "unable to resend `SYN`, no routing path available",
                            );

                            self.outbound_timers.push(async move {
                                R::delay(SYN_RETRY_TIMEOUT).await;
                                stream_id
                            });

                            continue;
                        };

                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?stream_id,
                            "resend `SYN`",
                        );

                        // create new timer for the new syn packet
                        //
                        // the future is guaranteed to be polled as we return from this branch
                        self.outbound_timers.push(async move {
                            R::delay(SYN_RETRY_TIMEOUT).await;
                            stream_id
                        });

                        return Poll::Ready(Some(StreamManagerEvent::SendPacket {
                            delivery_style: DeliveryStyle::ViaRoute { routing_path },
                            dst_port,
                            packet,
                            src_port,
                        }));
                    } else {
                        // stream must exist since it was just fetched from `pending_outbound`
                        let PendingOutboundStream {
                            destination_id,
                            mut socket,
                            ..
                        } = self.pending_outbound.remove(&stream_id).expect("to exist");

                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?stream_id,
                            "remote didn't reply after 3 tries, closing stream",
                        );

                        // send rejection to client and return event to `SamSession`
                        // indicating that the connection failed
                        R::spawn(async move {
                            let _ = socket
                                .send_message_blocking(
                                    b"STREAM STATUS RESULT=CANT_REACH_PEER\n".to_vec(),
                                )
                                .await;
                        });

                        return Poll::Ready(Some(StreamManagerEvent::StreamRejected {
                            destination_id,
                        }));
                    }
                }
            }
        }

        if let Poll::Ready(()) = self.prune_timer.poll_unpin(cx) {
            self.pending_inbound
                .iter()
                .filter_map(|(stream_id, pending_stream)| {
                    (pending_stream.established.elapsed() > PENDING_STREAM_PRUNE_THRESHOLD)
                        .then_some(*stream_id)
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .for_each(|stream_id| {
                    tracing::debug!(
                        local = %self.destination_id,
                        ?stream_id,
                        "pruning stale pending stream",
                    );
                    self.pending_inbound.remove(&stream_id);
                });

            // create new timer and register it into the executor
            {
                self.prune_timer = R::timer(PENDING_STREAM_PRUNE_THRESHOLD);
                let _ = self.prune_timer.poll_unpin(cx);
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        destination::routing_path::{PendingRoutingPathHandle, RoutingPathManager},
        error::QueryError,
        primitives::{Destination, Lease, RouterId, TunnelId},
        protocol::Protocol,
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            TcpStream,
        },
        sam::{protocol::streaming::packet::PacketBuilder, socket::SamSocket},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, BufReader},
        net::TcpListener,
    };

    use alloc::boxed::Box;

    struct SocketFactory {
        listener: TcpListener,
    }

    impl SocketFactory {
        pub async fn new() -> Self {
            Self {
                listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            }
        }

        pub async fn socket(&self) -> (Box<SamSocket<MockRuntime>>, tokio::net::TcpStream) {
            let address = self.listener.local_addr().unwrap();
            let (stream1, stream2) =
                tokio::join!(self.listener.accept(), MockTcpStream::connect(address));
            let (stream, _) = stream1.unwrap();

            (Box::new(SamSocket::new(stream2.unwrap())), stream)
        }
    }

    #[tokio::test]
    async fn register_ephemeral_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (_stream, _) = stream1.unwrap();
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream2.unwrap()));

        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            })
            .is_ok());
    }

    #[tokio::test]
    async fn stale_pending_streams_are_pruned() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let mut packets = (0..3)
            .into_iter()
            .map(|stream_id| {
                let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
                let destination = Destination::new::<MockRuntime>(signing_key.public());
                let packet = PacketBuilder::new(stream_id as u32)
                    .with_synchronize()
                    .with_send_stream_id(0u32)
                    .with_replay_protection(&destination_id)
                    .with_from_included(&destination)
                    .with_signature()
                    .build_and_sign(&signing_key);

                packet.to_vec()
            })
            .collect::<VecDeque<_>>();

        // register syn packet and verify the stream is pending
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload: packets.pop_front().unwrap(),
            })
            .is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // reset timer
        manager.prune_timer = MockRuntime::timer(PENDING_STREAM_PRUNE_THRESHOLD);

        // wait for a little while so all streams won't get pruned at the same time
        tokio::time::sleep(Duration::from_secs(20)).await;

        // register two other pending streams
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload: packets.pop_front().unwrap(),
            })
            .is_ok());
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload: packets.pop_front().unwrap(),
            })
            .is_ok());
        assert_eq!(manager.pending_inbound.len(), 3);

        // poll manager until the first stream is pruned
        //
        // verify that the other two are still left
        loop {
            futures::future::poll_fn(|cx| match manager.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => Poll::Ready(()),
            })
            .await;

            if manager.pending_inbound.len() != 3 {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // verify that first pending stream is pruned and that the other two are still left
        assert!(!manager.pending_inbound.contains_key(&0));
        assert!(manager.pending_inbound.contains_key(&1));
        assert!(manager.pending_inbound.contains_key(&2));

        // reset timer
        manager.prune_timer = MockRuntime::timer(Duration::from_secs(20));

        // poll until the last two streams are also pruned
        loop {
            futures::future::poll_fn(|cx| match manager.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("invalid event"),
            })
            .await;

            if manager.pending_inbound.is_empty() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_silent_listener() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(&destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload: packet,
            })
            .is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (_stream, _) = stream1.unwrap();
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream2.unwrap()));

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            })
            .is_ok());
        assert!(manager.pending_inbound.is_empty());

        assert!(std::matches!(
            manager.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        // poll manager until ack packet is received
        match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                delivery_style,
                packet,
                ..
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse::<MockRuntime>(&packet).unwrap();

                assert_eq!(delivery_style.destination_id(), &remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_non_silent_listener() {
        let local_signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let local_destination = Destination::new::<MockRuntime>(local_signing_key.public());
        let destination_id = local_destination.id();
        let mut manager =
            StreamManager::<MockRuntime>::new(local_destination.clone(), local_signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let remote_signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let remote_destination = Destination::new::<MockRuntime>(remote_signing_key.public());
        let serialized = base64_encode(remote_destination.serialize().to_vec());

        let remote_destination_id = remote_destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(&remote_destination)
            .with_signature()
            .build_and_sign(&remote_signing_key)
            .to_vec();

        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload: packet,
            })
            .is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (stream, _) = stream1.unwrap();
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream2.unwrap()));
        let mut routing_path_manager =
            RoutingPathManager::<MockRuntime>::new(destination_id, vec![]);
        let pending_routing_path_handle = routing_path_manager.pending_handle();

        // spawn routing path in the background
        //
        // it't not used in the test but must be polled in order for the listener to
        // acquire a routing path to remote destination
        tokio::spawn(async move { while routing_path_manager.next().await.is_some() {} });

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false,
                pending_routing_path_handle,
            })
            .is_ok());
        assert!(!manager.pending_inbound.is_empty());

        // poll manager until ack packet is received
        match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                delivery_style,
                packet,
                ..
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse::<MockRuntime>(&packet).unwrap();

                assert_eq!(delivery_style.destination_id(), &remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());
            }
            _ => panic!("invalid event"),
        }

        // spawn stream manager in the background so it makes progress
        tokio::spawn(async move { while manager.next().await.is_some() {} });

        let mut reader = BufReader::new(stream);
        let mut response = String::new();

        // read stream status
        {
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response, String::from("STREAM STATUS RESULT=OK\n"));
        }

        // read destination
        {
            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.trim_end(), serialized);
        }
    }

    #[tokio::test]
    async fn pending_stream_initialized_with_persistent_listener() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let serialized = base64_encode(destination.serialized());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(&destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let port = address.port();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (stream, _) = stream1.unwrap();
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream2.unwrap()));
        let mut routing_path_manager =
            RoutingPathManager::<MockRuntime>::new(destination_id, vec![]);
        let pending_routing_path_handle = routing_path_manager.pending_handle();

        // spawn routing path in the background
        //
        // it't not used in the test but must be polled in order for the listener to
        // acquire a routing path to remote destination
        tokio::spawn(async move { while routing_path_manager.next().await.is_some() {} });

        assert!(manager
            .register_listener(ListenerKind::Persistent {
                socket,
                port,
                silent: false,
                pending_routing_path_handle,
            })
            .is_ok());
        assert!(!manager.pending_inbound.is_empty());

        // poll manager until ack packet is received
        match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                delivery_style,
                packet,
                ..
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse::<MockRuntime>(&packet).unwrap();

                assert_eq!(delivery_style.destination_id(), &remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());
            }
            _ => panic!("invalid event"),
        }

        // spawn stream manager in the background so it makes progress
        tokio::spawn(async move { while manager.next().await.is_some() {} });

        // read stream status
        {
            let mut reader = BufReader::new(stream);
            let mut response = String::new();

            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response, String::from("STREAM STATUS RESULT=OK\n"));
        }

        // read destination
        {
            let (inbound_stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(inbound_stream);
            let mut response = String::new();

            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.trim_end(), serialized);
        }
    }

    #[tokio::test]
    async fn pending_stream_with_buffered_data_initialized() {
        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let destination_id = destination.id();
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        // register new inbound stream and since there are no listener, the stream will be pending
        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let remote_destination_id = destination.id();
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&destination_id)
            .with_from_included(&destination)
            .with_signature()
            .build_and_sign(&signing_key)
            .to_vec();

        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());
        assert_eq!(manager.pending_inbound.len(), 1);

        // poll manager until ack packet is received
        let recv_stream_id = match tokio::time::timeout(Duration::from_secs(5), manager.next())
            .await
            .unwrap()
            .unwrap()
        {
            StreamManagerEvent::SendPacket {
                delivery_style,
                packet,
                ..
            } => {
                let Packet {
                    send_stream_id,
                    recv_stream_id,
                    flags,
                    ..
                } = Packet::parse::<MockRuntime>(&packet).unwrap();

                assert_eq!(delivery_style.destination_id(), &remote_destination_id);
                assert_eq!(send_stream_id, 1337u32);
                assert_ne!(recv_stream_id, 0u32);
                assert!(flags.synchronize());

                recv_stream_id
            }
            _ => panic!("invalid event"),
        };

        // send three data packets and verify that they're all ack'ed
        {
            let messages = vec![
                b"hello, world".to_vec(),
                b"testing 123".to_vec(),
                b"goodbye world".to_vec(),
            ];

            for (i, message) in messages.into_iter().enumerate() {
                let packet = PacketBuilder::new(1337u32)
                    .with_synchronize()
                    .with_send_stream_id(recv_stream_id)
                    .with_seq_nro(i as u32 + 1u32)
                    .with_payload(&message)
                    .build()
                    .to_vec();

                assert!(manager
                    .on_packet(I2cpPayload {
                        src_port: 0u16,
                        dst_port: 0u16,
                        protocol: Protocol::Streaming,
                        payload: packet
                    })
                    .is_ok());

                // poll manager until ack packet is received
                match tokio::time::timeout(Duration::from_secs(5), manager.next())
                    .await
                    .unwrap()
                    .unwrap()
                {
                    StreamManagerEvent::SendPacket {
                        delivery_style,
                        packet,
                        ..
                    } => {
                        let Packet {
                            send_stream_id,
                            recv_stream_id,
                            ack_through,
                            ..
                        } = Packet::parse::<MockRuntime>(&packet).unwrap();

                        assert_eq!(delivery_style.destination_id(), &remote_destination_id);
                        assert_eq!(send_stream_id, 1337u32);
                        assert_ne!(recv_stream_id, 0u32);
                        assert_eq!(ack_through, i as u32 + 1u32);
                    }
                    _ => panic!("invalid event"),
                }
            }
        }

        // verify that the stream is still pending
        assert_eq!(manager.pending_inbound.len(), 1);

        // register new silent listener which is ready immediately
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));
        let (mut stream, _) = stream1.unwrap();
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream2.unwrap()));

        let outbound = TunnelId::random();
        let inbound = Lease::random();
        let mut path_manager =
            RoutingPathManager::<MockRuntime>::new(destination_id.clone(), vec![outbound]);
        path_manager.register_leases(&destination_id, Ok(vec![inbound]));
        let pending_handle = path_manager.pending_handle();

        tokio::spawn(async move { while let Some(_) = path_manager.next().await {} });

        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());
        assert!(manager.pending_inbound.is_empty());

        // poll manager in the background in order to drive the stream future forward
        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        // verify that the buffered data is returned to client
        let mut buffer = vec![0u8; 36];
        stream.read_exact(&mut buffer).await.unwrap();

        assert_eq!(buffer, b"hello, worldtesting 123goodbye world");
    }

    #[tokio::test]
    async fn outbound_stream_accepted() {
        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let outbound1 = TunnelId::random();
        let inbound1 = Lease::random();
        let mut path_manager1 = RoutingPathManager::<MockRuntime>::new(
            manager1.destination_id.clone(),
            vec![outbound1],
        );
        let pending_handle = path_manager1.pending_handle();
        path_manager1.register_leases(&manager2.destination_id, Ok(vec![inbound1]));

        let outbound2 = TunnelId::random();
        let inbound2 = Lease::random();
        let mut path_manager2 = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![outbound2],
        );
        path_manager2.register_leases(&manager1.destination_id, Ok(vec![inbound2]));
        let handle = path_manager2.handle(manager1.destination_id.clone());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut path_manager1.next() => {}
                    _ = &mut path_manager2.next() => {}
                }
            }
        });

        // register listener for `manager1`
        let (socket, _) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        // create new oubound stream to `manager1`
        let (socket, client_stream) = socket_factory.socket().await;
        let (_stream_id, packet, _, _, _) = manager2.create_stream(
            manager1.destination_id.clone(),
            handle,
            socket,
            HashMap::new(),
        );

        assert!(manager1
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet.to_vec()
            })
            .is_ok());

        assert!(std::matches!(
            manager1.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        let (destination_id, packet) =
            match tokio::time::timeout(Duration::from_secs(5), manager1.next())
                .await
                .unwrap()
                .unwrap()
            {
                StreamManagerEvent::SendPacket {
                    delivery_style,
                    packet,
                    ..
                } => (delivery_style.destination_id().clone(), packet),
                _ => panic!("invalid event"),
            };

        assert_eq!(destination_id, manager2.destination_id);
        assert!(manager2
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = manager1.next() => {}
                    _ = manager2.next() => {}
                }
            }
        });

        let mut reader = tokio::io::BufReader::new(client_stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");
    }

    #[tokio::test]
    async fn outbound_stream_rejected() {
        let socket_factory = SocketFactory::new().await;
        let remote = DestinationId::random();

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut path_manager = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![TunnelId::random()],
        );
        path_manager.register_leases(&remote, Ok(vec![Lease::random()]));

        // create new oubound stream to `manager1`
        let (socket, client_stream) = socket_factory.socket().await;
        let _ = manager2.create_stream(
            remote.clone(),
            path_manager.handle(remote.clone()),
            socket,
            HashMap::new(),
        );

        // verify the syn packet is sent 4 more times
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(15), manager2.next())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                StreamManagerEvent::SendPacket {
                    delivery_style,
                    packet,
                    ..
                } if delivery_style.destination_id() == &remote => {
                    assert!(Packet::parse::<MockRuntime>(&packet).unwrap().flags.synchronize());
                }
                _ => panic!("invalid event"),
            }
        }

        // verify that stream rejection is emitted
        match tokio::time::timeout(Duration::from_secs(15), manager2.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            StreamManagerEvent::StreamRejected { destination_id } if destination_id == remote => {}
            _ => panic!("invalid event"),
        }

        let mut reader = BufReader::new(client_stream);
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut response))
            .await
            .expect("no timeout")
            .expect("to succeed");

        assert_eq!(response, "STREAM STATUS RESULT=CANT_REACH_PEER\n");
    }

    #[tokio::test]
    async fn data_in_syn_packet_silent_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(&destination)
            .with_signature()
            .with_payload(b"hello, world")
            .build_and_sign(&signing_key)
            .to_vec();

        let outbound1 = TunnelId::random();
        let inbound1 = Lease::random();
        let mut path_manager1 =
            RoutingPathManager::<MockRuntime>::new(manager.destination_id.clone(), vec![outbound1]);
        let pending_handle = path_manager1.pending_handle();
        path_manager1.register_leases(&destination.id(), Ok(vec![inbound1]));

        tokio::spawn(async move { while let Some(_) = path_manager1.next().await {} });

        // register listener for `manager1`
        let (socket, mut client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        // handle syn packet and spawn manager in the background
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        // read the payload that was contained within the syn packet
        let mut buffer = [0u8; 12];
        tokio::time::timeout(
            Duration::from_secs(5),
            client_socket.read_exact(&mut buffer),
        )
        .await
        .expect("no timeout")
        .expect("to succeed");
        assert_eq!(&buffer, b"hello, world");
    }

    #[tokio::test]
    async fn data_in_syn_packet_non_silent_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let serialized = base64_encode(destination.serialized());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(&destination)
            .with_signature()
            .with_payload(b"hello, world\n")
            .build_and_sign(&signing_key)
            .to_vec();

        let outbound1 = TunnelId::random();
        let inbound1 = Lease::random();
        let mut path_manager1 =
            RoutingPathManager::<MockRuntime>::new(manager.destination_id.clone(), vec![outbound1]);
        let pending_handle = path_manager1.pending_handle();
        path_manager1.register_leases(&destination.id(), Ok(vec![inbound1]));

        tokio::spawn(async move { while let Some(_) = path_manager1.next().await {} });

        // register listener for `manager1`
        let (socket, client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        // handle syn packet and spawn manager in the background
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        let mut reader = BufReader::new(client_socket);
        let mut response = String::new();

        // read stream status
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "STREAM STATUS RESULT=OK\n");

        // read remote's destination id
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, format!("{serialized}\n"));

        // read payload from syn packet
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "hello, world\n");
    }

    #[tokio::test]
    async fn data_in_syn_packet_non_silent_pending_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let serialized = base64_encode(destination.serialized());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(&destination)
            .with_signature()
            .with_payload(b"hello, world\n")
            .build_and_sign(&signing_key)
            .to_vec();

        // handle syn packet and spawn manager in the background
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());
        assert!(!manager.pending_inbound.is_empty());

        let outbound = TunnelId::random();
        let inbound = Lease::random();
        let mut path_manager =
            RoutingPathManager::<MockRuntime>::new(manager.destination_id.clone(), vec![outbound]);
        path_manager.register_leases(&destination.id(), Ok(vec![inbound]));
        let pending_handle = path_manager.pending_handle();

        tokio::spawn(async move { while let Some(_) = path_manager.next().await {} });

        // register listener for `manager1`
        let (socket, client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: false,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        let mut reader = BufReader::new(client_socket);
        let mut response = String::new();

        // read stream status
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "STREAM STATUS RESULT=OK\n");

        // read remote's destination id
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, format!("{serialized}\n"));

        // read payload from syn packet
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "hello, world\n");
    }

    #[tokio::test]
    async fn data_in_syn_packet_silent_pending_ephemeral() {
        let socket_factory = SocketFactory::new().await;

        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let packet = PacketBuilder::new(1337u32)
            .with_synchronize()
            .with_send_stream_id(0u32)
            .with_replay_protection(&manager.destination.id())
            .with_from_included(&destination)
            .with_signature()
            .with_payload(b"hello, world\n")
            .build_and_sign(&signing_key)
            .to_vec();

        // handle syn packet and spawn manager in the background
        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());
        assert!(!manager.pending_inbound.is_empty());

        let outbound = TunnelId::random();
        let inbound = Lease::random();
        let mut path_manager =
            RoutingPathManager::<MockRuntime>::new(manager.destination_id.clone(), vec![outbound]);
        path_manager.register_leases(&destination.id(), Ok(vec![inbound]));
        let pending_handle = path_manager.pending_handle();

        tokio::spawn(async move { while let Some(_) = path_manager.next().await {} });

        // register listener for `manager1`
        let (socket, client_socket) = socket_factory.socket().await;
        assert!(manager
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        tokio::spawn(async move { while let Some(_) = manager.next().await {} });

        let mut reader = BufReader::new(client_socket);
        let mut response = String::new();

        // read payload from syn packet
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        assert_eq!(response, "hello, world\n");
    }

    #[tokio::test]
    async fn active_session_destroyed() {
        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let outbound1 = TunnelId::random();
        let inbound1 = Lease::random();
        let mut path_manager1 = RoutingPathManager::<MockRuntime>::new(
            manager1.destination_id.clone(),
            vec![outbound1],
        );
        let pending_handle = path_manager1.pending_handle();
        path_manager1.register_leases(&manager2.destination_id, Ok(vec![inbound1]));

        let outbound2 = TunnelId::random();
        let inbound2 = Lease::random();
        let mut path_manager2 = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![outbound2],
        );
        path_manager2.register_leases(&manager1.destination_id, Ok(vec![inbound2]));
        let handle = path_manager2.handle(manager1.destination_id.clone());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut path_manager1.next() => {}
                    _ = &mut path_manager2.next() => {}
                }
            }
        });

        // register listener for `manager1`
        let (socket, mut listener_stream) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        // create new oubound stream to `manager1`
        let (socket, client_stream) = socket_factory.socket().await;
        let (_stream_id, packet, _, _, _) = manager2.create_stream(
            manager1.destination_id.clone(),
            handle,
            socket,
            HashMap::new(),
        );

        assert!(manager1
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet.to_vec(),
            })
            .is_ok());

        assert!(std::matches!(
            manager1.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        let (destination_id, packet) =
            match tokio::time::timeout(Duration::from_secs(5), manager1.next())
                .await
                .unwrap()
                .unwrap()
            {
                StreamManagerEvent::SendPacket {
                    delivery_style,
                    packet,
                    ..
                } => (delivery_style.destination_id().clone(), packet),
                _ => panic!("invalid event"),
            };

        assert_eq!(destination_id, manager2.destination_id);
        assert!(manager2
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet,
            })
            .is_ok());

        // remove session to manager2 due to error
        manager1.remove_session(&manager2.destination_id);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = manager1.next() => {}
                    _ = manager2.next() => {}
                }
            }
        });

        let mut reader = tokio::io::BufReader::new(client_stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");

        // verify that the stream has been closed
        let mut buffer = vec![0u8; 12];
        assert_eq!(listener_stream.read(&mut buffer).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn signature_missing_inbound_stream() {
        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // build syn packet without signature
        let payload = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());

            PacketBuilder::new(1337u32)
                .with_synchronize()
                .with_send_stream_id(0u32)
                .with_replay_protection(&manager.destination.id())
                .with_from_included(&destination)
                .with_payload(b"hello, world\n")
                .build()
                .to_vec()
        };

        assert_eq!(
            manager.on_packet(I2cpPayload {
                dst_port: 0,
                payload,
                protocol: Protocol::Streaming,
                src_port: 0
            }),
            Err(StreamingError::SignatureMissing),
        );
    }

    #[tokio::test]
    async fn destination_missing() {
        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // build syn packet without replay protection
        let packet = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());

            PacketBuilder::new(1337u32)
                .with_send_stream_id(0u32)
                .with_synchronize()
                .with_signature()
                .with_from_included(&destination)
                .build_and_sign(&signing_key)
        };

        assert_eq!(
            manager.on_packet(I2cpPayload {
                dst_port: 0,
                payload: packet.to_vec(),
                protocol: Protocol::Streaming,
                src_port: 0
            }),
            Err(StreamingError::ReplayProtectionCheckFailed),
        );
    }

    #[tokio::test]
    async fn inbound_stream() {
        let signing_key = SigningPrivateKey::from_bytes(&[
            116, 15, 103, 156, 205, 43, 224, 113, 103, 249, 182, 195, 149, 25, 171, 177, 151, 135,
            221, 125, 79, 161, 205, 146, 188, 100, 15, 177, 189, 91, 167, 60,
        ])
        .unwrap();
        let destination = {
            let serialized_len = (320usize + 32usize)
                .saturating_add(32usize)
                .saturating_add(1usize)
                .saturating_add(2usize)
                .saturating_add(4usize);

            let mut out = BytesMut::with_capacity(serialized_len);

            out.put_slice(&[0u8; 320usize + 32usize]);
            out.put_slice(signing_key.public().as_ref());
            out.put_u8(0x05);
            out.put_u16(0x04);
            out.put_u16(0x0007);
            out.put_u16(0u16);

            Destination::parse(&out).unwrap()
        };
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let payload = vec![
            0, 0, 0, 0, 7, 170, 162, 225, 0, 0, 0, 0, 0, 0, 0, 0, 8, 92, 237, 166, 51, 230, 31, 2,
            219, 176, 105, 43, 109, 206, 122, 239, 241, 221, 135, 206, 60, 147, 145, 41, 155, 120,
            133, 180, 145, 4, 26, 107, 40, 9, 4, 169, 1, 201, 127, 213, 228, 57, 98, 56, 202, 186,
            4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107,
            167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46,
            112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93,
            127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224,
            232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56,
            202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97,
            227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192,
            50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101,
            93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46,
            224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57,
            98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217,
            232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78,
            254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167,
            187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112,
            10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127,
            213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232,
            108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202,
            186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227,
            107, 167, 187, 30, 101, 93, 25, 140, 66, 230, 135, 216, 58, 4, 196, 109, 50, 64, 50,
            20, 213, 102, 99, 242, 187, 7, 216, 187, 137, 158, 228, 199, 195, 182, 38, 53, 40, 227,
            5, 0, 4, 0, 7, 0, 0, 7, 20, 182, 215, 224, 75, 178, 60, 111, 31, 179, 197, 227, 223,
            204, 20, 139, 51, 220, 96, 129, 16, 67, 235, 112, 185, 5, 108, 37, 55, 24, 251, 233,
            175, 88, 10, 18, 128, 227, 33, 34, 87, 15, 141, 210, 183, 58, 42, 184, 148, 221, 156,
            78, 128, 175, 18, 79, 142, 32, 0, 13, 28, 247, 4, 222, 7,
        ];

        assert!(manager
            .on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload,
            })
            .is_ok());
    }

    #[tokio::test]
    async fn invalid_signature() {
        let signing_key = SigningPrivateKey::from_bytes(&[
            116, 15, 103, 156, 205, 43, 224, 113, 103, 249, 182, 195, 149, 25, 171, 177, 151, 135,
            221, 125, 79, 161, 205, 146, 188, 100, 15, 177, 189, 91, 167, 60,
        ])
        .unwrap();
        let destination = {
            let serialized_len = (320usize + 32usize)
                .saturating_add(32usize)
                .saturating_add(1usize)
                .saturating_add(2usize)
                .saturating_add(4usize);

            let mut out = BytesMut::with_capacity(serialized_len);

            out.put_slice(&[0u8; 320usize + 32usize]);
            out.put_slice(signing_key.public().as_ref());
            out.put_u8(0x05);
            out.put_u16(0x04);
            out.put_u16(0x0007);
            out.put_u16(0u16);

            Destination::parse(&out).unwrap()
        };
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let payload = vec![
            0, 0, 0, 0, 7, 170, 162, 225, 0, 0, 0, 0, 0, 0, 0, 0, 8, 92, 237, 166, 51, 230, 31, 2,
            219, 176, 105, 43, 109, 206, 122, 239, 241, 221, 135, 206, 60, 147, 145, 41, 155, 120,
            133, 180, 145, 4, 26, 107, 40, 9, 4, 169, 1, 201, 127, 213, 228, 57, 98, 56, 202, 186,
            4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107,
            167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46,
            112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93,
            127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224,
            232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56,
            202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97,
            227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192,
            50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101,
            93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46,
            224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57,
            98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217,
            232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78,
            254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167,
            187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112,
            10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127,
            213, 228, 57, 98, 56, 202, 186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232,
            108, 24, 217, 232, 97, 227, 107, 167, 187, 30, 101, 93, 127, 213, 228, 57, 98, 56, 202,
            186, 4, 78, 254, 192, 50, 46, 112, 10, 223, 46, 224, 232, 108, 24, 217, 232, 97, 227,
            107, 167, 187, 30, 101, 93, 25, 140, 66, 230, 135, 216, 58, 4, 196, 109, 50, 64, 50,
            20, 213, 102, 99, 242, 187, 7, 216, 187, 137, 158, 228, 199, 195, 182, 38, 53, 40, 227,
            5, 0, 4, 0, 7, 0, 0, 7, 20, 182, 215, 224, 75, 178, 60, 111, 31, 179, 197, 227, 223,
            204, 20, 139, 51, 220, 96, 129, 16, 67, 235, 112, 185, 5, 108, 37, 55, 24, 251, 233,
            175, 88, 10, 18, 128, 227, 33, 34, 87, 15, 141, 210, 183, 58, 42, 184, 148, 221, 156,
            78, 128, 175, 18, 79, 142, 32, 0, 13, 28, 247, 4, 223, 7,
        ];

        assert_eq!(
            manager.on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload,
            }),
            Err(StreamingError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn invalid_destination_id() {
        let mut manager = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let packet = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());

            PacketBuilder::new(1337u32)
                .with_send_stream_id(0u32)
                .with_replay_protection(&DestinationId::random())
                .with_synchronize()
                .with_signature()
                .with_from_included(&destination)
                .build_and_sign(&signing_key)
                .to_vec()
        };

        assert_eq!(
            manager.on_packet(I2cpPayload {
                src_port: 13u16,
                dst_port: 37u16,
                protocol: Protocol::Streaming,
                payload: packet,
            }),
            Err(StreamingError::ReplayProtectionCheckFailed)
        );
    }

    // TODO: add better test
    #[tokio::test]
    async fn offline() {
        // set runtime unix time clock to 0 to pass the offline signature expiration check
        MockRuntime::set_time(Some(Duration::from_nanos(0)));

        let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
        let destination = Destination::new::<MockRuntime>(signing_key.public());
        let mut manager = StreamManager::<MockRuntime>::new(destination, signing_key);

        let input = vec![
            226, 27, 26, 214, 19, 0, 72, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 8, 233, 2, 49, 0, 0,
            24, 166, 169, 39, 201, 40, 81, 192, 99, 254, 57, 144, 204, 123, 19, 99, 16, 224, 218,
            218, 95, 90, 61, 49, 141, 4, 243, 119, 192, 97, 124, 47, 92, 220, 228, 185, 127, 3,
            193, 53, 168, 224, 23, 231, 142, 15, 167, 130, 140, 84, 234, 78, 90, 43, 150, 30, 199,
            157, 223, 36, 94, 61, 106, 110, 85, 6, 93, 63, 173, 14, 132, 125, 253, 133, 124, 118,
            101, 229, 231, 87, 9, 159, 211, 21, 77, 26, 196, 169, 21, 146, 37, 85, 219, 81, 76,
            253, 183, 147, 232, 233, 118, 182, 227, 181, 107, 210, 194, 103, 219, 180, 120, 42,
            130, 143, 241, 5, 99, 212, 107, 135, 233, 208, 119, 111, 172, 19, 61, 179, 154, 152,
            45, 221, 144, 237, 124, 190, 68, 36, 125, 149, 148, 117, 19, 3, 94, 77, 29, 240, 7, 99,
            7, 65, 52, 243, 174, 39, 57, 63, 201, 244, 90, 103, 119, 106, 80, 19, 155, 168, 21, 62,
            143, 208, 58, 173, 65, 29, 163, 176, 91, 223, 244, 193, 58, 213, 170, 139, 188, 163,
            207, 90, 153, 32, 118, 126, 51, 233, 153, 38, 248, 210, 78, 112, 60, 246, 54, 255, 18,
            139, 184, 101, 139, 222, 4, 245, 40, 33, 49, 132, 108, 118, 53, 62, 146, 115, 155, 42,
            252, 98, 106, 9, 252, 224, 82, 48, 112, 234, 94, 167, 27, 134, 254, 65, 87, 116, 62,
            77, 126, 193, 244, 191, 165, 43, 139, 123, 172, 19, 117, 214, 15, 179, 240, 232, 255,
            42, 85, 129, 119, 246, 53, 8, 171, 131, 162, 52, 204, 15, 156, 214, 51, 203, 99, 120,
            152, 51, 16, 118, 199, 71, 59, 114, 212, 86, 31, 195, 18, 154, 78, 203, 208, 0, 152,
            74, 7, 14, 56, 201, 198, 221, 129, 20, 22, 198, 197, 247, 105, 100, 42, 68, 54, 76, 47,
            153, 151, 152, 83, 35, 66, 11, 48, 18, 169, 51, 142, 148, 220, 221, 166, 119, 188, 114,
            231, 172, 159, 115, 67, 92, 138, 77, 158, 161, 4, 232, 231, 185, 66, 110, 88, 56, 156,
            164, 173, 127, 213, 199, 247, 5, 21, 61, 208, 204, 49, 164, 34, 56, 241, 148, 80, 108,
            141, 66, 114, 98, 65, 99, 5, 0, 4, 0, 7, 0, 0, 6, 194, 103, 211, 114, 177, 0, 7, 114,
            245, 169, 33, 134, 26, 252, 238, 198, 139, 178, 162, 137, 244, 248, 219, 134, 158, 177,
            169, 36, 111, 194, 146, 62, 64, 132, 131, 205, 60, 141, 119, 75, 98, 229, 232, 91, 194,
            2, 167, 112, 200, 140, 187, 82, 159, 142, 104, 231, 51, 65, 186, 199, 13, 110, 250,
            125, 184, 96, 36, 20, 106, 127, 70, 84, 46, 253, 209, 8, 190, 88, 186, 122, 152, 13,
            39, 3, 238, 211, 221, 88, 159, 203, 116, 189, 186, 222, 120, 237, 193, 252, 251, 122,
            55, 198, 6, 234, 139, 212, 76, 100, 124, 36, 16, 82, 83, 191, 31, 246, 245, 9, 104,
            190, 118, 155, 58, 176, 214, 151, 106, 55, 80, 236, 75, 135, 68, 29, 86, 241, 79, 8,
            146, 151, 44, 48, 83, 253, 24, 26, 1, 172, 10, 174, 49, 29, 197, 101, 180, 213, 153, 6,
            43, 41, 125, 79, 60, 122, 216, 254, 14,
        ];

        match manager.on_packet(I2cpPayload {
            src_port: 13u16,
            dst_port: 37u16,
            protocol: Protocol::Streaming,
            payload: input,
        }) {
            Err(StreamingError::ReplayProtectionCheckFailed) => {}
            _ => panic!("invalid error"),
        }
    }

    #[tokio::test]
    async fn stream_destroyed_while_opening() {
        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        // register listener for `manager1`
        let (socket, _) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: PendingRoutingPathHandle::create(),
            })
            .is_ok());

        let mut path_manager = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![TunnelId::random()],
        );
        path_manager.register_leases(&manager1.destination_id.clone(), Ok(vec![Lease::random()]));

        // create new oubound stream to `manager1`
        let (socket, _client_stream) = socket_factory.socket().await;
        let (stream_id, _packet, _, _, _) = manager2.create_stream(
            manager1.destination_id.clone(),
            path_manager.handle(manager1.destination_id.clone()),
            socket,
            HashMap::new(),
        );

        // verify there's one outbound timer active
        assert_eq!(manager2.outbound_timers.len(), 1);
        assert!(manager2.pending_outbound.get(&stream_id).is_some());
        assert!(manager2.destination_streams.get(&manager1.destination_id).is_some());

        // remove session and verify the timer's still active
        manager2.remove_session(&manager1.destination_id.clone());

        // verify there's one outbound timer active and that the session is gone
        assert_eq!(manager2.outbound_timers.len(), 1);
        assert!(manager2.pending_outbound.get(&stream_id).is_none());
        assert!(manager2.destination_streams.get(&manager1.destination_id).is_none());

        // wait for 15 seconds and verify that no event is emitted
        assert!(tokio::time::timeout(Duration::from_secs(15), manager2.next()).await.is_err());

        // verify that there are no timers anymore
        assert!(manager2.outbound_timers.is_empty());
        assert!(manager2.pending_outbound.get(&stream_id).is_none());
        assert!(manager2.destination_streams.get(&manager1.destination_id).is_none());
    }

    #[tokio::test]
    async fn dst_and_src_ports_specified() {
        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let outbound1 = TunnelId::random();
        let inbound1 = Lease::random();
        let mut path_manager1 = RoutingPathManager::<MockRuntime>::new(
            manager1.destination_id.clone(),
            vec![outbound1],
        );
        let pending_handle = path_manager1.pending_handle();
        path_manager1.register_leases(&manager2.destination_id, Ok(vec![inbound1]));

        let outbound2 = TunnelId::random();
        let inbound2 = Lease::random();
        let mut path_manager2 = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![outbound2],
        );
        path_manager2.register_leases(&manager1.destination_id, Ok(vec![inbound2]));
        let handle = path_manager2.handle(manager1.destination_id.clone());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut path_manager1.next() => {}
                    _ = &mut path_manager2.next() => {}
                }
            }
        });

        // register listener for `manager1`
        let (socket, _) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        // create new oubound stream to `manager1`
        let (socket, client_stream) = socket_factory.socket().await;
        let (_stream_id, packet, _, src_port, dst_port) = manager2.create_stream(
            manager1.destination_id.clone(),
            handle,
            socket,
            HashMap::from_iter([
                (String::from("FROM_PORT"), String::from("1337")),
                (String::from("TO_PORT"), String::from("1338")),
            ]),
        );
        assert_eq!(src_port, 1337);
        assert_eq!(dst_port, 1338);

        assert!(manager1
            .on_packet(I2cpPayload {
                src_port,
                dst_port,
                protocol: Protocol::Streaming,
                payload: packet.to_vec()
            })
            .is_ok());

        assert!(std::matches!(
            manager1.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        let (destination_id, packet) =
            match tokio::time::timeout(Duration::from_secs(5), manager1.next())
                .await
                .unwrap()
                .unwrap()
            {
                StreamManagerEvent::SendPacket {
                    delivery_style,
                    packet,
                    ..
                } => (delivery_style.destination_id().clone(), packet),
                _ => panic!("invalid event"),
            };

        assert_eq!(destination_id, manager2.destination_id);
        assert!(manager2
            .on_packet(I2cpPayload {
                src_port: 1337u16,
                dst_port: 1338u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = manager1.next() => {}
                    _ = manager2.next() => {}
                }
            }
        });

        let mut reader = tokio::io::BufReader::new(client_stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response.as_str(), "STREAM STATUS RESULT=OK\n");
    }

    #[tokio::test]
    async fn syn_resend_with_different_routing_path() {
        let socket_factory = SocketFactory::new().await;
        let remote = DestinationId::random();

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut outbound = (0..3).map(|_| TunnelId::random()).collect::<HashSet<_>>();
        let mut inbound = (0..3)
            .map(|_| {
                let lease = Lease::random();

                (lease.tunnel_id, lease)
            })
            .collect::<HashMap<_, _>>();

        let mut path_manager = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            outbound.iter().cloned().collect(),
        );
        path_manager.register_leases(&remote, Ok(inbound.values().cloned().collect()));

        // create new oubound stream to `manager1`
        let (socket, _client_stream) = socket_factory.socket().await;
        let (_, _, delivery_style, _, _) = manager2.create_stream(
            remote.clone(),
            path_manager.handle(remote.clone()),
            socket,
            HashMap::new(),
        );

        match delivery_style {
            DeliveryStyle::ViaRoute { routing_path } => {
                assert!(outbound.remove(&routing_path.outbound));
                assert!(inbound.remove(&routing_path.inbound).is_some());
            }
            _ => panic!("invalid delivery style"),
        }

        // verify the syn packet is sent twice more
        match tokio::time::timeout(Duration::from_secs(15), manager2.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            StreamManagerEvent::SendPacket {
                delivery_style,
                packet,
                ..
            } if delivery_style.destination_id() == &remote => {
                assert!(Packet::parse::<MockRuntime>(&packet).unwrap().flags.synchronize());

                match delivery_style {
                    DeliveryStyle::ViaRoute { routing_path } => {
                        assert!(outbound.remove(&routing_path.outbound));
                        assert!(inbound.remove(&routing_path.inbound).is_some());
                    }
                    _ => panic!("invalid delivery style"),
                }
            }
            _ => panic!("invalid event"),
        }

        match tokio::time::timeout(Duration::from_secs(15), manager2.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            StreamManagerEvent::SendPacket {
                delivery_style,
                packet,
                ..
            } if delivery_style.destination_id() == &remote => {
                assert!(Packet::parse::<MockRuntime>(&packet).unwrap().flags.synchronize());

                match delivery_style {
                    DeliveryStyle::ViaRoute { routing_path } => {
                        assert!(outbound.remove(&routing_path.outbound));
                        assert!(inbound.remove(&routing_path.inbound).is_some());
                    }
                    _ => panic!("invalid delivery style"),
                }
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn stream_exits_after_multiple_lease_set_query_failures() {
        let socket_factory = SocketFactory::new().await;

        let mut manager1 = {
            let signing_key = SigningPrivateKey::from_bytes(&[0u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let outbound1 = TunnelId::random();
        let inbound1 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(35),
        };
        let mut path_manager1 = RoutingPathManager::<MockRuntime>::new(
            manager1.destination_id.clone(),
            vec![outbound1],
        );
        let pending_handle = path_manager1.pending_handle();
        path_manager1.register_leases(&manager2.destination_id, Ok(vec![inbound1]));

        let outbound2 = TunnelId::random();
        let inbound2 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(35),
        };
        let mut path_manager2 = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![outbound2],
        );
        path_manager2.register_leases(&manager1.destination_id, Ok(vec![inbound2]));
        let handle = path_manager2.handle(manager1.destination_id.clone());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = &mut path_manager1.next() => {
                        let remote = event.unwrap();
                        path_manager1.register_leases(&remote, Err(QueryError::Timeout));
                    }
                    event = &mut path_manager2.next() => {
                        let remote = event.unwrap();
                        path_manager1.register_leases(&remote, Err(QueryError::Timeout));
                    }
                }
            }
        });

        // register listener for `manager1`
        let (socket, _) = socket_factory.socket().await;
        assert!(manager1
            .register_listener(ListenerKind::Ephemeral {
                socket,
                silent: true,
                pending_routing_path_handle: pending_handle,
            })
            .is_ok());

        // create new oubound stream to `manager1`
        let (socket, _client_stream) = socket_factory.socket().await;
        let manager2_dest = manager2.destination_id.clone();
        let (_stream_id, packet, _, _, _) = manager2.create_stream(
            manager1.destination_id.clone(),
            handle,
            socket,
            HashMap::new(),
        );

        assert!(manager1
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet.to_vec()
            })
            .is_ok());

        assert!(std::matches!(
            manager1.next().await,
            Some(StreamManagerEvent::StreamOpened { .. })
        ));

        let (destination_id, packet) =
            match tokio::time::timeout(Duration::from_secs(5), manager1.next())
                .await
                .unwrap()
                .unwrap()
            {
                StreamManagerEvent::SendPacket {
                    delivery_style,
                    packet,
                    ..
                } => (delivery_style.destination_id().clone(), packet),
                _ => panic!("invalid event"),
            };

        assert_eq!(destination_id, manager2.destination_id);
        assert!(manager2
            .on_packet(I2cpPayload {
                src_port: 0u16,
                dst_port: 0u16,
                protocol: Protocol::Streaming,
                payload: packet
            })
            .is_ok());

        tokio::spawn(async move {
            loop {
                let _ = manager2.next().await;
            }
        });

        match tokio::time::timeout(Duration::from_secs(50), manager1.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            StreamManagerEvent::StreamClosed { destination_id } => {
                assert_eq!(destination_id, manager2_dest)
            }
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn outbound_stream_no_routing_path() {
        let socket_factory = SocketFactory::new().await;
        let remote = DestinationId::random();

        let mut manager2 = {
            let signing_key = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let destination = Destination::new::<MockRuntime>(signing_key.public());
            StreamManager::<MockRuntime>::new(destination, signing_key)
        };

        let mut path_manager = RoutingPathManager::<MockRuntime>::new(
            manager2.destination_id.clone(),
            vec![TunnelId::random()],
        );

        // create new outbound stream to random destination for which we don't have a lease set
        let (socket, client_stream) = socket_factory.socket().await;
        let _ = manager2.create_stream(
            remote.clone(),
            path_manager.handle(remote.clone()),
            socket,
            HashMap::new(),
        );

        // verify that stream rejection is emitted
        match tokio::time::timeout(Duration::from_secs(60), manager2.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            StreamManagerEvent::StreamRejected { destination_id } if destination_id == remote => {}
            _ => panic!("invalid event"),
        }

        let mut reader = BufReader::new(client_stream);
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut response))
            .await
            .expect("no timeout")
            .expect("to succeed");

        assert_eq!(response, "STREAM STATUS RESULT=CANT_REACH_PEER\n");
    }
}
