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
    crypto::chachapoly::ChaChaPoly,
    error::Ssu2Error,
    primitives::RouterId,
    runtime::Runtime,
    transport::{
        ssu2::{
            message::{Block, DataMessageBuilder, HeaderKind, HeaderReader},
            session::KeyContext,
            Packet,
        },
        TerminationReason,
    },
};

use futures::FutureExt;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::vec::Vec;
use core::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::terminating";

/// Termination timeout.
///
/// How long is the terminating SSU2 session kept active before it's permanently closed
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Termination context.
pub struct TerminationContext {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Intro key.
    pub intro_key: [u8; 32],

    /// Next packet number.
    pub next_pkt_num: u32,

    /// Termination reason.
    pub reason: TerminationReason,

    /// Receive key context.
    pub recv_key_ctx: KeyContext,

    /// ID of the remote router.
    pub router_id: RouterId,

    /// RX channel for receiving packets from [`Ssu2Socket`].
    pub rx: Receiver<Packet>,

    /// Send key context.
    pub send_key_ctx: KeyContext,

    /// TX channel for sending packets to [`Ssu2Socket`].
    pub tx: Sender<Packet>,
}

/// Terminating SSU2 session.
///
/// <https://geti2p.net/spec/ssu2#session-termination>
pub struct TerminatingSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Intro key.
    intro_key: [u8; 32],

    /// Termination packet.
    pkt: Vec<u8>,

    /// Receive key context.
    recv_key_ctx: KeyContext,

    /// ID of the remote router.
    router_id: RouterId,

    /// RX channel for receiving packets from [`Ssu2Socket`].
    rx: Receiver<Packet>,

    /// Expiration timer.
    timer: R::Timer,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: implement clonable udp socket
    tx: Sender<Packet>,
}

impl<R: Runtime> TerminatingSsu2Session<R> {
    /// Create new [`TerminatingSsu2Session`].
    pub fn new(ctx: TerminationContext) -> Self {
        let pkt = DataMessageBuilder::default()
            .with_dst_id(ctx.dst_id)
            .with_pkt_num(ctx.next_pkt_num)
            .with_key_context(ctx.intro_key, &ctx.send_key_ctx)
            .with_termination(ctx.reason)
            .build()
            .to_vec();

        // send `TerminationReceived` if the reason was anything but `TerminationReceived`
        if !core::matches!(ctx.reason, TerminationReason::TerminationReceived) {
            if let Err(error) = ctx.tx.try_send(Packet {
                pkt: pkt.clone(),
                address: ctx.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %ctx.router_id,
                    dst_id = ?ctx.dst_id,
                    ?error,
                    "failed to send termination packet",
                );
            }
        }

        Self {
            address: ctx.address,
            dst_id: ctx.dst_id,
            intro_key: ctx.intro_key,
            pkt,
            recv_key_ctx: ctx.recv_key_ctx,
            router_id: ctx.router_id,
            rx: ctx.rx,
            timer: R::timer(TERMINATION_TIMEOUT),
            tx: ctx.tx,
        }
    }

    /// Handle inbound packet `pkt`.
    ///
    /// Any packet received to a terminating SSU2 session will be discarded and be responded
    /// with a data message containing a termination block.
    fn on_packet(&mut self, mut pkt: Vec<u8>) -> Result<(), Ssu2Error> {
        let pkt_num = match HeaderReader::new(self.intro_key, &mut pkt)?
            .parse(self.recv_key_ctx.k_header_2)?
        {
            HeaderKind::Data { pkt_num } => pkt_num,
            kind => {
                tracing::trace!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    ?kind,
                    "invalid message, expected `Data`",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        };

        let mut payload = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&self.recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&pkt[..16], &mut payload)?;

        if !Block::parse(&payload)
            .ok_or(Ssu2Error::Malformed)?
            .iter()
            .any(|message| core::matches!(message, Block::Termination { .. }))
        {
            if let Err(error) = self.tx.try_send(Packet {
                pkt: self.pkt.clone(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    router_id = %self.router_id,
                    dst_id = ?self.dst_id,
                    ?error,
                    "failed to send termination packet",
                );
            }
        }

        Ok(())
    }
}

impl<R: Runtime> Future for TerminatingSsu2Session<R> {
    type Output = (RouterId, u64);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready((self.router_id.clone(), self.dst_id)),
                Poll::Ready(Some(Packet { pkt, .. })) =>
                    if let Err(error) = self.on_packet(pkt) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            router_id = %self.router_id,
                            dst_id = ?self.dst_id,
                            ?error,
                            "failed to handle packet",
                        );
                    },
            }
        }

        if self.timer.poll_unpin(cx).is_ready() {
            tracing::info!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                dst_id = ?self.dst_id,
                "shutting down session",
            );

            return Poll::Ready((self.router_id.clone(), self.dst_id));
        }

        Poll::Pending
    }
}
