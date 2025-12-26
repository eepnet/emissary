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

use std::collections::HashMap;

use anyhow::anyhow;
use clap::Parser;
use emissary_core::{
    Config, Ntcp2Config, SamConfig,
    crypto::{base32_encode, base64_decode},
    primitives::Destination,
    router::Router,
};
use emissary_util::{reseeder::Reseeder, runtime::tokio::Runtime, su3::ReseedRouterInfo};
use rand::prelude::*;
use rust_chat::DEVNET_ID;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::{Receiver, Sender, channel, error::TrySendError},
};
use tracing_subscriber::prelude::*;
use yosemite::{Session, SessionOptions, style::Stream};

/// Logging target for chat server
const LOG_TARGET: &str = "chat-server";

/// Simple chat server which acts as a message relay between connected clients.
///
/// Owns an embedded I2P router and a SAMv3 session bound to that router, allowing
/// the server to host a hidden service clients can connect to.
pub struct Server {
    /// I2P router.
    router: Router<Runtime>,

    /// SAMv3 session.
    session: Session<Stream>,
}

/// Convert `destination` into a .b32.i2p address.
fn convert_to_base32(destination: &str) -> String {
    let Some(destination) = base64_decode(destination) else {
        tracing::error!(target: LOG_TARGET, %destination, "invalid destination");
        return destination.to_string();
    };

    let destination = Destination::parse(destination).expect("to succeed");

    base32_encode(destination.id().to_vec())
}

impl Server {
    /// Create new [`Server`].
    pub async fn new(local: bool, routers: Vec<Vec<u8>>) -> anyhow::Result<Self> {
        let mut rng = rand::rng();

        let config = Config {
            // allow router to establish connections to local network addresses
            allow_local: local,

            // use insecure tunnels if local connections were allowed
            //
            // this disables tunnel participation-related security checks
            // and allows emissary to build tunnels from a limited set of routers
            //
            // not useful outside of testing
            insecure_tunnels: local,

            // if local network is used, set a custom network id so the router
            // doesn't connect to the I2P mainnet
            net_id: local.then_some(DEVNET_ID),

            // create NTCP2 config:
            //  * allow NTCP2 to bind itself to a random, OS-assigned port
            //  * don't publish the router info to NetDb
            //  * generate random NTCP2 key and IV
            ntcp2: Some(Ntcp2Config {
                port: 0,
                host: None,
                publish: false,
                iv: {
                    let mut iv = [0u8; 16];
                    rng.fill_bytes(&mut iv);
                    iv
                },
                key: {
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    key
                },
            }),

            // enable SAMv3 and bind TCP and UDP to random, OS-assigned ports
            samv3_config: Some(SamConfig {
                tcp_port: 0,
                udp_port: 0,
                host: String::from("127.0.0.1"),
            }),

            // pass in known routers
            //
            // these are needed to allow NTCP2 to establish connections
            routers,

            // generate static key for the router
            //
            // setting this to `None` causes `Router` to generate an ephemeral key
            // which is not recommended outside of testing and instead the static key
            // should be read from disk/other long-term storage
            static_key: Some({
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                key
            }),

            // generate signing key for the router
            //
            // setting this to `None` causes `Router` to generate an ephemeral key
            // which is not recommended outside of testing and instead the signing key
            // should be read from disk/other long-term storage
            signing_key: Some({
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                key
            }),

            // use defaults for the rest
            ..Default::default()
        };

        // initialize router from `config`
        //
        // address book is disabled meaning SAMv3 cannot make host lookups
        // and can only use .b32.i2p addresses for connections
        //
        // storage is disabled meaning emissary will not take backups of router infos or profiles
        let (mut router, _events, _router_info) = Router::<Runtime>::new(config, None, None)
            .await
            .map_err(|error| anyhow!(error))?;

        tracing::info!(
            target: LOG_TARGET,
            "router built, creating SAMv3 session",
        );

        // create new SAMv3 session which allows interacting with the router
        let session = Session::<Stream>::new(SessionOptions {
            // assing custom name for the server's SAMv3 session
            nickname: "chat-server".to_string(),

            // use the random, OS-assigned port the router is listening on
            samv3_tcp_port: router.protocol_address_info().sam_tcp.expect("to exist").port(),

            // publish destination of the session to NetDb
            //
            // this is needed so clients can connect to the server
            publish: true,

            // use defaults for the rest
            ..Default::default()
        });

        // poll the session until it has been created
        //
        // this includes building tunnels for the session and publishing the lease set
        // of the session to NetDb
        //
        // the router must also be polled because otherwise the SAMv3 server won't make progress
        let session = tokio::select! {
            _ = &mut router => {
                return Err(anyhow!("router exited early"));
            }
            result = session => match result {
                Ok(session) => session,
                Err(error) => {
                    return Err(anyhow!("failed to create session: {:?}", error));
                }
            }
        };

        tracing::info!(
            target: LOG_TARGET,
            "server is listening on {}.b32.i2p",
            convert_to_base32(session.destination())
        );

        Ok(Self { router, session })
    }

    /// Main event loop of the server.
    ///
    /// Spawns the router in the background and starts listening to incoming client connections.
    ///
    /// When a client connects, an event loop for it is spawned in the background.
    pub async fn run(self) -> anyhow::Result<()> {
        let Server {
            router,
            mut session,
        } = self;

        // spawn router in the background
        tokio::spawn(router);

        // create background task for the message handler
        let (tx, rx) = channel(128);
        tokio::spawn(Self::server_event_loop(rx));

        // start event loop which listens to incoming connections which are sent to a separate
        // event loop for actual message processing
        while let Ok(stream) = session.accept().await {
            let address = convert_to_base32(stream.remote_destination().trim())[..16].to_string();
            tx.send((address, stream)).await?;
        }

        Ok(())
    }

    /// Messaging-related event loop of the server.
    ///
    /// Accepts incoming client connections, spawns event loops for them and listens to messages
    /// received from clients and relays the messages to other connected clients.
    async fn server_event_loop(mut client_rx: Receiver<(String, yosemite::Stream)>) {
        let (msg_tx, mut msg_rx) = channel::<(String, String)>(128);
        let mut clients = HashMap::<String, Sender<String>>::new();

        loop {
            tokio::select! {
                result = client_rx.recv() => match result {
                    Some((address, stream)) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            %address,
                            "client connected",
                        );

                        // spawn event loop for the client in the background
                        //
                        // give the event loop two channel halves:
                        //  * one for sending the client messages received from other clients
                        //  * one for receiving messages from this client so they can be relayed to other clients
                        let (tx, rx) = channel(16);
                        clients.insert(address.clone(), tx);

                        tokio::spawn(Self::client_event_loop(stream, address, msg_tx.clone(),rx));

                    }
                    None => return,
                },
                msg = msg_rx.recv() => {
                    let (address, message) = msg.expect("message");
                    let message = format!("{address}: {message}");

                    clients.retain(|key, value| {
                        // skip the client who sent the message
                        if key == address.as_str() {
                            return true;
                        }

                        // remove clients that have disconnected
                        match value.try_send(message.clone()) {
                            Ok(()) | Err(TrySendError::Full(_)) => true,
                            Err(_) => false,
                        }
                    });
                }
            }
        }
    }

    /// Client event loop.
    ///
    /// Split `stream` into read and write halves and spawn two tasks:
    ///  * one for reading messages from the connected client
    ///  * one for sending messages received from other clients to the connected client
    async fn client_event_loop(
        stream: yosemite::Stream,
        address: String,
        tx: Sender<(String, String)>,
        mut rx: Receiver<String>,
    ) {
        let (mut read, mut write) = stream.split().expect("split to succeed");
        let write_client = address.clone();
        let read_client = address;

        // spawn task for the write half which reads messages from the client
        // and sends them to server so it can relay them to other clients
        tokio::spawn(async move {
            let mut data = [0u8; 128];

            loop {
                match read.read(&mut data).await {
                    Err(error) => {
                        tracing::error!(
                            target: LOG_TARGET,
                            ?error,
                            "{read_client}: read error",
                        );
                        return;
                    }
                    Ok(nread) => match std::str::from_utf8(&data[..nread]) {
                        Ok(message) => {
                            tx.send((read_client.clone(), message.to_string()))
                                .await
                                .expect("server to be alive");
                        }
                        Err(_) => tracing::error!(
                            target: LOG_TARGET,
                            "{read_client}: non-utf8 message",
                        ),
                    },
                }
            }
        });

        // spawn task for write half which reads messages received from other clients
        // and sends them to this client
        //
        // server has ensured the client will not receive its own messages
        tokio::spawn(async move {
            loop {
                let message = rx.recv().await.expect("message");

                if let Err(error) = write.write(message.as_bytes()).await {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "{write_client}: failed to write message",
                    );
                    return;
                }
            }
        });
    }
}

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// An optional path to a directory where the local I2P network's files are stored.
    ///
    /// If not specified, the client connects to I2P mainnet.
    #[arg(short = 'd', long, value_name = "PATH")]
    devnet: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let Arguments { devnet } = Arguments::parse();

    let routers = match &devnet {
        // if local network was used, reseed the router from the directory
        // where router info files of the other routers are stored
        Some(path) => {
            let mut entries = tokio::fs::read_dir(path).await?;
            let mut routers = Vec::new();

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_file() {
                    let contents = tokio::fs::read(path).await?;
                    routers.push(contents);
                }
            }

            routers
        }
        // reseed the router
        None => Reseeder::reseed(None, false)
            .await?
            .into_iter()
            .map(|ReseedRouterInfo { router_info, .. }| router_info)
            .collect(),
    };

    Server::new(devnet.is_some(), routers).await?.run().await
}
