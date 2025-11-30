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

use anyhow::anyhow;
use clap::Parser;
use emissary_core::{router::Router, Config, Ntcp2Config, SamConfig};
use emissary_util::{reseeder::Reseeder, runtime::tokio::Runtime, su3::ReseedRouterInfo};
use rand::prelude::*;
use rust_chat::DEVNET_ID;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing_subscriber::prelude::*;
use yosemite::{style::Stream, Session, SessionOptions};

/// Logging target for chat client
const LOG_TARGET: &str = "chat-client";

/// Simple chat client which allows connecting to a hidden I2P service and exchanging
/// messages with other connected clients.
///
/// Owns an embedded I2P router and a SAMv3 session bound to that router.
pub struct Client {
    /// I2P router.
    router: Router<Runtime>,

    /// SAMv3 session.
    session: Session<Stream>,

    /// .b32.i2p address of the server.
    server_address: String,
}

impl Client {
    /// Create new [`Server`].
    pub async fn new(
        local: bool,
        routers: Vec<Vec<u8>>,
        server_address: String,
    ) -> anyhow::Result<Self> {
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
            // assing custom name for the client's SAMv3 session
            nickname: "chat-client".to_string(),

            // use the random, OS-assigned port the router is listening on
            samv3_tcp_port: router.protocol_address_info().sam_tcp.expect("to exist").port(),

            // don't publish the lease set to NetDb since this is a client destination
            // and doesn't need to be reached by anyone
            publish: false,

            // use defaults for the rest
            ..Default::default()
        });

        // poll the session until it has been created
        //
        // client sessions are ready as soon as one inbound and one outbound tunnel have been built
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

        Ok(Self {
            router,
            session,
            server_address,
        })
    }

    /// Run the event loop of the client.
    ///
    /// Spawns the embedded I2P router in the background and connects to the chat server.
    ///
    /// Once a connection has been established, spawns two background tasks:
    /// * one for sending messages to the chat server
    /// * one for receiving messages from other clients
    ///
    /// If opening the connection fails or it gets closed, the client attempts to reconnect.
    pub async fn run(self) -> anyhow::Result<()> {
        let Client {
            router,
            mut session,
            server_address,
        } = self;

        // spawn the router in the background
        tokio::spawn(router);

        // run client event loop
        loop {
            // attempt to connect to the chat server and if connection fails, try again later
            let stream = match session.connect(&server_address).await {
                Ok(stream) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        ?server_address,
                        "connected to server",
                    );

                    stream
                }
                Err(error) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to connect to server, trying again later",
                    );

                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            let (mut read_half, mut write_half) = stream.split().expect("split to succeed");

            let write_handle = tokio::spawn(async move {
                // read messages from stdin and send them to server
                //
                // if writing to the stream fails, attempt to reconnect to server
                let stdin = BufReader::new(tokio::io::stdin());
                let mut lines = stdin.lines();

                loop {
                    if let Some(line) = lines.next_line().await.expect("to succeed") {
                        if let Err(error) = write_half.write(line.as_bytes()).await {
                            tracing::error!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to write to stream",
                            );
                            break;
                        }
                    }
                }
            });

            let read_handle = tokio::spawn(async move {
                let mut data = [0u8; 128];

                loop {
                    match read_half.read(&mut data).await {
                        Err(error) => {
                            tracing::error!(
                                target: LOG_TARGET,
                                ?error,
                                "read error",
                            );
                            return;
                        }
                        Ok(nread) => match std::str::from_utf8(&data[..nread]) {
                            Ok(message) => {
                                tracing::info!(
                                    target: LOG_TARGET,
                                    "{message:?}",
                                );
                            }
                            Err(_) => tracing::warn!(
                                target: LOG_TARGET,
                                "server: non-utf8 message",
                            ),
                        },
                    }
                }
            });

            let (_, _) = tokio::join!(read_handle, write_handle);
        }
    }
}

#[derive(Parser)]
#[command(version, about)]
pub struct Arguments {
    /// .b32.i2p address of the server.
    #[arg(short = 'a', long, value_name = "ADDRESS")]
    address: String,

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

    let Arguments { devnet, address } = Arguments::parse();

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

    Client::new(devnet.is_some(), routers, address).await?.run().await
}
