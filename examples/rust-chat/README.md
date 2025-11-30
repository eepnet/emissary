## Rust group chat

This example demonstrates how `emissary` can be embedded in a simple chat application. The application has two roles: server and client. The server embeds an I2P router and hosts a hidden service on that router. The hidden service acts as a simple message relay: multiple clients can connect to the server and send messages to it and the server relays the messages to other connected clients.

The example can be run either in an isolated local network (preferable for testing) or in the I2P mainnet.

### Running locally

To run the example locally, three things are needed: a local I2P network, a chat server and chat clients.

Start an I2P devnet:

```zsh
emissary-cli devnet --path /tmp/emissary-tutorial
```

The server must be given the path where `emissary-cli` stored the `routerInfo` files of the network as it needs a way to reeseed itself.

```zsh
RUST_LOG=chat-server=info cargo run --bin server -- --devnet /tmp/emissary-tutorial
```

After the server is initialized, it prints the `.b32.i2p` address of the hidden service clients can connect to.

Multiple clients can be started and each client must be given the same path as each client embeds an I2P router. Additionally clients must be given the `.b32.i2p` address of the server:

```zsh
RUST_LOG=chat-client=info cargo run --bin client -- --devnet /tmp/emissary-tutorial --address <.b32.i2p address of the server>
```

After the client is ready, it connects to the server and reads messages from stdin which it sends to server. Server acts as a relay and sends the messages it receives from a client to different connected clients.

### Running in I2P mainnet

In order to run the example in I2P mainnet, `--devnet` must be omitted from server and clients. Be mindful that the example will reseed each router separately and build tunnels through other routers of the network so it's best to use `--devnet` when testing, so as not to unnecessarily cause load on the network/reseed servers.

Run a server:

```zsh
RUST_LOG=chat-server=info cargo run --bin server
```

The setup will take longer than with a local network but after it's completed, the `.b32.i2p` printed in the console is globally reachable and you can connect to the chat server as a client from a different computer.

Run a client:

```zsh
RUST_LOG=chat-client=info cargo run --bin client -- --address <.b32.i2p address of the server>
```
