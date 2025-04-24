---
outline: deep
---

# Quick start

*Prebuilt binaries for Windows are available on [Github](https://github.com/altonen/emissary/releases)*

### Installing `emissary-cli`

#### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### Build `emissary-cli` from source

```bash
git clone https://github.com/altonen/emissary
cd emissary
cargo build --release
```

#### Install `emissary-cli` from [`crates.io`](https://crates.io/crates/emissary-cli)

```bash
cargo install --locked emissary-cli
```

#### Building `emissary-cli` for Headless Mode

The native UI can be disabled entirely during compilation, meaning `emissary-cli` will run in headless mode. In headless mode, a web UI is available and the default port of the UI is `7657`

```bash
cargo install --locked --no-default-features --features web-ui emissary-cli
```

### Running `emissary-cli`

Start the `emissary-cli` binary:

```bash
emissary-cli
```

On the first boot, the router performs the following tasks:
* creates a directory for itself under `$HOME/.emissary`
* generates router and transport keys
* creates a default configuration for the router
* reseeds the router over HTTPS
* downloads `hosts.txt` from `http://i2p-projekt.i2p/hosts.txt`

For more information on how to configure the router, see [router configuration](router-configuration.md).

Default listening ports: 

|  **Service**  | **Port** |
|---------------|----------|
|   SAMv3 TCP   |   7656   |
|   SAMv3 UDP   |   7655   |
|      I2CP     |   7654   |
|      HTTP     |   4444   |
|     Web UI    |   7657   |

### Graceful shutdown

`emissary-cli` supports graceful shutdown. When it receives a `SIGINT`, it starts a graceful shutdown process that lasts about 10 minutes until all transit tunnels have expired. If there are no transit tunnels the router shuts down immediately.

While not recommended, if you wish to skip graceful shutdown, send a second `SIGINT` which forcefully shuts down the router.
