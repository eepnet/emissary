---
outline: deep
---

# Embedding `emissary` into Rust applications

This page describes how to embed `emissary` into a Rust application. Full code is available on [Github](https://github.com/altonen/emissary/tree/master/examples/rust-tutorial/src/main.rs).

Additionally, there is an example project on [Github](https://github.com/altonen/emissary/tree/master/examples/rust-chat) that shows how to embed `emissary` into a chat application. The project also shows how to interact with the embedded router over SAMv3.

## Initializing router storage

`emissary` needs a way to read and store various files such as router infos and transport keys and `emissary-util` provides a `Storage` object which can be used to manage storage of the router. This is not mandatory and the application can manage the router storage itself if needed but `Storage` abstracts a lot of the details the application shouldn't need to concern itself with.

`Storage::new()` accepts `Option<PathBuf>` which is a path to the directory where `emissary` should store its files. If the application files are stored, e.g., in `$HOME/.app`, `Storage::new()` should be given `Some(PathBuf::from("$HOME/.app/emissary"))`.

If `None` is given, `Storage` initializes the router storage to `$HOME/.emissary`.

```rust
let storage = Storage::new(Some(base_path)).await?;
```

After the storage has been initialized, `Storage::load()` can be used to read a storage bundle which contains all the necessary on-disk information needed to initialize the router. This includes stored router infos and peer profiles, router and transport keys and the `routerInfo` of the embedded router, if it exist.

```rust
let StorageBundle {
    ntcp2_iv,
    ntcp2_key,
    profiles,
    router_info,
    routers,
    signing_key,
    static_key,
    ssu2_intro_key,
    ssu2_static_key,
} = storage.load().await;
```

## Reseeding the router

`emissary-core` doesn't have built-in support for reseeding itself and instead must be given router info files which it then uses to bootstrap. `emissary-util` provides a default HTTPS reseeder that can be used to initially reseed the router. After the router has been reseeded for the first time, reseeding is unecessary as `emissary` learns about other routers through its interactions with NetDb and if it is given a `Storage` object, it stores these discovered router info files on disk.

When the router is started, it should check if `routers` in the `StorageBundle` already contains enough routers and if so, it can skip reseeding entirely

```rust
if routers.is_empty() {
    match Reseeder::reseed(None, false).await {
        Ok(reseed_routers) =>
            for info in reseed_routers {
                let _ = storage.store_router_info(
                    info.name.to_string(),
                    info.router_info.clone()
                )
                .await;
                routers.push(info.router_info);
            },

        Err(_) if routers.is_empty() =>
            return Err(anyhow!("unable to start emissary")),

        Err(error) => tracing::warn!(
            num_routers = routers.len(),
            ?error,
            "failed to reseed router",
        ),
    }
}
```

The `routerInfo` files received in the reseed bundle should be stored on disk so `emissary` can reuse them the next time it boots, without contacting the reseed servers again.


## Configuring the router

Below is an example router configuration. NTCP2 is enabled as the transport protocol and `publish` is set to `true`, meaning the router is accepting inbound connections on the NTCP2 transport. `host` is set `None` and later on `PortMapper` is used to discover the external address of the router.

SAMv3 server is enabled and its TCP and UDP sockets are bound to random, OS-assigned ports. The actual ports can be found by calling `Router::protocol_address_info()`.

Transit tunnels are enabled and the maximum number of tunnels capped at 1000.

```rust
let config = Config {
    ntcp2: Some(Ntcp2Config {
        port: 25515,
        key: ntcp2_key,
        iv: ntcp2_iv,
        publish: true,
        host: None,
    }),
    samv3_config: Some(SamConfig {
        tcp_port: 0,
        udp_port: 0,
        host: "127.0.0.1".to_string(),
    }),
    routers,
    profiles,
    router_info,
    static_key: Some(static_key),
    signing_key: Some(signing_key),
    transit: Some(TransitConfig {
        max_tunnels: Some(1000),
    }),
    ..Default::default()
};
```

All available configurations options can be found from [docs.rs](https://docs.rs/emissary-core/latest/emissary_core/struct.Config.html#fields)

## Instantiating the router

The `Router` object is generic over [`Runtime`](https://docs.rs/emissary-core/latest/emissary_core/runtime/trait.Runtime.html) which provides concrete implementations for, e.g., TCP and UDP sockets, and `emissary-util` provides runtime implementations for `tokio` and `smol`.

`Router::new()` takes three parameters:
* `emissary_core::Config` which was created above
* an implementation of [`AddressBook`](https://docs.rs/emissary-core/latest/emissary_core/runtime/trait.AddressBook.html)
* an implementation of [`Storage`](https://docs.rs/emissary-core/latest/emissary_core/runtime/trait.Storage.html)

`AddressBook` and `Storage` are optional. The former allows `emissary-core` to resolve `.i2p` addresses to `.b32.i2p` addresses and the latter allows `emissary-core` to store router infos and peer profiles it creates during its runtime to disk. The `Storage` object provided by `emisssary-util` implements the `Storage` trait required by `emissary-core` and can be passed to `Router`.

While optional, it's recommended to give the router a `Storage` object as the peer profiling it does during its runtime gives the router a higher tunnel build success rate. If the router infos and peer profiles are not stored on disk, the router starts from scratch every time it's created.

```rust
let (mut router, _events, router_info) =
    Router::<Runtime>::new(config, None, Some(Arc::new(storage.clone())))
        .await
        .map_err(|error| anyhow!("failed to start router: {error}"))?;
```

`Router::new()` returns three objects:
* `Router` which is the I2P router
* `EventSubscriber` which provides router-related events
* local router info

`EventSubscriber` is generally not useful for embedded use-cases as it mainly provides runtime information about the router (bandwidth usage, number of connected routers, etc.) which is used in router UI implementations.

The returned `router_info` must to be stored on disk as it contains the identity of the router. Starting the router later on with the same `router_info` (passed into `emissary_core::Config`) allows the router to have a stable router ID.

```rust
storage.store_local_router_info(router_info).await?;
```

### Configuring port forwarding (optional)

An I2P router works the best when it's able to accept inbound connections and an unreachable NTCP2/SSU2 port causes issus both with building tunnels and accepting transit tunnels. The port can be mapped manually or a port mapper provided by `emissary-util` can be used to do the port mapping automatically.

`PortMapper` must be given a `PortMapperConfig` which specifies which protocols it can use, and NTCP2/SSU2 ports, depending on which transports were enabled.

`Router::protocol_address_info()` can be used to obtain [`ProtocolAddressInfo`](https://docs.rs/emissary-core/latest/emissary_core/router/struct.ProtocolAddressInfo.html#fields) which provides the ports and socket addresses for the transports and client services that were enabled.

```rust
let ProtocolAddressInfo { ntcp2_port, .. } = router.protocol_address_info();

let mut port_mapper = PortMapper::new(
    Some(PortMapperConfig {
        nat_pmp: true,
        upnp: true,
        name: "emissary-rust-tutorial".to_string(),
    }),
    *ntcp2_port,
    None,
);
```

## Running the router

The `Router` objects is a future that only needs to be polled in order for it to make progress.

```rust
tokio::spawn(router);
```

If `PortMapper` was enabled, both can be polled together in a loop in the background.

```rust
tokio::spawn(async move {
    loop {
        tokio::select! {
            address = port_mapper.next() => {
                router.add_external_address(address.expect("value"));
            },
            _ = &mut router => {
                break;
            }
        }
    }
});
```

Interacting with the router happens over [SAMv3](https://geti2p.net/en/docs/api/samv3) and [I2CP](https://geti2p.net/spec/i2cp). `emissary-cli` uses [`yosemite`](https://docs.rs/yosemite/latest/yosemite/) as its SAMv3 client library but there are other Rust SAMv3 client libraries such as [`i2p-rs`](https://github.com/i2p/i2p-rs/) and [`solitude`](https://github.com/syvita/solitude).

See [this example](https://github.com/altonen/emissary/tree/master/examples/rust-chat) for instruction on how to host and interact with I2P hidden services from Rust.
