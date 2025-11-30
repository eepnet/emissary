---
outline: deep
---

# Embedding `emissary`

*Make sure to read the [official guidelines](https://geti2p.net/en/docs/applications/embedding) for embedding I2P routers*

## Intro

`emissary-core` is an embeddable implementation of the I2P protocol stack. It implements the protocol stack as an asynchronous library that the application embedding it only needs to poll. Importantly, `emissary-core` doesn't provide Rust client interfaces and instead the router can be communicated with using SAMv3 and I2CP.

The first benefit of this approach is that it avoids the need to maintain bespoke client interfaces for every programming language. Since `emissary-core` exposes a standards-compliant SAMv3 and I2CP interfaces instead of a Rust-specific API, applications written in any language can integrate with the router by using their own native client libraries. Most major languages already have working SAMv3 libraries, which means developers can reuse familiar tooling rather than relying on generated bindings. This keeps the core implementation lean and reduces duplication across ecosystems.

The second benefit is that the I2P router used by the application can be switched without any modifications to the client code. Since all I2P routers support the same client interfaces, namely SAMv3 and I2CP, the application can switch from `emissary` to [`go-i2p`](https://github.com/go-i2p/go-i2p) or use a standalone I2P router without needing to modify the application logic. By default an application could embed an I2P router but some users might already have a router running and would prefer using their own router, rather than running two routers on the same host. If the application logic is written using SAMv3 or I2CP, supporting this use-case is a matter of pointing the client library to correct port.

## Embedding `emissary`

`emissary-core` is the core I2P router implementation that gets embedded into applications. It's generic over a `Runtime` object and currently both [`tokio`](https://docs.rs/tokio/latest/tokio/) and [`smol`](https://docs.rs/smol/latest/smol/) are supported. Bindings for other languages, such as Typescript and C/C++, are also on the roadmap.

`emissary-util` provides utilities related to `emissary-core`, such as runtime implementations, a port mapper and an HTTPS reseeder. These are optional utilities and the application that embeds `emissary-core` is free to provide its own implementations, e.g., for on-disk storage.

Embedding `emissary-core` into an application is relatively trivial if `emissary-util` is used:

  1) read the on-disk storage bundle using `emissary_util::storage::Storage`
  2) reseed the router using `emissary_util::reseeder::Reseeder`
  3) create a configuration for `emissary_core::router:Router` from storage bundle
  4) instantiate the router
  5) enable automatic port mapping using `emissary_util::port_mapper::PortMapper`
  6) poll the router and the port mapper in the background
  7) interact with the router over SAMv3 or I2CP
     * `emissary-cli` uses [`yosemite`](https://docs.rs/yosemite/latest/yosemite/) as its SAMv3 client library

The tutorial on the next page provides a step-by-step tutorial for embedding `emissary-core` into a Rust application.
