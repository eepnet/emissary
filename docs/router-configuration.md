---
outline: deep
---

# Router configuration

`emissary-cli` can be configured in two ways: either through a router configuration file (`router.toml`) or via command-line arguments. Command line arguments override options specified in the router configuration. For example, if `router.toml` specifies `allow_local = false` and the router is started with `emissary-cli --allow-local`, NTCP2 and SSU2 are able to connect to routers within a local network. 

To get a full list of available command-line arguments, run `emissary-cli --help`. They are also listed under [Command-line arguments](#command-line-arguments).

## Enabling and disabling subsystems

`router.toml` contains subsections such as `[http-proxy]`, `[i2cp]` and `[transit]`. To disable a subsystem, removed or comment it out. To re-enable it, uncomment the section and restart the router.

For most subsystems, such as I2CP, SAM and transports, disabling them means that the service is not started and that routers and client applications will not able to connect to the endpoints.

Disabling `[transit]` means that the router is started with `G` caps, i.e., ["rejecting all tunnels"](https://geti2p.net/spec/proposals/162-congestion-caps#specification) and all inbound tunnel build requests are rejected.

`[address-book]` is a special case. If an address book has already been downloaded and does not need to downloaded again, `default` and `subscriptions` can be commented out while leaving `[address-book]` uncommented. New `hosts.txt` files are not downloaded when the router starts but host lookups for SAM, I2CP and HTTP proxy are still supported using the existing hosts file.

`[http-proxy]`,  `[socks-proxy]`, `[address-book]`, `[[client-tunnels]]`, and `[[server-tunnels]]` require `[sam]` to be enabled for them to function.

### Examples

Transit tunnels disabled, address book enabled and downloaded during start up:

```toml
# [transit]
# max_tunnels = 10_000

[address-book]
default = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt"
subscriptions = ["http://your-favorite-address-service.i2p/hosts.txt"]
```

Address book, SAM and HTTP proxy disabled and I2CP enabled. Disabling address book means that `.i2p` host lookups are not supported and all connections must use `.b32.i2p` addresses:

```toml
# [address-book]
# default = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt"
# subscriptions = []

# [http-proxy]
# port = 4444
# host = "127.0.0.1"

# [sam]
# tcp_port = 7656
# udp_port = 7655

[i2cp]
port = 7654
```

SAM and address book are enabled but no `hosts.txt` files are downloaded. SAM can resolve any `.i2p` host that exist in the current host file:

```toml
[address-book]
# default = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt"
# subscriptions = []

[sam]
tcp_port = 7656
udp_port = 7655
```

## NTCP2 and SSU2

> [!warning]  
> SSU2 is still in development and is not recommended for general use

`[ntcp2]` and `[ssu2]` have three fields: `host`, `port` and `publish`.

`publish` accepts `true`/`false` which tells router whether the address should be published in the router info. The router will not be able to accept any inbound connections on unpublished transports.

`port` specifies on which port the transport should be bound. It can be left as `0`, meaning the transport will be bound to a random, OS-assigned port. This is not recommended outside of testing. A random port for NTCP2 and SSU2 is generated when the router boots up for the first time.

`host` is the public IP of your machine, i.e., the external address which other routers use to connect to your router. This can be found from your internet router's configuration page or, e.g., from [https://whatismyip.com](https://www.whatismyip.com), assuming you have a static IP. You can also leave `host` empty and use UPnP or NAT-PMP for external address discovery, see next section for more details.

IPv6 is currently ***not*** supported for either transport.

## Port forwarding, UPnP and NAT-PMP

Port forwarding should be configured for the ports specified in `[ntcp2]` and `[ssu2]`, otherwise the router will have difficulties both in building tunnels and accepting transit tunnels.

`emissary-cli` supports both UPnP and NAT-PMP for port forwarding and external address discovery. NAT-PMP is tried first and if it's not available, UPnP is used as a fallback. If neither protocol is available, `port` and `host` used by NTCP2 and SSU2 must be mapped manually. UPnP and NAT-PMP can be disabled by commenting out the `[port-forwarding]` section in `router.toml` or with `--disable-upnp` and `--disable-nat-pmp` CLI flags.

`emissary-cli` supports external address discovery using UPnP and NAT-PMP so if either of them is enabled in `router.toml` and your internet router supports the enabled protocol(s), `host` in `[ntcp2]` and `[ssu2]` can be commented out.

### Example

Enable both UPnP and NAT-PMP and use them for port forwarding and external address discovery:

```toml
[ntcp2]
port = 25515
publish = true

[port-forwarding]
name = "emissary"
nat_pmp = true
upnp = true
```

If either UPnP or NAT-PMP is supported, `emissary-cli` creates a mapping for port `25515` and publishes a router info with the external address discovered during the port mapping process.

## Logging

There are 5 logging levels, ordered by verbosity: `ERROR`, `WARN`, `INFO`, `DEBUG` and `TRACE`.

Each subsystem in `emissary` has a logging target which allows enabling, disabling and adjusting the logging level of that subsystem individually. It's possible to, e.g., enable `TRACE` for SSU2, disable logging for NTCP2 entirely and set the logging level of the tunnel subsystem to `DEBUG`.

By default, `INFO` is enabled for all logging targets.

### Examples

Enable full trace logging for all subsystems:

```bash
emissary-cli -lemissary=trace
```

Set default logging level to `WARN`, enable `DEBUG` for the tunnel subsystem and `TRACE` for NTCP2 and SSU2:

```bash
emissary-cli -lemissary=warn,emissary::tunnel=debug,emissary::ntcp2,emissary::ssu2=trace
```

Enable `TRACE` for transit tunnels and turn off tunnel pool-related logging:

```bash
emissary-cli -lemissary::tunnel::transit=trace,emissary::tunnel::pool=off
```

`emissary` has support for three logging presets which are just a shorthand for enabling/disabling several subsystems. All these turn off logging for `emissary::tunnel::pool`.

* `i2cp`
  * enable `TRACE` for all I2CP-related subsystems
* `sam`
  * enable `TRACE` for all SAM-related subsystems, including [`yosemite`](https://github.com/altonen/yosemite)
* `transit`
  * enable `TRACE` for transit tunnels and `DEBUG` for transport manager

Start `emissary` with full `TRACE`-level logging for SAM and related subsystems:

```bash
emissary-cli -lsam
```

### All logging targets

* `emissary`
* `emissary::address-book`
* `emissary::client-tunnel`
* `emissary::destination`
  * `emissary::destination::lease-set`
  * `emissary::destination::routing-path`
  * `emissary::destination::session`
  * `emissary::destination::session::context`
  * `emissary::destination::session::inbound`
  * `emissary::destination::session::outbound`
* `emissary::i2cp`
  * `emissary::i2cp::message`
  * `emissary::i2cp::pending-session`
  * `emissary::i2cp::session`
  * `emissary::i2cp::socket`
* `emissary::i2np`
* `emissary::netdb`
  * `emissary::netdb::k-bucket`
  * `emissary::netdb::routing-table`
* `emissary::ntcp2`
  * `emissary::ntcp2::active`
  * `emissary::ntcp2::initiator`
  * `emissary::ntcp2::message`
  * `emissary::ntcp2::responder`
  * `emissary::ntcp2::session`
* `emissary::port-mapper`
  * `emissary::port-mapper::nat-pmp`
  * `emissary::port-mapper::upnp`
* `emissary::primitives`
* `emissary::profile`
* `emissary::proxy::http`
* `emissary::reseeder`
* `emissary::router`
* `emissary::router-storage`
* `emissary::runtime::async-std`
* `emissary::runtime::tokio`
* `emissary::sam`
  * `emissary::sam::parser`
  * `emissary::sam::pending::connection`
  * `emissary::sam::pending::session`
  * `emissary::sam::session`
  * `emissary::sam::socket`
* `emissary::server-tunnel`
* `emissary::ssu2`
  * `emissary::ssu2::active`
  * `emissary::ssu2::active::duplicate-filter`
  * `emissary::ssu2::active::transmission`
  * `emissary::ssu2::message`
  * `emissary::ssu2::pending::inbound`
  * `emissary::ssu2::pending::outbound`
  * `emissary::ssu2::socket`
  * `emissary::ssu2::terminating`
* `emissary::streaming`
  * `emissary::streaming::active`
  * `emissary::streaming::listener`
  * `emissary::streaming::pending`
* `emissary::su3`
* `emissary::subsystem`
* `emissary::transport-manager`
* `emissary::tunnel`
  * `emissary::tunnel::context`
  * `emissary::tunnel::garlic`
  * `emissary::tunnel::ibep`
  * `emissary::tunnel::noise`
  * `emissary::tunnel::obgw`
  * `emissary::tunnel::pending`
  * `emissary::tunnel::pool`
    * `emissary::tunnel::pool::listener`
    * `emissary::tunnel::pool::zero-hop`
  * `emissary::tunnel::routing-table`
  * `emissary::tunnel::selector`
  * `emissary::tunnel::transit`
    * `emissary::tunnel::transit::ibgw`
    * `emissary::tunnel::transit::obep`
    * `emissary::tunnel::transit::participant`


### Command-line arguments

```bash
-b, --base-path <PATH>
        Base path where all i2p-related files are stored

        Defaults to $HOME/.emissary/ and if it doesn't exist, new directory is created

-l, --log <LOG>
        Logging targets

        By default, INFO is enabled for all logging targets

        Example: -lemissary::tunnel=debug,emissary::sam,emissary::streaming=trace,emissary::ntcp2=off

        Enables debug logging for tunnels, trace logging for SAM and streaming and turns off logging for NTCP2

    --floodfill
        Run the router as a floodfill

    --allow-local
        Allow local addresses

    --caps <CAPS>
        Router capabilities

    --net-id <NET_ID>
        Network ID

    --overwrite-config
        Overwrite configuration

    --exploratory-inbound-len <NUM>
        Length of an inbound exploratory tunnel

    --exploratory-inbound-count <NUM>
        Number of inbound exploratory tunnels

    --exploratory-outbound-len <NUM>
        Length of an outbound exploratory tunnel

    --exploratory-outbound-count <NUM>
        Number of outbound exploratory tunnels

    --insecure-tunnels
        Allow emissary to build insecure tunnels

        Disables /16 subnet and maximum tunnel participation checks

        Should only be used for testing

    --reseed-hosts <HOST>...
        Comma-separated list of reseed hosts

        Example: --reseed-hosts https://host1.com,https://host2.com,https://host3.com

    --disable-reseed
        Don't reseed the router even if there aren't enough routers

    --reseed-threshold <RESEED_THRESHOLD>
        Reseed threshold

    --force-reseed
        Forcibly reseed the router even if there are enough routers

    --metrics-server-port <METRICS_SERVER_PORT>
        Metrics server port

    --disable-metrics
        Disable metrics

    --http-proxy-port <PORT>
        HTTP proxy port.

        Defaults to 4444

    --http-proxy-host <HOST>
        HTTP proxy host.

        Defaults to 127.0.0.1

    --http-outproxy <HOST>
        HTTP outproxy.

    --socks-proxy-port <PORT>
        SOCKS proxy port.

        Defaults to 4447

    --socks-proxy-host <HOST>
        SOCKS proxy host.

        Defaults to 127.0.0.1

    --max-transit-tunnels <MAX_TUNNELS>
        Maximum number of transit tunnels

    --disable-transit-tunnels
        Disable transit tunnel manager

    --disable-upnp
        Disable UPnP

    --disable-nat-pmp
        Disable NAT-PMP

    --upnp-name <NAME>
        Name for the UPnP client

    --disable-ui
        Disable router UI

    --refresh-interval <REFRESH_INTERVAL>
        Router UI refresh interval

        How often are events gathered from different subsystem and redrawn in the UI

        Unit is seconds and must be at least 1

    --theme <THEME>
        Router UI theme

        [possible values: light, dark]

-h, --help
        Print help (see a summary with '-h')

-V, --version
        Print version
```
