---
outline: deep
---

# Router configuration

`emissary-cli` can be configured via either command-line arguments or a configuration file (`router.toml`). Modifying `router.toml` is just a way of passing command line arguments to the router at boot. For example, running `emissary-cli` with `--allow-local` and setting option `allow_local = true` in the config file will have the same effect.

Options specified on the command line take precedence over those in the config file.

Example `router.toml`:

```toml
allow_local = false
floodfill = false
insecure_tunnels = false

[http-proxy]
port = 4444
host = "127.0.0.1"

# upnp enabled, nat-pmp disabled
[port-forwarding]
upnp = true
nat_pmp = false
name = "emissary"

# host not specified
# upnp is used to resolve external address
[ntcp2]
port = 25515
publish = true

# i2cp disabled
# [i2cp]
# port = 7654

[sam]
tcp_port = 7656
udp_port = 7655
```

## Available options

Run `emissary-cli --help` to show the built-in help message with all available options.

### General options

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Config file</th>
      <th style="width: 26%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Base path</td>
      <td>-</td>
      <td><code>-b, --base-path &lt;PATH&gt;</code></td>
      <td>HTTP proxy port. (default: 4444)</td>
    </tr>
    <tr>
      <td>Logging</td>
      <td><code>log</code></td>
      <td><code>-l, --log &lt;LOG&gt;</code></td>
      <td>Logging targets. By default, <code>INFO</code> is enabled for all logging targets</td>
    </tr>
    <tr>
      <td>Floodfill</td>
      <td><code>floodfill</code></td>
      <td><code>--floodfill</code></td>
      <td>Run the router as a floodfill. (default: false)</td>
    </tr>
    <tr>
      <td>Insecure tunnels</td>
      <td><code>insecure_tunnels</code></td>
      <td><code>--insecure-tunnels</code></td>
      <td>Allow insecure tunnels. Disables /16 subnet and maximum tunnel participation checks. Should only be used for testing. (default: false)</td>
    </tr>
    <tr>
      <td>Capabilities</td>
      <td><code>caps</code></td>
      <td><code>--caps &lt;CAPS&gt;</code></td>
      <td>Router capabilities</td>
    </tr>
    <tr>
      <td>Network ID</td>
      <td><code>net_id</code></td>
      <td><code>--net-id &lt;NET-ID&gt;</code></td>
      <td>Network ID the router belongs to (default: 2)</td>
    </tr>
    <tr>
      <td>Overwrite config</td>
      <td>-</td>
      <td><code>--ovewrite-config</code></td>
      <td>Overwrite existing configuration file with defaults.</td>
    </tr>
  </tbody>
</table>

### NTCP2

**Config file section:** `[ntcp2]`

| Option | Config file | CLI | Description |
|--------|-------------|-----|-------------|
| Port | `port` | - | Port to listen for incoming NTCP2 connections. (default: random port between 9151-30777) |
| Host | `host` | - | Public IPv4 address for incoming connections. Can be auto-discovered via UPnP/NAT-PMP if left empty. |
| Publish | `publish` | - | Publish the address in router info for incoming connections. (default: true) |

Example:

```toml
[ntcp2]
port = 25515
host = "203.0.113.50"
publish = true
```

### SSU2

> [!warning]
> SSU2 is still in development and is not recommended for general use

**Config file section:** `[ssu2]`

| Option | Config file | CLI | Description |
|--------|-------------|-----|-------------|
| Port | `port` | - | Port to listen for incoming SSU2 connections. |
| Host | `host` | - | Public IPv4 address for incoming connections. Can be auto-discovered via UPnP/NAT-PMP if left empty. |
| Publish | `publish` | - | Publish the address in router info for incoming connections. (default: false) |

Example:

```toml
[ssu2]
port = 25516
publish = true
```

::: info
IPv6 is currently **not** supported for either transport.
:::

### HTTP proxy

**Config file section:** `[http-proxy]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Config file</th>
      <th style="width: 33%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Port</td>
      <td><code>port</code></td>
      <td><code>--http-proxy-port &lt;PORT&gt;</code></td>
      <td>HTTP proxy port. (default: 4444)</td>
    </tr>
    <tr>
      <td>Host</td>
      <td><code>host</code></td>
      <td><code>--http-proxy-host &lt;HOST&gt;</code></td>
      <td>HTTP proxy bind address. (default: 127.0.0.1)</td>
    </tr>
    <tr>
      <td>Outproxy</td>
      <td><code>outproxy</code></td>
      <td><code>--http-outproxy &lt;HOST&gt;</code></td>
      <td>HTTP outproxy for clearnet access.</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[http-proxy]
port = 4444
host = "127.0.0.1"
outproxy = "http://exit.stormycloud.i2p"
```

::: info
HTTP proxy requires SAM to be enabled.
:::

### SOCKS proxy

**Config file section:** `[socks-proxy]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Config file</th>
      <th style="width: 35%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Port</td>
      <td><code>port</code></td>
      <td><code>--socks-proxy-port &lt;PORT&gt;</code></td>
      <td>SOCKS proxy port. (default: 4447)</td>
    </tr>
    <tr>
      <td>Host</td>
      <td><code>host</code></td>
      <td><code>--socks-proxy-host &lt;HOST&gt;</code></td>
      <td>SOCKS proxy bind address. (default: 127.0.0.1)</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[socks-proxy]
port = 4447
host = "127.0.0.1"
```

::: info
SOCKS proxy requires SAM to be enabled.
:::

### SAMv3

**Config file section:** `[sam]`

| Option | Config file | CLI | Description |
|--------|-------------|-----|-------------|
| TCP Port | `tcp_port` | - | SAM TCP port. (default: 7656) |
| UDP Port | `udp_port` | - | SAM UDP port for datagrams. (default: 7655) |
| Host | `host` | - | SAM bind address. (default: 127.0.0.1) |

Example:

```toml
[sam]
tcp_port = 7656
udp_port = 7655
host = "127.0.0.1"
```

### I2CP

**Config file section:** `[i2cp]`

| Option | Config file | CLI | Description |
|--------|-------------|-----|-------------|
| Port | `port` | - | I2CP port. (default: 7654) |
| Host | `host` | - | I2CP bind address. (default: 127.0.0.1) |

Example:

```toml
[i2cp]
port = 7654
host = "127.0.0.1"
```

### Address book

**Config file section:** `[address-book]`

| Option | Config file | CLI | Description |
|--------|-------------|-----|-------------|
| Default | `default` | - | Default address book subscription URL for initial bootstrap. |
| Subscriptions | `subscriptions` | - | List of additional address book subscription URLs. |

Example:

```toml
[address-book]
default = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt"
subscriptions = ["http://your-favorite-address-service.i2p/hosts.txt"]
```

::: info
Address book requires SAM to be enabled. If disabled, `.i2p` host lookups are not supported and all connections must use `.b32.i2p` addresses.
:::

### Exploratory tunnels

**Config file section:** `[exploratory]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Config file</th>
      <th style="width: 35%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Inbound length</td>
      <td><code>inbound_len</code></td>
      <td><code>--exploratory-inbound-len &lt;NUM&gt;</code></td>
      <td>Length of inbound exploratory tunnels.</td>
    </tr>
    <tr>
      <td>Inbound count</td>
      <td><code>inbound_count</code></td>
      <td><code>--exploratory-inbound-count &lt;NUM&gt;</code></td>
      <td>Number of inbound exploratory tunnels.</td>
    </tr>
    <tr>
      <td>Outbound length</td>
      <td><code>outbound_len</code></td>
      <td><code>--exploratory-outbound-len &lt;NUM&gt;</code></td>
      <td>Length of outbound exploratory tunnels.</td>
    </tr>
    <tr>
      <td>Outbound count</td>
      <td><code>outbound_count</code></td>
      <td><code>--exploratory-outbound-count &lt;NUM&gt;</code></td>
      <td>Number of outbound exploratory tunnels.</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[exploratory]
inbound_len = 2
inbound_count = 3
outbound_len = 2
outbound_count = 3
```

### Transit tunnels

Transit tunnels allow your router to participate in the I2P network by relaying traffic for other routers.

**Config file section:** `[transit]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Config file</th>
      <th style="width: 36%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Max tunnels</td>
      <td><code>max_tunnels</code></td>
      <td><code>--max-transit-tunnels &lt;NUM&gt;</code></td>
      <td>Maximum number of transit tunnels. (default: 1000)</td>
    </tr>
    <tr>
      <td>Disable</td>
      <td>-</td>
      <td><code>--disable-transit-tunnels</code></td>
      <td>Disable transit tunnel participation entirely. Router will publish <code>G</code> caps.</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[transit]
max_tunnels = 10_000
```

::: info
Disabling transit means the router is started with `G` caps, i.e., ["rejecting all tunnels"](https://geti2p.net/spec/proposals/162-congestion-caps#specification) and all inbound tunnel build requests are rejected.
:::

### Port forwarding (UPnP/NAT-PMP)

Automatic port forwarding and external address discovery.

**Config file section:** `[port-forwarding]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th style="width: 24%">Config file</th>
      <th style="width: 28%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>UPnP</td>
      <td><code>upnp = true</code></td>
      <td>-</td>
      <td>Enable UPnP. (default: true)</td>
    </tr>
    <tr>
      <td>NAT-PMP</td>
      <td><code>nat_pmp = true</code></td>
      <td>-</td>
      <td>Enable NAT-PMP. (default: true)</td>
    </tr>
    <tr>
      <td>Name</td>
      <td><code>name</code></td>
      <td><code>--upnp-name &lt;NAME&gt;</code></td>
      <td></td>
    </tr>
    <tr>
      <td>Disable UPnP</td>
      <td><code>upnp = false</code></td>
      <td><code>--disable-upnp</code></td>
      <td>Disable UPnP via CLI.</td>
    </tr>
    <tr>
      <td>Disable NAT-PMP</td>
      <td><code>nat_pmp = false</code></td>
      <td><code>--disable-nat-pmp</code></td>
      <td>Disable NAT-PMP via CLI.</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[port-forwarding]
name = "emissary"
nat_pmp = true
upnp = false
```

::: info
NAT-PMP is tried first and if it's not available, UPnP is used as a fallback. If neither protocol is available, ports must be forwarded manually.
:::

### Reseeding

**Config file section:** `[reseed]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th style="width: 24%">Config file</th>
      <th style="width: 33%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Hosts</td>
      <td><code>hosts</code></td>
      <td><code>--reseed-hosts &lt;HOST&gt;...</code></td>
      <td>Comma-separated list of reseed host URLs.</td>
    </tr>
    <tr>
      <td>Threshold</td>
      <td><code>reseed_threshold</code></td>
      <td><code>--reseed-threshold &lt;NUM&gt;</code></td>
      <td>Minimum number of known routers before requesting reseed. (default: 25)</td>
    </tr>
    <tr>
      <td>Disable</td>
      <td>-</td>
      <td><code>--disable-reseed</code></td>
      <td>Don't reseed even if there aren't enough routers.</td>
    </tr>
    <tr>
      <td>Force</td>
      <td>-</td>
      <td><code>--force-reseed</code></td>
      <td>Forcibly reseed even if there are enough routers.</td>
    </tr>
    <tr>
      <td>Disable force IPv4</td>
      <td>-</td>
      <td><code>--disable-force-ipv4</code></td>
      <td>Disable forcing IPv4 when connecting to reseed hosts.</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[reseed]
reseed_threshold = 25
hosts = ["https://specific-reseed-host.com/"]
```

### Metrics

Prometheus-compatible metrics server.

See [the debugging guide](debugging.md#prometheus-and-grafana) for more information on metrics.

**Config file section:** `[metrics]`

<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Config file</th>
      <th style="width: 40%">CLI</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Port</td>
      <td><code>port</code></td>
      <td><code>--metrics-server-port &lt;PORT&gt;...</code></td>
      <td>Metrics server port. (default: 7788)</td>
    </tr>
    <tr>
      <td>Disable</td>
      <td>-</td>
      <td><code>--disable-metrics</code></td>
      <td>Disable metrics server</td>
    </tr>
  </tbody>
</table>

Example:

```toml
[metrics]
port = 7788
```

### Client tunnels

Client tunnels forward local ports to remote I2P destinations.

**Config file section:** `[[client-tunnels]]`

| Option | Config file | Description |
|--------|-------------|-------------|
| Name | `name` | Unique name for the tunnel. |
| Address | `address` | Local bind address. |
| Port | `port` | Local port to listen on. |
| Destination | `destination` | Remote I2P destination (`.i2p` or `.b32.i2p`). |
| Destination port | `destination_port` | Remote destination port. |

Example:

```toml
[[client-tunnels]]
name = "irc"
address = "127.0.0.1"
port = 6668
destination = "irc.postman.i2p"
destination_port = 6667
```

::: info
Client tunnels require SAM to be enabled. Each tunnel must have a unique name and port.
:::

### Server tunnels

Server tunnels expose local services to the I2P network.

**Config file section:** `[[server-tunnels]]`

| Option | Config file | Description |
|--------|-------------|-------------|
| Name | `name` | Unique name for the tunnel. |
| Port | `port` | Local port where the service is running. |
| Destination path | `destination_path` | Path to the destination keys file. |

Example:

```toml
[[server-tunnels]]
name = "my-website"
port = 8080
destination_path = "/path/to/base64-destination.keys"
```

::: info
Server tunnels require SAM to be enabled. Each tunnel must have a unique name, port, and destination path.
:::

### Router UI (Web)

**Config file section:** `[router-ui]`

Starts a local webserver on the specified `port`.

| Option | Config file | Description |
|--------|-------------|-------------|
| Theme | `theme` | Options: `light`, `dark`. (default: dark). |
| Refresh interval | `refresh_interval` | How often the web UI should update. (default: 5). |
| Port | `port` | The port to start the webserver on. (default: 7657) |

Example:

```toml
[router-ui]
theme = "dark"
refresh_interval = 5
port = 7657
```

::: info
Requires the `web-ui` feature.
:::

## Enabling and disabling subsystems

To disable a subsystem, remove or comment out its section in `router.toml`. To re-enable it, uncomment the section and restart the router.

For most subsystems (I2CP, SAM, transports), disabling them means the service is not started and routers/applications cannot connect to those endpoints.

### Examples

**Transit tunnels disabled, address book enabled:**

```toml
# [transit]
# max_tunnels = 10000

[address-book]
default = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt"
subscriptions = ["http://your-favorite-address-service.i2p/hosts.txt"]
```

**Address book, SAM and HTTP proxy disabled, I2CP enabled:**

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

**SAM and address book enabled but no hosts.txt downloaded:**

```toml
[address-book]
# default = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt"
# subscriptions = []

[sam]
tcp_port = 7656
udp_port = 7655
```
