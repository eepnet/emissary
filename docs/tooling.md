---
outline: deep
---

# Built-in tools

`emissary-cli` includes built-in tools inspired by [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools/), available as subcommands of the router.

## Base64 encoding and decoding

`base64-encode` and `base64-decode` commands allow encoding and decoding strings and files using the I2P Base64 alphabet.

### Examples

Base64-encode a binary key file, reading from stdin and writing to `key.b64` file:

```bash
emissary-cli base64-encode < key.dat > key.b64
```

Base64-decode a string and write the output to stdout:

```bash
emissary-cli base64-decode -s aGVsbG8sIHdvcmxkIQ==
```

Base64-decode a file and write the output to a file:

```bash
emissary-cli base64-decode -f key.b64 -o key.dat
```

## Running an isolated, local I2P network

Useful for testing, e.g., embedded use-cases as the application doesn't have to connect to the I2P mainnet. Stores the `routerInfo` files in a directory which the application can use for reseeding.

### Examples

Create a temporary directory for `routerInfo` files:

```bash
emissary-cli devnet
```

Use an existing directory, and run the devnet with 5 floodfills and 10 normal routers:

```bash
emissary-cli devnet \
  --path /tmp/devnet \
  --num-floodfills 5 \
  --num-routers 10
```
