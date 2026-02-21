---
outline: deep
---

# Developing `emissary`

## Modifying router UIs

The router can be started in "router UI only" mode which starts the UI (native or web) without connecting to the network:

```bash
# native ui
cargo run -- router-ui-dev

# web ui
cargo run --no-default-features --features web-ui -- router-ui-dev
```
