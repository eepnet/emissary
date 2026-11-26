FROM rust:latest AS builder

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked,id=apt-lists-builder \
    --mount=target=/var/cache/apt,type=cache,sharing=locked,id=apt-cache-builder \
    apt-get update && \
    apt-get install -y \
        cmake \
        libfontconfig1-dev \
        libglib2.0-dev \
        libgtk-3-dev \
        libwebkit2gtk-4.1-dev \
        libssl-dev \
        libxdo-dev \
        libayatana-appindicator3-dev

WORKDIR /usr/src/emissary
COPY . .
RUN --mount=type=cache,target=/usr/src/emissary/target/,id=cargo-target-builder \
    --mount=type=cache,target=/var/cache/cargo,id=cargo-cache-builder \
    CARGO_HOME=/var/cache/cargo cargo build --release --bin emissary-cli && \
    cp /usr/src/emissary/target/release/emissary-cli /emissary-cli

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    libglib2.0-0 \
    libgtk-3-0 \
    libwebkit2gtk-4.1-0 \
    libxdo3 \
    libssl3 \
    libfontconfig1 \
    libayatana-appindicator3-1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /emissary-cli /usr/local/bin/emissary-cli
RUN chmod +x /usr/local/bin/emissary-cli

ENTRYPOINT ["/usr/local/bin/emissary-cli"]
