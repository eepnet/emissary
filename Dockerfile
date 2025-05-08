FROM rust:1.82.0 AS builder
WORKDIR /usr/src/emissary

ARG PROFILE=release

RUN apt-get update && apt-get install -y cmake

RUN cargo install --profile $PROFILE --no-default-features emissary-cli

FROM debian:bookworm
RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/emissary-cli /usr/local/bin/emissary-cli

CMD ["emissary-cli"]
