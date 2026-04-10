FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY . .

RUN apt-get update && \
    apt-get install -y clang libclang-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN cargo build --release -p misaka-node --features dag,testnet

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/misaka-node /usr/local/bin/
COPY distribution/public-node/config/ /etc/misaka/

RUN mkdir -p /data

ENV MISAKA_RPC_AUTH_MODE=open

EXPOSE 6690 6691 3001

VOLUME ["/data"]

ENTRYPOINT ["misaka-node"]
CMD ["--config", "/etc/misaka/public-node.toml", "--data-dir", "/data", "--chain-id", "2"]
