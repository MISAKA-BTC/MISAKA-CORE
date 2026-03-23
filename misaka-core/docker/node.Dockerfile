FROM rust:1.80-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY wallet ./wallet
RUN cargo build -p misaka-node --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gosu \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/misaka-node /usr/local/bin/misaka-node
COPY docker/node-entrypoint.sh /usr/local/bin/misaka-node-entrypoint
RUN chmod +x /usr/local/bin/misaka-node-entrypoint \
    && useradd --system --create-home --home-dir /var/lib/misaka --uid 10001 misaka \
    && mkdir -p /var/lib/misaka \
    && chown -R misaka:misaka /var/lib/misaka
USER root
ENTRYPOINT ["/usr/local/bin/misaka-node-entrypoint"]
