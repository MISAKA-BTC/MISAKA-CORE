# ─── Stage 1: Build ─────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary
RUN cargo build --release --bin misaka-node --bin misaka-cli \
    && strip target/release/misaka-node \
    && strip target/release/misaka-cli

# ─── Stage 2: Runtime ───────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash misaka

COPY --from=builder /build/target/release/misaka-node /usr/local/bin/
COPY --from=builder /build/target/release/misaka-cli /usr/local/bin/

USER misaka
WORKDIR /home/misaka

# Data volume
VOLUME ["/home/misaka/data"]

# P2P + RPC ports
EXPOSE 6690 3001

# Default: public node
ENTRYPOINT ["misaka-node"]
CMD [ \
    "--name", "misaka-docker", \
    "--mode", "public", \
    "--chain-id", "2", \
    "--rpc-port", "3001", \
    "--p2p-port", "6690", \
    "--data-dir", "/home/misaka/data", \
    "--log-level", "info" \
]
