# ═══════════════════════════════════════════════════════════════════
# MISAKA-CORE Multi-Stage Production Dockerfile
# ═══════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ─────────────────────────────────────────────
FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY components ./components
COPY rpc ./rpc
COPY wallet ./wallet

# Build with hardened flags
ENV RUSTFLAGS="-C lto=thin -C strip=symbols -C opt-level=3 -C panic=abort -C overflow-checks=on"
RUN cargo build -p misaka-node --release --locked

# Verify binary is stripped
RUN file /build/target/release/misaka-node | grep -v "with debug_info" || \
    (echo "ERROR: binary has debug info" && exit 1)

# ── Stage 2: Runtime ────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system --gid 10001 misaka \
    && useradd --system --uid 10001 --gid misaka \
       --home-dir /var/lib/misaka --create-home misaka

# Copy stripped binary only
COPY --from=builder /build/target/release/misaka-node /usr/local/bin/misaka-node
COPY docker/node-entrypoint.sh /usr/local/bin/misaka-node-entrypoint
RUN chmod +x /usr/local/bin/misaka-node /usr/local/bin/misaka-node-entrypoint

# Data volume
RUN mkdir -p /var/lib/misaka/data && chown -R misaka:misaka /var/lib/misaka
VOLUME ["/var/lib/misaka/data"]

# Drop to non-root
USER misaka

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:16110/health || exit 1

EXPOSE 16110 16111

ENTRYPOINT ["tini", "--", "/usr/local/bin/misaka-node-entrypoint"]
