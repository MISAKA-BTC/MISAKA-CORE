FROM rust:1.80-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin misaka-relayer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/misaka-relayer /usr/local/bin/
RUN mkdir -p /data /keys
ENTRYPOINT ["misaka-relayer"]
