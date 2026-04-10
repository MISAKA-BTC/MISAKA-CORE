# RPC Audit R3

## CRITICAL
- **C1** main.rs:831 — RPC binds 0.0.0.0 by default. All read endpoints public. Fix: default 127.0.0.1.

## HIGH
- **H1** handler.rs:104 — `dev-noauth` bypasses all auth. Fix: compile_error on chain_id=1.

## MEDIUM
- **M1** rpc_rate_limit.rs:120 — ConnectInfo fallback to loopback (shared bucket DoS).
- **M2** WebSocket handler lacks visible auth integration.
- **M3** rpc_server.rs:42 — CORS empty string fails silently (current: fail-closed, good).

## LOW
- **L1** testnet.toml:45 — Faucet per-address cooldown but not per-IP.
