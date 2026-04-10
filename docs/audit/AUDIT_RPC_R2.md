# RPC Audit R2

## Scope: crates/misaka-rpc/ + misaka-node/src/dag_rpc.rs + rpc_server.rs + rpc_auth.rs + rpc_rate_limit.rs

## HIGH

### H1: Timing side-channel in API key comparison (rpc_auth.rs:174-188)
- Length check before constant-time compare creates length oracle.
- Fix: pad both to max length, or use `subtle::ConstantTimeEq`.

## MEDIUM

### M1: Faucet endpoint not compile-time blocked on mainnet (rpc_server.rs:78-129)
- Feature `faucet` + wrong `chain_id` = unlimited minting.
- Fix: compile_error if faucet + release, or require env var.

### M2: Fallback rate limit IP creates global bucket DoS (rpc_rate_limit.rs:120-139)
- Missing ConnectInfo → all requests share 127.0.0.1 bucket.
- Fix: reject request if ConnectInfo unavailable (fail-closed).

## LOW

### L1: CORS invalid origins silently discarded (dag_rpc.rs:95-99)
### L2: Default bind address not validated against 0.0.0.0 (rpc_server.rs:147)
### L3: Error responses leak TX size info (rpc_server.rs:786)
