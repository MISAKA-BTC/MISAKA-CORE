# R5 Bridge Audit — Status and Findings

## Status: NOT WIRED (Deferred to v1.1)

misaka-bridge is an orphan crate. It is not imported by misaka-node.
No bridge endpoints exist in the production RPC server.
The relayer does not compile.

## What exists (quality assessment)

| Component | Status | Quality |
|-----------|--------|---------|
| CommitteeVerifier (M-of-N ML-DSA-65) | Code exists | HIGH — production-grade |
| Replay protection (DurableReplayProtection) | Code exists | MEDIUM — lacks HMAC integrity |
| Circuit breaker | Code exists | MEDIUM — not called from process_lock_event |
| Asset registry | Code exists | OK |
| BridgeModule orchestrator | Code exists | OK — but never called |
| Node RPC endpoints | MISSING | N/A |
| relayer/src/main.rs | BROKEN | Syntax error (extra `}`) |
| relayer submit_unlock | BROKEN | SHA3 vs SHA256, hex vs base64, unsigned TX |
| relayer submit_mint | BROKEN | No AuthorizationProof in payload |

## Phase 35 fixes applied

1. lib.rs doc: WARNING header about orphan status
2. compile_error for dev-bridge-mock in release builds
3. domain_tag: pub → private (prevent accidental overwrite)
4. burn nonce monotonicity added (symmetric with lock_event)

## v1.1 requirements for bridge activation

1. Wire misaka-bridge into misaka-node Cargo.toml dependencies
2. Add /api/bridge/* endpoints under require_api_key
3. Fix relayer compilation (remove extra `}`)
4. Rewrite submit_unlock with solana-sdk (proper TX construction)
5. Add AuthorizationProof to relayer → misaka communication
6. DurableReplayProtection: add HMAC integrity checking
7. Circuit breaker: call from process_lock_event
8. E2E test: Solana → relayer → misaka → relayer → Solana round-trip
