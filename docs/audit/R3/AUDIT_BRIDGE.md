# Bridge Audit R3

## Verified Fixes
- ✅ Nonce binding (CRIT-1): proof.nonce == request.nonce check at lib.rs:116
- ✅ Domain separation: BRIDGE_AUTH_DOMAIN at verifier.rs:239
- ✅ Replay protection: DurableReplayProtection with fsync
- ✅ Circuit breaker: saturating_add, finality lag check

## HIGH
- **H5** lib.rs:133 — Nonce monotonicity comment but NO implementation. Per-chain nonce tracking absent.

## MEDIUM
- **M4** identity_commitment field unused (verifier.rs:26). Bind to public_input or remove.

## LOW
- **L2** registry.rs:26 — AssetRegistry has no access control.
