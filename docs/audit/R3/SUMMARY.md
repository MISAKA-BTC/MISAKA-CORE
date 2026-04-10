# MISAKA-CORE Audit R3 — Summary

**Date:** 2026-04-07
**Scope:** 9 areas (RPC, Bridge, Mempool, Shielded, Storage, P2P, Configs, PQ-Privacy, Tokenomics)

## Severity Totals

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 2 | Mainnet blockers |
| HIGH | 5 | Must fix before mainnet |
| MEDIUM | 12 | Recommended |
| LOW | 3 | At convenience |
| VERIFIED (previous fixes) | 10 | Phase fixes confirmed in-place |
| **Total findings** | **22** | |
| **Total verifications** | **10** | |

## New CRITICAL Findings

| # | Area | Finding | File |
|---|------|---------|------|
| C1 | RPC | Server binds to 0.0.0.0 by default (all read endpoints public) | main.rs:831 |
| C2 | P2P | Frame nonce replay — out-of-order frames accepted within gap window | secure_transport.rs:189 |

## New HIGH Findings

| # | Area | Finding | File |
|---|------|---------|------|
| H1 | RPC | `dev-noauth` feature bypasses all auth | handler.rs:104 |
| H2 | Configs | mainnet.toml has all-zero weak_subjectivity checkpoint | mainnet.toml:87 |
| H3 | Tokenomics | Validator self-reward not limited (no proposer cap) | reward.rs:155 |
| H4 | PQ-Privacy | HKDF salt misuse in stealth_v2 (tx_context as salt) | stealth_v2.rs:102 |
| H5 | Bridge | Nonce monotonicity comment but no implementation | lib.rs:133 |

## Verified Previous Fixes (10 items)

| Fix | Area | Status |
|-----|------|--------|
| Bridge nonce binding (CRIT-1) | Bridge | ✅ IN PLACE |
| Bridge domain separation | Bridge | ✅ IN PLACE |
| Bridge replay protection (durable) | Bridge | ✅ IN PLACE |
| Mempool nullifier &mut self protection | Mempool | ✅ IN PLACE |
| Shielded dev-stub-proof compile_error | Shielded | ✅ IN PLACE |
| Shielded stub registration cfg gate | Shielded | ✅ IN PLACE |
| Shielded nullifier reservation &mut self | Shielded | ✅ IN PLACE |
| Storage recovery dedup (CRIT-3) | Storage | ✅ IN PLACE |
| P2P bogon filter (IPv4-mapped) | P2P | ✅ CORRECT |
| P2P connection flooding defense | P2P | ✅ CORRECT |

## Per-Area Verdicts

| Area | CRIT | HIGH | MED | LOW | Verdict |
|------|------|------|-----|-----|---------|
| RPC | 1 | 1 | 3 | 1 | ⚠ Fix C1+H1 |
| Bridge | 0 | 1 | 1 | 1 | ⚠ Complete monotonicity |
| Mempool | 0 | 0 | 1 | 0 | ✅ (RBF is feature gap, not vulnerability) |
| Shielded | 0 | 0 | 0 | 0 | ✅ All fixes verified |
| Storage | 0 | 0 | 1 | 0 | ⚠ Add fsync |
| P2P | 1 | 0 | 0 | 1 | ⚠ Fix frame replay |
| Configs | 0 | 1 | 2 | 0 | ⚠ Update checkpoint |
| PQ-Privacy | 0 | 1 | 0 | 0 | ⚠ Fix HKDF salt |
| Tokenomics | 0 | 1 | 4 | 1 | ⚠ Add reward cap |

## Mainnet Readiness

**⚠ CONDITIONAL.** 2 CRITICAL + 5 HIGH must be resolved.

Compared to R2 (8 CRITICAL + 11 HIGH), significant progress:
- R2 CRITICAL count: 8 → R3: 2 (75% reduction)
- R2 HIGH count: 11 → R3: 5 (55% reduction)
- 10 previous Phase fixes verified in-place

Priority fixes:
1. **RPC bind address** (C1) — default to 127.0.0.1
2. **P2P frame replay** (C2) — application-level idempotency
3. **dev-noauth removal** (H1) — compile_error on mainnet
4. **Configs checkpoint** (H2) — real genesis hash
5. **HKDF salt** (H4) — fixed salt + tx_context in info
