# MISAKA-CORE Audit R2 — Summary

**Date:** 2026-04-07
**Scope:** 8 previously unaudited areas
**Auditor:** Claude Code (automated, requires human verification)

## Severity Totals

| Severity | Count | Mainnet Blocker? |
|----------|-------|-----------------|
| **CRITICAL** | 8 | YES — all must be fixed |
| **HIGH** | 11 | YES — all must be fixed |
| **MEDIUM** | 11 | Recommended before mainnet |
| **LOW** | 8 | Fix at convenience |
| **Total** | **38** | |

## CRITICAL Findings (mainnet blockers)

| # | Area | Finding | File |
|---|------|---------|------|
| C1 | Bridge | Nonce not monotonically enforced; replay via different request_id | lib.rs:111, verifier.rs:206 |
| C2 | Bridge | No permission model for mint/burn (any committee sig = any recipient) | lib.rs:102-142 |
| C3 | Bridge | Signature nonce not bound to request_id | request.rs:48, verifier.rs:155 |
| C4 | Mempool | Nullifier dedup race condition (TOCTOU on HashSet) | lib.rs:147-186 |
| C5 | Storage | Snapshot restore double-apply (WAL entries replayed over checkpoint) | recovery.rs:183-208 |
| C6 | P2P | Handshake PK not validated against genesis validator set | handshake.rs:159-171 |
| C7 | Tokenomics | Treasury send path lacks consensus-level destination verification | distribution.rs + reward_epoch.rs |
| C8 | Shielded | dev-stub-proof feature lacks release compile_error guard | proof_backend.rs:102-146 |

## HIGH Findings

| # | Area | Finding | File |
|---|------|---------|------|
| H1 | Bridge | CumulativeState resets to 0 on restart (accounting gap) | circuit_breaker.rs:200-216 |
| H2 | Bridge | identity_commitment field unused (auth not identity-bound) | verifier.rs:26 |
| H3 | Bridge | Committee verifier doesn't validate scheme consistency | verifier.rs:106-152 |
| H4 | Bridge | No domain separation enforcement in verifier (relies on caller) | lib.rs:36-40 |
| H5 | RPC | Timing side-channel in API key length comparison | rpc_auth.rs:174-188 |
| H6 | Mempool | Per-peer rate limit bypassable via distributed botnet | admission_pipeline.rs:76 |
| H7 | Shielded | testnet_mode allows stub backend without explicit mainnet guard | shielded_state.rs:68-74 |
| H8 | Shielded | Nullifier reservation race condition (TOCTOU) | nullifier_set.rs:84-98 |
| H9 | Storage | Missing fsync after RocksDB WriteBatch (ext4 metadata gap) | rocksdb_store.rs |
| H10 | P2P | IPv4-mapped IPv6 bypasses bogon filter | connection_guard.rs:429-456 |
| H11 | Tokenomics | u128 overflow in reward weight × pool multiplication | reward.rs:226 |

## Per-Area Summary

### 16.1 Bridge — 15 findings (3C, 5H, 4M, 3L)
**Status: NOT mainnet ready.** Authorization model is fundamentally incomplete.
Core issue: committee signature proves "committee approved" but does NOT prove
"this specific request by this specific sender for this specific recipient."
See `docs/audit/AUDIT_BRIDGE_R2.md`.

### 16.2 RPC — 6 findings (0C, 1H, 2M, 3L)
**Status: Acceptable with fixes.** No critical vulnerabilities.
Main risks: faucet on mainnet misconfiguration, rate limit bypass, error info leak.
See `docs/audit/AUDIT_RPC_R2.md`.

### 16.3 Mempool — 5 findings (1C, 1H, 1M, 2L)
**Status: NOT mainnet ready.** Nullifier race condition enables double-spend.
Requires Mutex/RwLock around admission path.
See `docs/audit/AUDIT_MEMPOOL_R2.md`.

### 16.4 Shielded — 5 findings (1C, 2H, 1M, 1L)
**Status: Conditional.** Phase 8 cfg gates are in place but need compile_error
for non-test dev-stub-proof. Nullifier reservation race mirrors mempool issue.
See `docs/audit/AUDIT_SHIELDED_R2.md`.

### 16.5 Storage — 3 findings (1C, 1H, 1M)
**Status: NOT mainnet ready.** Snapshot double-apply on recovery is data-corrupting.
See `docs/audit/AUDIT_STORAGE_R2.md`.

### 16.6 P2P — 4 findings (1C, 1H, 2M)
**Status: NOT mainnet ready.** Handshake accepts any PK without genesis validation.
See `docs/audit/AUDIT_P2P_R2.md`.

### 16.7 Finalizer Equivocation — covered in main audit
Phase 11-13 fixes verified. VoteRegistry with BTreeMap resolves HashMap overwrite.
See previous Phase reports.

### 16.8 Tokenomics — 4 findings (1C, 1H, 2M)
**Status: NOT mainnet ready.** Treasury destination not consensus-verified.
See `docs/audit/AUDIT_TOKENOMICS_R2.md`.

## Mainnet Readiness Verdict

**❌ NOT READY.** 8 CRITICAL + 11 HIGH must be resolved first.

Priority order for fixes:
1. **Bridge authorization model** (C1-C3) — architectural redesign needed
2. **Mempool + Shielded nullifier race** (C4, H8) — add synchronization
3. **Storage recovery double-apply** (C5) — add WAL sequence filtering
4. **P2P handshake genesis check** (C6) — thread validator set
5. **Treasury consensus verification** (C7) — add block-level check
6. **Shielded dev-stub compile_error** (C8) — one-line fix
7. **Remaining HIGH** — iterative
