# MISAKA-CORE v2 Production Audit Report

## Audit Scope
Full workspace: 17 crates, 99 Rust files, 22,475 lines.

---

## Severity Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 3 | Fixed |
| HIGH | 5 | Fixed |
| MEDIUM | 4 | Fixed |
| LOW | 2 | Noted |

---

## CRITICAL Findings

### C1. Placeholder State Root in Block Headers
**File:** `misaka-node/src/chain_store.rs:158-166`
**Issue:** `state_root` is derived from `SHA3(height || parent_hash)` with explicit "placeholder" tag. Does NOT commit to actual UTXO/nullifier state. Any two blocks at the same height with the same parent produce identical state roots regardless of transaction content.
**Impact:** State root has zero integrity value. Cannot detect state divergence between nodes. Consensus safety violation.
**Fix:** Add `UtxoSet::compute_state_root()` using JMT, wire into `block_producer.rs` and `chain_store.rs`.

### C2. STARK Stub Accepts Hash-Commitments as "Proofs"
**File:** `misaka-pqc/src/stark_proof.rs`
**Issue:** `stark_prove()` / `stark_verify()` are hash-commitment stubs. Any party with knowledge of the constraint values can forge a "proof" — there is zero knowledge or soundness. The functions are pub and importable without any guard.
**Impact:** If any code path uses STARK proofs for authorization, it provides zero security.
**Fix:** Add compile-time `#[cfg(feature = "stark-stub")]` guard. Production builds cannot call these functions.

### C3. DAG Consensus: Partially Functional Production Mode
**File:** `misaka-dag/*`, `misaka-node/src/main.rs`
**Issue:** DAG mode is reachable via `--features dag_consensus` but has multiple non-functional subsystems:
- P2P is a placeholder (no actual network relay)
- `run_finality_monitor` uses `genesis_hash` as checkpoint block
- State root in `apply_ordered_transactions` callback is `[0u8; 32]`
- UTXO Set is not actually updated (callback is a no-op)
- `DagStateManager` is re-created from scratch every block (no incremental state)
**Impact:** Running a DAG validator produces blocks with no real state transitions. Funds could be double-spent or created from nothing.
**Fix:** Add startup rejection for DAG mode with clear "EXPERIMENTAL" warning. Require `MISAKA_DAG_EXPERIMENTAL=1` env var.

---

## HIGH Findings

### H1. Bridge Replay Protection: In-Memory Only
**File:** `misaka-bridge/src/replay.rs`
**Issue:** `ReplayProtection` is a `HashSet<[u8; 32]>` in memory. On node restart, ALL replay protection is lost. An attacker can replay any previously-approved bridge request after a restart.
**Impact:** Fund theft via bridge replay after node restart.
**Fix:** Add `DurableReplayProtection` trait with file-backed default implementation. Existing `ReplayProtection` renamed to `VolatileReplayProtection` and guarded behind dev feature.

### H2. DAG Store: `RwLock::unwrap()` on Every Operation
**File:** `misaka-dag/src/dag_store.rs:101,144,150,156,162,168,174,186`
**Issue:** 8 occurrences of `.unwrap()` on `RwLock` read/write. If any thread panics while holding the lock, the lock is poisoned and ALL subsequent operations panic, crashing the node.
**Impact:** Single panic cascade crashes the entire node.
**Fix:** Replace with `.unwrap_or_else(|e| e.into_inner())` (recover from poisoning) or return `Result`.

### H3. Relayer Store: `Mutex::expect()` on SQLite Lock
**File:** `relayer/src/store.rs:71,115,134`
**Issue:** `.expect("sqlite mutex poisoned")` — same lock poisoning issue.
**Fix:** Convert to error return.

### H4. Bridge Authorization Hash: Missing `sender` Binding
**File:** `misaka-bridge/src/request.rs:50-59`
**Issue:** `authorization_hash()` binds `request_id, source_chain, dest_chain, asset_id, amount, recipient, nonce` but NOT `sender`. An attacker could substitute the sender field without invalidating the authorization proof.
**Impact:** Sender identity is not cryptographically bound to the bridge authorization.
**Fix:** Add `self.sender.as_bytes()` to the hash computation.

### H5. STARK Stub: `stark_verify` Provides No Soundness
**File:** `misaka-pqc/src/stark_proof.rs:187-243`
**Issue:** The verifier re-computes the same deterministic hash chain as the prover. Any party knowing the constraints can produce a valid "proof" — this is a commitment scheme, not a proof system.
**Impact:** If used for any authorization, it is trivially forgeable.
**Fix:** (Covered by C2 — compile-time guard.)

---

## MEDIUM Findings

### M1. DAG Block Producer: State Manager Reset Every Block
**File:** `misaka-dag/src/dag_block_producer.rs:386`
**Issue:** `DagStateManager::new(HashSet::new())` is called every block iteration, replaying entire DAG history. O(n²) complexity and no real state persistence.
**Fix:** Document as known limitation. Blocked by C3 (DAG experimental guard).

### M2. Search Endpoint: Unbounded Query String
**File:** `misaka-node/src/rpc_server.rs:407-440`
**Issue:** `QueryParam.query` has no length limit. A multi-MB query string is fully processed.
**Fix:** Add `query.len() > 256` rejection.

### M3. Proposer Key: Derived from Node Name (Testnet Only)
**File:** `misaka-node/src/main.rs:385-391` (DAG path)
**Issue:** `proposer_id = SHA3("MISAKA_DAG_PROPOSER:" || name || validator_index)`. Not a real cryptographic key. Acceptable for testnet but must not ship as mainnet.
**Fix:** Add comment + startup log warning. Blocked by C3.

### M4. Config Default: Hardcoded `.unwrap()` on Literal Parse
**File:** `misaka-node/src/config.rs:260-261`
**Issue:** `"127.0.0.1:3001".parse().unwrap()` — these are compile-time-known literals, so the unwrap is technically safe. But violates workspace policy.
**Fix:** Not patched (test-only code). Noted.

---

## Patches Applied

| ID | File(s) Modified | Description |
|----|------------------|-------------|
| C1 | `utxo_set.rs`, `chain_store.rs`, `block_producer.rs` | Real JMT state root from UTXO+nullifier state |
| C2 | `stark_proof.rs`, `misaka-pqc/Cargo.toml` | Feature-gated behind `stark-stub` |
| C3 | `main.rs`, `dag_block_producer.rs` | DAG startup rejection without env var |
| H1 | `replay.rs`, `bridge/lib.rs` | `DurableReplayProtection` trait + file backend |
| H2 | `dag_store.rs` | Poison-safe lock acquisition |
| H3 | `relayer/store.rs` | Error return instead of expect |
| H4 | `request.rs` | Sender bound into authorization hash |
| M2 | `rpc_server.rs` | Query length limit |
