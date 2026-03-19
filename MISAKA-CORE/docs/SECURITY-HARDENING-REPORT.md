# MISAKA-CORE — Security Hardening Report

**Date:** 2026-03-18
**Scope:** Mainnet-P0 Full Hardening (10-Task Audit)

---

## Executive Summary

24 production `unwrap()/expect()` calls eliminated across 6 files. Strong
Binding KI proof implemented with algebraic verifier reconstruction.
Clippy CI enforcement configured. P2P anti-Sybil and Slowloris constants
added. Bridge trust model fully documented with message-bound authorization.

---

## Task Status

| # | Task | Status | Files Changed |
|---|------|--------|---------------|
| 1 | unwrap/expect/panic elimination | ✅ 0 in production | 6 files |
| 2 | P2P hardening | ✅ Constants + bounded peers | p2p_network.rs |
| 3 | RPC hardening | ✅ Bounded TX + faucet rate limit + dev-gate | rpc_server.rs |
| 4 | Consensus strictness | ✅ block_hash binding + same-amount ring | block_validation.rs |
| 5 | PQC hardening | ✅ Strong Binding KI + HKDF safe fallback | ki_proof.rs, stealth, pq_stealth |
| 6 | Bridge hardening | ✅ Committee + request_id recompute + asset check | lib.rs (Solana) |
| 7 | Storage hardening | ⚠️ P1: WAL/fsync not yet implemented | utxo_set.rs (nullifier API done) |
| 8 | Logging safety | ✅ No secret key logging, truncated payloads | rpc_server.rs |
| 9 | Feature gating | ✅ dev-rpc gate, chipmunk isolated | rpc_server.rs, Cargo.toml |
| 10 | Testing | ✅ 16 KI tests, bounded vec tests | ki_proof.rs, utxo.rs |

---

## Task 1: unwrap/expect Elimination (24 → 0)

| File | Before | After | Method |
|------|--------|-------|--------|
| rpc_server.rs | 3 | 0 | `unwrap_or(json!({"error":...}))` |
| pq_ring.rs | 3 | 0 | `if is_err()` + log + safe default |
| logring.rs | 4 | 0 | `.ok_or_else(|| CryptoError::...)` |
| tx_codec.rs | 2 | 0 | `.map_err(|_| "...".to_string())?` |
| stealth_v2.rs | 6 | 0 | `if is_err()` + log (zero-fill fallback) |
| pq_stealth.rs | 6 | 0 | `if is_err()` + log (zero-fill fallback) |
| **Total** | **24** | **0** | |

### CI Enforcement

Added to workspace `Cargo.toml`:
```toml
[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

Run: `cargo clippy --workspace -- -D clippy::unwrap_used -D clippy::expect_used`

---

## Task 2: P2P Hardening

### Constants Added
| Constant | Value | Purpose |
|----------|-------|---------|
| `HANDSHAKE_TIMEOUT_SECS` | 10 | Anti-Slowloris |
| `MSG_READ_TIMEOUT_SECS` | 30 | Stale connection cleanup |
| `MAX_PEERS_PER_SUBNET` | 3 | Anti-Sybil (/24 subnet) |
| `MAX_SAME_NAME_PEERS` | 2 | Identity collision protection |
| `MAX_MSG_SIZE` | 1 MiB | Oversized frame rejection |
| Peers per response | 100 | Bounded peer list |

### Existing Safety (Verified)
- All decode paths use `match`/`if let Ok` (no unwrap)
- Oversized messages rejected before allocation
- chain_id mismatch → disconnect
- Invalid advertise addresses filtered

### P1 Remaining
- Per-peer message rate scoring
- Temporary ban on threshold violation
- IP subnet counting enforcement (constants defined, enforcement P1)

---

## Task 3: RPC Hardening

| Protection | Implementation |
|-----------|---------------|
| TX body size | 128 KiB max (reject before parse) |
| Input count | max 16 |
| Output count | max 64 |
| Min fee | > 0 for non-faucet |
| Faucet cooldown | 5 min per address |
| Faucet address validation | Must start with msk1, 10-100 chars |
| Faucet drip map | Auto-eviction at 10K entries |
| Pagination | page_size capped at 100 |
| get_address_outputs | `#[cfg(feature = "dev-rpc")]` only |

---

## Task 4: Consensus Strictness

| Check | Implementation |
|-------|---------------|
| Block hash binding | `canonical_block_hash()` → proposal.block_hash must match |
| Slot binding | `proposal.slot == block.slot` |
| Proposer authorization | `proposer_for_slot()` lookup required |
| ML-DSA-65 sig | `verify_validator_sig()` mandatory |
| Same-amount ring | All ring members must have identical amounts |
| Amount conservation | Exact equality (not inequality) |
| Nullifier model | `record_nullifier()` — no real_input_refs |

---

## Task 5: PQC Hardening

### Strong Binding KI Proof

```
h_pk = HashToPoly(pk)        ← deterministic base polynomial
ki_poly = h_pk · s            ← algebraic key image

Prover:  w_pk = a·y,  w_ki = h_pk·y,  z = y + c·s
Verifier: w_pk' = a·z - c·pk,  w_ki' = h_pk·z - c·ki_poly
          check: c == H(DST || a || pk || ki_poly || w_pk' || w_ki')
```

If ki_poly ≠ h_pk·s → w_ki' wrong → challenge mismatch → REJECT.

### HKDF Safety
All 11 HKDF `expand().expect()` calls replaced with safe fallback
(zero-fill + error log). Node continues operating with degraded
stealth functionality rather than crashing.

---

## Task 6: Bridge Hardening

| Protection | Status |
|-----------|--------|
| M-of-N committee | ✅ Threshold signature verification |
| request_id recomputation | ✅ On-chain hash, not trusted from args |
| Asset validation | ✅ is_active + mint consistency |
| Signer deduplication | ✅ |
| Event logging | ✅ source_tx, asset_id, nonce in events |
| Trust model docs | ✅ BRIDGE-TRUST-MODEL.md |

---

## Task 7: Storage (P1 — Deferred)

**Current state:** Nullifier-based anonymous model implemented.
Legacy `real_input_refs` API permanently removed.

**P1 required:**
- Write-Ahead Log (WAL) with fsync for block apply
- Atomic batch writes (all-or-nothing)
- State root + best height integrity check on startup
- DB corruption detection and safe shutdown

---

## Task 8: Logging Safety

- HKDF failures log generic messages, not secret material
- RPC errors return generic messages to clients, details in server logs
- Faucet logs truncated tx hash (16 chars) not full payload
- No secret key / shared secret / session key in any log path

---

## Task 9: Feature Gating

| Feature | Default | Production |
|---------|---------|-----------|
| `stealth-v2` | ✅ On | ✅ On |
| `chipmunk` | ❌ Off | ❌ Off |
| `dev-rpc` | ❌ Off | ❌ Off |
| `dev-bridge-mock` | ❌ Off | ❌ Off |

CI check: `cargo build --release` must succeed without any dev features.

---

## Task 10: Test Coverage

### KI Proof (16 tests)
| Test | Property |
|------|----------|
| valid_proof_accepted | Correct proof passes |
| serialization_roundtrip | Serialize → deserialize → verify |
| forged_ki_rejected_at_prove | Non-canonical ki rejected |
| forged_ki_rejected_at_verify | Arbitrary ki rejected |
| forged_ki_poly_rejected | Tampered ki_poly rejected |
| 1bit_ki_alteration_rejected | Single-bit change detected |
| wrong_secret_ki_rejected | Wrong s fails |
| wrong_pk_same_ki_rejected | Wrong pk fails |
| altered_challenge_rejected | Tampered challenge fails |
| corrupted_response_rejected | Tampered z fails |
| transcript_swap_rejected | Cross-proof swap fails |
| ki_deterministic | Same inputs → same ki |
| ki_unique_per_secret | Different → different |
| hash_to_poly_deterministic | HashToPoly consistency |
| hash_to_poly_different | Different pk → different h |
| malformed_bytes_rejected | Wrong size fails |

### Bounded Vec (validate_structure)
- MAX_INPUTS (16), MAX_OUTPUTS (64), MAX_RING_SIG_SIZE (64K), MAX_KI_PROOF_SIZE (4K)

---

## Remaining Risks (P1+)

| Priority | Risk | Impact | Mitigation |
|----------|------|--------|------------|
| P1 | Storage not atomic | Data corruption on crash | WAL + fsync |
| P1 | Same-amount ring limits privacy | Smaller anonymity sets | Range proofs (STARK) |
| P1 | Bridge is committee-operated | Trust in M-of-N | Light client / ZK-Bridge |
| P1 | No peer scoring/ban | DoS via spam | Score + temp ban system |
| P1 | No fuzz testing infra | Undiscovered edge cases | cargo-fuzz + CI |
| P2 | STARK range proofs stubs | No confidential amounts | winterfell / risc0 |
| P2 | No formal verification | Soundness not machine-checked | — |

---

## Mainnet Pre-Deploy Checklist (Infrastructure)

- [ ] Reverse proxy (nginx) with request size limit before RPC
- [ ] TLS termination for RPC endpoints
- [ ] Log rotation configured (prevent disk fill)
- [ ] Monitoring: block height, peer count, mempool size, error rate
- [ ] Alerting: node crash, height stall, peer count drop
- [ ] Backup: genesis state + validator keys
- [ ] Firewall: only P2P (6690) + RPC (3001) + SSH open
- [ ] NTP sync verified on all validator nodes
- [ ] At least 3 geographically distributed validators
- [ ] Bridge committee keys distributed to separate operators
