# MISAKA Network — Mainnet P0 Gap Analysis & Fixes

**Date:** 2026-03-18
**Branch:** mainnet-p0

---

## Summary of Changes

| # | Item | File(s) | Severity | Status |
|---|------|---------|----------|--------|
| 1 | KI Proof dual-binding | `ki_proof.rs` | CRITICAL | ✅ Fixed |
| 2 | Block hash binding | `block_validation.rs` | CRITICAL | ✅ Fixed |
| 3 | Same-amount ring | `block_validation.rs` | CRITICAL | ✅ Fixed |
| 4 | Bridge message-bound auth | `lib.rs` (Solana) | CRITICAL | ✅ Fixed |
| 5 | get_address_outputs gated | `rpc_server.rs` | HIGH | ✅ Fixed |
| 6 | real_input_refs removal | `utxo_set.rs` | CRITICAL | ✅ Fixed |
| 7 | Hardening (unwrap/bounded/rate) | Multiple | HIGH | ✅ Fixed |

---

## Item 1: KI Proof — Dual-Binding Σ-Protocol

### Vulnerability (CRITICAL)

Old ki_proof.rs proved `pk = a·s` but NOT `ki = CanonicalKI(s)`.
An adversary controlling `s` could claim any `ki'` — the Fiat-Shamir
challenge changes but a valid response is computable for the new challenge.

### Fix

Dual-commitment Σ-protocol:
```
Commit:    w_pk = a·y,  w_ki = CanonicalKI(y)
Challenge: c = H(DST || a || pk || ki || H(w_pk) || w_ki)
Response:  z = y + c·s
Verify:    recompute w_pk' = a·z - c·pk, recheck challenge
```

The `w_ki = CanonicalKI(y)` commitment binds ki to s through the
Fiat-Shamir transcript. Changing ki changes c, invalidating z.

Additionally, `prove_key_image()` now rejects at prover-side if
`key_image != canonical_key_image(secret)`.

### Tests Added (11 total)

| Test | What it verifies |
|------|-----------------|
| `test_forged_key_image_rejected_at_prove` | Prover rejects non-canonical ki |
| `test_forged_key_image_rejected_at_verify` | Verifier rejects arbitrary ki |
| `test_wrong_ki_same_pk_rejected` | Different secret's ki + same pk fails |
| `test_same_secret_altered_ki_rejected` | 1-bit ki change fails verification |
| `test_corrupted_response_rejected` | Tampered z polynomial fails |
| `test_corrupted_w_ki_commit_rejected` | Tampered w_ki commitment fails |
| `test_ki_proof_deterministic_ki` | Same secret → same ki always |
| `test_ki_proof_unique_per_secret` | Different secrets → different ki |
| `test_malformed_proof_bytes_rejected` | Wrong-size bytes rejected |
| `test_ki_proof_roundtrip` | Prove → serialize → deserialize → verify |
| `test_ki_proof_wrong_pk_fails` | Wrong public key fails |

---

## Item 2: Block Hash Binding

### Vulnerability (CRITICAL)

`proposal.block_hash` was not checked against the actual block content.
An attacker could sign one block hash but submit a different block body.

### Fix

Added `canonical_block_hash()`:
```rust
H("MISAKA_BLOCK_V1:" || height || slot || parent_hash || tx_root)
```

Validation now requires:
```rust
if proposal.block_hash != canonical_block_hash(block) {
    return Err(BlockError::ProposerBlockHashMismatch { ... });
}
```

---

## Item 3: Same-Amount Ring Enforcement

### Vulnerability (CRITICAL)

Old code: `sum_available += amounts.iter().max()`.
An attacker could include a 1M MISAKA decoy UTXO in a ring where their
real UTXO is only 1 MISAKA, then spend 1M MISAKA.

### Fix

**Same-amount ring**: ALL ring members MUST have identical amounts.
```rust
let ring_amount = amounts[0];
for &amt in amounts.iter().skip(1) {
    if amt != ring_amount {
        return Err(BlockError::TxRingAmountsNotUniform { ... });
    }
}
sum_input_amount += ring_amount; // Deterministic, not max()
```

Amount conservation is now EXACT equality (not inequality):
```rust
if sum_input_amount != required { return Err(...); }
```

---

## Item 4: Bridge Message-Bound Authorization

### Vulnerability (CRITICAL)

Old `unlock_tokens` accepted `request_id` as a trusted argument.
Committee members signed the instruction but not the specific unlock content.
An attacker could replay committee signatures with different amounts.

### Fix

1. **request_id recomputation** (not trusted from args):
```rust
computed_request_id = H(
    "MISAKA_BRIDGE_UNLOCK_V2:" || chain_id || source_tx ||
    asset_id || recipient || amount || nonce
)
```

2. **Asset validation**:
- `asset_mapping.is_active == true`
- `vault.mint == asset_mapping.mint`
- `recipient_token_account.mint == asset_mapping.mint`

3. **PDA seeded by computed request_id** (not arg):
```rust
seeds = [SEED_NONCE, &computed_request_id]
```

4. **NonceState now stores the computed request_id** for audit.

---

## Item 5: get_address_outputs Dev-Only

### Issue (HIGH)

`get_address_outputs` exposes address → UTXO mapping, breaking the
privacy model where wallets scan blocks client-side.

### Fix

Feature-gated behind `#[cfg(feature = "dev-rpc")]`:
```rust
#[cfg(feature = "dev-rpc")]
{
    app = app.route("/api/get_address_outputs", post(get_address_outputs));
}
```

Mainnet builds (`cargo build --release`) exclude this route entirely.

---

## Item 6: real_input_refs Storage Cleanup

### Issue (CRITICAL)

`apply_transaction(tx, real_input_refs)` required knowing which UTXO
was spent — breaking the ring signature anonymity model.

### Fix

1. New primary API: `record_nullifier(key_image)` — records only the nullifier.
2. New TX API: `apply_transaction_anonymous(tx)` — uses nullifiers only.
3. Old APIs `spend()` and `apply_transaction()` marked `#[deprecated]`.
4. `block_validation.rs` uses `record_nullifier()` exclusively.

---

## Item 7: Hardening

### P2P unwrap elimination
- `encode()`: `serde_json::to_vec().unwrap()` → `match Ok/Err`
- `advertise_addr.unwrap()` → `filter_map`/`match`
- 0 unwrap in production code (3 in test-only)

### Bounded Vec (DoS protection)
| Constant | Value | Location |
|----------|-------|----------|
| MAX_INPUTS | 16 | utxo.rs |
| MAX_OUTPUTS | 64 | utxo.rs |
| MAX_RING_SIG_SIZE | 64 KiB | utxo.rs |
| MAX_KI_PROOF_SIZE | 4 KiB | utxo.rs |
| MAX_MSG_SIZE | 1 MiB | p2p_network.rs |
| TX body max | 128 KiB | rpc_server.rs |
| Peers per response | 100 | p2p_network.rs |

### RPC Rate Limiting
| Endpoint | Limit |
|----------|-------|
| Faucet | 1 per address per 5 minutes |
| submit_tx | input/output count bounded, min fee enforced |
| Pagination | page_size capped at 100 |
| Faucet drip map | Auto-eviction at 10K entries |

---

## Remaining P1 Gaps

| Priority | Gap | Risk |
|----------|-----|------|
| P1 | Storage atomic writes (crash recovery) | Data corruption |
| P1 | Committed amount proofs (replace same-amount ring) | Privacy limitation |
| P1 | Peer scoring / ban | DoS resilience |
| P2 | STARK range proof integration | Full privacy |
| P2 | Fuzz / property-based testing | Edge cases |
| P2 | Storage proof for bridge (Merkle root verification) | Trustlessness |

---

## Files Changed

| File | Lines Changed | Summary |
|------|--------------|---------|
| `crates/misaka-pqc/src/ki_proof.rs` | Full rewrite (~290 lines) | Dual-binding PoK |
| `crates/misaka-consensus/src/block_validation.rs` | Full rewrite (~280 lines) | block_hash + same-amount |
| `solana-bridge/.../lib.rs` | Full rewrite (~380 lines) | Message-bound + committee |
| `crates/misaka-node/src/rpc_server.rs` | ~50 lines | Feature gate + submit_tx bounds |
| `crates/misaka-storage/src/utxo_set.rs` | ~80 lines | Nullifier API + deprecations |
| `crates/misaka-node/src/p2p_network.rs` | ~15 lines | unwrap removal + bounded peers |
| `crates/misaka-types/src/utxo.rs` | ~30 lines | MAX_INPUTS/OUTPUTS/SIG constants |
| `SECURITY.md` | New | Security policy |
| `docs/MAINNET-P0-GAP.md` | New | This document |

---

## Addendum: Final Corrections (mainnet-final)

### Item 1 Correction: KI Proof Honest Trust Model

The previous version claimed "dual-binding" via `w_ki = CanonicalKI(y)`.
This has been corrected:

**LogRing (mainnet default):** Link_tag binding is genuine. The link_tag
is included in the Fiat-Shamir transcript alongside the Merkle root and
signer's public key. A valid signature mathematically proves the link_tag
corresponds to the signer's secret key.

**LRS (legacy):** The KI proof proves `pk = a·s` with `key_image` in the
Fiat-Shamir transcript. This provides *transcript binding* (changing ki
invalidates the proof) but does NOT prove `ki = CanonicalKI(s)`. The
security relies on the assumption that honest wallets use the canonical
derivation. This is explicitly documented in `ki_proof.rs` and SECURITY.md.

**Decision:** Rather than implementing an expensive hash preimage proof
(STARK-scale), the mainnet strategy is:
- LogRing: Integrated linkability (no separate KI proof)
- LRS: Transcript-bound KI with documented limitations

### Item 2 Correction: Legacy API Permanent Removal

`utxo_set.rs` deprecated functions (`spend()`, `apply_transaction()`) have
been **permanently deleted**, not just deprecated. The storage layer has
no code path that accepts or processes `real_input_refs`.

### Item 3 Addition: Bridge Trust Model Documentation

`docs/BRIDGE-TRUST-MODEL.md` added with explicit documentation of:
- This is a committee-operated bridge, NOT trustless
- Compromise assumptions (M-of-N threshold)
- Committee rotation and incident response procedures
- Event logging for off-chain monitoring
- Future improvement path toward trust-minimized model

### Same-Amount Ring: Classification

**Status: Interim measure, not permanent specification.**

Same-amount rings are a pragmatic solution to prevent amount-inflation
attacks. They limit the anonymity set to UTXOs of the same denomination.
A future upgrade to committed amount proofs (range proofs) would allow
heterogeneous ring amounts while maintaining privacy.

The migration path is:
1. Current: Same-amount rings (simple, auditable)
2. Future P1: Pedersen commitment + range proof (Bulletproofs or STARK)
3. Future P2: Full confidential transactions

---

## Addendum: Strong Binding KI Proof (Final)

### Previous State (Weak → Transcript-only)

All prior versions either:
- Used `w_ki_commit` in the Fiat-Shamir hash but the verifier passed it
  through without reconstruction (v2 "dual-binding" — not actually verified)
- Only proved `pk = a·s` with ki in the transcript (v1 — transcript binding only)

### Current State: Algebraic Strong Binding

The KI proof now uses an algebraic dual-statement Σ-protocol:

```
ki_poly = h_pk · s   where h_pk = HashToPoly(pk)   ← algebraic, not hash-based
key_image = SHA3-256(DST || ki_poly.to_bytes())     ← 32-byte nullifier
```

**Verifier reconstructs BOTH:**
```
w_pk' = a    · z - c · pk        ← standard Σ-protocol
w_ki' = h_pk · z - c · ki_poly   ← NEW: algebraic KI verification
c'    = H(DST || a || pk || ki_poly || w_pk' || w_ki')
check: c' == proof.challenge
```

**Why this is strong:** The verifier computes `w_ki'` from `z` and `ki_poly`.
If `ki_poly ≠ h_pk · s`, the reconstructed `w_ki'` is wrong:
```
w_ki' = h_pk·(y + c·s) - c·ki_poly
      = h_pk·y + c·(h_pk·s - ki_poly)
      ≠ h_pk·y  unless ki_poly = h_pk·s
```
This changes the challenge hash, causing verification to fail.

### Test Coverage (15 tests)

| Test | Property |
|------|----------|
| `test_valid_proof_accepted` | Correct proof passes |
| `test_serialization_roundtrip` | Serialize → deserialize → verify |
| `test_forged_ki_rejected_at_prove` | Non-canonical ki rejected at prover |
| `test_forged_ki_rejected_at_verify` | Arbitrary ki rejected at verifier |
| `test_forged_ki_poly_rejected` | Tampered ki_poly rejected |
| `test_1bit_ki_alteration_rejected` | Single-bit change detected |
| `test_wrong_secret_ki_rejected` | Wrong s with correct pk fails |
| `test_wrong_pk_same_ki_rejected` | Wrong pk fails |
| `test_altered_challenge_rejected` | Tampered challenge fails |
| `test_corrupted_response_rejected` | Tampered z fails |
| `test_transcript_swap_rejected` | Cross-proof ki swap fails |
| `test_ki_deterministic` | Same inputs → same ki |
| `test_ki_unique_per_secret` | Different inputs → different ki |
| `test_hash_to_poly_deterministic` | HashToPoly is deterministic |
| `test_malformed_bytes_rejected` | Wrong-size deserialization fails |
