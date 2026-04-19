# v1.0 MuHash → SMT state commitment migration

Status: **DESIGN + PARALLEL-PHASE IMPLEMENTATION SHIPPED. Activation pending.**
Branch: `feature/v100-smt-migration` (from `origin/main`).

Cross-references:
- `crates/misaka-muhash/src/lib.rs` — legacy v3 accumulator.
- `crates/misaka-smt/src/lib.rs` — v1.0 `SparseMerkleTree` (spec-frozen since v0.7.x).
- `crates/misaka-storage/src/utxo_set.rs` — dual-accumulator `UtxoSet`.
- `crates/misaka-dag/src/narwhal_types/block.rs` — `Block.state_root_smt` (wire-skipped parallel).

---

## 1. Summary

v1.0 replaces the **MuHash** multiset accumulator used for UTXO
state commitment with a **Sparse Merkle Tree (SMT)** over
`(tx_hash, output_index) → TxOutput` leaves. The SMT admits
O(log N) inclusion / exclusion proofs, which MuHash cannot
produce — a precondition for light clients, ZK retrofits, and
the broader Phase 3b proof machinery.

The transition is **gradual**, not a flag day:

| Phase       | `state_root` canonical meaning            | `state_root_smt` on wire |
|-------------|-------------------------------------------|--------------------------|
| v0.9.x / v0.9.1 (pre-activation) | v3 — SHA3(`"MISAKA:state_root:v3:"` ‖ height ‖ MuHash.finalize) | **skipped** (borsh + serde) |
| Parallel (this branch, pre-activation) | v3 (unchanged)                           | skipped (zero on wire)    |
| v1.0 activation epoch (Step 7)    | v4 — SHA3(`"MISAKA:state_root:v4:"` ‖ height ‖ SMT.root) | **present** (digest-bound) |

Consensus rule change happens once, at the activation epoch. The
parallel phase lets us ship the accumulator, its determinism
tests, and the downstream consumer hooks **without** a hard-fork
flag, so the code that operators run in testnet is the same code
that activates at v1.0.

---

## 2. Scope

In scope for v1.0 hard fork:

1. `misaka-smt` crate promoted from spec-frozen library to live
   state commitment.
2. `UtxoSet` mirrors every mutation into the SMT in parallel
   with MuHash (Step 2, already shipped).
3. `UtxoSet::compute_state_root_v4()` — the canonical v1.0
   post-activation state root (Step 3, already shipped).
4. `Block.state_root_smt: [u8; 32]` — v4 state root transported
   per-block (Step 4, already shipped with `#[borsh(skip)]` +
   `#[serde(default, skip)]` — NOT yet on wire).
5. Executor / replay / audit surfaces expose `*_v4` companions
   (Step 5, already shipped).
6. **This document** (Step 6).
7. Activation — remove skip attributes, fold `state_root_smt`
   into `Block::digest_inner`, flip canonical check from v3 to
   v4 in commit path, activate `misaka-smt/v1-hardfork` feature
   (Step 7, NOT YET SHIPPED).
8. Remove MuHash XOR stub in
   `misaka-crypto/src/hashes.rs:113` (Step 8, NOT YET SHIPPED).

Out of scope for v1.0 (deferred):

- `MuHash` crate deletion. Kept until v1.1 so historical block
  replay (pre-activation blocks) still resolves their `state_root`
  against v3.
- `SparseMerkleTree` on-disk persistence. The parallel-phase
  tree is rebuilt leaf-by-leaf on startup from the UTXO
  snapshot. At v1.0 activation this becomes a live-throughput
  question — if testnet shows the rebuild pass dominates
  startup time, a persistent variant lands in v1.1.
- Light-client proof APIs. `SparseMerkleTree::prove(key)` is
  already available but not exposed through RPC; that's
  v1.1 work.

---

## 3. Shape contracts (frozen)

### 3.1 SMT key derivation

```text
smt_key(tx_hash, output_index)
  = SHA3_256( b"MISAKA:SMT:key:v1" || tx_hash || output_index_le )
```

Frozen in `misaka-smt/src/key.rs`. `(tx_hash, output_index)` is
the canonical UTXO identifier; no other scheme produces the
same 32-byte key for the same UTXO.

### 3.2 SMT value

```text
smt_value(serialised_output)
  = SHA3_256( b"MISAKA:SMT:value:v1" || borsh(TxOutput) )
```

Borsh (not JSON) for determinism across implementations.
Failure-to-serialise **panics** because `TxOutput` is fixed-size;
a silent skip would desynchronise the SMT from the MuHash
accumulator.

### 3.3 Tree structure & root

Reference `SparseMerkleTree` (sparse-branch compressed; 256
bits of key depth; empty-subtree precomputed hashes for every
depth). Details in `misaka-smt/src/tree.rs` and
`misaka-smt/src/empty.rs`. The root is a pure function of the
set of non-empty leaves — deterministic across insertion
order, rebuild order, and implementation choice (all honest
nodes converge on the same root).

### 3.4 v4 state root

```text
state_root_v4(UtxoSet at height H)
  = SHA3_256(
        b"MISAKA:state_root:v4:" ||
        H.to_le_bytes() ||
        UtxoSet.smt.root()
    )
```

Implemented by `UtxoSet::compute_state_root_v4` (Step 3).
`height` is folded to preserve replay-against-wrong-tip
detection (same rationale as v3). The SMT root itself is
height-independent by construction; the height fold happens
only in the wrapping SHA3.

### 3.5 Domain separation

The v3 and v4 commitments are domain-separated at the SHA3
level (`"MISAKA:state_root:v3:"` vs `"MISAKA:state_root:v4:"`).
Tests pin that the two roots differ on both empty and
non-empty UTXO sets (`compute_state_root_v4_differs_from_v3`
+ `compute_state_root_v4_differs_from_v3_even_when_empty`).
No mid-migration node can accept one as the other.

---

## 4. Activation mechanism

**Decision: epoch boundary.** Activation is not a chain-param
`activation_height` nor a cfg feature flag; it's an epoch
label compared against a `V100_ACTIVATION_EPOCH` constant
defined in `misaka-types` at Step 7 land time.

Rationale:

- **Deterministic** — same constant on every honest node.
- **Integrates with Phase 3a.5 Step 4 epoch-boundary handler**
  — the existing snapshot / adjust / audit / swap pipeline is
  already the correct surface for "flip canonical state root
  from v3 to v4" during the same atomic step.
- **Recoverable** — a node that boots into an epoch after
  activation knows to verify v4 without runtime detection; a
  node that boots before activation knows to verify v3. No
  wire-probing.
- **Testnet-friendly** — `V100_ACTIVATION_EPOCH` is a
  compile-time constant, so testnet can ship with an aggressive
  value (e.g. `epoch = 10`) while mainnet ships with a
  negotiated value.

Non-decision: the precise `V100_ACTIVATION_EPOCH` value is
deferred to Step 7. It will be proposed in
`misaka-protocol-config` alongside v1.0 mainnet genesis.

---

## 5. Transition form

**Decision: gradual parallel → activation cutover (Decision 2C
from the plan prompt).**

Three sub-phases:

### 5.1 Pre-parallel (pre-v0.9.1 main)

- `state_root` = v3 MuHash.
- No SMT running. `Block.state_root_smt` does not exist.

### 5.2 Parallel (this branch, after Steps 1-5)

- `state_root` canonical = v3 MuHash.
- SMT runs alongside MuHash inside `UtxoSet`, kept in sync on
  every mutation.
- `UtxoSet::compute_state_root_v4()` is callable and covered
  by tests, but consensus does not compare against it.
- `Block.state_root_smt` is a struct field but **skipped on
  the wire** (both borsh and serde), so v0.9.x wire format is
  unchanged. v0.9.x validators can still process v1.0-branch
  blocks and vice versa (parallel phase co-existence).

### 5.3 Activation (Step 7 — NOT YET SHIPPED)

At the first commit that advances the epoch into
`epoch ≥ V100_ACTIVATION_EPOCH`:

- `Block` removes the `#[borsh(skip)]` + `#[serde(default,
  skip)]` attributes on `state_root_smt`. Wire format
  changes — pre-activation nodes can no longer communicate
  with activated nodes.
- `Block::digest_inner` gains `h.update(&self.state_root_smt)`
  after the existing `h.update(&self.state_root)`. Block
  identity now commits to both.
- Commit loop canonical check shifts:
  - Pre-activation: `exec_result.state_root ==
    block.state_root` where `state_root` is v3.
  - Post-activation: `exec_result.state_root_v4 ==
    block.state_root_smt` where `state_root_smt` is v4.
- The v3 `state_root` field remains in the struct for one
  more release cycle (v1.1 removes it). Post-activation
  validators don't consume it for consensus; they may log it
  for cross-check.

### 5.4 Post-v1.0 (v1.1 cleanup)

- Remove `state_root: [u8; 32]` field and v3 plumbing.
- Remove `MuHash` crate dependency from `misaka-storage`.
- Remove `misaka-muhash` crate from workspace.
- `misaka-crypto/src/hashes.rs:113` XOR stub removed
  (Step 8 of this plan; can land at v1.0 activation or
  earlier — it's not observable on the wire).

---

## 6. Determinism + safety contracts

### 6.1 Parallel-phase invariants

- **`state_root` (v3) unchanged**. `cargo test -p
  misaka-storage` covers this (`test_state_root_*` family,
  `test_snapshot_roundtrip_preserves_outputs_and_spending_keys`).
- **`state_root_v4` deterministic across validators, across
  replays, across insertion orders**. Covered by
  `smt_root_*` + `compute_state_root_v4_*` test families in
  `utxo_set::tests` (13 new tests across Steps 2+3), plus
  `all_21_validators_agree_on_state_root_v4` +
  `utxo_set_order_independent_state_root_v4` in
  `misaka-eutxo-audit/src/integration/multi_validator.rs`.
- **Mutation neutrality**:
  `smt_root_round_trips_after_add_then_remove` — an add
  followed by a remove of the same output restores the prior
  root bit-for-bit.
- **Snapshot restore reproduces the tree**: `smt_root_rebuilt_on_snapshot_restore`.
- **Wire compatibility**: `Block` borsh bytes unchanged from
  v0.9.x (skip attrs on `state_root_smt`).

### 6.2 Post-activation invariants (to pin in Step 7)

- Every honest node at epoch `E ≥ V100_ACTIVATION_EPOCH`
  accepts a block iff
  `block.state_root_smt == UtxoSet::compute_state_root_v4()`
  after applying the block's transactions.
- `Block::digest` changes meaning at activation (now
  includes `state_root_smt`). Blocks produced pre-activation
  have `state_root_smt == 0` and are either (a) re-digested
  under the new rule on replay, or (b) kept as-is with an
  activation-aware digester. Step 7 picks (b) — the
  digester has two arms, gated on `block.epoch` against
  `V100_ACTIVATION_EPOCH`.
- `CertificateV2` (Phase 3a.5 Step 5) is unaffected — it
  signs the commit digest, not the state root.

---

## 7. Rollback strategy

Rollback *to* a pre-activation chain tip after activation is
**not supported on mainnet** (this is a hard fork). On
testnet, a node can:

1. Stop and downgrade to v0.9.x.
2. Delete RocksDB under `$data_dir`.
3. Re-sync from genesis or a pre-activation snapshot.

The SMT itself is rebuilt from the UTXO snapshot on every
boot, so there is no SMT state on disk to clean up
separately.

No wire-level rollback (e.g. an "un-activation" epoch) is
defined. If v1.0 activation proves broken in production,
mainnet requires an emergency patch release that forks off a
pre-activation checkpoint; that's the same procedure any
hard-fork rollback needs.

---

## 8. Smoke / testnet plan (Decision 4)

Unified with v1.0 — v0.8.9 standalone smoke is retired.

1. **Pre-activation smoke (parallel phase)**: run a 4-node
   testnet on `feature/v100-smt-migration` for ≥72 h. Assert
   `UtxoSet::compute_state_root_v4()` agrees across all
   validators at every commit. No consensus rule change,
   so any divergence = SMT bug.
2. **Activation dry-run**: bump `V100_ACTIVATION_EPOCH` to
   a low value on a disposable testnet, let it fire, confirm
   the commit loop switches its canonical check without
   halting.
3. **7-day post-activation soak**: activation fires on the
   shared testnet; run ≥7 days with user txs + validator
   rotation. Metrics targets:
   - `misaka_consensus_epoch_adjustments_total` —
     monotonic.
   - No `Phase 3a.5 Step 4` audit CF gaps.
   - `state_root_v4` == executor computation on every
     commit (no mismatch logs).

Smoke pass = precondition for v1.0 mainnet ship.

---

## 9. Step ledger

| Step | Scope | Status | Commit |
|------|-------|--------|--------|
| 1 | `misaka-storage` depends on `misaka-smt` | ✅ shipped | 625543f |
| 2 | Parallel SMT inside `UtxoSet` | ✅ shipped | 70e54f3 |
| 3 | `compute_state_root_v4` additive | ✅ shipped | 29064cc |
| 4 | `Block.state_root_smt` field (wire-skipped) | ✅ shipped | 7365745 |
| 5 | `_v4` companions on executor / replay / audit | ✅ shipped | 8e4d275 |
| 6 | This doc | ✅ shipped | (this commit) |
| 7 | Activation: remove skip attrs + fold in digest + flip canonical + activate `v1-hardfork` feature | ⏳ pending | — |
| 8 | Remove MuHash XOR stub in `misaka-crypto/src/hashes.rs:113` | ⏳ pending | — |
| Smoke | 4-node testnet (pre) + activation dry-run + 7-day post soak | ⏳ pending | — |

---

## 10. Non-goals for v1.0

- Light-client SMT proof RPCs (`SparseMerkleTree::prove` exposure).
- SMT persistence (tree serialised to disk). The rebuild on
  boot is O(N) in UTXO count and measured to be sub-second at
  testnet scale; revisit at v1.1 if mainnet UTXO count
  invalidates that.
- `MuHash` crate deletion. Historical block replay
  (pre-activation) still needs it; v1.1 removes.
- Cross-chain replay protection changes. `ChainContext`
  remains the authority for cross-network replay.
