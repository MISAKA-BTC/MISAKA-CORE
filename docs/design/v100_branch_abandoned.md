# `feature/v100-smt-migration` — abandoned / superseded

Status: **ABANDONED. Work shipped via PR #12 + #14 to main.**
Date: 2026-04-19
Origin: 625543f..9f23efb (8 commits)

## What this branch was

An 8-step incremental SMT migration plan that ran MuHash and SMT in
parallel at a v4 state-root domain tag, with deferred consensus
cutover (`#[borsh(skip)]` on `Block.state_root_smt` + feature flag
activation at a future epoch boundary).

- Step 1 `625543f` — `misaka-storage` depends on `misaka-smt`
- Step 2 `70e54f3` — parallel SMT in `UtxoSet` (8 tests)
- Step 3 `29064cc` — `compute_state_root_v4` (additive, 5 tests)
- Step 4 `7365745` — `Block.state_root_smt` field, `#[borsh(skip)]`
- Step 5 `8e4d275` — executor / replay / audit `_v4` companions
- Step 6 `e1f11f2` — `docs/design/v100_smt_migration.md` (341 lines)
- Step 7 `25d6d2f` — activate `v1-hardfork` feature
- Step 8 `9f23efb` — remove `misaka-crypto` XOR `MuHash` stub

## Why it was abandoned

During the v0.9.0 mainline merge (2026-04-19), we discovered that PR
#12 (`feature/v089-storage-and-interval`, merged as `a0d76a7`)
already shipped the **full SMT migration** under its "PR E" sub-work:

- `UtxoSet` has a live `SparseMerkleTree` **authoritative** field,
  not parallel / additive.
- `compute_state_root()` folds the SMT root under **`MISAKA:state_root:v5:`**
  (not v4).
- The legacy `muhash` field is kept only as a no-op shim for the
  transitional migration window and is not read by the canonical
  state root path.
- The `misaka-muhash` crate (MuHash3072) was the PR B stepping stone
  (domain v4) that PR #12's PR E superseded in the same merge.

So post-merge `origin/main` (commit `2322189`) already has:
- SMT as the canonical UTXO state commitment.
- v5 domain tag (not v4).
- No `#[borsh(skip)]` on the state root — SMT is the on-wire root.
- No activation epoch gate — cutover is the PR #12 merge itself.

My `feature/v100-smt-migration` branch was doing the same work from
first principles on top of the pre-v0.9.0 `origin/main`, unaware of
PR #12's scope. Keeping both would be duplicative; PR #12's version
is in main and is the canonical v1.0 SMT commitment.

## What carried over

**Nothing material** from the v100 branch is needed:
- The `misaka-smt` crate (which both branches depend on) was
  spec-frozen at v0.7.x and unchanged.
- PR #12's `UtxoSet` integration uses the same `smt_key` / `smt_value`
  / `SparseMerkleTree` APIs.
- The `docs/design/v100_smt_migration.md` design document is
  philosophically superseded by the actual PR #12 PR E implementation;
  it remains as historical record of the parallel-phase thinking.

## Action

- **Branch kept on origin** for historical reference; do not merge.
- **No PR opened** for this branch.
- Commit SHA of the head (`9f23efb`) retained so it can be recovered
  if needed.

Delete the branch at operator discretion after the v0.9.0 main-based
testnet smoke proves the PR #12 PR E implementation out:

```bash
git push origin --delete feature/v100-smt-migration
```

## Cross-references

- v0.9.0 main merge: `a0d76a7` (PR #12), `e193831` (PR #11),
  `4e9408f` (PR #13), `2322189` (PR #14).
- Canonical state root path: `crates/misaka-storage/src/utxo_set.rs`
  `compute_state_root` — domain `"MISAKA:state_root:v5:"`.
- Legacy docstring on the v1.0 migration contract:
  `docs/design/v100_smt_migration.md` (kept for reference only; v4
  pathway described there is NOT live).
