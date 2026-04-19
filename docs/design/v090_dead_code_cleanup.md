# v0.9.0 Dead-Code Cleanup — Audit & Plan

Status: **AUDIT ONLY — no deletions in this commit**
Context: Phase 2 Path X R6-b (commits 5b17319 + 0f58d84) landed the
Narwhal-native pruning pipeline, making parts of the Kaspa-era
scaffolding dead. This doc turns that observation into a concrete,
reviewable deletion manifest.

Scope is **two disjoint targets**:

* **Plan A** — Legacy pruning pipeline (~150 LoC, narrow, safe).
* **Plan B** — `ghostdag-compat` feature and everything it gates
  (~2,276 LoC, large, touches `main.rs`).

They are independent: either may land before the other. Both are
destructive and require explicit user approval in the session that
actually deletes code.

---

## 1. Context

After:

- Phase 2 Path X R1 step 4 (commit `1ea337e`) retired
  `RocksBlockStore`.
- R6-b Option W (commits `5b17319` + `0f58d84`) added
  `NarwhalPruningProcessor` + `DbCommitPruningStore` and wired them
  into `start_narwhal_node`, replacing the Kaspa-era GhostDAG-bound
  `PruningProcessor`.

…two legacy areas are dead under the default build:

1. The GhostDAG pruning pipeline (`pipeline/pruning_processor.rs`
   and its bespoke `stores/pruning.rs`) — superseded by the Narwhal
   equivalents.
2. The `ghostdag-compat` Cargo feature — gates `start_dag_node` and
   all the `misaka_dag::dag_*` module references that no longer
   exist in `misaka-dag`'s public API. `cargo check -p misaka-node
   --features ghostdag-compat` produces 15+ unresolved imports.

---

## 2. Plan A — Legacy pruning pipeline

### 2.1 Scope

Two files deleted; two `mod.rs` edits; one test removed.

| File / Edit | LoC change | Rationale |
|---|---|---|
| Delete `crates/misaka-consensus/src/pipeline/pruning_processor.rs` | −101 | `PruningProcessorConfig`, `PruningError`, `PruningProcessor`. No production call sites; `NarwhalPruningProcessor` (R6-b) is the live replacement. |
| Delete `crates/misaka-consensus/src/stores/pruning.rs` | −38  | `PruningPointInfo`, `DbPruningStore`. Only consumer is the file above plus one test. |
| Delete `pub mod pruning_processor;` from `crates/misaka-consensus/src/pipeline/mod.rs:17` | −1 | |
| Delete `pub mod pruning;` from `crates/misaka-consensus/src/stores/mod.rs:10` | −1 | |
| Delete `test_pruning_store` from `crates/misaka-consensus/tests/store_tests.rs:314-328` | −15 | Only reference to `DbPruningStore` outside the file being deleted. |

Total: **~156 LoC**.

### 2.2 What STAYS (explicitly kept)

- `stores/ghostdag.rs` (189 LoC): live — used by
  `header_processor.rs` + `virtual_processor.rs` + e2e tests. Its
  `BlueWorkType`, `Hash`, `KType`, `ZERO_HASH` re-exports at
  `stores/mod.rs:19` are part of the public API.
- `stores/headers.rs` (142 LoC): live — used by the same consumers.
- `pipeline/header_processor.rs` (290 LoC): live. File header
  carries a "Phase 33: #![allow(dead_code)] REMOVED — verification
  modules must never be silently dead" comment; tested in
  `e2e_pipeline.rs` and `pipeline_test.rs`.
- `pipeline/virtual_processor.rs` (172 LoC): live — used in
  `e2e_pipeline.rs:101`.

### 2.3 Verification steps (for the deletion commit)

1. `cargo test -p misaka-consensus --lib`: must still pass with the
   legacy pruning tests removed (count drops by ~1).
2. `cargo test -p misaka-consensus --test store_tests`: must still
   pass; pruning-store test removed, other store tests unchanged.
3. `cargo test -p misaka-consensus --test e2e_pipeline`: must still
   pass — confirms `ghostdag` / `headers` / `header_processor` /
   `virtual_processor` are genuinely live.
4. `cargo check --workspace --lib --bins`: clean.

### 2.4 Risk

**Low.** No production call site. The `NarwhalPruningProcessor`
replacement is already wired and passing tests
(`pipeline/narwhal_pruning_processor.rs` 11 unit tests, store 7
unit tests). Rollback is a pure `git revert` of the deletion commit.

---

## 3. Plan B — `ghostdag-compat` feature

### 3.1 Scope

`ghostdag-compat` is declared only in
`crates/misaka-node/Cargo.toml:16` (`ghostdag-compat = ["dag"]`).
`experimental_dag = ["dag"]` at line 18 does **not** transitively
enable it — the alias comment is misleading; the actual Cargo
expansion is just `["dag"]`. No other crate references the feature.

Removing the feature entails deleting every `#[cfg(...)]` block
gated on it in `misaka-node/src/main.rs`.

### 3.2 Inventory in `main.rs`

Per audit, 55 `#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]`
blocks, grouped:

- **Module declarations (lines 110–131)**: 8 `pub mod ...;` that
  declare modules (`dag_narwhal_dissemination_service`,
  `dag_p2p_network`, `dag_p2p_surface`, `dag_p2p_transport`,
  `dag_rpc`, `dag_rpc_service`, `dag_tx_dissemination_service`,
  `jsonrpc`). These module files themselves are **live** in the
  source tree — removing the cfg gate makes them default-compiled
  IF their contents still compile, or removing the `mod` line along
  with the files if the module contents depend on the same dead
  `misaka_dag::dag_*` names. Needs per-file inspection — see §3.4.
- **Match-arm dispatch (main.rs:1115–1117)**: the `start_dag_node`
  branch in the node-startup match. Default path already uses
  `start_narwhal_node`; removing this arm + the `else` collapse is
  mechanical.
- **`start_dag_node` function body (main.rs:5703–7128, ~1,426
  lines)**: the entire function is gated. Its body references
  `misaka_dag::dag_block_producer::run_dag_block_producer_dual`,
  `misaka_dag::dag_finality::FinalityManager`,
  `misaka_dag::dag_store::ThreadSafeDagStore`,
  `load_runtime_snapshot`, `save_runtime_snapshot`, `DagMempool`,
  `DagNodeState`, `DagStateManager`, `DagStore`, `GhostDagEngine`,
  `ZERO_HASH` — none of which exist in `misaka-dag`'s current
  public API (per `lib.rs`). Deleting the whole function is
  straightforward.
- **Tests (main.rs:~7613–8219, 7 helpers + 17 `#[test]` functions,
  ~450 lines)**: dead tests whose setup needs the same missing
  types. Delete with the function.
- **Secondary cfg blocks inside `start_narwhal_node`**
  (spot-check needed — the audit's "55 blocks" count includes
  some small conditionals inside live functions). Any cfg block
  referring only to `feature = "ghostdag-compat"` that lives
  inside a non-gated function must be inspected: if its body is
  dead without the feature, delete; if it's a feature-flagged
  alternative behaviour, evaluate separately.

### 3.3 Dead submodules in `crates/misaka-node/src/`

The 8 module declarations at lines 110–131 point at files that,
per the audit, import `misaka_dag::dag_*` types that do not exist.
Those files are themselves dead. Full deletion means:

- `crates/misaka-node/src/dag_narwhal_dissemination_service.rs`
- `crates/misaka-node/src/dag_p2p_network.rs`
- `crates/misaka-node/src/dag_p2p_surface.rs`
- `crates/misaka-node/src/dag_p2p_transport.rs`
- `crates/misaka-node/src/dag_rpc.rs`
- `crates/misaka-node/src/dag_rpc_service.rs`
- `crates/misaka-node/src/dag_tx_dissemination_service.rs`
- `crates/misaka-node/src/jsonrpc.rs` (needs inspection — `jsonrpc`
  *might* be used elsewhere despite the gate)

Plus any file-level `pub mod dag_rpc_legacy;` etc. surfaced by
`ls crates/misaka-node/src/dag_*.rs`.

LoC estimate for submodules combined: **several thousand lines**
on top of the ~2,276 in `main.rs`. The audit number (~2,276) is
the main.rs-only delta; the full feature-removal delta is larger.

### 3.4 Pre-deletion per-file verification

Before deleting each `crates/misaka-node/src/dag_*.rs` submodule:

1. Grep for its name outside `main.rs` and outside itself. Any
   reference (e.g. another module `use`ing it) reclassifies the
   file from "dead" to "needs follow-up".
2. Check for `#[cfg(feature = ...)]` attributes *inside* the file.
   Files that are themselves gated (`#![cfg(feature = "...")]` at
   the top) are confirmed dead under default build; files without
   the attribute but with dead contents are also dead but the
   gating boundary is one level up.
3. Test the `#[cfg(...)]` gates in main.rs by
   `cargo check -p misaka-node` (default features) — passes today,
   so any file only referenced from a gated block is proven dead.

### 3.5 Proposed commit sequence for Plan B

To keep the PR reviewable, split Plan B into logically grouped
sub-commits:

1. **B.1** — remove `start_dag_node` function body + the dispatch
   match arm + the relevant `use misaka_dag::...` statements at
   main.rs:5703–7128. ~1,500 LoC deletion. Verify node still boots
   (since the default path is `start_narwhal_node`, unchanged).
2. **B.2** — remove the 8 `pub mod dag_*;` lines in main.rs
   (lines 110–131) and delete the 8 (or however many) submodule
   files. ~1,500–3,000 LoC deletion depending on file sizes. Verify
   `cargo check --workspace --lib --bins` clean.
3. **B.3** — remove the 7 helpers + 17 `#[test]` functions gated
   by `ghostdag-compat`. ~450 LoC deletion. Verify test suites
   still run.
4. **B.4** — remove the `ghostdag-compat` feature declaration
   from `misaka-node/Cargo.toml` (line 16) and update any doc
   comments that referenced it. ~5 LoC.
5. **B.5** — finally inspect any small scattered `#[cfg(feature =
   "ghostdag-compat")]` blocks that remain inside live functions
   and decide case-by-case: delete the block if its body is dead,
   keep with a TODO if it represents a feature-flagged alternative
   we still want.

Each sub-commit is individually `cargo check`-clean. The PR body
lists the 5 sub-commits and references this doc §3.

### 3.6 Risk

**Medium**. The deletion is purely dead code by the audit, but:

- Large diff makes the PR harder to review.
- `main.rs` dispatch match has historically been a landmine — the
  `start_narwhal_node` branch already runs production, but any
  off-path branch (e.g. an observer / light-client profile that
  today falls through to `start_dag_node`) would silently lose
  coverage. Verified today that the default path is
  `start_narwhal_node`; the audit should re-confirm at deletion
  time.
- Documentation files outside `docs/design/` (`docs/architecture.md`,
  `docs/audit/R7_STORAGE_STATUS.md`, `docs/audit/PHASE1_*.md`)
  reference the GhostDAG node path. Those become historical
  context; a docs-pass follow-up is recommended.

Rollback is `git revert` on each sub-commit.

---

## 4. Ordering recommendation

1. **Plan A first** (one session, ~150 LoC) — low risk, quick
   win, shrinks the dead-code footprint right now.
2. **Plan B separately** (one session per sub-commit, or one
   session for the whole B series if scope allows).

Not atomic. The two plans do not share files except `main.rs`
(Plan B only). No merge-conflict risk.

---

## 5. Non-scope

- **`architecture.md` / `audit/R7_STORAGE_STATUS.md` updates**:
  references to `RocksBlockStore` + GhostDAG node path stay as
  *historical* context. Separate docs pass after Plan A + Plan B.
- **Narwhal-side module cleanup** beyond what's above: not
  needed — Narwhal pipeline is live.
- **`experimental_dag` feature alias**: leave alone. It expands
  to `["dag"]` which is the default; removing it does not help
  cleanup and may break external build scripts that reference
  the name.
- **Re-introducing a ghostdag node**: explicitly out of scope —
  v6 removed GhostDAG consensus intentionally.

---

## 6. Verification checklist (for whichever session lands the
   deletion commits)

### Plan A

- [ ] `cargo test -p misaka-consensus --lib` passes.
- [ ] `cargo test -p misaka-consensus --test store_tests` passes.
- [ ] `cargo test -p misaka-consensus --test e2e_pipeline` passes.
- [ ] `cargo check --workspace --lib --bins` clean.
- [ ] `git grep 'DbPruningStore\|PruningProcessor\b'` in the
  working tree returns zero hits outside
  `pipeline/narwhal_pruning_processor.rs` doc comments.

### Plan B

- [ ] `cargo check -p misaka-node` (default features) clean.
- [ ] `cargo check --workspace --lib --bins` clean.
- [ ] No `#[cfg(feature = "ghostdag-compat")]` remains anywhere
  in the workspace.
- [ ] No `ghostdag-compat` string remains in any `Cargo.toml`.
- [ ] `cargo test -p misaka-node --bin misaka-node` passes.
- [ ] Node boots on testnet against a v0.9.0 config.
