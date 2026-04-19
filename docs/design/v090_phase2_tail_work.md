# v0.9.0 Phase 2 Path X — Tail-Work Design (R1 prereq + R6-b Option W)

Status: **DRAFT — R1 step 1 shipped in this branch; remainder planned**
Depends on: `docs/design/v090_phase2_cf_split.md` §11.1 + §11.6.2
Branch: `feature/v090-cf-split-pruning`

---

## 1. Context

Phase 2 Path X shipped R5 / R3 / R4 / R6-a in
`feature/v090-cf-split-pruning` (commits d2626e4, ff6f14a, 06ab424,
a99905e, 7f09d67). Two items — R1 (retire legacy `RocksBlockStore`)
and R6-b (`PruneMode` storage wiring) — hit architectural blockers
documented at §11.1 / §11.6.2 of the CF-split design doc.

This doc turns those blockers into a concrete prereq plan. It does
**not** propose merging the prereq work into Phase 2 Path X — that
would expand Path X's scope past "additive, no consensus changes".
The prereq work is a separate multi-commit follow-up PR whose
shape is fixed here so implementation can start without re-deriving
the design.

---

## 2. R1 — Retire legacy `RocksBlockStore`

### 2.1 Current surface

`crates/misaka-storage/src/recovery.rs` is 150 lines, 40 of which
are logic. Three call sites hit the legacy block store:

| recovery.rs line | call                                   | purpose                                     |
|------------------|----------------------------------------|---------------------------------------------|
| 75               | `RocksBlockStore::open(&db_path, false)` | open DB + replay WAL                        |
| 92               | `store.verify_integrity()`               | height/state_root consistency cross-check   |
| 94               | `store.get_state_root()`                 | fetch persisted state_root                  |

External caller: `crates/misaka-node/src/main.rs:1004`.

### 2.2 Kaspa-aligned replacement strategy

A new `misaka-storage::startup_integrity` module persists the
committed chain tip under `StorePrefixes::VirtualState = 0x70`:

```text
VirtualState || b"committed_height"     → u64 LE
VirtualState || b"committed_state_root" → [u8; 32]
VirtualState || b"committed_tip_hash"   → [u8; 32]    (reserved; tip digest)
```

APIs (all pure DB operations — no `RocksBlockStore` dependency):

```rust
pub struct CommittedState { pub height: u64, pub state_root: [u8; 32], pub tip_hash: [u8; 32] }

pub enum IntegrityStatus {
    Fresh,                                      // no committed state persisted yet
    Ok(CommittedState),                         // consistent persisted state
    Inconsistent { reason: String },            // corrupt or mismatched
}

pub fn write_committed_state(db: &DB, state: &CommittedState) -> Result<(), IntegrityError>;
pub fn read_committed_state(db: &DB) -> Result<Option<CommittedState>, IntegrityError>;
pub fn verify_integrity(
    db: &DB,
    expected_state_root: Option<[u8; 32]>,      // if Some, cross-check against caller-recomputed root
) -> IntegrityStatus;
```

The cross-check against `expected_state_root` replaces the legacy
`block_meta[tip].state_root` oracle. The caller (ultimately main.rs)
is responsible for recomputing the root from the UTXO set if it
wants that extra layer; in its absence `verify_integrity` only
reports the persisted values.

### 2.3 Migration steps (multi-commit)

1. **Step 1 (dcdf189)**: add the `startup_integrity` module
   alongside the legacy `recovery.rs`. No caller touches it yet.
2. **Step 2 (shipped this commit)**: call `write_committed_state`
   in the Narwhal commit loop (`main.rs` per-commit site, gated on
   `txs_accepted > 0`) and on graceful shutdown. Uses the existing
   `Arc<RocksDbConsensusStore>` handle via a new `raw_db()` accessor;
   the committed-tip keys live under `StorePrefixes::VirtualState` in
   the *same* RocksDB instance as Narwhal consensus data, not a
   separate sidecar DB.
3. **Step 3 (shipped this commit)**: add
   `recovery::run_startup_check_kaspa_aware(data_dir, narwhal_subdir)`.
   Preference order: (a) Kaspa-aligned keys in
   `<data_dir>/narwhal_consensus` → (b) legacy `chain.db` state CF
   via the existing `RocksBlockStore` path → (c) `Fresh`. Corruption
   in either surfaces via the same `abort_with_reason` exit path as
   the legacy function. `main.rs:1052` now calls the
   `_kaspa_aware` variant.
4. **Step 4 (shipped this commit)**: remove the legacy fallback.
   - `crates/misaka-storage/src/block_store.rs` deleted (~650 LoC).
   - `pub use block_store::RocksBlockStore` removed from `lib.rs`.
   - `recovery.rs` rewritten: `run_startup_check` now takes
     `(data_dir, narwhal_consensus_subdir)` and reads only the
     Kaspa-aligned committed-tip keys. No more `chain.db` /
     `RocksBlockStore` code path anywhere in the crate.
   - `StartupCheckResult` and `verify_startup_integrity` retained
     as the library-level outcome API but now wrap the Kaspa-aligned
     check only. Four fresh unit tests cover the new surface:
     nonexistent dir → Fresh, empty DB → Fresh, roundtrip → Ok,
     partial write → Inconsistent.
   - `main.rs:1060` updated to the new two-arg signature.

Steps 1–3 were pure additive; step 4 is destructive. User explicitly
approved the deletion on 2026-04-19. No prior live-data window
because no v0.9.0-dev build of this branch had been deployed yet —
current testnet runs v0.8.9, whose `chain.db` was never read by
production paths on the Narwhal pipeline, so the "legacy data
window" concern did not materialise.

#### 2.3.1 Write path — what actually happens today

Discovered during step 2 implementation: `UtxoSet::apply_block_atomic`
is **in-memory only** (a HashMap + Vec of deltas). Neither it nor
`execute_block` persists anything to RocksDB. The live production
persistence on the Narwhal path is:

- `main.rs:4471` — `tx_executor.utxo_set().save_to_file(...)`
  (fs-JSON) on every commit with `txs_accepted > 0`.
- `main.rs:4492` — same on graceful shutdown.

Legacy `RocksBlockStore::apply_block_atomic` exists but has no
production call site. Step 2 therefore does *not* hook into any
block-apply pipeline; it co-locates with the fs-JSON snapshot
writes. Same cadence, same trigger, same guarantees. A future PR
that introduces a true persistent UTXO write path should add a
third `write_committed_state` call there; until then this is the
only alive write site.

#### 2.3.2 Path alignment with R6-a

R6-a's `misaka-node --migrate-to` tool defaulted to
`<data_dir>/storage` in its original draft. That subdir does not
exist in any live layout. Fixed this commit to
`<data_dir>/narwhal_consensus`, matching `main.rs:1615` (the
`RocksDbConsensusStore::open` path) and the step-3 recovery subdir.

### 2.4 Out of scope for R1

- **Replacing UTXO-set persistence**. `RocksBlockStore::{apply_block_
  atomic, undo_block_at_height}` persist the UTXO CF entries.
  Their replacement is the Kaspa-aligned `UtxoSet` + `PruningStore`
  stack's own write path — unrelated to R1.
- **State-root rollup hashing choice**. R1 persists whatever
  state_root the caller passes in. Choosing between "binary merkle
  of all UTXOs via SHA-256" vs a ZK-friendly hash is Phase 3 work.

---

## 3. R6-b — PruneMode storage wiring (Option W — rewrite) — CORE SHIPPED; integration deferred

### 3.1 Why Option W over Option R

`PruningProcessor` at
`crates/misaka-consensus/src/pipeline/pruning_processor.rs:48-86` is
a direct translation of Kaspa's GhostDAG pruning algorithm. Its
three store dependencies (`DbGhostdagStore`, `DbHeadersStore`,
`DbPruningStore`) are **never instantiated in production** anywhere
in this workspace — all 500+ LoC of the pipeline exist only for
test harnesses. v6 removed GhostDAG consensus
(`crates/misaka-dag/src/lib.rs:14`); what remains is orphaned
scaffolding.

Option R ("revive": feed synthetic GhostdagData derived from
Narwhal commits) keeps ~1,800 lines of dead code alive and carries
a hidden-invariants burden — the synthetic data must satisfy
properties Kaspa originally guaranteed from real DAG reachability.

Option W ("rewrite": a new `NarwhalPruningProcessor` operating on
`CommitIndex`) aligns with v6's clean break. Simpler algorithm
(integer compare, no selected-parent walk), unit-testable on
synthetic `CommittedSubDag` streams, no hidden invariants.

### 3.2 Shape of Option W

New files:

- `crates/misaka-consensus/src/pipeline/narwhal_pruning_processor.rs`
  (~120 LoC)
- `crates/misaka-consensus/src/stores/commit_pruning.rs` (~40 LoC)

The store persists under a new `StorePrefixes::PruningPoint = 0x30`
bucket (already reserved):

```text
PruningPoint || b"committed_pruning_index" → CommitIndex (u64 LE)
PruningPoint || b"committed_pruning_timestamp" → u64 LE
```

Processor surface:

```rust
pub struct NarwhalPruningProcessor {
    config: NarwhalPruningConfig,
    commit_pruning_store: Arc<RwLock<DbCommitPruningStore>>,
}

pub struct NarwhalPruningConfig {
    pub pruning_depth_commits: u64,  // e.g. unbonding_epochs × commits_per_epoch
}

impl NarwhalPruningProcessor {
    pub fn on_committed_subdag(
        &self,
        subdag: &CommittedSubDag,  // from misaka_dag::narwhal_types::commit
    ) -> Result<PruningDecision, NarwhalPruningError>;
}

pub enum PruningDecision {
    NoChange,
    Advance { new_pruning_index: CommitIndex, timestamp: u64 },
}
```

No GhostDAG walk, no selected-parent lookup. The caller drives it
from the Narwhal `CommitConsumer` stream.

### 3.3 Integration point

Subscribe to `CommitConsumer` inside `start_narwhal_node` at
`crates/misaka-node/src/main.rs:1237` (around the existing
`spawn_consensus_runtime` site). `NarwhalPruningProcessor` is
constructed with:

- `commit_pruning_store`: built from the same `Arc<DB>` that
  `PruningStore` uses.
- `config.pruning_depth_commits`: derived from
  `NodeConfig::prune_mode` (R3 — currently lives unwired on
  `NodeConfig`). For `Pruned { keep_rounds }`,
  `pruning_depth_commits = keep_rounds`. For `Archival`, the
  processor is not spawned at all.

### 3.4 Pruning trigger

The processor does not itself delete data. It publishes a
`PruningDecision::Advance` event; actual deletion happens in:

- `misaka-dag::narwhal_dag::rocksdb_store::gc_below_round` (already
  exists; currently called without a round argument by test
  harnesses).
- `misaka-storage::PruningStore` (already exists; `set_pruning_point`
  wires in the new pruning-point info).

R6-b therefore **adds the trigger**; the actual GC sites are
pre-existing and tested.

### 3.4.1 Core shipped 2026-04-19

Files added:

- `crates/misaka-consensus/src/stores/commit_pruning.rs`
  (`DbCommitPruningStore`, `CommitPruningInfo`, `CommitPruningError`).
  Writes under `misaka_storage::StorePrefixes::PruningPoint = 0x30`
  with sub-bucket keys `committed_pruning_index` and
  `committed_pruning_timestamp`. 7 unit tests cover fresh / roundtrip
  / overwrite / partial write / wrong-length corruption / prefix
  placement.
- `crates/misaka-consensus/src/pipeline/narwhal_pruning_processor.rs`
  (`NarwhalPruningProcessor`, `NarwhalCommitMeta`,
  `NarwhalPruningConfig`, `PruningDecision`, `NarwhalPruningError`).
  `on_committed_subdag(meta) -> Result<PruningDecision, _>`
  implements the monotonic integer-compare decision with
  no-regress guard, zero-depth guard, and early-chain
  saturating-sub handling. 11 unit tests cover all branches.
- `crates/misaka-consensus/src/stores/mod.rs` +
  `crates/misaka-consensus/src/pipeline/mod.rs` register the new
  modules.

`NarwhalCommitMeta` is a 16-byte adapter struct (index + timestamp_ms)
so `misaka-consensus` stays off the `misaka-dag` dep graph. The
caller extracts these two fields from `CommittedSubDag` at the
integration site.

Deferred to a follow-up commit: the main.rs integration (subscribe
to `CommitConsumer`, construct the processor when
`NodeConfig::prune_mode == Pruned{keep_rounds}`, spawn the tick
loop, feed `NarwhalCommitMeta` in). Splitting keeps the
store/processor landing reviewable in isolation and lets the
integration PR carry its own smoke plan.

### 3.5 Dead-code cleanup (optional follow-up)

After Option W ships, the legacy `PruningProcessor` +
`DbGhostdagStore` + `DbHeadersStore` + `DbPruningStore` + their
tests can be deleted in a separate PR. That's destructive and needs
explicit user approval; not a prereq for Option W itself.

### 3.6 Out of scope for R6-b

- **Reviving GhostDAG consensus**. Rejected — v6 removed it.
- **Pruning-point proofs**. Kaspa has a concept of pruning proof
  that lets light clients sync from the pruning point. Not relevant
  here; our light-client story is Phase 3+.
- **Checkpoint-based trigger**. R4's `CheckpointTrigger` could feed
  the pruning processor (checkpoint-aligned pruning) but that's a
  §11.4.1 follow-up, not R6-b core.

---

## 4. R1 step 1 — what lands in this branch

Only §2.3 step 1: the `startup_integrity` module. Standalone,
additive, zero callers. Unblocks the rest of R1 but commits no
migration.

Files touched:

- `crates/misaka-storage/src/startup_integrity.rs` (new, ~220 LoC
  including tests)
- `crates/misaka-storage/src/lib.rs` (mod declaration + re-exports)

Test coverage:

- Fresh DB → `IntegrityStatus::Fresh`.
- Write + read roundtrip → `IntegrityStatus::Ok` with matching
  fields.
- Partial write (e.g. height present, state_root absent) →
  `IntegrityStatus::Inconsistent`.
- Corrupt value (wrong byte length) → `IntegrityStatus::Inconsistent`
  with a concrete reason.
- `expected_state_root` cross-check: match → `Ok`; mismatch →
  `Inconsistent`.

No dependency on `RocksBlockStore`. No touch to `recovery.rs` or
`main.rs`.

---

## 5. Verification plan (when full R1 + R6-b land)

### R1

- `cargo test -p misaka-storage`: all suites pass.
- E2E: start a testnet node on a v0.8.x DB → node boots; `data/`
  gains new `VirtualState || committed_*` keys; legacy `state` CF
  remains untouched.
- E2E: kill -9 node mid-block, restart → `verify_integrity` passes.
- E2E: hand-corrupt `VirtualState || committed_state_root` → node
  refuses to start with the new error message.

### R6-b

- `cargo test -p misaka-consensus`: new `narwhal_pruning_processor`
  unit tests pass (synthetic `CommittedSubDag` streams).
- 4-node testnet smoke, 24 h: 2 nodes `prune_mode = "archival"`,
  2 nodes `prune_mode = "pruned"`. Pruned DB growth < archival DB
  growth by at least 2× after 24 h.
- Pruned node can still sync a fresh peer (checkpoint-based; R4
  trigger active).

---

## 6. Ordering

1. **This commit** (R1 step 1): `startup_integrity` additive module
   + this design doc.
2. Separate PR: R1 steps 2–4 (wire the module into the write path,
   then into recovery.rs, then delete legacy).
3. Separate PR: R6-b Option W implementation + 24 h smoke.
4. Separate PR: dead-code cleanup (legacy `PruningProcessor` + its
   stores). Destructive — user approval required.

Nothing in steps 2–4 affects PR #11 (Phase 2 foundation) or the
already-shipped Path X R5/R3/R4/R6-a.
