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

1. **Step 1 (lands in this branch)**: add the
   `startup_integrity` module alongside the legacy `recovery.rs`.
   No caller touches it yet. Tests cover fresh / roundtrip /
   corrupt / mismatch.
2. **Step 2**: wire `RocksBlockStore::apply_block_atomic` (or its
   Kaspa-aligned replacement) to also call `write_committed_state`,
   so that live v0.9.0 testnet DBs begin carrying the new keys.
3. **Step 3**: teach `recovery.rs` to prefer the new keys, falling
   back to the legacy `state` CF only when the new keys are absent.
   No behaviour change on healthy DBs.
4. **Step 4**: after one release of Step 2 live on testnet, remove
   the legacy fallback and delete `block_store.rs`, its re-export,
   and `recovery.rs`'s legacy call path.

Step 1 is pure additive; steps 2–4 each land in their own PR and
smoke-test window.

### 2.4 Out of scope for R1

- **Replacing UTXO-set persistence**. `RocksBlockStore::{apply_block_
  atomic, undo_block_at_height}` persist the UTXO CF entries.
  Their replacement is the Kaspa-aligned `UtxoSet` + `PruningStore`
  stack's own write path — unrelated to R1.
- **State-root rollup hashing choice**. R1 persists whatever
  state_root the caller passes in. Choosing between "binary merkle
  of all UTXOs via SHA-256" vs a ZK-friendly hash is Phase 3 work.

---

## 3. R6-b — PruneMode storage wiring (Option W — rewrite)

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
