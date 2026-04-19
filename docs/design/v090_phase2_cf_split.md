# v0.9.0 Phase 2 — CF Split, Pruning, Archival & Checkpoint (Design)

Status: **DRAFT — premise invalidated by code exploration; see §11**
Branch: `feature/v090-cf-split-pruning` (off of `feature/v090-cf-enum-foundation`, PR #11)
Prereq: PR #11 merged (Phase 2 foundation); v0.8.9 24h smoke verdict received.

---

## 1. Context

Phase 2 foundation (PR #11) introduced typed `StorageCf` (5 variants) and
`NarwhalCf` (8 variants) enums as a no-op refactor — 13 RocksDB column families
total, identical on-disk layout to v0.8.8.

Phase 2 本体 is intended to add three orthogonal capabilities on top:

1. **Storage mode** — allow operators to run nodes in `Archival` (keep all
   history) or `Pruned { keep_rounds }` (drop stale state beyond a boundary).
2. **Checkpoint** — an on-chain-verifiable snapshot (epoch boundary + every
   10 000 rounds) that a freshly-synced pruned node can trust.
3. **Schema evolution** — a forward-only migration from the v0.8.8 on-disk
   format to the v0.9.0 format, so existing testnet DBs can be upgraded
   without resync.

The memo `project_phase2_prompt.md` additionally prescribes **collapsing the
13 CFs into 7 unified CFs** (`Headers, Certificates, VotesIndex, Payload,
Metadata, Checkpoints, Equivocation`). This document proposes a mapping and
flags the tradeoffs that this collapse entails — see §5.

This is a multi-PR effort. The present document covers design only; code
lands in incremental PRs per §9.

---

## 2. Current 13-CF inventory (v0.8.8 / PR #11)

### 2.1 `misaka-storage` (5 CFs, `block_store.rs`)

| CF             | Key                                  | Value                          | Cardinality / block | Prunable                                  |
|----------------|--------------------------------------|--------------------------------|---------------------|-------------------------------------------|
| `utxos`        | `tx_hash(32) \|\| idx(4 LE)`         | `StoredUtxo` (JSON)            | O(utxo_outputs)     | NO — required for ring resolution         |
| `spent_tags`   | `tag(32)`                            | `height(8 LE)`                 | O(inputs)           | PARTIAL — after finality depth            |
| `spending_keys`| `tx_hash(32) \|\| idx(4 LE)`         | ring poly bytes                | O(utxo_outputs)     | NO — required for signature verification  |
| `block_meta`   | `height(8 LE)`                       | `BlockMeta` (JSON)             | O(1)                | PARTIAL — after SPC depth (~1000 blocks)  |
| `state`        | singleton `"height"`, `"state_root"` | u64 LE / `[u8; 32]`            | O(1)                | NO — singleton chain tip                  |

### 2.2 `misaka-dag::narwhal_dag` (8 CFs, `rocksdb_store.rs`)

| CF                               | Key                                      | Value                          | Cardinality            | Prunable                                   |
|----------------------------------|------------------------------------------|--------------------------------|------------------------|--------------------------------------------|
| `narwhal_blocks`                 | `BlockDigest(32)`                        | `Block` (JSON)                 | ~authorities/round     | YES — `gc_below_round`                     |
| `narwhal_commits`                | `CommitIndex(u64 LE)`                    | `CommittedSubDag` (JSON)       | ~1/commit              | YES — sorted for replay, GC after finality |
| `narwhal_meta`                   | singletons (`gc_round`, `last_committed_rounds`, `tx_filter_snapshot`) | raw / JSON | O(1) per update         | PARTIAL                                    |
| `narwhal_last_committed`         | singleton `"last_committed_rounds"`      | JSON `Vec<Round>`              | O(1)/commit            | NO — hot cache duplicating `meta`          |
| `narwhal_equivocation_evidence`  | `round_be(4) \|\| author_be(4)`          | evidence blob                  | 0..1 / (round, author) | **NEVER** — slashing + post-mortem         |
| `narwhal_committed_tx_filter`    | singleton `"tx_filter_snapshot"`         | filter bitmap                  | 1 / snapshot           | YES — replaceable                          |
| `narwhal_tx_index`               | `tx_hash(32)`                            | tx detail (JSON)               | O(txs)/commit          | YES — rebuildable                          |
| `narwhal_addr_index`             | `addr_prefix(64) \|\| height \|\| tx_hash` | entry bytes                   | O(M)/address           | YES — rebuildable                          |

### 2.3 Observations

- **Atomic-batch boundary**: every per-block mutation hits 5 storage CFs in
  one `WriteBatch`; every per-commit mutation hits 3-4 narwhal CFs in one
  `DagWriteBatch`. Crossing this boundary would regress crash-consistency.
- **Prefix extractors**: `narwhal_addr_index` uses a fixed-64 prefix
  extractor; merging it with other CFs requires preserving that extractor
  for its keyspace.
- **Hot-cache duplication**: `narwhal_last_committed` is a read-amp
  optimisation over `narwhal_meta` — merging them back would undo a past
  optimisation.

---

## 3. Phase 2 target CFs (per `project_phase2_prompt.md`)

```
Headers, Certificates, VotesIndex, Payload, Metadata, Checkpoints, Equivocation
```

The memo does **not** specify which old CF maps into which new CF. §4 proposes
a mapping; §5 flags concerns; §6 sketches an alternative.

---

## 4. Proposed 13 → 7 mapping (Option A — full collapse)

All old keys are preserved verbatim; each new CF internally prefixes keys with
a 1-byte namespace tag to keep historical keyspaces disjoint.

| New CF          | Old CFs folded in                        | Intra-CF prefix layout                                                                                            |
|-----------------|------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `Headers`       | `narwhal_blocks`                         | `0x01 \|\| digest(32)`                                                                                            |
| `Certificates`  | `narwhal_commits`                        | `0x01 \|\| commit_idx(8 LE)`                                                                                      |
| `VotesIndex`    | `narwhal_last_committed`, `narwhal_tx_index`, `narwhal_addr_index` | `0x01` per-authority round / `0x02` tx_hash / `0x03` addr_prefix (retains fixed-64 extractor for `0x03`)          |
| `Payload`       | `utxos`, `spending_keys`, `spent_tags`   | `0x01 \|\| tx_hash \|\| idx` (utxo) / `0x02 \|\| tx_hash \|\| idx` (spending key) / `0x03 \|\| tag(32)` (spent tag) |
| `Metadata`      | `state`, `block_meta`, `narwhal_meta`, `narwhal_committed_tx_filter` | `0x01` state singletons / `0x02 \|\| height` block_meta / `0x03` narwhal singletons / `0x04` tx_filter       |
| `Checkpoints`   | (new)                                    | `0x01 \|\| checkpoint_number(8 LE)` → `Checkpoint`                                                                |
| `Equivocation`  | `narwhal_equivocation_evidence`          | `0x01 \|\| round_be(4) \|\| author_be(4)`                                                                         |

**Rationale:**
- `Headers`/`Certificates` keep the Narwhal DAG hot path intact.
- `VotesIndex` groups the three rebuild-able lookup indexes — all three are
  prunable together in pruned mode.
- `Payload` groups the three "per-UTXO-coordinate" keyspaces.
- `Metadata` absorbs every singleton-shaped CF.
- `Equivocation` is isolated (never-prune invariant is easiest to enforce
  when it has no neighbours).

**Schema version marker**: `Metadata[0x00, "schema_version"]` → `u32 LE`.
`v0.8.8 = 1`, `v0.9.0 = 2`. Runtime refuses to open a DB whose
`schema_version != 2` and points the operator at `misaka-node migrate`.

---

## 5. Tradeoffs & concerns with Option A

1. **Per-CF tuning loss.** Today each CF can set its own block size,
   compression, bloom filter, and prefix extractor. Merging
   `narwhal_addr_index` (wants fixed-64 prefix extractor, large blocks) into
   `VotesIndex` alongside `narwhal_tx_index` (wants default extractor, small
   blocks) forces a single compromise configuration.

2. **Compaction coupling.** A hot-written keyspace (e.g. `utxos` inside
   `Payload`) and a rarely-touched one (e.g. `spent_tags` inside the same
   `Payload`) now share a single LSM tree. Compaction pressure from the hot
   keyspace affects iteration cost on the cold one.

3. **Prefix-scan ergonomics.** `VotesIndex` carries three different scan
   patterns. Range scans that used to be "iterate whole CF" now must be
   "iterate within prefix `0x??`" — every caller changes.

4. **Undoing a past optimisation.** `narwhal_last_committed` was split out
   from `narwhal_meta` specifically to avoid scanning the meta CF on every
   commit. Folding them into `VotesIndex` and `Metadata` respectively does
   not restore that split; we keep the split via namespace prefix, which
   means the "collapse" is cosmetic and the refactor cost is not repaid by
   any operational win.

5. **Migration tool complexity.** Every key in every old CF must be rewritten
   with a new 1-byte prefix into a new CF. The tool is linear in DB size and
   must be atomic or resumable — no partial-migration state should be
   observable.

6. **Rollback impossibility.** Going back from v0.9.0 → v0.8.8 requires
   reconstructing 13 CFs from 7; memory explicitly marks this **unsupported**
   (operator must preserve a pre-migration snapshot).

---

## 6. Alternative (Option B — keep 13 CFs, add Phase 2 capabilities only)

Skip the collapse; implement only the three Phase-2 capabilities.

| Capability         | Minimum change                                                                           |
|--------------------|------------------------------------------------------------------------------------------|
| `PruneMode`        | Add `Prunable` trait; implement for per-CF GC routines that already exist (blocks, commits) and extend to `block_meta`, `spent_tags` after finality. |
| `Checkpoint`       | Add a new CF `checkpoints` (14th) with `CheckpointStore` trait + state_root roll-up.     |
| Schema version     | Add a singleton key in `narwhal_meta`: `"schema_version"` = `2`. Runtime refuses `!= 2`. |
| Migration          | Minimal — just write `schema_version = 2` on first open of an unmarked DB (idempotent).  |

**Pros:** keeps per-CF tuning; ~100× less code; migration is trivial;
per-block atomic batch shapes unchanged.

**Cons:** diverges from the `project_phase2_prompt.md` spec ("7 unified
CFs"). The memo's rationale for 7 is not recorded anywhere I can find.

---

## 7. Decisions required from user

1. **Mapping (§4 vs §6)**: proceed with Option A (full 13→7 collapse) or
   Option B (keep 13, add capabilities only)?
2. If Option A: confirm the specific mapping in §4 or adjust (e.g. split
   `spent_tags` out of `Payload` into a separate `DoubleSpendGuard` CF).
3. **Schema-version enforcement**: refuse-to-open on mismatch (default) or
   opt-in via flag?
4. **Migration UX**: `misaka-node migrate --from 1 --to 2 [--dry-run]` as a
   subcommand on the main binary, or a separate `misaka-migrate` binary?
5. **State root**: commit to "binary merkle of all UTXOs via sha256" as the
   minimum impl, or defer state_root to Phase 3 and checkpoint only the
   height + validator set + total_supply?

---

## 8. Out of scope for this document

- Signature externalisation (Phase 3a).
- Adaptive rate limiting (Phase 3a).
- Cert V2 ZK-forward compatibility (Phase 3a).
- Group 2 staking work (unrelated branch).

---

## 9. Work breakdown (deferred until §7 decided)

Sketched only — precise shape depends on Option A vs B.

1. `schema_version` module + runtime refusal.
2. New `Cf` enum (Option A) or extended `StorageCf`/`NarwhalCf` (Option B).
3. Migration tool (Option A: non-trivial; Option B: trivial).
4. `PruneMode` + `Prunable` trait + per-CF impls.
5. `Checkpoint` struct + `CheckpointStore` trait + state_root roll-up.
6. `NodeRuntimeConfig` extension (storage_mode, checkpoint_interval,
   unbonding_epochs, safety_margin).
7. Prometheus metrics (per-CF bytes, prune boundary, checkpoint latency).
8. Unit + integration + bench tests.
9. 4-node 24h smoke (2 archival + 2 pruned).
10. `docs/ops/storage.md`.

---

## 10. Premise invalidated — Kaspa-aligned infra already exists

Discovered during coding phase (2026-04-19): `misaka-storage/src/lib.rs` re-exports a
fully-built "Kaspa-Aligned Storage Infrastructure" section containing:

- `StorePrefixes` enum with 40+ byte-prefix variants: `Headers = 0x01`,
  `BlockBodies = 0x02`, `BlockTransactions = 0x04`, `UtxoSet = 0x20`,
  `ShieldedSpendTags = 0x41`, `ChainCheckpoint = 0x72`, `TxIndex = 0x50`,
  `PruningPoint = 0x30`, etc. (`store_registry.rs`).
- `DbKey`: prefix-namespaced key construction, single RocksDB instance.
- `PruningStore`, `ReachabilityStore`, `CachedDbAccess`, `DbWriter` —
  Kaspa-style abstractions, used by `misaka-node/main.rs` and 8+ files.
- `checkpoint::{Checkpoint, CheckpointManager, CHECKPOINT_INTERVAL=500}` —
  filesystem JSON snapshots with `content_hash` (SHA3-256) and
  `prev_checkpoint_hash` (chain-of-trust).

### The actual state of the codebase

| System                         | Status                                            |
|--------------------------------|---------------------------------------------------|
| Legacy 5-CF `RocksBlockStore`  | Live only in 3 files (`block_store.rs`, `lib.rs` re-export, `recovery.rs`) — probably legacy/deprecated |
| Kaspa-aligned 40+ prefix stores| **Active**; used in `misaka-node/main.rs`, tests, ~10 files |
| Narwhal 8-CF `rocksdb_store`   | Active (consensus-critical)                       |
| `Checkpoint` (fs JSON)         | Already implemented; spec differs from memo       |

### Why §4's mapping is probably wrong

Implementing Option A (13→7 unified CFs) as the memo prescribes would:

1. Introduce a **fourth** storage schema alongside the three already
   present — the opposite of the memo's "unification" goal.
2. Duplicate the `Checkpoint` that already exists.
3. Break every caller of `PruningStore` / `ReachabilityStore` /
   `StorePrefixes`-based storage.
4. Reimplement what `StorePrefixes` + `DbKey` already provide (prefix
   namespacing inside one RocksDB).

### What Phase 2 本体 probably *should* be

Reinterpreted against the real code state:

**R1** Delete or deprecate the legacy `RocksBlockStore` / 5-CF path; migrate its
last consumer (`recovery.rs`) onto the Kaspa-aligned stores.

**R2** Either (a) leave the 8 Narwhal CFs where they are (they're active and
well-tuned per consensus needs), or (b) fold them into the same prefix
registry (`Headers = 0x01` is already taken — allocate a new block like
`0x90-0x97` for Narwhal DAG data).

**R3** Add `PruneMode::{Archival, Pruned{keep_rounds}}` at the *node runtime
config* level, integrated with the existing `PruningStore`.

**R4** Reconcile the existing filesystem `Checkpoint` with the Phase 2 memo's
"epoch boundary + every 10 000 rounds" trigger; keep the existing
`content_hash` + `prev_checkpoint_hash` chain-of-trust.

**R5** Add a `schema_version` marker in `StorePrefixes::VirtualState` (0x70)
or `ChainInfo` (0x71); runtime refuses mismatch.

**R6** Migration tool: migrate any live legacy-CF data into Kaspa-aligned
prefix keyspace (if any legacy data still exists in testnet DBs).

None of R1–R6 map cleanly onto "Headers, Certificates, VotesIndex, Payload,
Metadata, Checkpoints, Equivocation". The memo predates this infra.

### Recommendation

Halt implementation of §4 mapping. Decide with the user:

- **Path X**: Drop the Phase 2 memo's 7-CF scheme. Redefine Phase 2 本体
  against the actual code state (R1–R6 above).
- **Path Y**: Proceed with memo literally. Accept introducing a fourth
  schema and duplicating `Checkpoint`. (Not recommended.)
- **Path Z**: Pause Phase 2 entirely until the memo is rewritten with the
  Kaspa-aligned infra in mind.

---

## 11. Path X — redefined Phase 2 against the actual code state

After user sign-off on §10, Phase 2 本体 is redefined as a set of six
work items (R1–R6) that fit the current Kaspa-aligned infrastructure
without introducing a fourth storage schema.

### 11.1 R1 — Retire the legacy `RocksBlockStore` (BLOCKED)

`block_store.rs` + the 5 legacy CFs (`utxos`, `spent_tags`,
`spending_keys`, `block_meta`, `state`) are referenced in only three
files: itself, `lib.rs` (re-export), and `recovery.rs`. Grep in the rest
of the workspace returns no consumer.

Tasks:
- Confirm `recovery.rs`'s dependence is optional or can be satisfied by
  the Kaspa-aligned `PruningStore` + `UtxoSet`.
- Delete `block_store.rs` and its re-export; drop the 5 legacy CF names
  from `StorageCf`.
- Keep the `StorageCf` enum as a thin shim (now empty) or delete it
  outright if no caller remains.

Open question: do any persisted testnet DBs still contain legacy-CF
data that must be drained into the Kaspa-aligned prefix keyspace? If
yes, R6 must ship before R1. Verified by inspecting the live testnet
DBs on `163.43.225.27`.

#### 11.1.1 R1 audit outcome (2026-04-19)

Line-by-line audit of `crates/misaka-storage/src/recovery.rs`:

- 3 call sites onto `RocksBlockStore`: `open()` (75),
  `verify_integrity()` (92), `get_state_root()` (94).
- `verify_integrity()` has **no Kaspa-aligned equivalent**. It is the
  only thing that catches height/state_root inconsistency at startup.
- `get_state_root()` reads the *persisted* state root from the
  `state` CF. The Kaspa-aligned `UtxoSet::compute_state_root()` is
  **in-memory only** and is not a drop-in replacement — the new
  stack doesn't persist height or state_root at all.
- External callers: only `misaka-node/src/main.rs:1004` calls
  `run_startup_check`. No tests cover the chain.
- Legacy-CF test coverage: `block_store.rs:646` `test_integrity_
  check_passes` is the single test; deleting `block_store.rs`
  removes it with no replacement.

**Conclusion**: R1 cannot ship safely under Phase 2 Path X. The
prerequisite work is:

1. Port `verify_integrity()` logic to a new Kaspa-aligned module
   (decide: SHA3-hash the persisted UTXO set, or persist a rollup in
   `StorePrefixes::VirtualState`).
2. Persist height + state_root via `CachedDbAccess` so restart
   recovery can use them.
3. Add integration tests for the rebuilt startup recovery path.

(1)–(3) is a separate multi-commit PR with its own design doc.
`RocksBlockStore` therefore stays in place at the end of Phase 2
Path X. The new `CheckpointTrigger` and `PruneMode` APIs land on
top of — not as replacements for — the legacy block store.

### 11.2 R2 — Narwhal CFs (leave alone; revisit later)

The 8 `narwhal_*` CFs in `misaka-dag/src/narwhal_dag/rocksdb_store.rs`
are consensus-critical, well-tuned, and not a live source of pain.
Folding them into `StorePrefixes` (e.g. a new block `0x90–0x97`) is a
mechanical but invasive change with no immediate operational benefit.
**Deferred out of Phase 2.** Re-evaluate only if Phase 3+ needs cross-
referencing between DAG state and Kaspa-aligned stores inside one
atomic batch.

### 11.3 R3 — `PruneMode` at the node runtime config

Add a node-level enum:

```rust
pub enum PruneMode {
    Archival,                     // keep all history
    Pruned { keep_rounds: u64 },  // drop state older than this
}
```

Wire it through `NodeRuntimeConfig` and thread to `PruningStore`, which
already owns the pruning-point snapshot. The existing
`PruningPointInfo` and `PruningStore::set_pruning_point` cover the
mechanics; R3 adds only the mode switch + gate around "should this node
retain pre-pruning-point data at all".

No schema change; metrics (`prune_mode_gauge`, `rounds_pruned_total`)
are additive.

### 11.4 R4 — Checkpoint trigger reconciliation (SHIPPED, partial)

**Scope caveat uncovered 2026-04-19**: the codebase carries **two
distinct** `CheckpointManager` implementations with entirely different
semantics:

| File                                                                | Interval default | Unit        | Purpose                                                     |
|---------------------------------------------------------------------|------------------|-------------|-------------------------------------------------------------|
| `crates/misaka-storage/src/checkpoint.rs`                           | 500              | `blue_score`| fs-JSON UTXO state snapshot for local crash recovery         |
| `crates/misaka-dag/src/narwhal_finality/checkpoint_manager.rs`      | 100              | commits     | stake-weighted finality attestation, validator-signed       |

The Phase 2 memo's "epoch boundary + every 10 000 rounds" does not
disambiguate which of these it refers to. The `state_root` language
points at storage; the "epoch boundary" language points at
consensus/finality. A misinterpretation breaks either crash recovery
(storage side) or liveness/finality (dag side), so R4 is *not* a
quick refactor.

Required before R4 lands:

1. Pick which `CheckpointManager` owns the "Phase 2 checkpoint". My
   current read: the storage-side checkpoint is the one the memo means
   (state_root + epoch boundary + rollback boundary), and the finality
   checkpoint is independent consensus machinery that should stay
   untouched here.
2. Verify the γ-5 epoch subsystem is in main (or plan the stub).
3. Audit every `CheckpointManager::new` call site and decide
   whether `MAX_CHECKPOINTS_RETAINED` promotion to runtime config is
   backward-compatible.

Then the core change is narrow:

- Add `CheckpointTrigger::{BlockInterval(u64), EpochBoundary,
  RoundInterval(u64)}` in `misaka-storage::checkpoint`.
- `CheckpointManager::should_checkpoint()` becomes trigger-driven.
- Default remains `BlockInterval(500)` (no behaviour change).
- `MAX_CHECKPOINTS_RETAINED` becomes runtime config with the existing
  `5` as default.

No schema change. No finality-side change.

R4 is deferred to its own session — the disambiguation work above is
more than a single commit, and mixing it with R6/R1 increases
blast-radius for consensus regressions.

#### 11.4.1 R4 follow-up — 2026-04-19 outcome

Further investigation while scoping R4 code:

- **storage-side manager**: only referenced from its own tests — no
  production call site currently drives `should_checkpoint()`. The
  trigger refactor is still valuable (Phase 2 R6 will hook the
  existing checkpoint + PruneMode loop to it) so we land the API and
  preserve the legacy default.
- **narwhal_finality-side manager**: `CHECKPOINT_INTERVAL = 100` was
  a `pub const` with no call sites in production (unit tests only);
  `should_checkpoint` did not exist. Added one driven by a
  `CheckpointTrigger` enum with the same variants the storage-side
  manager exposes.
- **`misaka_dag::dag_finality::FinalityManager`** (referenced from
  `crates/misaka-node/src/main.rs` lines 5525, 5892, 6935, 6941 under
  `#[cfg(feature = "ghostdag-compat")]`) — the entire
  `dag_finality` module **does not exist** in `misaka-dag`. Running
  `cargo check -p misaka-node --features ghostdag-compat` surfaces
  the missing module alongside ~14 other unresolved imports
  (`DagNodeState`, `DagStore`, `DagMempool`, `dag_block`,
  `dag_store`, etc.). The feature is broken legacy dead code. Left
  untouched in R4 — deleting the references crosses the "user
  approval for destructive operations" line; flagged as tech debt
  for a future cleanup pass.

R4 thus shipped the `CheckpointTrigger` API on both live managers
(storage + narwhal_finality). The `EpochBoundary` variant falls back
to the legacy interval and is reserved for a γ-5 follow-up. The
dead `ghostdag-compat`/`dag_finality` path is unchanged.

### 11.5 R5 — Storage schema version marker (THIS COMMIT)

Done in this PR:

- `misaka-storage::schema_version` module with:
  - `STORAGE_SCHEMA_VERSION_V088 = 1`,
  - `STORAGE_SCHEMA_VERSION_V090 = 2`,
  - `CURRENT_STORAGE_SCHEMA_VERSION`,
  - `read_schema_version` / `write_schema_version` / `check_compatible`,
  - `SchemaVersionError::{Incompatible, MarkerAbsent, Corrupt, Rocks}`.
- Marker key: `StorePrefixes::ChainInfo || b"schema_version"` → `u32 LE`.
- Unit tests: fresh DB, roundtrip, overwrite, corruption, each
  `check_compatible` branch, arc-wrapper parity.

Wiring into the node boot path is a follow-up commit — the module is
standalone and additive.

### 11.6 R6 — Migration tool (R6-a SHIPPED; R6-b BLOCKED)

`misaka-node migrate --from <u32> --to <u32> [--dry-run] [--db <path>]`
subcommand:

- Idempotent (safe to re-run after partial completion).
- Resumable (writes progress key in `StorePrefixes::ChainInfo` bucket
  `b"migration_progress"`).
- On completion stamps the marker via `write_schema_version`.
- v0.8.8 → v0.9.0 is the only currently-supported path. Downgrade is
  explicitly unsupported; operator is instructed to restore from a
  pre-upgrade snapshot.

Shipping R6 is prerequisite for R1 if legacy-CF data is present on any
live DB.

#### 11.6.1 R6-a — marker-stamp tool (SHIPPED 2026-04-19)

`crates/misaka-node/src/migrate.rs` + four CLI flags on the existing
flat `Cli` struct:

```
misaka-node --migrate-to 2 \
            [--migrate-from 1] \
            [--migrate-dry-run] \
            [--migrate-db /path/to/storage]
```

Triggers an early-exit migration path *before* any node-startup
wiring. Semantics:

- Validates `--migrate-to` equals `CURRENT_STORAGE_SCHEMA_VERSION`.
- Reads the marker via R5 `misaka-storage::read_schema_version`.
- Enforces `--migrate-from` if supplied (guards against running a v2
  stamp against a DB another build already stamped v3).
- Refuses downgrades.
- Idempotent: running a second time on an already-stamped DB is a
  `no-op`.
- Dry-run prints the plan without mutating.
- Post-stamp it reopens the DB and runs `check_compatible` to verify
  the stamp took.

Legacy-CF drain is **not** part of R6-a. No live DB transform beyond
the 4-byte marker.

#### 11.6.2 R6-b — PruneMode storage wiring (BLOCKED)

Intended to spawn `PruningProcessor::maybe_advance_pruning_point()`
from `start_narwhal_node` with the `PruneMode` selected via R3.

Blocker discovered 2026-04-19 while scoping the wiring:
`PruningProcessor::new` requires `DbGhostdagStore`, `DbHeadersStore`,
and `Arc<RwLock<DbPruningStore>>`. These three stores exist only on
the legacy `start_dag_node` path; `start_narwhal_node` never
constructs them. Retrofitting them into the Narwhal pipeline is a
structural change that:

1. Touches the Narwhal boot sequence, which is consensus-critical.
2. Requires deciding what `DbGhostdagStore` means in a Narwhal-only
   world (GhostDAG was removed as of v6 per `crates/misaka-dag/src/
   lib.rs:14` — "GhostDAG has been fully removed as of v6").

R6-b therefore cannot ship under "Phase 2 Path X, additive-only,
no consensus changes". It is deferred to a dedicated session that
either (a) revives a GhostDAG-style pruning pipeline under the
Narwhal path, or (b) rewrites `PruningProcessor` to drop the
GhostDAG-specific dependencies and operate directly on
Narwhal-committed rounds.

The R3 `PruneMode` runtime config therefore lives in `NodeConfig`
without a consumer in the running node. That is intentional — it
unblocks operator-side config files without forcing the wiring
decision now.

### 11.7 Suggested ordering

1. R5 marker (this commit) — zero-risk, additive.
2. R3 `PruneMode` runtime config — additive, no schema change.
3. R4 checkpoint trigger — additive, no schema change.
4. R6 migration tool (core path: stamp marker on first open; legacy-CF
   drain path iff R1 needs it).
5. R1 legacy `RocksBlockStore` retirement.
6. R2 (deferred).

### 11.8 Non-scope for Path X

- Global 13→7 CF collapse (superseded by acknowledging the Kaspa-aligned
  infra already solves the prefix-namespacing problem).
- State root / UTXO merkle root reshape (Phase 3, per user decision
  2026-04-19).
- Any Narwhal-side restructure (R2 deferred).

---

## 12. Verification plan (when code lands)

- `cargo build` / `cargo test` / `cargo clippy` clean per crate.
- Migration tool: apply on a v0.8.8 snapshot copy, verify every old
  key → new key round-trip (byte-identical values).
- Runtime refusal: start node against v0.8.8 DB → expect error with
  migration hint; start against v0.9.0 DB → normal boot.
- 4-node smoke: 2 archival + 2 pruned, 24h, DB growth rate and sync
  correctness both logged.
- Bench: archival 1.5–2 GB/24h, pruned 500 MB–1 GB/24h (per memo).
