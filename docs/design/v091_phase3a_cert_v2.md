# v0.9.1 Phase 3a — Certificate V2 (ZK-forward-compatible foundation)

Status: **FOUNDATION shipping in this commit (types + scheme). Follow-up sessions wire write/read + adaptive rate + epoch adjustment.**

Stacked on: PR #13 (`feature/v090-cf-split-pruning`) which is stacked on PR #11 (`feature/v090-cf-enum-foundation`). Merge order: #11 → #13 → this PR.

Source memos (captured in `memory/project_phase3a_prompt.md`): two prompts that the user delivered in one burst. Reconciliation below.

---

## 1. Reconciliation of Prompt A and Prompt B

The two source prompts describe overlapping but not identical Cert V2 shapes.

| Field              | Prompt A (signature externalization)                 | Prompt B (ZK-forward)                                            | Chosen |
|--------------------|------------------------------------------------------|------------------------------------------------------------------|--------|
| `header` binding   | `header_digest: [u8; 32]`                            | `header: CheckpointDigest` (full digest type)                    | **B** — use the typed `CheckpointDigest` that already exists in `narwhal_finality/mod.rs`. Prompt A's raw `[u8; 32]` is the same 32 bytes but typed. |
| Vote carrier       | `vote_refs: BitVec`                                  | `vote_refs: VoteCommitment { voters: BitVec, root, scheme }`     | **B** — Prompt B wraps Prompt A's `BitVec` with a merkle-root + scheme tag. Extra fields default to `Blake3MerkleV1` with root computed from `voters`. Phase 3b can swap the scheme without shape change. |
| Epoch field        | `epoch: u64`                                         | (not present)                                                    | **Added** — Prompt A's `epoch` carries over. Lives at `CertificateV2::epoch`; not inside `VoteCommitment`. |
| Aggregation slot   | (not present)                                        | `aggregation_slot: Option<AggregationProof>`                     | **B** — Phase 3a populates `None` only; `ProofSystem::ReservedV1` is the sole variant and a cert with `Some(_)` is rejected. |
| Cert digest input  | implicit (probably everything)                       | explicit: digest excludes `aggregation_slot`                     | **B** — the exclusion is load-bearing: it lets a later hardfork retrofit proofs without changing every DAG reference. |

### Chosen shape (this commit)

```rust
pub struct CertificateV2 {
    pub header: CheckpointDigest,
    pub vote_refs: VoteCommitment,
    pub epoch: u64,
    pub aggregation_slot: Option<AggregationProof>,
}

pub enum Certificate {
    V1(FinalizedCheckpoint),   // existing — placeholder name for the current "cert"
    V2(CertificateV2),
}
```

Where `V1` aliases the existing `FinalizedCheckpoint` — no new V1 struct is created, and no migration is attempted in this foundation commit. The enum lets callers match on the variant when Prompt A's read path lands.

## 2. VoteCommitmentScheme

```rust
pub trait VoteCommitmentScheme {
    fn leaf(voter_id: &[u8; 32], signature_or_nothing: &[u8]) -> [u8; 32];
    fn internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
    fn root(leaves: &[[u8; 32]]) -> [u8; 32];
    fn scheme_tag() -> CommitmentScheme;
}
```

One impl this session: `Blake3MerkleV1`.

- **Domain separation**: distinct blake3 prefix per kind to prevent collisions across leaf / internal / root. Concretely: `b"MISAKA:cert_v2:leaf:v1"`, `b"MISAKA:cert_v2:internal:v1"`, `b"MISAKA:cert_v2:root:v1"`.
- **Hash choice**: blake3 rather than SHA-2-256 to match the existing `Checkpoint::compute_digest` convention at `narwhal_finality/mod.rs:35`. The memo called this scheme "Sha256MerkleV1"; renamed to `Blake3MerkleV1` so the scheme tag accurately labels the function. Tag byte stays `0x01` — this is the first persisted scheme either way.
- **Determinism**: the `root()` impl sorts leaves by voter_id ascending before hashing, so two validators computing the same commitment from the same voter set always agree.
- **Padding**: for non-power-of-two leaf counts, duplicate the last leaf up to the next power of two (Bitcoin-style). Avoids second-preimage on odd heights.
- **Scheme tag**: `CommitmentScheme::Blake3MerkleV1 = 0x01` reserved byte; future Poseidon etc. take 0x02+.

## 3. AggregationProof

```rust
pub enum ProofSystem {
    ReservedV1 = 0x01,  // no proofs accepted in Phase 3a
}

pub struct AggregationProof {
    pub system: ProofSystem,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub generated_at: u64,
}
```

Phase 3a invariant (enforced on verify path when wired): any `AggregationProof { system: _, ... }` — regardless of contents — is rejected. The field exists so that Phase 3b can drop in a real proof system without shape change.

## 4. Cert digest — what's in, what's out

`CertificateV2::digest()` hashes:

```
MISAKA:cert_v2:digest:v1 ||
  header_digest (32) ||
  epoch (8 LE) ||
  vote_refs.scheme_tag (1) ||
  vote_refs.voters.len (8 LE) ||
  vote_refs.voters (packed bits, length-prefixed) ||
  vote_refs.root (32)
```

**Explicitly NOT included**: `aggregation_slot`. Rationale per Prompt B: a later hardfork may retrofit a proof into existing certificates without breaking every DAG reference that cites them by digest. If the proof contents were inside the digest, retrofit would require re-signing every historical cert's downstream references.

## 5. Progress log

### 5.1 Foundation — 9a88656 (2026-04-19 early)

Cert V2 types + design doc (this file). See commit for details.

### 5.2 Part A.1-A.3 — e8197bd (2026-04-19 later)

- **A.1 — `votes` CF**: added `NarwhalCf::Votes = "narwhal_votes"`
  variant. CF descriptor in `open_with_sync`: compression off +
  BlobDB with `min_blob_size = 1024`. `cf_votes()` accessor +
  `CF_VOTES` const. `NarwhalCf::ALL` updated to 9 variants; the
  exhaustiveness test's `EXPECTED_COUNT` bumped accordingly.
- **A.2 — write path**: `RocksDbConsensusStore::put_cert_v2_votes(
  cert_digest, &VoteCommitment, &Option<AggregationProof>)`.
  Serde-JSON encoding for day-1 consistency with the other narwhal
  value encodings (borsh migration deferred — needs manual impls to
  preserve `#[repr(u8)]` tags on `CommitmentScheme` / `ProofSystem`).
  Intentionally accepts `aggregation_slot = Some(_)` at the store
  layer — the verify path (not yet wired) owns the Phase 3a "reject
  Some" invariant.
- **A.3 — read path**: `get_cert_v2_votes(cert_digest) ->
  Result<Option<(VoteCommitment, Option<AggregationProof>)>, _>`.
  Returns `Ok(None)` on missing key; propagates serde errors.
- 7 new unit tests in `rocksdb_store::tests`:
  `a1_votes_cf_is_registered_on_open`,
  `a2_a3_put_then_get_roundtrips_without_agg`,
  `a2_a3_put_then_get_roundtrips_with_agg`,
  `a3_get_on_missing_key_returns_none`,
  `a2_put_overwrites_previous_value`,
  `a1_write_to_votes_does_not_affect_tx_index`,
  `a3_roundtrip_preserves_scheme_tag`.
- 1 new assertion in `columns::tests::names_match_pre_refactor_literals`
  and 1 update to `all_is_exhaustive_and_unique::EXPECTED_COUNT`.

Totals: `cargo test -p misaka-dag --lib` 462/462 (455 prior + 7).
`cargo check --workspace --lib --bins` clean.

### 5.3 Part B — adaptive round-rate scheduler (342548e, 2026-04-19)

New module `crates/misaka-dag/src/narwhal_dag/round_scheduler.rs`:

- Constants: `DEFAULT_MIN_INTERVAL_MS = 100`,
  `DEFAULT_MAX_INTERVAL_MS = 2_000`, plus hard bounds
  `HARD_MIN_INTERVAL_MS = 50` and `HARD_MAX_INTERVAL_MS = 10_000`.
- `RoundSchedulerConfig { min_interval_ms, max_interval_ms }` with
  `Default` matching the memo and `validate()` that rejects
  below-floor / above-ceiling / `min >= max`.
- `next_round_interval_ms(utilisation: f64, &RoundSchedulerConfig)
  -> u64` — pure linear interp. `u=1.0 → min`, `u=0.0 → max`.
  Clamps `utilisation` to `[0, 1]`, rounds to nearest, re-clamps to
  `[min, max]` for FP drift tolerance. NaN survives without panic
  (caller still gets a valid u64).
- `next_round_interval(..)` is a `Duration` wrapper.
- `wait_until_next_round<F>(utilisation, config, mempool_wake: F)
  -> WakeCause` where `F: Future<Output = ()>`. Uses
  `tokio::select!` on a sleep vs the caller's future. Returns
  `TimerExpired` or `MempoolSignalled` so the caller can log /
  metric the cause. Caller who wants sleep-only semantics passes
  `std::future::pending()`.

Determinism: two nodes with the same `utilisation` + same config
compute the same interval. No clock read, no RNG, no I/O in the
pure function.

Not in this commit:
- Integration into `start_narwhal_node`'s proposer loop (replaces
  the fixed-cadence sleep). Requires wiring a mempool utilisation
  signal.
- Prometheus metrics (`round_interval_ms`, `mempool_utilization`).
  Plumbing deferred to the integration commit.

19 new unit tests in `round_scheduler::tests`:

- Default config shape + validate clean.
- `validate()` rejects below-floor / above-ceiling / `min>=max`.
- Endpoints: `u=0` → max, `u=1` → min, `u=0.5` → midpoint.
- Clamping: `u>1` → min, `u<0` → max, NaN no-panic.
- Monotonicity: higher `u` picks shorter-or-equal interval
  across 11 sample points.
- Custom range respected.
- Degenerate `min==max` yields `min` without panic.
- `Duration` wrapper matches ms function.
- Async (`#[tokio::test]`): pre-resolved future wins race;
  pending future → `TimerExpired`; slow mempool wake →
  `TimerExpired`.

Regression: `cargo test -p misaka-dag --lib` 481/481 (462 prior + 19).
`cargo check --workspace --lib --bins` clean.

### 5.4 Part B integration — proposer loop + metrics (64589df, 2026-04-19)

Wires the Part B scheduler into `start_narwhal_node`'s proposer
loop. Additive and opt-in: if either the scheduler config or the
mempool reference is `None`, the loop falls back to the pre-existing
fixed-cadence `status_tick`.

#### Changes

**`crates/misaka-node/src/metrics.rs`** — 4 new fields on
`NodeMetrics`:
- `round_interval_ms: Gauge` — most-recent adaptive interval picked.
- `mempool_utilisation_scaled: Gauge` — `utilisation × 1000` so the
  `[0, 1]` ratio fits in `u64`.
- `round_wake_timer_total: Counter` — wakes via the adaptive sleep.
- `round_wake_mempool_total: Counter` — wakes via mempool tx
  delivery.

All four are exposed by `render_prometheus()` with names
`misaka_round_interval_ms`, `misaka_mempool_utilisation_scaled`,
`misaka_round_wake_timer_total`, `misaka_round_wake_mempool_total`.

**`crates/misaka-node/src/narwhal_consensus.rs`** —
`ProposeLoopConfig` gains three `Option` fields: `scheduler`,
`mempool`, `metrics`. The spawn_propose_loop body:

- Computes `utilisation = mempool.len() / mempool.max_size()` each
  iteration when both `scheduler` and `mempool` are `Some`.
- Clamps to `[0, 1]`; zero-max degrades to `0.0` without panic.
- Calls `next_round_interval_ms` to derive the sleep.
- Publishes `round_interval_ms` + `mempool_utilisation_scaled`
  via the `metrics` handle (when present) before the `select!`.
- Uses `tokio::select!` arm guards: the adaptive sleep arm fires
  only when `adaptive.is_some()`; the legacy `status_tick` arm
  fires only when it's `None`. Cannot double-fire.
- Increments `round_wake_mempool_total` or `round_wake_timer_total`
  on whichever arm won.

Mempool lock on every iteration is held briefly (two field
accesses: `len()` + `max_size()`) — roughly the same cost as a
single `tokio::time::interval` tick. No contention concern in the
steady-state proposer hot path.

**`crates/misaka-node/src/main.rs`** —
`start_narwhal_node` now:
- Instantiates `NodeMetrics::new()` — previously a dead-code
  struct with no production call site.
- Passes `scheduler: Some(RoundSchedulerConfig::default())`,
  `mempool: Some(narwhal_mempool.mempool.clone())`, and
  `metrics: Some(node_metrics.clone())` into `ProposeLoopConfig`.
- Keeps a `_node_metrics_keep` binding alive for the rest of the
  node's lifetime so future subsystems (RPC `/metrics` endpoint,
  dashboard poll) can adopt the Arc.

No `/metrics` HTTP endpoint is wired in this commit; that's a
separate follow-up. The metrics are still accumulated; exposure is
the only missing piece.

#### Observable defaults

Freshly booted node with empty mempool:
- `round_interval_ms = 2000` (adaptive max, since `utilisation = 0`).
- `mempool_utilisation_scaled = 0`.
- `round_wake_timer_total` increments every ~2 s; no mempool wakes
  until txs arrive.

Saturated mempool:
- `round_interval_ms = 100` (adaptive min).
- `mempool_utilisation_scaled = 1000`.
- `round_wake_mempool_total` dominates.

#### Tests / regression

- `cargo test -p misaka-dag --lib`: 481/481 pass (Part B unit
  tests unchanged).
- `cargo test -p misaka-node --bin misaka-node`: 194/194 pass.
- `cargo check --workspace --lib --bins`: clean.

No new unit tests added in this integration commit — the behaviour
is emergent from the pure logic (already tested in §5.3) plus the
select! shape (covered by the `wait_until_next_round` async tests
in §5.3). A 24 h smoke is still required to verify the adaptive
cadence holds across real mempool fluctuations.

### 5.5 Part A.4 — verify path (bc84de0, 2026-04-19)

Pure `verify_cert_v2(&CertificateV2, voter_ids: &[[u8; 32]]) ->
Result<(), VerifyError>` in `cert_v2.rs`.

Checks, in order:
1. `aggregation_slot` MUST be `None` (Phase 3a invariant).
2. Scheme tag MUST be `CommitmentScheme::Blake3MerkleV1`
   (exhaustive match; future tags force a compile-time update).
3. `cert.vote_refs.voter_count` MUST equal `voter_ids.len()`.
4. Recomputed merkle root from `voter_ids` MUST equal
   `cert.vote_refs.root`.

`VerifyError::{AggregationSlotNotYetAccepted, UnknownCommitmentScheme,
VoterCountMismatch, RootMismatch}`. Pure function — no I/O.

9 unit tests cover all four rejection paths + happy path +
order-independence + empty-set edge case.

### 5.6 Part A.5 — cert v1 ↔ v2 mapping CF (5d8e332, 2026-04-19)

`NarwhalCf::CertMapping = "narwhal_cert_mapping"` (10th variant).
Tuning: compression off, no BlobDB (32-byte value always fits LSM).

`RocksDbConsensusStore`:
- `put_cert_mapping(v1_digest, v2_digest)` — idempotent.
- `get_cert_mapping_v1_to_v2(v1_digest) -> Result<Option<[u8; 32]>>`.
  Ok(None) on miss; Err(Corrupted) on wrong length.

v2 → v1 reverse lookup not shipped (future need — small CF, full
scan acceptable as fallback). GC policy deferred; 32-byte values
are cheap.

6 unit tests cover CF registration, roundtrip, miss → None,
idempotent rewrite, overwrite-with-different-v2 accepted, and CF
isolation vs the `votes` CF.

### 5.7 Part A.6 — migrate CLI v2 → v3 extension (this commit, 2026-04-19)

- `misaka-storage::schema_version` — new const
  `STORAGE_SCHEMA_VERSION_V091 = 3`;
  `CURRENT_STORAGE_SCHEMA_VERSION` bumped to V091.
  `constants_are_monotone_and_current_is_latest` test updated
  to assert V090 < V091 and CURRENT == V091.
- `misaka-storage::lib` — re-exports `STORAGE_SCHEMA_VERSION_V091`.
- `misaka-node::migrate` — `stamp_marker` now:
  1. Enumerates existing CFs via `DB::list_cf`.
  2. Unions with the target schema's required CFs — for v3 that
     adds `narwhal_votes` + `narwhal_cert_mapping`.
  3. Opens with the full CF descriptor list and
     `create_missing_column_families = true` so the new CFs are
     created atomically alongside the marker write.
- Module rustdoc updated: v3 row in the version table + "each
  build writes only its own schema" note.

CLI surface unchanged: `misaka-node --migrate-to 3` now stamps v3
and creates the two new CFs on any DB that's at v2 or earlier.

2 new e2e tests:
- `e2e_v2_to_v3_creates_new_cfs_and_stamps_marker` — stages a
  v2-era DB with some narwhal CFs, runs migrate, asserts the two
  new CFs appear on disk and the marker bumps to 3.
- `e2e_v2_to_v3_is_idempotent` — second `run()` is a no-op.

All existing migrate tests continue to pass unchanged (they use
`CURRENT_STORAGE_SCHEMA_VERSION` as `--to` rather than a
hard-coded number, so they automatically retarget to v3).

Regression: misaka-storage 109/109, misaka-node 196/196, misaka-dag
496/496. `cargo check --workspace --lib --bins` clean.

### 5.8 Part C — epoch-boundary config adjustment + audit log (this commit, 2026-04-19)

Ships the deterministic derivation of the next-epoch
`RoundSchedulerConfig` from the previous epoch's stats, plus a
persistent audit log keyed by epoch.

#### `crates/misaka-dag/src/narwhal_dag/round_config_adjust.rs` (new)

Pure logic module. No I/O, integer math only, `serde_json` only
for the persisted `RoundConfigAuditEntry`.

- Constants: `MAX_EPOCH_SHIFT_MS = 500`, `RTT_SAFETY_FACTOR = 2`.
- `EpochStats { epoch, max_observed_rtt_ms, total_rounds,
  non_empty_rounds, leader_timeout_ms }`.
  * `non_empty_ratio_scaled() -> u64` returns `0..=1000`
    fixed-point so the derivation stays off floating-point.
    `total == 0` → 0. Saturating multiplication on the
    numerator guards against `u64` overflow (not panic; precision
    degrades at extreme scale but real epochs stay ≪ 10^16
    rounds).
- `RoundConfigAuditEntry { applied_from_epoch, previous_config,
  new_config, stats, timestamp_ms }` with `serde`.
- `adjust_round_config(&EpochStats, &RoundSchedulerConfig)
  -> RoundSchedulerConfig`:
  1. `new_min = max(prev.min, rtt * 2)` — the RTT safety floor.
  2. `new_max = HARD_MAX - (HARD_MAX - new_min * 2) * ratio /
     1000` — busy epochs pull `max` toward `min * 2`, idle
     epochs push toward `HARD_MAX`. u128 intermediate to avoid
     multiplication overflow.
  3. Both endpoints drift-bounded by `MAX_EPOCH_SHIFT_MS` from
     the previous values to damp oscillation.
  4. Final clamp into `[HARD_MIN, HARD_MAX]` + spread guard if
     `min >= max` after drift bounding.
  5. Output always satisfies
     `RoundSchedulerConfig::validate`.

`RoundSchedulerConfig` gains `Serialize + Deserialize` derives
for use inside `RoundConfigAuditEntry`.

#### `NarwhalCf::RoundConfigAudit = "narwhal_round_config_audit"` (11th variant)

- Key: `applied_from_epoch: u64` in big-endian so RocksDB
  natural iteration order == chronological order.
- Value: serde-JSON of `RoundConfigAuditEntry` (~200 bytes).
- Tuning: Snappy compression (repeated JSON field names compress
  well), no BlobDB.

#### `RocksDbConsensusStore` — 3 new methods

- `put_round_config_audit(&entry)` — key = BE u64 epoch.
- `get_round_config_audit(epoch) -> Result<Option<Entry>>`.
- `list_round_config_audit() -> Result<Vec<Entry>>` — full scan
  in epoch order. Intended for ops / dashboards; the per-epoch
  getter is enough for a running node.

#### `misaka-node::migrate` V091 delta

`stamp_marker`'s V091 CF-delta list extended to include
`narwhal_round_config_audit`. Also the `e2e_v2_to_v3_creates_new_cfs`
test now asserts all three new CFs (votes + cert_mapping +
round_config_audit).

#### Tests

18 new tests in `round_config_adjust::tests` covering:

- `non_empty_ratio_scaled` edge cases (empty epoch, all-non-empty,
  half-non-empty, large-count no-panic, realistic 10_000-round
  sanity).
- `bound_drift` within, exceeding, and saturating cases.
- `adjust_round_config` determinism, output always validates,
  RTT flooring, zero-RTT no-op on min, busy tightens max, idle
  widens max, monotonicity across 6 ratio samples, extreme-RTT
  handling, collision between drift-bounded min and max.
- `RoundConfigAuditEntry` serde roundtrip.

5 new rocksdb_store tests:

- `partc_audit_cf_is_registered_on_open`
- `partc_put_then_get_audit_roundtrips`
- `partc_get_on_missing_epoch_returns_none`
- `partc_list_preserves_epoch_order` — inserts out-of-order
  (10, 3, 7) then asserts list returns ascending [3, 7, 10]
  (BE key order guarantees this).
- `partc_idempotent_rewrite_of_same_entry`

Plus 3 assertions added to `columns::tests`:
`EXPECTED_COUNT = 11`, new `RoundConfigAudit` name assertion.

Plus 1 assertion to the migrate v2→v3 e2e test (third CF check).

Regression: `cargo test -p misaka-dag --lib` 519/519
(496 prior + 18 + 5). `cargo test -p misaka-storage --lib`
109/109 unchanged. `cargo test -p misaka-node --bin misaka-node`
196/196 unchanged.

#### Not in this commit

- Integration into the epoch-boundary event. Needs a callsite
  that has:
  1. Previous-epoch's `EpochStats` (collected from the round
     loop).
  2. Previous-epoch's `RoundSchedulerConfig`.
  3. A handle to write `put_round_config_audit` + a way to hand
     the new config to the next epoch's propose-loop spawn.
  Deferred until the narwhal epoch transition path grows a hook
  for this — separate integration commit.
- Prometheus export of the `new_config` / `stats` — trivial to
  add once integration lands.

## 6. Out of scope for this session

Deferred to follow-up commits:

- **A.4 — verify path**: reject any `CertificateV2` with
  `aggregation_slot = Some(_)` and (later) verify merkle root against
  the persisted voters list.
- **A.5 — cert v1 ↔ v2 mapping CF** for one-epoch compatibility.
- **A.6 — migrate `--from 2 --to 3`**: extends the R6-a CLI to stage
  v2 stubs for every existing finalized cert.
- **Adaptive round rate** (Prompt A Part B): new `RoundScheduler`,
  `next_round_interval` linear interp, `tokio::select!` on sleep vs
  mempool.
- **Epoch-boundary config adjustment** (Prompt A Part C):
  `adjust_round_config` deterministic from previous-epoch stats.
- **ZK-aggregation retrofit plan**:
  `docs/design/zk-aggregation-retrofit-plan.md` (Prompt B final item).
- **7-day smoke**: deploy after the above lands. Prereq is also
  Phase 2's pending 24h smoke.

All of the above reference this design doc so the reconciliation is
stable across sessions.

## 7. Hard boundaries (unchanged from memory memo)

- Phase 3a = **storage layer only**. Wire stays V1 compatible. No hardfork.
- Phase 3b (hardfork, wire V2) = separate work, NOT in Phase 3a scope.
- No actual ZK proof verification in Phase 3a; `ProofSystem::ReservedV1` only.

## 8. Verification plan (when full Phase 3a lands)

- `cargo test -p misaka-dag` passes all of the new cert_v2 tests.
- Every round-trip: encode(cert) → decode → re-encode yields byte-identical output.
- Determinism test: two validators computing `VoteCommitment::new(voters, scheme)` from the same `voters` set produce identical `root`s regardless of insertion order.
- Aggregation rejection test: any cert with `aggregation_slot = Some(_)` rejected by the verify path.
- 7-day 4-node smoke: disk savings 10–20 % over Phase 2 archival, 5–10× reduction at idle — per Prompt A's target.
