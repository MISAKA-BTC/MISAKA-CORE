# Phase 3a Part C — Epoch transition integration (design + blockers)

Status: **DESIGN ONLY. Blocked pending architectural decision.**
Cross-refs: `docs/design/v091_phase3a_cert_v2.md` §5.8 (Part C
store-layer: `adjust_round_config`, `round_config_audit` CF).

## 0. Summary

Phase 3a Part C shipped a pure deterministic `adjust_round_config`
derivation function and a persistent `narwhal_round_config_audit`
CF. The original plan called for calling the function at each
epoch boundary, persisting the audit entry, and swapping the new
config into the live `RoundSchedulerConfig` used by the propose
loop. A pre-integration audit revealed **three separate blockers**
that collectively prevent a thin wiring commit:

1. There is no single "epoch boundary" production hook — there
   are two epoch subsystems, neither driven from the live loop.
2. `RoundSchedulerConfig` is constructed once at node startup;
   the propose-loop path takes a `Option<RoundSchedulerConfig>`
   by value, not a shared `Arc<RwLock>`.
3. `EpochStats { max_observed_rtt_ms, total_rounds,
   non_empty_rounds, leader_timeout_ms }` has no live collector.

This document records the blockers and proposes a staged
resolution.

## 1. What the original Part C integration was supposed to be

```rust
// Hypothetical: at epoch N → N+1 boundary
let prev_stats = epoch_stats_collector.snapshot();
let prev_cfg = *shared_scheduler_config.read().await;
let new_cfg = adjust_round_config(&prev_stats, &prev_cfg);

let entry = RoundConfigAuditEntry {
    applied_from_epoch: prev_stats.epoch + 1,
    previous_config: prev_cfg,
    new_config: new_cfg,
    stats: prev_stats,
    timestamp_ms: now_millis(),
};
rocks_store.put_round_config_audit(&entry)?;

*shared_scheduler_config.write().await = new_cfg;
```

Intended semantics: at every epoch boundary, collect the
previous epoch's observed behaviour, derive the next-epoch
config deterministically, persist the audit entry on-chain
(CF-wise), swap the live scheduler over.

## 2. Blocker 1 — two epoch subsystems, neither production-wired

### 2.1 Consensus-layer epoch (`misaka-consensus`)

File: `crates/misaka-consensus/src/epoch.rs`

```rust
pub fn on_checkpoint(&mut self) -> bool {
    self.checkpoints_in_epoch += 1;
    if self.checkpoints_in_epoch >= EPOCH_LENGTH {
        self.current_epoch += 1;
        self.checkpoints_in_epoch = 0;
        true
    } else {
        false
    }
}
```

- Returns `true` at boundary. **Ideal hook.**
- Only called from `crates/misaka-node/src/validator_lifecycle_persistence.rs:139`
  during snapshot replay — **not from the live propose loop**.
- Depends on `EPOCH_LENGTH` which is static; the adaptive
  scheduler doesn't change that.

### 2.2 DAG-layer epoch (`misaka-dag`)

File: `crates/misaka-dag/src/narwhal_dag/epoch.rs`

```rust
pub fn on_commit(&mut self, commit_index: u64) -> Option<PendingEpochChange> { /* ... */ }
pub fn prepare_epoch_change(&mut self, new_committee: Committee) { /* ... */ }
pub fn apply_epoch_change(&mut self) -> Option<Committee> { /* ... */ }
```

- Uses a grace-period two-phase boundary.
- Zero production call sites. `apply_epoch_change` only fires in
  tests.
- `Committee` rotation is implemented but never triggered.

### 2.3 Neither system ties to `RoundSchedulerConfig`

The Phase 3a Part B scheduler config is a `misaka-dag` type
(`narwhal_dag::round_scheduler::RoundSchedulerConfig`). Neither
epoch subsystem currently produces or consumes it. Both were
written well before Part C.

## 3. Blocker 2 — scheduler config is startup-static

`main.rs:2100`:

```rust
scheduler: Some(
    misaka_dag::narwhal_dag::round_scheduler::RoundSchedulerConfig::default(),
),
```

`ProposeLoopConfig::scheduler` is `Option<RoundSchedulerConfig>`
— a **value**, not `Arc<RwLock<_>>`. Once passed to
`spawn_propose_loop`, it's captured by move into the loop's local
state. There is no mechanism to update it from outside.

To make it swappable:

- Change `ProposeLoopConfig::scheduler` to
  `Option<Arc<RwLock<RoundSchedulerConfig>>>`.
- Update the propose loop at `crates/misaka-node/src/narwhal_consensus.rs:422`
  to `.read().await` the config at each iteration (currently
  `.zip`'d once at task start).
- Thread the same `Arc<RwLock<_>>` into the epoch boundary
  handler so it can `.write().await`.

Size: ~30 LoC in two files. Risk: every iteration now acquires a
read lock on a shared state. Measurable but small.

## 4. Blocker 3 — `EpochStats` has no live collector

`EpochStats` fields (from
`crates/misaka-dag/src/narwhal_dag/round_config_adjust.rs:74-93`):

- `max_observed_rtt_ms` — needs a running max of RTT samples.
  Closest existing counter: none. `round_prober` tracks round
  progress but not quorum-reply RTT.
- `total_rounds` — increment on every proposed round.
- `non_empty_rounds` — increment when `exec_result.txs_accepted
  > 0` (already available at `main.rs:4462`).
- `leader_timeout_ms` — static config; pass through.

Missing infrastructure:

- A shared `Arc<EpochStatsCollector>` that exposes atomic
  incrementers (`record_round()`, `record_non_empty()`,
  `record_rtt(duration_ms)`) and an atomic
  `snapshot_and_reset() -> EpochStats`.
- Wiring the three incrementers into the propose loop (round)
  and the commit loop (non-empty / RTT).

Size: ~100 LoC for the collector + ~20 LoC of wiring. Risk: low
(atomic counters, pure additive).

## 5. Resolution paths

### Path A — full integration (all three blockers, one commit)

Build the collector, make config swappable, pick ONE of the two
epoch subsystems to act as the boundary, wire Part C.

**Pros**: ships the integration as originally specified.
**Cons**: multi-session work (3-5 sessions). Picking an epoch
system is itself an architectural call — both are incomplete.

### Path B — partial integration: audit-log-only

Ship the `EpochStatsCollector` + call
`adjust_round_config` + write the audit entry **at a regular
cadence** (e.g. every 10 000 commits) instead of at an epoch
boundary. Skip the live-config swap.

**Pros**: operational visibility of what the adjustment would
produce. Low risk. Informs future decisions with real data.
**Cons**: `adjust_round_config` derives a new config but the
node doesn't use it — pure observability, no cadence change.
Violates the spirit of Part C ("config update at epoch boundary,
recorded in on-chain audit log") — it'd be "audit only, no
config change".

**Estimated effort**: 1-2 sessions.

### Path C — defer Part C integration to "Phase 3a.5 — Epoch subsystem activation"

Recognize that Part C integration shares a blocker with A.7
(§2 of `phase3a_finalizer_integration.md`): both assume an epoch
subsystem that isn't live. Bundle the two into a single Phase
3a.5 work item ("activate the epoch-aware subsystems —
`CheckpointManager`, `DagEpochManager`, `EpochStatsCollector`,
`RoundSchedulerConfig` swap — as one cohesive commit set").

**Pros**: truthful. Forces us to design the epoch machinery as
one thing rather than bolting on.
**Cons**: Phase 3a closes with "store-layer + docs, runtime
integration deferred". Operators see the feature but can't use
it yet.

## 6. Recommendation

**Path C** for Phase 3a. **Path A** shape for Phase 3a.5.

Rationale:
- Part C's integration depends on epoch machinery that Part C
  itself didn't ship. The mismatch is a memo-level gap, not a
  code-level one.
- A bundled Phase 3a.5 ("epoch activation") covers both A.7 and
  Part C integration with a unified design, avoiding two
  overlapping partial integrations.
- Phase 3b (ZK retrofit) is unaffected: it proves properties of
  certs already produced; how certs are emitted and how
  cadence changes across epochs are orthogonal concerns.

Explicit Path C content:

1. Mark Phase 3a Part C integration as **Deferred to Phase 3a.5**
   in `v091_phase3a_cert_v2.md` §6.
2. Keep the store-layer API (`adjust_round_config`,
   `put_round_config_audit`, `RoundConfigAuditEntry`) as the
   dependency target that Phase 3a.5 will consume.
3. Keep the `RoundConfigAudit` CF in the v3 schema — it's
   cheap (empty until 3a.5) and means no schema bump is needed
   when 3a.5 lands.
4. Cross-reference this doc + the finalizer one from §6.

## 7. What Phase 3a.5 will need (forward plan)

For the preferred shape when 3a.5 lands:

1. **Pick the epoch subsystem**. Recommendation: extend
   `misaka-dag::narwhal_dag::epoch::EpochManager` — it's closer
   to the DAG where `CommittedSubDag` lives and where the
   scheduler config is interpreted.

2. **Wire `on_commit` into the live commit loop** at
   `main.rs:4280`. When `prepare_epoch_change` fires, transition
   the committee AND the scheduler config in one transaction.

3. **Build `EpochStatsCollector`** in
   `crates/misaka-dag/src/narwhal_dag/`:
   ```rust
   pub struct EpochStatsCollector {
       total_rounds: AtomicU64,
       non_empty_rounds: AtomicU64,
       max_observed_rtt_ms: AtomicU64,
       current_epoch: AtomicU64,
   }
   impl EpochStatsCollector {
       pub fn record_round(&self);
       pub fn record_non_empty_round(&self);
       pub fn record_rtt(&self, rtt_ms: u64);
       pub fn snapshot_and_reset(&self, leader_timeout_ms: u64) -> EpochStats;
   }
   ```

4. **Make `ProposeLoopConfig::scheduler` shareable**:
   change from `Option<RoundSchedulerConfig>` to
   `Option<Arc<RwLock<RoundSchedulerConfig>>>`. Propose loop
   reads on each iteration; epoch handler writes at boundary.

5. **Put `EpochStatsCollector::record_round()`** at the top of
   each propose-loop iteration;
   **`record_non_empty_round()`** in the commit-loop branch
   where `exec_result.txs_accepted > 0`;
   **`record_rtt(ms)`** wherever we have a round-trip timing
   signal (TBD — probably the `msg_tx.try_send` →
   `reply_rx.await` round-trip around `main.rs:4440`).

6. **At epoch boundary** (after `apply_epoch_change()`
   succeeds): snapshot, derive, persist, swap. Exactly the
   pseudocode from §1.

7. **Metrics**: expose the derived `new_config`'s
   `min_interval_ms` and `max_interval_ms` as gauges alongside
   the existing `misaka_round_interval_ms`. Also
   `misaka_epoch_adjustments_total` counter.

## 8. Non-goals for Phase 3a.5

- Determinism regression on the existing propose-loop metrics
  already shipped in Part B integration (64589df). Those remain
  functional independently.
- Changes to the `adjust_round_config` derivation itself. If the
  §3.3 circuit proves mis-calibrated on live data, revisit in
  Phase 3a.6 — not 3a.5.
- Migrating the two existing epoch subsystems into a single one.
  That's a separate cleanup; 3a.5 picks one and uses it.
