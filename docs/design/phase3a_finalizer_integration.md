# Phase 3a A.7 — Finalizer integration for Cert V2 (design + blockers)

Status: **DESIGN ONLY. Blocked pending architectural decision.**
Cross-refs: `docs/design/v091_phase3a_cert_v2.md` §5.2 (votes CF +
write/read), §5.5 (verify path), §5.6 (cert mapping CF).

## 0. Summary

Phase 3a shipped a complete store-layer API for Cert V2
(`put_cert_v2_votes`, `put_cert_mapping`, `verify_cert_v2`). The
original plan called for wiring these into the narwhal commit
finalizer — specifically `checkpoint_manager::CheckpointManager::
add_vote` on the quorum-reached branch. A pre-integration audit
revealed a **deeper blocker**: `CheckpointManager` itself has no
production instantiation. The audit report is captured in §2.
This document proposes three resolution paths (§3) and recommends
the least-invasive one (§4).

## 1. What the original A.7 plan was

At the quorum-reached branch of
`crates/misaka-dag/src/narwhal_finality/checkpoint_manager.rs:269`
(inside `add_vote`), after constructing `FinalizedCheckpoint`:

```rust
// Hypothetical: after the quorum check passes, finalize the cert:
let voter_ids: Vec<[u8; 32]> = pending.votes.iter().map(|v| v.voter).collect();
let cert_v2 = CertificateV2 {
    header: pending.checkpoint.digest,
    vote_refs: VoteCommitment::with_blake3(&voter_ids, pack_bits(&voter_ids)),
    epoch: pending.checkpoint.epoch,
    aggregation_slot: None,
};
let cert_v1_digest = pending.checkpoint.digest;  // same type today
let cert_v2_digest = cert_v2.digest();

// Store write path (Phase 3a A.1-A.3, A.5):
store.put_cert_v2_votes(&cert_v2_digest.0, &cert_v2.vote_refs, &None)?;
store.put_cert_mapping(&cert_v1_digest.0, &cert_v2_digest.0)?;

// Verify path (Phase 3a A.4):
verify_cert_v2(&cert_v2, &voter_ids)
    .expect("locally-constructed cert must verify");
```

Intended semantics: every time a cert reaches quorum, its voter
commitment lands in the `narwhal_votes` CF, its v1 → v2 digest
mapping lands in the `narwhal_cert_mapping` CF, and the self-check
pins that our own cert construction matches the verifier's
expectations.

## 2. Blocker: `CheckpointManager` is unwired in production

Audit findings:

1. **No production `CheckpointManager::new` call site**.
   `cargo test -p misaka-dag` invokes it from
   `checkpoint_manager::tests` and
   `crates/misaka-consensus/tests/`; `rg 'CheckpointManager::new'`
   in production code (excluding `#[cfg(test)]` / `#[cfg(all(test,
   ...))]` blocks) returns **zero** matches.

2. **No production `add_vote` caller**. Same grep pattern — all
   call sites live under `cfg(test)`. Production consensus
   (`start_narwhal_node` → `narwhal_consensus.rs::spawn_propose_loop`
   → `CoreEngine::propose_block`) never passes a `CheckpointVote`
   through a `CheckpointManager`.

3. **`FinalizedCheckpoint` flow bypasses this module entirely** in
   production. The commit loop in `main.rs` (around line 4280 of
   `start_narwhal_node`) receives `CommittedSubDag` from
   `CoreEngine` and applies it to state directly; no "2/3-stake
   checkpoint vote aggregation" happens on the live path.

4. **`NodeMetrics::checkpoint_votes_received`** is declared but
   never incremented for the same reason — the counter awaits a
   caller that doesn't exist.

Conclusion: adding A.7 store calls into `add_vote`'s quorum
branch produces **dead code** — the code would compile, pass
tests, and never execute against a real node. Phase 3a's claim
that A.7 is "just wiring" depended on `CheckpointManager` being
live, which it isn't.

## 3. Resolution paths

### Path A — instantiate `CheckpointManager` in `start_narwhal_node` first

Actually wire the checkpoint-voting subsystem into the live
consensus loop, then hang A.7 off the now-live `add_vote`.

- Construct `CheckpointManager::new(epoch, voter_pubkeys, verifier,
  voter_stakes)` in `start_narwhal_node` after the committee is
  resolved.
- Feed it `CheckpointVote` on each quorum commitment from peers
  (requires P2P layer to surface these; not currently wired).
- Feed it `create_checkpoint(last_committed_round, ...)` at
  cadence points (requires a trigger — probably the existing
  `CheckpointTrigger` from Phase 2 Path X R4).
- *Then* add A.7 into the quorum branch.

**Estimated effort**: 3-6 sessions. Touches consensus hot path,
requires P2P vote gossip, metrics wiring, round-trip latency
handling. Non-trivial regression risk (this introduces a new
consensus-critical subsystem).

### Path B — skip `CheckpointManager`, wire A.7 into the existing commit loop

Recognize that the live finalization primitive is `CommittedSubDag`
from `CoreEngine::propose_block`, not `FinalizedCheckpoint` from
`CheckpointManager::add_vote`. Move the A.7 store calls to where
the commit is actually processed — around `main.rs:4280`.

Pros:
- Uses the live code path. Writes actually happen.
- No new subsystem, no P2P changes.

Cons:
- Requires constructing `CertificateV2` without a
  `CheckpointVote` trail (we'd need to synthesize the voter list
  from the `CommittedSubDag`'s signing validators, which may or
  may not be exposed today).
- Conceptually diverges from the memo — A.7 was specified in the
  `CheckpointManager` context; Path B reroutes to a different
  aggregator. Needs a design note so callers aren't confused.

**Estimated effort**: 1-2 sessions. Lower risk because
`CommittedSubDag` is already a production type.

### Path C — defer A.7 to a later phase entirely

Recognise that A.7 was premised on a subsystem that isn't yet
part of the live node. Formally defer A.7 to "Phase 3a.5 —
Checkpoint voting activation", a separate work item that covers
both `CheckpointManager` wiring and A.7 at once.

Pros:
- Truthful labeling — "Phase 3a is store-layer complete; the
  finalizer wiring awaits the checkpoint-voting subsystem".
- No partial work. No dead code.
- Phase 3b (ZK aggregation) is still unblocked — it's proof
  machinery, independent of whether the checkpoint subsystem is
  live.

Cons:
- Moves the "closure point" of Phase 3a. Operators expecting A.7
  in this release must wait.

**Estimated effort**: zero code in this phase; deferred work
budgeted against Phase 3a.5.

## 4. Recommendation

**Path C** for Phase 3a. **Path B** for Phase 3a.5 when
activation becomes the top priority.

Rationale:
- A.7 was premised on an assumption that turned out to be false.
  Correcting the premise is cheaper than forcing the original
  plan. Path A or B both involve substantive architectural work
  that should be planned separately, not bolted on.
- Phase 3b (ZK retrofit) can proceed on store-layer primitives
  alone. Step 2-5 don't need A.7.
- Path B is the eventual answer but it changes the "A.7 is
  wiring" narrative; a rename to "A.7' — live cert emission"
  is more honest.

Explicit Path C content:

1. Mark Phase 3a A.7 as **Deferred to Phase 3a.5**
   in `v091_phase3a_cert_v2.md` §6.
2. Keep the store API (A.1-A.6) as-is — it's the dependency
   target that Phase 3a.5 will consume.
3. Retain the `NodeMetrics::checkpoint_votes_received` counter
   (zero-incremented today) so its activation signal is ready.
4. Cross-reference this doc from §6 so the blocker is discoverable.

## 5. What Phase 3a.5 will need (forward plan)

For Path B (the likely shape when 3a.5 lands):

1. **Where to insert** (`main.rs:4280` region):
   ```rust
   // Just after `write_committed_state` (R1 step 2) and before
   // the narwhal pruning processor (R6-b integration):
   if let Some(store_v2) = node_v2_hooks.as_ref() {
       let voter_ids = output.leader_voters.clone();  // needs CoreEngine to expose
       let cert_v2 = CertificateV2 { /* from output + voter_ids */ };
       let cert_v1_digest = /* derive from output */;
       let _ = store_v2.put_cert_v2_votes(&cert_v2.digest().0, &cert_v2.vote_refs, &None);
       let _ = store_v2.put_cert_mapping(&cert_v1_digest, &cert_v2.digest().0);
       node_metrics.checkpoint_votes_received.add(voter_ids.len() as u64);
   }
   ```
2. **Missing dependency**: `CoreEngine::propose_block` currently
   doesn't expose per-commit voter lists; `CommittedSubDag`
   carries only the leader and member blocks. Need a minor API
   extension on the DAG side to surface the voters for a commit.
3. **Feature-flag rollout**: gate the whole A.7 block behind
   `NodeConfig::emit_cert_v2 = false` (default) so operators can
   opt in after the schema v3 migration.
4. **Integration test**: 1-node test that runs a few commits and
   asserts the `narwhal_votes` + `narwhal_cert_mapping` CFs are
   non-empty.

## 6. Non-goals for Phase 3a.5

- Consensus rule changes — `CertificateV2` is archival only.
- Wire V2 — same wire format as V1.
- Full `CheckpointManager` subsystem — Path A is explicitly
  **not** the chosen path.
- ZK aggregation — Phase 3b.
