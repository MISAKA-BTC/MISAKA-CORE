# Commit Finalizer — Design Document

## Sui Equivalent
`consensus/core/src/commit_finalizer.rs` (1,617 lines)

## Problem
After the committer (UniversalCommitter) produces a `CommittedSubDag`, the
transactions inside it must go through a finalization pipeline before being
handed to the Executor. The existing `linearizer.rs::CommitFinalizer` only
ensures sequential delivery; it does not handle:

1. **Reject voting** — transactions with ≥f+1 reject votes should be excluded
2. **Byzantine sub-DAG detection** — equivocating blocks in a sub-DAG
3. **Direct vs indirect finalization** — different latency guarantees
4. **GC of stale pending state**

## Responsibility Split

```
                  Ordering Layer                    Finality Layer
                  ─────────────                     ──────────────
 UniversalCommitter → CommittedSubDag
                         │
                         ▼
                 CommitFinalizer (NEW)
                 ├─ direct finalize (no reject votes)
                 ├─ indirect finalize (wait INDIRECT_REJECT_DEPTH rounds)
                 └─ reject (quorum reject votes)
                         │
                         ▼
              Linearizer → LinearizedOutput (EXISTING, unchanged)
                         │
                         ▼
              CommitFinalizer (EXISTING linearizer.rs) → sequential delivery
                         │
                         ▼
              Executor trait (Phase 0) → state transition
                         │
                         ▼
              BFT checkpoint (narwhal_finality/) → economic finality
```

### What CommitFinalizer (new) does:
- Per-TX reject vote aggregation using VoteRegistry
- Direct finalize: no reject votes → immediate output
- Indirect finalize: pending → accepted after INDIRECT_REJECT_DEPTH (3) rounds
- Indirect reject: pending → rejected when reject quorum reached
- Metrics: direct/indirect/rejected counts

### What CommitFinalizer (new) does NOT do:
- Sequential ordering (that's Linearizer's job)
- Economic finality / checkpoint voting (that's narwhal_finality's job)
- Execution (that's the Executor trait's job)
- Reorg handling (reorgs don't exist in Narwhal — once committed, it's final)

### Boundary with narwhal_finality
- `narwhal_finality/bft.rs`: BFT round voting for epoch-level finality
- `narwhal_finality/checkpoint_manager.rs`: checkpoint creation every 100 commits
- New `commit_finalizer.rs`: per-TX finalization within a single commit

The new file sits BETWEEN the committer and the checkpoint system.
It processes individual transactions; the checkpoint system processes
batches of finalized commits.

## File Location
`crates/misaka-dag/src/narwhal_dag/commit_finalizer.rs`

## Key Types
- `CommitFinalizerV2` (to avoid name collision with linearizer.rs)
- `TxFinalizationResult { Accepted, Rejected }`
- `PendingTx { tx_data, accept_stake, reject_stake }`
- `FinalizedSubDag { commit, accepted_txs, rejected_txs }`
