# Finality Layers — Responsibility Separation

## Three Layers of Finality

```
Layer 1: Consensus Ordering (misaka-dag)
  UniversalCommitter → CommittedSubDag
  "This sub-DAG is linearly ordered and agreed upon by ≥2f+1"

Layer 2: BFT Finalization (misaka-dag)
  CommitFinalizerV2 → FinalizedSubDag
  "Each TX in this commit is either accepted or rejected"

Layer 3: Economic Finality (misaka-consensus)
  economic_finality.rs → FinalizedEpoch
  "This epoch is economically irreversible (PoS stake weight)"
```

## Data Flow

```
Block → DagState → UniversalCommitter → CommittedSubDag
                                              │
                    CommitFinalizerV2 ←────────┘
                    ├─ direct finalize (no reject → accept)
                    ├─ indirect finalize (wait 3 rounds → accept)
                    └─ reject (quorum reject → drop)
                              │
                    FinalizedSubDag
                              │
                    Linearizer → LinearizedOutput → Executor
                              │
                    CheckpointManager → Checkpoint
                              │
                    BFT Voting (bft.rs) → FinalizedCheckpoint
                              │
                    EconomicFinalityManager (misaka-consensus)
                              │
                    FinalizedEpoch (irreversible)
```

## Responsibility Boundaries

| Responsibility | CommitFinalizerV2 | economic_finality.rs |
|---------------|-------------------|---------------------|
| TX accept/reject | **Yes** | No |
| Reject vote aggregation | **Yes** | No |
| Reorg prevention | **Yes** (monotonic commit index) | **Yes** (epoch boundary) |
| Recovery | **Yes** (recover from last_finalized_index) | **Yes** (attestation replay) |
| Quorum formula | Committee::quorum_threshold() | ValidatorSet::quorum_threshold() |
| Finality type | BFT (≥2f+1 vote) | Economic (PoS stake) |
| Reversibility | Irreversible within epoch | Irreversible across epochs |

## Invariants

1. **Monotonicity**: `highest_finalized` never decreases
2. **Idempotency**: re-processing a finalized commit is a no-op
3. **Completeness**: every CommittedSubDag eventually produces a FinalizedSubDag
4. **No TX loss**: accepted TXs in FinalizedSubDag = committed TXs minus rejected
5. **Layer isolation**: CommitFinalizerV2 never reads economic_finality state
