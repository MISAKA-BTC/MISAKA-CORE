# Leader Scoring — Design Document

## Sui Equivalent
`consensus/core/src/leader_scoring.rs` (317 lines)

## Problem
The existing `leader_schedule.rs` has basic reputation scores (commit-based
+1 per block author). Mysticeti uses a more sophisticated distributed vote
scoring that better captures actual network contribution.

## Algorithm: Distributed Vote Scoring

For each committed sub-DAG:
1. For each block B in the sub-DAG:
2. For each strong-linked parent P of B (P.round == B.round - 1):
3. P.author receives B.author's stake as score

Strong links only (round-adjacent). Weak links (skip-round references)
are ignored because they don't prove timely propagation.

```
Round 3: [B0, B1, B2, B3]  (each with stake 1)
Round 2: [L0, L1, L2, L3]  (leader at L0)

B0 → L0, L1, L2  → L0.author gets +1, L1.author gets +1, L2.author gets +1
B1 → L0, L1, L3  → L0.author gets +1, L1.author gets +1, L3.author gets +1
B2 → L0, L2, L3  → L0.author gets +1, L2.author gets +1, L3.author gets +1
B3 → L1, L2, L3  → L1.author gets +1, L2.author gets +1, L3.author gets +1

Result: L0=3, L1=3, L2=3, L3=2 (B0 didn't reference L3)
```

L3 has lower score because fewer blocks in the next round included it
→ worse propagation → less likely to be elected leader.

## Relationship to Existing Code

- `leader_schedule.rs::ReputationScores`: basic +1 per author per commit.
  → Still used as the data container. The new scoring module populates it.
- `ancestor.rs::AncestorSelector`: consumes scores to exclude slow authorities.
  → New scoring feeds into this.
- `core_engine.rs::update_ancestor_scores()`: entry point for score updates.

## Score Update Cadence
Every `SCORING_UPDATE_INTERVAL` commits (default: 300).
The scoring sub-DAG accumulates votes over this window, then
produces a new `ReputationScores` that replaces the current one.

## File Location
`crates/misaka-dag/src/narwhal_dag/leader_scoring.rs`

## Key Types
- `ScoringSubDag` — accumulator for vote scoring across commits
- `DistributedVoteScorer` — computes scores from accumulated data
- Uses existing `ReputationScores` from `leader_schedule.rs`
