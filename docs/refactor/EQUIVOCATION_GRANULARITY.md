# Equivocation Detection Granularity — CR-3 Fix (Phase 31)

## Problem

`EquivocationDetector::add_vote` compared on `payload_digest` only.

An attacker could create two blocks with:
- Same (author, round, epoch)
- Same payload
- **Different parents**

Since `payload_digest` was identical, the detector returned `Duplicate`
instead of `Equivocation`. The two blocks, having different parents,
could be accepted into different sub-DAGs, leading to conflicting commits.

## Equivocation definition (Narwhal/Bullshark)

Same `(epoch, author, round)` with **different block_id** (canonical hash).

`block_id` is a hash over ALL block fields:
- epoch, round, author, timestamp
- **ancestors** (parents)
- transactions (payload)
- commit_votes, tx_reject_votes

Different parents → different block_id → equivocation.

## Fix

### SignedVote structure
```rust
pub struct SignedVote {
    pub voter: AuthorityIndex,
    pub slot: VoteSlot,       // (epoch, round)
    pub block_id: [u8; 32],   // canonical hash INCLUDING parents
    pub signature: Vec<u8>,
}
```

### Comparison logic
```rust
match self.seen.get(&key) {
    Some(existing) if existing.block_id == vote.block_id => Duplicate,
    Some(_) => Equivocation,  // different block_id = different block
    None => Accepted,
}
```

### VoteSlot
Explicit `(epoch, round)` struct replacing bare `u64`.

### Storage simplification
Merged `seen` and `seen_full` into single `HashMap<(voter, slot), SignedVote>`.

## VoteRegistry (narwhal_dag) — already correct

`VoteRegistry` uses `BlockRef` (which includes `BlockDigest`) for
vote comparison. Same-payload-different-parents blocks would have
different digests and be correctly flagged. No changes needed.

## Regression tests

1. `cr3_same_payload_different_parents_detected_as_equivocation`
   - Before fix: returns `Duplicate` (BUG)
   - After fix: returns `Equivocation`
2. `cr3_same_block_id_is_duplicate` — positive idempotency test
3. `cr3_different_payload_different_block_id_detected` — baseline
