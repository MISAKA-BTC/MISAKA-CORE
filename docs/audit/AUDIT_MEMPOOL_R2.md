# Mempool Audit R2

## Scope: crates/misaka-mempool/src/

## CRITICAL

### C1: Nullifier dedup race condition (lib.rs:147-186)
- **Problem:** `spent_nullifiers` and `nullifiers_mempool` HashSets checked then inserted without lock. Two threads can both pass the conflict check before either inserts.
- **Attack:** Submit same nullifier from two concurrent threads → both admitted → double-spend at block validation.
- **Fix:** Wrap `admit()` in Mutex, or use `DashMap` with `entry()` API for atomic check-and-insert.

## HIGH

### H1: No Replace-by-Fee mechanism (lib.rs:117-121)
- **Problem:** Duplicate tx_hash returns early. No way to bump fee on stuck TX.
- **Attack:** Attacker submits low-fee TX, clogs mempool slot indefinitely.
- **Fix:** RBF with fee_increase ≥ 1.25x minimum.

## MEDIUM

### M1: Nullifier eviction is O(N×M) scan (lib.rs:209-214)
- Full mempool scan per nullifier on block commit. DoS with large mempool.
- Fix: Reverse index `nullifier → Vec<tx_hash>`.

## LOW

### L1: TX hash encoding not formally documented as canonical (lib.rs:521-533)
### L2: Per-peer rate limit bypassable via botnet (admission_pipeline.rs)
