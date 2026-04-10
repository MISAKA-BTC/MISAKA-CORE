# Commit Finalizer Gap Analysis

## Current: 410 lines / 8 pub methods / 6 tests

## Feature Matrix

| Feature | Sui (~lines) | MISAKA status | Gap |
|---------|-------------|---------------|-----|
| Two-phase finalization (direct/indirect) | ~300 | **Implemented** | None |
| TX-level reject voting | ~250 | **Implemented** (process_commit + add_late_reject) | None |
| Reorg prevention | ~200 | **Missing** | HIGH |
| Sub-DAG state recovery | ~150 | **Missing** | HIGH |
| SLO metrics integration | ~100 | **Missing** | MEDIUM |
| GC of finalized state | ~100 | **Missing** | MEDIUM |
| Idempotent re-finalization | ~80 | **Missing** | MEDIUM |
| Downstream notification trait | ~150 | Implicit (take_finalized) | LOW |
| Error handling (Result types) | ~100 | **Missing** (all infallible) | LOW |
| Backpressure on pending queue | ~50 | **Missing** | LOW |

## Implementation Plan (priority order)

### P1: Reorg prevention (~60 lines)
- Track finalized commit indices in a monotonic set
- `is_finalized(commit_index)` → bool
- Reject any attempt to re-process a finalized commit
- Test: attempt to finalize same commit twice → idempotent

### P2: Recovery from storage (~80 lines)
- `recover(last_finalized_index, pending_state)` → restore internal state
- Interface: caller provides what was persisted; finalizer rebuilds
- Test: simulate crash, reconstruct, verify continuity

### P3: SLO metrics (~40 lines)
- Wire `slo_metrics::COMMITS_TOTAL`, `FINALIZER_REJECTED_TXS`
- Observe finality_latency at finalization point
- Test: verify metrics increment after finalization

### P4: GC of old state (~40 lines)
- `gc(below_commit_index)` → remove seen_voters for old commits
- Prevent unbounded memory growth
- Test: 1000 commits → GC → seen_voters size bounded

### P5: Idempotency (~30 lines)
- If same commit_index arrives twice, skip (dedup)
- Test: process same commit twice → output once

### P6: Backpressure (~20 lines)
- Cap pending queue at MAX_PENDING
- Force-finalize oldest if cap reached
- Test: exceed cap → oldest finalized automatically

Total: ~270 new lines. Result: ~680 lines (410 + 270).
