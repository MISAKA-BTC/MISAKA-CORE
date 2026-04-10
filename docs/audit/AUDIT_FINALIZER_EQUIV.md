# Finalizer Equivocation Audit R2

## Scope: commit_finalizer.rs + vote_registry.rs + dag_state.rs

## Status: Previously audited findings RESOLVED

### HashMap overwrite → VoteRegistry (BTreeMap)
- Phase 11-13 introduced `VoteRegistry` with `BTreeMap` and explicit `VoteResult::Equivocation`.
- `BlockAcceptResult::AcceptedWithEquivocation` surfaced to callers.
- core_engine.rs logs equivocation on accept + unsuspend paths.

### Remaining concern: MEDIUM
- commit_finalizer.rs `add_late_reject()` deduplicates by `(commit_index, voter)` via `seen_voters` HashMap. If the same voter submits contradictory reject votes for the same commit (reject TX A in one block, reject TX B in another), only the first is counted.
- This is correct behavior (voter's first vote is authoritative), but the contradictory vote is not flagged as equivocation. A `VoteEquivocation` event should be emitted for monitoring.
- **Severity:** MEDIUM (no safety impact, monitoring gap).
