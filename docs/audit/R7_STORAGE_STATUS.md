# R7 Storage Audit — Status and Findings

## Architecture: Primitives exist, wiring absent

| Component | Code Quality | Production Wired |
|-----------|-------------|-----------------|
| WAL (wal.rs, 865 lines) | HIGH | NO — never called |
| RocksBlockStore (block_store.rs, 650 lines) | HIGH | Startup check only |
| UtxoSet (utxo_set.rs) | MEDIUM | YES — but in-memory only |
| JMT (jmt.rs → flat_merkle.rs) | LOW | Misnamed, O(N) not O(log N) |

## Phase 37 Fixes Applied

### C-T7-4: apply_block_atomic Phase 1 outref pre-validation
- Added OutputRef uniqueness check in Phase 1 (before any mutations)
- Prevents partial application: if Phase 2 would fail on add_output,
  Phase 1 now catches it first
- Checks both against existing UTXO set AND intra-block duplicates

### HIGH-T7-1: compute_state_root caching
- Added `cached_state_root: Option<[u8; 32]>` field
- Cached on first compute, invalidated on any mutation
- O(N log N) → O(1) for repeated read RPCs

### HIGH: save_to_file dir fsync fail-fast
- Changed from best-effort `let _ = dir.sync_all()` to fail-fast with error propagation
- Prevents silent data loss on power failure

### HIGH-T7-2: jmt.rs renamed to flat_merkle.rs
- Honest naming: it's a flat sorted Merkle list, not a Jellyfish Merkle Tree
- Real JMT with O(log N) proofs is a v1.1 goal

## v1.1 Storage Roadmap

1. Wire WAL into block apply path (or replace with RocksDB WriteBatch)
2. Make RocksBlockStore the backing store for UtxoSet (not just startup check)
3. Implement real incremental JMT for state proofs
4. Replace 100-block JSON snapshot with per-block RocksDB persistence
5. Add snapshot rotation (keep last N snapshots)
