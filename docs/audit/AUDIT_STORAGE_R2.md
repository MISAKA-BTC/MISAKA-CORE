# Storage Audit R2

## Scope: crates/misaka-storage/ + misaka-dag/narwhal_dag/store.rs + rocksdb_store.rs

## CRITICAL

### C1: Snapshot restore double-apply (recovery.rs:183-208)
- **Problem:** `recover()` loads snapshot then replays ALL WAL entries unconditionally. Blocks already in snapshot are applied twice.
- **Attack:** State divergence on crash recovery. DagState gets duplicate block entries.
- **Fix:** Track checkpoint WAL sequence number. Filter WAL replay to entries after snapshot seq.

## HIGH

### H1: Missing fsync after RocksDB WriteBatch (rocksdb_store.rs)
- ext4 metadata flush can take 30s. Crash in that window loses committed batch.
- Fix: `dir.sync_all()` after `db.write(wb)`.

## MEDIUM

### M1: Recovery doesn't enforce incomplete block cleanup (wal.rs:236-307)
- Incomplete blocks identified but not forcibly removed before DagState init.
- Fix: Make cleanup mandatory before `recover_dag_state()`.
