# Storage Audit R3

## Verified Fixes
- ✅ Snapshot+WAL dedup (CRIT-3): store.rs:200-224 dedup by digest/index

## MEDIUM
- **M6** rocksdb_store.rs:114 — Missing fsync after WriteBatch. Crash in 5-30s window loses data.
  Fix: `db.flush()` or `WriteOptions::set_sync(true)` after critical writes.
