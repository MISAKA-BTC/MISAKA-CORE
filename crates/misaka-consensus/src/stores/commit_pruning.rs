// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal-native commit-pruning store.
//!
//! # Phase 2 Path X R6-b (Option W)
//!
//! The legacy [`super::pruning::DbPruningStore`] was designed for
//! GhostDAG pruning (blue-score walks). v6 of this codebase removed
//! GhostDAG consensus entirely, so that store and its consumer
//! [`super::super::pipeline::pruning_processor::PruningProcessor`]
//! became test-only scaffolding with no production instantiation.
//!
//! R6-b Option W replaces the GhostDAG-bound design with a pruning
//! primitive that operates on Narwhal [`CommitIndex`]es: a monotonic
//! u64 per committed sub-DAG. No blue-score, no selected-parent walk
//! — just "the latest commit index we've decided is safe to prune
//! below".
//!
//! # What this store persists
//!
//! Two singleton keys under
//! [`misaka_storage::StorePrefixes::PruningPoint`] (`0x30`):
//!
//! ```text
//! PruningPoint || b"committed_pruning_index"     → u64 LE  (CommitIndex)
//! PruningPoint || b"committed_pruning_timestamp" → u64 LE  (timestamp_ms)
//! ```
//!
//! Both values are written together via [`DbCommitPruningStore::set`]
//! and read together via [`DbCommitPruningStore::get`]. A partial
//! write (one present, the other absent) is reported as [`CommitPruningError::Corrupt`].
//!
//! # Why not reuse the legacy prefix?
//!
//! The legacy `DbPruningStore` lives in a separate store-prefix
//! registry ([`misaka_database::registry::DatabaseStorePrefixes::PruningPoint`]
//! = `13`) and a separate RocksDB instance. The new store lives in
//! the Narwhal consensus RocksDB (the same DB as R5's schema_version
//! marker and R1's `startup_integrity` committed tip) under
//! `misaka_storage::StorePrefixes::PruningPoint = 0x30`. Sharing one
//! DB instance keeps backup/atomicity simple.

use std::sync::Arc;

use misaka_storage::db_key::DbKey;
use misaka_storage::store_registry::StorePrefixes;
use rocksdb::DB;
use serde::{Deserialize, Serialize};

/// Latest decision from the Narwhal pruning processor. Everything
/// with `commit_index <= self.commit_index` is deletable by downstream
/// GC (e.g. `misaka_dag::narwhal_dag::rocksdb_store::gc_below_round`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitPruningInfo {
    /// The latest commit index below which data may be pruned.
    pub commit_index: u64,
    /// The commit's timestamp — lets operators correlate the pruning
    /// point with wall-clock events in logs / dashboards.
    pub timestamp_ms: u64,
}

/// Errors raised by [`DbCommitPruningStore`].
#[derive(Debug, thiserror::Error)]
pub enum CommitPruningError {
    #[error("persisted {key} value is corrupt: {reason}")]
    Corrupt { key: &'static str, reason: String },
    #[error(transparent)]
    Rocks(#[from] rocksdb::Error),
}

const KEY_INDEX: &[u8] = b"committed_pruning_index";
const KEY_TIMESTAMP: &[u8] = b"committed_pruning_timestamp";

fn key(bucket: &[u8]) -> DbKey {
    DbKey::new_with_bucket(
        &StorePrefixes::PruningPoint.prefix_bytes(),
        bucket,
        [] as [u8; 0],
    )
}

/// Single-DB wrapper for the Narwhal commit-pruning info.
///
/// Thin by design — the algorithmic decisions live in
/// [`crate::pipeline::narwhal_pruning_processor::NarwhalPruningProcessor`].
#[derive(Clone)]
pub struct DbCommitPruningStore {
    db: Arc<DB>,
}

impl DbCommitPruningStore {
    /// Construct from a shared `Arc<DB>`.
    #[must_use]
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    /// Read the current commit-pruning info.
    ///
    /// * `Ok(None)` — neither key present: store has never been
    ///   written (fresh node, or `PruneMode::Archival`).
    /// * `Ok(Some(info))` — both keys present and parseable.
    /// * `Err(Corrupt)` — one of the two keys is present but the
    ///   other is missing, or a value has the wrong byte length.
    pub fn get(&self) -> Result<Option<CommitPruningInfo>, CommitPruningError> {
        let idx_bytes = self.db.get_pinned(key(KEY_INDEX).as_ref())?;
        let ts_bytes = self.db.get_pinned(key(KEY_TIMESTAMP).as_ref())?;

        match (idx_bytes, ts_bytes) {
            (None, None) => Ok(None),
            (Some(i), Some(t)) => {
                let commit_index = parse_u64(&i, "committed_pruning_index")?;
                let timestamp_ms = parse_u64(&t, "committed_pruning_timestamp")?;
                Ok(Some(CommitPruningInfo {
                    commit_index,
                    timestamp_ms,
                }))
            }
            _ => Err(CommitPruningError::Corrupt {
                key: "commit_pruning_info",
                reason: "partial write — one of the two commit_pruning_* keys is absent"
                    .to_string(),
            }),
        }
    }

    /// Write the commit-pruning info.
    ///
    /// Uses two sequential `put()` calls rather than a batch. The
    /// `get()` side detects the partial-write window and reports it
    /// as `Corrupt` — callers (only `NarwhalPruningProcessor`) can
    /// then either retry or report to the operator.
    pub fn set(&mut self, info: &CommitPruningInfo) -> Result<(), CommitPruningError> {
        self.db
            .put(key(KEY_INDEX).as_ref(), info.commit_index.to_le_bytes())?;
        self.db
            .put(key(KEY_TIMESTAMP).as_ref(), info.timestamp_ms.to_le_bytes())?;
        Ok(())
    }
}

fn parse_u64(bytes: &[u8], key_label: &'static str) -> Result<u64, CommitPruningError> {
    if bytes.len() != 8 {
        return Err(CommitPruningError::Corrupt {
            key: key_label,
            reason: format!("expected 8-byte u64 LE, got {} bytes", bytes.len()),
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::{Options, DB as RocksDB};
    use tempfile::TempDir;

    fn open_tmp() -> (TempDir, Arc<RocksDB>) {
        let dir = TempDir::new().expect("tmpdir");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = RocksDB::open(&opts, dir.path()).expect("open");
        (dir, Arc::new(db))
    }

    #[test]
    fn keys_live_under_pruning_point_prefix() {
        let k = key(KEY_INDEX);
        assert_eq!(k.as_ref()[0], StorePrefixes::PruningPoint as u8);
        assert_eq!(&k.as_ref()[1..1 + KEY_INDEX.len()], KEY_INDEX);
    }

    #[test]
    fn two_keys_are_distinct() {
        let k1 = key(KEY_INDEX);
        let k2 = key(KEY_TIMESTAMP);
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn fresh_store_returns_none() {
        let (_d, db) = open_tmp();
        let store = DbCommitPruningStore::new(db);
        assert!(store.get().expect("fresh get").is_none());
    }

    #[test]
    fn set_then_get_roundtrips() {
        let (_d, db) = open_tmp();
        let mut store = DbCommitPruningStore::new(db);
        let info = CommitPruningInfo {
            commit_index: 12_345,
            timestamp_ms: 1_700_000_000_000,
        };
        store.set(&info).expect("set");
        let got = store.get().expect("get").expect("some");
        assert_eq!(got, info);
    }

    #[test]
    fn overwrite_replaces() {
        let (_d, db) = open_tmp();
        let mut store = DbCommitPruningStore::new(db);
        store
            .set(&CommitPruningInfo {
                commit_index: 1,
                timestamp_ms: 100,
            })
            .unwrap();
        store
            .set(&CommitPruningInfo {
                commit_index: 2,
                timestamp_ms: 200,
            })
            .unwrap();
        let got = store.get().unwrap().unwrap();
        assert_eq!(got.commit_index, 2);
        assert_eq!(got.timestamp_ms, 200);
    }

    #[test]
    fn partial_write_is_corrupt() {
        let (_d, db) = open_tmp();
        // Write only the index key, leave timestamp absent.
        db.put(key(KEY_INDEX).as_ref(), 7u64.to_le_bytes()).unwrap();
        let store = DbCommitPruningStore::new(db);
        let err = store.get().expect_err("partial write");
        let msg = format!("{err}");
        assert!(
            msg.to_ascii_lowercase().contains("partial"),
            "error should mention partial: {msg}"
        );
    }

    #[test]
    fn wrong_length_index_is_corrupt() {
        let (_d, db) = open_tmp();
        db.put(key(KEY_INDEX).as_ref(), b"short").unwrap();
        db.put(key(KEY_TIMESTAMP).as_ref(), 0u64.to_le_bytes())
            .unwrap();
        let store = DbCommitPruningStore::new(db);
        let err = store.get().expect_err("corrupt index");
        let msg = format!("{err}");
        assert!(msg.contains("committed_pruning_index"), "msg: {msg}");
    }

    #[test]
    fn wrong_length_timestamp_is_corrupt() {
        let (_d, db) = open_tmp();
        db.put(key(KEY_INDEX).as_ref(), 0u64.to_le_bytes()).unwrap();
        db.put(key(KEY_TIMESTAMP).as_ref(), b"bad").unwrap();
        let store = DbCommitPruningStore::new(db);
        let err = store.get().expect_err("corrupt ts");
        let msg = format!("{err}");
        assert!(msg.contains("committed_pruning_timestamp"), "msg: {msg}");
    }
}
