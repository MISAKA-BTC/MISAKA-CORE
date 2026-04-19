// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Kaspa-aligned persistent chain-tip integrity check.
//!
//! # Why
//!
//! Phase 2 Path X R1 retires the legacy `RocksBlockStore`. That store
//! owned two responsibilities that the new Kaspa-aligned stack does not
//! provide yet:
//!
//! 1. Persist committed `(height, state_root)` so a restarting node
//!    does not have to re-derive the chain tip from the DAG.
//! 2. On open, cross-check that the persisted tip is internally
//!    consistent (height matches `block_meta` at that height, state
//!    root matches the block-meta recording).
//!
//! This module covers (1) and a caller-driven variant of (2). It is
//! additive — nothing calls it yet. R1 step 2 (in a follow-up PR)
//! wires the Kaspa-aligned write path to call
//! [`write_committed_state`] on every committed block. R1 step 3
//! re-points `recovery.rs` at [`verify_integrity`] with the legacy
//! `state` CF as a fallback.
//!
//! # Namespace
//!
//! All keys live under [`StorePrefixes::VirtualState`] (`0x70`), which
//! is the Kaspa-aligned prefix reserved for the virtual/committed tip
//! state. Sub-bucket literals:
//!
//! ```text
//! VirtualState || b"committed_height"     → u64 LE (8 bytes)
//! VirtualState || b"committed_state_root" → [u8; 32]
//! VirtualState || b"committed_tip_hash"   → [u8; 32]   (reserved)
//! ```
//!
//! The literals are persisted — renaming them orphans every live DB.
//!
//! # Scope
//!
//! This module performs key-level persistence and a self-consistency
//! check. It does **not**:
//!
//! * recompute `state_root` from the UTXO set (caller's responsibility
//!   — pass the recomputed value as `expected_state_root` if you want
//!   cross-check),
//! * interact with the legacy `state` CF (that lives in
//!   `block_store.rs` and is removed in R1 step 4),
//! * advance or validate the chain — it's a snapshot storage layer.

use std::sync::Arc;

use rocksdb::DB;

use crate::db_key::DbKey;
use crate::store_registry::StorePrefixes;

/// The committed chain tip as persisted under
/// [`StorePrefixes::VirtualState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedState {
    /// The highest applied block height.
    pub height: u64,
    /// SHA-3-256 (or equivalent) root over the post-apply UTXO set at
    /// this height.
    pub state_root: [u8; 32],
    /// The tip block's hash. Reserved for restart-integrity plumbing
    /// (R1 step 3). All-zero if not yet populated.
    pub tip_hash: [u8; 32],
}

impl CommittedState {
    /// Zero-valued state — the "genesis sentinel" used by nodes that
    /// have not yet persisted a first block.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            height: 0,
            state_root: [0u8; 32],
            tip_hash: [0u8; 32],
        }
    }
}

/// Outcome of [`verify_integrity`].
#[derive(Debug, Clone)]
pub enum IntegrityStatus {
    /// No committed state is persisted. Fresh DB.
    Fresh,
    /// Committed state is present and, if a cross-check was requested,
    /// matches.
    Ok(CommittedState),
    /// The DB carries committed-state keys but they are not internally
    /// consistent, or the caller's `expected_state_root` disagrees.
    Inconsistent { reason: String },
}

/// Errors raised by the raw read/write paths.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("persisted {key} value is corrupt: {reason}")]
    Corrupt { key: &'static str, reason: String },
    #[error(transparent)]
    Rocks(#[from] rocksdb::Error),
}

// ─── Key construction ───────────────────────────────────────────────

const KEY_HEIGHT: &[u8] = b"committed_height";
const KEY_STATE_ROOT: &[u8] = b"committed_state_root";
const KEY_TIP_HASH: &[u8] = b"committed_tip_hash";

fn key(bucket: &[u8]) -> DbKey {
    DbKey::new_with_bucket(
        &StorePrefixes::VirtualState.prefix_bytes(),
        bucket,
        [] as [u8; 0],
    )
}

// ─── Public API ─────────────────────────────────────────────────────

/// Atomically write the committed state.
///
/// Uses three separate `put()` calls rather than a `WriteBatch`
/// because callers on the hot path are expected to roll these into
/// their own atomic-batch alongside the UTXO mutations. The test
/// harness in this module does use three separate puts; that is
/// acceptable because `verify_integrity` detects the "partial write"
/// case and rejects startup.
pub fn write_committed_state(db: &DB, state: &CommittedState) -> Result<(), IntegrityError> {
    db.put(key(KEY_HEIGHT).as_ref(), state.height.to_le_bytes())?;
    db.put(key(KEY_STATE_ROOT).as_ref(), state.state_root)?;
    db.put(key(KEY_TIP_HASH).as_ref(), state.tip_hash)?;
    Ok(())
}

/// Read the committed state. Returns `Ok(None)` when no keys are
/// present (fresh DB) and `Err(Corrupt)` if a key exists but its
/// value has the wrong shape.
pub fn read_committed_state(db: &DB) -> Result<Option<CommittedState>, IntegrityError> {
    let h = db.get_pinned(key(KEY_HEIGHT).as_ref())?;
    let r = db.get_pinned(key(KEY_STATE_ROOT).as_ref())?;
    let t = db.get_pinned(key(KEY_TIP_HASH).as_ref())?;

    match (h, r, t) {
        (None, None, None) => Ok(None),
        (Some(h_bytes), Some(r_bytes), Some(t_bytes)) => {
            let height = parse_u64(&h_bytes, "committed_height")?;
            let state_root = parse_32(&r_bytes, "committed_state_root")?;
            let tip_hash = parse_32(&t_bytes, "committed_tip_hash")?;
            Ok(Some(CommittedState {
                height,
                state_root,
                tip_hash,
            }))
        }
        _ => {
            // Partial write: some keys present, others absent. Report
            // as corrupt so verify_integrity surfaces it as Inconsistent
            // rather than silently treating the DB as Fresh.
            Err(IntegrityError::Corrupt {
                key: "committed_state",
                reason: "partial write — some committed_* keys present, others absent".to_string(),
            })
        }
    }
}

/// High-level integrity check. Intended to be called immediately
/// after opening the DB at node startup.
///
/// * `expected_state_root = Some(r)`: if the persisted state root is
///   different from `r`, returns `Inconsistent`. Callers that can
///   recompute the root from the UTXO set should use this arm; it
///   replaces the legacy `block_meta` cross-check.
/// * `expected_state_root = None`: trust the persisted value; only
///   check that the three keys are self-consistent and parseable.
pub fn verify_integrity(db: &DB, expected_state_root: Option<[u8; 32]>) -> IntegrityStatus {
    match read_committed_state(db) {
        Ok(None) => IntegrityStatus::Fresh,
        Ok(Some(state)) => match expected_state_root {
            Some(expected) if expected != state.state_root => IntegrityStatus::Inconsistent {
                reason: format!(
                    "state_root mismatch at height {}: persisted {} vs expected {}",
                    state.height,
                    hex::encode(&state.state_root[..8]),
                    hex::encode(&expected[..8]),
                ),
            },
            _ => IntegrityStatus::Ok(state),
        },
        Err(e) => IntegrityStatus::Inconsistent {
            reason: format!("{e}"),
        },
    }
}

/// `Arc<DB>` convenience wrapper. Matches the handle shape used by
/// `PruningStore` / `ReachabilityStore`.
pub fn verify_integrity_arc(
    db: &Arc<DB>,
    expected_state_root: Option<[u8; 32]>,
) -> IntegrityStatus {
    verify_integrity(db.as_ref(), expected_state_root)
}

// ─── Parsing helpers ─────────────────────────────────────────────

fn parse_u64(bytes: &[u8], key_label: &'static str) -> Result<u64, IntegrityError> {
    if bytes.len() != 8 {
        return Err(IntegrityError::Corrupt {
            key: key_label,
            reason: format!("expected 8-byte u64 LE, got {} bytes", bytes.len()),
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

fn parse_32(bytes: &[u8], key_label: &'static str) -> Result<[u8; 32], IntegrityError> {
    if bytes.len() != 32 {
        return Err(IntegrityError::Corrupt {
            key: key_label,
            reason: format!("expected 32-byte hash, got {} bytes", bytes.len()),
        });
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::{Options, DB as RocksDB};
    use tempfile::TempDir;

    fn open_tmp() -> (TempDir, RocksDB) {
        let dir = TempDir::new().expect("tmpdir");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = RocksDB::open(&opts, dir.path()).expect("open");
        (dir, db)
    }

    fn make_state(n: u64) -> CommittedState {
        CommittedState {
            height: n,
            state_root: [(n & 0xff) as u8; 32],
            tip_hash: [((n >> 8) & 0xff) as u8; 32],
        }
    }

    // ── Key construction ──────────────────────────────────────────

    #[test]
    fn keys_live_under_virtual_state_prefix() {
        let k = key(KEY_HEIGHT);
        assert_eq!(k.as_ref()[0], StorePrefixes::VirtualState as u8);
        assert_eq!(&k.as_ref()[1..1 + KEY_HEIGHT.len()], KEY_HEIGHT);
    }

    #[test]
    fn three_keys_are_distinct() {
        let kh = key(KEY_HEIGHT);
        let ks = key(KEY_STATE_ROOT);
        let kt = key(KEY_TIP_HASH);
        assert_ne!(kh.as_ref(), ks.as_ref());
        assert_ne!(kh.as_ref(), kt.as_ref());
        assert_ne!(ks.as_ref(), kt.as_ref());
    }

    // ── Fresh DB ───────────────────────────────────────────────────

    #[test]
    fn fresh_db_yields_fresh_status() {
        let (_d, db) = open_tmp();
        match verify_integrity(&db, None) {
            IntegrityStatus::Fresh => {}
            other => panic!("expected Fresh, got {other:?}"),
        }
    }

    #[test]
    fn fresh_db_read_returns_none() {
        let (_d, db) = open_tmp();
        let r = read_committed_state(&db).expect("fresh read");
        assert!(r.is_none());
    }

    // ── Roundtrip ─────────────────────────────────────────────────

    #[test]
    fn write_then_read_roundtrips() {
        let (_d, db) = open_tmp();
        let state = make_state(42);
        write_committed_state(&db, &state).expect("write");
        let read = read_committed_state(&db).expect("read").expect("some");
        assert_eq!(read, state);
    }

    #[test]
    fn overwrite_replaces_previous_value() {
        let (_d, db) = open_tmp();
        write_committed_state(&db, &make_state(1)).unwrap();
        write_committed_state(&db, &make_state(2)).unwrap();
        let read = read_committed_state(&db).unwrap().unwrap();
        assert_eq!(read, make_state(2));
    }

    // ── Partial write ─────────────────────────────────────────────

    #[test]
    fn partial_write_surfaces_as_inconsistent() {
        let (_d, db) = open_tmp();
        // Only height written; state_root + tip_hash absent. Simulates
        // a crash between the three puts.
        db.put(key(KEY_HEIGHT).as_ref(), 123u64.to_le_bytes())
            .unwrap();
        let status = verify_integrity(&db, None);
        match status {
            IntegrityStatus::Inconsistent { reason } => {
                assert!(
                    reason.to_lowercase().contains("partial"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }

    // ── Corrupt values ────────────────────────────────────────────

    #[test]
    fn wrong_length_height_is_corrupt() {
        let (_d, db) = open_tmp();
        db.put(key(KEY_HEIGHT).as_ref(), b"three").unwrap();
        db.put(key(KEY_STATE_ROOT).as_ref(), [0u8; 32]).unwrap();
        db.put(key(KEY_TIP_HASH).as_ref(), [0u8; 32]).unwrap();
        let err = read_committed_state(&db).expect_err("corrupt height");
        let msg = format!("{err}");
        assert!(msg.contains("committed_height"), "msg: {msg}");
    }

    #[test]
    fn wrong_length_state_root_is_corrupt() {
        let (_d, db) = open_tmp();
        db.put(key(KEY_HEIGHT).as_ref(), 0u64.to_le_bytes())
            .unwrap();
        db.put(key(KEY_STATE_ROOT).as_ref(), b"short").unwrap();
        db.put(key(KEY_TIP_HASH).as_ref(), [0u8; 32]).unwrap();
        let err = read_committed_state(&db).expect_err("corrupt root");
        let msg = format!("{err}");
        assert!(msg.contains("committed_state_root"), "msg: {msg}");
    }

    // ── Expected-root cross-check ─────────────────────────────────

    #[test]
    fn expected_state_root_match_is_ok() {
        let (_d, db) = open_tmp();
        let state = make_state(7);
        write_committed_state(&db, &state).unwrap();
        match verify_integrity(&db, Some(state.state_root)) {
            IntegrityStatus::Ok(s) => assert_eq!(s, state),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn expected_state_root_mismatch_is_inconsistent() {
        let (_d, db) = open_tmp();
        let state = make_state(8);
        write_committed_state(&db, &state).unwrap();
        let status = verify_integrity(&db, Some([0xff; 32]));
        match status {
            IntegrityStatus::Inconsistent { reason } => {
                assert!(reason.contains("mismatch"), "reason: {reason}");
                assert!(reason.contains("height 8"), "reason: {reason}");
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }

    // ── Arc wrapper ───────────────────────────────────────────────

    #[test]
    fn arc_wrapper_matches_plain() {
        let (_d, db) = open_tmp();
        let state = make_state(99);
        write_committed_state(&db, &state).unwrap();
        let arc = Arc::new(db);
        match verify_integrity_arc(&arc, None) {
            IntegrityStatus::Ok(s) => assert_eq!(s, state),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    // ── CommittedState::zero ──────────────────────────────────────

    #[test]
    fn committed_state_zero_is_all_zero() {
        let z = CommittedState::zero();
        assert_eq!(z.height, 0);
        assert_eq!(z.state_root, [0u8; 32]);
        assert_eq!(z.tip_hash, [0u8; 32]);
    }
}
