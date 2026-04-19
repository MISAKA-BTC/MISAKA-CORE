//! Crash Recovery & State Integrity Verification.
//!
//! # Purpose
//!
//! On every node startup, this module verifies the consistency of the
//! persistent database before the node begins accepting blocks or peers.
//! If any inconsistency is detected, the node shuts down safely with a
//! clear error message, rather than running with corrupt state.
//!
//! # History
//!
//! * v0.8.x: backed by `RocksBlockStore::verify_integrity()` which
//!   cross-checked the `state` CF against the `block_meta` CF in
//!   `<data_dir>/chain.db`.
//! * v0.9.0-dev (Phase 2 Path X R1 steps 1-3): Kaspa-aligned
//!   integrity check was introduced in
//!   [`crate::startup_integrity`]; `run_startup_check` ran the new
//!   check first and fell back to the legacy block-store path when
//!   the new keys were absent.
//! * v0.9.0-dev (Phase 2 Path X R1 step 4, this file): legacy
//!   `RocksBlockStore` + its 5-CF keyspace retired. `run_startup_check`
//!   now reads only the Kaspa-aligned committed-tip keys.
//!
//! # Contract
//!
//! `run_startup_check` returns `(height, state_root)` or calls
//! `process::exit(1)`. Callers never observe an inconsistent boot.
//!
//! # Verification Steps
//!
//! 1. **Kaspa-aligned keys**: open the Narwhal consensus RocksDB
//!    read-only, run [`crate::startup_integrity::verify_integrity`]
//!    — which checks that the three committed-tip keys under
//!    `StorePrefixes::VirtualState` are present and self-consistent.
//! 2. **RocksDB WAL recovery**: handled automatically by the Narwhal
//!    consensus store when the node re-opens it read-write for
//!    production use.

use std::time::Instant;
use tracing::{error, info};

/// Outcome of the startup integrity check. Kept in the public surface
/// for callers that want to branch on the three outcomes without
/// relying on `process::exit`.
#[derive(Debug)]
pub enum StartupCheckResult {
    /// Database is consistent. Contains the verified height.
    Ok { height: u64, state_root: [u8; 32] },
    /// Database is inconsistent. Node MUST NOT start.
    Inconsistent { reason: String },
    /// Database does not exist (first run). Proceed with genesis.
    Fresh,
}

/// Verify database integrity on startup, returning the raw outcome.
///
/// This is the library-level API; most callers want
/// [`run_startup_check`] which turns `Inconsistent` into
/// `process::exit(1)` with the operator-facing message.
///
/// # Arguments
///
/// * `data_dir` — Path to the node's data directory.
/// * `narwhal_consensus_subdir` — Subdirectory under `data_dir` that
///   holds the Narwhal consensus RocksDB (typically
///   `"narwhal_consensus"`, matching
///   `RocksDbConsensusStore::open` at `main.rs:1615`).
pub fn verify_startup_integrity(
    data_dir: &std::path::Path,
    narwhal_consensus_subdir: &str,
) -> StartupCheckResult {
    use crate::startup_integrity::{verify_integrity, IntegrityStatus};

    let consensus_path = data_dir.join(narwhal_consensus_subdir);
    let started_at = Instant::now();

    if !consensus_path.exists() {
        info!(
            "No consensus DB found at {} — fresh start",
            consensus_path.display()
        );
        return StartupCheckResult::Fresh;
    }

    info!(
        "Opening consensus DB at {} for integrity check...",
        consensus_path.display()
    );

    // Open read-only so a running node (which holds a write lock) is
    // not disturbed. This is called pre-node-start in practice, but
    // read-only keeps the contract safe.
    let opts = rocksdb::Options::default();
    let db = match rocksdb::DB::open_for_read_only(&opts, &consensus_path, false) {
        Ok(d) => d,
        Err(e) => {
            return StartupCheckResult::Inconsistent {
                reason: format!(
                    "Cannot open consensus DB at '{}' read-only: {}. \
                     The database may be corrupted or locked by another process. \
                     If corruption is suspected, restore from a backup or delete \
                     the data directory and resync from the network.",
                    consensus_path.display(),
                    e,
                ),
            };
        }
    };

    match verify_integrity(&db, None) {
        IntegrityStatus::Ok(state) => {
            info!(
                "Startup integrity check PASSED in {:?}: height={}, state_root={}, db={}",
                started_at.elapsed(),
                state.height,
                hex::encode(&state.state_root[..8]),
                consensus_path.display(),
            );
            StartupCheckResult::Ok {
                height: state.height,
                state_root: state.state_root,
            }
        }
        IntegrityStatus::Fresh => {
            info!(
                "Consensus DB at {} has no committed-tip keys yet — fresh start",
                consensus_path.display(),
            );
            StartupCheckResult::Fresh
        }
        IntegrityStatus::Inconsistent { reason } => StartupCheckResult::Inconsistent { reason },
    }
}

/// Execute the startup check and handle failure.
///
/// Call this at the very beginning of `main()`, before any other
/// initialization. On `Inconsistent`, logs the operator-facing
/// message and calls `process::exit(1)`.
pub fn run_startup_check(
    data_dir: &std::path::Path,
    narwhal_consensus_subdir: &str,
) -> (u64, [u8; 32]) {
    match verify_startup_integrity(data_dir, narwhal_consensus_subdir) {
        StartupCheckResult::Ok { height, state_root } => (height, state_root),
        StartupCheckResult::Fresh => {
            info!("Fresh start — will initialize from genesis");
            (0, [0u8; 32])
        }
        StartupCheckResult::Inconsistent { reason } => abort_with_reason(&reason),
    }
}

fn abort_with_reason(reason: &str) -> ! {
    error!("╔═══════════════════════════════════════════════════════════╗");
    error!("║  DATABASE INTEGRITY CHECK FAILED                        ║");
    error!("╚═══════════════════════════════════════════════════════════╝");
    error!("");
    error!("Reason: {}", reason);
    error!("");
    error!("The node cannot start safely with inconsistent state.");
    error!("Options:");
    error!("  1. Restore from a known-good backup");
    error!("  2. Delete the data directory and resync from the network");
    error!("  3. Contact the MISAKA team for manual recovery assistance");
    error!("");
    error!("DO NOT attempt to run the node with corrupt state —");
    error!("this could cause consensus forks or loss of funds.");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn nonexistent_dir_is_fresh() {
        let tmp = TempDir::new().unwrap();
        let result = verify_startup_integrity(tmp.path(), "does_not_exist");
        matches!(result, StartupCheckResult::Fresh);
    }

    #[test]
    fn fresh_consensus_db_with_no_keys_is_fresh() {
        let tmp = TempDir::new().unwrap();
        let consensus_path = tmp.path().join("narwhal_consensus");
        // Create an empty DB (no committed-tip keys written).
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let _db = rocksdb::DB::open(&opts, &consensus_path).unwrap();
        drop(_db);

        let result = verify_startup_integrity(tmp.path(), "narwhal_consensus");
        matches!(result, StartupCheckResult::Fresh);
    }

    #[test]
    fn roundtrip_persisted_tip_is_ok() {
        use crate::startup_integrity::{write_committed_state, CommittedState};

        let tmp = TempDir::new().unwrap();
        let consensus_path = tmp.path().join("narwhal_consensus");
        {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = rocksdb::DB::open(&opts, &consensus_path).unwrap();
            let state = CommittedState {
                height: 42,
                state_root: [0xAB; 32],
                tip_hash: [0xCD; 32],
            };
            write_committed_state(&db, &state).unwrap();
        }
        // Re-open (the write handle drops first to release the lock).
        let result = verify_startup_integrity(tmp.path(), "narwhal_consensus");
        match result {
            StartupCheckResult::Ok { height, state_root } => {
                assert_eq!(height, 42);
                assert_eq!(state_root, [0xAB; 32]);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn partial_write_is_inconsistent() {
        use crate::db_key::DbKey;
        use crate::store_registry::StorePrefixes;

        let tmp = TempDir::new().unwrap();
        let consensus_path = tmp.path().join("narwhal_consensus");
        {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = rocksdb::DB::open(&opts, &consensus_path).unwrap();
            // Write only committed_height, leave the other two absent.
            let key = DbKey::new_with_bucket(
                &StorePrefixes::VirtualState.prefix_bytes(),
                b"committed_height",
                [] as [u8; 0],
            );
            db.put(key.as_ref(), 1u64.to_le_bytes()).unwrap();
        }
        let result = verify_startup_integrity(tmp.path(), "narwhal_consensus");
        match result {
            StartupCheckResult::Inconsistent { reason } => {
                assert!(
                    reason.to_ascii_lowercase().contains("partial"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
    }
}
