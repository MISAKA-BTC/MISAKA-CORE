//! Crash Recovery & State Integrity Verification.
//!
//! # Purpose
//!
//! On every node startup, this module verifies the consistency of the
//! persistent database before the node begins accepting blocks or peers.
//! If any inconsistency is detected, the node shuts down safely with a
//! clear error message, rather than running with corrupt state.
//!
//! # Verification Steps
//!
//! 1. **Height Consistency**: The committed height in the `state` CF matches
//!    the last `block_meta` entry.
//! 2. **State Root Consistency**: The state root in `state` CF matches the
//!    root recorded in the last block's metadata.
//! 3. **WAL Recovery**: RocksDB automatically replays its WAL on open,
//!    recovering any partially-written `WriteBatch` operations.
//!
//! # Failure Modes
//!
//! | Scenario                          | Recovery                              |
//! |-----------------------------------|---------------------------------------|
//! | Clean shutdown                    | No action needed                      |
//! | Crash before WriteBatch commit    | WAL replay undoes partial writes      |
//! | Crash after WriteBatch commit     | WAL replay completes the write        |
//! | Corrupted CF data                 | Detected → safe shutdown + resync log |
//! | Missing block_meta at tip height  | Detected → safe shutdown + resync log |

use std::time::Instant;
use tracing::{error, info};

/// Result of startup integrity verification.
#[derive(Debug)]
pub enum StartupCheckResult {
    /// Database is consistent. Contains the verified height.
    Ok { height: u64, state_root: [u8; 32] },
    /// Database is inconsistent. Node MUST NOT start.
    Inconsistent { reason: String },
    /// Database does not exist (first run). Proceed with genesis.
    Fresh,
}

/// Verify database integrity on startup.
///
/// This function MUST be called before the node starts processing blocks.
/// If it returns `Inconsistent`, the node MUST exit immediately.
///
/// # Arguments
///
/// * `data_dir` - Path to the node's data directory
///
/// # Returns
///
/// * `StartupCheckResult::Ok` — safe to proceed
/// * `StartupCheckResult::Inconsistent` — MUST exit with error
/// * `StartupCheckResult::Fresh` — first run, create genesis
pub fn verify_startup_integrity(data_dir: &std::path::Path) -> StartupCheckResult {
    let db_path = data_dir.join("chain.db");
    let started_at = Instant::now();

    // Check if database exists
    if !db_path.exists() {
        info!(
            "No existing database found at {} — fresh start",
            db_path.display()
        );
        return StartupCheckResult::Fresh;
    }

    // Open database (RocksDB will replay WAL automatically)
    info!(
        "Opening database at {} for integrity check...",
        db_path.display()
    );
    let store = match crate::RocksBlockStore::open(&db_path, false) {
        Ok(s) => s,
        Err(e) => {
            return StartupCheckResult::Inconsistent {
                reason: format!(
                    "Cannot open database at '{}': {}. \
                     The database may be corrupted or locked by another process. \
                     If corruption is suspected, restore from a backup or \
                     delete the data directory and resync from the network.",
                    db_path.display(),
                    e
                ),
            };
        }
    };

    // Run integrity verification
    match store.verify_integrity() {
        Ok(height) => {
            let state_root = match store.get_state_root() {
                Ok(r) => r,
                Err(e) => {
                    return StartupCheckResult::Inconsistent {
                        reason: format!("Failed to read state root: {e}"),
                    };
                }
            };
            info!(
                "Startup integrity check PASSED in {:?}: height={}, state_root={}, db={}",
                started_at.elapsed(),
                height,
                hex::encode(&state_root[..8]),
                db_path.display()
            );
            StartupCheckResult::Ok { height, state_root }
        }
        Err(e) => StartupCheckResult::Inconsistent {
            reason: format!("{e}"),
        },
    }
}

/// Execute the startup check and handle failure.
///
/// This is the main entry point for crash recovery. Call this at the
/// very beginning of `main()`, before any other initialization.
///
/// If the database is inconsistent, this function logs the error and
/// calls `std::process::exit(1)`.
pub fn run_startup_check(data_dir: &std::path::Path) -> (u64, [u8; 32]) {
    match verify_startup_integrity(data_dir) {
        StartupCheckResult::Ok { height, state_root } => (height, state_root),
        StartupCheckResult::Fresh => {
            info!("Fresh start — will initialize from genesis");
            (0, [0u8; 32])
        }
        StartupCheckResult::Inconsistent { reason } => {
            abort_with_reason(&reason);
        }
    }
}

/// Phase 2 Path X R1 step 3 — Kaspa-aligned-aware startup check.
///
/// Preference order:
///
/// 1. Kaspa-aligned committed-tip keys under
///    `StorePrefixes::VirtualState` in the Narwhal consensus RocksDB
///    at `<data_dir>/<narwhal_consensus_subdir>` (typically
///    `"narwhal_consensus"`). This is the path populated by R1 step 2.
/// 2. Legacy `state` CF inside `<data_dir>/chain.db` via the existing
///    `RocksBlockStore`-backed integrity check, when (1) returns
///    `Fresh` (new keys absent). Preserves recovery for DBs upgraded
///    from pre-R1-step-2 builds.
/// 3. Treat as `Fresh` when both are absent.
///
/// On corruption in (1) or (2), aborts with `process::exit(1)` exactly
/// like [`run_startup_check`]. Callers therefore see either a
/// `(height, state_root)` pair to trust or a clean exit — never an
/// inconsistent boot.
///
/// This function is side-effect free w.r.t. the DB (it does not stamp
/// or repair anything). R1 step 4, a follow-up, will delete the
/// legacy fallback once enough testnet time has elapsed on step 2
/// data.
pub fn run_startup_check_kaspa_aware(
    data_dir: &std::path::Path,
    narwhal_consensus_subdir: &str,
) -> (u64, [u8; 32]) {
    use crate::startup_integrity::{verify_integrity, IntegrityStatus};

    let consensus_path = data_dir.join(narwhal_consensus_subdir);
    if consensus_path.exists() {
        // Open read-only so a running node (which holds a write lock)
        // is not disturbed. This should only be called pre-node-start
        // in practice, but read-only keeps the contract safe.
        let opts = rocksdb::Options::default();
        match rocksdb::DB::open_for_read_only(&opts, &consensus_path, false) {
            Ok(db) => match verify_integrity(&db, None) {
                IntegrityStatus::Ok(state) => {
                    info!(
                        "Kaspa-aligned startup check PASSED: height={}, state_root={}, db={}",
                        state.height,
                        hex::encode(&state.state_root[..8]),
                        consensus_path.display()
                    );
                    return (state.height, state.state_root);
                }
                IntegrityStatus::Inconsistent { reason } => {
                    abort_with_reason(&reason);
                }
                IntegrityStatus::Fresh => {
                    // Keys absent — fall through to legacy path so
                    // DBs written by pre-R1-step-2 builds still boot.
                }
            },
            Err(e) => {
                // Not fatal on its own — the DB may simply not be
                // initialised yet (fresh node that has never called
                // RocksDbConsensusStore::open). Fall through.
                info!(
                    "Kaspa-aligned consensus DB at {} is not openable read-only ({}); \
                     falling back to legacy recovery.",
                    consensus_path.display(),
                    e,
                );
            }
        }
    }

    // Legacy fallback.
    run_startup_check(data_dir)
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
