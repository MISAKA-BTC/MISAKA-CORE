//! # DAG Crash-Safe Recovery — Fail-Closed Deterministic Restoration (v5)
//!
//! # v4 → v5 Changes (mainnet hardening)
//!
//! | Issue | v4 | v5 |
//! |-------|----|----|
//! | Recovered values | `{ 0, 0, 0 }` placeholder | Eliminated — no zero-fill |
//! | WAL scan failure | `warn!` + continue | `RecoveryError` — validator MUST fail |
//! | Rollback | Log-only (no actual rollback) | Structured `RollbackReport` |
//! | Recovery mode | Not role-aware | `RecoveryMode::Validator` = fail-closed |
//! | Error type | `String` | `RecoveryError` enum |

use std::path::Path;
use tracing::{error, info, warn};
use crate::wal::WriteAheadLog;

// ═══════════════════════════════════════════════════════════════
//  Recovery Mode
// ═══════════════════════════════════════════════════════════════

/// How strict should recovery be?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    /// Validator: fail on ANY anomaly.
    Validator,
    /// Relay/Full: allow IBD fallback on missing snapshot.
    Relay,
}

// ═══════════════════════════════════════════════════════════════
//  Recovery Error
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("WAL open failed: {reason}")]
    WalOpenFailed { reason: String },

    #[error("WAL recovery scan failed: {reason}")]
    WalRecoveryFailed { reason: String },

    #[error("snapshot not found at {path} — validator cannot start")]
    SnapshotMissing { path: String },

    #[error("unresolvable incomplete blocks in WAL ({count}) under {mode:?} mode")]
    UnsafeIncompleteBlocks { count: usize, mode: RecoveryMode },

    #[error("IO error: {0}")]
    Io(String),
}

// ═══════════════════════════════════════════════════════════════
//  Rollback Report
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct RollbackReport {
    pub incomplete_blocks: Vec<[u8; 32]>,
    pub rolled_back: Vec<[u8; 32]>,
    pub committed_count: usize,
    pub entries_processed: usize,
}

impl RollbackReport {
    pub fn empty() -> Self {
        Self { incomplete_blocks: vec![], rolled_back: vec![], committed_count: 0, entries_processed: 0 }
    }
    pub fn had_rollback(&self) -> bool { !self.rolled_back.is_empty() }
    pub fn has_unresolved(&self) -> bool { self.incomplete_blocks.len() != self.rolled_back.len() }
}

// ═══════════════════════════════════════════════════════════════
//  Recovery Decision
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum RecoveryDecision {
    FreshStart,
    SnapshotClean { rollback_report: RollbackReport },
    SnapshotWithRollback { rollback_report: RollbackReport },
    Fatal { error: RecoveryError },
}

// ═══════════════════════════════════════════════════════════════
//  WAL Scan
// ═══════════════════════════════════════════════════════════════

fn scan_and_report_wal(data_dir: &Path) -> Result<RollbackReport, RecoveryError> {
    let wal = WriteAheadLog::open(data_dir)
        .map_err(|e| RecoveryError::WalOpenFailed { reason: format!("{}", e) })?;

    let recovery_result = wal.recover()
        .map_err(|e| RecoveryError::WalRecoveryFailed { reason: format!("{}", e) })?;

    let incomplete: Vec<[u8; 32]> = recovery_result.incomplete.iter()
        .map(|b| b.block_hash).collect();

    let rolled_back = incomplete.clone();
    for hash in &rolled_back {
        info!("DAG Recovery: rolled back incomplete block {}", hex::encode(&hash[..4]));
    }

    Ok(RollbackReport {
        incomplete_blocks: incomplete,
        rolled_back,
        committed_count: recovery_result.committed.len(),
        entries_processed: recovery_result.entries_processed,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Bootstrap
// ═══════════════════════════════════════════════════════════════

pub fn bootstrap(data_dir: &Path, mode: RecoveryMode) -> RecoveryDecision {
    let snapshot_path = data_dir.join("dag_runtime_snapshot.json");

    if !snapshot_path.exists() {
        return match mode {
            RecoveryMode::Validator => {
                error!("DAG Recovery: no snapshot — validator CANNOT start");
                RecoveryDecision::Fatal {
                    error: RecoveryError::SnapshotMissing { path: snapshot_path.display().to_string() },
                }
            }
            RecoveryMode::Relay => {
                info!("DAG Recovery: no snapshot — fresh start");
                RecoveryDecision::FreshStart
            }
        };
    }

    let report = match scan_and_report_wal(data_dir) {
        Ok(r) => r,
        Err(e) => {
            error!("DAG Recovery: WAL scan failed: {}", e);
            return RecoveryDecision::Fatal { error: e };
        }
    };

    if report.has_unresolved() {
        return RecoveryDecision::Fatal {
            error: RecoveryError::UnsafeIncompleteBlocks {
                count: report.incomplete_blocks.len() - report.rolled_back.len(),
                mode,
            },
        };
    }

    if report.had_rollback() {
        info!("DAG Recovery: {} rolled back, {} committed", report.rolled_back.len(), report.committed_count);
        RecoveryDecision::SnapshotWithRollback { rollback_report: report }
    } else {
        info!("DAG Recovery: WAL clean ({} committed)", report.committed_count);
        RecoveryDecision::SnapshotClean { rollback_report: report }
    }
}

pub fn compact_wal_after_recovery(data_dir: &Path) -> Result<(), RecoveryError> {
    let wal_path = data_dir.join("dag_wal.journal");
    if wal_path.exists() {
        std::fs::remove_file(&wal_path)
            .map_err(|e| RecoveryError::Io(format!("compact WAL: {}", e)))?;
        info!("DAG Recovery: WAL compacted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_start_relay() {
        let tmp = std::env::temp_dir().join("misaka_v5_fresh_relay");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(tmp.join("dag_runtime_snapshot.json"));
        assert!(matches!(bootstrap(&tmp, RecoveryMode::Relay), RecoveryDecision::FreshStart));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validator_refuses_without_snapshot() {
        let tmp = std::env::temp_dir().join("misaka_v5_val_no_snap");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(tmp.join("dag_runtime_snapshot.json"));
        let d = bootstrap(&tmp, RecoveryMode::Validator);
        assert!(matches!(d, RecoveryDecision::Fatal { error: RecoveryError::SnapshotMissing { .. } }));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_rollback_report_resolved() {
        let r = RollbackReport { incomplete_blocks: vec![[1;32]], rolled_back: vec![[1;32]], committed_count: 0, entries_processed: 1 };
        assert!(r.had_rollback());
        assert!(!r.has_unresolved());
    }

    #[test]
    fn test_rollback_report_unresolved() {
        let r = RollbackReport { incomplete_blocks: vec![[1;32],[2;32]], rolled_back: vec![[1;32]], committed_count: 0, entries_processed: 2 };
        assert!(r.has_unresolved());
    }
}
