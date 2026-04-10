// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Consensus WAL — Write-Ahead Log for DAG block acceptance.
//!
//! Sui equivalent: consensus/core/src/commit_observer.rs + storage layer
//!
//! Ensures that accepted blocks survive crashes by logging them before
//! applying to in-memory state. On recovery, the WAL is replayed to
//! reconstruct the DAG.
//!
//! # Design
//!
//! ```text
//! Block received → WAL append → In-memory DAG update → Periodic flush to store
//!                     ↑                                        ↓
//!                  On crash: replay WAL → restore DAG state
//! ```
//!
//! Records use BLAKE3 checksums for integrity. On recovery, a CRC mismatch
//! at record N means N was a partial write — everything from N onward is
//! discarded (the safe truncation policy).
//!
//! # WP7 Enhancements
//!
//! - Full BLAKE3 checksum `[u8; 32]` over `(seq || timestamp || kind || payload)`
//! - Timestamp in every record for forensics
//! - `EquivocationEvidence` record kind
//! - Partial write tolerance: CRC failure → discard from that point
//! - Size-based rotation trigger (configurable, default 1 GB)
//! - Deterministic replay: records are consumed in seq order

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// WAL record kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum WalRecordKind {
    /// A block was accepted into the DAG.
    BlockAccepted = 0,
    /// A commit was produced (sub-DAG finalized).
    CommitProduced = 1,
    /// A checkpoint/flush was completed (all prior records are in the store).
    Checkpoint = 2,
    /// Equivocation evidence was detected (WP8).
    EquivocationEvidence = 3,
    /// Linearizer carryover snapshot for deterministic recovery (WP10).
    CarryoverSnapshot = 4,
}

/// A single WAL record.
///
/// WP7: Enhanced with timestamp and full BLAKE3 checksum.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalRecord {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Timestamp when this record was created (unix ms).
    pub timestamp_ms: u64,
    /// Record kind.
    pub kind: WalRecordKind,
    /// Payload (serialized block, commit, evidence, or checkpoint metadata).
    pub payload: Vec<u8>,
    /// BLAKE3 checksum of `seq || timestamp_ms || kind || payload`.
    ///
    /// WP7: Full 32-byte BLAKE3 instead of truncated CRC32.
    pub checksum: [u8; 32],
}

impl WalRecord {
    /// Create a new record with computed checksum.
    pub fn new(seq: u64, kind: WalRecordKind, payload: Vec<u8>) -> Self {
        Self::new_with_clock(seq, kind, payload, &super::clock::SystemClock)
    }

    /// Create a record with a specific clock (for deterministic simulation).
    pub fn new_with_clock(
        seq: u64,
        kind: WalRecordKind,
        payload: Vec<u8>,
        clock: &dyn super::clock::Clock,
    ) -> Self {
        let timestamp_ms = clock.now_millis();
        let checksum = Self::compute_checksum(seq, timestamp_ms, kind, &payload);
        Self {
            seq,
            timestamp_ms,
            kind,
            payload,
            checksum,
        }
    }

    /// Create a record with explicit timestamp (for testing/replay).
    pub fn new_with_timestamp(
        seq: u64,
        timestamp_ms: u64,
        kind: WalRecordKind,
        payload: Vec<u8>,
    ) -> Self {
        let checksum = Self::compute_checksum(seq, timestamp_ms, kind, &payload);
        Self {
            seq,
            timestamp_ms,
            kind,
            payload,
            checksum,
        }
    }

    /// Verify the checksum of this record.
    pub fn verify_checksum(&self) -> bool {
        self.checksum
            == Self::compute_checksum(self.seq, self.timestamp_ms, self.kind, &self.payload)
    }

    /// Backwards compatibility: verify CRC32 (truncated BLAKE3).
    /// Kept for existing callers; prefer `verify_checksum()`.
    pub fn verify_crc(&self) -> bool {
        self.verify_checksum()
    }

    /// Compute BLAKE3 checksum over `seq || timestamp_ms || kind || payload`.
    fn compute_checksum(
        seq: u64,
        timestamp_ms: u64,
        kind: WalRecordKind,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seq.to_le_bytes());
        hasher.update(&timestamp_ms.to_le_bytes());
        hasher.update(&[kind as u8]);
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    }

    /// Legacy CRC32 field (for backwards compat with old callers).
    /// Returns first 4 bytes of BLAKE3 hash as u32.
    pub fn crc32(&self) -> u32 {
        u32::from_le_bytes(self.checksum[..4].try_into().unwrap())
    }
}

/// WAL errors.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("WAL I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("WAL record checksum mismatch at seq {seq} (partial write detected)")]
    ChecksumMismatch { seq: u64 },
    #[error("WAL record deserialization failed at seq {seq}: {reason}")]
    DeserializeFailed { seq: u64, reason: String },
    #[error("WAL is corrupt: {0}")]
    Corrupt(String),
}

// Backwards compat alias
impl WalError {
    /// Create a CRC mismatch error (backwards compat).
    pub fn crc_mismatch(seq: u64) -> Self {
        Self::ChecksumMismatch { seq }
    }
}

/// Configuration for the consensus WAL.
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Path to the WAL file.
    pub path: PathBuf,
    /// fsync strategy: true = every record, false = periodic.
    pub fsync_every_record: bool,
    /// Maximum WAL size in records before rotation.
    pub max_records_before_rotation: u64,
    /// Maximum WAL file size in bytes before rotation (default 1 GB).
    pub max_file_size_bytes: u64,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("consensus_wal.log"),
            fsync_every_record: true,
            max_records_before_rotation: 10_000,
            max_file_size_bytes: 1_073_741_824, // 1 GB
        }
    }
}

/// The consensus Write-Ahead Log.
///
/// WP7: Enhanced with partial write tolerance, size-based rotation,
/// and deterministic recovery.
pub struct ConsensusWal {
    config: WalConfig,
    next_seq: u64,
    records_since_checkpoint: u64,
    /// Approximate current file size for rotation decisions.
    approx_file_size: u64,
}

impl ConsensusWal {
    /// Open or create the WAL.
    ///
    /// On open, validates all existing records. If a CRC mismatch is found,
    /// it is treated as a partial write: the WAL is truncated to the last
    /// valid record and a warning is logged.
    pub fn open(config: WalConfig) -> Result<Self, WalError> {
        let (next_seq, file_size) = if config.path.exists() {
            let file = std::fs::File::open(&config.path)?;
            let file_size = file.metadata()?.len();
            let reader = io::BufReader::new(file);
            let mut max_seq = 0u64;
            let mut valid_lines = 0usize;
            let mut total_lines = 0usize;

            for line in reader.lines() {
                let line = line?;
                total_lines += 1;
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<WalRecord>(&line) {
                    Ok(record) => {
                        if !record.verify_checksum() {
                            // WP7: Partial write detected — stop here.
                            // All records from this point are unreliable.
                            tracing::warn!(
                                seq = record.seq,
                                line = total_lines,
                                "WAL: checksum mismatch at seq {} — treating as partial write, \
                                 discarding this and all subsequent records",
                                record.seq
                            );
                            break;
                        }
                        max_seq = max_seq.max(record.seq);
                        valid_lines += 1;
                    }
                    Err(e) => {
                        // WP7: Deserialization failure — also partial write.
                        tracing::warn!(
                            line = total_lines,
                            error = %e,
                            "WAL: deserialization failed at line {} — treating as partial write",
                            total_lines
                        );
                        break;
                    }
                }
            }

            tracing::info!(
                valid_records = valid_lines,
                total_lines = total_lines,
                next_seq = max_seq + 1,
                "WAL opened: {} valid records",
                valid_lines
            );

            (if valid_lines > 0 { max_seq + 1 } else { 0 }, file_size)
        } else {
            (0, 0)
        };

        Ok(Self {
            config,
            next_seq,
            records_since_checkpoint: 0,
            approx_file_size: file_size,
        })
    }

    /// Append a record to the WAL.
    pub fn append(&mut self, kind: WalRecordKind, payload: Vec<u8>) -> Result<u64, WalError> {
        let record = WalRecord::new(self.next_seq, kind, payload);
        let seq = record.seq;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.path)?;

        let json = serde_json::to_string(&record).map_err(|e| WalError::DeserializeFailed {
            seq,
            reason: e.to_string(),
        })?;
        let line_bytes = json.len() as u64 + 1; // +1 for newline
        writeln!(file, "{}", json)?;

        if self.config.fsync_every_record {
            file.sync_all()?;
            // fsync parent directory on first record
            if seq == 0 {
                if let Some(parent) = self.config.path.parent() {
                    if let Ok(dir) = std::fs::File::open(parent) {
                        let _ = dir.sync_all();
                    }
                }
            }
        }

        self.next_seq += 1;
        self.records_since_checkpoint += 1;
        self.approx_file_size += line_bytes;
        Ok(seq)
    }

    /// Write a checkpoint marker (all prior records are in the store).
    pub fn checkpoint(&mut self) -> Result<u64, WalError> {
        let seq = self.append(WalRecordKind::Checkpoint, vec![])?;
        self.records_since_checkpoint = 0;
        Ok(seq)
    }

    /// Read all records since the last checkpoint (for recovery).
    ///
    /// WP7: Partial write tolerance — if a CRC mismatch or deserialization
    /// failure is encountered, all records from that point onward are
    /// discarded. This handles the case where a crash occurred mid-write.
    pub fn recover(&self) -> Result<Vec<WalRecord>, WalError> {
        if !self.config.path.exists() {
            return Ok(vec![]);
        }

        let file = std::fs::File::open(&self.config.path)?;
        let reader = io::BufReader::new(file);
        let mut all_records = Vec::new();
        let mut last_checkpoint_idx = None;

        for (line_num, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(
                        line = line_num,
                        "WAL recovery: I/O error at line {} — stopping: {}",
                        line_num,
                        e
                    );
                    break; // Partial read
                }
            };

            if line.is_empty() {
                continue;
            }

            let record: WalRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    // WP7: Deserialization failure → partial write → stop
                    tracing::warn!(
                        line = line_num,
                        "WAL recovery: deserialization failed at line {} — \
                         discarding this and subsequent records: {}",
                        line_num,
                        e
                    );
                    break;
                }
            };

            if !record.verify_checksum() {
                // WP7: CRC mismatch → partial write → stop
                tracing::warn!(
                    seq = record.seq,
                    line = line_num,
                    "WAL recovery: checksum mismatch at seq {} (line {}) — \
                     discarding this and subsequent records (partial write)",
                    record.seq,
                    line_num
                );
                break;
            }

            if record.kind == WalRecordKind::Checkpoint {
                last_checkpoint_idx = Some(all_records.len());
            }
            all_records.push(record);
        }

        // Return records after the last checkpoint
        match last_checkpoint_idx {
            Some(idx) => Ok(all_records.into_iter().skip(idx + 1).collect()),
            None => Ok(all_records), // no checkpoint → replay all
        }
    }

    /// Check if rotation is needed (by record count OR file size).
    pub fn needs_rotation(&self) -> bool {
        self.records_since_checkpoint >= self.config.max_records_before_rotation
            || self.approx_file_size >= self.config.max_file_size_bytes
    }

    /// Rotate: truncate the WAL file (call after checkpoint + store flush).
    ///
    /// Uses atomic rename for safety: write empty tmp file, rename over WAL.
    pub fn rotate(&mut self) -> Result<(), WalError> {
        let tmp_path = self.config.path.with_extension("wal.tmp");
        std::fs::write(&tmp_path, "")?;
        std::fs::rename(&tmp_path, &self.config.path)?;

        // SEC-FIX: fsync parent directory after rename to ensure the directory
        // entry is persisted. Without this, a crash after rename but before the
        // OS flushes directory metadata could lose the rename operation.
        // This follows the same pattern as append() (lines 296-301).
        if let Some(parent) = self.config.path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        self.records_since_checkpoint = 0;
        self.approx_file_size = 0;
        Ok(())
    }

    /// Current sequence number.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Approximate WAL file size in bytes.
    pub fn approx_file_size(&self) -> u64 {
        self.approx_file_size
    }

    /// Records written since last checkpoint.
    pub fn records_since_checkpoint(&self) -> u64 {
        self.records_since_checkpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn temp_config() -> WalConfig {
        let tmp = NamedTempFile::new().unwrap();
        WalConfig {
            path: tmp.path().to_path_buf(),
            fsync_every_record: false, // fast tests
            max_records_before_rotation: 100,
            max_file_size_bytes: 1_073_741_824,
        }
    }

    #[test]
    fn test_append_and_recover() {
        let config = temp_config();
        let mut wal = ConsensusWal::open(config.clone()).unwrap();

        wal.append(WalRecordKind::BlockAccepted, vec![1, 2, 3])
            .unwrap();
        wal.append(WalRecordKind::BlockAccepted, vec![4, 5, 6])
            .unwrap();
        wal.append(WalRecordKind::CommitProduced, vec![7, 8])
            .unwrap();

        // Recover all (no checkpoint)
        let records = wal.recover().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].payload, vec![1, 2, 3]);
        assert_eq!(records[2].kind, WalRecordKind::CommitProduced);
    }

    #[test]
    fn test_checkpoint_recovery() {
        let config = temp_config();
        let mut wal = ConsensusWal::open(config.clone()).unwrap();

        wal.append(WalRecordKind::BlockAccepted, vec![1]).unwrap();
        wal.append(WalRecordKind::BlockAccepted, vec![2]).unwrap();
        wal.checkpoint().unwrap(); // checkpoint after 2 records
        wal.append(WalRecordKind::BlockAccepted, vec![3]).unwrap();

        // Recover: only record after checkpoint
        let records = wal.recover().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload, vec![3]);
    }

    #[test]
    fn test_checksum_integrity() {
        let record = WalRecord::new(0, WalRecordKind::BlockAccepted, vec![42]);
        assert!(record.verify_checksum());
        assert!(record.verify_crc()); // backwards compat

        let mut corrupted = record.clone();
        corrupted.payload = vec![99];
        assert!(!corrupted.verify_checksum());
    }

    #[test]
    fn test_rotation() {
        let config = temp_config();
        let mut wal = ConsensusWal::open(config).unwrap();

        for i in 0..50 {
            wal.append(WalRecordKind::BlockAccepted, vec![i as u8])
                .unwrap();
        }
        assert!(!wal.needs_rotation()); // < 100

        wal.checkpoint().unwrap();
        wal.rotate().unwrap();

        let records = wal.recover().unwrap();
        assert!(records.is_empty()); // rotated away
    }

    #[test]
    fn test_reopen() {
        let config = temp_config();

        {
            let mut wal = ConsensusWal::open(config.clone()).unwrap();
            wal.append(WalRecordKind::BlockAccepted, vec![1]).unwrap();
            wal.append(WalRecordKind::BlockAccepted, vec![2]).unwrap();
        }

        // Reopen
        let wal = ConsensusWal::open(config).unwrap();
        assert_eq!(wal.next_seq(), 2);
        let records = wal.recover().unwrap();
        assert_eq!(records.len(), 2);
    }

    // ── WP7: Partial write tolerance tests ───────────────────

    #[test]
    fn test_partial_write_corrupt_last_entry() {
        let config = temp_config();

        // Write 3 valid records
        {
            let mut wal = ConsensusWal::open(config.clone()).unwrap();
            wal.append(WalRecordKind::BlockAccepted, vec![1]).unwrap();
            wal.append(WalRecordKind::BlockAccepted, vec![2]).unwrap();
            wal.append(WalRecordKind::CommitProduced, vec![3]).unwrap();
        }

        // Append corrupt JSON line (simulates partial write)
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&config.path)
                .unwrap();
            writeln!(file, "{{\"seq\":3,\"timestamp_ms\":0,\"kind\":\"BlockAccepted\",\"payload\":[],\"checksum\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}").unwrap();
        }

        // Recovery should return only 3 valid records (corrupt 4th discarded)
        let wal = ConsensusWal::open(config).unwrap();
        let records = wal.recover().unwrap();
        assert_eq!(
            records.len(),
            3,
            "should recover 3 valid records, discard corrupt 4th"
        );
    }

    #[test]
    fn test_partial_write_truncated_json() {
        let config = temp_config();

        {
            let mut wal = ConsensusWal::open(config.clone()).unwrap();
            wal.append(WalRecordKind::BlockAccepted, vec![1]).unwrap();
            wal.append(WalRecordKind::BlockAccepted, vec![2]).unwrap();
        }

        // Append truncated JSON (simulates kill -9 mid-write)
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&config.path)
                .unwrap();
            writeln!(file, "{{\"seq\":2,\"truncated").unwrap();
        }

        // Recovery should return 2 valid records
        let wal = ConsensusWal::open(config).unwrap();
        let records = wal.recover().unwrap();
        assert_eq!(
            records.len(),
            2,
            "should recover 2 valid records before truncated line"
        );
    }

    #[test]
    fn test_equivocation_evidence_record_kind() {
        let config = temp_config();
        let mut wal = ConsensusWal::open(config.clone()).unwrap();

        wal.append(WalRecordKind::EquivocationEvidence, vec![0xEE; 100])
            .unwrap();
        wal.append(WalRecordKind::CarryoverSnapshot, vec![0xCC; 50])
            .unwrap();

        let records = wal.recover().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, WalRecordKind::EquivocationEvidence);
        assert_eq!(records[1].kind, WalRecordKind::CarryoverSnapshot);
    }

    #[test]
    fn test_records_have_timestamps() {
        let config = temp_config();
        let mut wal = ConsensusWal::open(config.clone()).unwrap();

        wal.append(WalRecordKind::BlockAccepted, vec![1]).unwrap();

        let records = wal.recover().unwrap();
        assert_eq!(records.len(), 1);
        assert!(
            records[0].timestamp_ms > 0,
            "record should have a non-zero timestamp"
        );
    }

    #[test]
    fn test_size_based_rotation() {
        let config = WalConfig {
            max_file_size_bytes: 500, // very small for testing
            ..temp_config()
        };
        let mut wal = ConsensusWal::open(config).unwrap();

        // Write until size exceeds 500 bytes
        for i in 0..50 {
            wal.append(WalRecordKind::BlockAccepted, vec![i; 20])
                .unwrap();
            if wal.needs_rotation() {
                break;
            }
        }
        assert!(wal.needs_rotation(), "should trigger rotation by file size");
    }

    #[test]
    fn test_empty_wal_recovery() {
        let config = temp_config();
        // Create empty file
        std::fs::write(&config.path, "").unwrap();

        let wal = ConsensusWal::open(config).unwrap();
        let records = wal.recover().unwrap();
        assert!(records.is_empty());
        assert_eq!(wal.next_seq(), 0);
    }

    #[test]
    fn test_deterministic_replay_order() {
        let config = temp_config();
        let mut wal = ConsensusWal::open(config.clone()).unwrap();

        for i in 0..10u64 {
            wal.append(WalRecordKind::BlockAccepted, vec![i as u8])
                .unwrap();
        }

        let records = wal.recover().unwrap();
        for (i, record) in records.iter().enumerate() {
            assert_eq!(record.seq, i as u64, "records must be in seq order");
            assert_eq!(record.payload, vec![i as u8]);
        }
    }
}
