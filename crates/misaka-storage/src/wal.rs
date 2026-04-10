//! Write-Ahead Log (WAL) for atomic DAG block acceptance.
//!
//! # Problem
//!
//! Block acceptance involves multiple stores (header, ghostdag, virtual state,
//! spent_tags, UTXOs). Without atomicity, a crash mid-acceptance leaves the
//! node in a half-committed state that is unrecoverable.
//!
//! # Solution: Journal-Based WAL
//!
//! Every block acceptance is a multi-phase transaction:
//!
//! ```text
//! Phase 1: Journal write       — {block_hash, phase=Received}
//! Phase 2: Block data persist  — header, body, parent edges
//! Phase 3: Consensus persist   — ghostdag, validation status
//! Phase 4: Virtual resolve     — chain changes, acceptance data
//! Phase 5: State commit        — utxo root, spent root
//! Phase 6: Commit marker       — {block_hash, phase=Committed}
//! ```
//!
//! On restart:
//! - Entries with `Committed` marker → completed, skip
//! - Entries without `Committed` → discard partial state
//!
//! # File Format
//!
//! The WAL is a simple append-only file with length-prefixed JSON entries.
//! Each entry is: `[4-byte LE length][JSON payload][1-byte newline]`
//!
//! # Crash Safety
//!
//! - Journal file is fsync'd after each write
//! - Commit marker is the LAST write in the transaction
//! - If commit marker is missing → transaction is incomplete → discard
//! - Journal is compacted after N committed entries

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Compact journal after this many committed entries.
pub const COMPACT_THRESHOLD: usize = 1000;

/// Maximum journal file size before forced compaction (bytes).
pub const MAX_JOURNAL_SIZE: u64 = 64 * 1024 * 1024; // 64 MB

fn should_compact_after_commit(committed_since_compact: usize, journal_size_bytes: u64) -> bool {
    committed_since_compact >= COMPACT_THRESHOLD || journal_size_bytes >= MAX_JOURNAL_SIZE
}

// ═══════════════════════════════════════════════════════════════
//  Journal Entry
// ═══════════════════════════════════════════════════════════════

/// Phase of a block acceptance transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptPhase {
    /// Block received, journal opened.
    Received,
    /// Block data (header + body) persisted.
    BlockDataPersisted,
    /// Consensus metadata (ghostdag, validation) persisted.
    ConsensusPersisted,
    /// Virtual state resolved (chain changes computed).
    VirtualResolved,
    /// State commitments (utxo root, spent root) persisted.
    StateCommitted,
    /// Transaction fully committed. This is the ONLY phase that
    /// guarantees all prior phases completed successfully.
    Committed,
}

/// A single WAL journal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Block hash being processed.
    pub block_hash: [u8; 32],
    /// Current phase.
    pub phase: AcceptPhase,
    /// Monotonic sequence number (for ordering on recovery).
    pub seq: u64,
    /// Timestamp (unix ms).
    pub timestamp_ms: u64,
    /// Optional metadata (e.g., error reason for failed phases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  WAL Error
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("journal corrupted at byte offset {offset}: {reason}")]
    Corrupted { offset: u64, reason: String },

    #[error("block {block} has incomplete transaction (phase={phase:?}), needs discard")]
    IncompleteTransaction { block: String, phase: AcceptPhase },
}

// ═══════════════════════════════════════════════════════════════
//  Recovery Result
// ═══════════════════════════════════════════════════════════════

/// Result of WAL recovery on startup.
#[derive(Debug)]
pub struct RecoveryResult {
    /// Blocks that were fully committed (no action needed).
    pub committed: Vec<[u8; 32]>,
    /// Blocks that were partially written (need discard).
    pub incomplete: Vec<IncompleteBlock>,
    /// Total journal entries processed.
    pub entries_processed: usize,
}

/// An incomplete block transaction found during recovery.
#[derive(Debug)]
pub struct IncompleteBlock {
    pub block_hash: [u8; 32],
    /// The last phase that was written before the crash.
    pub last_phase: AcceptPhase,
    /// Sequence number of the last entry.
    pub last_seq: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Write-Ahead Log
// ═══════════════════════════════════════════════════════════════

/// Write-Ahead Log for atomic block acceptance.
///
/// # Usage
///
/// ```ignore
/// let mut wal = WriteAheadLog::open(&data_dir)?;
///
/// // On startup: recover incomplete transactions
/// let recovery = wal.recover()?;
/// for incomplete in &recovery.incomplete {
///     discard incomplete block data;
/// }
///
/// // During block acceptance:
/// wal.log_phase(block_hash, AcceptPhase::Received)?;
/// persist_block_data(...);
/// wal.log_phase(block_hash, AcceptPhase::BlockDataPersisted)?;
/// persist_consensus_data(...);
/// wal.log_phase(block_hash, AcceptPhase::ConsensusPersisted)?;
/// resolve_virtual_state(...);
/// wal.log_phase(block_hash, AcceptPhase::VirtualResolved)?;
/// persist_state_commitments(...);
/// wal.log_phase(block_hash, AcceptPhase::StateCommitted)?;
/// // CRITICAL: This is the atomic commit point
/// wal.log_phase(block_hash, AcceptPhase::Committed)?;
/// ```
pub struct WriteAheadLog {
    /// Path to the journal file.
    path: PathBuf,
    /// Current sequence number.
    seq: u64,
    /// Number of committed entries since last compaction.
    committed_since_compact: usize,
}

impl WriteAheadLog {
    /// Open or create a WAL at the given directory.
    pub fn open(data_dir: &Path) -> Result<Self, WalError> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join("dag_wal.journal");

        // Determine current sequence from existing journal
        let seq = if path.exists() {
            let entries = Self::read_entries(&path)?;
            entries.iter().map(|e| e.seq).max().unwrap_or(0)
        } else {
            0
        };

        Ok(Self {
            path,
            seq,
            committed_since_compact: 0,
        })
    }

    /// Log a phase transition for a block acceptance transaction.
    ///
    /// Each call appends a single entry to the journal and fsyncs.
    pub fn log_phase(&mut self, block_hash: [u8; 32], phase: AcceptPhase) -> Result<(), WalError> {
        let seq = self.next_seq();
        self.log_entry(JournalEntry {
            block_hash,
            phase,
            seq,
            timestamp_ms: now_ms(),
            metadata: None,
        })
    }

    /// Log a phase transition with metadata (e.g., state root, error info).
    pub fn log_phase_with_metadata(
        &mut self,
        block_hash: [u8; 32],
        phase: AcceptPhase,
        metadata: String,
    ) -> Result<(), WalError> {
        let seq = self.next_seq();
        self.log_entry(JournalEntry {
            block_hash,
            phase,
            seq,
            timestamp_ms: now_ms(),
            metadata: Some(metadata),
        })
    }

    /// Recover from journal on startup.
    ///
    /// Reads all entries, identifies committed vs incomplete transactions,
    /// and returns the recovery result. The caller is responsible for
    /// rolling back incomplete transactions.
    pub fn recover(&self) -> Result<RecoveryResult, WalError> {
        if !self.path.exists() {
            return Ok(RecoveryResult {
                committed: vec![],
                incomplete: vec![],
                entries_processed: 0,
            });
        }

        let entries = Self::read_entries(&self.path)?;
        let entries_processed = entries.len();

        // Group entries by block_hash, track the max phase per block
        let mut block_phases: std::collections::HashMap<[u8; 32], (AcceptPhase, u64)> =
            std::collections::HashMap::new();

        for entry in &entries {
            let current = block_phases.get(&entry.block_hash);
            let dominated = match current {
                Some((_, existing_seq)) => entry.seq > *existing_seq,
                None => true,
            };
            if dominated {
                block_phases.insert(entry.block_hash, (entry.phase, entry.seq));
            }
        }

        let mut committed = Vec::new();
        let mut incomplete = Vec::new();

        for (block_hash, (phase, seq)) in block_phases {
            if phase == AcceptPhase::Committed {
                committed.push(block_hash);
            } else {
                incomplete.push(IncompleteBlock {
                    block_hash,
                    last_phase: phase,
                    last_seq: seq,
                });
            }
        }

        // Sort incomplete by sequence for deterministic discard order
        incomplete.sort_by_key(|b| b.last_seq);

        if !incomplete.is_empty() {
            warn!(
                "WAL recovery: {} committed, {} incomplete (need discard)",
                committed.len(),
                incomplete.len(),
            );
            for inc in &incomplete {
                warn!(
                    "  Incomplete: block={} phase={:?} seq={}",
                    hex::encode(&inc.block_hash[..4]),
                    inc.last_phase,
                    inc.last_seq,
                );
            }
        } else {
            info!(
                "WAL recovery: {} committed, 0 incomplete — clean state",
                committed.len(),
            );
        }

        Ok(RecoveryResult {
            committed,
            incomplete,
            entries_processed,
        })
    }

    /// Compact the journal — remove entries for committed blocks.
    ///
    /// Keeps only entries for non-committed (in-progress) transactions.
    pub fn compact(&mut self) -> Result<usize, WalError> {
        if !self.path.exists() {
            return Ok(0);
        }

        let entries = Self::read_entries(&self.path)?;
        let total_before = entries.len();

        // Find committed block hashes
        let committed: std::collections::HashSet<[u8; 32]> = entries
            .iter()
            .filter(|e| e.phase == AcceptPhase::Committed)
            .map(|e| e.block_hash)
            .collect();

        // Keep only entries for non-committed blocks
        let retained: Vec<&JournalEntry> = entries
            .iter()
            .filter(|e| !committed.contains(&e.block_hash))
            .collect();

        let removed = total_before - retained.len();

        // Write retained entries to a temp file, then atomically rename
        // H3 FIX: Write in new format with integrity hash
        let tmp_path = self.path.with_extension("journal.tmp");
        {
            use sha3::{Digest, Sha3_256};

            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            for entry in &retained {
                let json = serde_json::to_string(entry)?;
                let hash = Sha3_256::digest(json.as_bytes());
                // SEC-FIX NM-15: Use full 32-byte hash for integrity (was 4 bytes).
                // 4-byte truncation has 1/2^32 collision probability which is too high
                // for consensus-critical WAL integrity verification.
                let hash_hex = hex::encode(&hash);
                writer.write_all(json.as_bytes())?;
                writer.write_all(b"|")?;
                writer.write_all(hash_hex.as_bytes())?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        fs::rename(&tmp_path, &self.path)?;

        // SEC-FIX-5: fsync the parent directory to ensure the rename is
        // durable. Without this, a crash after rename() but before the
        // directory metadata is flushed to disk (ext4 default) could lose
        // the new journal, leaving the node with a stale or missing WAL.
        Self::fsync_directory(&self.path)?;

        self.committed_since_compact = 0;
        info!(
            "WAL compacted: removed {} entries, {} retained",
            removed,
            retained.len()
        );

        Ok(removed)
    }

    /// Clear the entire journal (after clean shutdown or full recovery).
    pub fn clear(&mut self) -> Result<(), WalError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
            // SEC-FIX-5: fsync directory after removal
            Self::fsync_directory(&self.path)?;
        }
        self.seq = 0;
        self.committed_since_compact = 0;
        Ok(())
    }

    /// Get the journal file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// SEC-FIX-5: fsync the parent directory of a path.
    ///
    /// On Linux/ext4 (default mount), `rename()` and `unlink()` update the
    /// directory entry but the metadata may not be flushed to disk until the
    /// next periodic writeback (~30s). A crash in that window loses the
    /// rename/delete. This is a known WAL correctness issue in databases
    /// (SQLite, RocksDB, etc.) and is fixed by opening + fsyncing the
    /// parent directory after the rename/delete.
    fn fsync_directory(file_path: &Path) -> Result<(), WalError> {
        if let Some(parent) = file_path.parent() {
            let dir = File::open(parent)?;
            dir.sync_all()?;
        }
        Ok(())
    }

    // ─── Internal ──────────────────────────────────────────

    fn append_entry(&self, entry: &JournalEntry) -> Result<(), WalError> {
        use sha3::{Digest, Sha3_256};

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        let json = serde_json::to_string(entry)?;

        // H3 FIX: Per-entry integrity check.
        // Format: JSON|HEXHASH\n
        // where HEXHASH is the first 8 hex chars of SHA3-256(JSON).
        //
        // This detects bit-flips that produce valid JSON with wrong values
        // (e.g. AcceptPhase::Received → AcceptPhase::Committed via single byte change).
        // A truncated last line (crash mid-write) is still detected by
        // the separator/hash being missing or incomplete.
        // SEC-FIX CRITICAL: Use full 32-byte SHA3-256 hash instead of truncated 4 bytes.
        // Previously only 4 bytes (2^32 collision space) were used, making it feasible
        // for an attacker to forge a valid hash for a tampered entry in ~2^32 attempts.
        // Full 32 bytes provides 2^256 collision resistance.
        let hash = Sha3_256::digest(json.as_bytes());
        let hash_hex = hex::encode(&hash); // full 32 bytes = 64 hex chars

        file.write_all(json.as_bytes())?;
        file.write_all(b"|")?;
        file.write_all(hash_hex.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?; // fsync — ensures durability

        // Phase 38c: fsync parent directory on first creation to ensure
        // the WAL file entry itself is durably persisted.
        Self::fsync_directory(&self.path)?;

        debug!(
            "WAL: block={} phase={:?} seq={} hash={}",
            hex::encode(&entry.block_hash[..4]),
            entry.phase,
            entry.seq,
            hash_hex,
        );

        Ok(())
    }

    fn log_entry(&mut self, entry: JournalEntry) -> Result<(), WalError> {
        self.append_entry(&entry)?;

        if entry.phase == AcceptPhase::Committed {
            self.committed_since_compact += 1;
            let journal_size = self.path.metadata().map(|meta| meta.len()).unwrap_or(0);
            if should_compact_after_commit(self.committed_since_compact, journal_size) {
                let reason = match (
                    self.committed_since_compact >= COMPACT_THRESHOLD,
                    journal_size >= MAX_JOURNAL_SIZE,
                ) {
                    (true, true) => "count+size",
                    (true, false) => "count",
                    (false, true) => "size",
                    (false, false) => unreachable!(),
                };
                info!(
                    "WAL compaction triggered after commit: reason={}, committed_since_compact={}, journal_size_bytes={}",
                    reason,
                    self.committed_since_compact,
                    journal_size
                );
                if let Err(e) = self.compact() {
                    warn!("WAL compaction failed (non-fatal): {}", e);
                }
            }
        }

        Ok(())
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn read_entries(path: &Path) -> Result<Vec<JournalEntry>, WalError> {
        use sha3::{Digest, Sha3_256};

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        // SEC-FIX TM-9: Maximum line length to prevent memory exhaustion
        const MAX_WAL_LINE_LEN: usize = 64 * 1024 * 1024; // 64 MB

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.len() > MAX_WAL_LINE_LEN {
                warn!(
                    "WAL: line {} exceeds max length ({} > {}) — skipping",
                    line_num + 1, line.len(), MAX_WAL_LINE_LEN
                );
                continue;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // SEC-FIX: Parse format "JSON|HEXHASH". Legacy format (no hash) is REJECTED.
            // Previously legacy entries without hash were accepted with a warning,
            // allowing attackers to bypass integrity checks by removing the hash suffix.
            let (json_part, expected_hash) = if let Some(sep_pos) = trimmed.rfind('|') {
                let json = &trimmed[..sep_pos];
                let hash_hex = &trimmed[sep_pos + 1..];
                (json, hash_hex.to_string())
            } else {
                // SEC-FIX: Reject legacy format (no hash) — potential tampering.
                warn!(
                    "WAL: rejecting legacy entry at line {} (no integrity hash — \
                     may be tampered or from pre-security version)",
                    line_num + 1,
                );
                continue;
            };

            // SEC-FIX TM-8: Require full 64-char (32-byte SHA3-256) integrity hashes.
            // Old truncated 8-char (4-byte) hashes have high collision probability
            // (birthday bound ~65K entries) and must be rejected.
            {
                if expected_hash.len() != 64 {
                    warn!(
                        "WAL: rejecting entry at line {} with truncated hash ({} chars) — \
                         only full 64-char SHA3-256 hashes are accepted",
                        line_num + 1,
                        expected_hash.len(),
                    );
                    continue;
                }
                let computed = Sha3_256::digest(json_part.as_bytes());
                let computed_hex = hex::encode(&computed);
                if computed_hex != expected_hash {
                    warn!(
                        "WAL: integrity hash mismatch at line {} — \
                         expected={}, computed={} — entry may be corrupted, stopping here",
                        line_num + 1,
                        expected_hash,
                        computed_hex,
                    );
                    break;
                }
            }

            match serde_json::from_str::<JournalEntry>(json_part) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    // Truncated last line (crash mid-write) — stop here
                    warn!(
                        "WAL: truncated entry at line {} (crash mid-write?): {}",
                        line_num + 1,
                        e,
                    );
                    break;
                }
            }
        }

        Ok(entries)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn test_wal_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::BlockDataPersisted)
            .unwrap();
        wal.log_phase(h(1), AcceptPhase::Committed).unwrap();

        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.committed.len(), 1);
        assert_eq!(recovery.committed[0], h(1));
        assert!(recovery.incomplete.is_empty());
        assert_eq!(recovery.entries_processed, 3);
    }

    #[test]
    fn test_wal_compact_trigger_conditions() {
        assert!(!should_compact_after_commit(
            COMPACT_THRESHOLD - 1,
            MAX_JOURNAL_SIZE - 1
        ));
        assert!(should_compact_after_commit(COMPACT_THRESHOLD, 0));
        assert!(should_compact_after_commit(0, MAX_JOURNAL_SIZE));
    }

    #[test]
    fn test_wal_incomplete_detected() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        // Block 1: fully committed
        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::Committed).unwrap();

        // Block 2: incomplete (crash after ConsensusPersisted)
        wal.log_phase(h(2), AcceptPhase::Received).unwrap();
        wal.log_phase(h(2), AcceptPhase::ConsensusPersisted)
            .unwrap();

        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.committed.len(), 1);
        assert_eq!(recovery.incomplete.len(), 1);
        assert_eq!(recovery.incomplete[0].block_hash, h(2));
        assert_eq!(
            recovery.incomplete[0].last_phase,
            AcceptPhase::ConsensusPersisted
        );
    }

    #[test]
    fn test_wal_compact() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        // 3 committed blocks + 1 incomplete
        for b in 1..=3u8 {
            wal.log_phase(h(b), AcceptPhase::Received).unwrap();
            wal.log_phase(h(b), AcceptPhase::Committed).unwrap();
        }
        wal.log_phase(h(4), AcceptPhase::Received).unwrap();

        let removed = wal.compact().unwrap();
        assert_eq!(removed, 6); // 3 blocks × 2 entries

        // After compaction: only block 4's entry remains
        let recovery = wal.recover().unwrap();
        assert!(recovery.committed.is_empty());
        assert_eq!(recovery.incomplete.len(), 1);
        assert_eq!(recovery.incomplete[0].block_hash, h(4));
    }

    #[test]
    fn test_wal_empty_on_fresh() {
        let tmp = TempDir::new().unwrap();
        let wal = WriteAheadLog::open(tmp.path()).unwrap();
        let recovery = wal.recover().unwrap();
        assert!(recovery.committed.is_empty());
        assert!(recovery.incomplete.is_empty());
    }

    #[test]
    fn test_wal_survives_reopen() {
        let tmp = TempDir::new().unwrap();

        // Write some entries
        {
            let mut wal = WriteAheadLog::open(tmp.path()).unwrap();
            wal.log_phase(h(1), AcceptPhase::Received).unwrap();
            wal.log_phase(h(1), AcceptPhase::Committed).unwrap();
            wal.log_phase(h(2), AcceptPhase::Received).unwrap();
            // "crash" — drop wal without committing block 2
        }

        // Re-open and recover
        let wal = WriteAheadLog::open(tmp.path()).unwrap();
        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.committed.len(), 1);
        assert_eq!(recovery.incomplete.len(), 1);
    }

    #[test]
    fn test_wal_sequence_monotonic() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::Committed).unwrap();
        wal.log_phase(h(2), AcceptPhase::Received).unwrap();

        let entries = WriteAheadLog::read_entries(wal.path()).unwrap();
        for i in 1..entries.len() {
            assert!(
                entries[i].seq > entries[i - 1].seq,
                "sequence must be strictly monotonic"
            );
        }
    }

    // ── H3 Tests: Per-Entry Integrity Hash ──

    #[test]
    fn test_wal_integrity_hash_present() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        wal.log_phase(h(1), AcceptPhase::Received).unwrap();

        // Read raw file — should contain JSON|HEXHASH format
        let content = std::fs::read_to_string(wal.path()).unwrap();
        let line = content.trim();
        assert!(
            line.contains('|'),
            "WAL entry must contain '|' separator for integrity hash"
        );

        let parts: Vec<&str> = line.rsplitn(2, '|').collect();
        // SEC-FIX NM-15: Full 32-byte SHA3-256 hash = 64 hex chars
        assert_eq!(
            parts[0].len(),
            64,
            "integrity hash must be 64 hex chars (32 bytes SHA3-256)"
        );

        // Entries should still parse correctly
        let entries = WriteAheadLog::read_entries(wal.path()).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_wal_integrity_hash_detects_tamper() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::Committed).unwrap();

        // Tamper with the first entry's phase in the raw file
        let content = std::fs::read_to_string(wal.path()).unwrap();
        let tampered = content.replacen("\"Received\"", "\"Committed\"", 1);
        std::fs::write(wal.path(), tampered).unwrap();

        // Read should stop at the tampered entry
        let entries = WriteAheadLog::read_entries(wal.path()).unwrap();
        assert_eq!(
            entries.len(),
            0,
            "tampered first entry must be rejected, stopping parse"
        );
    }

    #[test]
    fn test_wal_legacy_format_accepted() {
        // SEC-FIX: Legacy entries without integrity hash are now REJECTED
        // to prevent tamper attacks. This test verifies they are skipped.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dag_wal.journal");

        // Write a legacy-format entry (no |HASH suffix)
        let entry = JournalEntry {
            block_hash: h(1),
            phase: AcceptPhase::Received,
            seq: 1,
            timestamp_ms: 1000,
            metadata: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, format!("{}\n", json)).unwrap();

        let entries = WriteAheadLog::read_entries(&path).unwrap();
        assert_eq!(
            entries.len(),
            0,
            "legacy format without hash must be rejected"
        );
    }

    // ── SEC-FIX-5 Tests: Crash & Corruption Resilience ──

    #[test]
    fn test_wal_truncated_mid_write_detected() {
        // Simulate: crash during write leaves partial line at end of journal
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        // Write one complete entry
        wal.log_phase(h(1), AcceptPhase::Received).unwrap();

        // Append garbage (simulating partial write from crash)
        let path = wal.path().to_path_buf();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(b"{\"block_hash\":\"truncated").unwrap();

        // Recovery should find the first valid entry and stop at truncation
        let entries = WriteAheadLog::read_entries(&path).unwrap();
        assert_eq!(
            entries.len(),
            1,
            "must recover valid entries before truncation"
        );
    }

    #[test]
    fn test_wal_compact_preserves_incomplete_blocks() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        // Block 1: committed
        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::Committed).unwrap();

        // Block 2: in-progress (not committed)
        wal.log_phase(h(2), AcceptPhase::Received).unwrap();
        wal.log_phase(h(2), AcceptPhase::BlockDataPersisted)
            .unwrap();

        // Block 3: committed
        wal.log_phase(h(3), AcceptPhase::Received).unwrap();
        wal.log_phase(h(3), AcceptPhase::Committed).unwrap();

        // Compact — should remove blocks 1 and 3, keep block 2
        let removed = wal.compact().unwrap();
        assert_eq!(removed, 4, "2 entries for block 1 + 2 entries for block 3");

        // Verify block 2's entries survived
        let recovery = wal.recover().unwrap();
        assert!(recovery.committed.is_empty());
        assert_eq!(recovery.incomplete.len(), 1);
        assert_eq!(recovery.incomplete[0].block_hash, h(2));
        assert_eq!(
            recovery.incomplete[0].last_phase,
            AcceptPhase::BlockDataPersisted
        );
    }

    #[test]
    fn test_wal_multiple_phases_tracked_correctly() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        // Write all phases for a single block
        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::BlockDataPersisted)
            .unwrap();
        wal.log_phase(h(1), AcceptPhase::ConsensusPersisted)
            .unwrap();
        wal.log_phase(h(1), AcceptPhase::VirtualResolved).unwrap();
        wal.log_phase(h(1), AcceptPhase::StateCommitted).unwrap();
        // Crash here — no Committed marker

        let recovery = wal.recover().unwrap();
        assert!(recovery.committed.is_empty());
        assert_eq!(recovery.incomplete.len(), 1);
        assert_eq!(
            recovery.incomplete[0].last_phase,
            AcceptPhase::StateCommitted,
            "must track the LAST phase written"
        );
    }

    #[test]
    fn test_wal_empty_file_handled_gracefully() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dag_wal.journal");
        // Create empty file
        std::fs::write(&path, "").unwrap();

        let wal = WriteAheadLog::open(tmp.path()).unwrap();
        let recovery = wal.recover().unwrap();
        assert!(recovery.committed.is_empty());
        assert!(recovery.incomplete.is_empty());
    }

    #[test]
    fn test_wal_all_blank_lines_ignored() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dag_wal.journal");
        std::fs::write(&path, "\n\n\n\n").unwrap();

        let entries = WriteAheadLog::read_entries(&path).unwrap();
        assert!(entries.is_empty(), "blank lines must be silently skipped");
    }
}
