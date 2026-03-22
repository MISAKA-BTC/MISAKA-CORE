//! Write-Ahead Log (WAL) for atomic DAG block acceptance.
//!
//! # Problem
//!
//! Block acceptance involves multiple stores (header, ghostdag, virtual state,
//! nullifiers, UTXOs). Without atomicity, a crash mid-acceptance leaves the
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
//! Phase 5: State commit        — utxo root, nullifier root
//! Phase 6: Commit marker       — {block_hash, phase=Committed}
//! ```
//!
//! On restart:
//! - Entries with `Committed` marker → completed, skip
//! - Entries without `Committed` → rollback partial state
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
//! - If commit marker is missing → transaction is incomplete → rollback
//! - Journal is compacted after N committed entries

use std::io::{self, BufRead, Write, BufReader, BufWriter};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Compact journal after this many committed entries.
pub const COMPACT_THRESHOLD: usize = 1000;

/// Maximum journal file size before forced compaction (bytes).
pub const MAX_JOURNAL_SIZE: u64 = 64 * 1024 * 1024; // 64 MB

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
    /// State commitments (utxo root, nullifier root) persisted.
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

    #[error("block {block} has incomplete transaction (phase={phase:?}), needs rollback")]
    IncompleteTransaction {
        block: String,
        phase: AcceptPhase,
    },
}

// ═══════════════════════════════════════════════════════════════
//  Recovery Result
// ═══════════════════════════════════════════════════════════════

/// Result of WAL recovery on startup.
#[derive(Debug)]
pub struct RecoveryResult {
    /// Blocks that were fully committed (no action needed).
    pub committed: Vec<[u8; 32]>,
    /// Blocks that were partially written (need rollback).
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
///     rollback_block(incomplete.block_hash);
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
    pub fn log_phase(
        &mut self,
        block_hash: [u8; 32],
        phase: AcceptPhase,
    ) -> Result<(), WalError> {
        self.seq += 1;
        let entry = JournalEntry {
            block_hash,
            phase,
            seq: self.seq,
            timestamp_ms: now_ms(),
            metadata: None,
        };

        self.append_entry(&entry)?;

        if phase == AcceptPhase::Committed {
            self.committed_since_compact += 1;
            if self.committed_since_compact >= COMPACT_THRESHOLD {
                if let Err(e) = self.compact() {
                    warn!("WAL compaction failed (non-fatal): {}", e);
                }
            }
        }

        Ok(())
    }

    /// Log a phase transition with metadata (e.g., state root, error info).
    pub fn log_phase_with_metadata(
        &mut self,
        block_hash: [u8; 32],
        phase: AcceptPhase,
        metadata: String,
    ) -> Result<(), WalError> {
        self.seq += 1;
        let entry = JournalEntry {
            block_hash,
            phase,
            seq: self.seq,
            timestamp_ms: now_ms(),
            metadata: Some(metadata),
        };
        self.append_entry(&entry)
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

        // Sort incomplete by sequence for deterministic rollback order
        incomplete.sort_by_key(|b| b.last_seq);

        if !incomplete.is_empty() {
            warn!(
                "WAL recovery: {} committed, {} incomplete (need rollback)",
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
        let committed: std::collections::HashSet<[u8; 32]> = entries.iter()
            .filter(|e| e.phase == AcceptPhase::Committed)
            .map(|e| e.block_hash)
            .collect();

        // Keep only entries for non-committed blocks
        let retained: Vec<&JournalEntry> = entries.iter()
            .filter(|e| !committed.contains(&e.block_hash))
            .collect();

        let removed = total_before - retained.len();

        // Write retained entries to a temp file, then atomically rename
        let tmp_path = self.path.with_extension("journal.tmp");
        {
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            for entry in &retained {
                let json = serde_json::to_string(entry)?;
                writer.write_all(json.as_bytes())?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        fs::rename(&tmp_path, &self.path)?;

        self.committed_since_compact = 0;
        info!("WAL compacted: removed {} entries, {} retained", removed, retained.len());

        Ok(removed)
    }

    /// Clear the entire journal (after clean shutdown or full recovery).
    pub fn clear(&mut self) -> Result<(), WalError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        self.seq = 0;
        self.committed_since_compact = 0;
        Ok(())
    }

    /// Get the journal file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ─── Internal ──────────────────────────────────────────

    fn append_entry(&self, entry: &JournalEntry) -> Result<(), WalError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        let json = serde_json::to_string(entry)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?; // fsync — ensures durability

        debug!(
            "WAL: block={} phase={:?} seq={}",
            hex::encode(&entry.block_hash[..4]),
            entry.phase,
            entry.seq,
        );

        Ok(())
    }

    fn read_entries(path: &Path) -> Result<Vec<JournalEntry>, WalError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<JournalEntry>(trimmed) {
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

    fn h(b: u8) -> [u8; 32] { [b; 32] }

    #[test]
    fn test_wal_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut wal = WriteAheadLog::open(tmp.path()).unwrap();

        wal.log_phase(h(1), AcceptPhase::Received).unwrap();
        wal.log_phase(h(1), AcceptPhase::BlockDataPersisted).unwrap();
        wal.log_phase(h(1), AcceptPhase::Committed).unwrap();

        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.committed.len(), 1);
        assert_eq!(recovery.committed[0], h(1));
        assert!(recovery.incomplete.is_empty());
        assert_eq!(recovery.entries_processed, 3);
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
        wal.log_phase(h(2), AcceptPhase::ConsensusPersisted).unwrap();

        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.committed.len(), 1);
        assert_eq!(recovery.incomplete.len(), 1);
        assert_eq!(recovery.incomplete[0].block_hash, h(2));
        assert_eq!(recovery.incomplete[0].last_phase, AcceptPhase::ConsensusPersisted);
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
            assert!(entries[i].seq > entries[i-1].seq,
                "sequence must be strictly monotonic");
        }
    }
}
