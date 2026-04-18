// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! RocksDB-backed ConsensusStore for production deployment.
//!
//! Feature-gated behind `rocksdb` to avoid linking RocksDB in dev builds.
//!
//! Column families:
//! - `CF_BLOCKS`: BlockDigest -> Block (serialized JSON)
//! - `CF_COMMITS`: CommitIndex -> CommittedSubDag (serialized JSON)
//! - `CF_META`: singleton keys (last_committed_rounds, gc_round, etc.)
//! - `CF_LAST_COMMITTED`: per-authority last committed round (separate CF
//!    for hot-path reads without scanning CF_META)
//! - `CF_EQUIVOCATION_EVIDENCE`: (round, author) -> equivocation evidence
//!    for slashing and post-mortem analysis

#[cfg(feature = "rocksdb")]
use std::path::Path;
#[cfg(feature = "rocksdb")]
use std::sync::Arc;

#[cfg(feature = "rocksdb")]
use super::dag_state::DagWriteBatch;
#[cfg(feature = "rocksdb")]
use super::store::{ConsensusStore, StoreError};
#[cfg(feature = "rocksdb")]
use crate::narwhal_types::block::*;
#[cfg(feature = "rocksdb")]
use crate::narwhal_types::commit::*;

// ─── Column family names ─────────────────────────────────────
//
// CF names live in `super::columns::NarwhalCf`. The aliases below keep
// existing call sites compiling without churn; the enum owns the
// canonical source of truth and is tested against these literals.
#[cfg(feature = "rocksdb")]
use super::columns::NarwhalCf;
#[cfg(feature = "rocksdb")]
const CF_BLOCKS: &str = NarwhalCf::Blocks.name();
#[cfg(feature = "rocksdb")]
const CF_COMMITS: &str = NarwhalCf::Commits.name();
#[cfg(feature = "rocksdb")]
const CF_META: &str = NarwhalCf::Meta.name();
#[cfg(feature = "rocksdb")]
const CF_LAST_COMMITTED: &str = NarwhalCf::LastCommitted.name();
#[cfg(feature = "rocksdb")]
const CF_EQUIVOCATION_EVIDENCE: &str = NarwhalCf::EquivocationEvidence.name();
#[cfg(feature = "rocksdb")]
const CF_COMMITTED_TX_FILTER: &str = NarwhalCf::CommittedTxFilter.name();
#[cfg(feature = "rocksdb")]
const CF_TX_INDEX: &str = NarwhalCf::TxIndex.name();
#[cfg(feature = "rocksdb")]
const CF_ADDR_INDEX: &str = NarwhalCf::AddrIndex.name();

// ─── Meta keys ───────────────────────────────────────────────
#[cfg(feature = "rocksdb")]
const KEY_LAST_COMMITTED_ROUNDS: &[u8] = b"last_committed_rounds";
#[cfg(feature = "rocksdb")]
const KEY_GC_ROUND: &[u8] = b"gc_round";
#[cfg(feature = "rocksdb")]
const KEY_TX_FILTER_SNAPSHOT: &[u8] = b"tx_filter_snapshot";

/// RocksDB-backed consensus store.
///
/// This is the ONLY production-grade store. `JsonFileStore` is dev/test only.
///
/// ## fsync Policy
///
/// By default, `sync_writes = true` for safety. This means every `WriteBatch`
/// is fsync'd to disk before returning. For benchmarking, use `open_with_sync(path, false)`.
#[cfg(feature = "rocksdb")]
pub struct RocksDbConsensusStore {
    db: Arc<rocksdb::DB>,
    /// If true, all writes are fsynced (production default).
    sync_writes: bool,
}

#[cfg(feature = "rocksdb")]
impl RocksDbConsensusStore {
    /// Open or create a RocksDB store at the given path.
    ///
    /// Default: `sync_writes = true` (production safe).
    /// Creates all 6 column families if missing.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_sync(path, true)
    }

    /// Open with explicit fsync policy.
    ///
    /// - `sync_writes = true`: every WriteBatch is fsynced (production default, safe)
    /// - `sync_writes = false`: no explicit fsync (benchmark mode, NOT crash-safe)
    pub fn open_with_sync(path: &Path, sync_writes: bool) -> Result<Self, StoreError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // Production tuning: WAL + fsync for crash safety
        opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::AbsoluteConsistency);
        if sync_writes {
            // Sync WAL on every write for maximum durability
            opts.set_bytes_per_sync(0); // 0 = fsync every write
        }

        // Per-CF options
        let block_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o
        };
        let commit_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o
        };
        let meta_opts = rocksdb::Options::default();
        let last_committed_opts = rocksdb::Options::default();
        let equivocation_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o
        };
        let tx_filter_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o
        };

        let tx_index_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o
        };
        let addr_index_opts = {
            let mut o = rocksdb::Options::default();
            o.set_compression_type(rocksdb::DBCompressionType::Snappy);
            o.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(64));
            o
        };

        let cfs = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCKS, block_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_COMMITS, commit_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_META, meta_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_LAST_COMMITTED, last_committed_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_EQUIVOCATION_EVIDENCE, equivocation_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_COMMITTED_TX_FILTER, tx_filter_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_TX_INDEX, tx_index_opts),
            rocksdb::ColumnFamilyDescriptor::new(CF_ADDR_INDEX, addr_index_opts),
        ];

        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB open failed: {}", e)))?;

        Ok(Self {
            db: Arc::new(db),
            sync_writes,
        })
    }

    // ─── CF handle accessors ─────────────────────────────────

    fn cf_blocks(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_BLOCKS).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_BLOCKS
            ))
        })
    }

    fn cf_commits(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_COMMITS).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_COMMITS
            ))
        })
    }

    fn cf_meta(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_META).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_META
            ))
        })
    }

    fn cf_last_committed(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_LAST_COMMITTED).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_LAST_COMMITTED
            ))
        })
    }

    fn cf_equivocation_evidence(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_EQUIVOCATION_EVIDENCE).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_EQUIVOCATION_EVIDENCE
            ))
        })
    }

    fn cf_committed_tx_filter(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_COMMITTED_TX_FILTER).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_COMMITTED_TX_FILTER
            ))
        })
    }

    fn cf_tx_index(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_TX_INDEX).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_TX_INDEX
            ))
        })
    }

    fn cf_addr_index(&self) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(CF_ADDR_INDEX).ok_or_else(|| {
            StoreError::Corrupted(format!(
                "column family '{}' missing — DB may be corrupted",
                CF_ADDR_INDEX
            ))
        })
    }

    // ─── TX index persistence ─────────────────────────────────

    /// Store a committed transaction detail (JSON bytes).
    pub fn put_tx_detail(&self, tx_hash: &[u8; 32], detail: &[u8]) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_tx_index()?, tx_hash, detail)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put tx_index failed: {}", e)))
    }

    /// Retrieve a committed transaction detail by hash.
    pub fn get_tx_detail(&self, tx_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        self.db
            .get_cf(self.cf_tx_index()?, tx_hash)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB get tx_index failed: {}", e)))
    }

    /// Store an address index entry. Key format: `{address_hex}:{height_be8}:{tx_hash_hex}`.
    pub fn put_addr_entry(&self, key: &[u8], entry: &[u8]) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_addr_index()?, key, entry)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put addr_index failed: {}", e)))
    }

    /// Retrieve all address index entries for a given address (prefix scan).
    pub fn get_addr_entries(&self, address_hex: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let cf = self.cf_addr_index()?;
        let prefix = address_hex.as_bytes();
        let mut results = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf, prefix);
        for item in iter {
            match item {
                Ok((k, v)) => {
                    if !k.starts_with(prefix) {
                        break;
                    }
                    results.push(v.to_vec());
                }
                Err(e) => {
                    return Err(StoreError::Corrupted(format!(
                        "RocksDB addr_index iterator failed: {}",
                        e
                    )));
                }
            }
        }
        Ok(results)
    }

    // ─── Committed TX filter persistence ─────────────────────

    /// Save a committed TX filter snapshot.
    pub fn save_tx_filter_snapshot(&self, data: &[u8]) -> Result<(), StoreError> {
        self.db
            .put_cf(self.cf_committed_tx_filter()?, KEY_TX_FILTER_SNAPSHOT, data)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put tx filter failed: {}", e)))?;
        Ok(())
    }

    /// Load the most recent committed TX filter snapshot.
    pub fn load_tx_filter_snapshot(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match self
            .db
            .get_cf(self.cf_committed_tx_filter()?, KEY_TX_FILTER_SNAPSHOT)
        {
            Ok(v) => Ok(v),
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get tx filter failed: {}",
                e
            ))),
        }
    }

    // ─── Equivocation evidence ───────────────────────────────

    /// Store equivocation evidence for a (round, author) slot.
    ///
    /// Evidence is append-only: once stored, it is never overwritten.
    /// Used for slashing proposals and post-mortem analysis.
    pub fn store_equivocation_evidence(
        &self,
        round: Round,
        author: AuthorityIndex,
        evidence: &[u8],
    ) -> Result<(), StoreError> {
        let key = equivocation_key(round, author);
        self.db
            .put_cf(self.cf_equivocation_evidence()?, key, evidence)
            .map_err(|e| {
                StoreError::Corrupted(format!("RocksDB put equivocation failed: {}", e))
            })?;
        Ok(())
    }

    /// Read equivocation evidence for a (round, author) slot.
    pub fn read_equivocation_evidence(
        &self,
        round: Round,
        author: AuthorityIndex,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = equivocation_key(round, author);
        match self.db.get_cf(self.cf_equivocation_evidence()?, key) {
            Ok(v) => Ok(v),
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get equivocation failed: {}",
                e
            ))),
        }
    }

    /// Read all equivocation evidence.
    pub fn read_all_equivocation_evidence(
        &self,
    ) -> Result<Vec<(Round, AuthorityIndex, Vec<u8>)>, StoreError> {
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(
            self.cf_equivocation_evidence()?,
            rocksdb::IteratorMode::Start,
        );
        for item in iter {
            let (key, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            if key.len() == 8 {
                let round = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
                let author = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
                results.push((round, author, value.to_vec()));
            }
        }
        Ok(results)
    }

    // ─── GC round persistence ────────────────────────────────

    /// Persist the current GC round to meta.
    pub fn set_gc_round(&self, round: Round) -> Result<(), StoreError> {
        let value = round.to_le_bytes();
        self.db
            .put_cf(self.cf_meta()?, KEY_GC_ROUND, value)
            .map_err(|e| StoreError::Corrupted(format!("RocksDB put gc_round failed: {}", e)))?;
        Ok(())
    }

    /// Read the persisted GC round.
    pub fn get_gc_round(&self) -> Result<Option<Round>, StoreError> {
        match self.db.get_cf(self.cf_meta()?, KEY_GC_ROUND) {
            Ok(Some(value)) if value.len() == 4 => Ok(Some(u32::from_le_bytes([
                value[0], value[1], value[2], value[3],
            ]))),
            Ok(Some(_)) => Err(StoreError::Corrupted(
                "gc_round: unexpected value length".into(),
            )),
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Corrupted(format!(
                "RocksDB get gc_round failed: {}",
                e
            ))),
        }
    }
}

/// Encode (round, author) as a big-endian 8-byte key for sorted iteration.
#[cfg(feature = "rocksdb")]
fn equivocation_key(round: Round, author: AuthorityIndex) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[..4].copy_from_slice(&round.to_be_bytes());
    key[4..].copy_from_slice(&author.to_be_bytes());
    key
}

#[cfg(feature = "rocksdb")]
impl ConsensusStore for RocksDbConsensusStore {
    fn write_batch(&self, batch: &DagWriteBatch) -> Result<(), StoreError> {
        let mut wb = rocksdb::WriteBatch::default();

        for block in &batch.blocks {
            let key = block.digest().0;
            let value = serde_json::to_vec(block.inner()).map_err(StoreError::Serde)?;
            wb.put_cf(self.cf_blocks()?, key, value);
        }

        for commit in &batch.commits {
            let key = commit.index.to_le_bytes();
            let value = serde_json::to_vec(commit).map_err(StoreError::Serde)?;
            wb.put_cf(self.cf_commits()?, key, value);
        }

        if let Some(rounds) = &batch.last_committed_rounds {
            // Write to both CF_META (legacy) and CF_LAST_COMMITTED (hot-path)
            let value = serde_json::to_vec(rounds).map_err(StoreError::Serde)?;
            wb.put_cf(self.cf_meta()?, KEY_LAST_COMMITTED_ROUNDS, &value);
            wb.put_cf(self.cf_last_committed()?, KEY_LAST_COMMITTED_ROUNDS, &value);
        }

        // Atomic write: all CF mutations in a single WriteBatch
        if self.sync_writes {
            let mut write_opts = rocksdb::WriteOptions::default();
            write_opts.set_sync(true);
            self.db
                .write_opt(wb, &write_opts)
                .map_err(|e| StoreError::Corrupted(format!("RocksDB write failed: {}", e)))?;
        } else {
            self.db
                .write(wb)
                .map_err(|e| StoreError::Corrupted(format!("RocksDB write failed: {}", e)))?;
        }

        Ok(())
    }

    fn read_all_blocks(&self) -> Result<Vec<(BlockRef, Block)>, StoreError> {
        let mut blocks = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf_blocks()?, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            let block: Block = serde_json::from_slice(&value).map_err(StoreError::Serde)?;
            let block_ref = block.reference();
            blocks.push((block_ref, block));
        }

        Ok(blocks)
    }

    fn read_all_commits(&self) -> Result<Vec<CommittedSubDag>, StoreError> {
        let mut commits = Vec::new();
        let iter = self
            .db
            .iterator_cf(self.cf_commits()?, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            let commit: CommittedSubDag =
                serde_json::from_slice(&value).map_err(StoreError::Serde)?;
            commits.push(commit);
        }

        // Sort by index (LE key encoding means iterator order matches)
        commits.sort_by_key(|c| c.index);
        Ok(commits)
    }

    fn read_last_committed_rounds(&self) -> Result<Option<Vec<Round>>, StoreError> {
        // Prefer CF_LAST_COMMITTED (hot-path), fall back to CF_META
        let result = self
            .db
            .get_cf(self.cf_last_committed()?, KEY_LAST_COMMITTED_ROUNDS);
        match result {
            Ok(Some(value)) => {
                let rounds: Vec<Round> =
                    serde_json::from_slice(&value).map_err(StoreError::Serde)?;
                Ok(Some(rounds))
            }
            Ok(None) => {
                // Fall back to legacy CF_META
                match self.db.get_cf(self.cf_meta()?, KEY_LAST_COMMITTED_ROUNDS) {
                    Ok(Some(value)) => {
                        let rounds: Vec<Round> =
                            serde_json::from_slice(&value).map_err(StoreError::Serde)?;
                        Ok(Some(rounds))
                    }
                    Ok(None) => Ok(None),
                    Err(e) => Err(StoreError::Corrupted(format!("RocksDB get failed: {}", e))),
                }
            }
            Err(e) => Err(StoreError::Corrupted(format!("RocksDB get failed: {}", e))),
        }
    }

    fn sync_wal(&self) -> Result<(), StoreError> {
        self.db
            .flush()
            .map_err(|e| StoreError::Corrupted(format!("RocksDB flush failed: {}", e)))?;
        Ok(())
    }

    fn gc_below_round(&self, round: Round) -> Result<u64, StoreError> {
        let mut deleted = 0u64;
        let mut to_delete = Vec::new();

        let iter = self
            .db
            .iterator_cf(self.cf_blocks()?, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) =
                item.map_err(|e| StoreError::Corrupted(format!("RocksDB iterator error: {}", e)))?;
            match serde_json::from_slice::<Block>(&value) {
                Ok(block) if block.round < round => {
                    to_delete.push(key.to_vec());
                }
                Ok(_) => {} // block.round >= round, keep
                Err(e) => {
                    // R7 L-9: Log and delete corrupt entries instead of silently skipping
                    tracing::warn!(
                        "gc_below_round: corrupt block entry (key={} bytes), deleting: {}",
                        key.len(),
                        e
                    );
                    to_delete.push(key.to_vec());
                }
            }
        }

        // Use WriteBatch for atomic GC
        if !to_delete.is_empty() {
            let mut wb = rocksdb::WriteBatch::default();
            for key in &to_delete {
                wb.delete_cf(self.cf_blocks()?, key);
            }
            self.db
                .write(wb)
                .map_err(|e| StoreError::Corrupted(format!("RocksDB gc delete failed: {}", e)))?;
            deleted = to_delete.len() as u64;
        }

        // Persist GC watermark
        self.set_gc_round(round)?;

        Ok(deleted)
    }
}
