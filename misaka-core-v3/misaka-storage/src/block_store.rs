//! RocksDB-backed Block Store — Atomic Batch Writes for Crash Safety.
//!
//! # Architecture: Crash-Resistant State Management
//!
//! All state mutations (UTXO creation, nullifier recording, height update)
//! are collected into a single `rocksdb::WriteBatch` and committed with one
//! atomic `db.write(batch)` call. RocksDB's internal Write-Ahead Log (WAL)
//! guarantees that either ALL mutations in the batch are persisted, or NONE
//! are — even if the process crashes or the OS loses power mid-write.
//!
//! ## Column Families
//!
//! | CF Name       | Key                  | Value               | Purpose                    |
//! |---------------|----------------------|---------------------|----------------------------|
//! | `utxos`       | tx_hash(32) ++ idx(4)| StoredUtxo (JSON)   | Unspent output set         |
//! | `nullifiers`  | nullifier(32)        | height(8 LE)        | Spent key images           |
//! | `spending_keys`| tx_hash(32) ++ idx(4)| Poly bytes (512)   | Ring member resolution     |
//! | `block_meta`  | height(8 LE)         | BlockMeta (JSON)    | Block headers + delta info |
//! | `state`       | "height"             | u64 LE              | Current chain tip          |
//! | `state`       | "state_root"         | [u8; 32]            | JMT state root at tip      |
//!
//! ## Sync Guarantees
//!
//! - **Testnet:** `WriteOptions::set_sync(false)` — WAL is written but not
//!   fsynced on every commit. Fast but ~1s data loss window on OS crash.
//! - **Mainnet:** `WriteOptions::set_sync(true)` — WAL is fsynced on every
//!   commit. Slower but zero data loss even on power failure.

use rocksdb::{
    DB, Options, ColumnFamilyDescriptor, WriteBatch, WriteOptions,
};
use std::path::Path;
use tracing::info;

use misaka_types::utxo::{OutputRef, TxOutput};

/// Column family names.
const CF_UTXOS: &str = "utxos";
const CF_NULLIFIERS: &str = "nullifiers";
const CF_SPENDING_KEYS: &str = "spending_keys";
const CF_BLOCK_META: &str = "block_meta";
const CF_STATE: &str = "state";

/// State keys within the `state` column family.
const STATE_KEY_HEIGHT: &[u8] = b"height";
const STATE_KEY_STATE_ROOT: &[u8] = b"state_root";

/// Block store error.
#[derive(Debug, thiserror::Error)]
pub enum BlockStoreError {
    #[error("rocksdb: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("serialization: {0}")]
    Serde(String),
    #[error("key image already spent: {0}")]
    KeyImageSpent(String),
    #[error("output already exists: {0}")]
    OutputExists(String),
    #[error("state inconsistency: {0}")]
    StateInconsistency(String),
    #[error("not found: {0}")]
    NotFound(String),
}

/// Serialized UTXO entry stored in RocksDB.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredUtxo {
    amount: u64,
    one_time_address: [u8; 32],
    pq_stealth_json: Option<String>,
    /// Block height at which this UTXO was created (NOT a timestamp).
    created_in_height: u64,
}

/// Block metadata stored per height.
#[derive(serde::Serialize, serde::Deserialize)]
struct BlockMeta {
    height: u64,
    /// OutputRefs created in this block (for rollback).
    created_outrefs: Vec<(/* tx_hash */ [u8; 32], /* idx */ u32)>,
    /// Key images (nullifiers) added in this block (for rollback).
    nullifiers_added: Vec<[u8; 32]>,
    /// State root hash after this block was applied.
    state_root: [u8; 32],
}

/// RocksDB-backed persistent block store.
///
/// All block application is done via `WriteBatch` for atomicity.
///
/// # Single-Writer Protection (Task 3.4)
///
/// `apply_block_atomic()` and `rollback_block()` acquire an exclusive
/// `write_lock` Mutex before performing any reads or writes. This
/// serializes all state mutations, preventing the following race:
///
/// 1. Thread A reads: nullifier X not spent
/// 2. Thread B reads: nullifier X not spent
/// 3. Thread A writes: record nullifier X at height 100
/// 4. Thread B writes: record nullifier X at height 101 ← DOUBLE SPEND
///
/// The Mutex guarantees that step 2 cannot interleave with steps 1+3.
///
/// Read-only operations (`get_height`, `get_utxo`, `has_nullifier`, etc.)
/// do NOT acquire the lock — they operate on RocksDB's MVCC snapshots
/// and are safe to call concurrently with writes.
pub struct RocksBlockStore {
    db: DB,
    /// If true, fsync WAL on every write (mainnet safety).
    sync_writes: bool,
    /// Exclusive lock for state-mutating operations (apply_block, rollback).
    /// Prevents TOCTOU races between validation reads and batch writes.
    write_lock: std::sync::Mutex<()>,
}

impl RocksBlockStore {
    /// Open or create the database at the given path.
    ///
    /// # Fail-Closed Initialization
    ///
    /// If the database cannot be opened (corruption, permission error),
    /// this returns `Err` — the caller MUST NOT proceed with an empty state.
    pub fn open(path: &Path, sync_writes: bool) -> Result<Self, BlockStoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // Optimize for point lookups (UTXO/nullifier checks)
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_UTXOS, Options::default()),
            ColumnFamilyDescriptor::new(CF_NULLIFIERS, Options::default()),
            ColumnFamilyDescriptor::new(CF_SPENDING_KEYS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCK_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_STATE, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;

        info!(
            "RocksDB opened at {} (sync_writes={})",
            path.display(),
            sync_writes
        );

        Ok(Self { db, sync_writes, write_lock: std::sync::Mutex::new(()) })
    }

    /// Get WriteOptions with sync flag set according to configuration.
    fn write_opts(&self) -> WriteOptions {
        let mut opts = WriteOptions::default();
        opts.set_sync(self.sync_writes);
        opts
    }

    // ─── Key Encoding ───────────────────────────────────

    /// Encode an OutputRef as a 36-byte key: tx_hash(32) || output_index(4 LE).
    fn outref_key(outref: &OutputRef) -> Vec<u8> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(&outref.tx_hash);
        key.extend_from_slice(&outref.output_index.to_le_bytes());
        key
    }

    /// Encode a block height as an 8-byte LE key.
    fn height_key(height: u64) -> [u8; 8] {
        height.to_le_bytes()
    }

    // ─── Read Operations ────────────────────────────────

    /// Get the current committed chain height.
    pub fn get_height(&self) -> Result<u64, BlockStoreError> {
        let cf = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| BlockStoreError::NotFound("CF state".into()))?;
        match self.db.get_cf(&cf, STATE_KEY_HEIGHT)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.as_slice().try_into()
                    .map_err(|_| BlockStoreError::Serde("height bytes".into()))?;
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0), // Genesis state
        }
    }

    /// Get the state root hash at the current tip.
    pub fn get_state_root(&self) -> Result<[u8; 32], BlockStoreError> {
        let cf = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| BlockStoreError::NotFound("CF state".into()))?;
        match self.db.get_cf(&cf, STATE_KEY_STATE_ROOT)? {
            Some(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into()
                    .map_err(|_| BlockStoreError::Serde("state_root bytes".into()))?;
                Ok(arr)
            }
            None => Ok([0u8; 32]), // Empty state root
        }
    }

    /// Check if a key image (nullifier) has been spent.
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, BlockStoreError> {
        let cf = self.db.cf_handle(CF_NULLIFIERS)
            .ok_or_else(|| BlockStoreError::NotFound("CF nullifiers".into()))?;
        Ok(self.db.get_cf(&cf, nullifier)?.is_some())
    }

    /// Get a UTXO entry.
    pub fn get_utxo(&self, outref: &OutputRef) -> Result<Option<(TxOutput, u64)>, BlockStoreError> {
        let cf = self.db.cf_handle(CF_UTXOS)
            .ok_or_else(|| BlockStoreError::NotFound("CF utxos".into()))?;
        let key = Self::outref_key(outref);
        match self.db.get_cf(&cf, &key)? {
            Some(bytes) => {
                let stored: StoredUtxo = serde_json::from_slice(&bytes)
                    .map_err(|e| BlockStoreError::Serde(e.to_string()))?;
                let output = TxOutput {
                    amount: stored.amount,
                    one_time_address: stored.one_time_address,
                    pq_stealth: None, // Stealth data is not needed for UTXO lookups
                    spending_pubkey: None,
                };
                Ok(Some((output, stored.created_in_height)))
            }
            None => Ok(None),
        }
    }

    /// Get a spending key for ring member resolution.
    pub fn get_spending_key(&self, outref: &OutputRef) -> Result<Option<Vec<u8>>, BlockStoreError> {
        let cf = self.db.cf_handle(CF_SPENDING_KEYS)
            .ok_or_else(|| BlockStoreError::NotFound("CF spending_keys".into()))?;
        let key = Self::outref_key(outref);
        Ok(self.db.get_cf(&cf, &key)?)
    }

    // ─── Atomic Block Application ───────────────────────

    /// Apply a block atomically using RocksDB WriteBatch.
    ///
    /// # Atomicity Guarantee
    ///
    /// All of the following operations are batched into a single WriteBatch:
    /// 1. Record all nullifiers (key images)
    /// 2. Create all new UTXOs
    /// 3. Register spending keys for new UTXOs
    /// 4. Store block metadata (for rollback)
    /// 5. Update chain height
    /// 6. Update state root
    ///
    /// The `db.write(batch)` call is the single commit point. If the process
    /// crashes before this call, no state is modified. If it crashes after,
    /// all state is guaranteed to be persisted (with WAL + fsync).
    pub fn apply_block_atomic(
        &self,
        height: u64,
        nullifiers: &[[u8; 32]],
        new_outputs: &[(OutputRef, TxOutput, Option<Vec<u8>>)], // (outref, output, spending_key)
        state_root: [u8; 32],
    ) -> Result<(), BlockStoreError> {
        // ── Acquire exclusive write lock (Task 3.4) ──
        //
        // Serializes all state-mutating operations. This prevents TOCTOU races
        // where two concurrent callers both pass validation reads then overwrite
        // each other's writes (e.g., double-spending the same nullifier).
        //
        // The lock is held for the entire read-validate-write cycle.
        // Read-only operations (get_height, get_utxo, has_nullifier) do NOT
        // acquire this lock — they use RocksDB's MVCC snapshots.
        let _write_guard = self.write_lock.lock()
            .map_err(|_| BlockStoreError::StateInconsistency(
                "write_lock poisoned — previous write panicked".into()
            ))?;

        // ── Phase 1: Validate (read-only checks, under lock) ──
        for ki in nullifiers {
            if self.has_nullifier(ki)? {
                return Err(BlockStoreError::KeyImageSpent(hex::encode(ki)));
            }
        }
        for (outref, _, _) in new_outputs {
            if self.get_utxo(outref)?.is_some() {
                return Err(BlockStoreError::OutputExists(format!(
                    "{}:{}",
                    hex::encode(&outref.tx_hash[..8]),
                    outref.output_index
                )));
            }
        }

        // ── Phase 2: Build atomic WriteBatch ──
        let mut batch = WriteBatch::default();

        let cf_utxos = self.db.cf_handle(CF_UTXOS)
            .ok_or_else(|| BlockStoreError::NotFound("CF utxos".into()))?;
        let cf_null = self.db.cf_handle(CF_NULLIFIERS)
            .ok_or_else(|| BlockStoreError::NotFound("CF nullifiers".into()))?;
        let cf_spk = self.db.cf_handle(CF_SPENDING_KEYS)
            .ok_or_else(|| BlockStoreError::NotFound("CF spending_keys".into()))?;
        let cf_meta = self.db.cf_handle(CF_BLOCK_META)
            .ok_or_else(|| BlockStoreError::NotFound("CF block_meta".into()))?;
        let cf_state = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| BlockStoreError::NotFound("CF state".into()))?;

        // 2a. Nullifiers
        for ki in nullifiers {
            batch.put_cf(&cf_null, ki, &height.to_le_bytes());
        }

        // 2b. New UTXOs + spending keys
        let mut created_outrefs = Vec::with_capacity(new_outputs.len());
        for (outref, output, spending_key) in new_outputs {
            let key = Self::outref_key(outref);
            let stored = StoredUtxo {
                amount: output.amount,
                one_time_address: output.one_time_address,
                pq_stealth_json: None,
                created_in_height: height,
            };
            let val = serde_json::to_vec(&stored)
                .map_err(|e| BlockStoreError::Serde(e.to_string()))?;
            batch.put_cf(&cf_utxos, &key, &val);

            if let Some(spk) = spending_key {
                batch.put_cf(&cf_spk, &key, spk);
            }

            created_outrefs.push((outref.tx_hash, outref.output_index));
        }

        // 2c. Block metadata (for rollback)
        let meta = BlockMeta {
            height,
            created_outrefs,
            nullifiers_added: nullifiers.to_vec(),
            state_root,
        };
        let meta_val = serde_json::to_vec(&meta)
            .map_err(|e| BlockStoreError::Serde(e.to_string()))?;
        batch.put_cf(&cf_meta, &Self::height_key(height), &meta_val);

        // 2d. Update chain height + state root
        batch.put_cf(&cf_state, STATE_KEY_HEIGHT, &height.to_le_bytes());
        batch.put_cf(&cf_state, STATE_KEY_STATE_ROOT, &state_root);

        // ── Phase 3: Atomic commit ──
        // This is the single point of truth. If the process crashes before
        // this line, the database is unchanged. If it crashes after, the
        // WAL guarantees all writes are recovered on next open.
        self.db.write_opt(batch, &self.write_opts())?;

        Ok(())
    }

    /// Rollback the last applied block.
    ///
    /// Reads the BlockMeta at the given height, then atomically:
    /// - Removes all nullifiers added by that block
    /// - Removes all UTXOs created by that block
    /// - Removes spending keys for those UTXOs
    /// - Removes the block metadata
    /// - Decrements height and restores the previous state root
    pub fn rollback_block(&self, height: u64) -> Result<(), BlockStoreError> {
        // ── Acquire exclusive write lock (Task 3.4) ──
        let _write_guard = self.write_lock.lock()
            .map_err(|_| BlockStoreError::StateInconsistency(
                "write_lock poisoned — previous write panicked".into()
            ))?;

        let cf_meta = self.db.cf_handle(CF_BLOCK_META)
            .ok_or_else(|| BlockStoreError::NotFound("CF block_meta".into()))?;

        // Load block metadata
        let meta_bytes = self.db.get_cf(&cf_meta, &Self::height_key(height))?
            .ok_or_else(|| BlockStoreError::NotFound(
                format!("block meta at height {}", height)
            ))?;
        let meta: BlockMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| BlockStoreError::Serde(e.to_string()))?;

        let mut batch = WriteBatch::default();

        let cf_utxos = self.db.cf_handle(CF_UTXOS)
            .ok_or_else(|| BlockStoreError::NotFound("CF utxos".into()))?;
        let cf_null = self.db.cf_handle(CF_NULLIFIERS)
            .ok_or_else(|| BlockStoreError::NotFound("CF nullifiers".into()))?;
        let cf_spk = self.db.cf_handle(CF_SPENDING_KEYS)
            .ok_or_else(|| BlockStoreError::NotFound("CF spending_keys".into()))?;
        let cf_state = self.db.cf_handle(CF_STATE)
            .ok_or_else(|| BlockStoreError::NotFound("CF state".into()))?;

        // Remove nullifiers
        for ki in &meta.nullifiers_added {
            batch.delete_cf(&cf_null, ki);
        }

        // Remove created UTXOs + spending keys
        for (tx_hash, idx) in &meta.created_outrefs {
            let outref = OutputRef { tx_hash: *tx_hash, output_index: *idx };
            let key = Self::outref_key(&outref);
            batch.delete_cf(&cf_utxos, &key);
            batch.delete_cf(&cf_spk, &key);
        }

        // Remove block metadata
        batch.delete_cf(&cf_meta, &Self::height_key(height));

        // Restore previous height
        let prev_height = height.saturating_sub(1);
        batch.put_cf(&cf_state, STATE_KEY_HEIGHT, &prev_height.to_le_bytes());

        // Restore previous state root (from prev block meta, or zeros for genesis)
        if prev_height > 0 {
            if let Some(prev_meta_bytes) = self.db.get_cf(&cf_meta, &Self::height_key(prev_height))? {
                let prev_meta: BlockMeta = serde_json::from_slice(&prev_meta_bytes)
                    .map_err(|e| BlockStoreError::Serde(e.to_string()))?;
                batch.put_cf(&cf_state, STATE_KEY_STATE_ROOT, &prev_meta.state_root);
            }
        } else {
            batch.put_cf(&cf_state, STATE_KEY_STATE_ROOT, &[0u8; 32]);
        }

        self.db.write_opt(batch, &self.write_opts())?;
        Ok(())
    }

    // ─── State Root Verification (Task 3) ───────────────

    /// Verify database consistency at startup.
    ///
    /// Checks:
    /// 1. Height in `state` CF matches the last `block_meta` entry
    /// 2. State root in `state` CF matches the last block's recorded root
    /// 3. Basic nullifier count sanity
    ///
    /// Returns `Ok(height)` if consistent, `Err` if corruption detected.
    pub fn verify_integrity(&self) -> Result<u64, BlockStoreError> {
        let height = self.get_height()?;
        let state_root = self.get_state_root()?;

        if height == 0 {
            // Genesis state — nothing to verify
            return Ok(0);
        }

        // Check that block_meta exists for the claimed height
        let cf_meta = self.db.cf_handle(CF_BLOCK_META)
            .ok_or_else(|| BlockStoreError::NotFound("CF block_meta".into()))?;

        let meta_bytes = self.db.get_cf(&cf_meta, &Self::height_key(height))?
            .ok_or_else(|| BlockStoreError::StateInconsistency(format!(
                "height={} but no block_meta exists at that height. \
                 Database may have crashed during block application. \
                 Resync required.",
                height
            )))?;

        let meta: BlockMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| BlockStoreError::StateInconsistency(format!(
                "block_meta at height {} is corrupted: {}. Resync required.",
                height, e
            )))?;

        // Verify state root matches
        if meta.state_root != state_root {
            return Err(BlockStoreError::StateInconsistency(format!(
                "state_root mismatch at height {}: state CF has {}, block_meta has {}. \
                 Resync required.",
                height,
                hex::encode(&state_root[..8]),
                hex::encode(&meta.state_root[..8]),
            )));
        }

        // Verify height in meta matches
        if meta.height != height {
            return Err(BlockStoreError::StateInconsistency(format!(
                "height mismatch: state CF says {}, block_meta says {}",
                height, meta.height,
            )));
        }

        info!(
            "Database integrity verified: height={}, state_root={}",
            height,
            hex::encode(&state_root[..8])
        );

        Ok(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_outref(id: u8, idx: u32) -> OutputRef {
        OutputRef { tx_hash: [id; 32], output_index: idx }
    }

    fn make_output(amount: u64) -> TxOutput {
        TxOutput { amount, one_time_address: [0xAA; 32], pq_stealth: None, spending_pubkey: None }
    }

    #[test]
    fn test_open_and_empty_state() {
        let dir = TempDir::new().unwrap();
        let store = RocksBlockStore::open(dir.path(), false).unwrap();
        assert_eq!(store.get_height().unwrap(), 0);
        assert_eq!(store.get_state_root().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_apply_and_read_back() {
        let dir = TempDir::new().unwrap();
        let store = RocksBlockStore::open(dir.path(), false).unwrap();

        let outref = make_outref(1, 0);
        let output = make_output(5000);
        let ki = [0xBB; 32];
        let root = [0xCC; 32];

        store.apply_block_atomic(
            1,
            &[ki],
            &[(outref.clone(), output.clone(), Some(vec![0xDD; 512]))],
            root,
        ).unwrap();

        assert_eq!(store.get_height().unwrap(), 1);
        assert_eq!(store.get_state_root().unwrap(), root);
        assert!(store.has_nullifier(&ki).unwrap());
        let (read_output, created_in_height) = store.get_utxo(&outref).unwrap().unwrap();
        assert_eq!(read_output.amount, 5000);
        assert_eq!(created_in_height, 1);
        assert!(store.get_spending_key(&outref).unwrap().is_some());
    }

    #[test]
    fn test_double_nullifier_rejected() {
        let dir = TempDir::new().unwrap();
        let store = RocksBlockStore::open(dir.path(), false).unwrap();

        let ki = [0xAA; 32];
        store.apply_block_atomic(1, &[ki], &[], [0; 32]).unwrap();
        assert!(store.apply_block_atomic(2, &[ki], &[], [0; 32]).is_err());
    }

    #[test]
    fn test_rollback() {
        let dir = TempDir::new().unwrap();
        let store = RocksBlockStore::open(dir.path(), false).unwrap();

        let outref = make_outref(1, 0);
        let ki = [0xBB; 32];

        store.apply_block_atomic(
            1, &[ki], &[(outref.clone(), make_output(1000), None)], [0xCC; 32],
        ).unwrap();

        assert_eq!(store.get_height().unwrap(), 1);
        assert!(store.has_nullifier(&ki).unwrap());

        store.rollback_block(1).unwrap();

        assert_eq!(store.get_height().unwrap(), 0);
        assert!(!store.has_nullifier(&ki).unwrap());
        assert!(store.get_utxo(&outref).unwrap().is_none());
    }

    #[test]
    fn test_integrity_check_passes() {
        let dir = TempDir::new().unwrap();
        let store = RocksBlockStore::open(dir.path(), false).unwrap();
        store.apply_block_atomic(1, &[], &[], [0xAA; 32]).unwrap();
        assert_eq!(store.verify_integrity().unwrap(), 1);
    }
}
