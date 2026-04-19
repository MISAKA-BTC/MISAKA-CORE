//! BlockArchive — persistent block and transaction index backed by RocksDB.
//!
//! Opens a SEPARATE RocksDB instance from the Narwhal consensus store.
//! This avoids modifying the consensus store's WAL and allows independent
//! pruning and compaction.

use super::types::*;
use std::path::Path;
use std::sync::Arc;

/// Column family names.
const CF_BLOCK_META: &str = "block_meta";
const CF_BLOCK_TXS: &str = "block_txs";
const CF_HEIGHT_BLOCK: &str = "height_block";
const CF_TX_INDEX: &str = "tx_index";
const CF_TX_BODY: &str = "tx_body";

/// Block/Tx archive backed by a dedicated RocksDB instance.
pub struct BlockArchive {
    db: Arc<rocksdb::DB>,
    txindex_enabled: bool,
    prune_keep_commits: Option<u64>,
}

/// Errors from the block archive.
#[derive(Debug, thiserror::Error)]
pub enum BlockArchiveError {
    #[error("rocksdb: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("borsh deserialize: {0}")]
    Deserialize(String),
    #[error("borsh serialize: {0}")]
    Serialize(String),
}

impl BlockArchive {
    /// Open (or create) the block archive DB at the given path.
    pub fn open(
        path: &Path,
        txindex_enabled: bool,
        prune_keep_commits: Option<u64>,
    ) -> Result<Self, BlockArchiveError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);

        let cf_opts = rocksdb::Options::default();
        let mut cf_descs = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCK_META, cf_opts.clone()),
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCK_TXS, cf_opts.clone()),
            rocksdb::ColumnFamilyDescriptor::new(CF_HEIGHT_BLOCK, cf_opts.clone()),
        ];
        if txindex_enabled {
            cf_descs.push(rocksdb::ColumnFamilyDescriptor::new(
                CF_TX_INDEX,
                cf_opts.clone(),
            ));
            cf_descs.push(rocksdb::ColumnFamilyDescriptor::new(CF_TX_BODY, cf_opts));
        }

        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cf_descs)?;

        Ok(Self {
            db: Arc::new(db),
            txindex_enabled,
            prune_keep_commits,
        })
    }

    /// Persist a committed sub-DAG as a "block" in the archive.
    pub fn put_commit(
        &self,
        meta: &BlockMetadata,
        tx_refs: &[TxRef],
    ) -> Result<(), BlockArchiveError> {
        let meta_cf = self.cf(CF_BLOCK_META)?;
        let txs_cf = self.cf(CF_BLOCK_TXS)?;
        let height_cf = self.cf(CF_HEIGHT_BLOCK)?;

        let meta_bytes =
            borsh::to_vec(meta).map_err(|e| BlockArchiveError::Serialize(e.to_string()))?;
        let txs_bytes =
            borsh::to_vec(tx_refs).map_err(|e| BlockArchiveError::Serialize(e.to_string()))?;
        let height_key = meta.commit_index.to_be_bytes();

        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&meta_cf, &meta.hash, &meta_bytes);
        batch.put_cf(&txs_cf, &meta.hash, &txs_bytes);

        // Height → hash index. Append to existing list if multiple blocks at same height.
        let existing = self.db.get_cf(&height_cf, &height_key)?;
        let mut hashes: Vec<[u8; 32]> = match existing {
            Some(data) => borsh::from_slice(&data)
                .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?,
            None => Vec::new(),
        };
        if !hashes.contains(&meta.hash) {
            hashes.push(meta.hash);
        }
        let hashes_bytes =
            borsh::to_vec(&hashes).map_err(|e| BlockArchiveError::Serialize(e.to_string()))?;
        batch.put_cf(&height_cf, &height_key, &hashes_bytes);

        self.db.write(batch)?;
        Ok(())
    }

    /// Persist a transaction body + index (only when txindex=true).
    pub fn put_tx(
        &self,
        tx_hash: [u8; 32],
        block_hash: [u8; 32],
        commit_index: u64,
        position: u32,
        raw_tx: &[u8],
    ) -> Result<(), BlockArchiveError> {
        if !self.txindex_enabled {
            return Ok(());
        }
        let idx_cf = self.cf(CF_TX_INDEX)?;
        let body_cf = self.cf(CF_TX_BODY)?;

        let loc = TxLocation {
            block_hash,
            commit_index,
            position,
        };
        let loc_bytes =
            borsh::to_vec(&loc).map_err(|e| BlockArchiveError::Serialize(e.to_string()))?;

        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&idx_cf, &tx_hash, &loc_bytes);
        batch.put_cf(&body_cf, &tx_hash, raw_tx);
        self.db.write(batch)?;
        Ok(())
    }

    /// Look up block metadata by hash (leader digest).
    pub fn get_block_meta(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<BlockMetadata>, BlockArchiveError> {
        let cf = self.cf(CF_BLOCK_META)?;
        match self.db.get_cf(&cf, hash)? {
            Some(data) => {
                let meta = borsh::from_slice(&data)
                    .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Look up transaction references for a block.
    pub fn get_block_txs(&self, hash: &[u8; 32]) -> Result<Option<Vec<TxRef>>, BlockArchiveError> {
        let cf = self.cf(CF_BLOCK_TXS)?;
        match self.db.get_cf(&cf, hash)? {
            Some(data) => {
                let refs = borsh::from_slice(&data)
                    .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?;
                Ok(Some(refs))
            }
            None => Ok(None),
        }
    }

    /// Look up block hashes at a given commit index ("height").
    pub fn get_blocks_at_height(
        &self,
        commit_index: u64,
    ) -> Result<Vec<[u8; 32]>, BlockArchiveError> {
        let cf = self.cf(CF_HEIGHT_BLOCK)?;
        let key = commit_index.to_be_bytes();
        match self.db.get_cf(&cf, &key)? {
            Some(data) => {
                let hashes: Vec<[u8; 32]> = borsh::from_slice(&data)
                    .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?;
                Ok(hashes)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Look up a transaction's location (block hash + commit index + position).
    pub fn get_tx_location(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<TxLocation>, BlockArchiveError> {
        if !self.txindex_enabled {
            return Ok(None);
        }
        let cf = self.cf(CF_TX_INDEX)?;
        match self.db.get_cf(&cf, tx_hash)? {
            Some(data) => {
                let loc = borsh::from_slice(&data)
                    .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?;
                Ok(Some(loc))
            }
            None => Ok(None),
        }
    }

    /// Look up raw transaction bytes.
    pub fn get_tx_body(&self, tx_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, BlockArchiveError> {
        if !self.txindex_enabled {
            return Ok(None);
        }
        let cf = self.cf(CF_TX_BODY)?;
        Ok(self.db.get_cf(&cf, tx_hash)?)
    }

    /// Whether the tx index is enabled.
    pub fn txindex_enabled(&self) -> bool {
        self.txindex_enabled
    }

    /// Configured prune-keep-commits (None = keep all).
    pub fn prune_keep_commits(&self) -> Option<u64> {
        self.prune_keep_commits
    }

    /// Remove block + tx data for commits strictly below `min_keep_commit`.
    pub fn prune_below(&self, min_keep_commit: u64) -> Result<PruneStats, BlockArchiveError> {
        let height_cf = self.cf(CF_HEIGHT_BLOCK)?;
        let meta_cf = self.cf(CF_BLOCK_META)?;
        let txs_cf = self.cf(CF_BLOCK_TXS)?;

        let mut stats = PruneStats::default();
        let mut batch = rocksdb::WriteBatch::default();

        // Iterate height_block CF from the beginning up to min_keep_commit.
        let iter = self.db.iterator_cf(
            &height_cf,
            rocksdb::IteratorMode::From(&0u64.to_be_bytes(), rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, value) = item?;
            if key.len() != 8 {
                continue;
            }
            let mut key_arr = [0u8; 8];
            key_arr.copy_from_slice(&key);
            let commit_idx = u64::from_be_bytes(key_arr);
            if commit_idx >= min_keep_commit {
                break;
            }

            let hashes: Vec<[u8; 32]> = borsh::from_slice(&value)
                .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?;

            for hash in &hashes {
                // Delete tx records if txindex is enabled
                if self.txindex_enabled {
                    if let Some(txs_data) = self.db.get_cf(&txs_cf, hash)? {
                        let tx_refs: Vec<TxRef> = borsh::from_slice(&txs_data)
                            .map_err(|e| BlockArchiveError::Deserialize(e.to_string()))?;
                        let idx_cf = self.cf(CF_TX_INDEX)?;
                        let body_cf = self.cf(CF_TX_BODY)?;
                        for tx_ref in &tx_refs {
                            batch.delete_cf(&idx_cf, &tx_ref.tx_hash);
                            batch.delete_cf(&body_cf, &tx_ref.tx_hash);
                            stats.tx_records_removed += 1;
                        }
                    }
                }
                batch.delete_cf(&meta_cf, hash);
                batch.delete_cf(&txs_cf, hash);
            }
            batch.delete_cf(&height_cf, &key);
            stats.commits_removed += 1;
        }

        self.db.write(batch)?;
        Ok(stats)
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, BlockArchiveError> {
        self.db.cf_handle(name).ok_or_else(|| {
            BlockArchiveError::Deserialize(format!("column family '{}' not found", name))
        })
    }
}
