#![allow(dead_code, unused_imports, unused_variables)]
//! Body processor — validates block bodies (transactions) in context.

use crate::stores::block_transactions::{DbBlockTransactionsStore, StoredTransaction};
use crate::stores::ghostdag::Hash;
use crate::stores::statuses::{BlockStatus, DbStatusesStore, StatusesStoreReader};
use misaka_database::prelude::*;
use rocksdb::WriteBatch;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum BodyProcessingError {
    #[error("block not in header-only state: {0}")]
    InvalidStatus(String),
    #[error("transaction validation failed: {0}")]
    TxValidationFailed(String),
    #[error("duplicate transaction: {0}")]
    DuplicateTransaction(String),
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    #[error("store error: {0}")]
    StoreError(#[from] StoreError),
}

pub struct BodyProcessor {
    db: Arc<DB>,
    block_txs_store: DbBlockTransactionsStore,
    statuses_store: DbStatusesStore,
}

impl BodyProcessor {
    pub fn new(
        db: Arc<DB>,
        block_txs_store: DbBlockTransactionsStore,
        statuses_store: DbStatusesStore,
    ) -> Self {
        Self {
            db,
            block_txs_store,
            statuses_store,
        }
    }

    /// Validate and store block body.
    pub fn process_body(
        &self,
        block_hash: Hash,
        transactions: Vec<StoredTransaction>,
    ) -> Result<(), BodyProcessingError> {
        // 1. Verify block is in header-only state
        let status = self.statuses_store.get(block_hash)?;
        if status != BlockStatus::StatusHeaderOnly {
            return Err(BodyProcessingError::InvalidStatus(hex::encode(block_hash)));
        }

        // 2. Validate transactions in isolation
        self.validate_transactions_in_isolation(&transactions)?;

        // 3. Validate merkle root
        // (simplified — full implementation would compute and compare)

        // 4. Commit
        let mut batch = WriteBatch::default();
        self.block_txs_store
            .insert_batch(&mut batch, block_hash, transactions)?;
        self.statuses_store
            .set_batch(&mut batch, block_hash, BlockStatus::StatusBodyValid)?;
        self.db.write(batch).map_err(StoreError::from)?;

        Ok(())
    }

    fn validate_transactions_in_isolation(
        &self,
        txs: &[StoredTransaction],
    ) -> Result<(), BodyProcessingError> {
        let mut seen_tx_ids = std::collections::HashSet::new();
        for tx in txs {
            if !seen_tx_ids.insert(tx.tx_id) {
                return Err(BodyProcessingError::DuplicateTransaction(hex::encode(
                    tx.tx_id,
                )));
            }
            // Validate transaction structure
            self.validate_tx_in_isolation(tx)?;
        }
        Ok(())
    }

    fn validate_tx_in_isolation(&self, tx: &StoredTransaction) -> Result<(), BodyProcessingError> {
        if tx.inputs.is_empty() && !tx.is_coinbase {
            return Err(BodyProcessingError::TxValidationFailed("no inputs".into()));
        }
        if tx.outputs.is_empty() {
            return Err(BodyProcessingError::TxValidationFailed("no outputs".into()));
        }
        // Validate PQC signature presence for non-coinbase transactions
        if !tx.is_coinbase {
            if tx.signature.is_empty() {
                return Err(BodyProcessingError::TxValidationFailed(
                    "non-coinbase transaction missing signature".into(),
                ));
            }
            // Full signature verification happens in UTXO context (tx_validation_in_utxo_context.rs)
            // where the spending public key from the UTXO is available.
            // Body processor validates: signature is present and structurally valid.
            if tx.signature.len() < 32 {
                return Err(BodyProcessingError::TxValidationFailed(format!(
                    "signature too short: {} bytes (min 32)",
                    tx.signature.len()
                )));
            }
        }
        Ok(())
    }
}
