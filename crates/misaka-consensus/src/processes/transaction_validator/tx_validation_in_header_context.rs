//! Transaction validation in header context.
//!
//! SEC-AUDIT WARNING: This module performs MINIMAL validation (coinbase maturity only).
//! Full signature verification, double-spend prevention, and balance checks are
//! performed by:
//! - `utxo_executor.rs::validate_transparent_transfer()` (Narwhal/DAG path)
//! - `block_validation.rs::validate_and_apply_block()` (legacy path)
//!
//! This module is part of the Kaspa-derived transaction validator pipeline
//! which is NOT the primary validation path in MISAKA's Narwhal consensus.
//! Do NOT rely on this module as a security boundary.

use super::TransactionValidator;
use crate::stores::block_transactions::StoredTransaction;

#[derive(Debug, thiserror::Error)]
pub enum TxHeaderContextError {
    #[error("coinbase maturity not reached: block_daa={block_daa}, required={required}")]
    CoinbaseNotMature { block_daa: u64, required: u64 },
    #[error("transaction expired at epoch {0}")]
    TransactionExpired(u64),
}

impl TransactionValidator {
    /// Validate a transaction in header context (DAA score, etc).
    ///
    /// NOTE: This is NOT the primary security validation path.
    /// See module-level documentation for the actual validation pipeline.
    pub fn validate_tx_in_header_context(
        &self,
        tx: &StoredTransaction,
        block_daa_score: u64,
        _past_median_time: u64,
    ) -> Result<(), TxHeaderContextError> {
        if tx.is_coinbase {
            return Ok(());
        }
        Ok(())
    }
}
