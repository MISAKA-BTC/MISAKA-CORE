#![allow(dead_code, unused_imports, unused_variables)]
//! Phase 3: Transaction validation in UTXO context.

use super::{TransactionValidator, TxValidationFlags};
use crate::stores::block_transactions::StoredTransaction;
use crate::stores::utxo_diffs::UtxoEntry;

#[derive(Debug, thiserror::Error)]
pub enum TxUtxoContextError {
    #[error("missing UTXO for input: tx={tx_id} index={index}")]
    MissingUtxo { tx_id: String, index: u32 },
    #[error("insufficient funds: input_sum={input_sum}, output_sum={output_sum}")]
    InsufficientFunds { input_sum: u64, output_sum: u64 },
    #[error("coinbase not mature: daa_diff={daa_diff}, required={required}")]
    CoinbaseNotMature { daa_diff: u64, required: u64 },
    #[error("PQC signature verification failed")]
    PqcSignatureInvalid,
    #[error("shielded proof verification failed")]
    ShieldedProofInvalid,
}

/// Resolved UTXO entries for a transaction's inputs.
pub struct PopulatedTransaction<'a> {
    pub tx: &'a StoredTransaction,
    pub utxo_entries: Vec<UtxoEntry>,
}

impl TransactionValidator {
    /// Validate a transaction against the UTXO set.
    pub fn validate_tx_in_utxo_context(
        &self,
        populated_tx: &PopulatedTransaction<'_>,
        current_daa_score: u64,
        flags: TxValidationFlags,
    ) -> Result<u64, TxUtxoContextError> {
        let tx = populated_tx.tx;

        if tx.is_coinbase {
            return Ok(0); // Coinbase has no fee
        }

        // Check all UTXOs exist and match
        if populated_tx.utxo_entries.len() != tx.inputs.len() {
            return Err(TxUtxoContextError::MissingUtxo {
                tx_id: hex::encode(tx.tx_id),
                index: 0,
            });
        }

        // Verify coinbase maturity for coinbase UTXOs
        for entry in &populated_tx.utxo_entries {
            if entry.is_coinbase {
                let daa_diff = current_daa_score.saturating_sub(entry.block_daa_score);
                if daa_diff < self.coinbase_maturity {
                    return Err(TxUtxoContextError::CoinbaseNotMature {
                        daa_diff,
                        required: self.coinbase_maturity,
                    });
                }
            }
        }

        // Check total input >= total output (the difference is the fee)
        let input_sum: u64 = populated_tx.utxo_entries.iter().map(|e| e.amount).sum();
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        if input_sum < output_sum {
            return Err(TxUtxoContextError::InsufficientFunds { input_sum, output_sum });
        }

        // Verify PQC signatures (ML-DSA-65)
        if !flags.skip_script_verification {
            // TODO: Integrate with misaka-pqc for actual signature verification
        }

        let fee = input_sum - output_sum;
        Ok(fee)
    }
}
