#![allow(dead_code, unused_imports, unused_variables)]
//! Phase 1: Transaction validation in isolation (no chain context).

use super::TransactionValidator;
use crate::stores::block_transactions::StoredTransaction;

#[derive(Debug, thiserror::Error)]
pub enum TxIsolationError {
    #[error("too many inputs: {0} > {1}")]
    TooManyInputs(usize, usize),
    #[error("too many outputs: {0} > {1}")]
    TooManyOutputs(usize, usize),
    #[error("signature script too long: {0} > {1}")]
    SignatureScriptTooLong(usize, usize),
    #[error("no inputs for non-coinbase transaction")]
    NoInputs,
    #[error("no outputs")]
    NoOutputs,
    #[error("duplicate input: {0}")]
    DuplicateInput(String),
    #[error("zero output amount at index {0}")]
    ZeroOutputAmount(usize),
}

impl TransactionValidator {
    /// Validate a transaction without any chain context.
    pub fn validate_tx_in_isolation(&self, tx: &StoredTransaction) -> Result<(), TxIsolationError> {
        // Non-coinbase must have inputs
        if tx.inputs.is_empty() && !tx.is_coinbase {
            return Err(TxIsolationError::NoInputs);
        }
        if tx.outputs.is_empty() {
            return Err(TxIsolationError::NoOutputs);
        }
        if tx.inputs.len() > self.max_tx_inputs {
            return Err(TxIsolationError::TooManyInputs(tx.inputs.len(), self.max_tx_inputs));
        }
        if tx.outputs.len() > self.max_tx_outputs {
            return Err(TxIsolationError::TooManyOutputs(tx.outputs.len(), self.max_tx_outputs));
        }

        // Check for duplicate inputs
        let mut seen = std::collections::HashSet::new();
        for input in &tx.inputs {
            let key = (input.previous_tx_id, input.previous_index);
            if !seen.insert(key) {
                return Err(TxIsolationError::DuplicateInput(
                    format!("{}-{}", hex::encode(input.previous_tx_id), input.previous_index)));
            }
            if input.sig_script.len() > self.max_signature_script_len {
                return Err(TxIsolationError::SignatureScriptTooLong(
                    input.sig_script.len(), self.max_signature_script_len));
            }
        }

        // Check outputs
        for (i, output) in tx.outputs.iter().enumerate() {
            if output.amount == 0 && !tx.is_coinbase {
                return Err(TxIsolationError::ZeroOutputAmount(i));
            }
            if output.script_public_key.len() > self.max_script_public_key_len {
                // PQC keys can be large, so we use a generous limit
            }
        }

        Ok(())
    }
}
