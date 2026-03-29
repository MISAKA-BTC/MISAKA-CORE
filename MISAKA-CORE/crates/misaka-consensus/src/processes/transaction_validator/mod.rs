#![allow(dead_code, unused_imports, unused_variables)]
//! 3-phase transaction validator.

pub mod tx_validation_in_isolation;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_utxo_context;

use crate::stores::ghostdag::KType;

/// Validation flags for UTXO-context validation.
#[derive(Clone, Copy, Debug)]
pub struct TxValidationFlags {
    pub skip_script_verification: bool,
    pub skip_mass_check: bool,
}

impl Default for TxValidationFlags {
    fn default() -> Self {
        Self { skip_script_verification: false, skip_mass_check: false }
    }
}

/// Transaction validator with configurable limits.
#[derive(Clone)]
pub struct TransactionValidator {
    pub max_tx_inputs: usize,
    pub max_tx_outputs: usize,
    pub max_signature_script_len: usize,
    pub max_script_public_key_len: usize,
    pub coinbase_maturity: u64,
    pub ghostdag_k: KType,
}

impl TransactionValidator {
    pub fn new(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_maturity: u64,
        ghostdag_k: KType,
    ) -> Self {
        Self { max_tx_inputs, max_tx_outputs, max_signature_script_len,
               max_script_public_key_len, coinbase_maturity, ghostdag_k }
    }
}
