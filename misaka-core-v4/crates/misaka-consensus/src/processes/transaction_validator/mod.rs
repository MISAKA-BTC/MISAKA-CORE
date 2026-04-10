// Phase 33: #![allow(dead_code)] REMOVED — verification modules must never be silently dead.
//! 3-phase transaction validator.

pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;
// Phase 2c-B D2: tx_validation_in_utxo_context deleted (replaced by utxo_executor)

use crate::stores::ghostdag::KType;

/// Validation flags for UTXO-context validation.
///
/// SECURITY: `skip_script_verification` bypasses ALL signature checks.
/// It is only constructible with `true` in `#[cfg(test)]` builds.
/// Production code can only obtain flags via `Default` (all checks enabled).
#[derive(Clone, Copy, Debug)]
pub struct TxValidationFlags {
    /// Skip ML-DSA-65 signature verification.
    /// DANGER: Only available in test builds. Setting this to `true` in
    /// production would allow unsigned transactions to pass validation.
    skip_script_verification: bool,
    pub skip_mass_check: bool,
}

impl TxValidationFlags {
    /// Read whether script verification is skipped.
    pub fn skip_script_verification(&self) -> bool {
        self.skip_script_verification
    }

    /// Create flags for testing that skip signature verification.
    ///
    /// # Safety
    /// This disables ALL cryptographic signature checks. Only available
    /// in test builds to allow unit-testing non-crypto validation logic.
    #[cfg(test)]
    pub fn test_skip_scripts() -> Self {
        Self {
            skip_script_verification: true,
            skip_mass_check: false,
        }
    }
}

impl Default for TxValidationFlags {
    fn default() -> Self {
        Self {
            skip_script_verification: false,
            skip_mass_check: false,
        }
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
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_maturity,
            ghostdag_k,
        }
    }
}
