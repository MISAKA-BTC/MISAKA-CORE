//! Standard transaction checking and policy enforcement.

use crate::opcodes::*;
use crate::script_class::ScriptClass;

/// Maximum standard transaction size (100 KB).
pub const MAX_STANDARD_TX_SIZE: usize = 100_000;

/// Maximum standard script size (10 KB).
pub const MAX_STANDARD_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of standard signature operations.
pub const MAX_STANDARD_SIG_OPS: usize = 4_000;

/// Maximum standard OP_RETURN data size (80 bytes).
pub const MAX_OP_RETURN_DATA: usize = 80;

/// Dust threshold in base units (1000 = 0.000001 MISAKA).
pub const DUST_THRESHOLD: u64 = 1000;

/// Check if a script public key is standard.
pub fn is_standard_script(script: &[u8]) -> bool {
    let class = ScriptClass::from_script(script);
    match class {
        ScriptClass::NonStandard => false,
        ScriptClass::NullData => {
            // OP_RETURN data must not exceed maximum
            if script.len() > MAX_OP_RETURN_DATA + 2 {
                return false;
            }
            true
        }
        _ => script.len() <= MAX_STANDARD_SCRIPT_SIZE,
    }
}

/// Check if an output amount is above the dust threshold.
pub fn is_dust(amount: u64, script_len: usize) -> bool {
    if amount == 0 {
        return true;
    }
    // Cost to spend = 3 * (script_len + 148) for P2PKH-like scripts
    // For PQ scripts, cost is higher due to larger signatures
    let spend_cost = 3 * (script_len as u64 + 200);
    amount < spend_cost.max(DUST_THRESHOLD)
}

/// Validate a transaction for standard policy rules.
#[derive(Debug)]
pub struct StandardValidator;

impl StandardValidator {
    /// Check if a transaction's scripts are all standard.
    pub fn check_scripts(
        input_scripts: &[&[u8]],
        output_scripts: &[&[u8]],
    ) -> Result<(), StandardError> {
        for (i, script) in output_scripts.iter().enumerate() {
            if !is_standard_script(script) {
                return Err(StandardError::NonStandardOutput(i));
            }
        }

        let total_sig_ops: usize = input_scripts.iter()
            .chain(output_scripts.iter())
            .map(|s| count_sig_ops(s))
            .sum();

        if total_sig_ops > MAX_STANDARD_SIG_OPS {
            return Err(StandardError::TooManySigOps(total_sig_ops));
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StandardError {
    #[error("non-standard output at index {0}")]
    NonStandardOutput(usize),
    #[error("too many signature operations: {0}")]
    TooManySigOps(usize),
    #[error("transaction too large: {0} bytes")]
    TxTooLarge(usize),
    #[error("dust output: {amount} at index {index}")]
    DustOutput { index: usize, amount: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_builder::ScriptBuilder;

    #[test]
    fn test_standard_scripts() {
        let hash = [0u8; 32];
        assert!(is_standard_script(&ScriptBuilder::p2pkh(&hash)));
        assert!(is_standard_script(&ScriptBuilder::p2sh(&hash)));
        assert!(is_standard_script(&ScriptBuilder::p2pkh_pq(&hash)));
        assert!(is_standard_script(&ScriptBuilder::op_return(b"data")));
    }

    #[test]
    fn test_dust() {
        assert!(is_dust(0, 34));
        assert!(is_dust(100, 34));
        assert!(!is_dust(1_000_000, 34));
    }
}
