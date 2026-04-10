//! Standard transaction validation checks.

use crate::errors::MempoolRuleError;
use crate::mempool::model::tx::MempoolTransaction;

/// Maximum standard transaction mass.
pub const MAX_STANDARD_TX_MASS: u64 = 100_000;

/// Maximum number of inputs per transaction.
pub const MAX_TX_INPUTS: usize = 10_000;

/// Maximum number of outputs per transaction.
pub const MAX_TX_OUTPUTS: usize = 10_000;

/// Check if a transaction meets standard policy rules.
pub fn check_transaction_standard(tx: &MempoolTransaction) -> Result<(), MempoolRuleError> {
    if tx.mass > MAX_STANDARD_TX_MASS {
        return Err(MempoolRuleError::MassExceeded {
            mass: tx.mass,
            max: MAX_STANDARD_TX_MASS,
        });
    }

    if tx.input_count > MAX_TX_INPUTS {
        return Err(MempoolRuleError::TooManyInputs(tx.input_count));
    }

    if tx.output_count > MAX_TX_OUTPUTS {
        return Err(MempoolRuleError::TooManyOutputs(tx.output_count));
    }

    if tx.fee_rate() < 1.0 {
        return Err(MempoolRuleError::InsufficientFee {
            fee: tx.fee,
            mass: tx.mass,
        });
    }

    Ok(())
}
