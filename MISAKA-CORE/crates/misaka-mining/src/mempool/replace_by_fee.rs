//! Replace-by-fee (RBF) policy enforcement.

use crate::errors::MempoolRuleError;

/// Validate that a replacement transaction meets RBF requirements.
pub fn validate_rbf_replacement(
    new_fee: u64,
    new_mass: u64,
    old_fee: u64,
    old_mass: u64,
    min_increment_pct: f64,
) -> Result<(), MempoolRuleError> {
    let min_new_fee = old_fee + (old_fee as f64 * (min_increment_pct - 1.0)) as u64;
    if new_fee < min_new_fee {
        return Err(MempoolRuleError::RbfInsufficientFee {
            old: old_fee,
            new: new_fee,
            min_increment: min_new_fee - old_fee,
        });
    }

    // New fee rate must be higher
    let old_rate = if old_mass > 0 { old_fee as f64 / old_mass as f64 } else { 0.0 };
    let new_rate = if new_mass > 0 { new_fee as f64 / new_mass as f64 } else { 0.0 };

    if new_rate <= old_rate {
        return Err(MempoolRuleError::RbfViolation(
            format!("new fee rate {:.2} must exceed old rate {:.2}", new_rate, old_rate)
        ));
    }

    Ok(())
}
