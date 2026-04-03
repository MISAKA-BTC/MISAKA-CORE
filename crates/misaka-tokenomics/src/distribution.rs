//! Fee distribution and block reward computation.
//!
//! # Fee Distribution (per block)
//!
//! | Recipient    | Share | Purpose                                   |
//! |-------------|-------|--------------------------------------------|
//! | Validators  | 90%   | Distributed to 21 SR nodes by stake ratio  |
//! | Treasury    | 10%   | Protocol development fund                  |
//!
//! Burn is NOT applied. All fees remain in circulation.
//!
//! # Block Reward = Inflation Emission + Validator Fee Share
//!
//! The proposing validator receives:
//! 1. Inflation emission for this block (from `inflation.rs`)
//! 2. 90% of total transaction fees in this block
//!
//! In a multi-validator network, the per-block fee share is credited
//! to the proposer. Stake-proportional redistribution across all 21 SRs
//! occurs at epoch boundaries.

/// Validators receive 90% of fees (distributed by stake ratio at epoch boundary).
pub const VALIDATOR_FEE_BPS: u64 = 9000;
/// Treasury receives 10% of fees.
pub const TREASURY_FEE_BPS: u64 = 1000;

/// Fee distribution for a single block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeShares {
    /// Amount sent to validators (90%).
    pub validator: u64,
    /// Amount sent to the protocol treasury (10%).
    pub treasury: u64,
}

/// Compute fee distribution for a block's total fees.
///
/// Invariant: `validator + treasury == total_fee`
/// (rounding dust goes to validator).
pub fn compute_fee_shares(total_fee: u64) -> FeeShares {
    let treasury = total_fee * TREASURY_FEE_BPS / 10_000;
    let validator = total_fee - treasury; // absorbs rounding
    FeeShares {
        validator,
        treasury,
    }
}

/// Total block reward for the proposer = inflation emission + fee share.
///
/// # Returns
///
/// `(validator_reward, treasury_reward, burned=0)` — all in base units.
/// Burn is always 0 (no fee burning in MISAKA).
pub fn compute_block_reward(inflation_emission: u64, total_fees: u64) -> (u64, u64, u64) {
    let fee_shares = compute_fee_shares(total_fees);
    let validator_total = inflation_emission.saturating_add(fee_shares.validator);
    (validator_total, fee_shares.treasury, 0) // burn = 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_shares_basic() {
        let s = compute_fee_shares(10_000);
        assert_eq!(s.validator, 9_000); // 90%
        assert_eq!(s.treasury, 1_000); // 10%
        assert_eq!(s.validator + s.treasury, 10_000);
    }

    #[test]
    fn test_fee_shares_rounding() {
        // 10001 → treasury=1000, validator=9001 (dust goes to validator)
        let s = compute_fee_shares(10_001);
        assert_eq!(s.validator + s.treasury, 10_001);
        assert_eq!(s.treasury, 1_000);
        assert_eq!(s.validator, 9_001);
    }

    #[test]
    fn test_fee_shares_zero() {
        let s = compute_fee_shares(0);
        assert_eq!(s.validator, 0);
        assert_eq!(s.treasury, 0);
    }

    #[test]
    fn test_no_burn() {
        // Burn is always 0
        let (_, _, burned) = compute_block_reward(1000, 10_000);
        assert_eq!(burned, 0);
    }

    #[test]
    fn test_block_reward() {
        let (validator, treasury, burned) = compute_block_reward(1000, 10_000);
        assert_eq!(validator, 1000 + 9000); // inflation + 90% fees
        assert_eq!(treasury, 1000); // 10% fees
        assert_eq!(burned, 0); // no burn
    }
}
