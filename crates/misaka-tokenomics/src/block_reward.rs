//! Block Reward — connects inflation schedule + fee distribution to coinbase UTXO creation.
//!
//! This module is the bridge between tokenomics calculations and the actual
//! UTXO state transitions. Called by the block producer after successful
//! block execution.
//!
//! # Inflation Schedule
//!
//! - Year 0: 0% (no emission — genesis stabilization period)
//! - Year 1: 3.00% (emission starts, distributed to 21 SR by stake ratio)
//! - Decay: -0.50%/year
//! - Floor: 1.00% (year 5+)
//!
//! # Fee Distribution: Validator 90% / Treasury 10% / Burn 0%
//!
//! ```text
//! Block produced → execute_block() → compute_block_rewards() → coinbase TX(s)
//!                                          │
//!                       ┌─────────────────┤
//!                       │                 │
//!                  Validator TX      Treasury TX
//!                  (inflation +     (10% fee share)
//!                   90% fee share)
//! ```

use crate::distribution::compute_block_reward;
use crate::inflation::epoch_emission;

/// Parameters needed to compute block rewards.
#[derive(Debug, Clone)]
pub struct BlockRewardParams {
    /// Current total supply (in base units).
    pub total_supply: u128,
    /// Current year of the chain (0-indexed from genesis).
    pub chain_year: u64,
    /// Epochs (blocks) per year (e.g. 525_600 for 60s blocks).
    pub epochs_per_year: u64,
    /// One-time address for the proposer's reward output.
    pub proposer_address: [u8; 32],
    /// One-time address for the treasury reward output (if any).
    pub treasury_address: [u8; 32],
}

/// Computed reward outputs for a single block.
#[derive(Debug, Clone)]
pub struct BlockRewardOutputs {
    /// Amount to send to the block proposer (inflation + fee share).
    pub proposer_amount: u64,
    /// Amount to send to the treasury (fee share only).
    pub treasury_amount: u64,
    /// Amount burned (removed from circulation).
    pub burn_amount: u64,
    /// Per-block inflation emission (subset of proposer_amount).
    pub inflation_emission: u64,
}

/// Compute reward outputs for a block.
///
/// # Arguments
///
/// - `params`: Chain parameters and addresses
/// - `total_fees`: Sum of all transaction fees in this block
///
/// # Returns
///
/// `BlockRewardOutputs` with amounts for proposer, treasury, and burn.
pub fn compute_block_rewards(params: &BlockRewardParams, total_fees: u64) -> BlockRewardOutputs {
    // Inflation emission for this block
    let emission = epoch_emission(
        params.total_supply,
        params.chain_year,
        params.epochs_per_year,
    ) as u64;

    // Fee distribution: proposer gets inflation + fee share
    let (proposer_total, treasury_share, burn_share) = compute_block_reward(emission, total_fees);

    BlockRewardOutputs {
        proposer_amount: proposer_total,
        treasury_amount: treasury_share,
        burn_amount: burn_share,
        inflation_emission: emission,
    }
}

/// CRIT-4 FIX: Validate that a coinbase transaction's output amounts match
/// the expected block reward.
///
/// Called by block validators to ensure the proposer didn't inflate the reward.
///
/// # Arguments
/// - `params`: chain parameters for emission calculation
/// - `total_fees`: sum of all TX fees in this block
/// - `coinbase_proposer_amount`: actual amount in coinbase TX for proposer
/// - `coinbase_treasury_amount`: actual amount in coinbase TX for treasury
///
/// # Returns
/// `Ok(())` if amounts are valid, `Err` with description if not.
pub fn validate_coinbase_amounts(
    params: &BlockRewardParams,
    total_fees: u64,
    coinbase_proposer_amount: u64,
    coinbase_treasury_amount: u64,
) -> Result<(), String> {
    let expected = compute_block_rewards(params, total_fees);

    if coinbase_proposer_amount != expected.proposer_amount {
        return Err(format!(
            "coinbase proposer amount mismatch: got {}, expected {}",
            coinbase_proposer_amount, expected.proposer_amount
        ));
    }
    if coinbase_treasury_amount != expected.treasury_amount {
        return Err(format!(
            "coinbase treasury amount mismatch: got {}, expected {}",
            coinbase_treasury_amount, expected.treasury_amount
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_validation_correct() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 1,
            epochs_per_year: 525_600,
            proposer_address: [0xAA; 32],
            treasury_address: [0xBB; 32],
        };
        let expected = compute_block_rewards(&params, 10_000);
        assert!(validate_coinbase_amounts(
            &params, 10_000,
            expected.proposer_amount,
            expected.treasury_amount,
        ).is_ok());
    }

    #[test]
    fn test_coinbase_validation_inflated_proposer() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 1,
            epochs_per_year: 525_600,
            proposer_address: [0xAA; 32],
            treasury_address: [0xBB; 32],
        };
        // Try to claim more than allowed
        assert!(validate_coinbase_amounts(&params, 10_000, 999_999, 1_000).is_err());
    }

    #[test]
    fn test_year0_no_emission() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 0,
            epochs_per_year: 525_600,
            proposer_address: [0xAA; 32],
            treasury_address: [0xBB; 32],
        };
        // Year 0: NO inflation emission
        let r = compute_block_rewards(&params, 0);
        assert_eq!(r.inflation_emission, 0);
        assert_eq!(r.proposer_amount, 0);
        assert_eq!(r.burn_amount, 0);

        // Year 0 with fees: validator gets 90% fees, no inflation
        let r2 = compute_block_rewards(&params, 10_000);
        assert_eq!(r2.inflation_emission, 0);
        assert_eq!(r2.proposer_amount, 9_000); // 0 inflation + 90% fee
        assert_eq!(r2.treasury_amount, 1_000); // 10% fee
        assert_eq!(r2.burn_amount, 0); // no burn
    }

    #[test]
    fn test_year1_emission_starts() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 1,
            epochs_per_year: 525_600,
            proposer_address: [0xAA; 32],
            treasury_address: [0xBB; 32],
        };
        // Year 1: 3% of 10B = 300M / 525600 = 570 per block
        let r = compute_block_rewards(&params, 0);
        assert_eq!(r.inflation_emission, 570);
        assert_eq!(r.proposer_amount, 570);

        // With fees: validator gets inflation + 90% fees
        let r2 = compute_block_rewards(&params, 10_000);
        assert_eq!(r2.proposer_amount, 570 + 9_000); // inflation + 90% fee
        assert_eq!(r2.treasury_amount, 1_000); // 10% fee
        assert_eq!(r2.burn_amount, 0);
    }

    #[test]
    fn test_year5_floor_rate() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 5,
            epochs_per_year: 525_600,
            proposer_address: [0; 32],
            treasury_address: [0; 32],
        };
        // Year 5+: 1% floor → 100M / 525600 = 190 per block
        let r = compute_block_rewards(&params, 0);
        assert_eq!(r.inflation_emission, 190);
    }
}
