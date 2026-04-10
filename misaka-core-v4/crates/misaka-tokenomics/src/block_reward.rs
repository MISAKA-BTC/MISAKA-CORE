//! Block Reward — connects inflation schedule + fee distribution to coinbase UTXO creation.
//!
//! This module is the bridge between tokenomics calculations and the actual
//! UTXO state transitions. Called by the block producer after successful
//! block execution.
//!
//! # Flow
//!
//! ```text
//! Block produced → execute_block() → compute_block_rewards() → coinbase TX(s)
//!                                          │
//!                       ┌─────────────────┼──────────────────┐
//!                       │                 │                  │
//!                  Proposer TX      Treasury TX         Burn (no TX)
//!                  (inflation +     (fee share)
//!                   fee share)
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
/// `Ok(BlockRewardOutputs)` with amounts for proposer, treasury, and burn.
///
/// # Errors
///
/// SEC-FIX T3-H7: Returns `Err` if emission overflows `u64` instead of
/// silently minting `u64::MAX` tokens.
pub fn compute_block_rewards(
    params: &BlockRewardParams,
    total_fees: u64,
) -> Result<BlockRewardOutputs, BlockRewardError> {
    let emission_u128 = epoch_emission(
        params.total_supply,
        params.chain_year,
        params.epochs_per_year,
    );
    let emission: u64 = emission_u128.try_into().map_err(|_| {
        BlockRewardError::EmissionOverflow {
            emission: emission_u128,
        }
    })?;

    let (proposer_total, treasury_share, burn_share) = compute_block_reward(emission, total_fees);

    Ok(BlockRewardOutputs {
        proposer_amount: proposer_total,
        treasury_amount: treasury_share,
        burn_amount: burn_share,
        inflation_emission: emission,
    })
}

/// Errors from block reward computation.
#[derive(Debug, thiserror::Error)]
pub enum BlockRewardError {
    #[error("epoch emission {emission} exceeds u64::MAX — refusing to mint")]
    EmissionOverflow { emission: u128 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_rewards_basic() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 0,
            epochs_per_year: 525_600,
            proposer_address: [0xAA; 32],
            treasury_address: [0xBB; 32],
        };

        // No fees: proposer gets only inflation
        let r = compute_block_rewards(&params, 0).unwrap();
        assert_eq!(r.inflation_emission, 951); // 500M / 525600
        assert_eq!(r.proposer_amount, 951);
        assert_eq!(r.treasury_amount, 0);
        assert_eq!(r.burn_amount, 0);

        // With fees: proposer gets inflation + 50% fees, treasury gets 10%
        let r2 = compute_block_rewards(&params, 10_000).unwrap();
        assert_eq!(r2.inflation_emission, 951);
        assert_eq!(r2.proposer_amount, 951 + 5_000); // inflation + 50% fee
        assert_eq!(r2.treasury_amount, 1_000); // 10% fee
        assert_eq!(r2.burn_amount, 4_000); // 40% fee
    }

    #[test]
    fn test_year_8_floor_rate() {
        let params = BlockRewardParams {
            total_supply: 10_000_000_000,
            chain_year: 8,
            epochs_per_year: 525_600,
            proposer_address: [0; 32],
            treasury_address: [0; 32],
        };
        let r = compute_block_rewards(&params, 0).unwrap();
        assert_eq!(r.inflation_emission, 190); // 100M / 525600
    }
}
