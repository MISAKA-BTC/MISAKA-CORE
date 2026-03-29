//! Fee distribution and block reward computation.
//!
//! # Fee Distribution (per block)
//!
//! | Recipient  | Share | Purpose                            |
//! |-----------|-------|------------------------------------|
//! | Proposer  | 50%   | Block proposer reward              |
//! | Treasury  | 10%   | Protocol development fund          |
//! | Burn      | 40%   | Deflationary pressure              |
//!
//! # Block Reward = Inflation Emission + Proposer Fee Share
//!
//! The proposer receives:
//! 1. Inflation emission for this block (from `inflation.rs`)
//! 2. 50% of total transaction fees in this block

/// Proposer receives 50% of fees.
pub const PROPOSER_FEE_BPS: u64 = 5000;
/// Treasury receives 10% of fees.
pub const TREASURY_FEE_BPS: u64 = 1000;
/// Burned: 40% of fees (remainder).
pub const BURN_FEE_BPS: u64 = 4000;

/// Fee distribution for a single block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeShares {
    /// Amount sent to the block proposer.
    pub proposer: u64,
    /// Amount sent to the protocol treasury.
    pub treasury: u64,
    /// Amount permanently burned (removed from circulation).
    pub burned: u64,
}

/// Compute fee distribution for a block's total fees.
///
/// Invariant: `proposer + treasury + burned == total_fee`
/// (rounding dust goes to burn).
pub fn compute_fee_shares(total_fee: u64) -> FeeShares {
    let proposer = total_fee * PROPOSER_FEE_BPS / 10_000;
    let treasury = total_fee * TREASURY_FEE_BPS / 10_000;
    let burned = total_fee - proposer - treasury; // absorbs rounding
    FeeShares {
        proposer,
        treasury,
        burned,
    }
}

/// Total block reward for the proposer = inflation emission + fee share.
///
/// # Arguments
///
/// - `inflation_emission`: Per-block emission from `inflation::epoch_emission()`
/// - `total_fees`: Sum of all transaction fees in this block
///
/// # Returns
///
/// `(proposer_reward, treasury_reward, burned)` — all in base units.
pub fn compute_block_reward(inflation_emission: u64, total_fees: u64) -> (u64, u64, u64) {
    let fee_shares = compute_fee_shares(total_fees);
    let proposer_total = inflation_emission.saturating_add(fee_shares.proposer);
    (proposer_total, fee_shares.treasury, fee_shares.burned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_shares_basic() {
        let s = compute_fee_shares(10_000);
        assert_eq!(s.proposer, 5_000); // 50%
        assert_eq!(s.treasury, 1_000); // 10%
        assert_eq!(s.burned, 4_000); // 40%
        assert_eq!(s.proposer + s.treasury + s.burned, 10_000);
    }

    #[test]
    fn test_fee_shares_rounding() {
        // 10001 → proposer=5000, treasury=1000, burned=4001 (dust goes to burn)
        let s = compute_fee_shares(10_001);
        assert_eq!(s.proposer + s.treasury + s.burned, 10_001);
    }

    #[test]
    fn test_fee_shares_zero() {
        let s = compute_fee_shares(0);
        assert_eq!(s.proposer, 0);
        assert_eq!(s.treasury, 0);
        assert_eq!(s.burned, 0);
    }

    #[test]
    fn test_block_reward() {
        let (proposer, treasury, burned) = compute_block_reward(1000, 10_000);
        assert_eq!(proposer, 1000 + 5000); // inflation + 50% fees
        assert_eq!(treasury, 1000); // 10% fees
        assert_eq!(burned, 4000); // 40% fees
    }
}
