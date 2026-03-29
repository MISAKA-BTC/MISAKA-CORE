#![allow(dead_code, unused_imports, unused_variables)]
//! Coinbase/block reward management.


/// Block reward data for a given block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockRewardData {
    pub proposer_pk: Vec<u8>,
    pub reward_amount: u64,
    pub extra_data: Vec<u8>,
}

/// Coinbase manager handles reward computation.
pub struct CoinbaseManager {
    /// Base reward per block (in base units, 1 MISAKA = 1_000_000_000).
    pub base_block_reward: u64,
    /// Fraction of reward going to proposer (basis points, e.g., 8000 = 80%).
    pub proposer_fraction_bps: u16,
}

impl CoinbaseManager {
    pub fn new(base_block_reward: u64, proposer_fraction_bps: u16) -> Self {
        Self { base_block_reward, proposer_fraction_bps }
    }

    /// Calculate the block reward for a given DAA score.
    pub fn calc_block_reward(&self, daa_score: u64) -> u64 {
        // MISAKA uses a deflationary model with halving
        let halvings = daa_score / 210_000; // blocks per halving epoch
        if halvings >= 64 { return 0; }
        self.base_block_reward >> halvings
    }

    /// Split reward between proposer and stakers.
    pub fn split_reward(&self, total_reward: u64) -> (u64, u64) {
        let proposer = total_reward * self.proposer_fraction_bps as u64 / 10_000;
        let stakers = total_reward - proposer;
        (proposer, stakers)
    }
}
