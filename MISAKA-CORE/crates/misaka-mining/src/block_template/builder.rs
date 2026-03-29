//! Block template builder: assembles transactions into a valid block template.

use super::{BlockTemplate, CoinbaseData, TemplateTransaction, TemplateBuildMode};
use super::policy::BlockPolicy;
use super::selector::TransactionSelector;
use crate::errors::{MiningError, MiningResult};

/// Builds block templates from mempool transactions.
pub struct BlockTemplateBuilder {
    policy: BlockPolicy,
}

impl BlockTemplateBuilder {
    pub fn new(policy: BlockPolicy) -> Self {
        Self { policy }
    }

    /// Build a block template from selected transactions.
    pub fn build(
        &self,
        parent_hashes: Vec<[u8; 32]>,
        daa_score: u64,
        timestamp: u64,
        bits: u32,
        coinbase: CoinbaseData,
        transactions: Vec<TemplateTransaction>,
    ) -> MiningResult<BlockTemplate> {
        let total_mass: u64 = transactions.iter().map(|t| t.mass).sum();
        let total_fees: u64 = transactions.iter().map(|t| t.fee).sum();

        if total_mass > self.policy.max_block_mass {
            return Err(MiningError::TemplateBuildFailed(
                format!("block mass {} exceeds limit {}", total_mass, self.policy.max_block_mass)
            ));
        }

        let header_hash = compute_template_hash(&parent_hashes, timestamp, daa_score, bits);

        Ok(BlockTemplate {
            header_hash,
            parent_hashes,
            timestamp,
            daa_score,
            bits,
            coinbase_data: coinbase,
            transactions,
            total_mass,
            total_fees,
            build_mode: TemplateBuildMode::Standard,
        })
    }

    /// Modify an existing template with new coinbase data.
    pub fn modify_coinbase(template: &BlockTemplate, new_coinbase: CoinbaseData) -> BlockTemplate {
        let mut new = template.clone();
        new.coinbase_data = new_coinbase;
        new.build_mode = TemplateBuildMode::CoinbaseUpdate;
        new.header_hash = compute_template_hash(
            &new.parent_hashes, new.timestamp, new.daa_score, new.bits,
        );
        new
    }

    /// Build an empty block (emergency fallback).
    pub fn build_empty(
        parent_hashes: Vec<[u8; 32]>,
        daa_score: u64,
        timestamp: u64,
        bits: u32,
        coinbase: CoinbaseData,
    ) -> BlockTemplate {
        let header_hash = compute_template_hash(&parent_hashes, timestamp, daa_score, bits);
        BlockTemplate {
            header_hash,
            parent_hashes,
            timestamp,
            daa_score,
            bits,
            coinbase_data: coinbase,
            transactions: Vec::new(),
            total_mass: 0,
            total_fees: 0,
            build_mode: TemplateBuildMode::Empty,
        }
    }
}

fn compute_template_hash(
    parents: &[[u8; 32]],
    timestamp: u64,
    daa_score: u64,
    bits: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for p in parents { hasher.update(p); }
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(&daa_score.to_le_bytes());
    hasher.update(&bits.to_le_bytes());
    *hasher.finalize().as_bytes()
}
