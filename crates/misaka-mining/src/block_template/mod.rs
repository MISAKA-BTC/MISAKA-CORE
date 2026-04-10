//! Block template construction for validators.

pub mod builder;
pub mod policy;
pub mod selector;

/// A block template ready for signing by a validator.
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    pub header_hash: [u8; 32],
    pub parent_hashes: Vec<[u8; 32]>,
    pub timestamp: u64,
    pub daa_score: u64,
    pub bits: u32,
    pub coinbase_data: CoinbaseData,
    pub transactions: Vec<TemplateTransaction>,
    pub total_mass: u64,
    pub total_fees: u64,
    pub build_mode: TemplateBuildMode,
}

#[derive(Debug, Clone)]
pub struct CoinbaseData {
    pub validator_script: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub reward: u64,
    pub fees: u64,
}

#[derive(Debug, Clone)]
pub struct TemplateTransaction {
    pub tx_id: [u8; 32],
    pub raw_data: Vec<u8>,
    pub mass: u64,
    pub fee: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateBuildMode {
    /// Standard build from mempool.
    Standard,
    /// Rebuild with updated coinbase only.
    CoinbaseUpdate,
    /// Emergency empty block.
    Empty,
}
