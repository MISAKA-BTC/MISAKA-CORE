//! Block construction policy: mass limits, transaction selection rules.

/// Policy parameters for block template construction.
#[derive(Debug, Clone)]
pub struct BlockPolicy {
    /// Maximum block mass.
    pub max_block_mass: u64,
    /// Maximum number of transactions per block.
    pub max_tx_count: usize,
    /// Minimum fee rate for inclusion.
    pub min_fee_rate: f64,
    /// Whether to include orphan-resolving transactions.
    pub include_orphan_resolvers: bool,
    /// Maximum coinbase extra data size.
    pub max_coinbase_extra_data: usize,
}

impl Default for BlockPolicy {
    fn default() -> Self {
        Self {
            max_block_mass: 500_000,
            max_tx_count: 50_000,
            min_fee_rate: 1.0,
            include_orphan_resolvers: false,
            max_coinbase_extra_data: 150,
        }
    }
}
