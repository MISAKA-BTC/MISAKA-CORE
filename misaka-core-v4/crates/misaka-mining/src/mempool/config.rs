//! Mempool configuration.

/// Configuration for the transaction mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum total mass of all transactions in mempool.
    pub max_mempool_mass: u64,
    /// Maximum number of transactions.
    pub max_transaction_count: usize,
    /// Maximum orphan pool size.
    pub max_orphan_count: usize,
    /// Minimum fee rate to accept (fee/mass).
    pub minimum_fee_rate: f64,
    /// Minimum RBF fee increment multiplier (e.g., 1.25 = 25% more).
    pub rbf_fee_increment: f64,
    /// Maximum age of a transaction in the mempool (seconds).
    pub max_tx_age_seconds: u64,
    /// Whether to accept non-standard transactions.
    pub accept_non_standard: bool,
    /// Target time per block in milliseconds.
    pub target_time_per_block: u64,
    /// Maximum block mass.
    pub max_block_mass: u64,
}

impl MempoolConfig {
    pub fn build_default(
        target_time_per_block: u64,
        relay_non_std: bool,
        max_block_mass: u64,
    ) -> Self {
        Self {
            max_mempool_mass: max_block_mass * 100, // 100 blocks worth
            max_transaction_count: 1_000_000,
            max_orphan_count: 500,
            minimum_fee_rate: 1.0,
            rbf_fee_increment: 1.25,
            max_tx_age_seconds: 3600 * 24, // 24 hours
            accept_non_standard: relay_non_std,
            target_time_per_block,
            max_block_mass,
        }
    }

    pub fn apply_ram_scale(mut self, scale: f64) -> Self {
        self.max_mempool_mass = (self.max_mempool_mass as f64 * scale) as u64;
        self.max_transaction_count = (self.max_transaction_count as f64 * scale) as usize;
        self
    }
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self::build_default(1000, false, 500_000)
    }
}
