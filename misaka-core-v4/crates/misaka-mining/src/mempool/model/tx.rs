//! Mempool transaction model.

/// A transaction stored in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolTransaction {
    pub tx_id: [u8; 32],
    pub raw_data: Vec<u8>,
    pub mass: u64,
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub input_outpoints: Vec<[u8; 36]>,
    pub added_daa_score: u64,
    pub added_timestamp: u64,
    pub is_high_priority: bool,
}

impl MempoolTransaction {
    pub fn fee_rate(&self) -> f64 {
        if self.mass == 0 {
            0.0
        } else {
            self.fee as f64 / self.mass as f64
        }
    }

    pub fn age_seconds(&self, now: u64) -> u64 {
        now.saturating_sub(self.added_timestamp)
    }
}

/// Pre-validation result.
#[derive(Debug)]
pub struct TransactionPreValidation {
    pub tx_id: [u8; 32],
    pub mass: u64,
    pub fee: u64,
    pub is_standard: bool,
}

/// Post-validation result.
#[derive(Debug)]
pub struct TransactionPostValidation {
    pub tx_id: [u8; 32],
    pub is_valid: bool,
    pub error: Option<String>,
}
