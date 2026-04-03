//! Transaction query types for mempool inspection.

/// Query result for a mempool transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionQuery {
    pub tx_id: String,
    pub mass: u64,
    pub fee: u64,
    pub fee_rate: f64,
    pub is_orphan: bool,
    pub input_count: usize,
    pub output_count: usize,
    pub added_at_daa_score: u64,
}
