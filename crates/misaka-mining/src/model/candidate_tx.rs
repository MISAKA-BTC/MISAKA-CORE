//! Candidate transaction model for block template selection.

/// A transaction candidate for block template inclusion.
#[derive(Debug, Clone)]
pub struct CandidateTx {
    /// Transaction ID (hash).
    pub tx_id: [u8; 32],
    /// Serialized transaction data.
    pub data: Vec<u8>,
    /// Transaction mass (weight).
    pub mass: u64,
    /// Transaction fee in base units.
    pub fee: u64,
    /// Fee rate (fee / mass).
    pub fee_rate: f64,
    /// Number of inputs.
    pub input_count: usize,
    /// Number of outputs.
    pub output_count: usize,
    /// Dependency transaction IDs (parents in mempool).
    pub dependencies: Vec<[u8; 32]>,
}

impl CandidateTx {
    pub fn fee_rate(&self) -> f64 {
        if self.mass == 0 {
            0.0
        } else {
            self.fee as f64 / self.mass as f64
        }
    }
}
