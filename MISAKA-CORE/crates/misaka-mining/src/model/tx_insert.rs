//! Transaction insertion result types.

/// Result of inserting a transaction into the mempool.
#[derive(Debug, Clone)]
pub struct TransactionInsertion {
    /// Whether the transaction was accepted.
    pub accepted: bool,
    /// Transaction ID.
    pub tx_id: [u8; 32],
    /// If the transaction replaced another via RBF.
    pub replaced_tx: Option<[u8; 32]>,
    /// Transactions that became ready after this insertion resolved their deps.
    pub unorphaned: Vec<[u8; 32]>,
}
