//! Transaction removal from mempool.

use crate::mempool::tx::TxRemovalReason;
use crate::mempool::Mempool;

/// Remove a transaction and its dependents from the mempool.
pub fn remove_transaction_chain(
    mempool: &mut Mempool,
    tx_id: &[u8; 32],
    reason: TxRemovalReason,
) -> Vec<[u8; 32]> {
    let mut removed = Vec::new();
    if mempool.remove(tx_id).is_some() {
        removed.push(*tx_id);
        tracing::debug!(
            "Removed tx {} from mempool: {:?}",
            hex::encode(tx_id),
            reason
        );
    }
    removed
}
