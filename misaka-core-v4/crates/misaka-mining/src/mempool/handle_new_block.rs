//! Handle transactions that were included in a new block.

use crate::mempool::Mempool;

/// Remove transactions that were included in a block.
pub fn handle_new_block_transactions(mempool: &mut Mempool, block_tx_ids: &[[u8; 32]]) -> usize {
    let mut removed = 0;
    for tx_id in block_tx_ids {
        if mempool.remove(tx_id).is_some() {
            removed += 1;
        }
    }
    tracing::info!("Removed {} transactions included in new block", removed);
    removed
}
