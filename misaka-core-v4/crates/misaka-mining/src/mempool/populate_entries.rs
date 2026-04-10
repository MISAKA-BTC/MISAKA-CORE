//! Populate UTXO entries for transaction validation.

use crate::mempool::model::tx::MempoolTransaction;

/// Populate a transaction's UTXO entries from the consensus UTXO set.
pub fn populate_mempool_entries(
    tx: &MempoolTransaction,
    _consensus_utxo_lookup: &dyn Fn(&[u8; 36]) -> Option<(u64, Vec<u8>)>,
) -> Result<Vec<(u64, Vec<u8>)>, PopulateError> {
    let mut entries = Vec::with_capacity(tx.input_count);
    for outpoint in &tx.input_outpoints {
        match _consensus_utxo_lookup(outpoint) {
            Some(entry) => entries.push(entry),
            None => return Err(PopulateError::MissingUtxo(hex::encode(outpoint))),
        }
    }
    Ok(entries)
}

#[derive(Debug, thiserror::Error)]
pub enum PopulateError {
    #[error("missing UTXO: {0}")]
    MissingUtxo(String),
}
