//! UTXO conversion utilities.

use crate::model::RpcUtxoEntry;

pub fn format_outpoint(tx_id: &[u8; 32], index: u32) -> String {
    format!("{}:{}", hex::encode(tx_id), index)
}
