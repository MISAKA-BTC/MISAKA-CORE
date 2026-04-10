//! UTXO conversion utilities.

pub fn format_outpoint(tx_id: &[u8; 32], index: u32) -> String {
    format!("{}:{}", hex::encode(tx_id), index)
}
