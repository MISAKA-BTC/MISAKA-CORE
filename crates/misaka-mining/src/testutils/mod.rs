//! Test utilities for the mining subsystem.

pub mod consensus_mock;

use crate::mempool::model::tx::MempoolTransaction;

/// Create a mock mempool transaction for testing.
pub fn mock_tx(id: u8, mass: u64, fee: u64) -> MempoolTransaction {
    let mut tx_id = [0u8; 32];
    tx_id[0] = id;
    MempoolTransaction {
        tx_id,
        raw_data: vec![0; mass as usize],
        mass,
        fee,
        input_count: 1,
        output_count: 1,
        input_outpoints: vec![],
        added_daa_score: 100,
        added_timestamp: 0,
        is_high_priority: false,
    }
}
