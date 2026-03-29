//! Transaction conversion utilities.

use crate::model::{RpcTransaction, RpcTransactionInput, RpcTransactionOutput};

pub fn tx_id_to_hex(id: &[u8; 32]) -> String { hex::encode(id) }

pub fn build_rpc_tx(
    tx_id: [u8; 32],
    inputs: Vec<RpcTransactionInput>,
    outputs: Vec<RpcTransactionOutput>,
    mass: u64,
) -> RpcTransaction {
    RpcTransaction {
        tx_id: hex::encode(tx_id),
        inputs,
        outputs,
        mass,
        fee: 0,
        payload: String::new(),
        version: 1,
    }
}
