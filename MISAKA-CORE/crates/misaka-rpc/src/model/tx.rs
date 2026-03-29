use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransaction {
    pub tx_id: String,
    pub version: u32,
    pub inputs: Vec<RpcTransactionInput>,
    pub outputs: Vec<RpcTransactionOutput>,
    pub mass: u64,
    pub fee: u64,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransactionInput {
    pub previous_outpoint: RpcOutpoint,
    pub signature_script: String,
    pub sequence: u64,
    pub sig_op_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOutpoint {
    pub transaction_id: String,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransactionOutput {
    pub value: u64,
    pub script_public_key: RpcScriptPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcScriptPublicKey {
    pub version: u16,
    pub script: String,
}
