use super::tx::RpcTransaction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlock {
    pub header: RpcBlockHeader,
    pub transactions: Vec<RpcTransaction>,
    pub verbose_data: Option<RpcBlockVerboseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlockHeader {
    pub hash: String,
    pub version: u32,
    pub parents: Vec<Vec<String>>,
    pub hash_merkle_root: String,
    pub accepted_id_merkle_root: String,
    pub utxo_commitment: String,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub blue_work: String,
    pub blue_score: u64,
    pub pruning_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlockVerboseData {
    pub hash: String,
    pub difficulty: f64,
    pub selected_parent_hash: String,
    pub transaction_ids: Vec<String>,
    pub is_header_only: bool,
    pub blue_score: u64,
    pub children_hashes: Vec<String>,
    pub merge_set_blues_hashes: Vec<String>,
    pub merge_set_reds_hashes: Vec<String>,
    pub is_chain_block: bool,
}
