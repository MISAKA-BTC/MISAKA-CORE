//! RPC data model types.

pub mod address;
pub mod block;
pub mod header;
pub mod mempool;
pub mod network;
pub mod tx;

use serde::{Deserialize, Serialize};

// Re-export commonly used types
pub use block::{RpcBlock, RpcBlockHeader};
pub use tx::{RpcTransaction, RpcTransactionInput, RpcTransactionOutput};

// ─── Request/Response types ───────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSystemInfoResponse {
    pub version: String,
    pub server_version: String,
    pub network_id: String,
    pub is_synced: bool,
    pub is_utxo_indexed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetConnectionsResponse {
    pub peer_count: u32,
    pub connections: Vec<ConnectionEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub address: String,
    pub direction: String,
    pub user_agent: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetMetricsRequest {
    pub process_metrics: bool,
    pub connection_metrics: bool,
    pub bandwidth_metrics: bool,
    pub consensus_metrics: bool,
    pub storage_metrics: bool,
    pub custom_metrics: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetMetricsResponse {
    pub server_time: u64,
    pub process: Option<serde_json::Value>,
    pub connection: Option<serde_json::Value>,
    pub bandwidth: Option<serde_json::Value>,
    pub consensus: Option<serde_json::Value>,
    pub storage: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockResponse {
    pub block: RpcBlock,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlocksResponse {
    pub blocks: Vec<RpcBlock>,
    pub tip_hashes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockCountResponse {
    pub header_count: u64,
    pub block_count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockDagInfoResponse {
    pub network: String,
    pub block_count: u64,
    pub header_count: u64,
    pub tip_hashes: Vec<String>,
    pub difficulty: f64,
    pub past_median_time: u64,
    pub virtual_parent_hashes: Vec<String>,
    pub pruning_point_hash: String,
    pub virtual_daa_score: u64,
    pub sink_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetHeadersResponse {
    pub headers: Vec<RpcBlockHeader>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetMempoolEntriesResponse {
    pub entries: Vec<MempoolEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub tx_id: String,
    pub fee: u64,
    pub mass: u64,
    pub is_orphan: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetMempoolEntryResponse {
    pub entry: MempoolEntry,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    pub tx_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcUtxoEntry {
    pub address: String,
    pub outpoint: String,
    pub amount: u64,
    pub script_public_key: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUtxosByAddressesResponse {
    pub entries: Vec<RpcUtxoEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBalanceByAddressResponse {
    pub address: String,
    pub balance: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBalancesByAddressesResponse {
    pub entries: Vec<GetBalanceByAddressResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetVirtualChainResponse {
    pub removed_chain_block_hashes: Vec<String>,
    pub added_chain_block_hashes: Vec<String>,
    pub accepted_transaction_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockTemplateResponse {
    pub block: RpcBlock,
    pub is_synced: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitBlockResponse {
    pub report: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeeEstimateResponse {
    pub priority_fee_rate: f64,
    pub normal_fee_rate: f64,
    pub low_fee_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscribeResponse {
    pub listener_id: u64,
}
