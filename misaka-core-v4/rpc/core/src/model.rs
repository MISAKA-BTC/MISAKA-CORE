//! Shared RPC request/response models.

use serde::{Deserialize, Serialize};

/// Block header information returned by RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlockHeader {
    pub hash: String,
    pub version: u32,
    pub parents: Vec<String>,
    pub timestamp: u64,
    pub blue_score: u64,
    pub blue_work: String,
    pub bits: u32,
}

/// Chain/DAG information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDagInfo {
    pub network: String,
    pub block_count: u64,
    pub header_count: u64,
    pub tip_hashes: Vec<String>,
    pub virtual_daa_score: u64,
    pub pruning_point_hash: String,
}

/// Peer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPeerInfo {
    pub id: String,
    pub address: String,
    pub is_outbound: bool,
    pub user_agent: String,
    pub protocol_version: u32,
}

/// Node health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcHealthResponse {
    pub is_synced: bool,
    pub peer_count: u32,
    pub block_count: u64,
    pub version: String,
}
