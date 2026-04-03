//! RPC API trait definition.
//!
//! All RPC servers (gRPC, wRPC, JSON-RPC) can implement this trait once the
//! current local runtime/operator contract is ready to converge on a shared
//! transport-agnostic surface.

use crate::error::RpcResult;
use crate::model::*;

/// The core RPC API trait. Transport-agnostic.
pub trait RpcApi: Send + Sync {
    fn get_block(&self, hash: &str, include_txs: bool) -> RpcResult<serde_json::Value>;
    fn get_block_count(&self) -> RpcResult<u64>;
    fn submit_block(&self, block_hex: &str) -> RpcResult<String>;
    fn get_dag_info(&self) -> RpcResult<RpcDagInfo>;
    fn get_peer_info(&self) -> RpcResult<Vec<RpcPeerInfo>>;
    fn get_health(&self) -> RpcResult<RpcHealthResponse>;
    fn ping(&self) -> RpcResult<()>;
}
