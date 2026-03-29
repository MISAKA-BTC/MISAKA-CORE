//! RPC connection abstraction.

use std::net::SocketAddr;

/// Dynamic RPC connection trait.
pub trait RpcConnection: Send + Sync {
    fn id(&self) -> u64;
    fn peer_addr(&self) -> Option<SocketAddr>;
    fn is_open(&self) -> bool;
}

pub type DynRpcConnection = dyn RpcConnection;

/// RPC connection info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionInfo {
    pub id: u64,
    pub peer_addr: String,
    pub connected_since: u64,
    pub is_authenticated: bool,
}
