//! RPC server: HTTP and WebSocket transport.

use crate::error::RpcResult;
use crate::service::RpcService;
use std::net::SocketAddr;

/// RPC server configuration.
#[derive(Debug, Clone)]
pub struct RpcServerConfig {
    pub listen_addr: SocketAddr,
    pub max_connections: usize,
    pub rate_limit_per_second: f64,
    pub enable_websocket: bool,
    pub ws_max_frame_size: usize,
    pub cors_allowed_origins: Vec<String>,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:16110".parse().expect("valid addr"),
            max_connections: 100,
            rate_limit_per_second: 100.0,
            enable_websocket: true,
            ws_max_frame_size: 16 * 1024 * 1024,
            cors_allowed_origins: vec!["*".to_string()],
        }
    }
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".to_string(), result: Some(result), error: None, id }
    }

    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError { code, message, data: None }),
            id,
        }
    }
}
