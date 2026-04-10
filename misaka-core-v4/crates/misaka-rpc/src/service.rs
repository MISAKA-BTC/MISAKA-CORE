//! RPC service: dispatches JSON-RPC calls to the appropriate handlers.

use crate::error::{RpcError, RpcResult};
use crate::server::{JsonRpcRequest, JsonRpcResponse};

/// RPC service that dispatches requests.
pub struct RpcService {
    #[allow(dead_code)]
    name: String,
}

impl RpcService {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Dispatch a JSON-RPC request.
    pub async fn dispatch(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();
        match self.handle_method(&request.method, request.params).await {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err(err) => {
                let (code, msg) = match &err {
                    RpcError::MethodNotFound(_) => (-32601, err.to_string()),
                    RpcError::InvalidParams(_) => (-32602, err.to_string()),
                    RpcError::Internal(_) => (-32603, err.to_string()),
                    RpcError::RateLimited => (-32000, "rate limited".to_string()),
                    _ => (-32603, err.to_string()),
                };
                JsonRpcResponse::error(id, code, msg)
            }
        }
    }

    async fn handle_method(
        &self,
        method: &str,
        _params: serde_json::Value,
    ) -> RpcResult<serde_json::Value> {
        match method {
            "ping" => Ok(serde_json::json!({})),
            "getSystemInfo" => Ok(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "serverVersion": "misaka-rpc/1.0",
                "networkId": "misaka-mainnet",
                "isSynced": true,
                "isUtxoIndexed": true,
            })),
            "getBlockCount" => Ok(serde_json::json!({
                "headerCount": 0,
                "blockCount": 0,
            })),
            "getBlockDagInfo" => Ok(serde_json::json!({
                "network": "misaka-mainnet",
                "blockCount": 0,
                "headerCount": 0,
            })),
            "getSinkBlueScore" => Ok(serde_json::json!({ "blueScore": 0 })),
            "getVirtualDaaScore" => Ok(serde_json::json!({ "virtualDaaScore": 0 })),
            "estimateFeeRate" => Ok(serde_json::json!({
                "priorityFeeRate": 10.0,
                "normalFeeRate": 5.0,
                "lowFeeRate": 1.0,
            })),
            _ => Err(RpcError::MethodNotFound(method.to_string())),
        }
    }
}
