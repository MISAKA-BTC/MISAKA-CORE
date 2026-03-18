//! JSON-RPC server with PQ transaction support.

use serde::{Deserialize, Serialize};

pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".into(), result: Some(result), error: None, id }
    }
    pub fn error(id: serde_json::Value, code: i64, message: String) -> Self {
        Self { jsonrpc: "2.0".into(), result: None, error: Some(JsonRpcError { code, message }), id }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub chain_id: u32,
    pub height: u64,
    pub utxo_count: usize,
    pub mempool_size: usize,
    pub validator_scheme: String,
    pub ring_signature_scheme: String,
    pub tx_privacy: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: u64,
    pub has_stealth: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxSubmitResult {
    pub tx_hash: String,
    pub accepted: bool,
    pub error: Option<String>,
}

pub fn handle_request(
    req: &JsonRpcRequest,
    height: u64,
    utxo_count: usize,
    mempool_size: usize,
) -> JsonRpcResponse {
    match req.method.as_str() {
        "misaka_getStatus" => {
            let status = NodeStatus {
                chain_id: 1, height, utxo_count, mempool_size,
                validator_scheme: "ML-DSA-65 (PQ-only)".into(),
                ring_signature_scheme: "LogRing-v1 O(log n) [default], LRS-v1 O(n) [legacy]".into(),
                tx_privacy: "LogRing linkable ring sig + ML-KEM-768 stealth".into(),
            };
            JsonRpcResponse::success(req.id.clone(), serde_json::to_value(status).unwrap())
        }
        "misaka_getUtxoCount" => {
            JsonRpcResponse::success(req.id.clone(), serde_json::json!(utxo_count))
        }
        "misaka_getHeight" => {
            JsonRpcResponse::success(req.id.clone(), serde_json::json!(height))
        }
        _ => JsonRpcResponse::error(req.id.clone(), ERR_METHOD_NOT_FOUND,
            format!("unknown method: {}", req.method)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_status() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(), method: "misaka_getStatus".into(),
            params: serde_json::Value::Null, id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 42, 1000, 5);
        assert!(resp.result.is_some());
        let status: NodeStatus = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(status.height, 42);
        assert_eq!(status.utxo_count, 1000);
    }

    #[test]
    fn test_rpc_unknown_method() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(), method: "foo".into(),
            params: serde_json::Value::Null, id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 0, 0, 0);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_rpc_height() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(), method: "misaka_getHeight".into(),
            params: serde_json::Value::Null, id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 99, 0, 0);
        assert_eq!(resp.result.unwrap(), serde_json::json!(99));
    }
}
