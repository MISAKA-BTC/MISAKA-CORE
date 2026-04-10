//! JSON-RPC 2.0 error codes — standard + MISAKA extensions.

use serde_json::Value;

// ── JSON-RPC 2.0 standard ──
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// ── MISAKA extensions (-32000 ~ -32099) ──
pub const TX_REJECTED_MEMPOOL_FULL: i32 = -32000;
pub const TX_REJECTED_INVALID_SIGNATURE: i32 = -32001;
pub const TX_REJECTED_INSUFFICIENT_FUNDS: i32 = -32002;
pub const TX_REJECTED_NULLIFIER_CONFLICT: i32 = -32003;
pub const TX_REJECTED_INVALID_FORMAT: i32 = -32004;
pub const BLOCK_NOT_FOUND: i32 = -32010;
pub const TX_NOT_FOUND: i32 = -32011;
pub const ADDRESS_INVALID: i32 = -32020;
pub const NODE_SYNCING: i32 = -32030;
pub const NODE_NOT_READY: i32 = -32031;
pub const RATE_LIMITED: i32 = -32070;
pub const UNAUTHORIZED: i32 = -32080;
pub const NOT_IMPLEMENTED: i32 = -32099;

/// Build a JSON-RPC 2.0 error object.
pub fn rpc_error(code: i32, message: &str, data: Option<Value>) -> Value {
    let mut err = serde_json::json!({
        "code": code,
        "message": message,
    });
    if let Some(d) = data {
        err["data"] = d;
    }
    err
}

/// Build a full JSON-RPC 2.0 error response.
pub fn error_response(id: Value, code: i32, message: &str, data: Option<Value>) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": rpc_error(code, message, data),
    })
}

/// Build a full JSON-RPC 2.0 success response.
pub fn success_response(id: Value, result: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}
