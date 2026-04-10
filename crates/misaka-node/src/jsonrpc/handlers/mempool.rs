use super::HandlerResult;
use crate::dag_rpc::DagRpcState;
use serde_json::{json, Value};

/// `getmempoolinfo` — mempool summary.
pub async fn get_mempool_info(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    Ok(json!({
        "size": s.mempool.len(),
        "bytes": 0, // TODO: track aggregate serialized size
    }))
}

/// `getrawmempool` — list transaction hashes in the mempool.
pub async fn get_raw_mempool(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let _verbose = params.get(0).and_then(|v| v.as_bool()).unwrap_or(false);

    let s = rpc.node.read().await;
    let tx_hashes: Vec<Value> = s
        .mempool
        .all_tx_hashes()
        .iter()
        .map(|h| Value::String(hex::encode(h)))
        .collect();

    Ok(Value::Array(tx_hashes))
}
