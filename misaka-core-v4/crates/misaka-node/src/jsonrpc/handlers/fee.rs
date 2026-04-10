use serde_json::{json, Value};
use crate::dag_rpc::DagRpcState;
use super::HandlerResult;
use crate::jsonrpc::error::*;

/// `estimatesmartfee` — estimate fee rate for target confirmation blocks.
///
/// Delegates to the same mempool-pressure heuristic used by the existing
/// `/api/fee_estimate` endpoint.
pub async fn estimate_smart_fee(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let conf_target = params.get(0)
        .and_then(|v| v.as_u64())
        .unwrap_or(6);

    let s = rpc.node.read().await;
    let mempool_size = s.mempool.len();

    // Same heuristic as dag_fee_estimate in dag_rpc.rs
    let feerate = if mempool_size < 100 {
        100u64
    } else if mempool_size < 500 {
        200
    } else {
        500
    };

    Ok(json!({
        "feerate": feerate,
        "blocks": conf_target,
    }))
}
