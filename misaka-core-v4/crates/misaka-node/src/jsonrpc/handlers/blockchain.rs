use serde_json::{json, Value};
use crate::dag_rpc::DagRpcState;
use super::HandlerResult;
use crate::jsonrpc::error::*;

/// `getblockchaininfo` — summary of the DAG chain state.
pub async fn get_blockchain_info(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let max_score = s.dag_store.max_blue_score();
    let tips = s.dag_store.snapshot().get_tips();
    let best_hash = tips.first().copied().unwrap_or([0u8; 32]);

    Ok(json!({
        "chain": "misaka",
        "blocks": max_score,
        "bestblockhash": hex::encode(best_hash),
        "headers": max_score,
        "narwhal_finalized_height": 0, // TODO: wire when narwhal commit height is tracked
        "chainwork": "0",
        "pruned": false,
    }))
}

/// `getblockcount` — current tip height (blue score).
pub async fn get_block_count(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    Ok(Value::Number(s.dag_store.max_blue_score().into()))
}

/// `getbestblockhash` — hash of the current best tip.
pub async fn get_best_block_hash(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let tips = s.dag_store.snapshot().get_tips();
    let best = tips.first().copied().unwrap_or([0u8; 32]);
    Ok(Value::String(hex::encode(best)))
}

/// `getblockhash` — hash of the block at a given height (blue score).
pub async fn get_block_hash(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let height = params.get(0)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected height (u64)".into(), None))?;

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();

    // Walk the SP chain looking for the block at this blue score.
    // This is a DAG — "height" maps to blue_score.
    let tips = snapshot.get_tips();
    for tip in &tips {
        if let Some(data) = snapshot.get_ghostdag_data(tip) {
            if data.blue_score == height {
                return Ok(Value::String(hex::encode(tip)));
            }
        }
    }
    // Fallback: scan all known blocks via the tip chain walk
    // TODO: implement a height→hash index for O(1) lookup
    Err((BLOCK_NOT_FOUND, format!("no block at height {}", height), None))
}

/// `getblock` — block data by hash.
pub async fn get_block(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let hash_hex = params.get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected blockhash hex".into(), None))?;
    let _verbosity = params.get(1).and_then(|v| v.as_u64()).unwrap_or(1);

    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?
        .try_into()
        .map_err(|_| (INVALID_PARAMS, "hash must be 32 bytes".into(), None))?;

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();

    let header = snapshot.get_header(&hash_bytes)
        .ok_or_else(|| (BLOCK_NOT_FOUND, format!("block {} not found", hash_hex), None))?;
    let ghostdag = snapshot.get_ghostdag_data(&hash_bytes);
    let txs = s.dag_store.get_block_txs(&hash_bytes);

    Ok(json!({
        "hash": hash_hex,
        "version": header.version,
        "parents": header.parents.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestampMs": header.timestamp_ms,
        "txRoot": hex::encode(header.tx_root),
        "proposerId": hex::encode(header.proposer_id),
        "blueScore": header.blue_score,
        "ghostdag": ghostdag.map(|d| json!({
            "selectedParent": hex::encode(d.selected_parent),
            "mergesetBlues": d.mergeset_blues.len(),
            "mergesetReds": d.mergeset_reds.len(),
            "blueScore": d.blue_score,
        })),
        "txCount": txs.len(),
        "txHashes": txs.iter().map(|tx| hex::encode(tx.tx_hash())).collect::<Vec<_>>(),
    }))
}

/// `getblockheader` — block header (no transactions).
pub async fn get_block_header(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let hash_hex = params.get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected blockhash hex".into(), None))?;

    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?
        .try_into()
        .map_err(|_| (INVALID_PARAMS, "hash must be 32 bytes".into(), None))?;

    let s = rpc.node.read().await;
    let snapshot = s.dag_store.snapshot();

    let header = snapshot.get_header(&hash_bytes)
        .ok_or_else(|| (BLOCK_NOT_FOUND, format!("block {} not found", hash_hex), None))?;
    let ghostdag = snapshot.get_ghostdag_data(&hash_bytes);

    Ok(json!({
        "hash": hash_hex,
        "version": header.version,
        "parents": header.parents.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestampMs": header.timestamp_ms,
        "txRoot": hex::encode(header.tx_root),
        "proposerId": hex::encode(header.proposer_id),
        "blueScore": header.blue_score,
        "ghostdag": ghostdag.map(|d| json!({
            "selectedParent": hex::encode(d.selected_parent),
            "blueScore": d.blue_score,
        })),
    }))
}

/// `getmininginfo` — basic mining/production info.
pub async fn get_mining_info(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    Ok(json!({
        "blocks": s.dag_store.max_blue_score(),
        "pooledtx": s.mempool.len(),
        "chain": "misaka",
    }))
}

/// `gettxoutsetinfo` — UTXO set summary.
pub async fn get_txout_set_info(rpc: &DagRpcState) -> HandlerResult {
    let s = rpc.node.read().await;
    let height = s.utxo_set.height;
    // Use cached state root if available; compute is expensive and requires &mut.
    // TODO: expose cached_state_root via a getter if not already public.
    Ok(json!({
        "height": height,
        "bestblock": hex::encode(s.genesis_hash), // TODO: track actual tip hash
        "txouts": s.utxo_set.len(),
        "total_amount": s.utxo_set.total_amount(),
        "hash_serialized": "0000000000000000000000000000000000000000000000000000000000000000", // TODO: expose cached state root
    }))
}

/// `uptime` — seconds since node start.
pub async fn uptime(_rpc: &DagRpcState) -> HandlerResult {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    Ok(Value::Number(start.elapsed().as_secs().into()))
}

/// `getconnectioncount` — number of connected peers.
pub async fn get_connection_count(_rpc: &DagRpcState) -> HandlerResult {
    // TODO: wire to P2P observation
    Ok(Value::Number(0.into()))
}

/// `getpeerinfo` — connected peer details.
pub async fn get_peer_info(_rpc: &DagRpcState) -> HandlerResult {
    // TODO: wire to P2P observation
    Ok(Value::Array(vec![]))
}

/// `getnetworkinfo` — network metadata.
pub async fn get_network_info(_rpc: &DagRpcState) -> HandlerResult {
    Ok(json!({
        "version": "0.1.0",
        "subversion": "/MISAKA:0.1.0/",
        "protocolversion": 1,
        "connections": 0,
    }))
}
