//! HTTP RPC server — axum-based, serves Explorer + CLI.

use std::net::SocketAddr;
use std::sync::Arc;
use axum::{Router, Json, extract::State, routing::{post, get}, http::StatusCode};
use tower_http::cors::CorsLayer;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::block_producer::{SharedState, PendingTx};
use crate::p2p_network::P2pNetwork;

/// Combined state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    pub node: SharedState,
    pub p2p: Arc<P2pNetwork>,
}

pub async fn run_rpc_server(state: SharedState, p2p: Arc<P2pNetwork>, addr: SocketAddr) -> anyhow::Result<()> {
    let rpc_state = RpcState { node: state, p2p };

    let app = Router::new()
        .route("/api/get_chain_info", post(get_chain_info))
        .route("/api/get_latest_blocks", post(get_latest_blocks))
        .route("/api/get_block_by_height", post(get_block_by_height))
        .route("/api/get_block_by_hash", post(get_block_by_hash))
        .route("/api/get_latest_txs", post(get_latest_txs))
        .route("/api/get_tx_by_hash", post(get_tx_by_hash))
        .route("/api/get_validator_set", post(get_validator_set))
        .route("/api/get_validator_by_id", post(get_validator_by_id))
        .route("/api/get_block_production", post(get_block_production))
        .route("/api/get_address_outputs", post(get_address_outputs))
        .route("/api/get_peers", post(get_peers))
        .route("/api/search", post(search))
        .route("/api/submit_tx", post(submit_tx))
        .route("/api/faucet", post(faucet))
        .route("/health", get(health))
        .layer(CorsLayer::permissive())
        .with_state(rpc_state);

    info!("RPC server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ─── Request/Response types ──────────────────────────

#[derive(Deserialize)] struct PageParams { page: Option<usize>, #[serde(rename = "pageSize")] page_size: Option<usize> }
#[derive(Deserialize)] struct HeightParam { height: u64 }
#[derive(Deserialize)] struct HashParam { hash: String }
#[derive(Deserialize)] struct CountParam { count: Option<usize> }
#[derive(Deserialize)] struct QueryParam { query: String }
#[derive(Deserialize)] struct AddressParam { address: String }
#[derive(Deserialize)] struct IdParam { id: String }
#[derive(Deserialize)] struct FaucetReq { address: String }

#[derive(Serialize)]
struct TxInfo {
    hash: String,
    #[serde(rename = "blockHeight")] block_height: u64,
    timestamp: String,
    fee: u64,
    #[serde(rename = "inputCount")] input_count: usize,
    #[serde(rename = "outputCount")] output_count: usize,
    status: String,
}

#[derive(Serialize)]
struct TxDetail {
    #[serde(flatten)] base: TxInfo,
    #[serde(rename = "blockHash")] block_hash: String,
    size: usize,
    #[serde(rename = "ringInputCount")] ring_input_count: usize,
    #[serde(rename = "keyImages")] key_images: Vec<String>,
    #[serde(rename = "stealthOutputCount")] stealth_output_count: usize,
    #[serde(rename = "hasPayload")] has_payload: bool,
    confirmations: u64,
    version: u8,
}

#[derive(Serialize)]
struct BlockInfo {
    height: u64, hash: String,
    #[serde(rename = "parentHash")] parent_hash: String,
    proposer: String,
    #[serde(rename = "txCount")] tx_count: usize,
    timestamp: String, size: usize, finality: String,
    #[serde(rename = "validatorSignatures")] validator_signatures: usize,
    #[serde(rename = "totalFees")] total_fees: u64,
    status: String,
    transactions: Vec<TxInfo>,
}

fn ms_to_iso(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339()).unwrap_or_default()
}

fn block_to_info(b: &crate::chain_store::StoredBlockHeader, txs: Vec<TxInfo>) -> BlockInfo {
    BlockInfo {
        height: b.height, hash: hex::encode(b.hash),
        parent_hash: hex::encode(b.parent_hash),
        proposer: format!("validator-{:02}", b.proposer_index),
        tx_count: b.tx_count, timestamp: ms_to_iso(b.timestamp_ms),
        size: 2000 + b.tx_count * 600, finality: "finalized".into(),
        validator_signatures: 1, total_fees: b.total_fees,
        status: "confirmed".into(), transactions: txs,
    }
}

fn stored_tx_to_info(tx: &crate::chain_store::StoredTx, block_h: u64) -> TxInfo {
    TxInfo {
        hash: hex::encode(tx.hash), block_height: block_h,
        timestamp: ms_to_iso(tx.timestamp_ms), fee: tx.fee,
        input_count: tx.input_count, output_count: tx.output_count,
        status: tx.status.clone(),
    }
}

// ─── Handlers ────────────────────────────────────────

async fn health() -> &'static str { "ok" }

async fn get_chain_info(State(rpc): State<RpcState>) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    Json(serde_json::json!({
        "networkName": s.chain_name,
        "networkVersion": s.version,
        "latestBlockHeight": s.height,
        "totalTransactions": s.tx_count_total,
        "activeValidators": s.validator_count,
        "avgBlockTime": 60.0,
        "tpsEstimate": if s.height > 0 { s.tx_count_total as f64 / (s.height as f64 * 60.0) } else { 0.0 },
        "finalityStatus": "finalized",
        "chainHealth": "healthy",
        "genesisTimestamp": ms_to_iso(s.genesis_timestamp_ms),
    }))
}

async fn get_latest_blocks(State(rpc): State<RpcState>, Json(p): Json<PageParams>) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let all = s.chain.get_latest(s.chain.len().min(500));
    let total = all.len();
    let start = (page - 1) * ps;
    let data: Vec<_> = all.into_iter().skip(start).take(ps).map(|b| {
        let txs = s.chain.get_txs_for_block(b.height).iter()
            .map(|t| stored_tx_to_info(t, b.height)).collect();
        block_to_info(&b, txs)
    }).collect();
    Json(serde_json::json!({ "data": data, "total": total, "page": page, "pageSize": ps, "hasMore": start + ps < total }))
}

async fn get_block_by_height(State(rpc): State<RpcState>, Json(p): Json<HeightParam>) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    let b = s.chain.get_by_height(p.height).ok_or(StatusCode::NOT_FOUND)?;
    let txs: Vec<TxInfo> = s.chain.get_txs_for_block(b.height).iter().map(|t| stored_tx_to_info(t, b.height)).collect();
    Ok(Json(serde_json::to_value(block_to_info(b, txs)).unwrap()))
}

async fn get_block_by_hash(State(rpc): State<RpcState>, Json(p): Json<HashParam>) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    let hash: [u8; 32] = hex::decode(&p.hash).ok().and_then(|v| v.try_into().ok()).ok_or(StatusCode::BAD_REQUEST)?;
    let b = s.chain.get_by_hash(&hash).ok_or(StatusCode::NOT_FOUND)?;
    let txs: Vec<TxInfo> = s.chain.get_txs_for_block(b.height).iter().map(|t| stored_tx_to_info(t, b.height)).collect();
    Ok(Json(serde_json::to_value(block_to_info(b, txs)).unwrap()))
}

async fn get_latest_txs(State(rpc): State<RpcState>, Json(p): Json<PageParams>) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let (txs, total) = s.chain.get_recent_txs(page, ps);
    let data: Vec<TxInfo> = txs.iter().map(|(t, h)| stored_tx_to_info(t, *h)).collect();
    Json(serde_json::json!({ "data": data, "total": total, "page": page, "pageSize": ps, "hasMore": (page * ps) < total }))
}

async fn get_tx_by_hash(State(rpc): State<RpcState>, Json(p): Json<HashParam>) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    let hash: [u8; 32] = hex::decode(&p.hash).ok().and_then(|v| v.try_into().ok()).ok_or(StatusCode::BAD_REQUEST)?;
    let (tx, block_h) = s.chain.get_tx_by_hash(&hash).ok_or(StatusCode::NOT_FOUND)?;
    let block = s.chain.get_by_height(block_h).ok_or(StatusCode::NOT_FOUND)?;
    let detail = TxDetail {
        base: stored_tx_to_info(&tx, block_h),
        block_hash: hex::encode(block.hash),
        size: tx.size,
        ring_input_count: tx.input_count,
        key_images: tx.key_images.iter().map(|ki| hex::encode(ki)).collect(),
        stealth_output_count: tx.output_count,
        has_payload: tx.has_payload,
        confirmations: s.height.saturating_sub(block_h),
        version: 1,
    };
    Ok(Json(serde_json::to_value(detail).unwrap()))
}

async fn get_validator_set(State(rpc): State<RpcState>, Json(_p): Json<PageParams>) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let vals: Vec<serde_json::Value> = (0..s.validator_count).map(|i| serde_json::json!({
        "id": format!("validator-{:02}", i),
        "publicKey": format!("msk1val{:064x}", i),
        "stakeWeight": 1_000_000,
        "status": "active",
        "latestProposedBlock": s.height,
        "participationRate": 100.0,
        "uptime": 100.0,
    })).collect();
    Json(serde_json::json!({ "data": vals, "total": s.validator_count, "page": 1, "pageSize": 50, "hasMore": false }))
}

async fn get_validator_by_id(State(rpc): State<RpcState>, Json(p): Json<IdParam>) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    // Parse validator index from id like "validator-02"
    let idx: usize = p.id.strip_prefix("validator-")
        .and_then(|s| s.parse().ok())
        .ok_or(StatusCode::NOT_FOUND)?;
    if idx >= s.validator_count { return Err(StatusCode::NOT_FOUND); }

    let recent_proposals: Vec<u64> = (0..10.min(s.height as usize))
        .filter_map(|i| {
            let h = s.height.saturating_sub(i as u64);
            s.chain.get_by_height(h)
                .filter(|b| b.proposer_index == idx)
                .map(|b| b.height)
        })
        .collect();

    let recent_votes: Vec<u64> = (0..20.min(s.height as usize))
        .map(|i| s.height.saturating_sub(i as u64))
        .collect();

    Ok(Json(serde_json::json!({
        "id": p.id,
        "publicKey": format!("msk1val{:064x}", idx),
        "stakeWeight": 1_000_000,
        "status": "active",
        "latestProposedBlock": s.height,
        "participationRate": 100.0,
        "uptime": 100.0,
        "recentProposals": recent_proposals,
        "recentVotes": recent_votes,
        "slashingStatus": "clean",
        "latestActivity": ms_to_iso(chrono::Utc::now().timestamp_millis() as u64),
        "totalBlocksProposed": s.height / s.validator_count as u64,
        "joinedAt": ms_to_iso(s.genesis_timestamp_ms),
    })))
}

async fn get_block_production(State(rpc): State<RpcState>, Json(p): Json<CountParam>) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let count = p.count.unwrap_or(30).min(100);
    let blocks = s.chain.get_latest(count);
    let data: Vec<serde_json::Value> = blocks.iter().map(|b| serde_json::json!({
        "height": b.height, "txCount": b.tx_count,
        "timestamp": ms_to_iso(b.timestamp_ms), "blockTime": 60.0,
    })).collect();
    Json(serde_json::json!(data))
}

async fn get_address_outputs(Json(p): Json<AddressParam>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "address": p.address, "balance": null, "totalReceived": null, "totalSent": null,
        "txCount": 0, "outputs": [],
        "privacyNote": "Balance and amounts are privacy-protected via stealth addresses and ring signatures."
    }))
}

/// Get connected peers — for Explorer /peers page.
async fn get_peers(State(rpc): State<RpcState>) -> Json<serde_json::Value> {
    let peers = rpc.p2p.get_peer_info_list().await;
    let total = peers.len();
    let inbound = peers.iter().filter(|p| p.direction == "inbound").count();
    let outbound = total - inbound;

    Json(serde_json::json!({
        "peers": peers,
        "total": total,
        "inbound": inbound,
        "outbound": outbound,
    }))
}

async fn search(State(rpc): State<RpcState>, Json(p): Json<QueryParam>) -> Json<serde_json::Value> {
    let q = p.query.trim();
    let s = rpc.node.read().await;

    // Numeric → block height
    if let Ok(h) = q.parse::<u64>() {
        if s.chain.get_by_height(h).is_some() {
            return Json(serde_json::json!({ "type": "block", "value": q, "label": format!("Block #{}", h) }));
        }
    }

    // 64 hex chars → try block hash, then tx hash
    if q.len() == 64 && q.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(q) {
            if let Ok(hash) = <[u8; 32]>::try_from(bytes.as_slice()) {
                if s.chain.get_by_hash(&hash).is_some() {
                    return Json(serde_json::json!({ "type": "block", "value": q }));
                }
                if s.chain.get_tx_by_hash(&hash).is_some() {
                    return Json(serde_json::json!({ "type": "transaction", "value": q }));
                }
            }
        }
        // Default to transaction search
        return Json(serde_json::json!({ "type": "transaction", "value": q }));
    }

    // Address
    if q.starts_with("msk1") {
        return Json(serde_json::json!({ "type": "address", "value": q }));
    }

    Json(serde_json::json!({ "type": "not_found", "value": q }))
}

/// Submit a raw transaction.
async fn submit_tx(State(rpc): State<RpcState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    // Parse required fields
    let fee = body["fee"].as_u64().unwrap_or(0);
    let input_count = body["inputCount"].as_u64().unwrap_or(body["inputs"].as_array().map(|a| a.len() as u64).unwrap_or(0)) as usize;
    let output_count = body["outputCount"].as_u64().unwrap_or(body["outputs"].as_array().map(|a| a.len() as u64).unwrap_or(0)) as usize;

    // Compute TX hash from body
    let tx_hash: [u8; 32] = {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:tx:v1:");
        h.update(serde_json::to_vec(&body).unwrap_or_default());
        h.update(now_ms.to_le_bytes());
        h.finalize().into()
    };

    // Extract key images
    let key_images: Vec<[u8; 32]> = body["keyImages"].as_array()
        .map(|arr| arr.iter().filter_map(|v| {
            v.as_str().and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok())
        }).collect())
        .unwrap_or_default();

    let mut s = rpc.node.write().await;

    // Double-spend check
    for ki in &key_images {
        if s.spent_key_images.contains(ki) {
            return Json(serde_json::json!({
                "txHash": hex::encode(tx_hash),
                "accepted": false,
                "error": format!("double-spend: key image {} already spent", hex::encode(ki))
            }));
        }
        // Check pending pool too
        for ptx in &s.pending_txs {
            if ptx.key_images.contains(ki) {
                return Json(serde_json::json!({
                    "txHash": hex::encode(tx_hash),
                    "accepted": false,
                    "error": "double-spend: key image in pending pool"
                }));
            }
        }
    }

    // Basic validation
    if input_count == 0 && output_count == 0 && fee == 0 {
        return Json(serde_json::json!({
            "txHash": hex::encode(tx_hash),
            "accepted": false,
            "error": "empty transaction"
        }));
    }

    // Add to pending pool
    s.pending_txs.push_back(PendingTx {
        tx_hash,
        raw_json: serde_json::to_string(&body).unwrap_or_default(),
        fee,
        input_count,
        output_count,
        key_images,
        submitted_at_ms: now_ms,
    });

    let hash_hex = hex::encode(tx_hash);
    info!("TX submitted: {} | fee={} | inputs={} | outputs={} | mempool={}", 
          &hash_hex[..16], fee, input_count, output_count, s.pending_txs.len());

    Json(serde_json::json!({
        "txHash": hash_hex,
        "accepted": true,
        "error": null
    }))
}

/// Faucet — drip testnet tokens.
async fn faucet(State(rpc): State<RpcState>, Json(req): Json<FaucetReq>) -> Json<serde_json::Value> {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let mut s = rpc.node.write().await;

    // Rate limit: 1 drip per address per 60 seconds
    if let Some(&last) = s.faucet_drips.get(&req.address) {
        if now_ms - last < 60_000 {
            let wait = (60_000 - (now_ms - last)) / 1000;
            return Json(serde_json::json!({
                "success": false,
                "error": format!("rate limited: wait {}s", wait),
                "txHash": null
            }));
        }
    }

    // Create a faucet TX (special: no ring sig needed, genesis-funded)
    let tx_hash: [u8; 32] = {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:faucet:v1:");
        h.update(req.address.as_bytes());
        h.update(now_ms.to_le_bytes());
        h.finalize().into()
    };

    let faucet_amount: u64 = 1_000_000; // 1M MISAKA testnet tokens

    s.pending_txs.push_back(PendingTx {
        tx_hash,
        raw_json: serde_json::json!({
            "type": "faucet",
            "to": req.address,
            "amount": faucet_amount,
        }).to_string(),
        fee: 0,
        input_count: 0,
        output_count: 1,
        key_images: vec![],
        submitted_at_ms: now_ms,
    });

    s.faucet_drips.insert(req.address.clone(), now_ms);

    let hash_hex = hex::encode(tx_hash);
    info!("Faucet drip: {} → {} ({} MISAKA)", &hash_hex[..16], req.address, faucet_amount);

    Json(serde_json::json!({
        "success": true,
        "txHash": hash_hex,
        "amount": faucet_amount,
        "address": req.address,
        "error": null
    }))
}
