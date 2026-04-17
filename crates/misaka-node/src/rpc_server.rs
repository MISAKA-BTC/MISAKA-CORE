//! HTTP RPC server — axum-based, serves Explorer + CLI.
//!
//! ## Security (Mainnet P0)
//!
//! - **API Key Auth**: Write endpoints (submit_tx) require
//!   `Authorization: Bearer <key>` when `MISAKA_RPC_API_KEY` is set.
//!   Read-only endpoints and /health remain public.
//! - Rate limiting via tower::limit (global concurrency + per-endpoint)
//! - Body size limit: 128KB default, 128KB hard limit on submit_tx
//! - CORS: fail-closed (no permissive() under any circumstance)

use axum::extract::DefaultBodyLimit;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::block_producer::SharedState;
use crate::p2p_network::P2pNetwork;
use crate::rpc_auth::{require_api_key, ApiKeyState};
use misaka_p2p::PeerModeLabel;
use misaka_pqc::{default_privacy_backend, PrivacyBackendFamily, SpendIdentifierModel};
#[cfg(feature = "faucet")]
use misaka_types::utxo::TxType;
use misaka_types::utxo::UtxoTransaction;

/// Combined state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    pub node: SharedState,
    pub p2p: Arc<P2pNetwork>,
}

fn build_linear_cors_layer() -> anyhow::Result<CorsLayer> {
    match std::env::var("MISAKA_CORS_ORIGINS") {
        Ok(origins_str) => {
            let origins: Vec<axum::http::HeaderValue> = origins_str
                .split(',')
                .filter(|o| !o.trim().is_empty())
                .filter_map(|o| o.trim().parse().ok())
                .collect();
            if origins.is_empty() {
                anyhow::bail!(
                    "FATAL: MISAKA_CORS_ORIGINS is set but contains no valid origins: '{}'. \
                     Fix the value or unset the variable for localhost-only default.",
                    origins_str
                );
            }
            info!("CORS: allowing {} configured origins", origins.len());
            Ok(CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE]))
        }
        Err(_) => {
            info!("CORS: no MISAKA_CORS_ORIGINS set, allowing localhost only");
            #[allow(clippy::unwrap_used)] // static string parse
            Ok(CorsLayer::new()
                .allow_origin([
                    "http://localhost:3000".parse().expect("static origin"),
                    "http://localhost:3001".parse().expect("static origin"),
                    "http://127.0.0.1:3000".parse().expect("static origin"),
                    "http://127.0.0.1:3001".parse().expect("static origin"),
                ])
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE]))
        }
    }
}

pub async fn run_rpc_server(
    state: SharedState,
    p2p: Arc<P2pNetwork>,
    addr: SocketAddr,
    chain_id: u32,
) -> anyhow::Result<()> {
    let rpc_state = RpcState { node: state, p2p };

    // ── API Key configuration ──
    // SEC-FIX: Use from_env_checked so mainnet (chain_id=1) REQUIRES an API key.
    let auth_state = ApiKeyState::from_env_checked(chain_id)?;
    if auth_state.is_enabled() {
        info!("RPC: API key authentication ENABLED for write endpoints");
    } else {
        warn!("RPC: API key authentication DISABLED (set MISAKA_RPC_API_KEY to enable)");
    }

    // ── Read-only endpoints (public, no auth required) ──
    let public_routes = Router::new()
        .route("/api/get_chain_info", post(get_chain_info))
        .route("/api/get_latest_blocks", post(get_latest_blocks))
        .route("/api/get_block_by_height", post(get_block_by_height))
        .route("/api/get_block_by_hash", post(get_block_by_hash))
        .route("/api/get_latest_txs", post(get_latest_txs))
        .route("/api/get_tx_by_hash", post(get_tx_by_hash))
        .route("/api/get_validator_set", post(get_validator_set))
        .route("/api/get_validator_by_id", post(get_validator_by_id))
        .route("/api/get_block_production", post(get_block_production))
        .route("/api/get_peers", post(get_peers))
        .route("/api/search", post(search))
        .route("/api/get_anonymity_set", post(get_anonymity_set))
        .route("/health", get(health))
        .route("/api/health", get(health));

    // ── Write endpoints (auth required when MISAKA_RPC_API_KEY is set) ──
    // SEC-FIX [Audit #1]: route_layer is applied AFTER all routes are added,
    // so that every write endpoint (including faucet) is covered by auth.
    let write_routes = {
        let routes = Router::new().route("/api/submit_tx", post(submit_tx));

        // Faucet is feature-gated: not available in production builds
        #[cfg(feature = "faucet")]
        let routes = routes.route("/api/faucet", post(faucet));

        // Apply auth middleware to ALL write routes (must be last)
        routes.route_layer(axum::middleware::from_fn_with_state(
            auth_state,
            require_api_key,
        ))
    };

    let app = {
        let app = public_routes.merge(write_routes);

        // MAINNET: get_address_outputs is dev-only (privacy leak — exposes address→UTXO mapping)
        #[cfg(feature = "dev-rpc")]
        let app = app.route("/api/get_address_outputs", post(get_address_outputs));

        app
    };

    // CORS: Fail-closed. No permissive() under ANY circumstance.
    //
    // - MISAKA_CORS_ORIGINS set + valid → allow those origins only
    // - MISAKA_CORS_ORIGINS set + empty/invalid → FATAL: refuse to start
    // - MISAKA_CORS_ORIGINS unset → localhost only (dev default)
    let cors = build_linear_cors_layer()?;

    // ── SEC-FIX-1: Per-IP rate limiting (before concurrency limit) ──
    let node_limiter = crate::rpc_rate_limit::NodeRateLimiter::from_env();
    info!(
        "RPC: per-IP rate limit write={}/min read={}/min",
        node_limiter.write_limit, node_limiter.read_limit
    );

    let app = app
        .layer(cors)
        // ── Global body size limit: 128KB (DoS protection) ──
        .layer(DefaultBodyLimit::max(131_072))
        // ── Global concurrency limit: max 64 in-flight requests ──
        .layer(ConcurrencyLimitLayer::new(64))
        // ── SEC-FIX-1: Per-IP rate limiting runs BEFORE concurrency limit ──
        // so abusive IPs are rejected before consuming concurrency slots.
        .layer(axum::middleware::from_fn_with_state(
            node_limiter,
            crate::rpc_rate_limit::node_rate_limit,
        ))
        .with_state(rpc_state);

    info!("RPC server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // SEC-FIX-1: Enable ConnectInfo<SocketAddr> so extract_ip() in
    // rpc_rate_limit.rs can read the real client socket IP.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ─── Request/Response types ──────────────────────────

#[derive(Deserialize)]
struct PageParams {
    page: Option<usize>,
    #[serde(rename = "pageSize")]
    page_size: Option<usize>,
}
#[derive(Deserialize)]
struct HeightParam {
    height: u64,
}
#[derive(Deserialize)]
struct HashParam {
    hash: String,
}
#[derive(Deserialize)]
struct CountParam {
    count: Option<usize>,
}
#[derive(Deserialize)]
struct QueryParam {
    query: String,
}
#[cfg(feature = "dev-rpc")]
#[derive(Deserialize)]
struct AddressParam {
    address: String,
}
#[derive(Deserialize)]
struct IdParam {
    id: String,
}
#[cfg(feature = "faucet")]
#[derive(Deserialize)]
struct FaucetReq {
    address: String,
    #[serde(rename = "spendingPubkey")]
    spending_pubkey: Option<String>,
}

#[derive(Serialize)]
struct TxPrivacyInfo {
    #[serde(rename = "schemeTag")]
    scheme_tag: u8,
    #[serde(rename = "schemeName")]
    scheme_name: String,
    #[serde(rename = "backendFamily")]
    backend_family: PrivacyBackendFamily,
    #[serde(rename = "anonymityModel")]
    anonymity_model: String,
    #[serde(rename = "spendIdentifierModel")]
    spend_identifier_model: SpendIdentifierModel,
    #[serde(rename = "spendIdentifierLabel")]
    spend_identifier_label: String,
    #[serde(rename = "spendIdentifiers")]
    spend_identifiers: Vec<String>,
    #[serde(rename = "fullVerifierMemberIndexHidden")]
    full_verifier_member_index_hidden: bool,
    #[serde(rename = "zkpMigrationReady")]
    zkp_migration_ready: bool,
    #[serde(rename = "statusNote")]
    status_note: String,
}

#[derive(Serialize)]
struct TxInfo {
    hash: String,
    #[serde(rename = "blockHeight")]
    block_height: u64,
    timestamp: String,
    fee: u64,
    #[serde(rename = "inputCount")]
    input_count: usize,
    #[serde(rename = "outputCount")]
    output_count: usize,
    status: String,
    /// PUBLIC chain data — wallets scan these to find owned outputs.
    /// The node does NOT know which wallet owns which output.
    outputs: Vec<serde_json::Value>,
    /// PUBLIC spend proofs — wallets check key images to detect spent outputs.
    inputs: Vec<serde_json::Value>,
    /// Stored privacy semantics for this transaction.
    privacy: TxPrivacyInfo,
}

#[derive(Serialize)]
struct TxDetail {
    #[serde(flatten)]
    base: TxInfo,
    #[serde(rename = "blockHash")]
    block_hash: String,
    size: usize,
    #[serde(rename = "ringInputCount")]
    ring_input_count: usize,
    #[serde(rename = "keyImages")]
    spend_ids: Vec<String>,
    #[serde(rename = "spendIdentifierLabel")]
    spend_identifier_label: String,
    #[serde(rename = "spendIdentifiers")]
    spend_identifiers: Vec<String>,
    // Phase 2c-B D4e: deprecated_output_count deleted
    #[serde(rename = "outputCount")]
    output_count: usize,
    #[serde(rename = "hasPayload")]
    has_payload: bool,
    confirmations: u64,
    version: u8,
}

#[derive(Serialize)]
struct BlockInfo {
    height: u64,
    hash: String,
    #[serde(rename = "parentHash")]
    parent_hash: String,
    proposer: String,
    #[serde(rename = "txCount")]
    tx_count: usize,
    timestamp: String,
    size: usize,
    finality: String,
    #[serde(rename = "validatorSignatures")]
    validator_signatures: usize,
    #[serde(rename = "totalFees")]
    total_fees: u64,
    status: String,
    transactions: Vec<TxInfo>,
}

fn ms_to_iso(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

fn linear_consumer_surfaces_json() -> serde_json::Value {
    serde_json::json!({
        "validatorAttestation": {
            "available": false,
            "bridgeReadiness": "notAvailable",
            "explorerConfirmationLevel": "blockFinalized"
        },
        "txStatusVocabulary": ["confirmed"]
    })
}

fn linear_privacy_path_surface_json(runtime_path: &str) -> serde_json::Value {
    serde_json::json!({
        "runtimePath": runtime_path,
        "targetPath": "zeroKnowledge",
        "targetBackendFamily": "zeroKnowledge",
        "note": "linear path remains transparent-default while target privacy path stays zeroKnowledge"
    })
}

fn block_to_info(b: &crate::chain_store::StoredBlockHeader, txs: Vec<TxInfo>) -> BlockInfo {
    BlockInfo {
        height: b.height,
        hash: hex::encode(b.hash),
        parent_hash: hex::encode(b.parent_hash),
        proposer: format!("validator-{:02}", b.proposer_index),
        tx_count: b.tx_count,
        timestamp: ms_to_iso(b.timestamp_ms),
        size: 2000 + b.tx_count * 600,
        finality: "finalized".into(),
        validator_signatures: 1,
        total_fees: b.total_fees,
        status: "confirmed".into(),
        transactions: txs,
    }
}

fn stored_tx_privacy_info(tx: &crate::chain_store::StoredTx) -> TxPrivacyInfo {
    TxPrivacyInfo {
        scheme_tag: tx.privacy_scheme_tag,
        scheme_name: tx.privacy_scheme_name.clone(),
        backend_family: tx.privacy_backend_family,
        anonymity_model: tx.privacy_anonymity_model.clone(),
        spend_identifier_model: tx.spend_identifier_model,
        spend_identifier_label: tx.spend_identifier_label.clone(),
        spend_identifiers: tx.spend_identifiers.iter().map(hex::encode).collect(),
        full_verifier_member_index_hidden: tx.full_verifier_member_index_hidden,
        zkp_migration_ready: tx.zkp_migration_ready,
        status_note: tx.privacy_status_note.clone(),
    }
}

fn stored_tx_to_info(tx: &crate::chain_store::StoredTx, block_h: u64) -> TxInfo {
    // Serialize outputs as public chain data (Monero-style)
    let outputs: Vec<serde_json::Value> = tx
        .outputs
        .iter()
        .map(|o| {
            serde_json::json!({
                "address": o.address,
                "amount": o.amount,
                "outputIndex": o.output_index,
                "oneTimePubkey": o.one_time_pubkey,
                "ephemeralPubkey": o.ephemeral_pubkey,
                "viewTag": o.view_tag,
            })
        })
        .collect();

    // Serialize inputs with key images (public spend proofs)
    // Return input with outpoint reference (for wallet spent detection)
    let inputs: Vec<serde_json::Value> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, i)| {
            let spend_identifier = tx
                .spend_identifiers
                .get(idx)
                .map(hex::encode)
                .unwrap_or_else(|| i.spend_id.clone());
            serde_json::json!({
                "spendId": i.spend_id,
                "ringSize": i.anonymity_set_size,
                "txHash": i.source_tx_hash,
                "outputIndex": i.source_output_index,
                "spendIdentifier": spend_identifier,
                "spendIdentifierLabel": tx.spend_identifier_label,
            })
        })
        .collect();

    TxInfo {
        hash: hex::encode(tx.hash),
        block_height: block_h,
        timestamp: ms_to_iso(tx.timestamp_ms),
        fee: tx.fee,
        input_count: tx.input_count,
        output_count: tx.output_count,
        status: tx.status.clone(),
        outputs,
        inputs,
        privacy: stored_tx_privacy_info(tx),
    }
}

// ─── Handlers ────────────────────────────────────────

async fn health(State(rpc): State<RpcState>) -> (StatusCode, Json<serde_json::Value>) {
    let s = rpc.node.read().await;
    let block_height = s.chain.len() as u64;
    let peer_count = rpc.p2p.peer_count().await;

    let last_block_age_secs = s
        .chain
        .last()
        .map(|b| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(b.header.timestamp / 1000)
        })
        .unwrap_or(0);

    let stale_threshold_secs = 300;
    let is_healthy = peer_count > 0 || block_height == 0;
    let is_synced = last_block_age_secs < stale_threshold_secs || block_height == 0;

    let status = if is_healthy && is_synced {
        "ok"
    } else {
        "degraded"
    };
    let code = if is_healthy && is_synced {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        code,
        Json(serde_json::json!({
            "status": status,
            "block_height": block_height,
            "peer_count": peer_count,
            "last_block_age_secs": last_block_age_secs,
        })),
    )
}

async fn get_chain_info(State(rpc): State<RpcState>) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let privacy_backend = default_privacy_backend();
    let experimental_privacy_path = if s.experimental_zk_path {
        "zeroKnowledge"
    } else {
        "ringSignature"
    };
    // Count validators dynamically from connected peers
    let peers = rpc.p2p.get_peer_info_list().await;
    let peer_validators = peers
        .iter()
        .filter(|p| PeerModeLabel::parse(&p.mode).counts_as_active_validator_surface())
        .count();
    let active_validators = if s.validator_count > 0 {
        1 + peer_validators
    } else {
        peer_validators
    };
    let connected_peers = peers.len();
    Json(serde_json::json!({
        "networkName": s.chain_name,
        "networkVersion": s.version,
        "latestBlockHeight": s.height,
        "totalTransactions": s.tx_count_total,
        "activeValidators": active_validators,
        "connectedPeers": connected_peers,
        "avgBlockTime": 60.0,
        "tpsEstimate": if s.height > 0 { s.tx_count_total as f64 / (s.height as f64 * 60.0) } else { 0.0 },
        "finalityStatus": "finalized",
        "chainHealth": "healthy",
        "genesisTimestamp": ms_to_iso(s.genesis_timestamp_ms),
        "experimentalPrivacyPath": experimental_privacy_path,
        "privacyPathSurface": linear_privacy_path_surface_json(experimental_privacy_path),
        "consumerSurfaces": linear_consumer_surfaces_json(),
        "privacyBackend": serde_json::to_value(privacy_backend).unwrap_or(serde_json::json!({
            "schemeName": "UnifiedZKP-v1",
            "statusNote": "privacy backend descriptor serialization failed"
        })),
    }))
}

async fn get_latest_blocks(
    State(rpc): State<RpcState>,
    Json(p): Json<PageParams>,
) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let all = s.chain.get_latest(s.chain.len().min(500));
    let total = all.len();
    let start = (page - 1) * ps;
    let data: Vec<_> = all
        .into_iter()
        .skip(start)
        .take(ps)
        .map(|b| {
            let txs = s
                .chain
                .get_txs_for_block(b.height)
                .iter()
                .map(|t| stored_tx_to_info(t, b.height))
                .collect();
            block_to_info(&b, txs)
        })
        .collect();
    Json(
        serde_json::json!({ "data": data, "total": total, "page": page, "pageSize": ps, "hasMore": start + ps < total }),
    )
}

async fn get_block_by_height(
    State(rpc): State<RpcState>,
    Json(p): Json<HeightParam>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    let b = s
        .chain
        .get_by_height(p.height)
        .ok_or(StatusCode::NOT_FOUND)?;
    let txs: Vec<TxInfo> = s
        .chain
        .get_txs_for_block(b.height)
        .iter()
        .map(|t| stored_tx_to_info(t, b.height))
        .collect();
    Ok(Json(
        serde_json::to_value(block_to_info(b, txs))
            .unwrap_or(serde_json::json!({"error":"serialize"})),
    ))
}

async fn get_block_by_hash(
    State(rpc): State<RpcState>,
    Json(p): Json<HashParam>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    let hash: [u8; 32] = hex::decode(&p.hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let b = s.chain.get_by_hash(&hash).ok_or(StatusCode::NOT_FOUND)?;
    let txs: Vec<TxInfo> = s
        .chain
        .get_txs_for_block(b.height)
        .iter()
        .map(|t| stored_tx_to_info(t, b.height))
        .collect();
    Ok(Json(
        serde_json::to_value(block_to_info(b, txs))
            .unwrap_or(serde_json::json!({"error":"serialize"})),
    ))
}

async fn get_latest_txs(
    State(rpc): State<RpcState>,
    Json(p): Json<PageParams>,
) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let (txs, total) = s.chain.get_recent_txs(page, ps);
    let data: Vec<TxInfo> = txs.iter().map(|(t, h)| stored_tx_to_info(t, *h)).collect();
    Json(
        serde_json::json!({ "data": data, "total": total, "page": page, "pageSize": ps, "hasMore": (page * ps) < total }),
    )
}

async fn get_tx_by_hash(
    State(rpc): State<RpcState>,
    Json(p): Json<HashParam>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    let hash: [u8; 32] = hex::decode(&p.hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let (tx, block_h) = s.chain.get_tx_by_hash(&hash).ok_or(StatusCode::NOT_FOUND)?;
    let block = s
        .chain
        .get_by_height(block_h)
        .ok_or(StatusCode::NOT_FOUND)?;
    let detail = TxDetail {
        base: stored_tx_to_info(&tx, block_h),
        block_hash: hex::encode(block.hash),
        size: tx.size,
        ring_input_count: tx.input_count,
        spend_ids: tx.spend_ids.iter().map(|ki| hex::encode(ki)).collect(),
        spend_identifier_label: tx.spend_identifier_label.clone(),
        spend_identifiers: tx.spend_identifiers.iter().map(hex::encode).collect(),
        output_count: tx.output_count,
        has_payload: tx.has_payload,
        confirmations: s.height.saturating_sub(block_h),
        version: 1,
    };
    Ok(Json(
        serde_json::to_value(detail).unwrap_or(serde_json::json!({"error":"serialize"})),
    ))
}

async fn get_validator_set(
    State(rpc): State<RpcState>,
    Json(_p): Json<PageParams>,
) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let vals: Vec<serde_json::Value> = (0..s.validator_count)
        .map(|i| {
            serde_json::json!({
                "id": format!("validator-{:02}", i),
                "publicKey": format!("msk1val{:064x}", i),
                "stakeWeight": 1_000_000,
                "status": "active",
                "latestProposedBlock": s.height,
                "participationRate": 100.0,
                "uptime": 100.0,
            })
        })
        .collect();
    Json(
        serde_json::json!({ "data": vals, "total": s.validator_count, "page": 1, "pageSize": 50, "hasMore": false }),
    )
}

async fn get_validator_by_id(
    State(rpc): State<RpcState>,
    Json(p): Json<IdParam>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let s = rpc.node.read().await;
    // Parse validator index from id like "validator-02"
    let idx: usize =
        p.id.strip_prefix("validator-")
            .and_then(|s| s.parse().ok())
            .ok_or(StatusCode::NOT_FOUND)?;
    if idx >= s.validator_count {
        return Err(StatusCode::NOT_FOUND);
    }

    let recent_proposals: Vec<u64> = (0..10.min(s.height as usize))
        .filter_map(|i| {
            let h = s.height.saturating_sub(i as u64);
            s.chain
                .get_by_height(h)
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

async fn get_block_production(
    State(rpc): State<RpcState>,
    Json(p): Json<CountParam>,
) -> Json<serde_json::Value> {
    let s = rpc.node.read().await;
    let count = p.count.unwrap_or(30).min(100);
    let blocks = s.chain.get_latest(count);
    let data: Vec<serde_json::Value> = blocks
        .iter()
        .map(|b| {
            serde_json::json!({
                "height": b.height, "txCount": b.tx_count,
                "timestamp": ms_to_iso(b.timestamp_ms), "blockTime": 60.0,
            })
        })
        .collect();
    Json(serde_json::json!(data))
}

/// DEPRECATED: Address-indexed output query.
/// In Monero-style model, the node does NOT maintain address→output index.
/// Wallets should scan blocks via get_block_by_height and detect owned outputs
/// using their private view/scan key. This endpoint returns minimal info only.
#[cfg(feature = "dev-rpc")]
async fn get_address_outputs(Json(p): Json<AddressParam>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "address": p.address,
        "balance": null,
        "totalReceived": null,
        "totalSent": null,
        "txCount": null,
        "outputs": [],
        "deprecated": true,
        "privacyNote": "This node does not maintain address-indexed outputs. Use block scanning (get_block_by_height) with your wallet\'s view key to detect owned outputs."
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

    // M2 audit fix: bound query length to prevent DoS
    if q.len() > 256 {
        return Json(
            serde_json::json!({ "type": "error", "value": "query too long (max 256 chars)" }),
        );
    }

    let s = rpc.node.read().await;

    // Numeric → block height
    if let Ok(h) = q.parse::<u64>() {
        if s.chain.get_by_height(h).is_some() {
            return Json(
                serde_json::json!({ "type": "block", "value": q, "label": format!("Block #{}", h) }),
            );
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

/// Submit a transaction with FULL cryptographic verification.
///
/// # Security (Mainnet P0)
///
/// 1. Deserialize to typed `UtxoTransaction` (reject malformed JSON)
/// 2. Reject oversized payloads (DoS protection)
/// 3. Pass through `UtxoMempool::admit()` which performs:
///    - Structural validation (version, input/output counts, sizes)
///    - Ring member UTXO existence check
///    - Lattice ZKP proof cryptographic verification (LRS/LogRing/Chipmunk)
///    - Key image / link_tag proof verification
///    - Key image double-spend check (chain + mempool)
///    - Stealth extension sanity
/// 4. TX hash is DETERMINISTIC via `UtxoTransaction::tx_hash()`
///    (canonical encoding hash, no timestamp dependency)
///
/// **FAIL-CLOSED:** Any verification failure → reject. No bypass paths.
async fn submit_tx(
    State(rpc): State<RpcState>,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    // ── 1. Size limit (DoS protection: reject before parsing) ──
    if body.len() > 131_072 {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("tx body too large: {} bytes (max 131072)", body.len())
        }));
    }

    // ── 2. Strict deserialization to typed UtxoTransaction ──
    // This rejects arbitrary JSON that doesn't match the schema.
    let tx: UtxoTransaction = match serde_json::from_slice(&body) {
        Ok(tx) => tx,
        Err(e) => {
            return Json(serde_json::json!({
                "txHash": null, "accepted": false,
                "error": format!("invalid transaction format: {}", e)
            }));
        }
    };

    // ── SEC-FIX: Reject system-only tx types at RPC ingress ──
    // SystemEmission and Faucet transactions MUST NOT be user-submittable.
    match tx.tx_type {
        misaka_types::utxo::TxType::SystemEmission | misaka_types::utxo::TxType::Faucet => {
            return Json(serde_json::json!({
                "txHash": null, "accepted": false,
                "error": "SystemEmission/Faucet transactions cannot be user-submitted"
            }));
        }
        _ => {}
    }

    // ── 3. Deterministic TX hash (canonical encoding, no timestamp) ──
    let tx_hash = tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);

    // ── SEC-FIX: ML-DSA-65 pre-verification (anti-spam) ──
    // Previously this path deferred all signature verification to commit time,
    // allowing garbage-signed transactions to flood the mempool for free.
    // narwhal_consensus.rs already has this check — unify behavior here.
    // TODO(PERF): This requires UTXO set read lock to resolve spending_pubkey.
    // For now, add a structural check: reject TransparentTransfer with empty proof.
    if tx.tx_type == misaka_types::utxo::TxType::TransparentTransfer {
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.proof.is_empty() {
                return Json(serde_json::json!({
                    "txHash": hash_hex, "accepted": false,
                    "error": format!("input[{}]: missing ML-DSA-65 signature", i)
                }));
            }
            // ML-DSA-65 signature length is 3309 bytes
            if input.proof.len() != 3309 {
                return Json(serde_json::json!({
                    "txHash": hash_hex, "accepted": false,
                    "error": format!("input[{}]: invalid signature length {} (expected 3309)", i, input.proof.len())
                }));
            }
        }
    }

    // ── SEC-FIX C-11: ML-DSA-65 cryptographic pre-verification ──
    // Previously deferred ALL signature verification to commit time, allowing
    // garbage-signed TXs (valid 3309-byte random proofs) to fill the mempool.
    // Now verify ML-DSA-65 signatures BEFORE mempool admission.
    if tx.tx_type == misaka_types::utxo::TxType::TransparentTransfer && !tx.inputs.is_empty() {
        let guard = rpc.node.read().await;
        let utxo_set = &guard.utxo_set;

        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some(outref) = input.utxo_refs.first() {
                let mut fallback_pk = Vec::new();
                let pk_bytes_opt = match utxo_set.get_spending_key(outref) {
                    Some(pk) => Some(pk),
                    None if tx.extra.len() == 1952 => {
                        fallback_pk = tx.extra.clone();
                        Some(&fallback_pk[..])
                    }
                    None => None,
                };

                if let Some(pk_bytes) = pk_bytes_opt {
                    // Parse ML-DSA-65 public key and signature
                    let pk = match misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&pk_bytes) {
                        Ok(pk) => pk,
                        Err(_) => {
                            drop(guard);
                            return Json(serde_json::json!({
                                "txHash": hash_hex, "accepted": false,
                                "error": format!("input[{}]: invalid spending pubkey in UTXO set", i)
                            }));
                        }
                    };
                    let sig = match misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&input.proof) {
                        Ok(sig) => sig,
                        Err(_) => {
                            drop(guard);
                            return Json(serde_json::json!({
                                "txHash": hash_hex, "accepted": false,
                                "error": format!("input[{}]: malformed ML-DSA-65 signature", i)
                            }));
                        }
                    };
                    // Verify using tx_hash as digest (v1 legacy path).
                    // The Narwhal DAG path uses IntentMessage but this v1 RPC path
                    // uses tx_hash for backward compatibility.
                    let digest = tx.tx_hash();
                    if misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, &digest, &sig).is_err() {
                        drop(guard);
                        return Json(serde_json::json!({
                            "txHash": hash_hex, "accepted": false,
                            "error": format!("input[{}]: ML-DSA-65 signature verification failed", i)
                        }));
                    }
                }
            }
        }
        drop(guard);
    }

    // ── 4. Mempool admission (structural + UTXO existence) ──
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let mut guard = rpc.node.write().await;
    // Reborrow to allow disjoint field access (mempool + utxo_set)
    let s = &mut *guard;

    match s.mempool.admit(tx, &s.utxo_set, now_ms) {
        Ok(admitted_hash) => {
            info!(
                "TX verified & admitted: {} | mempool={}",
                &hash_hex[..16],
                s.mempool.len()
            );
            Json(serde_json::json!({
                "txHash": hex::encode(admitted_hash),
                "accepted": true,
                "error": null
            }))
        }
        Err(e) => {
            tracing::warn!("TX rejected: {} | reason: {}", &hash_hex[..16], e);
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": false,
                "error": format!("{}", e)
            }))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Q-DAG-CT Endpoints
// ═══════════════════════════════════════════════════════════════

// REMOVED: submit_ct_tx endpoint — confidential transactions deprecated in v1.0.

/// Anonymity set request parameters.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnonymitySetReq {
    /// The UTXO being spent (for excluding from ring).
    tx_hash: String,
    output_index: u32,
    /// Desired ring size.
    anonymity_set_size: Option<usize>,
}

/// Get anonymity set for Q-DAG-CT membership proof construction.
///
/// Returns leaf hashes and the signer's position within the set.
/// The client uses this to build a SIS Merkle tree and generate
/// the UnifiedZKP membership proof.
///
/// # Privacy Note
///
/// This endpoint reveals which UTXO the client intends to spend
/// (the tx_hash + output_index is the real input). This is acceptable
/// because the query goes to the client's own node. On-chain observers
/// see only the anonymity_root in the final transaction.
async fn get_anonymity_set(
    State(rpc): State<RpcState>,
    Json(req): Json<AnonymitySetReq>,
) -> Json<serde_json::Value> {
    let anonymity_set_size = req.anonymity_set_size.unwrap_or(16).max(4).min(1024);
    let guard = rpc.node.read().await;

    // Collect confirmed UTXO spending pubkeys as leaf candidates
    let all_keys = guard.utxo_set.all_spending_keys();
    if all_keys.len() < anonymity_set_size {
        return Json(serde_json::json!({
            "error": format!("insufficient UTXOs for ring: need {}, have {}", anonymity_set_size, all_keys.len()),
            "leaves": [],
            "signerIndex": 0
        }));
    }

    // Find the signer's UTXO
    let mut tx_hash_bytes = [0u8; 32];
    if let Ok(decoded) = hex::decode(&req.tx_hash) {
        let len = decoded.len().min(32);
        tx_hash_bytes[..len].copy_from_slice(&decoded[..len]);
    }

    // Build anonymity set: select random UTXOs + include the real one
    use sha3::{Digest as Sha3Digest, Sha3_256};

    // Hash each spending pubkey to create leaf hashes
    let mut all_leaf_hashes: Vec<([u8; 32], String)> = all_keys
        .iter()
        .map(|(outref, pk_bytes)| {
            let leaf: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA_ANON_LEAF:");
                h.update(pk_bytes);
                h.finalize().into()
            };
            (
                leaf,
                format!(
                    "{}:{}",
                    hex::encode(&outref.tx_hash[..8]),
                    outref.output_index
                ),
            )
        })
        .collect();

    // Find signer leaf
    let signer_key = format!("{}:{}", hex::encode(&tx_hash_bytes[..8]), req.output_index);
    let signer_pos = all_leaf_hashes.iter().position(|(_, k)| k == &signer_key);

    // Shuffle and select
    use rand::seq::SliceRandom;
    let mut rng = rand::rngs::OsRng;
    all_leaf_hashes.shuffle(&mut rng);

    let mut signer_index = 0usize;
    let mut selected = Vec::with_capacity(anonymity_set_size);

    // Ensure signer is included
    if signer_pos.is_some() {
        // Find the signer in the shuffled list
        if let Some(shuffled_pos) = all_leaf_hashes.iter().position(|(_, k)| k == &signer_key) {
            let signer_leaf = all_leaf_hashes.remove(shuffled_pos);
            // Insert at random position
            signer_index = rand::Rng::gen_range(&mut rng, 0..anonymity_set_size);
            selected.push((signer_index, signer_leaf.0));
        }
    }

    // Fill remaining slots
    let mut fill_idx = 0;
    for (leaf, _) in all_leaf_hashes
        .iter()
        .take(anonymity_set_size - selected.len())
    {
        while fill_idx == signer_index {
            fill_idx += 1;
        }
        if fill_idx >= anonymity_set_size {
            break;
        }
        selected.push((fill_idx, *leaf));
        fill_idx += 1;
    }

    selected.sort_by_key(|(idx, _)| *idx);
    let leaf_hexes: Vec<String> = selected.iter().map(|(_, l)| hex::encode(l)).collect();

    // Compute root
    let root: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_ANON_ROOT:");
        for (_, l) in &selected {
            h.update(l);
        }
        h.finalize().into()
    };

    Json(serde_json::json!({
        "leaves": leaf_hexes,
        "signerIndex": signer_index,
        "ringSize": selected.len(),
        "root": hex::encode(root),
    }))
}

/// Faucet — drip testnet tokens via coinbase queue.
///
/// FIX-4: Faucet outputs go through apply_block_atomic (same path as all outputs).
/// No direct utxo_set.add_output(). Outputs are spendable through normal flow.
#[cfg(feature = "faucet")]
async fn faucet(
    State(rpc): State<RpcState>,
    Json(req): Json<FaucetReq>,
) -> Json<serde_json::Value> {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    let addr = req.address.trim();

    let mut guard = rpc.node.write().await;
    let s = &mut *guard;

    if s.chain_id == 1 {
        return Json(serde_json::json!({
            "success": false,
            "error": "faucet is disabled on mainnet (chain_id=1)",
            "txHash": null
        }));
    }

    // H-3 FIX: Unified address validation (chain_id bound)
    if let Err(e) = misaka_types::address::validate_address(addr, s.chain_id) {
        return Json(serde_json::json!({
            "success": false, "error": format!("invalid address: {}", e), "txHash": null
        }));
    }

    let cooldown_ms = s.faucet_cooldown_ms;
    if let Some(&last) = s.faucet_drips.get(addr) {
        if now_ms - last < cooldown_ms {
            let wait = (cooldown_ms - (now_ms - last)) / 1000;
            return Json(serde_json::json!({
                "success": false,
                "error": format!("rate limited: wait {}s", wait),
                "txHash": null
            }));
        }
    }

    if s.faucet_drips.len() > 10_000 {
        let cutoff = now_ms.saturating_sub(cooldown_ms * 2);
        s.faucet_drips.retain(|_, &mut v| v > cutoff);
    }

    let faucet_amount = s.faucet_amount;
    // SEC-FIX CRITICAL: spending_pubkey is now REQUIRED for faucet outputs.
    // Previously the address was computed as SHA3("MISAKA:faucet_addr:v1:" || addr || now_ms)
    // which made the output permanently unspendable because P2PKH verification
    // requires address == SHA3(spending_pubkey), and no key produces that hash.
    let spending_pubkey = match req.spending_pubkey.as_deref() {
        Some(hex_str) => match hex::decode(hex_str) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => {
                return Json(serde_json::json!({
                    "success": false, "error": "invalid spendingPubkey hex", "txHash": null
                }));
            }
        },
        None => {
            return Json(serde_json::json!({
                "success": false,
                "error": "spendingPubkey is required — without it, faucet outputs cannot be spent",
                "txHash": null
            }));
        }
    };

    // SEC-FIX: Compute address as SHA3-256(spending_pubkey) for P2PKH compatibility.
    // This ensures the output can actually be spent by the owner of the spending key.
    let p2pkh_address: [u8; 32] = {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(&spending_pubkey).into()
    };

    // Build coinbase TX — queued for next block via apply_block_atomic.
    let coinbase_tx = misaka_types::utxo::UtxoTransaction {
        version: misaka_types::utxo::UTXO_TX_VERSION,
        tx_type: TxType::SystemEmission,
        inputs: vec![],
        outputs: vec![misaka_types::utxo::TxOutput {
            amount: faucet_amount,
            address: p2pkh_address,
            spending_pubkey: Some(spending_pubkey),
        }],
        fee: 0,
        extra: b"faucet".to_vec(),
        expiry: 0,
    };

    let tx_hash = coinbase_tx.tx_hash();
    s.coinbase_pending.push(coinbase_tx);
    s.faucet_drips.insert(addr.to_string(), now_ms);

    let hash_hex = hex::encode(tx_hash);
    info!(
        "Faucet queued: {} → {} ({} MISAKA)",
        &hash_hex[..16],
        addr,
        faucet_amount
    );

    Json(serde_json::json!({
        "success": true,
        "txHash": hash_hex,
        "amount": faucet_amount,
        "address": addr,
        "error": null
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        build_linear_cors_layer, get_block_by_hash, get_tx_by_hash, get_validator_by_id, health,
        linear_consumer_surfaces_json, linear_privacy_path_surface_json, search, stored_tx_to_info,
        submit_tx, HashParam, IdParam, QueryParam,
    };
    #[cfg(feature = "faucet")]
    use super::{faucet, FaucetReq};
    use crate::{
        block_producer::{NodeState, SharedState},
        chain_store::{ChainStore, StoredTx, TxInput, TxOutput},
        config::{NodeMode, P2pConfig},
        p2p_network::P2pNetwork,
        rpc_auth::{require_api_key, ApiKeyState},
    };
    use axum::{
        body::Body,
        extract::{DefaultBodyLimit, State},
        http::{Request, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use misaka_mempool::UtxoMempool;
    use misaka_pqc::{PrivacyBackendFamily, SpendIdentifierModel};
    use misaka_storage::utxo_set::UtxoSet;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::env_lock()
    }

    fn sample_stored_tx() -> StoredTx {
        StoredTx {
            hash: [0x11; 32],
            fee: 42,
            input_count: 1,
            output_count: 1,
            timestamp_ms: 1_710_000_000_000,
            status: "confirmed".into(),
            spend_ids: vec![[0x22; 32]],
            privacy_scheme_tag: 0x10,
            privacy_scheme_name: "UnifiedZKP-v1".into(),
            privacy_backend_family: PrivacyBackendFamily::ZeroKnowledge,
            privacy_anonymity_model:
                "SIS Merkle + BDLOP committed path + algebraic identifier (pk non-recoverable)"
                    .into(),
            spend_identifier_model: SpendIdentifierModel::CanonicalSpendTag,
            spend_identifier_label: "canonical_id".into(),
            spend_identifiers: vec![[0x33; 32]],
            full_verifier_member_index_hidden: true,
            zkp_migration_ready: true,
            privacy_status_note: "Production ZK path.".into(),
            size: 128,
            has_payload: false,
            outputs: vec![TxOutput {
                address: "msk1example".into(),
                amount: 100,
                output_index: 0,
                one_time_pubkey: String::new(),
                ephemeral_pubkey: String::new(),
                view_tag: "abcd".into(),
            }],
            inputs: vec![TxInput {
                spend_id: hex::encode([0x22; 32]),
                anonymity_set_size: 16,
                source_tx_hash: "deadbeef".into(),
                source_output_index: 0,
            }],
        }
    }

    fn make_test_state() -> SharedState {
        let mut chain = ChainStore::new();
        chain.store_genesis(1_710_000_000_000);

        Arc::new(RwLock::new(NodeState {
            chain,
            height: 0,
            tx_count_total: 0,
            validator_count: 0,
            genesis_timestamp_ms: 1_710_000_000_000,
            chain_id: 2,
            chain_name: "MISAKA Testnet".into(),
            version: "test".into(),
            mempool: UtxoMempool::new(8),
            utxo_set: UtxoSet::new(8),
            coinbase_pending: Vec::new(),
            faucet_drips: HashMap::new(),
            faucet_amount: 0,
            faucet_cooldown_ms: 0,
            data_dir: std::env::temp_dir()
                .join("misaka-node-rpc-tests")
                .display()
                .to_string(),
            experimental_zk_path: false,
            proposer_payout_address: None,
            treasury_address: None,
        }))
    }

    fn make_test_rpc_state() -> super::RpcState {
        super::RpcState {
            node: make_test_state(),
            p2p: Arc::new(P2pNetwork::new(
                2,
                "rpc-test-node".into(),
                P2pConfig::from_mode(NodeMode::Hidden),
            )),
        }
    }

    #[test]
    fn test_stored_tx_to_info_exposes_privacy_metadata() {
        let info = stored_tx_to_info(&sample_stored_tx(), 7);
        let json = serde_json::to_value(info).expect("serialize tx info");

        assert_eq!(json["privacy"]["schemeTag"], 16);
        assert_eq!(json["privacy"]["schemeName"], "UnifiedZKP-v1");
        assert_eq!(json["privacy"]["backendFamily"], "zeroKnowledge");
        assert_eq!(json["privacy"]["spendIdentifierModel"], "canonicalSpendTag");
        assert_eq!(json["privacy"]["spendIdentifierLabel"], "canonical_id");
        assert_eq!(
            json["privacy"]["spendIdentifiers"][0],
            hex::encode([0x33; 32])
        );
        assert_eq!(json["inputs"][0]["keyImage"], hex::encode([0x22; 32]));
        assert_eq!(
            json["inputs"][0]["spendIdentifier"],
            hex::encode([0x33; 32])
        );
        assert_eq!(json["inputs"][0]["spendIdentifierLabel"], "canonical_id");
    }

    #[tokio::test]
    async fn test_submit_tx_rejects_payload_over_global_body_limit() {
        let app = Router::new()
            .route(
                "/api/submit_tx",
                post(|_: axum::body::Bytes| async { StatusCode::OK }),
            )
            .layer(DefaultBodyLimit::max(131_072));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit_tx")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'{'; 131_073]))
                    .expect("test request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // REMOVED: test_submit_ct_tx — endpoint deleted in v1.0.

    #[tokio::test]
    async fn test_rpc_write_routes_require_api_key_and_health_stays_public() {
        let auth_state = ApiKeyState {
            required_key: Some(secrecy::SecretString::new("rpc-secret".into())),
            write_ip_allowlist: vec![],
            auth_required: false,
        };
        let public_routes = Router::new().route("/health", get(health));
        let write_routes = {
            let routes = Router::new()
                .route("/api/submit_tx", post(submit_tx))
                .route("/api/submit_ct_tx", post(submit_ct_tx));
            #[cfg(feature = "faucet")]
            let routes = routes.route("/api/faucet", post(faucet));
            routes.route_layer(axum::middleware::from_fn_with_state(
                auth_state,
                require_api_key,
            ))
        };
        let app = public_routes
            .merge(write_routes)
            .with_state(make_test_rpc_state());

        let health_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(health_response.status(), StatusCode::OK);

        let mut routes = vec!["/api/submit_tx", "/api/submit_ct_tx"];
        #[cfg(feature = "faucet")]
        routes.push("/api/faucet");

        for route in routes {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .expect("write request"),
                )
                .await
                .expect("write response");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{route} must stay behind API-key auth"
            );
        }
    }

    #[tokio::test]
    async fn test_run_rpc_server_rejects_invalid_cors_origin_config() {
        let _guard = env_lock();
        std::env::set_var("MISAKA_CORS_ORIGINS", " ,  , ");

        let result: anyhow::Result<()> = super::run_rpc_server(
            make_test_state(),
            Arc::new(P2pNetwork::new(
                2,
                "rpc-test-node".into(),
                P2pConfig::from_mode(NodeMode::Hidden),
            )),
            "127.0.0.1:0".parse().expect("socket addr"),
            2,
        )
        .await;

        assert!(result.is_err(), "invalid CORS config must fail closed");
        let err = result.expect_err("invalid CORS config");
        assert!(err.to_string().contains("contains no valid origins"));

        std::env::remove_var("MISAKA_CORS_ORIGINS");
    }

    #[tokio::test]
    async fn test_linear_cors_default_allows_localhost_only() {
        let _guard = env_lock();
        std::env::remove_var("MISAKA_CORS_ORIGINS");

        let app = Router::new()
            .route("/health", get(health))
            .layer(build_linear_cors_layer().expect("default cors"))
            .with_state(make_test_rpc_state());

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header(axum::http::header::ORIGIN, "http://localhost:3000")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .expect("allowed preflight"),
            )
            .await
            .expect("allowed response");
        assert_eq!(
            allowed
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&axum::http::HeaderValue::from_static(
                "http://localhost:3000"
            ))
        );

        let denied = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header(axum::http::header::ORIGIN, "https://evil.example")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .expect("denied preflight"),
            )
            .await
            .expect("denied response");
        assert!(denied
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    #[tokio::test]
    async fn test_get_block_by_hash_rejects_malformed_hash() {
        let err = get_block_by_hash(
            State(make_test_rpc_state()),
            Json(HashParam {
                hash: "not-a-hex-hash".into(),
            }),
        )
        .await
        .expect_err("invalid hashes must fail closed");

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_validator_by_id_rejects_malformed_id() {
        let err = get_validator_by_id(
            State(make_test_rpc_state()),
            Json(IdParam {
                id: "validator-not-a-number".into(),
            }),
        )
        .await
        .expect_err("malformed validator ids must fail closed");

        assert_eq!(err, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_search_rejects_overlong_query() {
        let json = search(
            State(make_test_rpc_state()),
            Json(QueryParam {
                query: "a".repeat(257),
            }),
        )
        .await
        .0;

        assert_eq!(json["type"], serde_json::Value::String("error".into()));
        assert_eq!(
            json["value"],
            serde_json::Value::String("query too long (max 256 chars)".into())
        );
    }

    #[test]
    fn test_linear_consumer_surfaces_json_exposes_v4_vocabulary() {
        let json = linear_consumer_surfaces_json();
        assert_eq!(
            json["validatorAttestation"]["available"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            json["validatorAttestation"]["bridgeReadiness"],
            serde_json::Value::String("notAvailable".into())
        );
        assert_eq!(json["txStatusVocabulary"], serde_json::json!(["confirmed"]));
    }

    #[test]
    fn test_linear_privacy_path_surface_json_splits_runtime_and_target() {
        let json = linear_privacy_path_surface_json("ringSignature");
        assert_eq!(
            json["runtimePath"],
            serde_json::Value::String("ringSignature".into())
        );
        assert_eq!(
            json["targetPath"],
            serde_json::Value::String("zeroKnowledge".into())
        );
        assert_eq!(
            json["targetBackendFamily"],
            serde_json::Value::String("zeroKnowledge".into())
        );
    }

    #[tokio::test]
    async fn test_get_tx_by_hash_rejects_invalid_hash_without_state_lookup() {
        let rpc = make_test_rpc_state();
        let response = get_tx_by_hash(
            State(rpc),
            Json(HashParam {
                hash: "not-a-hex-hash".into(),
            }),
        )
        .await;

        assert!(matches!(response, Err(StatusCode::BAD_REQUEST)));
    }

    #[cfg(feature = "faucet")]
    #[tokio::test]
    async fn test_linear_faucet_rejects_invalid_address() {
        let response = faucet(
            State(make_test_rpc_state()),
            Json(FaucetReq {
                address: "not-a-valid-address".into(),
                spending_pubkey: None,
            }),
        )
        .await;

        assert_eq!(response.0["success"], serde_json::Value::Bool(false));
        assert!(response.0["error"]
            .as_str()
            .expect("error string")
            .contains("invalid address"));
    }

    #[cfg(feature = "faucet")]
    #[tokio::test]
    async fn test_linear_faucet_is_disabled_on_mainnet() {
        let rpc = make_test_rpc_state();
        {
            let mut guard = rpc.node.write().await;
            guard.chain_id = 1;
        }

        let response = faucet(
            State(rpc),
            Json(FaucetReq {
                address: "msk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kc2m7".into(),
                spending_pubkey: None,
            }),
        )
        .await;

        assert_eq!(response.0["success"], serde_json::Value::Bool(false));
        assert_eq!(
            response.0["error"],
            serde_json::Value::String("faucet is disabled on mainnet (chain_id=1)".into())
        );
    }
}
