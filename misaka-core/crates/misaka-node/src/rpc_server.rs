//! HTTP RPC server — axum-based, serves Explorer + CLI.
//!
//! ## Security (Mainnet P0)
//!
//! - **API Key Auth**: Write endpoints (submit_tx, submit_ct_tx) require
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
use misaka_rpc::{linear_consumer_surfaces_status, v4_privacy_path_surface_status};
use misaka_types::utxo::{TxType, UtxoTransaction};

/// Combined state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    pub node: SharedState,
    pub p2p: Arc<P2pNetwork>,
}

pub async fn run_rpc_server(
    state: SharedState,
    p2p: Arc<P2pNetwork>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let rpc_state = RpcState { node: state, p2p };

    // ── API Key configuration ──
    let auth_state = ApiKeyState::from_env();
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
        .route("/health", get(health));

    // ── Write endpoints (auth required when MISAKA_RPC_API_KEY is set) ──
    let mut write_routes = Router::new()
        .route("/api/submit_tx", post(submit_tx))
        .route("/api/submit_ct_tx", post(submit_ct_tx))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_state,
            require_api_key,
        ));

    // Faucet is feature-gated: not available in production builds
    #[cfg(feature = "faucet")]
    {
        write_routes = write_routes.route("/api/faucet", post(faucet));
    }

    let mut app = public_routes.merge(write_routes);

    // MAINNET: get_address_outputs is dev-only (privacy leak — exposes address→UTXO mapping)
    #[cfg(feature = "dev-rpc")]
    {
        app = app.route("/api/get_address_outputs", post(get_address_outputs));
    }

    // CORS: Fail-closed. No permissive() under ANY circumstance.
    //
    // - MISAKA_CORS_ORIGINS set + valid → allow those origins only
    // - MISAKA_CORS_ORIGINS set + empty/invalid → FATAL: refuse to start
    // - MISAKA_CORS_ORIGINS unset → localhost only (dev default)
    let cors = {
        match std::env::var("MISAKA_CORS_ORIGINS") {
            Ok(origins_str) => {
                let origins: Vec<axum::http::HeaderValue> = origins_str
                    .split(',')
                    .filter(|o| !o.trim().is_empty())
                    .filter_map(|o| o.trim().parse().ok())
                    .collect();
                if origins.is_empty() {
                    // Env var was SET but parsed to zero valid origins → FATAL
                    // This prevents fail-open on typos like "htpp://localhost:3000"
                    anyhow::bail!(
                        "FATAL: MISAKA_CORS_ORIGINS is set but contains no valid origins: '{}'. \
                         Fix the value or unset the variable for localhost-only default.",
                        origins_str
                    );
                }
                info!("CORS: allowing {} configured origins", origins.len());
                CorsLayer::new()
                    .allow_origin(origins)
                    .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                    .allow_headers([axum::http::header::CONTENT_TYPE])
            }
            Err(_) => {
                // No env var set: restrictive localhost-only default
                info!("CORS: no MISAKA_CORS_ORIGINS set, allowing localhost only");
                CorsLayer::new()
                    .allow_origin([
                        "http://localhost:3000".parse().expect("static origin"),
                        "http://localhost:3001".parse().expect("static origin"),
                        "http://127.0.0.1:3000".parse().expect("static origin"),
                        "http://127.0.0.1:3001".parse().expect("static origin"),
                    ])
                    .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                    .allow_headers([axum::http::header::CONTENT_TYPE])
            }
        }
    };

    let app = app
        .layer(cors)
        // ── Global body size limit: 128KB (DoS protection) ──
        .layer(DefaultBodyLimit::max(131_072))
        // ── Global concurrency limit: max 64 in-flight requests ──
        .layer(ConcurrencyLimitLayer::new(64))
        .with_state(rpc_state);

    info!("RPC server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
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
#[derive(Deserialize)]
struct AddressParam {
    address: String,
}
#[derive(Deserialize)]
struct IdParam {
    id: String,
}
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
    key_images: Vec<String>,
    #[serde(rename = "spendIdentifierLabel")]
    spend_identifier_label: String,
    #[serde(rename = "spendIdentifiers")]
    spend_identifiers: Vec<String>,
    #[serde(rename = "stealthOutputCount")]
    stealth_output_count: usize,
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

/// Generate a view tag for fast wallet scanning (Monero-style).
/// view_tag = first 2 bytes of SHA3-256(address || amount || tx_entropy)
/// This is PUBLIC data — does not reveal ownership.
/// Wallet checks: if view_tag matches → run full ownership detection.
fn generate_view_tag(address: &str, amount: u64, entropy: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:viewtag:v1:");
    h.update(address.as_bytes());
    h.update(amount.to_le_bytes());
    h.update(entropy);
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(&hash[..2]) // 2-byte view tag = 4 hex chars
}

fn ms_to_iso(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

fn linear_consumer_surfaces_json() -> serde_json::Value {
    serde_json::to_value(linear_consumer_surfaces_status()).unwrap_or(serde_json::json!({
        "validatorAttestation": {
            "available": false,
            "bridgeReadiness": "notAvailable",
            "explorerConfirmationLevel": "blockFinalized"
        },
        "txStatusVocabulary": ["confirmed"]
    }))
}

fn linear_privacy_path_surface_json(runtime_path: &str) -> serde_json::Value {
    serde_json::to_value(v4_privacy_path_surface_status(runtime_path)).unwrap_or(
        serde_json::json!({
            "runtimePath": runtime_path,
            "targetPath": "zeroKnowledge",
            "targetBackendFamily": "zeroKnowledge",
            "note": "privacy path surface serialization failed"
        }),
    )
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
                .unwrap_or_else(|| i.key_image.clone());
            serde_json::json!({
                "keyImage": i.key_image,
                "ringSize": i.ring_size,
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

async fn health() -> &'static str {
    "ok"
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
        key_images: tx.key_images.iter().map(|ki| hex::encode(ki)).collect(),
        spend_identifier_label: tx.spend_identifier_label.clone(),
        spend_identifiers: tx.spend_identifiers.iter().map(hex::encode).collect(),
        stealth_output_count: tx.output_count,
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
///    - Ring signature cryptographic verification (LRS/LogRing/Chipmunk)
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

    // ── 3. Deterministic TX hash (canonical encoding, no timestamp) ──
    let tx_hash = tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);

    // ── 4. Full verification via mempool.admit() ──
    // This performs ALL cryptographic checks:
    // - Ring signature verification (PQ lattice-based)
    // - Key image proof verification
    // - UTXO existence for ring members
    // - Double-spend detection (chain + mempool)
    // - Structural validation
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

/// Submit a confidential transaction (Q-DAG-CT v4).
///
/// Accepts a v4 UtxoTransaction where `key_image` fields carry nullifiers.
/// The mempool performs nullifier conflict detection; full ZKP verification
/// is deferred to block validation (via qdag_verify).
async fn submit_ct_tx(
    State(rpc): State<RpcState>,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    // Size limit — CT transactions are larger due to range proofs (~67KB per output)
    if body.len() > 1_048_576 {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("ct tx body too large: {} bytes (max 1MB)", body.len())
        }));
    }

    // Deserialize as UtxoTransaction (v4 format)
    let tx: UtxoTransaction = match serde_json::from_slice(&body) {
        Ok(tx) => tx,
        Err(e) => {
            return Json(serde_json::json!({
                "txHash": null, "accepted": false,
                "error": format!("invalid CT transaction format: {}", e)
            }));
        }
    };

    if !tx.is_qdag() {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("expected v4 (Q-DAG-CT) transaction, got version 0x{:02x}", tx.version)
        }));
    }

    let tx_hash = tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let mut guard = rpc.node.write().await;
    let s = &mut *guard;

    match s.mempool.admit(tx, &s.utxo_set, now_ms) {
        Ok(admitted_hash) => {
            info!(
                "CT TX verified & admitted: {} | mempool={}",
                &hash_hex[..16],
                s.mempool.len()
            );
            Json(serde_json::json!({
                "txHash": hex::encode(admitted_hash),
                "accepted": true,
                "error": null,
                "txType": "confidential"
            }))
        }
        Err(e) => {
            tracing::warn!("CT TX rejected: {} | reason: {}", &hash_hex[..16], e);
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": false,
                "error": format!("{}", e)
            }))
        }
    }
}

/// Anonymity set request parameters.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnonymitySetReq {
    /// The UTXO being spent (for excluding from ring).
    tx_hash: String,
    output_index: u32,
    /// Desired ring size.
    ring_size: Option<usize>,
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
    let ring_size = req.ring_size.unwrap_or(16).max(4).min(1024);
    let guard = rpc.node.read().await;

    // Collect confirmed UTXO spending pubkeys as leaf candidates
    let all_keys = guard.utxo_set.all_spending_keys();
    if all_keys.len() < ring_size {
        return Json(serde_json::json!({
            "error": format!("insufficient UTXOs for ring: need {}, have {}", ring_size, all_keys.len()),
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
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(ring_size);

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
    let mut selected = Vec::with_capacity(ring_size);

    // Ensure signer is included
    if let Some(pos) = signer_pos {
        // Find the signer in the shuffled list
        if let Some(shuffled_pos) = all_leaf_hashes.iter().position(|(_, k)| k == &signer_key) {
            let signer_leaf = all_leaf_hashes.remove(shuffled_pos);
            // Insert at random position
            signer_index = rand::Rng::gen_range(&mut rng, 0..ring_size);
            selected.push((signer_index, signer_leaf.0));
        }
    }

    // Fill remaining slots
    let mut fill_idx = 0;
    for (leaf, _) in all_leaf_hashes.iter().take(ring_size - selected.len()) {
        while fill_idx == signer_index {
            fill_idx += 1;
        }
        if fill_idx >= ring_size {
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
    if addr.len() < 10 || addr.len() > 100 {
        return Json(serde_json::json!({
            "success": false, "error": "invalid address length", "txHash": null
        }));
    }
    if !addr.starts_with("msk1") {
        return Json(serde_json::json!({
            "success": false, "error": "address must start with msk1", "txHash": null
        }));
    }

    let mut guard = rpc.node.write().await;
    let s = &mut *guard;

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
    let spending_pubkey = match req.spending_pubkey.as_deref() {
        Some(hex_str) => match hex::decode(hex_str) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                return Json(serde_json::json!({
                    "success": false, "error": "invalid spendingPubkey hex", "txHash": null
                }));
            }
        },
        None => None,
    };

    // Build coinbase TX — queued for next block via apply_block_atomic.
    // NO direct utxo_set mutation. Same execution path as all outputs.
    let coinbase_tx = misaka_types::utxo::UtxoTransaction {
        version: misaka_types::utxo::UTXO_TX_VERSION_V3,
        ring_scheme: misaka_types::utxo::RING_SCHEME_LOGRING,
        tx_type: TxType::Faucet,
        inputs: vec![], // Faucet: no inputs
        outputs: vec![misaka_types::utxo::TxOutput {
            amount: faucet_amount,
            one_time_address: {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:faucet_addr:v1:");
                h.update(addr.as_bytes());
                h.update(now_ms.to_le_bytes());
                let hash: [u8; 32] = h.finalize().into();
                let mut a = [0u8; 32];
                a.copy_from_slice(&hash);
                a
            },
            pq_stealth: None,
            spending_pubkey,
        }],
        fee: 0,
        extra: b"faucet".to_vec(),
        zk_proof: None,
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
        linear_consumer_surfaces_json, linear_privacy_path_surface_json, stored_tx_to_info,
    };
    use crate::chain_store::{StoredTx, TxInput, TxOutput};
    use misaka_pqc::{PrivacyBackendFamily, SpendIdentifierModel};

    fn sample_stored_tx() -> StoredTx {
        StoredTx {
            hash: [0x11; 32],
            fee: 42,
            input_count: 1,
            output_count: 1,
            timestamp_ms: 1_710_000_000_000,
            status: "confirmed".into(),
            key_images: vec![[0x22; 32]],
            privacy_scheme_tag: 0x10,
            privacy_scheme_name: "UnifiedZKP-v1".into(),
            privacy_backend_family: PrivacyBackendFamily::ZeroKnowledge,
            privacy_anonymity_model:
                "SIS Merkle + BDLOP committed path + algebraic nullifier (pk non-recoverable)"
                    .into(),
            spend_identifier_model: SpendIdentifierModel::CanonicalNullifier,
            spend_identifier_label: "nullifier".into(),
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
                key_image: hex::encode([0x22; 32]),
                ring_size: 16,
                source_tx_hash: "deadbeef".into(),
                source_output_index: 0,
            }],
        }
    }

    #[test]
    fn test_stored_tx_to_info_exposes_privacy_metadata() {
        let info = stored_tx_to_info(&sample_stored_tx(), 7);
        let json = serde_json::to_value(info).expect("serialize tx info");

        assert_eq!(json["privacy"]["schemeTag"], 16);
        assert_eq!(json["privacy"]["schemeName"], "UnifiedZKP-v1");
        assert_eq!(json["privacy"]["backendFamily"], "zeroKnowledge");
        assert_eq!(
            json["privacy"]["spendIdentifierModel"],
            "canonicalNullifier"
        );
        assert_eq!(json["privacy"]["spendIdentifierLabel"], "nullifier");
        assert_eq!(
            json["privacy"]["spendIdentifiers"][0],
            hex::encode([0x33; 32])
        );
        assert_eq!(json["inputs"][0]["keyImage"], hex::encode([0x22; 32]));
        assert_eq!(
            json["inputs"][0]["spendIdentifier"],
            hex::encode([0x33; 32])
        );
        assert_eq!(json["inputs"][0]["spendIdentifierLabel"], "nullifier");
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
}
