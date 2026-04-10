//! Explorer & Indexer API routes.
//!
//! # Endpoints
//!
//! ## Wallet Sync (Prompt 1)
//! - `GET /api/v1/address/:address/utxos` — Unspent UTXOs for an address.
//! - `GET /api/v1/address/:address/history` — Paginated TX history.
//! - `GET /api/v1/address/:address/balance` — Balance summary.
//! - `GET /api/v1/tx/:hash/status` — TX lifecycle status.
//!
//! ## Explorer (Prompt 3)
//! - `GET /api/v1/explorer/blocks?limit=20` — Recent blocks.
//! - `GET /api/v1/explorer/block/:hash_or_height` — Block details.
//! - `GET /api/v1/explorer/search/:query` — Universal search.
//! - `GET /api/v1/explorer/stats` — Chain statistics.
//! - `GET /explorer` — Embedded HTML frontend.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // ── Wallet Sync API ──
        .route("/api/v1/address/:address/utxos", get(get_address_utxos))
        .route("/api/v1/address/:address/history", get(get_address_history))
        .route("/api/v1/address/:address/balance", get(get_address_balance))
        .route("/api/v1/tx/:hash/status", get(get_tx_status))
        // ── Explorer API ──
        .route("/api/v1/explorer/blocks", get(get_recent_blocks))
        .route(
            "/api/v1/explorer/block/:hash_or_height",
            get(get_block_detail),
        )
        .route("/api/v1/explorer/search/:query", get(search))
        .route("/api/v1/explorer/stats", get(get_stats))
        // ── Explorer Frontend ──
        .route("/explorer", get(explorer_frontend))
}

fn api_error(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "code": code, "message": message } })
}

fn validate_address(address: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    misaka_types::address::validate_format(address).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(api_error("INVALID_ADDRESS", &e.to_string())),
        )
    })?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Wallet Sync Endpoints
// ═══════════════════════════════════════════════════════════════

/// `GET /api/v1/address/:address/utxos`
async fn get_address_utxos(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_address(&address)?;

    // Proxy to node's indexer endpoint
    state
        .proxy
        .post(
            "/api/get_indexed_utxos",
            &serde_json::json!({ "address": address }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_page_size")]
    page_size: usize,
}
fn default_page() -> usize {
    1
}
fn default_page_size() -> usize {
    20
}

/// `GET /api/v1/address/:address/history?page=1&page_size=20`
async fn get_address_history(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_address(&address)?;

    let page = q.page.max(1);
    let page_size = q.page_size.clamp(1, 100);

    state
        .proxy
        .post(
            "/api/get_address_history",
            &serde_json::json!({
                "address": address,
                "page": page,
                "pageSize": page_size,
            }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

/// `GET /api/v1/address/:address/balance`
async fn get_address_balance(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_address(&address)?;

    state
        .proxy
        .post(
            "/api/get_address_balance",
            &serde_json::json!({ "address": address }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

/// `GET /api/v1/tx/:hash/status`
async fn get_tx_status(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(api_error("INVALID_HASH", "must be 64 hex chars")),
        ));
    }

    state
        .proxy
        .post("/api/get_tx_status", &serde_json::json!({ "txHash": hash }))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

// ═══════════════════════════════════════════════════════════════
//  Explorer Endpoints
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct BlocksQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    20
}

/// `GET /api/v1/explorer/blocks?limit=20`
async fn get_recent_blocks(
    State(state): State<AppState>,
    Query(q): Query<BlocksQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let limit = q.limit.clamp(1, 100);

    state
        .proxy
        .post(
            "/api/get_latest_blocks",
            &serde_json::json!({ "page": 1, "pageSize": limit }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

/// `GET /api/v1/explorer/block/:hash_or_height`
async fn get_block_detail(
    State(state): State<AppState>,
    Path(hash_or_height): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Detect if it's a height (numeric) or hash (64 hex)
    if let Ok(height) = hash_or_height.parse::<u64>() {
        return state
            .proxy
            .post(
                "/api/get_block_by_height",
                &serde_json::json!({ "height": height }),
            )
            .await
            .map(Json)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(crate::proxy::public_upstream_error(&e)),
                )
            });
    }

    if hash_or_height.len() == 64 && hash_or_height.chars().all(|c| c.is_ascii_hexdigit()) {
        return state
            .proxy
            .post(
                "/api/get_block_by_hash",
                &serde_json::json!({ "hash": hash_or_height }),
            )
            .await
            .map(Json)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(crate::proxy::public_upstream_error(&e)),
                )
            });
    }

    Err((
        StatusCode::BAD_REQUEST,
        Json(api_error(
            "INVALID_PARAM",
            "must be a block height (number) or hash (64 hex chars)",
        )),
    ))
}

/// `GET /api/v1/explorer/search/:query`
async fn search(
    State(state): State<AppState>,
    Path(query): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let q = query.trim();
    if q.is_empty() || q.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(api_error("INVALID_QUERY", "query must be 1-256 chars")),
        ));
    }

    state
        .proxy
        .post("/api/search", &serde_json::json!({ "query": q }))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

/// `GET /api/v1/explorer/stats`
async fn get_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .proxy
        .post("/api/get_chain_info", &serde_json::json!({}))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

// ═══════════════════════════════════════════════════════════════
//  Embedded Explorer Frontend
// ═══════════════════════════════════════════════════════════════

/// `GET /explorer` — Serves the single-page explorer UI.
async fn explorer_frontend() -> Html<&'static str> {
    Html(include_str!("explorer_frontend.html"))
}
