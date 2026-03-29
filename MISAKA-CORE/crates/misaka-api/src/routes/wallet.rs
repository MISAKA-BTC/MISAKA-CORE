//! Wallet routes — GET /v1/wallet/:address, etc.
//!
//! # Hardening (v5.2)
//!
//! - Address format validation (msk1 prefix, length bounds).
//! - Decoy parameter bounds (count clamped to [1, 64], amount > 0).
//! - Proper HTTP status codes (400 on bad input, 502 on upstream).
//! - New: GET /v1/wallet/:address/history for tx history scan.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/wallet/:address", get(get_wallet))
        .route("/v1/wallet/:address/utxos", get(get_utxos))
        .route("/v1/wallet/:address/history", get(get_history))
        .route("/v1/decoys", get(get_decoys))
}

/// Structured API error body.
fn api_error(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "code": code, "message": message } })
}

/// Validate MISAKA address format (structural check, no chain binding).
fn validate_address(address: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    misaka_types::address::validate_format(address).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(api_error("INVALID_ADDRESS", &e.to_string())),
        )
    })?;
    Ok(())
}

/// `GET /v1/wallet/:address`
async fn get_wallet(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_address(&address)?;
    state
        .proxy
        .post(
            "/api/get_utxos_by_address",
            &serde_json::json!({ "address": address }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

/// `GET /v1/wallet/:address/utxos`
async fn get_utxos(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_address(&address)?;
    state
        .proxy
        .post(
            "/api/get_utxos_by_address",
            &serde_json::json!({ "address": address }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_history_page")]
    page: usize,
    #[serde(default = "default_history_page_size")]
    page_size: usize,
}
fn default_history_page() -> usize {
    1
}
fn default_history_page_size() -> usize {
    20
}

/// `GET /v1/wallet/:address/history?page=1&page_size=20`
///
/// Proxy to node's tx history for an address. Useful for block explorers
/// and wallet activity screens.
async fn get_history(
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
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

/// Maximum decoy count per request (DoS protection).
const MAX_DECOY_COUNT: usize = 64;

#[derive(Deserialize)]
struct DecoyQuery {
    amount: Option<u64>,
    #[serde(default = "default_count")]
    count: usize,
    #[serde(default)]
    exclude_tx: String,
    #[serde(default)]
    exclude_index: u32,
}

fn default_count() -> usize {
    8
}

/// `GET /v1/decoys?amount=1000000&count=8`
async fn get_decoys(
    State(state): State<AppState>,
    Query(q): Query<DecoyQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate amount
    let amount = match q.amount {
        Some(a) if a > 0 => a,
        Some(0) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(api_error("INVALID_AMOUNT", "amount must be greater than 0")),
            ));
        }
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(api_error("MISSING_AMOUNT", "amount query parameter is required")),
            ));
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(api_error("INVALID_AMOUNT", "invalid amount")),
            ));
        }
    };

    // Clamp count to safe bounds
    let count = q.count.clamp(1, MAX_DECOY_COUNT);

    state
        .proxy
        .post(
            "/api/get_decoy_utxos",
            &serde_json::json!({
                "amount": amount,
                "count": count,
                "excludeTxHash": q.exclude_tx,
                "excludeOutputIndex": q.exclude_index,
            }),
        )
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}
