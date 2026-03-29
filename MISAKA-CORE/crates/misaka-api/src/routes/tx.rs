//! Transaction routes — POST /v1/tx/submit, GET /v1/tx/:hash
//!
//! # Hardening (v5.2)
//!
//! - Proper HTTP status codes (502 upstream, 400 bad input, 422 rejected TX).
//! - TX hash path param validation (64 hex chars).
//! - Structured JSON error responses.
//!
//! # SEC-FIX: /v1/faucet removed — bypassed hardened queue (see faucet.rs).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/tx/submit", post(submit_tx))
        .route("/v1/tx/:hash", get(get_tx))
        // SEC-FIX: /v1/faucet removed — it bypassed the hardened queue-based
        // /api/v1/faucet/request (24h cooldown, IP rate limit).
        // All faucet requests must go through faucet.rs::router().
}

/// Structured API error body.
fn api_error(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "code": code, "message": message } })
}

/// `POST /v1/tx/submit` — Forward signed transaction to node.
async fn submit_tx(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Basic structural validation before forwarding
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(api_error("INVALID_BODY", "request body must be a JSON object")),
        );
    }

    match state.proxy.post("/api/submit_tx", &body).await {
        Ok(data) => {
            let accepted = data["accepted"].as_bool().unwrap_or(false);
            let status = if accepted {
                StatusCode::OK
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            (status, Json(data))
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "accepted": false,
                "error": { "code": "UPSTREAM_ERROR", "message": e.to_string() },
            })),
        ),
    }
}

/// `GET /v1/tx/:hash` — Look up transaction by hash.
async fn get_tx(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(api_error(
                "INVALID_HASH",
                "tx hash must be exactly 64 hex characters",
            )),
        ));
    }

    state
        .proxy
        .post("/api/get_tx_by_hash", &serde_json::json!({ "hash": hash }))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

// SEC-FIX: faucet() handler removed — all faucet traffic goes through
// the hardened queue in faucet.rs (/api/v1/faucet/request).
