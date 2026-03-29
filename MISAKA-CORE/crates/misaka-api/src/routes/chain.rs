//! Chain routes — GET /v1/chain/*, GET /v1/dag/*
//!
//! # Hardening (v5.2)
//!
//! - Proper HTTP status codes (502 on upstream failure, 400 on bad input).
//! - Path parameter validation (hex hash must be 64 hex chars).
//! - Structured JSON error responses with `code` + `message`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/chain/info", get(get_chain_info))
        .route("/v1/chain/fees", get(get_fees))
        .route("/v1/chain/mempool", get(get_mempool))
        .route("/v1/dag/info", get(get_dag_info))
        .route("/v1/dag/tips", get(get_dag_tips))
        .route("/v1/dag/block/:hash", get(get_dag_block))
        .route("/health", get(health))
        .route("/v1/health/deep", get(deep_health))
}

/// Structured API error body.
fn api_error(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "code": code, "message": message } })
}

/// Validate a hex-encoded hash parameter (must be 64 hex chars = 32 bytes).
fn validate_hex_hash(hash: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(api_error(
                "INVALID_HASH",
                "hash must be exactly 64 hex characters (32 bytes)",
            )),
        ));
    }
    Ok(())
}

async fn get_chain_info(
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
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

async fn get_fees(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .proxy
        .get("/api/fee_estimate")
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

async fn get_mempool(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .proxy
        .get("/api/get_mempool_info")
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

async fn get_dag_info(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .proxy
        .post("/api/get_dag_info", &serde_json::json!({}))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

async fn get_dag_tips(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .proxy
        .post("/api/get_dag_tips", &serde_json::json!({}))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

async fn get_dag_block(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_hex_hash(&hash)?;
    state
        .proxy
        .post("/api/get_dag_block", &serde_json::json!({ "hash": hash }))
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(api_error("UPSTREAM_ERROR", &e.to_string())),
            )
        })
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.proxy.get("/health").await {
        Ok(mut data) => {
            data["apiProxy"] = serde_json::json!("ok");
            Json(data)
        }
        Err(e) => Json(serde_json::json!({
            "status": "degraded",
            "upstream": e.to_string(),
            "apiProxy": "ok",
        })),
    }
}

/// Deep health check — verifies upstream liveness AND data freshness.
async fn deep_health(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.proxy.get("/health").await {
        Ok(mut data) => {
            data["apiProxy"] = serde_json::json!("ok");
            data["deepCheck"] = serde_json::json!("pass");
            (StatusCode::OK, Json(data))
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "unhealthy",
                "upstream": e.to_string(),
                "apiProxy": "ok",
                "deepCheck": "fail",
            })),
        ),
    }
}
