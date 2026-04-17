//! Validator governance routes — forward to misaka-node RPC.
//!
//! These paths exist on the node at `127.0.0.1:3001` but must be exposed
//! through `misaka-api` for operators who only have the public API port.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/register_validator", post(register_validator))
        .route("/api/deregister_validator", post(deregister_validator))
        .route("/api/get_committee", get(get_committee))
}

async fn register_validator(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !body.is_object() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": { "code": "INVALID_BODY", "message": "request body must be a JSON object" }
            })),
        ));
    }
    state
        .proxy
        .post("/api/register_validator", &body)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

async fn deregister_validator(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !body.is_object() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": { "code": "INVALID_BODY", "message": "request body must be a JSON object" }
            })),
        ));
    }
    state
        .proxy
        .post("/api/deregister_validator", &body)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

async fn get_committee(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    state
        .proxy
        .get("/api/get_committee")
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}
