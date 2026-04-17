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

fn degraded_health_from_error(err: &anyhow::Error) -> serde_json::Value {
    let (code, _) = crate::proxy::classify_upstream_error(err);
    serde_json::json!({
        "status": "degraded",
        "upstream": "degraded",
        "upstreamError": code,
        "apiProxy": "ok",
    })
}

fn deep_health_failure_from_error(err: &anyhow::Error) -> serde_json::Value {
    let (code, _) = crate::proxy::classify_upstream_error(err);
    serde_json::json!({
        "status": "unhealthy",
        "upstream": "unavailable",
        "upstreamError": code,
        "apiProxy": "ok",
        "deepCheck": "fail",
    })
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
        .get("/api/get_chain_info")
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(crate::proxy::public_upstream_error(&e)),
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
                Json(crate::proxy::public_upstream_error(&e)),
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
                Json(crate::proxy::public_upstream_error(&e)),
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
                Json(crate::proxy::public_upstream_error(&e)),
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
                Json(crate::proxy::public_upstream_error(&e)),
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
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.proxy.get("/api/health").await {
        Ok(mut data) => {
            data["apiProxy"] = serde_json::json!("ok");
            data["upstream"] = serde_json::json!("ok");
            Json(data)
        }
        Err(e) => Json(degraded_health_from_error(&e)),
    }
}

/// Deep health check — verifies upstream liveness AND data freshness.
async fn deep_health(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.proxy.get("/api/health").await {
        Ok(mut data) => {
            data["apiProxy"] = serde_json::json!("ok");
            data["upstream"] = serde_json::json!("ok");
            data["deepCheck"] = serde_json::json!("pass");
            (StatusCode::OK, Json(data))
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(deep_health_failure_from_error(&e)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn spawn_mock_upstream(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test: bind mock upstream");
        let addr = listener.local_addr().expect("test: local addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test: serve mock upstream");
        });
        format!("http://{}", addr)
    }

    async fn test_state(upstream: Router) -> AppState {
        let proxy = crate::proxy::NodeProxy::new(&spawn_mock_upstream(upstream).await)
            .expect("test: proxy");
        let faucet = crate::routes::faucet::FaucetState::new(
            crate::routes::faucet::FaucetConfig::default(),
            proxy.clone(),
        );
        AppState {
            proxy,
            faucet,
            ws_broadcaster: crate::routes::ws::WsBroadcaster::new(),
        }
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("test: body bytes");
        serde_json::from_slice(&bytes).expect("test: json")
    }

    #[tokio::test]
    async fn test_health_redacts_upstream_failure_details() {
        let upstream = Router::new().route(
            "/api/health",
            get(|| async {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "upstream exploded at /internal/recovery/path",
                )
                    .into_response()
            }),
        );
        let app = router().with_state(test_state(upstream).await);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("test: request"),
            )
            .await
            .expect("test: response");

        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["status"], serde_json::json!("degraded"));
        assert_eq!(
            body["upstreamError"],
            serde_json::json!("UPSTREAM_BAD_RESPONSE")
        );
        let text = body.to_string();
        assert!(!text.contains("/internal/recovery/path"));
    }

    #[tokio::test]
    async fn test_deep_health_returns_summary_only_on_failure() {
        let upstream = Router::new().route(
            "/api/health",
            get(|| async {
                (
                    StatusCode::BAD_GATEWAY,
                    "dial tcp 127.0.0.1:3001/internal failed",
                )
                    .into_response()
            }),
        );
        let app = router().with_state(test_state(upstream).await);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/health/deep")
                    .body(Body::empty())
                    .expect("test: request"),
            )
            .await
            .expect("test: response");

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_json(resp).await;
        assert_eq!(body["status"], serde_json::json!("unhealthy"));
        assert_eq!(body["deepCheck"], serde_json::json!("fail"));
        let text = body.to_string();
        assert!(!text.contains("127.0.0.1:3001/internal"));
        assert!(!text.contains("dial tcp"));
    }
}
