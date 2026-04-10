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
            Json(api_error(
                "INVALID_BODY",
                "request body must be a JSON object",
            )),
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
                "error": crate::proxy::public_upstream_error(&e)["error"].clone(),
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
                Json(crate::proxy::public_upstream_error(&e)),
            )
        })
}

// SEC-FIX: faucet() handler removed — all faucet traffic goes through
// the hardened queue in faucet.rs (/api/v1/faucet/request).

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        response::IntoResponse,
        routing::post,
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
        AppState { proxy, faucet }
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("test: body bytes");
        serde_json::from_slice(&bytes).expect("test: json")
    }

    #[tokio::test]
    async fn test_submit_tx_sanitizes_upstream_failure() {
        let upstream = Router::new().route(
            "/api/submit_tx",
            post(|| async {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "panic at /internal/path with http://127.0.0.1:3001/private",
                )
                    .into_response()
            }),
        );
        let app = router().with_state(test_state(upstream).await);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tx":"deadbeef"}"#))
                    .expect("test: request"),
            )
            .await
            .expect("test: response");

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = response_json(resp).await;
        assert_eq!(body["accepted"], serde_json::json!(false));
        assert_eq!(
            body["error"]["code"],
            serde_json::json!("UPSTREAM_BAD_RESPONSE")
        );
        let body_text = body.to_string();
        assert!(!body_text.contains("/internal/path"));
        assert!(!body_text.contains("127.0.0.1:3001/private"));
    }

    #[tokio::test]
    async fn test_get_tx_rejects_invalid_hash() {
        let app = router().with_state(
            test_state(Router::new().route("/api/get_tx_by_hash", post(|| async { "{}" }))).await,
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/tx/not-a-hash")
                    .body(Body::empty())
                    .expect("test: request"),
            )
            .await
            .expect("test: response");

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_json(resp).await;
        assert_eq!(body["error"]["code"], serde_json::json!("INVALID_HASH"));
    }
}
