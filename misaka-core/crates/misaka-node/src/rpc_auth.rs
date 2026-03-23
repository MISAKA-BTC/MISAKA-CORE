//! Shared RPC authentication middleware.
//!
//! Used by both v1 (`rpc_server.rs`) and DAG (`dag_rpc.rs`) RPC servers.
//!
//! ## Configuration
//!
//! - `MISAKA_RPC_API_KEY` env var: when set, write endpoints require
//!   `Authorization: Bearer <key>` header.
//! - When unset: all endpoints are open (suitable for testnet / local dev).
//! - Checkpoint vote gossip is intentionally handled as a separate,
//!   explicitly documented ingress because peers do not yet attach HTTP auth.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;

/// Cached API key loaded once at server startup.
#[derive(Clone)]
pub struct ApiKeyState {
    /// None = auth disabled (open access). Some = require Bearer token.
    pub required_key: Option<String>,
}

impl ApiKeyState {
    /// Load from environment. Returns auth-disabled state if env var is unset or empty.
    pub fn from_env() -> Self {
        Self {
            required_key: std::env::var("MISAKA_RPC_API_KEY")
                .ok()
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.required_key.is_some()
    }
}

/// Axum middleware: reject requests without valid Bearer token
/// when API key is configured.
///
/// Usage:
/// ```ignore
/// let auth = ApiKeyState::from_env();
/// let protected = Router::new()
///     .route("/api/submit_tx", post(handler))
///     .route_layer(axum::middleware::from_fn_with_state(auth, require_api_key));
/// ```
pub async fn require_api_key(
    axum::extract::State(auth): axum::extract::State<ApiKeyState>,
    req: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    if let Some(ref expected_key) = auth.required_key {
        let auth_header = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        match auth_header {
            Some(value) if value.starts_with("Bearer ") => {
                let token = &value[7..];
                // SEC-AUDIT-V5 HIGH-002: constant-time comparison prevents
                // timing side-channel that could leak the API key byte-by-byte.
                let token_bytes = token.as_bytes();
                let expected_bytes = expected_key.as_bytes();
                let length_match = token_bytes.len() == expected_bytes.len();
                let mut acc = 0u8;
                // Compare up to the shorter length to avoid indexing OOB,
                // but the length_match flag ensures we reject mismatches.
                let n = std::cmp::min(token_bytes.len(), expected_bytes.len());
                for i in 0..n {
                    acc |= token_bytes[i] ^ expected_bytes[i];
                }
                if !length_match || acc != 0 {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            _ => return Err(StatusCode::UNAUTHORIZED),
        }
    }
    Ok(next.run(req).await)
}
