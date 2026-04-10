//! Shared RPC authentication middleware.
//!
//! Used by both v1 (`rpc_server.rs`) and DAG (`dag_rpc.rs`) RPC servers.
//!
//! ## Configuration
//!
//! - `MISAKA_RPC_API_KEY` env var: when set, write endpoints require
//!   `Authorization: Bearer <key>` header.
//! - Production mode (`MISAKA_CHAIN_ID=1` or `MISAKA_RPC_AUTH_MODE=required`):
//!   the API key MUST be set. Server refuses to start otherwise.
//! - `MISAKA_RPC_WRITE_ALLOWLIST`: comma-separated IP allowlist for write
//!   endpoints. When set, write requests from non-listed IPs are rejected
//!   EVEN IF the Bearer token is valid.
//!
//! ## Security Model
//!
//! Write endpoints have two independent gates (both must pass):
//! 1. Bearer token authentication (API key match)
//! 2. IP allowlist (if configured)
//!
//! Read endpoints are public (no auth required).
//! /health is always public.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use std::net::IpAddr;

/// Cached API key + IP allowlist loaded once at server startup.
#[derive(Clone)]
pub struct ApiKeyState {
    /// None = auth disabled (open access). Some = require Bearer token.
    pub required_key: Option<String>,
    /// IP allowlist for write endpoints. Empty = no IP restriction.
    pub write_ip_allowlist: Vec<IpAddr>,
    /// Whether auth is mandatory (production mode).
    pub auth_required: bool,
}

/// Configuration error for auth setup.
#[derive(Debug, thiserror::Error)]
pub enum AuthConfigError {
    #[error(
        "FATAL: MISAKA_RPC_API_KEY must be set (auth is required by default). \
         Set the key or explicitly set MISAKA_RPC_AUTH_MODE=open for local development."
    )]
    ApiKeyRequiredInProduction,
    #[error(
        "FATAL: MISAKA_RPC_AUTH_MODE=open is forbidden on mainnet (chain_id=1). \
         Remove AUTH_MODE=open from your configuration or use a non-mainnet chain_id."
    )]
    OpenModeForbiddenOnMainnet,
    #[error("FATAL: MISAKA_RPC_WRITE_ALLOWLIST contains invalid IP '{ip}': {reason}")]
    InvalidAllowlistIp { ip: String, reason: String },
}

impl ApiKeyState {
    /// Load from environment with production safety checks.
    ///
    /// Returns `Err(AuthConfigError)` if production mode requires auth
    /// but the API key is not set. Never panics.
    pub fn from_env_checked(chain_id: u32) -> Result<Self, AuthConfigError> {
        let required_key = std::env::var("MISAKA_RPC_API_KEY")
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());

        // Determine if auth is mandatory.
        // Default: REQUIRED (fail-closed). Only explicitly setting "open" disables auth.
        // This prevents accidental auth-free exposure on testnet or forked chains.
        let auth_mode = std::env::var("MISAKA_RPC_AUTH_MODE")
            .unwrap_or_default()
            .to_lowercase();

        // Mainnet MUST NOT run with AUTH_MODE=open — even if explicitly set.
        // This prevents operator misconfiguration from exposing submit_tx/faucet.
        if chain_id == 1 && auth_mode == "open" {
            return Err(AuthConfigError::OpenModeForbiddenOnMainnet);
        }

        // SEC-FIX v0.5.7: write surface defaults to fail-closed on every
        // chain. Previously testnet was opt-in: write routes were
        // accepted with no auth unless `MISAKA_RPC_AUTH_MODE=required` was
        // explicitly set. Combined with the (also v0.5.7) move of
        // `submit_tx` / `bridge/submit_mint` onto the shared
        // `require_api_key` middleware, this means a default-config
        // testnet operator who does NOT set `MISAKA_RPC_API_KEY` and does
        // NOT set `MISAKA_RPC_AUTH_MODE=open` now gets a hard startup
        // failure rather than a silently wide-open faucet/submit_tx.
        //
        // Decision matrix:
        //   chain_id == 1                              → required
        //   chain_id != 1 && auth_mode == "open"       → optional
        //   chain_id != 1 && auth_mode == ""           → required (NEW)
        //   chain_id != 1 && anything_else             → required
        //
        // The bundled launcher still exports `MISAKA_RPC_AUTH_MODE=open`
        // so the demo / self-host UX is preserved. Production operators
        // who remove that line get the fail-closed default.
        let auth_required = if chain_id == 1 {
            true // mainnet always requires auth
        } else {
            auth_mode != "open"
        };

        // Fail-closed: production without API key is a fatal error
        if auth_required && required_key.is_none() {
            return Err(AuthConfigError::ApiKeyRequiredInProduction);
        }

        // Parse IP allowlist
        let write_ip_allowlist = match std::env::var("MISAKA_RPC_WRITE_ALLOWLIST") {
            Ok(list) => {
                let mut ips = Vec::new();
                for entry in list.split(',') {
                    let trimmed = entry.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let ip: IpAddr =
                        trimmed
                            .parse()
                            .map_err(|e| AuthConfigError::InvalidAllowlistIp {
                                ip: trimmed.to_string(),
                                reason: format!("{}", e),
                            })?;
                    ips.push(ip);
                }
                ips
            }
            Err(_) => Vec::new(),
        };

        Ok(Self {
            required_key,
            write_ip_allowlist,
            auth_required,
        })
    }

    /// Legacy constructor for backward compatibility (no chain_id check).
    /// Use `from_env_checked()` for production.
    #[deprecated(
        note = "Use from_env_checked(chain_id) instead — from_env bypasses mainnet safety checks"
    )]
    pub fn from_env() -> Self {
        Self::from_env_checked(0).unwrap_or_else(|_| Self {
            required_key: std::env::var("MISAKA_RPC_API_KEY")
                .ok()
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty()),
            write_ip_allowlist: Vec::new(),
            auth_required: false,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.required_key.is_some()
    }

    /// Check if an IP is allowed for write operations.
    fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        if self.write_ip_allowlist.is_empty() {
            return true; // No allowlist = all IPs allowed (backward compat)
        }
        self.write_ip_allowlist.contains(ip)
    }
}

/// Axum middleware: reject requests without valid Bearer token
/// when API key is configured, AND enforce IP allowlist for write endpoints.
///
/// # Security Layers
///
/// 1. **Bearer Token**: constant-time comparison to prevent timing side-channel
/// 2. **IP Allowlist**: checked via ConnectInfo<SocketAddr>
///
/// Both must pass for write requests. Read requests skip auth entirely.
pub async fn require_api_key(
    axum::extract::State(auth): axum::extract::State<ApiKeyState>,
    req: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    // ── IP Allowlist Check (for write endpoints) ──
    if !auth.write_ip_allowlist.is_empty() {
        if let Some(connect_info) = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        {
            let client_ip = connect_info.0.ip();
            if !auth.is_ip_allowed(&client_ip) {
                tracing::warn!("RPC write rejected: IP {} not in allowlist", client_ip);
                return Err(StatusCode::FORBIDDEN);
            }
        } else {
            // SEC-FIX [Audit #5]: fail-closed. If ConnectInfo is missing,
            // we CANNOT determine the client IP, so we MUST reject.
            // This prevents allowlist bypass if the server binding changes.
            tracing::error!(
                "RPC write rejected: ConnectInfo unavailable — \
                 cannot verify IP allowlist (fail-closed)"
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // ── Bearer Token Check ──
    if let Some(ref expected_key) = auth.required_key {
        let auth_header = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        match auth_header {
            Some(value) if value.starts_with("Bearer ") => {
                let token = &value[7..];
                // Phase 38: Fixed timing side-channel (R8 HIGH #1).
                // Previous impl leaked expected_key length via loop iteration count.
                // New impl: hash both sides to fixed length, then constant-time compare.
                // This eliminates both length leakage and byte-by-byte timing.
                use sha3::{Digest, Sha3_256};
                let token_hash = Sha3_256::digest(token.as_bytes());
                let expected_hash = Sha3_256::digest(expected_key.as_bytes());
                let mut acc = 0u8;
                for i in 0..32 {
                    acc |= token_hash[i] ^ expected_hash[i];
                }
                if acc != 0 {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            _ => return Err(StatusCode::UNAUTHORIZED),
        }
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::post, Router};
    use tower::util::ServiceExt;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::env_lock()
    }

    #[test]
    fn test_production_requires_api_key() {
        let _guard = env_lock();
        std::env::remove_var("MISAKA_RPC_API_KEY");
        std::env::remove_var("MISAKA_RPC_AUTH_MODE");
        let result = ApiKeyState::from_env_checked(1); // mainnet chain_id
        assert!(result.is_err());
    }

    #[test]
    fn test_production_with_key_succeeds() {
        let _guard = env_lock();
        std::env::set_var("MISAKA_RPC_API_KEY", "test-key-123");
        let result = ApiKeyState::from_env_checked(1);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(state.is_enabled());
        assert!(state.auth_required);
        std::env::remove_var("MISAKA_RPC_API_KEY");
    }

    #[test]
    fn test_dev_open_mode_without_key_succeeds() {
        // SEC-FIX v0.5.7: testnet now defaults to fail-closed. To run a
        // testnet node without an API key (the bundled launcher path),
        // operators must explicitly opt in via `MISAKA_RPC_AUTH_MODE=open`.
        // This test checks that explicit-open mode still works as a no-auth
        // dev path.
        let _guard = env_lock();
        std::env::remove_var("MISAKA_RPC_API_KEY");
        std::env::set_var("MISAKA_RPC_AUTH_MODE", "open");
        let result = ApiKeyState::from_env_checked(2); // testnet
        assert!(
            result.is_ok(),
            "explicit open mode on testnet should succeed"
        );
        let state = result.unwrap();
        assert!(!state.is_enabled());
        assert!(!state.auth_required);
        std::env::remove_var("MISAKA_RPC_AUTH_MODE");
    }

    #[test]
    fn test_dev_without_key_or_mode_now_fails_closed() {
        // SEC-FIX v0.5.7: previously this returned Ok with auth_required=false,
        // making testnet write surfaces wide open by default. Now it errors.
        let _guard = env_lock();
        std::env::remove_var("MISAKA_RPC_API_KEY");
        std::env::remove_var("MISAKA_RPC_AUTH_MODE");
        let result = ApiKeyState::from_env_checked(2);
        assert!(
            matches!(result, Err(AuthConfigError::ApiKeyRequiredInProduction)),
            "testnet without API key and without AUTH_MODE=open must fail-closed"
        );
    }

    #[test]
    fn test_auth_mode_required_forces_key() {
        let _guard = env_lock();
        std::env::remove_var("MISAKA_RPC_API_KEY");
        std::env::set_var("MISAKA_RPC_AUTH_MODE", "required");
        let result = ApiKeyState::from_env_checked(2); // testnet but forced
        assert!(result.is_err());
        std::env::remove_var("MISAKA_RPC_AUTH_MODE");
    }

    #[test]
    fn test_ip_allowlist_parsed() {
        let _guard = env_lock();
        std::env::set_var("MISAKA_RPC_API_KEY", "key");
        std::env::set_var("MISAKA_RPC_WRITE_ALLOWLIST", "127.0.0.1, 10.0.0.1");
        let state = ApiKeyState::from_env_checked(2).unwrap();
        assert_eq!(state.write_ip_allowlist.len(), 2);
        assert!(state.is_ip_allowed(&"127.0.0.1".parse().unwrap()));
        assert!(state.is_ip_allowed(&"10.0.0.1".parse().unwrap()));
        assert!(!state.is_ip_allowed(&"1.2.3.4".parse().unwrap()));
        std::env::remove_var("MISAKA_RPC_API_KEY");
        std::env::remove_var("MISAKA_RPC_WRITE_ALLOWLIST");
    }

    #[test]
    fn test_invalid_ip_allowlist_entry_fails_closed() {
        let _guard = env_lock();
        std::env::set_var("MISAKA_RPC_API_KEY", "key");
        std::env::set_var("MISAKA_RPC_WRITE_ALLOWLIST", "127.0.0.1, not-an-ip");

        let err = match ApiKeyState::from_env_checked(2) {
            Ok(_) => panic!("invalid IP must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, AuthConfigError::InvalidAllowlistIp { .. }));

        std::env::remove_var("MISAKA_RPC_API_KEY");
        std::env::remove_var("MISAKA_RPC_WRITE_ALLOWLIST");
    }

    #[test]
    fn test_empty_allowlist_allows_all() {
        let state = ApiKeyState {
            required_key: Some("key".into()),
            write_ip_allowlist: vec![],
            auth_required: false,
        };
        assert!(state.is_ip_allowed(&"1.2.3.4".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_require_api_key_fail_closed_without_connect_info_when_allowlist_enabled() {
        let auth = ApiKeyState {
            required_key: Some("key".into()),
            write_ip_allowlist: vec!["127.0.0.1".parse().expect("loopback ip")],
            auth_required: false,
        };
        let app = Router::new()
            .route("/write", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(auth, require_api_key));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .header(axum::http::header::AUTHORIZATION, "Bearer key")
                    .body(Body::empty())
                    .expect("test request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_require_api_key_rejects_disallowed_ip_even_with_valid_bearer() {
        let auth = ApiKeyState {
            required_key: Some("key".into()),
            write_ip_allowlist: vec!["127.0.0.1".parse().expect("loopback ip")],
            auth_required: false,
        };
        let app = Router::new()
            .route("/write", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(auth, require_api_key));

        let mut request = Request::builder()
            .method("POST")
            .uri("/write")
            .header(axum::http::header::AUTHORIZATION, "Bearer key")
            .body(Body::empty())
            .expect("test request");
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "10.0.0.9:1234"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr"),
        ));

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_require_api_key_accepts_allowed_ip_with_valid_bearer() {
        let auth = ApiKeyState {
            required_key: Some("key".into()),
            write_ip_allowlist: vec!["127.0.0.1".parse().expect("loopback ip")],
            auth_required: false,
        };
        let app = Router::new()
            .route("/write", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(auth, require_api_key));

        let mut request = Request::builder()
            .method("POST")
            .uri("/write")
            .header(axum::http::header::AUTHORIZATION, "Bearer key")
            .body(Body::empty())
            .expect("test request");
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:5555"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr"),
        ));

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_require_api_key_rejects_invalid_bearer_from_allowed_ip() {
        let auth = ApiKeyState {
            required_key: Some("key".into()),
            write_ip_allowlist: vec!["127.0.0.1".parse().expect("loopback ip")],
            auth_required: false,
        };
        let app = Router::new()
            .route("/write", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(auth, require_api_key));

        let mut request = Request::builder()
            .method("POST")
            .uri("/write")
            .header(axum::http::header::AUTHORIZATION, "Bearer wrong-key")
            .body(Body::empty())
            .expect("test request");
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:5555"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr"),
        ));

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
