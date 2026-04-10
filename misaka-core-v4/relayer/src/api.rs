//! HTTP API for the Burn & Mint bridge relayer.
//!
//! Endpoints:
//! - POST /api/burn/register-address -- register MISAKA receive address for a wallet
//! - POST /api/burn/submit-tx -- submit a Solana burn tx signature for processing
//! - GET  /api/burn/status/:signature -- get processing status
//! - GET  /api/admin/claims -- list all claims (admin auth required)
//!
//! Phase 3 C3: Migrated from hand-rolled TCP server to axum.
//! Default bind: 127.0.0.1 (not 0.0.0.0). Override via API_BIND_ADDRESS env.

use crate::burn_verifier::BurnVerifier;
use crate::config::RelayerConfig;
use crate::store::BurnRequestStore;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Shared state for the API server.
pub struct ApiState {
    pub store: Arc<BurnRequestStore>,
    pub verifier: Arc<BurnVerifier>,
    pub config: RelayerConfig,
}

/// Start the HTTP API server. Runs forever.
pub async fn run_api_server(state: Arc<ApiState>) {
    let app = Router::new()
        .route("/api/burn/register-address", post(handle_register_address))
        .route("/api/burn/submit-tx", post(handle_submit_tx))
        .route("/api/burn/status/{signature}", get(handle_get_status))
        .route("/api/admin/claims", get(handle_admin_claims))
        .with_state(state.clone());

    // Default bind to 127.0.0.1 (not 0.0.0.0). Override via API_BIND_ADDRESS env.
    let bind_host = std::env::var("API_BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", bind_host, state.config.api_port);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            info!("API server listening on {}", addr);
            l
        }
        Err(e) => {
            error!("Failed to bind API server to {}: {}", addr, e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("API server error: {}", e);
    }
}

/// POST /api/burn/register-address
///
/// Body: { "wallet_address": "...", "misaka_receive_address": "..." }
async fn handle_register_address(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let wallet = match body.get("wallet_address").and_then(|v| v.as_str()) {
        Some(w) if !w.is_empty() => w,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing wallet_address"})),
            );
        }
    };

    let misaka_addr = match body.get("misaka_receive_address").and_then(|v| v.as_str()) {
        Some(a) if !a.is_empty() => a,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing misaka_receive_address"})),
            );
        }
    };

    // SEC-FIX: Use proper address validation with checksum.
    // Previously checked "msk1" prefix which is not a valid MISAKA prefix.
    if misaka_types::address::validate_format(misaka_addr).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid misaka_receive_address format"})),
        );
    }

    match state.store.register_address(wallet, misaka_addr) {
        Ok(()) => {
            let _ = state.store.audit_log(
                "address_registered",
                None,
                &format!("wallet={} misaka={}", wallet, misaka_addr),
            );
            info!("Address registered: {} -> {}", wallet, misaka_addr);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "registered",
                    "wallet_address": wallet,
                    "misaka_receive_address": misaka_addr,
                })),
            )
        }
        Err(e) => {
            error!("Failed to register address: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            )
        }
    }
}

/// POST /api/burn/submit-tx
///
/// Body: { "solana_tx_signature": "..." }
async fn handle_submit_tx(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let tx_sig = match body.get("solana_tx_signature").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing solana_tx_signature"})),
            );
        }
    };

    // SEC-FIX: wallet_address is now mandatory to prevent any-wallet burn claims.
    let wallet_address = match body.get("wallet_address").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing wallet_address"})),
            );
        }
    };

    // Check if already submitted
    match state.store.get_burn_by_signature(&tx_sig) {
        Ok(Some(existing)) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "already_submitted",
                    "id": existing.id,
                    "burn_status": existing.status,
                })),
            );
        }
        Ok(None) => {}
        Err(e) => {
            error!("Store error checking signature: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            );
        }
    }

    // Verify the burn on-chain
    let verified = match state.verifier.verify_burn_tx(&tx_sig, &wallet_address).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Burn verification failed for {}: {}", tx_sig, e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "burn verification failed",
                    "detail": e.to_string(),
                })),
            );
        }
    };

    // Check address registration
    let misaka_addr = match state.store.get_registered_address(&verified.wallet) {
        Ok(Some(addr)) => addr,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "no MISAKA receive address registered for this wallet",
                    "wallet_address": verified.wallet,
                })),
            );
        }
        Err(e) => {
            error!("Store error looking up address: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            );
        }
    };

    // Compute burn event ID
    let event_id = {
        let mut h = Sha3_256::new();
        h.update(tx_sig.as_bytes());
        h.update(&(verified.burn_index as u64).to_le_bytes());
        hex::encode(h.finalize())
    };

    // Insert into store
    match state.store.insert_burn_request(
        &event_id,
        &verified.wallet,
        &misaka_addr,
        &verified.mint,
        verified.amount,
        &tx_sig,
        verified.slot,
        verified.block_time,
        "verified",
    ) {
        Ok(true) => {
            let _ = state.store.audit_log(
                "burn_submitted_via_api",
                Some(&event_id),
                &format!(
                    "tx={} amount={} wallet={}",
                    tx_sig, verified.amount, verified.wallet
                ),
            );
            info!(
                "Burn submitted via API: id={} tx={} amount={}",
                &event_id[..16],
                &tx_sig[..16.min(tx_sig.len())],
                verified.amount
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "accepted",
                    "id": event_id,
                    "amount": verified.amount,
                    "wallet_address": verified.wallet,
                    "misaka_receive_address": misaka_addr,
                })),
            )
        }
        Ok(false) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "already_submitted",
                "id": event_id,
            })),
        ),
        Err(e) => {
            error!("Failed to insert burn request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            )
        }
    }
}

/// GET /api/burn/status/:signature
async fn handle_get_status(
    State(state): State<Arc<ApiState>>,
    Path(signature): Path<String>,
) -> impl IntoResponse {
    match state.store.get_burn_by_signature(&signature) {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": row.id,
                "solana_tx_signature": row.solana_tx_signature,
                "wallet_address": row.wallet_address,
                "misaka_receive_address": row.misaka_receive_address,
                "mint_address": row.mint_address,
                "burn_amount_raw": row.burn_amount_raw,
                "slot": row.slot,
                "block_time": row.block_time,
                "status": row.status,
                "error_message": row.error_message,
                "attempt_count": row.attempt_count,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "burn request not found"})),
        ),
        Err(e) => {
            error!("Store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            )
        }
    }
}

/// GET /api/admin/claims
///
/// Requires admin auth via Authorization header (constant-time comparison from C1).
async fn handle_admin_claims(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Phase 3 C1: constant-time comparison to prevent timing side-channel
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // SEC-FIX CRITICAL: Hash-then-compare to prevent length leakage.
    // Previously, early return on length mismatch leaked the expected token length
    // via timing side-channel, aiding brute-force of the admin secret.
    let expected = format!("Bearer {}", state.config.admin_secret);
    let auth_ok = {
        use sha3::{Digest, Sha3_256};
        use subtle::ConstantTimeEq;
        let token_hash = Sha3_256::digest(auth_header.as_bytes());
        let expected_hash = Sha3_256::digest(expected.as_bytes());
        token_hash.ct_eq(&expected_hash).into()
    };

    if !auth_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        );
    }

    match state.store.get_all_burn_requests() {
        Ok(rows) => {
            let claims: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "solana_tx_signature": r.solana_tx_signature,
                        "wallet_address": r.wallet_address,
                        "misaka_receive_address": r.misaka_receive_address,
                        "mint_address": r.mint_address,
                        "burn_amount_raw": r.burn_amount_raw,
                        "slot": r.slot,
                        "status": r.status,
                        "error_message": r.error_message,
                        "attempt_count": r.attempt_count,
                        "created_at": r.created_at,
                        "updated_at": r.updated_at,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "claims": claims, "total": claims.len() })),
            )
        }
        Err(e) => {
            error!("Store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            )
        }
    }
}
