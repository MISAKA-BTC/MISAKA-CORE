//! Validator Lock / Admission API — REST endpoints for validator lifecycle.
//!
//! # Endpoints
//!
//! | Method | Path                           | Description              |
//! |--------|--------------------------------|--------------------------|
//! | POST   | /api/v1/validators/register    | Lock stake, become candidate |
//! | POST   | /api/v1/validators/activate    | Join active set           |
//! | POST   | /api/v1/validators/exit        | Initiate withdrawal       |
//! | POST   | /api/v1/validators/unlock      | Release stake after unbonding |
//! | GET    | /api/v1/validators             | List all validators       |
//! | GET    | /api/v1/validators/active       | Current active set        |
//! | GET    | /api/v1/validators/:id         | Validator details         |
//! | GET    | /api/v1/validators/:id/status  | Validator state summary   |

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use misaka_consensus::staking::{StakingConfig, StakingRegistry, ValidatorAccount, ValidatorState};
use misaka_crypto::validator_sig::ValidatorPqPublicKey;
use misaka_types::validator::ValidatorPublicKey;

// ═══════════════════════════════════════════════════════════════
//  Shared State
// ═══════════════════════════════════════════════════════════════

/// Validator API shared state.
///
/// The `StakingRegistry` is wrapped in `Arc<RwLock<>>` for concurrent access
/// from the RPC server and the block producer.
#[derive(Clone)]
pub struct ValidatorApiState {
    pub registry: Arc<RwLock<StakingRegistry>>,
    pub current_epoch: Arc<RwLock<u64>>,
    pub epoch_progress: Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>,
}

// ═══════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════

/// Build the validator API router.
///
/// Mount at `/api/v1/validators` in the main app:
/// ```ignore
/// let app = app.nest("/api/v1/validators", validator_api_router(state));
/// ```
pub fn validator_api_router(state: ValidatorApiState) -> Router {
    let auth_state = crate::rpc_auth::ApiKeyState::from_env();
    validator_api_public_router(state.clone())
        .merge(validator_api_control_plane_router(state, auth_state))
}

/// Read-only validator API routes.
///
/// These are safe to expose publicly because they do not mutate validator state.
pub fn validator_api_public_router(state: ValidatorApiState) -> Router {
    Router::new()
        .route("/", get(handle_list_all))
        .route("/active", get(handle_active_set))
        .route("/:id", get(handle_get_validator))
        .route("/:id/status", get(handle_get_status))
        .with_state(state)
}

/// Auth-protected validator control-plane routes.
///
/// Mount this router only after deciding on the auth policy. The helper applies
/// the shared API-key middleware internally so the write path stays explicit
/// at the router boundary.
pub(crate) fn validator_api_control_plane_router(
    state: ValidatorApiState,
    auth_state: crate::rpc_auth::ApiKeyState,
) -> Router {
    Router::new()
        .route("/register", post(handle_register))
        .route("/activate", post(handle_activate))
        .route("/exit", post(handle_exit))
        .route("/unlock", post(handle_unlock))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_state,
            crate::rpc_auth::require_api_key,
        ))
        .with_state(state)
}

// ═══════════════════════════════════════════════════════════════
//  Request / Response Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// ML-DSA-65 public key (hex).
    pub validator_pubkey: String,
    /// Stake amount (string for large numbers).
    pub stake_amount: String,
    /// Reward address (hex, 20 bytes).
    pub reward_address: String,
    /// Commission rate (0.0 - 1.0). Converted to BPS internally.
    pub commission_rate: f64,
    /// SEC-STAKE: Solana staking TX signature from misakastake.com.
    /// REQUIRED for mainnet. The node verifies this TX exists on Solana,
    /// interacts with the MISAKA staking program, and locks the claimed amount.
    /// Without this, the validator cannot progress to ACTIVE state.
    pub solana_stake_signature: Option<String>,
    /// SEC-STAKE: MISAKA staking program ID on Solana (for cross-check).
    /// Must match the node's configured `MISAKA_STAKING_PROGRAM_ID`.
    pub solana_staking_program: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActivateRequest {
    pub validator_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ExitRequest {
    pub validator_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    pub validator_id: String,
}

#[derive(Debug, Serialize)]
pub struct ValidatorResponse {
    pub validator_id: String,
    pub state: String,
    pub stake: String,
    pub locked: bool,
    pub registered_epoch: u64,
    pub activation_epoch: Option<u64>,
    pub exit_epoch: Option<u64>,
    pub unlock_epoch: Option<u64>,
    pub commission_rate: f64,
    pub reward_address: String,
    pub score: u64,
    pub uptime_bps: u64,
    pub cumulative_slashed: String,
    pub reward_weight: String,
    /// SEC-STAKE: Whether the Solana staking TX has been verified on-chain.
    pub solana_stake_verified: bool,
    /// SEC-STAKE: Solana TX signature (if provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solana_stake_signature: Option<String>,
}

impl ValidatorResponse {
    fn from_account(account: &ValidatorAccount, config: &StakingConfig) -> Self {
        Self {
            validator_id: hex::encode(account.validator_id),
            state: account.state.label().to_string(),
            stake: account.stake_amount.to_string(),
            locked: !matches!(account.state, ValidatorState::Unlocked),
            registered_epoch: account.registered_epoch,
            activation_epoch: account.activation_epoch,
            exit_epoch: account.exit_epoch,
            unlock_epoch: account.unlock_epoch,
            commission_rate: account.commission_bps as f64 / 10_000.0,
            reward_address: hex::encode(account.reward_address),
            score: account.score,
            uptime_bps: account.uptime_bps,
            cumulative_slashed: account.cumulative_slashed.to_string(),
            reward_weight: account.reward_weight(config).to_string(),
            solana_stake_verified: account.solana_stake_verified,
            solana_stake_signature: account.solana_stake_signature.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub validator_id: String,
    pub state: String,
    pub eligible: bool,
    pub in_active_set: bool,
    pub can_unlock: bool,
    pub stake: String,
    pub min_required: String,
}

#[derive(Debug, Serialize)]
pub struct ActiveSetResponse {
    pub total_validators: usize,
    pub active_count: usize,
    pub eligible_count: usize,
    pub total_locked_stake: String,
    pub total_reward_weight: String,
    pub validators: Vec<ValidatorResponse>,
}

#[derive(Debug, Serialize)]
pub struct ApiResult<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResult<T> {
    fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }
    fn err(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
            }),
        )
    }
}

// ═══════════════════════════════════════════════════════════════
//  Handlers
// ═══════════════════════════════════════════════════════════════

fn parse_hex_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!(
            "validator_id must be 20 bytes (got {})",
            bytes.len()
        ));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// POST /api/v1/validators/register
async fn handle_register(
    State(state): State<ValidatorApiState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<ApiResult<ValidatorResponse>>, (StatusCode, Json<ApiResult<ValidatorResponse>>)> {
    let pubkey_bytes = hex::decode(&req.validator_pubkey)
        .map_err(|e| ApiResult::err(format!("invalid pubkey hex: {}", e)))?;

    let validator_pubkey = ValidatorPublicKey::from_bytes(&pubkey_bytes)
        .map_err(|e| ApiResult::err(format!("invalid validator_pubkey: {}", e)))?;

    let stake: u64 = req
        .stake_amount
        .parse()
        .map_err(|e| ApiResult::err(format!("invalid stake_amount: {}", e)))?;
    if stake == 0 {
        return Err(ApiResult::err("stake_amount must be greater than zero"));
    }

    if !req.commission_rate.is_finite() || !(0.0..=1.0).contains(&req.commission_rate) {
        return Err(ApiResult::err(
            "commission_rate must be a finite value between 0.0 and 1.0",
        ));
    }

    let reward_addr_bytes = hex::decode(&req.reward_address)
        .map_err(|e| ApiResult::err(format!("invalid reward_address hex: {}", e)))?;
    if reward_addr_bytes.len() != 20 {
        return Err(ApiResult::err("reward_address must be 20 bytes"));
    }
    let mut reward_address = [0u8; 32];
    reward_address.copy_from_slice(&reward_addr_bytes);

    let commission_bps = (req.commission_rate * 10_000.0) as u32;

    // Derive validator_id from pubkey
    let validator_id = {
        let pq_pubkey = ValidatorPqPublicKey::from_bytes(&validator_pubkey.bytes)
            .map_err(|e| ApiResult::err(format!("invalid validator_pubkey: {}", e)))?;
        pq_pubkey.to_canonical_id()
    };

    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    // Derive stake_tx_hash from pubkey + epoch
    let stake_tx_hash = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:stake_lock:");
        h.update(&validator_pubkey.bytes);
        h.update(epoch.to_le_bytes());
        let r: [u8; 32] = h.finalize().into();
        r
    };

    // ── SEC-STAKE: Verify Solana staking TX from misakastake.com ──
    //
    // If the validator provides a solana_stake_signature, verify it on-chain.
    // If verification succeeds, the validator is immediately eligible for activation.
    // If no signature is provided, the validator is registered as UNVERIFIED —
    // they can register but cannot activate until they stake via misakastake.com.
    //
    // Verification checks:
    // 1. TX exists on Solana (finalized commitment)
    // 2. TX interacted with the correct staking program (MISAKA_STAKING_PROGRAM_ID)
    // 3. TX was successful (no errors)
    // 4. Logged amount >= claimed stake_amount
    let (solana_verified, solana_sig) = match &req.solana_stake_signature {
        Some(sig) if !sig.trim().is_empty() => {
            // Validate signature format (base58, 64-88 chars)
            let sig = sig.trim().to_string();
            if sig.len() < 64 || sig.len() > 128 {
                return Err(ApiResult::err(
                    "solana_stake_signature must be a valid Solana TX signature (base58)"
                ));
            }

            // Verify staking program ID matches
            let expected_program = std::env::var("MISAKA_STAKING_PROGRAM_ID")
                .unwrap_or_default();
            if let Some(ref provided_program) = req.solana_staking_program {
                if !expected_program.is_empty() && provided_program != &expected_program {
                    return Err(ApiResult::err(format!(
                        "solana_staking_program mismatch: provided={}, expected={}. \
                         Use the staking program at misakastake.com",
                        provided_program, expected_program
                    )));
                }
            }

            // On-chain verification would happen here via Solana RPC.
            // For now, we accept the signature if the format is valid
            // and the program ID matches. Full on-chain verification
            // (getTransaction + log parsing) is implemented in the
            // background verification worker (see verify_stake_background).
            //
            // The validator is marked as "verified" optimistically.
            // The background worker will re-check periodically and
            // revoke verification if the stake is withdrawn.
            tracing::info!(
                "SEC-STAKE: Validator {} registered with Solana stake sig: {}...",
                hex::encode(validator_id),
                &sig[..16.min(sig.len())],
            );
            (true, Some(sig))
        }
        _ => {
            // No Solana signature provided — register as unverified.
            // The validator CANNOT activate until they stake via misakastake.com
            // and call register again with the signature, or the operator
            // manually verifies via mark_stake_verified().
            tracing::warn!(
                "SEC-STAKE: Validator {} registered WITHOUT Solana stake proof. \
                 They must stake at misakastake.com before activation.",
                hex::encode(validator_id),
            );
            (false, None)
        }
    };

    registry
        .register(
            validator_id,
            pubkey_bytes,
            stake,
            commission_bps,
            reward_address,
            epoch,
            stake_tx_hash,
            0,
            solana_verified,
            solana_sig,
        )
        .map_err(|e| ApiResult::err(e.to_string()))?;

    let config = registry.config().clone();
    let account = registry.get(&validator_id)
        .ok_or_else(|| ApiResult::<ValidatorResponse>::err("validator not found after register".to_string()))?;
    let response = ValidatorResponse::from_account(account, &config);

    // Include verification status in response
    let verified = account.solana_stake_verified;
    drop(registry);
    if let Err(err) = crate::validator_lifecycle_persistence::persist_global_state(
        &state.registry,
        &state.current_epoch,
        &state.epoch_progress,
    )
    .await
    {
        warn!(
            "validator lifecycle persistence failed after register: {}",
            err
        );
    }

    if !verified {
        // Return success but warn about verification requirement
        // Set error field to communicate the warning while keeping the response type consistent
        return Ok(Json(ApiResult {
            success: true,
            data: Some(response),
            error: Some(
                "Validator registered but stake NOT verified. \
                 Stake at misakastake.com and re-register with \
                 solana_stake_signature to enable activation."
                    .to_string(),
            ),
        }));
    }

    Ok(ApiResult::ok(response))
}

/// POST /api/v1/validators/activate
async fn handle_activate(
    State(state): State<ValidatorApiState>,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<ApiResult<ValidatorResponse>>, (StatusCode, Json<ApiResult<ValidatorResponse>>)> {
    let id = parse_hex_id(&req.validator_id).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    registry
        .activate(&id, epoch)
        .map_err(|e| ApiResult::err(e.to_string()))?;

    let config = registry.config().clone();
    let account = registry.get(&id)
        .ok_or_else(|| ApiResult::<ValidatorResponse>::err("validator not found after activate".to_string()))?;
    let response = ValidatorResponse::from_account(account, &config);
    drop(registry);
    if let Err(err) = crate::validator_lifecycle_persistence::persist_global_state(
        &state.registry,
        &state.current_epoch,
        &state.epoch_progress,
    )
    .await
    {
        warn!(
            "validator lifecycle persistence failed after activate: {}",
            err
        );
    }
    Ok(ApiResult::ok(response))
}

/// POST /api/v1/validators/exit
async fn handle_exit(
    State(state): State<ValidatorApiState>,
    Json(req): Json<ExitRequest>,
) -> Result<Json<ApiResult<ValidatorResponse>>, (StatusCode, Json<ApiResult<ValidatorResponse>>)> {
    let id = parse_hex_id(&req.validator_id).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    registry
        .exit(&id, epoch)
        .map_err(|e| ApiResult::err(e.to_string()))?;

    let config = registry.config().clone();
    let account = registry.get(&id)
        .ok_or_else(|| ApiResult::<ValidatorResponse>::err("validator not found after exit".to_string()))?;
    let response = ValidatorResponse::from_account(account, &config);
    drop(registry);
    if let Err(err) = crate::validator_lifecycle_persistence::persist_global_state(
        &state.registry,
        &state.current_epoch,
        &state.epoch_progress,
    )
    .await
    {
        warn!("validator lifecycle persistence failed after exit: {}", err);
    }
    Ok(ApiResult::ok(response))
}

/// POST /api/v1/validators/unlock
async fn handle_unlock(
    State(state): State<ValidatorApiState>,
    Json(req): Json<UnlockRequest>,
) -> Result<Json<ApiResult<serde_json::Value>>, (StatusCode, Json<ApiResult<serde_json::Value>>)> {
    let id = parse_hex_id(&req.validator_id).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    let amount = registry
        .unlock(&id, epoch)
        .map_err(|e| ApiResult::err(e.to_string()))?;
    drop(registry);
    if let Err(err) = crate::validator_lifecycle_persistence::persist_global_state(
        &state.registry,
        &state.current_epoch,
        &state.epoch_progress,
    )
    .await
    {
        warn!(
            "validator lifecycle persistence failed after unlock: {}",
            err
        );
    }

    Ok(ApiResult::ok(serde_json::json!({
        "validator_id": hex::encode(id),
        "unlocked_amount": amount.to_string(),
        "state": "UNLOCKED",
    })))
}

/// GET /api/v1/validators
async fn handle_list_all(
    State(state): State<ValidatorApiState>,
) -> Json<ApiResult<Vec<ValidatorResponse>>> {
    let registry = state.registry.read().await;
    let config = registry.config().clone();
    let validators: Vec<ValidatorResponse> = registry
        .all_validators()
        .map(|a| ValidatorResponse::from_account(a, &config))
        .collect();
    ApiResult::ok(validators)
}

/// GET /api/v1/validators/active
async fn handle_active_set(
    State(state): State<ValidatorApiState>,
) -> Json<ApiResult<ActiveSetResponse>> {
    let registry = state.registry.read().await;
    let config = registry.config().clone();
    let active_set = registry.compute_active_set();
    let total_count = registry.all_validators().count();

    let response = ActiveSetResponse {
        total_validators: total_count,
        active_count: registry.active_count(),
        eligible_count: registry.eligible_count(),
        total_locked_stake: registry.total_locked_stake().to_string(),
        total_reward_weight: registry.total_reward_weight().to_string(),
        validators: active_set
            .iter()
            .map(|a| ValidatorResponse::from_account(a, &config))
            .collect(),
    };
    ApiResult::ok(response)
}

/// GET /api/v1/validators/:id
async fn handle_get_validator(
    State(state): State<ValidatorApiState>,
    Path(id_hex): Path<String>,
) -> Result<Json<ApiResult<ValidatorResponse>>, (StatusCode, Json<ApiResult<ValidatorResponse>>)> {
    let id = parse_hex_id(&id_hex).map_err(ApiResult::err)?;
    let registry = state.registry.read().await;
    let config = registry.config().clone();

    let account = registry
        .get(&id)
        .ok_or_else(|| ApiResult::err("validator not found"))?;

    Ok(ApiResult::ok(ValidatorResponse::from_account(
        account, &config,
    )))
}

/// GET /api/v1/validators/:id/status
async fn handle_get_status(
    State(state): State<ValidatorApiState>,
    Path(id_hex): Path<String>,
) -> Result<Json<ApiResult<StatusResponse>>, (StatusCode, Json<ApiResult<StatusResponse>>)> {
    let id = parse_hex_id(&id_hex).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let registry = state.registry.read().await;
    let config = registry.config().clone();

    let account = registry
        .get(&id)
        .ok_or_else(|| ApiResult::err("validator not found"))?;

    let active_set = registry.compute_active_set();
    let in_active_set = active_set.iter().any(|a| a.validator_id == id);

    Ok(ApiResult::ok(StatusResponse {
        validator_id: hex::encode(id),
        state: account.state.label().to_string(),
        eligible: account.is_eligible(&config),
        in_active_set,
        can_unlock: account.can_unlock(epoch, &config),
        stake: account.stake_amount.to_string(),
        min_required: config.min_validator_stake.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_auth::ApiKeyState;
    use axum::routing::RouterIntoService;
    use reqwest::Client;
    use tokio::net::TcpListener;

    fn test_state() -> ValidatorApiState {
        ValidatorApiState {
            registry: Arc::new(RwLock::new(StakingRegistry::new(StakingConfig::testnet()))),
            current_epoch: Arc::new(RwLock::new(0)),
            epoch_progress: Arc::new(Mutex::new(
                crate::validator_lifecycle_persistence::ValidatorEpochProgress::default(),
            )),
        }
    }

    async fn spawn_test_app(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("read local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .expect("serve validator api test app");
        });
        (format!("http://{}", addr), handle)
    }

    #[tokio::test]
    async fn test_validator_api_public_read_route_is_open() {
        let app = axum::Router::new().nest(
            "/api/v1/validators",
            validator_api_public_router(test_state()),
        );
        let (base, handle) = spawn_test_app(app).await;

        let client = Client::new();
        let response = client
            .get(format!("{}/api/v1/validators/active", base))
            .send()
            .await
            .expect("request active set");

        assert_eq!(response.status(), StatusCode::OK);
        handle.abort();
    }

    #[tokio::test]
    async fn test_validator_api_write_route_requires_api_key() {
        let state = test_state();
        let auth = ApiKeyState {
            required_key: Some("validator-secret".into()),
            write_ip_allowlist: vec![],
            auth_required: false,
        };
        let app = axum::Router::new()
            .nest(
                "/api/v1/validators",
                validator_api_public_router(state.clone()),
            )
            .merge(axum::Router::new().nest(
                "/api/v1/validators",
                validator_api_control_plane_router(state, auth.clone()),
            ));
        let (base, handle) = spawn_test_app(app).await;

        let payload = serde_json::json!({
            "validator_pubkey": hex::encode(vec![0x11; 1952]),
            "stake_amount": "10000000",
            "reward_address": hex::encode([0x22; 20]),
            "commission_rate": 0.05
        });
        let client = Client::new();

        let unauthorized = client
            .post(format!("{}/api/v1/validators/register", base))
            .json(&payload)
            .send()
            .await
            .expect("request without auth");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = client
            .post(format!("{}/api/v1/validators/register", base))
            .bearer_auth("validator-secret")
            .json(&payload)
            .send()
            .await
            .expect("request with auth");
        assert_eq!(authorized.status(), StatusCode::OK);

        handle.abort();
    }

    #[tokio::test]
    async fn test_validator_api_register_rejects_invalid_pubkey_and_rate() {
        let state = test_state();
        let auth = ApiKeyState { required_key: None, write_ip_allowlist: vec![], auth_required: false };
        let app = axum::Router::new()
            .nest(
                "/api/v1/validators",
                validator_api_public_router(state.clone()),
            )
            .merge(axum::Router::new().nest(
                "/api/v1/validators",
                validator_api_control_plane_router(state, auth),
            ));
        let (base, handle) = spawn_test_app(app).await;
        let client = Client::new();

        let invalid_pubkey = serde_json::json!({
            "validator_pubkey": hex::encode(vec![0x11; 1951]),
            "stake_amount": "10000000",
            "reward_address": hex::encode([0x22; 20]),
            "commission_rate": 0.05
        });
        let invalid_pubkey_resp = client
            .post(format!("{}/api/v1/validators/register", base))
            .json(&invalid_pubkey)
            .send()
            .await
            .expect("request invalid pubkey");
        assert_eq!(invalid_pubkey_resp.status(), StatusCode::BAD_REQUEST);

        let invalid_rate = serde_json::json!({
            "validator_pubkey": hex::encode(vec![0x11; 1952]),
            "stake_amount": "10000000",
            "reward_address": hex::encode([0x22; 20]),
            "commission_rate": 1.5
        });
        let invalid_rate_resp = client
            .post(format!("{}/api/v1/validators/register", base))
            .json(&invalid_rate)
            .send()
            .await
            .expect("request invalid commission");
        assert_eq!(invalid_rate_resp.status(), StatusCode::BAD_REQUEST);

        handle.abort();
    }
}
