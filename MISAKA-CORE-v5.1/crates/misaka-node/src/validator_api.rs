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
use tokio::sync::RwLock;

use misaka_consensus::staking::{
    SlashSeverity, StakingConfig, StakingRegistry, ValidatorAccount, ValidatorState,
};

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
    Router::new()
        .route("/register", post(handle_register))
        .route("/activate", post(handle_activate))
        .route("/exit", post(handle_exit))
        .route("/unlock", post(handle_unlock))
        .route("/", get(handle_list_all))
        .route("/active", get(handle_active_set))
        .route("/:id", get(handle_get_validator))
        .route("/:id/status", get(handle_get_status))
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
        Json(Self { success: true, data: Some(data), error: None })
    }
    fn err(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (StatusCode::BAD_REQUEST, Json(Self { success: false, data: None, error: Some(msg.into()) }))
    }
}

// ═══════════════════════════════════════════════════════════════
//  Handlers
// ═══════════════════════════════════════════════════════════════

fn parse_hex_id(hex_str: &str) -> Result<[u8; 20], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!("validator_id must be 20 bytes (got {})", bytes.len()));
    }
    let mut id = [0u8; 20];
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

    let stake: u64 = req.stake_amount.parse()
        .map_err(|e| ApiResult::err(format!("invalid stake_amount: {}", e)))?;

    let reward_addr_bytes = hex::decode(&req.reward_address)
        .map_err(|e| ApiResult::err(format!("invalid reward_address hex: {}", e)))?;
    if reward_addr_bytes.len() != 20 {
        return Err(ApiResult::err("reward_address must be 20 bytes"));
    }
    let mut reward_address = [0u8; 20];
    reward_address.copy_from_slice(&reward_addr_bytes);

    let commission_bps = (req.commission_rate * 10_000.0) as u32;

    // Derive validator_id from pubkey
    let validator_id = {
        use sha3::{Digest, Sha3_256};
        let hash = Sha3_256::digest(&pubkey_bytes);
        let mut id = [0u8; 20];
        id.copy_from_slice(&hash[..20]);
        id
    };

    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    // Derive stake_tx_hash from pubkey + epoch (placeholder — real impl uses UTXO ref)
    let stake_tx_hash = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:stake_lock:");
        h.update(&pubkey_bytes);
        h.update(epoch.to_le_bytes());
        let r: [u8; 32] = h.finalize().into();
        r
    };

    registry.register(
        validator_id,
        pubkey_bytes,
        stake,
        commission_bps,
        reward_address,
        epoch,
        stake_tx_hash,
        0,
    ).map_err(|e| ApiResult::err(e.to_string()))?;

    let config = registry.config().clone();
    let account = registry.get(&validator_id).unwrap();
    Ok(ApiResult::ok(ValidatorResponse::from_account(account, &config)))
}

/// POST /api/v1/validators/activate
async fn handle_activate(
    State(state): State<ValidatorApiState>,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<ApiResult<ValidatorResponse>>, (StatusCode, Json<ApiResult<ValidatorResponse>>)> {
    let id = parse_hex_id(&req.validator_id).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    registry.activate(&id, epoch).map_err(|e| ApiResult::err(e.to_string()))?;

    let config = registry.config().clone();
    let account = registry.get(&id).unwrap();
    Ok(ApiResult::ok(ValidatorResponse::from_account(account, &config)))
}

/// POST /api/v1/validators/exit
async fn handle_exit(
    State(state): State<ValidatorApiState>,
    Json(req): Json<ExitRequest>,
) -> Result<Json<ApiResult<ValidatorResponse>>, (StatusCode, Json<ApiResult<ValidatorResponse>>)> {
    let id = parse_hex_id(&req.validator_id).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    registry.exit(&id, epoch).map_err(|e| ApiResult::err(e.to_string()))?;

    let config = registry.config().clone();
    let account = registry.get(&id).unwrap();
    Ok(ApiResult::ok(ValidatorResponse::from_account(account, &config)))
}

/// POST /api/v1/validators/unlock
async fn handle_unlock(
    State(state): State<ValidatorApiState>,
    Json(req): Json<UnlockRequest>,
) -> Result<Json<ApiResult<serde_json::Value>>, (StatusCode, Json<ApiResult<serde_json::Value>>)> {
    let id = parse_hex_id(&req.validator_id).map_err(ApiResult::err)?;
    let epoch = *state.current_epoch.read().await;
    let mut registry = state.registry.write().await;

    let amount = registry.unlock(&id, epoch).map_err(|e| ApiResult::err(e.to_string()))?;

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
        validators: active_set.iter()
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

    let account = registry.get(&id)
        .ok_or_else(|| ApiResult::err("validator not found"))?;

    Ok(ApiResult::ok(ValidatorResponse::from_account(account, &config)))
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

    let account = registry.get(&id)
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
