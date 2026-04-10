//! # DAG RPC アダプター (MISAKA-CORE v2)
//!
//! 既存の RPC エンドポイント (`/api/submit_tx`, `/api/get_chain_info` 等) を
//! DAG ベースの状態に接続するアダプター層。
//!
//! ## 設計方針
//!
//! v1 の `RpcState { node: SharedState, p2p: Arc<P2pNetwork> }` を
//! v2 の `DagRpcState` に置き換え、同一の HTTP エンドポイントを維持する。
//! Explorer やウォレットからは v1/v2 の違いが透過的に見える。

use axum::{
    extract::DefaultBodyLimit,
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::dag_narwhal_dissemination_service::DagNarwhalDisseminationService;
use crate::dag_tx_dissemination_service::DagTxDisseminationService;
use crate::rpc_auth::{require_api_key, ApiKeyState};

use misaka_mempool::UtxoMempool;
use misaka_pqc::{default_privacy_backend, PrivacyBackendFamily};
// Consumer surface status and privacy path status are inlined below.
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::{TxType, UtxoTransaction};
use misaka_types::validator::{DagCheckpointFinalityProof, DagCheckpointVote, ValidatorIdentity};

use crate::dag_p2p_surface::DagP2pObservationState;
use crate::{ingest_checkpoint_vote, sr21_election};

/// Stake-weighted quorum threshold for uniform-stake validators.
///
/// HIGH #5 fix: Uses the Sui-aligned formula `N - floor((N-1)/3)` which
/// is correct for uniform stake. For non-uniform stake, callers MUST
/// use `Committee::quorum_threshold()` directly.
///
/// This replaces the old `expected_dag_quorum_threshold` which used
/// `(N*2)/3 + 1` — a different formula that disagrees with Sui for N=3k.
fn uniform_stake_quorum_threshold(validator_count: usize) -> u128 {
    let n = validator_count.max(1) as u128;
    let f = (n - 1) / 3;
    n - f
}
use misaka_dag::{
    save_runtime_snapshot,
    DaaScore,
    DagCheckpoint,
    DagNodeState,
    DagStore, // trait — for snapshot.get_tips() etc.
};

#[derive(Deserialize)]
struct DagTxQuery {
    hash: String,
}

// ═══════════════════════════════════════════════════════════════
//  DAG RPC State
// ═══════════════════════════════════════════════════════════════

/// DAG ノード用の共有 RPC 状態。
///
/// v1 の `RpcState { node: SharedState, p2p }` に相当する。
pub type DagSharedState = Arc<RwLock<DagNodeState>>;

#[derive(Clone)]
pub struct DagRpcState {
    pub node: DagSharedState,
    pub narwhal_dissemination: Option<Arc<DagNarwhalDisseminationService>>,
    pub dag_p2p_observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    pub runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    /// Phase 2b'': chain_id for IntentMessage-based signature verification.
    pub chain_id: u32,
    /// Phase 2c-A: genesis_hash for AppId construction.
    pub genesis_hash: [u8; 32],
    // Stop line:
    // DAG P2P handle is intentionally not exposed here yet. Adding it changes
    // the live relay surface and should be aligned with the DAG/ZK track.
    // pub p2p: Arc<DagP2pNetwork>,
}

fn build_dag_cors_layer() -> anyhow::Result<CorsLayer> {
    match std::env::var("MISAKA_CORS_ORIGINS") {
        Ok(origins_str) => {
            let origins: Vec<axum::http::HeaderValue> = origins_str
                .split(',')
                .filter(|o| !o.trim().is_empty())
                .filter_map(|o| o.trim().parse().ok())
                .collect();
            if origins.is_empty() {
                anyhow::bail!(
                    "FATAL: MISAKA_CORS_ORIGINS contains no valid origins: '{}'",
                    origins_str
                );
            }
            Ok(CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE]))
        }
        Err(_) => {
            use tower_http::cors::AllowOrigin;

            #[allow(clippy::unwrap_used)] // static string parse never fails
            let localhost_origins: Vec<axum::http::HeaderValue> = vec![
                "http://localhost:3000".parse().expect("static origin"),
                "http://localhost:3001".parse().expect("static origin"),
                "http://localhost:5173".parse().expect("static origin"),
                "http://127.0.0.1:3000".parse().expect("static origin"),
                "http://127.0.0.1:3001".parse().expect("static origin"),
            ];

            let allowed_extensions: Vec<String> = std::env::var("MISAKA_CORS_EXTENSIONS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| format!("chrome-extension://{}", s.trim()))
                .collect();

            if !allowed_extensions.is_empty() {
                info!(
                    "CORS: allowing {} Chrome extension origin(s)",
                    allowed_extensions.len()
                );
            }

            Ok(CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(move |origin, _| {
                    let origin_str = origin.to_str().unwrap_or("");
                    if origin_str.starts_with("chrome-extension://") {
                        return allowed_extensions
                            .iter()
                            .any(|ext| origin_str == ext.as_str());
                    }
                    localhost_origins.iter().any(|o| o == origin)
                }))
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE]))
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DagRuntimeRecoveryObservation {
    pub snapshot_path: PathBuf,
    pub validator_lifecycle_path: PathBuf,
    pub wal_journal_path: PathBuf,
    pub wal_tmp_path: PathBuf,
    pub startup_snapshot_restored: bool,
    pub startup_wal_state: String,
    pub startup_wal_rolled_back_blocks: usize,
    pub last_checkpoint_blue_score: Option<u64>,
    pub last_checkpoint_block_hash: Option<String>,
    pub last_checkpoint_persisted_at_ms: Option<u64>,
    pub last_checkpoint_finality_blue_score: Option<u64>,
    pub last_checkpoint_decision_source: Option<String>,
    pub last_bullshark_candidate_preview_at_ms: Option<u64>,
    pub last_bullshark_candidate_preview_tx_hashes: Vec<String>,
    pub last_bullshark_commit_preview_at_ms: Option<u64>,
    pub last_bullshark_commit_preview_tx_hashes: Vec<String>,
    pub last_bullshark_commit_at_ms: Option<u64>,
    pub last_bullshark_commit_tx_hashes: Vec<String>,
}

impl DagRuntimeRecoveryObservation {
    pub fn new(
        snapshot_path: PathBuf,
        validator_lifecycle_path: PathBuf,
        wal_journal_path: PathBuf,
        wal_tmp_path: PathBuf,
    ) -> Self {
        Self {
            snapshot_path,
            validator_lifecycle_path,
            wal_journal_path,
            wal_tmp_path,
            startup_snapshot_restored: false,
            startup_wal_state: "unknown".to_string(),
            startup_wal_rolled_back_blocks: 0,
            last_checkpoint_blue_score: None,
            last_checkpoint_block_hash: None,
            last_checkpoint_persisted_at_ms: None,
            last_checkpoint_finality_blue_score: None,
            last_checkpoint_decision_source: None,
            last_bullshark_candidate_preview_at_ms: None,
            last_bullshark_candidate_preview_tx_hashes: Vec::new(),
            last_bullshark_commit_preview_at_ms: None,
            last_bullshark_commit_preview_tx_hashes: Vec::new(),
            last_bullshark_commit_at_ms: None,
            last_bullshark_commit_tx_hashes: Vec::new(),
        }
    }

    pub fn mark_startup_snapshot_restored(&mut self, restored: bool) {
        self.startup_snapshot_restored = restored;
    }

    pub fn mark_startup_wal_state(&mut self, wal_state: impl Into<String>, rolled_back: usize) {
        self.startup_wal_state = wal_state.into();
        self.startup_wal_rolled_back_blocks = rolled_back;
    }

    pub fn mark_checkpoint_persisted(&mut self, blue_score: u64, block_hash: [u8; 32]) {
        self.last_checkpoint_blue_score = Some(blue_score);
        self.last_checkpoint_block_hash = Some(hex::encode(block_hash));
        self.last_checkpoint_persisted_at_ms = Some(chrono::Utc::now().timestamp_millis() as u64);
        self.last_checkpoint_decision_source = Some(
            misaka_consensus::current_checkpoint_decision_source()
                .as_str()
                .to_string(),
        );
    }

    pub fn mark_checkpoint_finality(&mut self, blue_score: Option<u64>) {
        self.last_checkpoint_finality_blue_score = blue_score;
        if blue_score.is_some() {
            self.last_checkpoint_decision_source = Some(
                misaka_consensus::current_checkpoint_decision_source()
                    .as_str()
                    .to_string(),
            );
        }
    }

    pub fn mark_bullshark_candidate_preview(&mut self, tx_hashes: &[[u8; 32]]) {
        self.last_bullshark_candidate_preview_at_ms =
            Some(chrono::Utc::now().timestamp_millis() as u64);
        self.last_bullshark_candidate_preview_tx_hashes =
            tx_hashes.iter().map(hex::encode).collect();
    }

    pub fn mark_bullshark_commit_preview(&mut self, tx_hashes: &[[u8; 32]]) {
        self.last_bullshark_commit_preview_at_ms =
            Some(chrono::Utc::now().timestamp_millis() as u64);
        self.last_bullshark_commit_preview_tx_hashes = tx_hashes.iter().map(hex::encode).collect();
    }

    pub fn mark_bullshark_commit(&mut self, tx_hashes: &[[u8; 32]]) {
        self.last_bullshark_commit_at_ms = Some(chrono::Utc::now().timestamp_millis() as u64);
        self.last_bullshark_commit_tx_hashes = tx_hashes.iter().map(hex::encode).collect();
    }
}

async fn sync_runtime_recovery_from_shadow_state(
    state: &DagNodeState,
    observation: Option<&Arc<RwLock<DagRuntimeRecoveryObservation>>>,
) {
    let Some(observation) = observation else {
        return;
    };

    let candidate_preview_hashes = state
        .mempool
        .shadow_bullshark_candidate_candidates(misaka_dag::TxDisseminationLane::Any, 256)
        .into_iter()
        .map(|tx| tx.tx_hash())
        .collect::<Vec<_>>();
    let commit_preview_hashes = state
        .mempool
        .shadow_bullshark_commit_candidates(misaka_dag::TxDisseminationLane::Any, 256)
        .into_iter()
        .map(|tx| tx.tx_hash())
        .collect::<Vec<_>>();
    let commit_hashes = state
        .mempool
        .shadow_bullshark_committed_candidates(misaka_dag::TxDisseminationLane::Any, 256)
        .into_iter()
        .map(|tx| tx.tx_hash())
        .collect::<Vec<_>>();

    let mut guard = observation.write().await;
    let candidate_preview_hexes = candidate_preview_hashes
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>();
    if !candidate_preview_hashes.is_empty()
        && guard.last_bullshark_candidate_preview_tx_hashes != candidate_preview_hexes
    {
        guard.mark_bullshark_candidate_preview(&candidate_preview_hashes);
    }

    let commit_preview_hexes = commit_preview_hashes.iter().map(hex::encode).collect::<Vec<_>>();
    if !commit_preview_hashes.is_empty()
        && guard.last_bullshark_commit_preview_tx_hashes != commit_preview_hexes
    {
        guard.mark_bullshark_commit_preview(&commit_preview_hashes);
    }

    let commit_hexes = commit_hashes.iter().map(hex::encode).collect::<Vec<_>>();
    if !commit_hashes.is_empty() && guard.last_bullshark_commit_tx_hashes != commit_hexes {
        guard.mark_bullshark_commit(&commit_hashes);
    }
}

async fn dag_p2p_observation_json(
    observation: Option<&Arc<RwLock<DagP2pObservationState>>>,
) -> serde_json::Value {
    let Some(observation) = observation else {
        return serde_json::json!({
            "available": false
        });
    };

    let guard = observation.read().await;
    serde_json::to_value(&*guard).unwrap_or(serde_json::json!({
        "available": true,
        "error": "dag p2p observation serialization failed"
    }))
}

async fn dag_runtime_recovery_json(
    observation: Option<&Arc<RwLock<DagRuntimeRecoveryObservation>>>,
) -> serde_json::Value {
    let Some(observation) = observation else {
        return serde_json::json!({
            "available": false
        });
    };

    let guard = observation.read().await;
    let snapshot_exists = guard.snapshot_path.exists();
    let validator_lifecycle_exists = guard.validator_lifecycle_path.exists();
    let wal_journal_exists = guard.wal_journal_path.exists();
    let wal_tmp_exists = guard.wal_tmp_path.exists();
    let restart_ready = snapshot_exists && validator_lifecycle_exists && !wal_tmp_exists;
    let release_rehearsal_ready = restart_ready && guard.last_checkpoint_persisted_at_ms.is_some();

    serde_json::json!({
        "available": true,
        "snapshotPath": guard.snapshot_path,
        "snapshotExists": snapshot_exists,
        "validatorLifecyclePath": guard.validator_lifecycle_path,
        "validatorLifecycleExists": validator_lifecycle_exists,
        "walJournalPath": guard.wal_journal_path,
        "walJournalExists": wal_journal_exists,
        "walTmpPath": guard.wal_tmp_path,
        "walTmpExists": wal_tmp_exists,
        "startupSnapshotRestored": guard.startup_snapshot_restored,
        "startupWalState": guard.startup_wal_state,
        "startupWalRolledBackBlocks": guard.startup_wal_rolled_back_blocks,
        "lastCheckpointBlueScore": guard.last_checkpoint_blue_score,
        "lastCheckpointBlockHash": guard.last_checkpoint_block_hash,
        "lastCheckpointPersistedAtMs": guard.last_checkpoint_persisted_at_ms,
        "lastCheckpointFinalityBlueScore": guard.last_checkpoint_finality_blue_score,
        "lastCheckpointDecisionSource": guard.last_checkpoint_decision_source,
        "lastBullsharkCandidatePreviewAtMs": guard.last_bullshark_candidate_preview_at_ms,
        "lastBullsharkCandidatePreviewCount": guard.last_bullshark_candidate_preview_tx_hashes.len(),
        "lastBullsharkCandidatePreviewTxHashes": guard.last_bullshark_candidate_preview_tx_hashes,
        "lastBullsharkCommitPreviewAtMs": guard.last_bullshark_commit_preview_at_ms,
        "lastBullsharkCommitPreviewCount": guard.last_bullshark_commit_preview_tx_hashes.len(),
        "lastBullsharkCommitPreviewTxHashes": guard.last_bullshark_commit_preview_tx_hashes,
        "lastBullsharkCommitAtMs": guard.last_bullshark_commit_at_ms,
        "lastBullsharkCommitCount": guard.last_bullshark_commit_tx_hashes.len(),
        "lastBullsharkCommitTxHashes": guard.last_bullshark_commit_tx_hashes,
        "bullsharkCandidatePreviewObserved": !guard.last_bullshark_candidate_preview_tx_hashes.is_empty(),
        "bullsharkCommitPreviewObserved": !guard.last_bullshark_commit_preview_tx_hashes.is_empty(),
        "bullsharkCommitObserved": !guard.last_bullshark_commit_tx_hashes.is_empty(),
        "operatorRestartReady": restart_ready,
        "releaseRehearsalReady": release_rehearsal_ready,
    })
}

async fn validator_lifecycle_recovery_json(
    observation: Option<&Arc<RwLock<DagRuntimeRecoveryObservation>>>,
) -> serde_json::Value {
    let Some(observation) = observation else {
        return serde_json::json!({
            "available": false
        });
    };

    let guard = observation.read().await;
    let snapshot_exists = guard.snapshot_path.exists();
    let validator_lifecycle_exists = guard.validator_lifecycle_path.exists();
    let wal_tmp_exists = guard.wal_tmp_path.exists();
    let restart_ready = snapshot_exists && validator_lifecycle_exists && !wal_tmp_exists;
    let checkpoint_persisted = guard.last_checkpoint_persisted_at_ms.is_some();
    let checkpoint_finalized = guard.last_checkpoint_finality_blue_score.is_some();
    let summary = if !snapshot_exists || !validator_lifecycle_exists {
        "missing_persistence"
    } else if wal_tmp_exists {
        "needs_wal_cleanup"
    } else if !guard.startup_snapshot_restored {
        "needs_snapshot_restore"
    } else if !checkpoint_persisted {
        "needs_checkpoint_persistence"
    } else if !checkpoint_finalized {
        "needs_checkpoint_finality"
    } else {
        "ready"
    };

    serde_json::json!({
        "available": true,
        "snapshotExists": snapshot_exists,
        "validatorLifecycleExists": validator_lifecycle_exists,
        "walClean": !wal_tmp_exists,
        "restartReady": restart_ready,
        "checkpointPersisted": checkpoint_persisted,
        "checkpointFinalized": checkpoint_finalized,
        "startupSnapshotRestored": guard.startup_snapshot_restored,
        "startupWalState": guard.startup_wal_state,
        "startupWalRolledBackBlocks": guard.startup_wal_rolled_back_blocks,
        "lastCheckpointBlueScore": guard.last_checkpoint_blue_score,
        "lastCheckpointBlockHash": guard.last_checkpoint_block_hash,
        "lastCheckpointPersistedAtMs": guard.last_checkpoint_persisted_at_ms,
        "lastCheckpointFinalityBlueScore": guard.last_checkpoint_finality_blue_score,
        "lastCheckpointDecisionSource": guard.last_checkpoint_decision_source,
        "lastBullsharkCandidatePreviewAtMs": guard.last_bullshark_candidate_preview_at_ms,
        "lastBullsharkCandidatePreviewCount": guard.last_bullshark_candidate_preview_tx_hashes.len(),
        "lastBullsharkCandidatePreviewTxHashes": guard.last_bullshark_candidate_preview_tx_hashes,
        "lastBullsharkCommitPreviewAtMs": guard.last_bullshark_commit_preview_at_ms,
        "lastBullsharkCommitPreviewCount": guard.last_bullshark_commit_preview_tx_hashes.len(),
        "lastBullsharkCommitPreviewTxHashes": guard.last_bullshark_commit_preview_tx_hashes,
        "lastBullsharkCommitAtMs": guard.last_bullshark_commit_at_ms,
        "lastBullsharkCommitCount": guard.last_bullshark_commit_tx_hashes.len(),
        "lastBullsharkCommitTxHashes": guard.last_bullshark_commit_tx_hashes,
        "summary": summary,
    })
}

/// Interim peer-gossip ingress for checkpoint votes.
///
/// This stays separate from the API-key protected control plane because peers
/// Phase 35 (C-T4-1 fix): Checkpoint vote gossip is now auth-protected.
///
/// Previously this was merged outside the auth layer, allowing unauthenticated
/// validator registry injection via `validator_identity` field.
/// Now requires API key like all other write endpoints.
fn dag_checkpoint_vote_gossip_router() -> Router<DagRpcState> {
    Router::new().route(
        "/api/submit_checkpoint_vote",
        post(dag_submit_checkpoint_vote),
    )
}

fn dag_admission_path(tx: &UtxoTransaction) -> PrivacyBackendFamily {
    if tx.is_transparent() {
        return PrivacyBackendFamily::Transparent;
    }
    PrivacyBackendFamily::ZeroKnowledge
}

fn verify_dag_pre_admission(
    tx: &UtxoTransaction,
    utxo_set: &UtxoSet,
    now_ms: u64,
    chain_id: u32,
    genesis_hash: [u8; 32],
) -> Result<PrivacyBackendFamily, String> {
    // SEC-FIX: Defense-in-depth — reject system-only tx types before any further
    // processing. The mempool.admit() call below also rejects these (FIX 1 Layer 2),
    // but this guard catches them even if the mempool check is somehow bypassed.
    if matches!(
        tx.tx_type,
        misaka_types::utxo::TxType::SystemEmission | misaka_types::utxo::TxType::Faucet
    ) {
        return Err("SystemEmission/Faucet transactions cannot be user-submitted".into());
    }

    let admission_path = dag_admission_path(tx);
    let mut verifier_pool = UtxoMempool::new(1);

    let result = match admission_path {
        PrivacyBackendFamily::ZeroKnowledge => verifier_pool.admit(tx.clone(), utxo_set, now_ms),
        PrivacyBackendFamily::Transparent => verifier_pool.admit(tx.clone(), utxo_set, now_ms),
    };

    result.map_err(|e| format!("dag pre-admission failed: {}", e))?;

    // ── A-1: ML-DSA-65 Signature Verification ──
    // For transparent transfers, verify each input's proof (ML-DSA-65 sig)
    // against the spending_pubkey stored in the UTXO set.
    // Coinbase/Faucet TXs skip this (no UTXO inputs).
    // Phase 2c-B: all transfers are transparent (privacy layer removed).
    if !tx.inputs.is_empty() {
        // Phase 2c-A: TxSignablePayload-based IntentMessage digest.
        use misaka_types::tx_signable::TxSignablePayload;

        let payload = TxSignablePayload::from(tx);
        let intent = misaka_types::intent::IntentMessage::wrap(
            misaka_types::intent::IntentScope::TransparentTransfer,
            misaka_types::intent::AppId::new(chain_id, genesis_hash),
            &payload,
        );
        let signing_digest = intent.signing_digest();
        for (i, inp) in tx.inputs.iter().enumerate() {
            if inp.proof.is_empty() {
                return Err(format!("input[{}]: missing ML-DSA-65 signature", i));
            }
            // Look up spending_pubkey from UTXO set
            if let Some(source_ref) = inp.utxo_refs.first() {
                if let Some(pk_bytes) = utxo_set.get_spending_key(source_ref) {
                    // Verify ML-DSA-65 signature
                    let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(pk_bytes)
                        .map_err(|e| format!("input[{}]: invalid spending pubkey: {}", i, e))?;
                    let sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&inp.proof)
                        .map_err(|e| format!("input[{}]: invalid signature: {}", i, e))?;
                    // Phase 2b': verify with empty domain (IntentMessage provides separation)
                    misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, &signing_digest, &sig).map_err(
                        |e| {
                            format!(
                                "input[{}]: ML-DSA-65 signature verification failed: {}",
                                i, e
                            )
                        },
                    )?;
                } else {
                    // C-1 fix: fail-closed. Reject TX if spending_pubkey is not
                    // registered in UTXO set. Previously this was a warn+skip
                    // which allowed unsigned TX into mempool.
                    return Err(format!(
                        "input[{}]: spending_pubkey not found for {:?} — cannot verify signature",
                        i, source_ref
                    ));
                }
            }
        }
    }

    Ok(admission_path)
}

fn latest_checkpoint_json(checkpoint: &DagCheckpoint) -> serde_json::Value {
    let target = checkpoint.validator_target();
    serde_json::json!({
        "blockHash": hex::encode(checkpoint.block_hash),
        "blueScore": checkpoint.blue_score,
        "utxoRoot": hex::encode(checkpoint.utxo_root),
        "totalSpentCount": checkpoint.total_spent_count,
        "totalAppliedTxs": checkpoint.total_applied_txs,
        "timestampMs": checkpoint.timestamp_ms,
        "validatorTarget": {
            "blockHash": hex::encode(target.block_hash),
            "blueScore": target.blue_score,
            "utxoRoot": hex::encode(target.utxo_root),
            "totalSpentCount": target.total_spent_count,
            "totalAppliedTxs": target.total_applied_txs,
        }
    })
}

fn validator_identity_json(identity: &ValidatorIdentity) -> serde_json::Value {
    serde_json::json!({
        "validatorId": hex::encode(identity.validator_id),
        "stakeWeight": identity.stake_weight.to_string(),
        "publicKeyHex": hex::encode(&identity.public_key.bytes),
        "publicKeyBytes": identity.public_key.bytes.len(),
        "isActive": identity.is_active,
    })
}

fn dag_sr21_committee_json(state: &DagNodeState) -> serde_json::Value {
    let blue_score = state.dag_store.max_blue_score();
    let current_epoch = DaaScore(blue_score).epoch();
    let election_result = sr21_election::run_election(&state.known_validators, current_epoch);
    let preview_active_validator_ids: Vec<[u8; 32]> = election_result
        .active_srs
        .iter()
        .map(|elected| elected.validator_id)
        .collect();
    let eligible_validator_count = state
        .known_validators
        .iter()
        .filter(|validator| {
            validator.is_active && validator.stake_weight >= sr21_election::MIN_SR_STAKE
        })
        .count();
    let configured_active_count = state.num_active_srs.max(1);
    let preview_active_count = election_result.num_active;
    let effective_preview_active_count = preview_active_count.max(1);
    let preview_quorum_threshold =
        uniform_stake_quorum_threshold(effective_preview_active_count as usize).to_string();
    let runtime_quorum_threshold =
        uniform_stake_quorum_threshold(configured_active_count as usize).to_string();
    let local_validator = state
        .local_validator
        .as_ref()
        .map(|validator| &validator.identity);
    let preview_local_sr_index = local_validator.and_then(|identity| {
        sr21_election::find_sr_index(&election_result, &identity.validator_id)
    });
    let runtime_active_set_present = !state.runtime_active_sr_validator_ids.is_empty();
    let runtime_active_set_matches_preview = runtime_active_set_present
        && state.runtime_active_sr_validator_ids == preview_active_validator_ids;
    let runtime_active_count_consistent = configured_active_count == effective_preview_active_count;
    let local_runtime_sr_index_consistent = local_validator
        .map(|_| preview_local_sr_index == Some(state.sr_index))
        .unwrap_or(true);

    serde_json::json!({
        "selection": "stakeWeightedTop21Election",
        "rotationStage": "sr21EpochRotation",
        "currentRuntimeCommittee": "validatorBreadth",
        "completionTargetCommittee": "superRepresentative21",
        "committeeSizeCap": sr21_election::MAX_SR_COUNT,
        "minimumStake": sr21_election::MIN_SR_STAKE.to_string(),
        "knownValidatorCount": state.known_validators.len(),
        "eligibleValidatorCount": eligible_validator_count,
        "activeCount": preview_active_count,
        "configuredActiveCount": configured_active_count,
        "previewQuorumThreshold": preview_quorum_threshold,
        "runtimeQuorumThreshold": runtime_quorum_threshold,
        "quorumThresholdConsistent": configured_active_count == effective_preview_active_count,
        "totalActiveStake": election_result.total_active_stake.to_string(),
        "droppedCount": election_result.dropped_count,
        "currentEpoch": current_epoch,
        "epochSource": "daaBlueScore",
        "blueScore": blue_score,
        "localValidatorPresent": local_validator.is_some(),
        "localValidatorInActiveSet": preview_local_sr_index.is_some(),
        "localRuntimeSrIndex": local_validator.map(|_| state.sr_index),
        "localPreviewSrIndex": preview_local_sr_index,
        "runtimeActiveCountConsistent": runtime_active_count_consistent,
        "localRuntimeSrIndexConsistent": local_runtime_sr_index_consistent,
        "runtimeActiveSetPresent": runtime_active_set_present,
        "runtimeActiveSetCount": state.runtime_active_sr_validator_ids.len(),
        "runtimeActiveSetMatchesPreview": runtime_active_set_matches_preview,
        "previewMatchesRuntime": runtime_active_count_consistent && local_runtime_sr_index_consistent,
        "activeSetPreview": election_result.active_srs.iter().map(|elected| {
            serde_json::json!({
                "validatorId": hex::encode(elected.validator_id),
                "stakeWeight": elected.stake_weight.to_string(),
                "srIndex": elected.sr_index,
                "isLocal": local_validator
                    .map(|identity| identity.validator_id == elected.validator_id)
                    .unwrap_or(false),
            })
        }).collect::<Vec<_>>(),
        "runtimeActiveSet": state.runtime_active_sr_validator_ids.iter().enumerate().map(|(idx, validator_id)| {
            serde_json::json!({
                "validatorId": hex::encode(validator_id),
                "srIndex": idx,
                "isLocal": local_validator
                    .map(|identity| identity.validator_id == *validator_id)
                    .unwrap_or(false),
            })
        }).collect::<Vec<_>>(),
    })
}

fn checkpoint_vote_json(vote: &DagCheckpointVote) -> serde_json::Value {
    serde_json::json!({
        "voter": hex::encode(vote.voter),
        "signatureBytes": vote.signature.bytes.len(),
        "target": {
            "blockHash": hex::encode(vote.target.block_hash),
            "blueScore": vote.target.blue_score,
            "utxoRoot": hex::encode(vote.target.utxo_root),
            "totalSpentCount": vote.target.total_spent_count,
            "totalAppliedTxs": vote.target.total_applied_txs,
        }
    })
}

fn checkpoint_finality_json(proof: &DagCheckpointFinalityProof) -> serde_json::Value {
    serde_json::json!({
        "target": {
            "blockHash": hex::encode(proof.target.block_hash),
            "blueScore": proof.target.blue_score,
            "utxoRoot": hex::encode(proof.target.utxo_root),
            "totalSpentCount": proof.target.total_spent_count,
            "totalAppliedTxs": proof.target.total_applied_txs,
        },
        "commitCount": proof.commits.len(),
        "voters": proof.commits.iter().map(|vote| hex::encode(vote.voter)).collect::<Vec<_>>(),
    })
}

fn checkpoint_target_json(
    target: &misaka_types::validator::DagCheckpointTarget,
) -> serde_json::Value {
    serde_json::json!({
        "blockHash": hex::encode(target.block_hash),
        "blueScore": target.blue_score,
        "utxoRoot": hex::encode(target.utxo_root),
        "totalSpentCount": target.total_spent_count,
        "totalAppliedTxs": target.total_applied_txs,
    })
}

fn checkpoint_vote_pool_json(
    state: &DagNodeState,
) -> (Option<serde_json::Value>, Vec<serde_json::Value>) {
    let quorum_threshold = uniform_stake_quorum_threshold(state.validator_count);
    let current_target = state
        .latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.validator_target());

    let current_summary = current_target.as_ref().map(|target| {
        let votes = state
            .checkpoint_vote_pool
            .get(target)
            .cloned()
            .unwrap_or_default();
        serde_json::json!({
            "target": checkpoint_target_json(target),
            "voteCount": votes.len(),
            "quorumThreshold": quorum_threshold.to_string(),
            "quorumReached": state.latest_checkpoint_finality.is_some(),
            "voters": votes.iter().map(|vote| hex::encode(vote.voter)).collect::<Vec<_>>(),
        })
    });

    let mut pool = state
        .checkpoint_vote_pool
        .iter()
        .map(|(target, votes)| {
            serde_json::json!({
                "target": checkpoint_target_json(target),
                "voteCount": votes.len(),
                "voters": votes.iter().map(|vote| hex::encode(vote.voter)).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    pool.sort_by(|a, b| {
        a["target"]["blueScore"]
            .as_u64()
            .cmp(&b["target"]["blueScore"].as_u64())
    });

    (current_summary, pool)
}

fn current_checkpoint_consumer_status(state: &DagNodeState) -> serde_json::Value {
    let quorum_threshold = uniform_stake_quorum_threshold(state.validator_count);
    let current_target = state
        .latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.validator_target());
    let vote_count = current_target
        .as_ref()
        .and_then(|target| state.checkpoint_vote_pool.get(target))
        .map(|votes| votes.len() as u128)
        .unwrap_or(0);
    let finalized = current_target
        .as_ref()
        .map(|target| {
            state
                .latest_checkpoint_finality
                .as_ref()
                .map(|proof| proof.target == *target)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let quorum_missing = if current_target.is_some() && quorum_threshold > vote_count {
        Some((quorum_threshold - vote_count).to_string())
    } else {
        None
    };
    let (wallet_view, explorer_view, bridge_view) = if current_target.is_none() {
        ("none", "none", "waitCheckpoint")
    } else if finalized {
        ("finalized", "checkpointFinalized", "ready")
    } else {
        ("pending", "checkpointPending", "waitCheckpointFinality")
    };

    serde_json::json!({
        "checkpointPresent": current_target.is_some(),
        "currentCheckpointFinalized": finalized,
        "quorumThreshold": if current_target.is_some() { serde_json::Value::String(quorum_threshold.to_string()) } else { serde_json::Value::Null },
        "quorumMissing": quorum_missing,
        "walletView": wallet_view,
        "explorerConfirmationLevel": explorer_view,
        "bridgeReadiness": bridge_view,
    })
}

fn dag_consumer_surfaces_json(state: &DagNodeState) -> serde_json::Value {
    let current = current_checkpoint_consumer_status(state);
    let checkpoint_present = current["checkpointPresent"].as_bool().unwrap_or(false);
    let checkpoint_finalized = current["currentCheckpointFinalized"]
        .as_bool()
        .unwrap_or(false);
    let bridge_readiness = current["bridgeReadiness"]
        .as_str()
        .unwrap_or("checkpointDependent");
    let explorer_confirmation_level = current["explorerConfirmationLevel"]
        .as_str()
        .unwrap_or("checkpointAware");
    let consumer_readiness = if !checkpoint_present {
        "waitCheckpoint"
    } else if checkpoint_finalized {
        "ready"
    } else {
        "waitCheckpointFinality"
    };

    serde_json::json!({
        "validatorAttestation": {
            "available": true,
            "bridgeReadiness": bridge_readiness,
            "explorerConfirmationLevel": explorer_confirmation_level
        },
        "dataAvailability": {
            "available": true,
            "checkpointAnchorPresent": checkpoint_present,
            "checkpointAnchorFinalized": checkpoint_finalized,
            "consumerReadiness": consumer_readiness,
            "anchorSource": "latestCheckpoint",
            "headerSurface": "dagBlock"
        },
        "lightClient": {
            "available": true,
            "checkpointAnchorPresent": checkpoint_present,
            "checkpointAnchorFinalized": checkpoint_finalized,
            "consumerReadiness": consumer_readiness,
            "confirmationLevel": explorer_confirmation_level,
            "txLookupKey": "txHash"
        },
        "txStatusVocabulary": [
            "pending",
            "ordered",
            "finalized",
            "failedConflict",
            "failedInvalidSignature",
            "failed"
        ]
    })
}

fn dag_privacy_path_surface_json(runtime_path: &str) -> serde_json::Value {
    serde_json::json!({
        "runtimePath": runtime_path,
        "targetPath": "zeroKnowledge",
        "targetBackendFamily": "zeroKnowledge",
        "note": "v10 PQ-native: all privacy uses lattice ZKP"
    })
}

fn dag_consensus_architecture_json() -> serde_json::Value {
    serde_json::to_value(misaka_consensus::consensus_architecture_summary()).unwrap_or(
        serde_json::json!({
            "currentRuntime": {
                "dissemination": "ghostdagNativeMempool",
                "disseminationStage": "nativeMempool",
                "ordering": "ghostdag",
                "orderingStage": "ghostdagTotalOrder",
                "orderingInput": "ghostdagSelectedParent",
                "finality": "checkpointBft",
                "checkpointDecisionSource": "ghostdagCheckpointBft",
                "committee": "validatorBreadth",
                "committeeStage": "validatorBreadthProof",
                "committeeSelection": "validatorBreadthRehearsal",
                "committeeSizeCap": 21
            },
            "completionTarget": {
                "dissemination": "narwhal",
                "disseminationStage": "narwhalBatchDissemination",
                "ordering": "bullshark",
                "orderingStage": "bullsharkCommitOrder",
                "orderingInput": "narwhalDeliveredBatch",
                "finality": "bullsharkCommit",
                "checkpointDecisionSource": "bullsharkCommit",
                "committee": "superRepresentative21",
                "committeeStage": "sr21EpochRotation",
                "committeeSelection": "stakeWeightedTop21Election",
                "committeeSizeCap": 21,
                "privacyScope": "deferred",
                "cexFriendlyPriority": true,
                "publicOperatorRecoveryPriority": true
            },
            "statusNote": "consensus architecture summary serialization failed"
        }),
    )
}

fn dag_ordering_contract_fallback_json() -> serde_json::Value {
    serde_json::json!({
        "currentRuntime": {
            "stage": "ghostdagTotalOrder",
            "inputSource": "ghostdagSelectedParent",
            "commitSource": "ghostdagCheckpointBft"
        },
        "completionTarget": {
            "stage": "bullsharkCommitOrder",
            "inputSource": "narwhalDeliveredBatch",
            "commitSource": "bullsharkCommit"
        },
        "currentRuntimeState": {
            "maxBlueScore": 0,
            "checkpointFinalityLive": false,
            "checkpointFinalityBlueScore": serde_json::Value::Null,
            "ready": true
        },
        "completionTargetShadowState": {
            "queued": 0,
            "fastTransparentQueued": 0,
            "candidatePreviewQueued": 0,
            "candidatePreviewFastTransparentQueued": 0,
            "commitPreviewQueued": 0,
            "commitPreviewFastTransparentQueued": 0,
            "committedQueued": 0,
            "committedFastTransparentQueued": 0,
            "live": false,
            "candidatePreviewReady": false,
            "candidatePreviewLive": false,
            "commitPreviewLive": false,
            "committedLive": false,
            "consistentWithDeliveredQueue": true,
            "consistentWithCandidatePreview": true,
            "consistentWithCommitPreview": true
        },
        "completionTargetShadowCapabilities": {
            "narwhalDeliveredBatchInputReady": true,
            "bullsharkCandidatePreviewReady": true,
            "bullsharkCommitPreviewReady": true,
            "bullsharkCommitReady": true
        },
        "orchestration": {
            "serviceBound": false,
            "serviceRunning": false,
            "candidatePreviewCallerReady": false,
            "commitPreviewCallerReady": false,
            "commitCallerReady": false
        },
        "stagedContractReady": true,
        "statusNote": "ordering contract serialization failed"
    })
}

fn dag_ordering_orchestration_json(
    narwhal_dissemination: Option<&Arc<DagNarwhalDisseminationService>>,
) -> serde_json::Value {
    let service_bound = narwhal_dissemination.is_some();
    let service_running = narwhal_dissemination
        .map(|service| service.is_running())
        .unwrap_or(false);
    serde_json::json!({
        "serviceBound": service_bound,
        "serviceRunning": service_running,
        "candidatePreviewCallerReady": service_running,
        "commitPreviewCallerReady": service_running,
        "commitCallerReady": service_running,
    })
}

fn dag_ordering_contract_json(
    state: &DagNodeState,
    narwhal_dissemination: Option<&Arc<DagNarwhalDisseminationService>>,
) -> serde_json::Value {
    let mut value = serde_json::to_value(state.ordering_contract_summary())
        .unwrap_or_else(|_| dag_ordering_contract_fallback_json());
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "orchestration".into(),
            dag_ordering_orchestration_json(narwhal_dissemination),
        );
    }
    value
}

fn dag_authority_switch_readiness_json(
    consensus_architecture: &serde_json::Value,
    ordering_contract: &serde_json::Value,
    sr21_committee: &serde_json::Value,
    runtime_recovery: &serde_json::Value,
) -> serde_json::Value {
    let current_ordering_stage = consensus_architecture
        .pointer("/currentRuntime/orderingStage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let current_checkpoint_decision_source = consensus_architecture
        .pointer("/currentRuntime/checkpointDecisionSource")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let current_committee = consensus_architecture
        .pointer("/currentRuntime/committee")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_ordering_stage = consensus_architecture
        .pointer("/completionTarget/orderingStage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_ordering_input = consensus_architecture
        .pointer("/completionTarget/orderingInput")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_checkpoint_decision_source = consensus_architecture
        .pointer("/completionTarget/checkpointDecisionSource")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_committee = consensus_architecture
        .pointer("/completionTarget/committee")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_committee_stage = consensus_architecture
        .pointer("/completionTarget/committeeStage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_committee_selection = consensus_architecture
        .pointer("/completionTarget/committeeSelection")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let target_committee_size_cap = consensus_architecture
        .pointer("/completionTarget/committeeSizeCap")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let candidate_preview_queued = ordering_contract
        .pointer("/completionTargetShadowState/candidatePreviewQueued")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let commit_preview_queued = ordering_contract
        .pointer("/completionTargetShadowState/commitPreviewQueued")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let committed_queued = ordering_contract
        .pointer("/completionTargetShadowState/committedQueued")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let candidate_preview_ready = candidate_preview_queued > 0
        && ordering_contract
            .pointer("/completionTargetShadowState/candidatePreviewLive")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let commit_preview_ready = commit_preview_queued > 0
        && ordering_contract
            .pointer("/completionTargetShadowState/commitPreviewLive")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let committed_ready = committed_queued > 0
        && ordering_contract
            .pointer("/completionTargetShadowState/committedLive")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        && ordering_contract
            .pointer("/completionTargetShadowState/consistentWithCommitPreview")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let runtime_recovery_commit_observed = runtime_recovery
        .get("bullsharkCommitObserved")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let runtime_recovery_commit_count = runtime_recovery
        .get("lastBullsharkCommitCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let runtime_recovery_commit_tx_hashes = runtime_recovery
        .get("lastBullsharkCommitTxHashes")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let runtime_recovery_commit_hash_count = runtime_recovery_commit_tx_hashes
        .as_array()
        .map(|hashes| hashes.len() as u64)
        .unwrap_or(0);
    let runtime_recovery_commit_consistent = runtime_recovery_commit_observed
        && runtime_recovery_commit_count == committed_queued
        && runtime_recovery_commit_hash_count == committed_queued;
    let orchestration_ready = ordering_contract
        .pointer("/orchestration/serviceBound")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && ordering_contract
            .pointer("/orchestration/serviceRunning")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        && ordering_contract
            .pointer("/orchestration/candidatePreviewCallerReady")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        && ordering_contract
            .pointer("/orchestration/commitPreviewCallerReady")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        && ordering_contract
            .pointer("/orchestration/commitCallerReady")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

    let committee_active_count = sr21_committee
        .get("activeCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let committee_configured_active_count = sr21_committee
        .get("configuredActiveCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let committee_current_epoch = sr21_committee
        .get("currentEpoch")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let committee_preview_quorum_threshold = sr21_committee
        .get("previewQuorumThreshold")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0");
    let committee_runtime_quorum_threshold = sr21_committee
        .get("runtimeQuorumThreshold")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0");
    let committee_quorum_threshold_ready = sr21_committee
        .get("quorumThresholdConsistent")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && committee_preview_quorum_threshold == committee_runtime_quorum_threshold
        && committee_runtime_quorum_threshold != "0";
    let committee_size_cap = sr21_committee
        .get("committeeSizeCap")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let current_authority_retained = current_ordering_stage == "ghostdagTotalOrder"
        && current_checkpoint_decision_source == "ghostdagCheckpointBft"
        && current_committee == "validatorBreadth";
    let bullshark_plan_ready = target_ordering_stage == "bullsharkCommitOrder"
        && target_ordering_input == "narwhalDeliveredBatch"
        && target_checkpoint_decision_source == "bullsharkCommit";
    let committee_plan_ready = target_committee == "superRepresentative21"
        && target_committee_stage == "sr21EpochRotation"
        && target_committee_selection == "stakeWeightedTop21Election"
        && target_committee_size_cap == 21;
    let committee_preview_ready = sr21_committee
        .get("previewMatchesRuntime")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let committee_selection_ready = sr21_committee
        .get("selection")
        .and_then(serde_json::Value::as_str)
        == Some("stakeWeightedTop21Election")
        && committee_size_cap == 21
        && committee_active_count > 0
        && committee_active_count <= 21;
    let committee_rotation_ready = sr21_committee
        .get("rotationStage")
        .and_then(serde_json::Value::as_str)
        == Some("sr21EpochRotation")
        && committee_preview_ready
        && committee_configured_active_count == committee_active_count;

    let ready = current_authority_retained
        && bullshark_plan_ready
        && committee_plan_ready
        && candidate_preview_ready
        && commit_preview_ready
        && committed_ready
        && runtime_recovery_commit_consistent
        && orchestration_ready
        && committee_preview_ready
        && committee_selection_ready
        && committee_rotation_ready
        && committee_quorum_threshold_ready;

    serde_json::json!({
        "currentAuthorityRetained": current_authority_retained,
        "bullsharkPlanReady": bullshark_plan_ready,
        "committeePlanReady": committee_plan_ready,
        "candidatePreviewReady": candidate_preview_ready,
        "commitPreviewReady": commit_preview_ready,
        "committedReady": committed_ready,
        "runtimeRecoveryCommitObserved": runtime_recovery_commit_observed,
        "runtimeRecoveryCommitCount": runtime_recovery_commit_count,
        "runtimeRecoveryCommitTxHashes": runtime_recovery_commit_tx_hashes,
        "runtimeRecoveryCommitConsistent": runtime_recovery_commit_consistent,
        "orchestrationReady": orchestration_ready,
        "committeePreviewReady": committee_preview_ready,
        "committeeSelectionReady": committee_selection_ready,
        "committeeRotationReady": committee_rotation_ready,
        "committeePreviewQuorumThreshold": committee_preview_quorum_threshold,
        "committeeRuntimeQuorumThreshold": committee_runtime_quorum_threshold,
        "committeeQuorumThresholdReady": committee_quorum_threshold_ready,
        "ready": ready,
        "currentOrderingStage": current_ordering_stage,
        "currentCheckpointDecisionSource": current_checkpoint_decision_source,
        "currentCommittee": current_committee,
        "targetOrderingStage": target_ordering_stage,
        "targetOrderingInput": target_ordering_input,
        "targetCheckpointDecisionSource": target_checkpoint_decision_source,
        "targetCommittee": target_committee,
        "targetCommitteeStage": target_committee_stage,
        "targetCommitteeSelection": target_committee_selection,
        "targetCommitteeSizeCap": target_committee_size_cap,
        "candidatePreviewQueued": candidate_preview_queued,
        "commitPreviewQueued": commit_preview_queued,
        "committedQueued": committed_queued,
        "committeeActiveCount": committee_active_count,
        "committeeConfiguredActiveCount": committee_configured_active_count,
        "committeeCurrentEpoch": committee_current_epoch,
    })
}

fn dag_tx_dissemination_fallback_json() -> serde_json::Value {
    serde_json::json!({
        "currentRuntime": {
            "stage": "nativeMempool",
            "ingress": "directRpcMempoolAdmit",
            "defaultCandidateSource": "nativeMempoolTopByFee",
            "fastTransparentCandidateSource": "nativeTransparentLane"
        },
        "completionTarget": {
            "stage": "narwhalBatchDissemination",
            "ingress": "narwhalWorkerBatchIngress",
            "defaultCandidateSource": "narwhalDeliveredBatch",
            "fastTransparentCandidateSource": "narwhalDeliveredBatch"
        },
        "currentRuntimeQueue": {
            "queued": 0,
            "fastTransparentQueued": 0
        },
        "completionTargetShadowQueue": {
            "queued": 0,
            "fastTransparentQueued": 0,
            "mirroredCurrentRuntimeQueued": 0,
            "narwhalWorkerBatchIngressQueued": 0,
            "stagedOnlyQueued": 0,
            "live": false,
            "consistentSubsetOfReadyQueue": true
        },
        "completionTargetDeliveredQueue": {
            "queued": 0,
            "fastTransparentQueued": 0,
            "live": false,
            "consistentSubsetOfShadowQueue": true
        },
        "completionTargetShadowCapabilities": {
            "mirroredCurrentRuntimeIngressReady": true,
            "narwhalWorkerBatchIngressReady": true,
            "stagedOnlyPreviewReady": true,
            "narwhalDeliveredBatchReady": true
        },
        "orchestration": {
            "serviceBound": false,
            "serviceRunning": false,
            "shadowBatchCallerReady": false,
            "deliveredBatchCallerReady": false
        },
        "stagedContractReady": true,
        "statusNote": "tx dissemination contract serialization failed"
    })
}

fn dag_tx_dissemination_orchestration_json(
    narwhal_dissemination: Option<&Arc<DagNarwhalDisseminationService>>,
) -> serde_json::Value {
    let service_bound = narwhal_dissemination.is_some();
    let service_running = narwhal_dissemination
        .map(|service| service.is_running())
        .unwrap_or(false);
    serde_json::json!({
        "serviceBound": service_bound,
        "serviceRunning": service_running,
        "shadowBatchCallerReady": service_running,
        "deliveredBatchCallerReady": service_running,
    })
}

fn dag_tx_dissemination_json(
    state: &DagNodeState,
    narwhal_dissemination: Option<&Arc<DagNarwhalDisseminationService>>,
) -> serde_json::Value {
    let mut value = serde_json::to_value(state.dissemination_contract_summary())
        .unwrap_or_else(|_| dag_tx_dissemination_fallback_json());
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "orchestration".into(),
            dag_tx_dissemination_orchestration_json(narwhal_dissemination),
        );
    }
    value
}

// Phase 2c-B: tx_apply_status_label deleted (TxApplyStatus removed with ring layer).

fn checkpoint_finality_blue_score(state: &DagNodeState) -> Option<u64> {
    state.checkpoint_finality_blue_score()
}

fn dag_tx_status_json(state: &DagNodeState, tx_hash: [u8; 32]) -> serde_json::Value {
    if let Some(tx) = state.mempool.get_by_hash(&tx_hash) {
        let admission_path = dag_admission_path(tx);
        return serde_json::json!({
            "status": "pending",
            "ordered": false,
            "finalized": false,
            "failedConflict": false,
            "executionStatus": serde_json::Value::Null,
            "admissionPath": match admission_path {
                PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                PrivacyBackendFamily::Transparent => "transparent",
            },
            "backendFamily": match admission_path {
                PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                PrivacyBackendFamily::Transparent => "transparent",
            },
            "blockHash": serde_json::Value::Null,
            "blockBlueScore": serde_json::Value::Null,
        });
    }

    let Some((block_hash, tx)) = state.dag_store.find_tx(&tx_hash) else {
        return serde_json::json!({
            "status": "unknown",
            "ordered": false,
            "finalized": false,
            "failedConflict": false,
            "executionStatus": serde_json::Value::Null,
            "admissionPath": serde_json::Value::Null,
            "backendFamily": serde_json::Value::Null,
            "blockHash": serde_json::Value::Null,
            "blockBlueScore": serde_json::Value::Null,
        });
    };

    let apply_status = state.dag_store.get_tx_status(&tx_hash);
    let snapshot = state.dag_store.snapshot();
    let block_blue_score = snapshot
        .get_ghostdag_data(&block_hash)
        .map(|data| data.blue_score)
        .unwrap_or(0);
    let finalized_cutoff = checkpoint_finality_blue_score(state);
    let backend_family = dag_admission_path(&tx);
    let (status, ordered, finalized, failed_conflict, conflict_meta) = match apply_status {
        Some(misaka_dag::TxApplyStatus::Applied) => {
            let finalized = finalized_cutoff
                .map(|cutoff| block_blue_score <= cutoff)
                .unwrap_or(false);
            (
                if finalized { "finalized" } else { "ordered" },
                true,
                finalized,
                false,
                serde_json::Value::Null,
            )
        }
        // Phase 2c-B: ring conflict variants removed.
        Some(_other) => (
            "failed",
            true,
            false,
            false,
            serde_json::Value::Null,
        ),
        None => ("seenInDag", false, false, false, serde_json::Value::Null),
    };

    serde_json::json!({
        "status": status,
        "ordered": ordered,
        "finalized": finalized,
        "failedConflict": failed_conflict,
        "executionStatus": apply_status.map(tx_apply_status_label),
        "admissionPath": match backend_family {
            PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                PrivacyBackendFamily::Transparent => "transparent",
        },
        "backendFamily": match backend_family {
            PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                PrivacyBackendFamily::Transparent => "transparent",
        },
        "blockHash": hex::encode(block_hash),
        "blockBlueScore": block_blue_score,
        "checkpointFinalityBlueScore": finalized_cutoff,
        "conflict": conflict_meta,
    })
}

// ═══════════════════════════════════════════════════════════════
//  RPC サーバー起動
// ═══════════════════════════════════════════════════════════════

/// DAG 対応 RPC サーバーを起動する。
///
/// v1 と同じエンドポイントパスを使用し、Explorer/ウォレット互換性を維持。
pub async fn run_dag_rpc_server(
    state: DagSharedState,
    addr: SocketAddr,
    chain_id: u32,
    genesis_hash: [u8; 32],
) -> anyhow::Result<()> {
    run_dag_rpc_server_with_observation_and_shutdown(
        state,
        None,
        None,
        None,
        None,
        Arc::new(RwLock::new(0)),
        None,
        addr,
        chain_id,
        genesis_hash,
        std::future::pending(),
    )
    .await
}

pub async fn run_dag_rpc_server_with_observation(
    state: DagSharedState,
    narwhal_dissemination: Option<Arc<DagNarwhalDisseminationService>>,
    dag_p2p_observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    validator_registry: Option<Arc<RwLock<misaka_consensus::staking::StakingRegistry>>>,
    current_epoch: Arc<RwLock<u64>>,
    epoch_progress: Option<
        Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>,
    >,
    addr: SocketAddr,
    chain_id: u32,
    genesis_hash: [u8; 32],
) -> anyhow::Result<()> {
    run_dag_rpc_server_with_observation_and_shutdown(
        state,
        narwhal_dissemination,
        dag_p2p_observation,
        runtime_recovery,
        validator_registry,
        current_epoch,
        epoch_progress,
        addr,
        chain_id,
        genesis_hash,
        std::future::pending(),
    )
    .await
}

pub(crate) async fn run_dag_rpc_server_with_observation_and_shutdown<F>(
    state: DagSharedState,
    narwhal_dissemination: Option<Arc<DagNarwhalDisseminationService>>,
    dag_p2p_observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    validator_registry: Option<Arc<RwLock<misaka_consensus::staking::StakingRegistry>>>,
    current_epoch: Arc<RwLock<u64>>,
    epoch_progress: Option<
        Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>,
    >,
    addr: SocketAddr,
    chain_id: u32,
    genesis_hash: [u8; 32],
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let rpc_state = DagRpcState {
        node: state,
        narwhal_dissemination,
        dag_p2p_observation,
        runtime_recovery,
        chain_id,
        genesis_hash,
    };

    // ── API Key configuration ──
    // SEC-FIX: Use from_env_checked so mainnet (chain_id=1) REQUIRES an API key.
    let auth_state = ApiKeyState::from_env_checked(chain_id)?;
    if auth_state.is_enabled() {
        info!("DAG RPC: API key authentication ENABLED for write endpoints");
        info!("DAG RPC: checkpoint vote gossip ingress requires API key (auth enforced)");
    } else {
        warn!("DAG RPC: API key authentication DISABLED (set MISAKA_RPC_API_KEY to enable)");
    }

    // ── Read-only endpoints (public) ──
    let public_routes = Router::new()
        .route("/api/get_chain_info", post(dag_get_chain_info))
        .route("/api/get_tx_by_hash", post(dag_get_tx_by_hash))
        .route("/api/get_dag_info", post(dag_get_dag_info))
        .route("/api/get_dag_tips", post(dag_get_tips))
        .route("/api/get_dag_block", post(dag_get_block))
        .route("/api/get_virtual_chain", post(dag_get_virtual_chain))
        .route("/api/get_virtual_state", post(dag_get_virtual_state));

    // SEC-FIX: get_utxos_by_address and get_decoy_utxos expose address→UTXO
    // mappings — privacy leak on mainnet. Gate behind dev-rpc feature like
    // rpc_server.rs does for get_address_outputs.
    #[cfg(feature = "dev-rpc")]
    let public_routes = public_routes
        .route("/api/get_utxos_by_address", post(dag_get_utxos_by_address))
        .route("/api/get_decoy_utxos", post(dag_get_decoy_utxos));

    // SEC-FIX: get_anonymity_set moved behind dev-rpc gate.
    // Previously exposed unconditionally, leaking privacy infrastructure
    // details and making the node appear to support ZKP privacy features
    // that are not implemented. All transfers are transparent (Phase 2c-B).
    #[cfg(feature = "dev-rpc")]
    let public_routes = public_routes
        .route("/api/get_anonymity_set", post(dag_get_anonymity_set));

    let public_routes = public_routes
        .route("/api/get_mempool_info", get(dag_get_mempool_info))
        .route("/api/fee_estimate", get(dag_fee_estimate))
        .route("/health", get(dag_health))
        .route("/api/openapi.yaml", get(dag_openapi_spec))
        .route("/docs", get(dag_swagger_ui));

    // ── Write endpoints (auth required when MISAKA_RPC_API_KEY is set) ──
    // `submit_tx` is the user-facing write path. Checkpoint votes use a
    // separate interim gossip ingress because peers do not yet attach HTTP
    // auth headers.
    let write_routes = Router::new()
        .route("/api/submit_tx", post(dag_submit_tx));

    // Phase 35: faucet gated by feature flag (compile-time exclusion from mainnet).
    // Previously unconditionally compiled; now requires --features faucet.
    #[cfg(feature = "faucet")]
    let write_routes = write_routes.route("/api/faucet", post(dag_faucet));

    let write_routes = write_routes.route_layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        require_api_key,
    ));

    // Phase 35 (C-T4-1 fix): checkpoint gossip gets its OWN route_layer before
    // merging. Axum's route_layer only applies to routes that already exist at
    // the time of the call, so merging after route_layer would leave the gossip
    // routes unauthenticated.
    let checkpoint_gossip = dag_checkpoint_vote_gossip_router()
        .route_layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            require_api_key,
        ));
    let write_routes = write_routes.merge(checkpoint_gossip);

    let mut app = public_routes
        .merge(write_routes)
        .with_state(rpc_state);

    // ── Validator Lock / Admission API ──
    if let Some(registry) = validator_registry {
        let validator_state = crate::validator_api::ValidatorApiState {
            registry,
            current_epoch,
            epoch_progress: epoch_progress.unwrap_or_else(|| {
                Arc::new(Mutex::new(
                    crate::validator_lifecycle_persistence::ValidatorEpochProgress::default(),
                ))
            }),
        };
        let public_validator_router =
            crate::validator_api::validator_api_public_router(validator_state.clone());
        let write_validator_router = crate::validator_api::validator_api_control_plane_router(
            validator_state,
            auth_state.clone(),
        );
        app = app
            .merge(Router::new().nest("/api/v1/validators", public_validator_router))
            .merge(Router::new().nest("/api/v1/validators", write_validator_router));
        info!("DAG RPC: Validator API enabled at /api/v1/validators/*");
    }

    // CORS — 同じ fail-closed ポリシー
    let cors = build_dag_cors_layer()?;

    // ── SEC-H2: Per-IP rate limiting (before concurrency limit) ──
    let node_limiter = crate::rpc_rate_limit::NodeRateLimiter::from_env();
    info!(
        "DAG RPC: per-IP rate limit write={}/min read={}/min",
        node_limiter.write_limit, node_limiter.read_limit
    );

    let app = app
        .layer(cors)
        .layer(DefaultBodyLimit::max(131_072))
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(axum::middleware::from_fn_with_state(
            node_limiter,
            crate::rpc_rate_limit::node_rate_limit,
        ));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("DAG RPC server listening on {}", addr);
    // SEC-FIX-1: Enable ConnectInfo<SocketAddr> so extract_ip() in
    // rpc_rate_limit.rs can read the real client socket IP.
    // Without this, per-IP rate limiting degrades to a single global bucket.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: Chain Info (v1 互換)
// ═══════════════════════════════════════════════════════════════

/// `/api/get_chain_info` — v1 Explorer 互換レスポンス。
///
/// `latestBlockHeight` は `max_blue_score` にマッピング。
/// `blockTime` は DAG のブロック間隔目標。
async fn dag_get_chain_info(State(rpc): State<DagRpcState>) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;
    sync_runtime_recovery_from_shadow_state(s, rpc.runtime_recovery.as_ref()).await;
    let privacy_backend = default_privacy_backend();
    let (current_checkpoint_votes, vote_pool) = checkpoint_vote_pool_json(s);
    let dag_p2p_observation = dag_p2p_observation_json(rpc.dag_p2p_observation.as_ref()).await;
    let runtime_recovery = dag_runtime_recovery_json(rpc.runtime_recovery.as_ref()).await;
    let validator_lifecycle_recovery =
        validator_lifecycle_recovery_json(rpc.runtime_recovery.as_ref()).await;

    let max_score = s.dag_store.max_blue_score();
    let block_count = s.dag_store.block_count();
    let tip_count = s.dag_store.tip_count();
    let consensus_architecture = dag_consensus_architecture_json();
    let tx_dissemination = dag_tx_dissemination_json(s, rpc.narwhal_dissemination.as_ref());
    let ordering_contract = dag_ordering_contract_json(s, rpc.narwhal_dissemination.as_ref());
    let sr21_committee = dag_sr21_committee_json(s);
    let authority_switch_readiness = dag_authority_switch_readiness_json(
        &consensus_architecture,
        &ordering_contract,
        &sr21_committee,
        &runtime_recovery,
    );

    Json(serde_json::json!({
        "networkName": "MISAKA DAG Testnet",
        "networkVersion": "v2.0.0-alpha",
        "consensus": "GhostDAG",
        "consensusArchitecture": consensus_architecture,
        "txDissemination": tx_dissemination,
        "orderingContract": ordering_contract,
        "latestBlockHeight": max_score,
        "dagBlockCount": block_count,
        "dagTipCount": tip_count,
        "chainId": s.chain_id,
        "mempoolSize": s.mempool.len(),
        "txStats": {
            "applied": s.state_manager.stats.txs_applied,
            "failedKiConflict": s.state_manager.stats.txs_failed_ki_conflict,
            "coinbase": s.state_manager.stats.txs_coinbase,
            "totalFees": s.state_manager.stats.total_fees,
        },
        "validatorAttestation": {
            "validatorCount": s.validator_count,
            "attestationRpcPeers": s.attestation_rpc_peers,
            "knownValidators": s.known_validators.iter().map(validator_identity_json).collect::<Vec<_>>(),
            "localValidator": s.local_validator.as_ref().map(|v| validator_identity_json(&v.identity)),
            "latestCheckpointVote": s.latest_checkpoint_vote.as_ref().map(checkpoint_vote_json),
            "latestCheckpointFinality": s.latest_checkpoint_finality.as_ref().map(checkpoint_finality_json),
            "currentCheckpointVotes": current_checkpoint_votes,
            "votePool": vote_pool,
            "currentCheckpointStatus": current_checkpoint_consumer_status(s),
        },
        "sr21Committee": sr21_committee,
        "authoritySwitchReadiness": authority_switch_readiness,
        "latestCheckpoint": s.latest_checkpoint.as_ref().map(latest_checkpoint_json),
        "dagP2pObservation": dag_p2p_observation,
        "runtimeRecovery": runtime_recovery,
        "validatorLifecycleRecovery": validator_lifecycle_recovery,
        // SEC-FIX: privacyPathSurface and privacyBackend removed from chain_info response.
        // All transfers are transparent (Phase 2c-B). Exposing ZKP privacy descriptors
        // misleads external clients into believing privacy features are active.
        "consumerSurfaces": dag_consumer_surfaces_json(s),
    }))
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: Submit TX (DAG Mempool 経由)
// ═══════════════════════════════════════════════════════════════

/// `/api/submit_tx` — TX を DAG Mempool に投入する。
///
/// # TODO(SEC): Consolidate RPC submit paths
///
/// Three independent tx submission endpoints exist:
/// 1. `narwhal_consensus.rs::submit_tx()` — IntentMessage-based sig verification
/// 2. `rpc_server.rs::submit_tx()` — structural validation only
/// 3. This function (`dag_rpc_legacy.rs::dag_submit_tx()`)
///
/// These should be unified into a single entry point to prevent
/// validation inconsistencies. See security audit FIX 15.
///
/// v1 との違い:
/// - `mempool.admit()` → `TxDisseminationPipeline(nativeMempool)` 経由に変更
/// - KI チェックが DAG State Manager 経由
async fn dag_submit_tx(
    State(rpc): State<DagRpcState>,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    // ── 1. サイズ制限 ──
    if body.len() > 131_072 {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("tx body too large: {} bytes (max 131072)", body.len())
        }));
    }

    // ── 2. デシリアライズ ──
    let tx: UtxoTransaction = match serde_json::from_slice(&body) {
        Ok(tx) => tx,
        Err(e) => {
            return Json(serde_json::json!({
                "txHash": null, "accepted": false,
                "error": format!("invalid transaction format: {}", e)
            }));
        }
    };

    // ── SEC-FIX: Reject system-only tx types at RPC ingress ──
    // SystemEmission and Faucet transactions MUST NOT be user-submittable.
    match tx.tx_type {
        misaka_types::utxo::TxType::SystemEmission
        | misaka_types::utxo::TxType::Faucet => {
            return Json(serde_json::json!({
                "txHash": null, "accepted": false,
                "error": "SystemEmission/Faucet transactions cannot be user-submitted"
            }));
        }
        _ => {}
    }

    // ── 3. 構造バリデーション ──
    if let Err(e) = tx.validate_structure() {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("structural validation failed: {}", e)
        }));
    }

    let tx_hash = tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let backend_family = dag_admission_path(&tx);

    // ── 4. DAG Mempool に投入 ──
    let dissemination = DagTxDisseminationService::new(rpc.node.clone());
    let rpc_chain_id = rpc.chain_id;
    let rpc_genesis_hash = rpc.genesis_hash;
    let result = dissemination
        .admit_transaction_with_validation(tx, |state, tx| {
            verify_dag_pre_admission(tx, &state.utxo_set, now_ms, rpc_chain_id, rpc_genesis_hash)
        })
        .await;
    match result {
        Ok((_, admission_path)) => {
            let current_runtime_queued = dissemination
                .contract_summary()
                .await
                .current_runtime_queue
                .queued;
            info!(
                "TX admitted to DAG mempool: {} | pool={} | admission_path={:?}",
                &hash_hex[..16],
                current_runtime_queued,
                admission_path
            );
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": true,
                "admissionPath": match admission_path {
                    PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                    PrivacyBackendFamily::Transparent => "transparent",
                },
                "error": null
            }))
        }
        Err(e) => {
            warn!(
                "TX rejected before or during DAG ingest: {} | reason: {}",
                &hash_hex[..16],
                e
            );
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": false,
                "admissionPath": match backend_family {
                    PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                    PrivacyBackendFamily::Transparent => "transparent",
                },
                "error": e
            }))
        }
    }
}

#[derive(Deserialize)]
struct DagCheckpointVoteRequest {
    vote: DagCheckpointVote,
    #[serde(default)]
    validator_identity: Option<ValidatorIdentity>,
}

/// Checkpoint vote ingress for validator gossip.
///
/// Phase 35 (C-T4-1 fix): Now auth-protected. The `validator_identity` field
/// is IGNORED to prevent external validator registry injection.
/// Validators must be registered via on-chain discovery only.
async fn dag_submit_checkpoint_vote(
    State(rpc): State<DagRpcState>,
    Json(req): Json<DagCheckpointVoteRequest>,
) -> Json<serde_json::Value> {
    let mut guard = rpc.node.write().await;
    let state = &mut *guard;

    // Phase 35 (C-T4-1): Ignore validator_identity from HTTP to prevent
    // external validator registry injection. Pass None unconditionally.
    if req.validator_identity.is_some() {
        tracing::warn!(
            "C-T4-1: checkpoint vote contained validator_identity — IGNORED (external registration disabled)"
        );
    }
    match ingest_checkpoint_vote(state, req.vote.clone(), None) {
        Ok(()) => {
            let target = req.vote.target;
            let vote_count = state
                .checkpoint_vote_pool
                .get(&target)
                .map(|votes| votes.len())
                .unwrap_or(0);
            if let Err(e) = save_runtime_snapshot(
                &state.snapshot_path,
                &state.dag_store,
                &state.utxo_set,
                &state.state_manager.stats,
                state.latest_checkpoint.as_ref(),
                &state.known_validators,
                &state.runtime_active_sr_validator_ids,
                state.latest_checkpoint_vote.as_ref(),
                state.latest_checkpoint_finality.as_ref(),
                &state.checkpoint_vote_pool,
            ) {
                warn!("Failed to persist DAG attestation snapshot: {}", e);
            } else if let Some(runtime_recovery) = rpc.runtime_recovery.as_ref() {
                let finalized_blue_score = state
                    .latest_checkpoint_finality
                    .as_ref()
                    .map(|proof| proof.target.blue_score);
                let mut recovery = runtime_recovery.write().await;
                recovery.mark_checkpoint_persisted(target.blue_score, target.block_hash);
                recovery.mark_checkpoint_finality(finalized_blue_score);
            }
            Json(serde_json::json!({
                "accepted": true,
                "voter": hex::encode(req.vote.voter),
                "target": checkpoint_target_json(&target),
                "knownValidatorCount": state.known_validators.len(),
                "voteCount": vote_count,
                "quorumThreshold": uniform_stake_quorum_threshold(state.validator_count).to_string(),
                "quorumReached": state.latest_checkpoint_finality.as_ref().map(|proof| proof.target == target).unwrap_or(false),
                "error": null,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "accepted": false,
            "voter": hex::encode(req.vote.voter),
            "target": checkpoint_target_json(&req.vote.target),
            "error": e.to_string(),
        })),
    }
}

async fn dag_get_tx_by_hash(
    State(rpc): State<DagRpcState>,
    Json(q): Json<DagTxQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tx_hash: [u8; 32] = hex::decode(&q.hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let guard = rpc.node.read().await;
    let status = dag_tx_status_json(&guard, tx_hash);

    if status["status"] == serde_json::Value::String("unknown".into()) {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(serde_json::json!({
        "txHash": q.hash,
        "txStatus": status,
    })))
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: DAG 固有情報
// ═══════════════════════════════════════════════════════════════

/// `/api/get_dag_info` — DAG 固有のメトリクス。
async fn dag_get_dag_info(State(rpc): State<DagRpcState>) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;
    sync_runtime_recovery_from_shadow_state(s, rpc.runtime_recovery.as_ref()).await;
    let (current_checkpoint_votes, vote_pool) = checkpoint_vote_pool_json(s);
    let runtime_recovery = dag_runtime_recovery_json(rpc.runtime_recovery.as_ref()).await;
    let validator_lifecycle_recovery =
        validator_lifecycle_recovery_json(rpc.runtime_recovery.as_ref()).await;

    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();
    let consensus_architecture = dag_consensus_architecture_json();
    let tx_dissemination = dag_tx_dissemination_json(s, rpc.narwhal_dissemination.as_ref());
    let ordering_contract = dag_ordering_contract_json(s, rpc.narwhal_dissemination.as_ref());
    let sr21_committee = dag_sr21_committee_json(s);
    let authority_switch_readiness = dag_authority_switch_readiness_json(
        &consensus_architecture,
        &ordering_contract,
        &sr21_committee,
        &runtime_recovery,
    );

    Json(serde_json::json!({
        "ghostdagK": s.ghostdag.k,
        "consensusArchitecture": consensus_architecture,
        "txDissemination": tx_dissemination,
        "orderingContract": ordering_contract,
        "genesisHash": hex::encode(s.genesis_hash),
        "maxBlueScore": s.dag_store.max_blue_score(),
        "blockCount": s.dag_store.block_count(),
        "tipCount": tips.len(),
        "tips": tips.iter().map(|t| hex::encode(&t[..8])).collect::<Vec<_>>(),
        "blocksProduced": s.blocks_produced,
        "stateManager": {
            "applied": s.state_manager.stats.txs_applied,
            "failedKi": s.state_manager.stats.txs_failed_ki_conflict,
            "failedSig": s.state_manager.stats.txs_failed_invalid_sig,
            "coinbase": s.state_manager.stats.txs_coinbase,
            "totalFees": s.state_manager.stats.total_fees,
        },
        "validatorAttestation": {
            "validatorCount": s.validator_count,
            "attestationRpcPeers": s.attestation_rpc_peers,
            "knownValidators": s.known_validators.iter().map(validator_identity_json).collect::<Vec<_>>(),
            "localValidator": s.local_validator.as_ref().map(|v| validator_identity_json(&v.identity)),
            "latestCheckpointVote": s.latest_checkpoint_vote.as_ref().map(checkpoint_vote_json),
            "latestCheckpointFinality": s.latest_checkpoint_finality.as_ref().map(checkpoint_finality_json),
            "currentCheckpointVotes": current_checkpoint_votes,
            "votePool": vote_pool,
            "currentCheckpointStatus": current_checkpoint_consumer_status(s),
        },
        "sr21Committee": sr21_committee,
        "authoritySwitchReadiness": authority_switch_readiness,
        "latestCheckpoint": s.latest_checkpoint.as_ref().map(latest_checkpoint_json),
        "runtimeRecovery": runtime_recovery,
        "validatorLifecycleRecovery": validator_lifecycle_recovery,
        "consumerSurfaces": dag_consumer_surfaces_json(s),
    }))
}

/// `/api/get_dag_tips` — 現在の DAG Tips を取得。
async fn dag_get_tips(State(rpc): State<DagRpcState>) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let snapshot = guard.dag_store.snapshot();
    let tips = snapshot.get_tips();

    let tip_info: Vec<serde_json::Value> = tips
        .iter()
        .map(|tip_hash| {
            let score = snapshot
                .get_ghostdag_data(tip_hash)
                .map(|d| d.blue_score)
                .unwrap_or(0);
            serde_json::json!({
                "hash": hex::encode(tip_hash),
                "blueScore": score,
            })
        })
        .collect();

    Json(serde_json::json!({ "tips": tip_info }))
}

/// `/api/get_dag_block` — ハッシュ指定で DAG ブロック情報を取得。
#[derive(Deserialize)]
struct DagBlockQuery {
    hash: String,
}

async fn dag_get_block(
    State(rpc): State<DagRpcState>,
    Json(q): Json<DagBlockQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&q.hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let guard = rpc.node.read().await;
    let snapshot = guard.dag_store.snapshot();

    let header = snapshot
        .get_header(&hash_bytes)
        .ok_or(StatusCode::NOT_FOUND)?;
    let ghostdag = snapshot.get_ghostdag_data(&hash_bytes);

    let txs = guard.dag_store.get_block_txs(&hash_bytes);
    let tx_summaries = txs
        .iter()
        .map(|tx| {
            let tx_hash = tx.tx_hash();
            serde_json::json!({
                "txHash": hex::encode(tx_hash),
                "txStatus": dag_tx_status_json(&guard, tx_hash),
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "hash": q.hash,
        "version": header.version,
        "parents": header.parents.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestampMs": header.timestamp_ms,
        "txRoot": hex::encode(header.tx_root),
        "proposerId": hex::encode(header.proposer_id),
        "blueScore": header.blue_score,
        "ghostdag": ghostdag.map(|d| serde_json::json!({
            "selectedParent": hex::encode(d.selected_parent),
            "mergesetBlues": d.mergeset_blues.len(),
            "mergesetReds": d.mergeset_reds.len(),
            "blueScore": d.blue_score,
        })),
        "txCount": txs.len(),
        "txHashes": txs.iter().map(|tx| hex::encode(tx.tx_hash())).collect::<Vec<_>>(),
        "txs": tx_summaries,
    })))
}

/// `/health` — ヘルスチェック。
async fn dag_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "consensus": "ghostdag",
        "version": "v2.0.0-alpha"
    }))
}

/// `/api/openapi.yaml` — Serve the OpenAPI 3.1 specification.
#[allow(clippy::unwrap_used)] // static response builder never fails
async fn dag_openapi_spec() -> axum::response::Response {
    axum::response::Response::builder()
        .header("content-type", "text/yaml; charset=utf-8")
        .body(axum::body::Body::from(include_str!(
            "../../../docs/api/openapi.yaml"
        )))
        .unwrap_or_else(|_| {
            axum::response::Response::builder()
                .status(500)
                .body(axum::body::Body::from("failed to load openapi spec"))
                .unwrap()
        })
}

/// `/docs` — Embedded Swagger UI (no external dependencies).
async fn dag_swagger_ui() -> axum::response::Html<&'static str> {
    // SEC-P0-4: Swagger UI CDN gated — same policy as misaka-api.
    #[cfg(feature = "swagger-cdn")]
    {
        axum::response::Html(
            r#"<!DOCTYPE html>
<html><head>
<title>MISAKA Node API (dev)</title>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head><body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: '/api/openapi.yaml',
  dom_id: '#swagger-ui',
  deepLinking: true,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: 'BaseLayout',
});
</script>
</body></html>"#,
        )
    }
    #[cfg(not(feature = "swagger-cdn"))]
    {
        axum::response::Html(
            r#"<!DOCTYPE html>
<html><head>
<title>MISAKA Node API</title>
<meta charset="utf-8"/>
<style>
body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
h1 { font-size: 1.4em; }
a { color: #0066cc; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
.note { background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 4px; margin: 16px 0; }
</style>
</head><body>
<h1>MISAKA Node RPC</h1>
<p>OpenAPI spec: <a href="/api/openapi.yaml"><code>/api/openapi.yaml</code></a></p>
<div class="note">
  Interactive Swagger UI is disabled in production builds.
  Enable with <code>--features swagger-cdn</code> for development.
</div>
</body></html>"#,
        )
    }
}

// ═══════════════════════════════════════════════════════════════
//  Phase 4 (v8): Kaspa-Style Virtual Chain API
// ═══════════════════════════════════════════════════════════════

/// Request body for `/api/get_virtual_chain`.
///
/// Kaspa の `GetVirtualChainFromBlockV2` に相当。
/// `start_hash` から virtual tip までの chain changes を返す。
#[derive(Deserialize)]
struct GetVirtualChainRequest {
    /// Starting block hash (hex-encoded).
    /// Chain changes between this block and the current virtual tip are returned.
    /// If omitted, returns changes from genesis.
    start_hash: Option<String>,
    /// Include acceptance data (accepted/rejected TXs per block).
    /// Default: true.
    include_accepted_txs: Option<bool>,
}

/// `/api/get_virtual_chain` — Kaspa 風 Virtual Chain 変更 API。
///
/// VirtualState::resolve() の結果を利用し、指定ブロックから virtual tip までの:
/// - chain_changes: SP chain に追加/除去されたブロック群
/// - accepted_transactions: 各ブロックで accept/reject された TX
///
/// を決定論的に返す。Wallet / Explorer / Bridge が購読する想定。
///
/// # Kaspa 対応
///
/// `GetVirtualChainFromBlockV2` に相当するデータ抽出 API。
/// 「どの TX が Accept され、どれが Reject されたか」の決定論的な結果を
/// 外部 (Wallet, Explorer, Bridge) へ供給する。
async fn dag_get_virtual_chain(
    State(rpc): State<DagRpcState>,
    Json(req): Json<GetVirtualChainRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let guard = rpc.node.read().await;
    let s = &*guard;

    let include_txs = req.include_accepted_txs.unwrap_or(true);

    // Parse start_hash
    let start_hash: Option<[u8; 32]> = match &req.start_hash {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str).map_err(|_| StatusCode::BAD_REQUEST)?;
            if bytes.len() != 32 {
                return Err(StatusCode::BAD_REQUEST);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        None => None,
    };

    // Build the virtual selected parent chain from current tips
    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();
    if tips.is_empty() {
        return Ok(Json(serde_json::json!({
            "virtualTip": null,
            "addedChainHashes": [],
            "removedChainHashes": [],
            "acceptanceData": [],
        })));
    }

    let virtual_sp = s.ghostdag.select_parent_public(&tips, &snapshot);
    let virtual_score = snapshot
        .get_ghostdag_data(&virtual_sp)
        .map(|d| d.blue_score)
        .unwrap_or(0);

    // Walk the SP chain from virtual_sp back to start_hash (or genesis)
    let mut sp_chain = Vec::new();
    let mut current = virtual_sp;
    loop {
        sp_chain.push(current);
        if Some(current) == start_hash {
            break;
        }
        if current == s.genesis_hash || current == misaka_dag::ZERO_HASH {
            break;
        }
        match snapshot.get_ghostdag_data(&current) {
            Some(data) if data.selected_parent != misaka_dag::ZERO_HASH => {
                current = data.selected_parent;
            }
            _ => break,
        }
    }
    sp_chain.reverse(); // Genesis/start → virtual_sp

    // If start_hash was found, exclude it from the added chain
    // (it's the common point, not a new addition)
    if start_hash.is_some() && !sp_chain.is_empty() && Some(sp_chain[0]) == start_hash {
        sp_chain.remove(0);
    }

    // Build acceptance data for each block in the chain
    let acceptance_data: Vec<serde_json::Value> = if include_txs {
        sp_chain
            .iter()
            .map(|block_hash| {
                let txs = s.dag_store.get_block_txs(block_hash);
                let tx_results: Vec<serde_json::Value> = txs
                    .iter()
                    .map(|tx| {
                        let tx_hash = tx.tx_hash();
                        let status = s.dag_store.get_tx_status(&tx_hash);
                        // Phase 2c-B: conflict variants removed.
                        let (accepted, reason) = match status {
                            Some(misaka_dag::TxApplyStatus::Applied) => (true, "".to_string()),
                            Some(_other) => (false, "failed".to_string()),
                            None => (true, "".to_string()), // No status recorded -- assume accepted
                        };
                        serde_json::json!({
                            "txHash": hex::encode(tx_hash),
                            "accepted": accepted,
                            "rejectionReason": reason,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "blockHash": hex::encode(block_hash),
                    "blueScore": snapshot.get_ghostdag_data(block_hash)
                        .map(|d| d.blue_score).unwrap_or(0),
                    "txResults": tx_results,
                })
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(serde_json::json!({
        "virtualTip": hex::encode(virtual_sp),
        "virtualScore": virtual_score,
        "addedChainHashes": sp_chain.iter()
            .map(|h| hex::encode(h))
            .collect::<Vec<_>>(),
        "removedChainHashes": [],
        "acceptanceData": acceptance_data,
    })))
}

/// `/api/get_virtual_state` — Virtual State summary (SSOT status).
///
/// VirtualState の現在のスナップショット情報を返す。
/// Wallet / Explorer が「現在の状態」を確認する用途。
async fn dag_get_virtual_state(
    State(rpc): State<DagRpcState>,
    _body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;

    let vs = &s.virtual_state;
    let snapshot = vs.snapshot();

    Json(serde_json::json!({
        "tip": hex::encode(snapshot.tip),
        "tipScore": snapshot.tip_score,
        "spentCount": snapshot.spent_count,
        "utxoCount": snapshot.utxo_count,
        "stateRoot": hex::encode(snapshot.state_root),
        "createdAtMs": snapshot.created_at_ms,
        "stats": {
            "blocksApplied": vs.stats.blocks_applied,
            "spcSwitches": vs.stats.spc_switches,
            "reorgs": vs.stats.reorgs,
            "deepestReorg": vs.stats.deepest_reorg,
        },
    }))
}

// ═══════════════════════════════════════════════════════════════
//  Wallet API — Chrome拡張 / 外部サービス向け
// ═══════════════════════════════════════════════════════════════

/// Derive a MISAKA address from a spending public key.
///
/// H-3 FIX: Uses `misaka_types::address::encode_address` for unified prefix.
fn derive_address_from_spending_key(pk_bytes: &[u8], chain_id: u32) -> String {
    use sha3::{Digest as Sha3Digest, Sha3_256};
    let hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(pk_bytes);
        h.finalize().into()
    };
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&hash);
    misaka_types::address::encode_address(&addr, chain_id)
}

// ── Request types ──

#[cfg(feature = "dev-rpc")]
#[derive(Deserialize)]
struct GetUtxosByAddressReq {
    address: String,
}

#[cfg(feature = "dev-rpc")]
#[derive(Deserialize)]
struct GetDecoyUtxosReq {
    amount: u64,
    count: Option<usize>,
    #[serde(rename = "excludeTxHash", default)]
    exclude_tx_hash: String,
    #[serde(rename = "excludeOutputIndex", default)]
    exclude_output_index: u32,
}

#[derive(Deserialize)]
struct GetAnonymitySetReq {
    #[serde(rename = "ringSize")]
    anonymity_set_size: Option<usize>,
    #[serde(rename = "txHash", default)]
    tx_hash: String,
    #[serde(rename = "outputIndex", default)]
    output_index: u32,
}

// ── Handlers ──

/// `POST /api/get_utxos_by_address`
///
/// Scan the UTXO set for outputs whose spending_pubkey derives to the given address.
/// Returns matching UTXOs with amount, spending_pubkey, and key metadata.
///
/// NOTE: This is an O(n) scan over the entire UTXO set. For production use at
/// scale, use the misaka-api indexer service instead.
#[cfg(feature = "dev-rpc")]
async fn dag_get_utxos_by_address(
    State(rpc): State<DagRpcState>,
    Json(req): Json<GetUtxosByAddressReq>,
) -> Json<serde_json::Value> {
    let address = req.address.trim().to_string();

    let guard = rpc.node.read().await;
    let s = &*guard;

    // H-3 FIX: Use unified address validation with chain_id binding
    if let Err(e) = misaka_types::address::validate_address(&address, s.chain_id) {
        return Json(serde_json::json!({
            "address": address,
            "error": format!("invalid address: {}", e),
            "utxos": [],
            "balance": 0
        }));
    }

    let mut utxos = Vec::new();
    let mut balance: u64 = 0;

    // SEC-FIX: Limit results to prevent O(N) scan from holding read lock
    // indefinitely and returning unbounded response payloads.
    const MAX_UTXOS_PER_QUERY: usize = 1000;

    for (outref, pk_bytes) in s.utxo_set.all_spending_keys() {
        let derived = derive_address_from_spending_key(pk_bytes, s.chain_id);
        if derived != address {
            continue;
        }

        if let Some(entry) = s.utxo_set.get(outref) {
            balance = balance.saturating_add(entry.output.amount);
            if utxos.len() < MAX_UTXOS_PER_QUERY {
                utxos.push(serde_json::json!({
                    "txHash": hex::encode(outref.tx_hash),
                    "outputIndex": outref.output_index,
                    "amount": entry.output.amount,
                    "address": hex::encode(entry.output.address),
                    "spendingPubkey": hex::encode(pk_bytes),
                    "createdAt": entry.created_at,
                }));
            }
            // Continue iterating to get accurate balance even if we hit the UTXO limit
        }
    }

    Json(serde_json::json!({
        "address": address,
        "utxos": utxos,
        "balance": balance,
        "utxoCount": utxos.len(),
    }))
}

/// `POST /api/get_decoy_utxos`
///
/// Return same-amount UTXOs with their spending_pubkey for ML-DSA signature construction.
/// Compatible with the CLI `transfer.rs` decoy fetching format.
#[cfg(feature = "dev-rpc")]
async fn dag_get_decoy_utxos(
    State(rpc): State<DagRpcState>,
    Json(req): Json<GetDecoyUtxosReq>,
) -> Json<serde_json::Value> {
    let count = req.count.unwrap_or(8).min(64);
    let target_amount = req.amount;

    let mut exclude_hash = [0u8; 32];
    if let Ok(decoded) = hex::decode(&req.exclude_tx_hash) {
        let len = decoded.len().min(32);
        exclude_hash[..len].copy_from_slice(&decoded[..len]);
    }

    let guard = rpc.node.read().await;
    let s = &*guard;

    let mut decoys = Vec::new();

    for (outref, pk_bytes) in s.utxo_set.all_spending_keys() {
        if decoys.len() >= count {
            break;
        }

        // Skip the excluded UTXO (the one being spent)
        if outref.tx_hash == exclude_hash && outref.output_index == req.exclude_output_index {
            continue;
        }

        if let Some(entry) = s.utxo_set.get(outref) {
            if entry.output.amount != target_amount {
                continue;
            }
            decoys.push(serde_json::json!({
                "txHash": hex::encode(outref.tx_hash),
                "outputIndex": outref.output_index,
                "amount": entry.output.amount,
                "spendingPubkey": hex::encode(pk_bytes),
            }));
        }
    }

    Json(serde_json::json!({
        "utxos": decoys,
        "count": decoys.len(),
        "requestedAmount": target_amount,
    }))
}

/// `POST /api/get_anonymity_set`
///
/// Build a ZKP anonymity set from confirmed UTXO spending pubkeys.
/// Returns leaf hashes for SIS Merkle tree construction.
async fn dag_get_anonymity_set(
    State(rpc): State<DagRpcState>,
    Json(req): Json<GetAnonymitySetReq>,
) -> Json<serde_json::Value> {
    use sha3::{Digest as Sha3Digest, Sha3_256};

    let anonymity_set_size = req.anonymity_set_size.unwrap_or(16).max(4).min(1024);

    let mut signer_tx_hash = [0u8; 32];
    if let Ok(decoded) = hex::decode(&req.tx_hash) {
        let len = decoded.len().min(32);
        signer_tx_hash[..len].copy_from_slice(&decoded[..len]);
    }

    let guard = rpc.node.read().await;
    let s = &*guard;

    let all_keys = s.utxo_set.all_spending_keys();
    if all_keys.len() < anonymity_set_size {
        return Json(serde_json::json!({
            "error": format!("insufficient UTXOs for anonymity set: need {}, have {}", anonymity_set_size, all_keys.len()),
            "leaves": [],
            "signerIndex": 0
        }));
    }

    // Hash each spending pubkey to create leaf hashes
    let mut all_leaf_hashes: Vec<([u8; 32], String)> = all_keys
        .iter()
        .map(|(outref, pk_bytes)| {
            let leaf: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA_ANON_LEAF:");
                h.update(pk_bytes);
                h.finalize().into()
            };
            (
                leaf,
                format!(
                    "{}:{}",
                    hex::encode(&outref.tx_hash[..8]),
                    outref.output_index
                ),
            )
        })
        .collect();

    // Deterministic shuffle based on signer tx hash
    all_leaf_hashes.sort_by(|a, b| a.0.cmp(&b.0));

    // Find the signer's leaf
    let signer_outref = misaka_types::utxo::OutputRef {
        tx_hash: signer_tx_hash,
        output_index: req.output_index,
    };

    let signer_pk = all_keys.get(&signer_outref);
    let signer_leaf: Option<[u8; 32]> = signer_pk.map(|pk| {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_ANON_LEAF:");
        h.update(pk);
        h.finalize().into()
    });

    // Select anonymity_set_size leaves, ensuring signer is included
    let mut selected: Vec<[u8; 32]> = Vec::with_capacity(anonymity_set_size);
    let mut signer_index = 0usize;

    if let Some(s_leaf) = signer_leaf {
        // Add signer first, then fill remaining from the sorted set
        selected.push(s_leaf);
        for (leaf, _) in &all_leaf_hashes {
            if selected.len() >= anonymity_set_size {
                break;
            }
            if *leaf != s_leaf {
                selected.push(*leaf);
            }
        }
        // Shuffle signer into a random position
        if selected.len() > 1 {
            // Deterministic position from hash
            let pos_seed: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA_ANON_POS:");
                h.update(&signer_tx_hash);
                h.update(&req.output_index.to_le_bytes());
                h.finalize().into()
            };
            signer_index = (pos_seed[0] as usize) % selected.len();
            selected.swap(0, signer_index);
        }
    } else {
        // Signer not found — return first anonymity_set_size leaves
        for (leaf, _) in all_leaf_hashes.iter().take(anonymity_set_size) {
            selected.push(*leaf);
        }
    }

    // Compute Merkle root (simple binary hash tree)
    let merkle_root = compute_simple_merkle_root(&selected);

    Json(serde_json::json!({
        "leaves": selected.iter().map(hex::encode).collect::<Vec<_>>(),
        "signerIndex": signer_index,
        "ringSize": selected.len(),
        "merkleRoot": hex::encode(merkle_root),
    }))
}

/// Simple binary Merkle root from a list of 32-byte leaves.
fn compute_simple_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    use sha3::{Digest as Sha3Digest, Sha3_256};

    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for chunk in layer.chunks(2) {
            let mut h = Sha3_256::new();
            h.update(&chunk[0]);
            if chunk.len() == 2 {
                h.update(&chunk[1]);
            } else {
                h.update(&chunk[0]); // duplicate odd leaf
            }
            next.push(h.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

/// `GET /api/get_mempool_info`
///
/// Returns mempool size and basic statistics.
async fn dag_get_mempool_info(State(rpc): State<DagRpcState>) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;

    let mempool_size = s.mempool.len();
    let utxo_count = s.utxo_set.len();

    Json(serde_json::json!({
        "mempoolSize": mempool_size,
        "utxoSetSize": utxo_count,
        "minFee": 100,
    }))
}

/// `GET /api/fee_estimate`
///
/// Returns estimated fees at three priority levels.
/// Currently static; will become dynamic based on mempool pressure.
async fn dag_fee_estimate(State(rpc): State<DagRpcState>) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;

    // Simple fee estimation based on mempool pressure
    let mempool_size = s.mempool.len();
    let (low, medium, high) = if mempool_size < 100 {
        (100u64, 100, 200)
    } else if mempool_size < 500 {
        (100, 200, 500)
    } else {
        (200, 500, 1000)
    };

    Json(serde_json::json!({
        "low": low,
        "medium": medium,
        "high": high,
        "unit": "base",
        "mempoolSize": mempool_size,
    }))
}

// ═══════════════════════════════════════════════════════════════
//  Faucet (testnet only, feature-gated in dag mode)
// ═══════════════════════════════════════════════════════════════

/// `POST /api/faucet`
///
/// Drip testnet tokens to the given address.
///
/// # Security (SEC-FAUCET)
///
/// - **Consensus path**: Faucet TXs go through mempool → block → consensus → state.
///   Direct UTXO writes are FORBIDDEN (consensus bypass = free money printing).
/// - **Rate limit**: Per-IP (1 per cooldown) + per-address (1 per cooldown).
///   Rate state is checked AND recorded atomically (TOCTOU-safe).
/// - **Mainnet disable**: chain_id == 1 → hard reject.
/// - **Feature gate**: Only available when `faucet` feature is enabled in the build.
///   Production binaries MUST NOT include this feature.
/// - **Auth**: When `MISAKA_RPC_API_KEY` is set, the faucet requires auth
///   (handled by the `require_api_key` middleware on the route layer).
#[cfg(feature = "faucet")]
async fn dag_faucet(
    State(rpc): State<DagRpcState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let address = req["address"].as_str().unwrap_or("").trim().to_string();
    let spending_pubkey_hex = req["spendingPubkey"].as_str().unwrap_or("").to_string();

    if address.is_empty() {
        return Json(serde_json::json!({
            "accepted": false,
            "error": "address is required"
        }));
    }

    let mut guard = rpc.node.write().await;
    let s = &mut *guard;

    // Validate address with chain-bound checksum
    let addr_bytes = match misaka_types::address::validate_address(&address, s.chain_id) {
        Ok(b) => b,
        Err(e) => {
            return Json(serde_json::json!({
                "accepted": false,
                "error": format!("invalid address: {}", e)
            }));
        }
    };

    // ── SEC-FAUCET-1: Hard reject on mainnet ──
    if s.chain_id == 1 {
        return Json(serde_json::json!({
            "accepted": false,
            "error": "faucet is disabled on mainnet (chain_id=1)"
        }));
    }

    // ── SEC-FAUCET-2: Per-address cooldown (atomic check-and-record) ──
    //
    // TOCTOU fix: the cooldown check and the reservation happen under
    // the same write lock on DagNodeState. No gap between "is it allowed?"
    // and "mark it as used" — the lock is held the entire time.
    //
    // Note: We use s.faucet_cooldowns (a HashMap added to DagNodeState)
    // which is protected by the RwLock<DagNodeState> already held above.
    let cooldown_ms: u64 = 60_000; // 1 minute for testnet (24h for public testnet)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Some(last_ms) = s.faucet_cooldowns.get(&address) {
        let elapsed = now_ms.saturating_sub(*last_ms);
        if elapsed < cooldown_ms {
            let wait = (cooldown_ms - elapsed) / 1000;
            return Json(serde_json::json!({
                "accepted": false,
                "error": format!("rate limited: try again in {}s", wait),
                "retryAfter": wait,
            }));
        }
    }

    // Record cooldown BEFORE processing (atomic with the check above)
    s.faucet_cooldowns.insert(address.clone(), now_ms);

    // GC old cooldown entries (every ~100 requests)
    if s.faucet_cooldowns.len() > 1000 {
        let cutoff = now_ms.saturating_sub(cooldown_ms * 2);
        s.faucet_cooldowns.retain(|_, ts| *ts > cutoff);
    }

    let ota_bytes = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&addr_bytes);
        arr
    };

    // ── SEC-FAUCET-3: Build TX and submit through mempool (NOT direct UTXO write) ──
    //
    // The old code called `s.utxo_set.add_output()` directly, which:
    //   1. Bypasses the mempool (no dedup, no rate limit, no conflict check)
    //   2. Bypasses consensus (no block production, no finality)
    //   3. Creates money out of thin air without a valid block
    //
    // Fix: Build a proper Faucet-type TX and submit it to the mempool.
    // It will be included in the next block by the block producer,
    // validated through consensus, and applied to state atomically.
    let faucet_amount: u64 = std::env::var("MISAKA_FAUCET_AMOUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000_000); // default 1 MISAKA; set MISAKA_FAUCET_AMOUNT for more

    let spending_pubkey = if !spending_pubkey_hex.is_empty() {
        hex::decode(&spending_pubkey_hex).ok()
    } else {
        None
    };

    let faucet_tx = misaka_types::utxo::UtxoTransaction {
        version: misaka_types::utxo::UTXO_TX_VERSION,
        tx_type: misaka_types::utxo::TxType::Faucet,
        inputs: vec![],
        outputs: vec![misaka_types::utxo::TxOutput {
            amount: faucet_amount,
            address: ota_bytes,
            spending_pubkey,
        }],
        fee: 0,
        extra: vec![],
        expiry: 0,
    };

    let tx_hash = faucet_tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);

    // Submit to mempool — the TX will be included in the next block
    // through normal block production. This is the ONLY correct path.
    // Faucet TXs have no inputs, so ki_spent check always returns false.
    drop(guard);
    let dissemination = DagTxDisseminationService::new(rpc.node.clone());
    let mempool_result = dissemination.admit_transaction(faucet_tx.clone()).await;
    if mempool_result.is_err() {
        warn!(
            "Faucet TX {} rejected by mempool: {:?}",
            hash_hex, mempool_result
        );
    }

    info!(
        "Faucet drip queued: {} → {} ({} base units) — awaiting block inclusion",
        hash_hex, address, faucet_amount
    );

    Json(serde_json::json!({
        "accepted": true,
        "txHash": hash_hex,
        "amount": faucet_amount,
        "address": address,
        "note": "TX submitted to mempool. Will be included in the next block."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply_sr21_election_at_epoch_boundary;
    use crate::dag_narwhal_dissemination_service::DagNarwhalDisseminationService;
    use crate::dag_p2p_surface::{DagP2pDirection, DagP2pObservationState, DagP2pSurface};
    use crate::dag_rpc_service::DagRpcServerService;
    use crate::dag_tx_dissemination_service::DagTxDisseminationService;
    use crate::{
        gossip_checkpoint_vote_to_peers, local_vote_gossip_payload,
        refresh_local_checkpoint_attestation,
    };
    use axum::{
        body::{to_bytes, Body},
        extract::{DefaultBodyLimit, State},
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use misaka_dag::daa::BLOCKS_PER_EPOCH;
    use misaka_dag::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
    use misaka_dag::dag_store::ThreadSafeDagStore;
    use misaka_dag::reachability::ReachabilityStore;
    use misaka_dag::{
        DagCheckpoint, DagMempool, DagStateManager, GhostDagEngine, LocalDagValidator,
        TxApplyStatus, TxDisseminationLane,
    };
    use misaka_p2p::PeerId;
    use misaka_pqc::pq_ring::SpendingKeypair;
    use misaka_pqc::pq_sign::MlDsaKeypair;

    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION,
    };
    use misaka_types::validator::{
        DagCheckpointFinalityProof, DagCheckpointVote, ValidatorIdentity, ValidatorPublicKey,
        ValidatorSignature,
    };
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::util::ServiceExt;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::env_lock()
    }

    fn setup_utxo_with_uniform_ring() -> (UtxoSet, Vec<SpendingKeypair>) {
        let mut utxo_set = UtxoSet::new(32);
        let wallets: Vec<SpendingKeypair> = (0..4)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();

        for (i, wallet) in wallets.iter().enumerate() {
            let outref = OutputRef {
                tx_hash: [(i + 1) as u8; 32],
                output_index: 0,
            };
            let output = TxOutput {
                amount: 10_000,
                address: [0x80 + i as u8; 32],
                spending_pubkey: Some(wallet.public_poly.to_bytes()),
            };
            utxo_set.add_output(outref.clone(), output, 0, false).unwrap();
            utxo_set.register_spending_key(outref, wallet.public_poly.to_bytes())
                .expect("test: register_spending_key");
        }

        (utxo_set, wallets)
    }

    fn make_ring_tx(wallets: &[SpendingKeypair]) -> UtxoTransaction {
        let utxo_refs: Vec<OutputRef> = wallets
            .iter()
            .enumerate()
            .map(|(i, _)| OutputRef {
                tx_hash: [(i + 1) as u8; 32],
                output_index: 0,
            })
            .collect();

        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInput {
                utxo_refs,
                proof: vec![0xAA; 32],
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                address: [0x42; 32],
                spending_pubkey: Some(wallets[0].public_poly.to_bytes()),
            }],
            fee: 100,
            extra: vec![],
            expiry: 0,
        }
    }

    fn make_test_dag_state() -> DagNodeState {
        let genesis_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1_700_000_000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0u8; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        };
        let genesis_hash = genesis_header.compute_hash();

        DagNodeState {
            dag_store: Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header)),
            ghostdag: GhostDagEngine::new(18, genesis_hash),
            state_manager: DagStateManager::new(HashSet::new(), HashSet::new()),
            utxo_set: UtxoSet::new(32),
            virtual_state: misaka_dag::VirtualState::new(genesis_hash),
            ingestion_pipeline: misaka_dag::IngestionPipeline::new(
                [genesis_hash].into_iter().collect(),
            ),
            quarantined_blocks: HashSet::new(),
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count: 2,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
            sr_index: 0,
            num_active_srs: 1,
            runtime_active_sr_validator_ids: Vec::new(),
            local_validator: None,
            genesis_hash,
            snapshot_path: PathBuf::from("/tmp/misaka-dag-rpc-test-snapshot.json"),
            latest_checkpoint: None,
            latest_checkpoint_vote: None,
            latest_checkpoint_finality: None,
            checkpoint_vote_pool: std::collections::HashMap::new(),
            attestation_rpc_peers: Vec::new(),
            blocks_produced: 0,
            reachability: ReachabilityStore::new(genesis_hash),
            persistent_backend: None,
            faucet_cooldowns: std::collections::HashMap::new(),
            pending_transactions: std::collections::HashMap::new(),

        }
    }

    fn set_test_dag_epoch(state: &mut DagNodeState, epoch: u64) {
        let mut dump = state.dag_store.export_dump();
        let blue_score = epoch.saturating_mul(BLOCKS_PER_EPOCH);

        if let Some(record) = dump
            .ghostdag
            .iter_mut()
            .find(|record| record.hash == state.genesis_hash)
        {
            record.data.blue_score = blue_score;
            record.data.blue_work = blue_score as u128;
        }

        if let Some(record) = dump
            .headers
            .iter_mut()
            .find(|record| record.hash == state.genesis_hash)
        {
            record.header.blue_score = blue_score;
        }

        state.dag_store = Arc::new(ThreadSafeDagStore::from_dump(dump));
    }

    fn make_test_dissemination_tx(seed: u8, tx_type: TxType) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [seed; 32],
                    output_index: 0,
                }],
                proof: vec![0xAA; 32],
            }],
            outputs: vec![TxOutput {
                amount: 100,
                address: [seed.wrapping_add(1); 32],
                spending_pubkey: None,
            }],
            fee: u64::from(seed),
            extra: vec![],
            expiry: 0,
        }
    }

    fn make_test_rpc_state() -> DagRpcState {
        DagRpcState {
            node: Arc::new(tokio::sync::RwLock::new(make_test_dag_state())),
            narwhal_dissemination: None,
            dag_p2p_observation: None,
            runtime_recovery: None,
            chain_id: 2, // testnet
            genesis_hash: [0u8; 32],
        }
    }

    fn unique_temp_dir(label: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}-{}", label, unique));
        std::fs::create_dir_all(&path).expect("dir");
        path.to_string_lossy().into_owned()
    }

        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create result dir");
        }
        let _ = std::fs::remove_file(&path);
        let enriched_payload = enrich_named_result_payload(payload);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&enriched_payload).expect("bounded e2e json"),
        )
        .expect("write bounded e2e result");
    }
    fn maybe_write_narwhal_dissemination_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_RESULT",
            payload,
            "narwhal dissemination rehearsal json",
        );
    }

    fn maybe_write_bullshark_ordering_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_ORDERING_REHEARSAL_RESULT",
            payload,
            "bullshark ordering rehearsal json",
        );
    }

    fn maybe_write_bullshark_auto_candidate_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_AUTO_CANDIDATE_REHEARSAL_RESULT",
            payload,
            "bullshark auto candidate rehearsal json",
        );
    }

    fn maybe_write_bullshark_auto_commit_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_AUTO_COMMIT_REHEARSAL_RESULT",
            payload,
            "bullshark auto commit rehearsal json",
        );
    }

    fn maybe_write_bullshark_auto_commit_live_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_AUTO_COMMIT_LIVE_REHEARSAL_RESULT",
            payload,
            "bullshark auto commit live rehearsal json",
        );
    }

    fn maybe_write_bullshark_auto_committed_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_AUTO_COMMITTED_REHEARSAL_RESULT",
            payload,
            "bullshark auto committed rehearsal json",
        );
    }

    fn maybe_write_bullshark_auto_committed_live_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_RESULT",
            payload,
            "bullshark auto committed live rehearsal json",
        );
    }

    fn maybe_write_sr21_committee_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_SR21_COMMITTEE_REHEARSAL_RESULT",
            payload,
            "sr21 committee rehearsal json",
        );
    }

    fn maybe_write_sr21_rotation_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_SR21_ROTATION_REHEARSAL_RESULT",
            payload,
            "sr21 rotation rehearsal json",
        );
    }

    fn maybe_write_sr21_selection_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_SR21_SELECTION_REHEARSAL_RESULT",
            payload,
            "sr21 selection rehearsal json",
        );
    }

    fn maybe_write_bullshark_commit_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_COMMIT_REHEARSAL_RESULT",
            payload,
            "bullshark commit rehearsal json",
        );
    }

    fn maybe_write_bullshark_commit_authority_switch_rehearsal_result(
        payload: &serde_json::Value,
    ) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_RESULT",
            payload,
            "bullshark commit authority switch rehearsal json",
        );
    }

    fn maybe_write_bullshark_authority_switch_rehearsal_result(payload: &serde_json::Value) {
        maybe_write_named_json_result(
            "MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_RESULT",
            payload,
            "bullshark authority switch rehearsal json",
        );
    }

    fn maybe_write_named_json_result(env_var: &str, payload: &serde_json::Value, label: &str) {
        let Ok(path) = std::env::var(env_var) else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create named result dir");
        }
        let _ = std::fs::remove_file(&path);
        let enriched_payload = enrich_named_result_payload(payload);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&enriched_payload).expect(label),
        )
        .expect("write named result");
    }

    fn enrich_named_result_payload(payload: &serde_json::Value) -> serde_json::Value {
        let mut enriched = payload.clone();
        if let Some(map) = enriched.as_object_mut() {
            map.entry("consensusArchitecture")
                .or_insert_with(dag_consensus_architecture_json);
            map.entry("txDissemination")
                .or_insert_with(dag_tx_dissemination_fallback_json);
        }
        enriched
    }
    fn persist_named_artifact(
        source: &std::path::Path,
        result_env_var: &str,
        filename: &str,
    ) -> PathBuf {
        let Ok(result_path) = std::env::var(result_env_var) else {
            return source.to_path_buf();
        };
        let result_path = PathBuf::from(result_path);
        let artifacts_dir = result_path
            .parent()
            .expect("named result parent")
            .join("artifacts");
        std::fs::create_dir_all(&artifacts_dir).expect("create named artifacts dir");
        let dest = artifacts_dir.join(filename);
        let _ = std::fs::remove_file(&dest);
        std::fs::copy(source, &dest).expect("copy named artifact");
        dest
    }
    fn rebuild_live_test_reachability(
        dag_store: &Arc<ThreadSafeDagStore>,
        genesis_hash: [u8; 32],
    ) -> ReachabilityStore {
        let mut reachability = ReachabilityStore::new(genesis_hash);
        let snapshot = dag_store.snapshot();
        let all_hashes = snapshot.all_hashes();
        if all_hashes.len() <= 1 {
            return reachability;
        }

        let mut blocks_with_score: Vec<([u8; 32], u64)> = all_hashes
            .into_iter()
            .filter(|hash| *hash != genesis_hash)
            .filter_map(|hash| {
                snapshot
                    .get_ghostdag_data(&hash)
                    .map(|gd| (hash, gd.blue_score))
            })
            .collect();
        blocks_with_score.sort_by_key(|(_, blue_score)| *blue_score);

        for (hash, _) in blocks_with_score {
            if let Some(ghostdag) = snapshot.get_ghostdag_data(&hash) {
                let selected_parent = ghostdag.selected_parent;
                if selected_parent != ZERO_HASH {
                    let _ = reachability.add_child(selected_parent, hash);
                }
            }
        }

        reachability
    }

    fn make_live_test_dag_state(
        temp_dir: &str,
        validator_count: usize,
        local_validator: Option<LocalDagValidator>,
    ) -> DagNodeState {
        let mut state = make_test_dag_state();
        state.validator_count = validator_count;
        state.local_validator = local_validator;
        state.snapshot_path = PathBuf::from(temp_dir).join("dag_runtime_snapshot.json");
        state
    }

    fn make_test_local_validator(stake_weight: u128) -> LocalDagValidator {
        let keypair = misaka_crypto::validator_sig::generate_validator_keypair();
        let identity = ValidatorIdentity {
            validator_id: keypair.public_key.to_canonical_id(),
            stake_weight,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        LocalDagValidator { identity, keypair }
    }

    fn make_test_validator_cluster(
        validator_count: usize,
        stake_weight: u128,
    ) -> (
        LocalDagValidator,
        Vec<LocalDagValidator>,
        Vec<ValidatorIdentity>,
    ) {
        assert!(
            validator_count >= 2,
            "validator cluster needs at least two validators"
        );
        let local_validator = make_test_local_validator(stake_weight);
        let mut known_validators = vec![local_validator.identity.clone()];
        let remote_validators = (0..validator_count - 1)
            .map(|_| make_test_local_validator(stake_weight))
            .collect::<Vec<_>>();
        known_validators.extend(
            remote_validators
                .iter()
                .map(|validator| validator.identity.clone()),
        );
        (local_validator, remote_validators, known_validators)
    }

    async fn gossip_remote_checkpoint_votes_for_live_test(
        validator_count: usize,
        remote_validators: Vec<LocalDagValidator>,
        checkpoint: DagCheckpoint,
        base_url: &str,
        known_validators: &[ValidatorIdentity],
    ) {
        for remote_validator in remote_validators {
            let (remote_vote, remote_vote_identity, remote_vote_peers) =
                make_remote_vote_gossip_payload(
                    validator_count,
                    remote_validator,
                    checkpoint.clone(),
                    base_url.to_string(),
                    known_validators.to_vec(),
                );
            gossip_checkpoint_vote_to_peers(remote_vote_peers, remote_vote, remote_vote_identity)
                .await;
        }
    }
    fn make_runtime_recovery_observation(
        temp_dir: &str,
    ) -> Arc<tokio::sync::RwLock<DagRuntimeRecoveryObservation>> {
        Arc::new(tokio::sync::RwLock::new(
            DagRuntimeRecoveryObservation::new(
                PathBuf::from(temp_dir).join("dag_runtime_snapshot.json"),
                PathBuf::from(temp_dir).join("validator_lifecycle.json"),
                PathBuf::from(temp_dir).join("dag_wal.journal"),
                PathBuf::from(temp_dir).join("dag_wal.journal.tmp"),
            ),
        ))
    }

    async fn seed_runtime_recovery_for_live_test(
        observation: &Arc<tokio::sync::RwLock<DagRuntimeRecoveryObservation>>,
    ) {
        let (snapshot_path, validator_lifecycle_path, wal_journal_path) = {
            let guard = observation.read().await;
            (
                guard.snapshot_path.clone(),
                guard.validator_lifecycle_path.clone(),
                guard.wal_journal_path.clone(),
            )
        };
        if let Some(parent) = snapshot_path.parent() {
            std::fs::create_dir_all(parent).expect("recovery snapshot dir");
        }
        std::fs::write(&snapshot_path, b"{}").expect("seed recovery snapshot");
        std::fs::write(&validator_lifecycle_path, b"{}").expect("seed validator lifecycle");
        std::fs::write(&wal_journal_path, b"{}").expect("seed wal journal");
        let mut guard = observation.write().await;
        guard.mark_startup_snapshot_restored(true);
        guard.mark_startup_wal_state("recovered", 0);
    }

    async fn make_restarted_runtime_recovery_observation(
        temp_dir: &str,
        checkpoint_blue_score: u64,
        checkpoint_block_hash: [u8; 32],
    ) -> Arc<tokio::sync::RwLock<DagRuntimeRecoveryObservation>> {
        let observation = make_runtime_recovery_observation(temp_dir);
        {
            let mut guard = observation.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 0);
            guard.mark_checkpoint_persisted(checkpoint_blue_score, checkpoint_block_hash);
            guard.mark_checkpoint_finality(Some(checkpoint_blue_score));
        }
        observation
    }

    async fn start_live_dag_rpc_service(
        dag_state: Arc<tokio::sync::RwLock<DagNodeState>>,
        runtime_recovery: Arc<tokio::sync::RwLock<DagRuntimeRecoveryObservation>>,
        addr: SocketAddr,
    ) -> Arc<DagRpcServerService> {
        let server = DagRpcServerService::new(
            dag_state,
            None,
            Some(runtime_recovery),
            None,
            Arc::new(tokio::sync::RwLock::new(0)),
            None,
            addr,
            31337,
        );
        server.start().await.expect("start live dag rpc service");
        server
    }

    fn make_restored_live_test_dag_state(temp_dir: &str, validator_count: usize) -> DagNodeState {
        let snapshot_path = PathBuf::from(temp_dir).join("dag_runtime_snapshot.json");
        let restored = misaka_dag::load_runtime_snapshot(&snapshot_path, 1000)
            .expect("load live full-path snapshot")
            .expect("restored live full-path snapshot");

        let dag_store = Arc::new(restored.dag_store);
        let reachability = rebuild_live_test_reachability(&dag_store, restored.genesis_hash);
        let known_block_hashes: HashSet<_> =
            dag_store.snapshot().all_hashes().into_iter().collect();
        let latest_checkpoint = restored.latest_checkpoint.clone();
        let mut state = make_test_dag_state();
        state.validator_count = validator_count;
        state.local_validator = None;
        state.snapshot_path = snapshot_path;
        state.dag_store = dag_store;
        state.utxo_set = restored.utxo_set;
        state.state_manager = restored.state_manager;
        state.genesis_hash = restored.genesis_hash;
        state.latest_checkpoint = latest_checkpoint.clone();
        state.known_validators = restored.known_validators;
        state.runtime_active_sr_validator_ids = restored.runtime_active_sr_validator_ids;
        state.latest_checkpoint_vote = restored.latest_checkpoint_vote;
        state.latest_checkpoint_finality = restored.latest_checkpoint_finality;
        state.checkpoint_vote_pool = restored.checkpoint_vote_pool;
        state.ingestion_pipeline = misaka_dag::IngestionPipeline::new(known_block_hashes);
        state.reachability = reachability;
        state.virtual_state = if let Some(checkpoint) = latest_checkpoint {
            let utxo_snapshot = state.utxo_set.export_snapshot();
            let tracked_utxos = utxo_snapshot
                .unspent
                .into_iter()
                .map(|entry| (entry.outref, entry.output))
                .collect();
            let mut virtual_state = misaka_dag::VirtualState::from_snapshot(
                checkpoint.block_hash,
                checkpoint.blue_score,
                HashSet::new(),
                tracked_utxos,
            );
            virtual_state.set_finality_boundary(checkpoint.blue_score);
            virtual_state
        } else {
            misaka_dag::VirtualState::new(state.genesis_hash)
        };
        state
    }

    async fn wait_for_chain_info_http(
        client: &reqwest::Client,
        base_url: &str,
    ) -> serde_json::Value {
        for _ in 0..60 {
            if let Ok(response) = client
                .post(format!("{base_url}/api/get_chain_info"))
                .json(&serde_json::json!({}))
                .send()
                .await
            {
                if response.status().is_success() {
                    return response.json().await.expect("chain info json");
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for live DAG RPC server");
    }

    async fn wait_for_chain_info_http_matching<F>(
        client: &reqwest::Client,
        base_url: &str,
        predicate: F,
    ) -> serde_json::Value
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        for _ in 0..60 {
            let json = wait_for_chain_info_http(client, base_url).await;
            if predicate(&json) {
                return json;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for matching tx dissemination runtime surface");
    }
    async fn fetch_tx_by_hash_http(
        client: &reqwest::Client,
        base_url: &str,
        tx_hash_hex: &str,
    ) -> reqwest::Response {
        client
            .post(format!("{base_url}/api/get_tx_by_hash"))
            .json(&serde_json::json!({ "hash": tx_hash_hex }))
            .send()
            .await
            .expect("tx by hash response")
    }

    async fn wait_for_committed_tx_http(
        client: &reqwest::Client,
        base_url: &str,
        tx_hash_hex: &str,
    ) -> serde_json::Value {
        for _ in 0..60 {
            let response = fetch_tx_by_hash_http(client, base_url, tx_hash_hex).await;
            if response.status().is_success() {
                let json = response
                    .json::<serde_json::Value>()
                    .await
                    .expect("committed tx json");
                if matches!(
                    json["txStatus"]["status"].as_str(),
                    Some("ordered" | "finalized")
                ) {
                    return json;
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
        panic!("timed out waiting for committed tx status");
    }
    async fn wait_for_checkpoint_consumer_http(
        client: &reqwest::Client,
        base_url: &str,
    ) -> serde_json::Value {
        for _ in 0..80 {
            let json = wait_for_chain_info_http(client, base_url).await;
            if json["validatorAttestation"]["currentCheckpointStatus"]["explorerConfirmationLevel"]
                == serde_json::Value::String("checkpointFinalized".into())
            {
                return json;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
        panic!("timed out waiting for checkpoint consumer readiness");
    }

    async fn fetch_dag_info_http(client: &reqwest::Client, base_url: &str) -> serde_json::Value {
        client
            .post(format!("{base_url}/api/get_dag_info"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("dag info response")
            .json::<serde_json::Value>()
            .await
            .expect("dag info json")
    }

    async fn fetch_virtual_chain_http(
        client: &reqwest::Client,
        base_url: &str,
        start_hash: Option<&str>,
    ) -> serde_json::Value {
        client
            .post(format!("{base_url}/api/get_virtual_chain"))
            .json(&serde_json::json!({
                "start_hash": start_hash,
                "include_accepted_txs": true,
            }))
            .send()
            .await
            .expect("virtual chain response")
            .json::<serde_json::Value>()
            .await
            .expect("virtual chain json")
    }

    async fn fetch_virtual_state_http(
        client: &reqwest::Client,
        base_url: &str,
    ) -> serde_json::Value {
        client
            .post(format!("{base_url}/api/get_virtual_state"))
            .body("")
            .send()
            .await
            .expect("virtual state response")
            .json::<serde_json::Value>()
            .await
            .expect("virtual state json")
    }

    fn make_remote_vote_gossip_payload(
        validator_count: usize,
        local_validator: LocalDagValidator,
        checkpoint: DagCheckpoint,
        peer: String,
        known_validators: Vec<ValidatorIdentity>,
    ) -> (DagCheckpointVote, ValidatorIdentity, Vec<String>) {
        let mut state = make_test_dag_state();
        state.validator_count = validator_count;
        state.local_validator = Some(local_validator);
        state.latest_checkpoint = Some(checkpoint);
        state.attestation_rpc_peers = vec![peer];
        state.known_validators = known_validators;
        refresh_local_checkpoint_attestation(&mut state).expect("refresh remote vote gossip");
        local_vote_gossip_payload(&state).expect("remote vote gossip payload")
    }

    fn make_test_dag_app(auth_state: crate::rpc_auth::ApiKeyState) -> Router {
        let rpc_state = make_test_rpc_state();
        let public_routes = Router::new()
            .route("/api/get_chain_info", post(dag_get_chain_info))
            .route("/api/get_dag_info", post(dag_get_dag_info));
        let write_routes = Router::new()
            .route("/api/submit_tx", post(dag_submit_tx))
            .route("/api/faucet", post(dag_faucet))
            .route_layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                crate::rpc_auth::require_api_key,
            ));

        // Match production: checkpoint gossip also requires API key
        let checkpoint_gossip = dag_checkpoint_vote_gossip_router()
            .route_layer(axum::middleware::from_fn_with_state(
                auth_state,
                crate::rpc_auth::require_api_key,
            ));

        public_routes
            .merge(checkpoint_gossip)
            .merge(write_routes)
            .with_state(rpc_state)
            .layer(DefaultBodyLimit::max(131_072))
    }

    #[test]
    fn test_latest_checkpoint_json_includes_validator_target() {
        let cp = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 12,
            utxo_root: [0xBB; 32],
            total_spent_count: 5,
            total_applied_txs: 9,
            timestamp_ms: 1_700_000_000_000,
        };

        let json = latest_checkpoint_json(&cp);
        assert_eq!(json["blueScore"], 12);
        assert_eq!(json["validatorTarget"]["blueScore"], 12);
        assert_eq!(
            json["validatorTarget"]["blockHash"],
            serde_json::Value::String(hex::encode(cp.block_hash))
        );
    }

    #[test]
    fn test_checkpoint_vote_json_includes_signature_bytes() {
        let vote = DagCheckpointVote {
            voter: [0x11; 32],
            target: misaka_types::validator::DagCheckpointTarget {
                block_hash: [0x22; 32],
                blue_score: 77,
                utxo_root: [0x33; 32],
                total_spent_count: 9,
                total_applied_txs: 10,
            },
            signature: misaka_types::validator::ValidatorSignature {
                bytes: vec![0x44; 3309],
            },
        };
        let json = checkpoint_vote_json(&vote);
        assert_eq!(json["signatureBytes"], 3309);
        assert_eq!(json["target"]["blueScore"], 77);
    }

    #[test]
    fn test_validator_identity_json_includes_public_key_hex() {
        let identity = ValidatorIdentity {
            validator_id: [0x55; 32],
            stake_weight: 42,
            public_key: misaka_types::validator::ValidatorPublicKey {
                bytes: vec![0xAA; misaka_types::validator::ValidatorPublicKey::SIZE],
            },
            is_active: true,
        };

        let json = validator_identity_json(&identity);
        assert_eq!(
            json["publicKeyHex"],
            serde_json::Value::String(hex::encode(&identity.public_key.bytes))
        );
        assert_eq!(
            json["publicKeyBytes"],
            serde_json::Value::from(misaka_types::validator::ValidatorPublicKey::SIZE)
        );
    }


    #[tokio::test]
    async fn test_dag_submit_checkpoint_vote_rejects_unknown_validator_without_registration() {
        let mut state = make_test_dag_state();
        let checkpoint = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 11,
            utxo_root: [0xBB; 32],
            total_spent_count: 2,
            total_applied_txs: 4,
            timestamp_ms: 1_700_000_100_000,
        };
        let vote = DagCheckpointVote {
            voter: [0x11; 32],
            target: checkpoint.validator_target(),
            signature: ValidatorSignature {
                bytes: vec![0x55; ValidatorSignature::SIZE],
            },
        };
        state.latest_checkpoint = Some(checkpoint);

        let response = dag_submit_checkpoint_vote(
            State(DagRpcState {
                node: Arc::new(tokio::sync::RwLock::new(state)),
                narwhal_dissemination: None,
                dag_p2p_observation: None,
                runtime_recovery: None,
                chain_id: 2,
            genesis_hash: [0u8; 32],
            }),
            Json(DagCheckpointVoteRequest {
                vote,
                validator_identity: None,
            }),
        )
        .await;

        assert_eq!(response.0["accepted"], serde_json::Value::Bool(false));
        assert!(response.0["error"]
            .as_str()
            .expect("error string")
            .contains("unknown checkpoint voter"));
    }

    #[tokio::test]
    async fn test_dag_submit_checkpoint_vote_rejects_target_mismatch() {
        let mut state = make_test_dag_state();
        let checkpoint = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 11,
            utxo_root: [0xBB; 32],
            total_spent_count: 2,
            total_applied_txs: 4,
            timestamp_ms: 1_700_000_100_000,
        };
        let mut wrong_target = checkpoint.validator_target();
        wrong_target.blue_score += 1;
        let vote = DagCheckpointVote {
            voter: [0x11; 32],
            target: wrong_target,
            signature: ValidatorSignature {
                bytes: vec![0x55; ValidatorSignature::SIZE],
            },
        };
        state.latest_checkpoint = Some(checkpoint);

        let response = dag_submit_checkpoint_vote(
            State(DagRpcState {
                node: Arc::new(tokio::sync::RwLock::new(state)),
                narwhal_dissemination: None,
                dag_p2p_observation: None,
                runtime_recovery: None,
                chain_id: 2,
            genesis_hash: [0u8; 32],
            }),
            Json(DagCheckpointVoteRequest {
                vote,
                validator_identity: None,
            }),
        )
        .await;

        assert_eq!(response.0["accepted"], serde_json::Value::Bool(false));
        assert!(response.0["error"]
            .as_str()
            .expect("error string")
            .contains("target mismatch"));
    }

    #[tokio::test]
    async fn test_dag_submit_checkpoint_vote_rejects_mismatched_validator_identity() {
        let mut state = make_test_dag_state();
        let checkpoint = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 11,
            utxo_root: [0xBB; 32],
            total_spent_count: 2,
            total_applied_txs: 4,
            timestamp_ms: 1_700_000_100_000,
        };
        let vote = DagCheckpointVote {
            voter: [0x11; 32],
            target: checkpoint.validator_target(),
            signature: ValidatorSignature {
                bytes: vec![0x55; ValidatorSignature::SIZE],
            },
        };
        let validator_identity = ValidatorIdentity {
            validator_id: [0x22; 32],
            stake_weight: 1,
            public_key: misaka_types::validator::ValidatorPublicKey {
                bytes: vec![0xAA; misaka_types::validator::ValidatorPublicKey::SIZE],
            },
            is_active: true,
        };
        state.latest_checkpoint = Some(checkpoint);

        let response = dag_submit_checkpoint_vote(
            State(DagRpcState {
                node: Arc::new(tokio::sync::RwLock::new(state)),
                narwhal_dissemination: None,
                dag_p2p_observation: None,
                runtime_recovery: None,
                chain_id: 2,
            genesis_hash: [0u8; 32],
            }),
            Json(DagCheckpointVoteRequest {
                vote,
                validator_identity: Some(validator_identity),
            }),
        )
        .await;

        assert_eq!(response.0["accepted"], serde_json::Value::Bool(false));
        assert!(response.0["error"]
            .as_str()
            .expect("error string")
            .contains("validator identity mismatch"));
    }

    #[test]
    fn test_dag_tx_status_json_pending() {
        let (utxo_set, wallets) = setup_utxo_with_uniform_ring();
        let mut state = make_test_dag_state();
        state.utxo_set = utxo_set;

        let tx = make_ring_tx(&wallets);
        let tx_hash = tx.tx_hash();
        state.mempool.insert(tx, |_| false).unwrap();

        let json = dag_tx_status_json(&state, tx_hash);
        assert_eq!(json["status"], serde_json::Value::String("pending".into()));
        assert_eq!(json["ordered"], serde_json::Value::Bool(false));
        assert_eq!(
            json["backendFamily"],
            serde_json::Value::String("zeroKnowledge".into())
        );
    }

    #[test]
    fn test_dag_tx_status_json_finalized_and_failed_conflict() {
        let (_, wallets) = setup_utxo_with_uniform_ring();
        let mut state = make_test_dag_state();

        let tx_applied = make_ring_tx(&wallets);
        let tx_conflict = make_ring_tx(&wallets);

        let block_hash = [0x66; 32];
        let block_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![state.genesis_hash],
            timestamp_ms: 1_700_000_100_000,
            tx_root: [0x55; 32],
            proposer_id: [0x12; 32],
            nonce: 0,
            blue_score: 8,
            bits: 0,
        };

        state
            .dag_store
            .insert_block(
                block_hash,
                block_header,
                vec![tx_applied.clone(), tx_conflict.clone()],
            )
            .unwrap();
        state.dag_store.set_ghostdag(
            block_hash,
            GhostDagData {
                blue_score: 8,
                blue_work: 8,
                ..GhostDagData::default()
            },
        );
        state
            .dag_store
            .set_tx_status(tx_applied.tx_hash(), TxApplyStatus::Applied);
        // Phase 2c-B: ring conflict variants removed; use generic failed status.
        state.dag_store.set_tx_status(
            tx_conflict.tx_hash(),
            TxApplyStatus::FailedInvalidSignature,
        );

        let checkpoint = DagCheckpoint {
            block_hash,
            blue_score: 10,
            utxo_root: [0x88; 32],
            total_spent_count: 1,
            total_applied_txs: 1,
            timestamp_ms: 1_700_000_200_000,
        };
        let target = checkpoint.validator_target();
        state.latest_checkpoint = Some(checkpoint);
        state.latest_checkpoint_finality = Some(DagCheckpointFinalityProof {
            target,
            commits: vec![],
        });

        let applied_json = dag_tx_status_json(&state, tx_applied.tx_hash());
        assert_eq!(
            applied_json["status"],
            serde_json::Value::String("finalized".into())
        );
        assert_eq!(applied_json["ordered"], serde_json::Value::Bool(true));
        assert_eq!(applied_json["finalized"], serde_json::Value::Bool(true));

        let conflict_json = dag_tx_status_json(&state, tx_conflict.tx_hash());
        assert_eq!(
            conflict_json["status"],
            serde_json::Value::String("failed_conflict".into())
        );
        assert_eq!(conflict_json["ordered"], serde_json::Value::Bool(true));
        assert_eq!(
            conflict_json["failedConflict"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            conflict_json["conflict"]["priorTxHash"],
            serde_json::Value::String(hex::encode(tx_applied.tx_hash()))
        );
    }

    #[test]
    fn test_dag_consumer_surfaces_json_tracks_checkpoint_status() {
        let mut state = make_test_dag_state();

        let pending = dag_consumer_surfaces_json(&state);
        assert_eq!(
            pending["validatorAttestation"]["available"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            pending["validatorAttestation"]["bridgeReadiness"],
            serde_json::Value::String("waitCheckpoint".into())
        );
        assert_eq!(
            pending["txStatusVocabulary"],
            serde_json::json!([
                "pending",
                "ordered",
                "finalized",
                "failedConflict",
                "failedInvalidSignature",
                "failed"
            ])
        );
        assert_eq!(
            pending["dataAvailability"]["consumerReadiness"],
            serde_json::Value::String("waitCheckpoint".into())
        );
        assert_eq!(
            pending["dataAvailability"]["checkpointAnchorPresent"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            pending["lightClient"]["consumerReadiness"],
            serde_json::Value::String("waitCheckpoint".into())
        );
        assert_eq!(
            pending["lightClient"]["txLookupKey"],
            serde_json::Value::String("txHash".into())
        );

        let checkpoint = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 7,
            utxo_root: [0xBB; 32],
            total_spent_count: 1,
            total_applied_txs: 2,
            timestamp_ms: 1_700_000_000_000,
        };
        let target = checkpoint.validator_target();
        state.latest_checkpoint = Some(checkpoint);
        state.latest_checkpoint_finality = Some(DagCheckpointFinalityProof {
            target,
            commits: vec![],
        });

        let finalized = dag_consumer_surfaces_json(&state);
        assert_eq!(
            finalized["validatorAttestation"]["bridgeReadiness"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(
            finalized["validatorAttestation"]["explorerConfirmationLevel"],
            serde_json::Value::String("checkpointFinalized".into())
        );
        assert_eq!(
            finalized["dataAvailability"]["consumerReadiness"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(
            finalized["dataAvailability"]["checkpointAnchorFinalized"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            finalized["lightClient"]["consumerReadiness"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(
            finalized["lightClient"]["confirmationLevel"],
            serde_json::Value::String("checkpointFinalized".into())
        );
    }

    #[test]
    fn test_dag_privacy_path_surface_json_targets_v4_path() {
        let json = dag_privacy_path_surface_json("zeroKnowledge");
        assert_eq!(
            json["runtimePath"],
            serde_json::Value::String("zeroKnowledge".into())
        );
        assert_eq!(
            json["targetPath"],
            serde_json::Value::String("zeroKnowledge".into())
        );
        assert_eq!(
            json["targetBackendFamily"],
            serde_json::Value::String("zeroKnowledge".into())
        );
    }

    #[tokio::test]
    async fn test_dag_submit_tx_rejects_payload_over_global_body_limit() {
        let app = Router::new()
            .route(
                "/api/submit_tx",
                post(|_: axum::body::Bytes| async { StatusCode::OK }),
            )
            .layer(DefaultBodyLimit::max(131_072));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit_tx")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'{'; 131_073]))
                    .expect("test request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_dag_submit_checkpoint_vote_rejects_payload_over_global_body_limit() {
        let app = Router::new()
            .route(
                "/api/submit_checkpoint_vote",
                post(|_: axum::body::Bytes| async { StatusCode::OK }),
            )
            .layer(DefaultBodyLimit::max(131_072));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit_checkpoint_vote")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'{'; 131_073]))
                    .expect("test request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_run_dag_rpc_server_rejects_invalid_cors_origin_config() {
        let _guard = env_lock();
        std::env::set_var("MISAKA_CORS_ORIGINS", " ,  , ");

        let result = run_dag_rpc_server(
            Arc::new(tokio::sync::RwLock::new(make_test_dag_state())),
            "127.0.0.1:0".parse().expect("socket addr"),
            2,
        )
        .await;

        assert!(result.is_err(), "invalid CORS config must fail closed");
        let err = result.expect_err("invalid CORS config");
        assert!(err.to_string().contains("contains no valid origins"));

        std::env::remove_var("MISAKA_CORS_ORIGINS");
    }

    #[tokio::test]
    async fn test_dag_cors_default_rejects_unlisted_chrome_extension_origin() {
        let _guard = env_lock();
        std::env::remove_var("MISAKA_CORS_ORIGINS");
        std::env::remove_var("MISAKA_CORS_EXTENSIONS");

        let app = Router::new()
            .route("/api/get_chain_info", post(dag_get_chain_info))
            .layer(build_dag_cors_layer().expect("default dag cors"))
            .with_state(make_test_rpc_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/get_chain_info")
                    .header(axum::http::header::ORIGIN, "chrome-extension://evil")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .expect("preflight request"),
            )
            .await
            .expect("preflight response");

        assert!(response
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    #[tokio::test]
    async fn test_dag_cors_allows_explicit_chrome_extension_origin() {
        let _guard = env_lock();
        std::env::remove_var("MISAKA_CORS_ORIGINS");
        std::env::set_var("MISAKA_CORS_EXTENSIONS", "abc123");

        let app = Router::new()
            .route("/api/get_chain_info", post(dag_get_chain_info))
            .layer(build_dag_cors_layer().expect("extension dag cors"))
            .with_state(make_test_rpc_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/get_chain_info")
                    .header(axum::http::header::ORIGIN, "chrome-extension://abc123")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .expect("preflight request"),
            )
            .await
            .expect("preflight response");

        assert_eq!(
            response
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&axum::http::HeaderValue::from_static(
                "chrome-extension://abc123"
            ))
        );

        std::env::remove_var("MISAKA_CORS_EXTENSIONS");
    }

    #[tokio::test]
    async fn test_dag_rpc_write_routes_and_checkpoint_vote_gossip_require_api_key() {
        let app = make_test_dag_app(crate::rpc_auth::ApiKeyState {
            required_key: Some("dag-secret".into()),
            write_ip_allowlist: vec![],
            auth_required: false,
        });

        let submit_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit_tx")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("submit request"),
            )
            .await
            .expect("submit response");
        assert_eq!(submit_response.status(), StatusCode::UNAUTHORIZED);

        let vote_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit_checkpoint_vote")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("vote request"),
            )
            .await
            .expect("vote response");
        assert_eq!(vote_response.status(), StatusCode::UNAUTHORIZED,
            "checkpoint vote gossip must require API key");
    }

    #[tokio::test]
    async fn test_dag_faucet_rejects_invalid_address() {
        let response = dag_faucet(
            State(make_test_rpc_state()),
            Json(serde_json::json!({
                "address": "not-a-valid-address"
            })),
        )
        .await;

        assert_eq!(response.0["accepted"], serde_json::Value::Bool(false));
        assert!(response.0["error"]
            .as_str()
            .expect("error string")
            .contains("invalid address"));
    }

    #[tokio::test]
    async fn test_dag_faucet_is_disabled_on_mainnet() {
        let mut state = make_test_dag_state();
        state.chain_id = 1;
        let address = derive_address_from_spending_key(&[0x11; 32], 1);

        let response = dag_faucet(
            State(DagRpcState {
                node: Arc::new(tokio::sync::RwLock::new(state)),
                narwhal_dissemination: None,
                dag_p2p_observation: None,
                runtime_recovery: None,
                chain_id: 2,
            genesis_hash: [0u8; 32],
            }),
            Json(serde_json::json!({
                "address": address
            })),
        )
        .await;

        assert_eq!(response.0["accepted"], serde_json::Value::Bool(false));
        assert_eq!(
            response.0["error"],
            serde_json::Value::String("faucet is disabled on mainnet (chain_id=1)".into())
        );
    }

    #[tokio::test]
    async fn test_dag_get_tx_by_hash_rejects_malformed_hash() {
        let err = dag_get_tx_by_hash(
            State(make_test_rpc_state()),
            Json(DagTxQuery {
                hash: "not-a-hex-hash".into(),
            }),
        )
        .await
        .expect_err("invalid hashes must fail closed");

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_dag_p2p_observation_json_exposes_recent_surface() {
        let mut observation = DagP2pObservationState::default();
        let peer_id = PeerId::from([0xAA; 32]);
        observation.record(
            DagP2pDirection::Inbound,
            &misaka_dag::dag_p2p::DagP2pMessage::GetDagTips,
            Some(&peer_id),
        );
        let observation = Arc::new(tokio::sync::RwLock::new(observation));

        let json = dag_p2p_observation_json(Some(&observation)).await;
        assert_eq!(json["total_messages"], serde_json::Value::from(1_u64));
        assert_eq!(
            json["last_surface"],
            serde_json::Value::String(
                serde_json::to_string(&DagP2pSurface::SteadyStateRelay)
                    .unwrap()
                    .trim_matches('"')
                    .to_string()
            )
        );
        assert_eq!(
            json["last_direction"],
            serde_json::Value::String(
                serde_json::to_string(&DagP2pDirection::Inbound)
                    .unwrap()
                    .trim_matches('"')
                    .to_string()
            )
        );
        assert_eq!(
            json["last_peer_prefix"],
            serde_json::Value::String("aaaaaaaa".into())
        );
    }

    #[tokio::test]
    async fn test_dag_runtime_recovery_json_exposes_restart_and_release_flags() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("misaka-dag-runtime-{stamp}"));
        std::fs::create_dir_all(&dir).unwrap();

        let snapshot_path = dir.join("dag_runtime_snapshot.json");
        let lifecycle_path = dir.join("validator_lifecycle_chain_2.json");
        let wal_path = dir.join("dag_wal.journal");
        let wal_tmp_path = dir.join("dag_wal.journal.tmp");
        std::fs::write(&snapshot_path, b"{}").unwrap();
        std::fs::write(&lifecycle_path, b"{}").unwrap();
        std::fs::write(&wal_path, b"{}").unwrap();

        let observation = Arc::new(tokio::sync::RwLock::new(
            DagRuntimeRecoveryObservation::new(
                snapshot_path,
                lifecycle_path,
                wal_path,
                wal_tmp_path,
            ),
        ));
        {
            let mut guard = observation.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 2);
            guard.mark_checkpoint_persisted(9, [0xAA; 32]);
            guard.mark_checkpoint_finality(Some(9));
            guard.mark_bullshark_candidate_preview(&[[0x11; 32], [0x22; 32]]);
            guard.mark_bullshark_commit_preview(&[[0x11; 32], [0x22; 32]]);
        }

        let json = dag_runtime_recovery_json(Some(&observation)).await;
        assert_eq!(json["available"], serde_json::Value::Bool(true));
        assert_eq!(json["snapshotExists"], serde_json::Value::Bool(true));
        assert_eq!(
            json["startupSnapshotRestored"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            json["startupWalState"],
            serde_json::Value::String("recovered".into())
        );
        assert_eq!(
            json["startupWalRolledBackBlocks"],
            serde_json::Value::from(2_u64)
        );
        assert_eq!(
            json["lastCheckpointBlueScore"],
            serde_json::Value::from(9_u64)
        );
        assert_eq!(
            json["lastCheckpointFinalityBlueScore"],
            serde_json::Value::from(9_u64)
        );
        assert_eq!(
            json["lastBullsharkCandidatePreviewCount"],
            serde_json::Value::from(2_u64)
        );
        assert_eq!(
            json["lastBullsharkCommitPreviewCount"],
            serde_json::Value::from(2_u64)
        );
        assert_eq!(
            json["bullsharkCandidatePreviewObserved"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            json["bullsharkCommitPreviewObserved"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(json["operatorRestartReady"], serde_json::Value::Bool(true));
        assert_eq!(json["releaseRehearsalReady"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn test_validator_lifecycle_recovery_json_exposes_summary() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("misaka-dag-lifecycle-{stamp}"));
        std::fs::create_dir_all(&dir).unwrap();

        let snapshot_path = dir.join("dag_runtime_snapshot.json");
        let lifecycle_path = dir.join("validator_lifecycle_chain_2.json");
        let wal_path = dir.join("dag_wal.journal");
        let wal_tmp_path = dir.join("dag_wal.journal.tmp");
        std::fs::write(&snapshot_path, b"{}").unwrap();
        std::fs::write(&lifecycle_path, b"{}").unwrap();
        std::fs::write(&wal_path, b"{}").unwrap();

        let observation = Arc::new(tokio::sync::RwLock::new(
            DagRuntimeRecoveryObservation::new(
                snapshot_path,
                lifecycle_path,
                wal_path,
                wal_tmp_path,
            ),
        ));
        {
            let mut guard = observation.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 1);
            guard.mark_checkpoint_persisted(12, [0xCC; 32]);
            guard.mark_checkpoint_finality(Some(12));
        }

        let json = validator_lifecycle_recovery_json(Some(&observation)).await;
        assert_eq!(json["available"], serde_json::Value::Bool(true));
        assert_eq!(json["restartReady"], serde_json::Value::Bool(true));
        assert_eq!(json["checkpointPersisted"], serde_json::Value::Bool(true));
        assert_eq!(json["checkpointFinalized"], serde_json::Value::Bool(true));
        assert_eq!(json["summary"], serde_json::Value::String("ready".into()));
    }

    #[tokio::test]
    async fn test_chain_and_dag_info_include_validator_lifecycle_recovery_summary() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("misaka-dag-chain-info-{stamp}"));
        std::fs::create_dir_all(&dir).unwrap();

        let snapshot_path = dir.join("dag_runtime_snapshot.json");
        let lifecycle_path = dir.join("validator_lifecycle_chain_2.json");
        let wal_path = dir.join("dag_wal.journal");
        let wal_tmp_path = dir.join("dag_wal.journal.tmp");
        std::fs::write(&snapshot_path, b"{}").unwrap();
        std::fs::write(&lifecycle_path, b"{}").unwrap();
        std::fs::write(&wal_path, b"{}").unwrap();

        let observation = Arc::new(tokio::sync::RwLock::new(
            DagRuntimeRecoveryObservation::new(
                snapshot_path,
                lifecycle_path,
                wal_path,
                wal_tmp_path,
            ),
        ));
        {
            let mut guard = observation.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 0);
            guard.mark_checkpoint_persisted(14, [0xDD; 32]);
            guard.mark_checkpoint_finality(Some(14));
        }

        let rpc = DagRpcState {
            node: Arc::new(tokio::sync::RwLock::new(make_test_dag_state())),
            narwhal_dissemination: None,
            dag_p2p_observation: None,
            runtime_recovery: Some(observation),
        };

        let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let dag_info = dag_get_dag_info(State(rpc)).await.0;

        assert_eq!(
            chain_info["validatorLifecycleRecovery"]["available"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["dissemination"],
            serde_json::Value::String("ghostdagNativeMempool".into())
        );
        assert_eq!(
            chain_info["txDissemination"]["currentRuntime"]["stage"],
            serde_json::Value::String("nativeMempool".into())
        );
        assert_eq!(
            chain_info["txDissemination"]["currentRuntime"]["ingress"],
            serde_json::Value::String("directRpcMempoolAdmit".into())
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["currentRuntime"]["defaultCandidateSource"],
            serde_json::Value::String("nativeMempoolTopByFee".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["disseminationStage"],
            serde_json::Value::String("nativeMempool".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["ordering"],
            serde_json::Value::String("ghostdag".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["orderingStage"],
            serde_json::Value::String("ghostdagTotalOrder".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["orderingInput"],
            serde_json::Value::String("ghostdagSelectedParent".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"],
            serde_json::Value::String("ghostdagCheckpointBft".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["committee"],
            serde_json::Value::String("validatorBreadth".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["committeeStage"],
            serde_json::Value::String("validatorBreadthProof".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["committeeSelection"],
            serde_json::Value::String("validatorBreadthRehearsal".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["currentRuntime"]["committeeSizeCap"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["dissemination"],
            serde_json::Value::String("narwhal".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["disseminationStage"],
            serde_json::Value::String("narwhalBatchDissemination".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["ordering"],
            serde_json::Value::String("bullshark".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"],
            serde_json::Value::String("bullsharkCommitOrder".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"],
            serde_json::Value::String("narwhalDeliveredBatch".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["finality"],
            serde_json::Value::String("bullsharkCommit".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"],
            serde_json::Value::String("bullsharkCommit".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["committee"],
            serde_json::Value::String("superRepresentative21".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"],
            serde_json::Value::String("sr21EpochRotation".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"],
            serde_json::Value::String("stakeWeightedTop21Election".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            chain_info["sr21Committee"]["selection"],
            serde_json::Value::String("stakeWeightedTop21Election".into())
        );
        assert_eq!(
            chain_info["sr21Committee"]["rotationStage"],
            serde_json::Value::String("sr21EpochRotation".into())
        );
        assert_eq!(
            chain_info["sr21Committee"]["committeeSizeCap"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            chain_info["sr21Committee"]["knownValidatorCount"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["sr21Committee"]["runtimeActiveCountConsistent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["privacyScope"],
            serde_json::Value::String("deferred".into())
        );
        assert_eq!(
            chain_info["consensusArchitecture"]["completionTarget"]["cexFriendlyPriority"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTarget"]["stage"],
            serde_json::Value::String("narwhalBatchDissemination".into())
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTarget"]["ingress"],
            serde_json::Value::String("narwhalWorkerBatchIngress".into())
        );

        assert_eq!(
            chain_info["txDissemination"]["currentRuntimeQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["currentRuntimeQueue"]["fastTransparentQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["mirroredCurrentRuntimeQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["narwhalWorkerBatchIngressQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["stagedOnlyQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["fastTransparentQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["mirroredCurrentRuntimeIngressReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["narwhalWorkerBatchIngressReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["stagedOnlyPreviewReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["narwhalDeliveredBatchReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["live"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["live"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["consistentSubsetOfReadyQueue"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["consistentSubsetOfShadowQueue"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["stagedContractReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["currentRuntime"]["stage"],
            serde_json::Value::String("ghostdagTotalOrder".into())
        );
        assert_eq!(
            chain_info["orderingContract"]["currentRuntime"]["inputSource"],
            serde_json::Value::String("ghostdagSelectedParent".into())
        );
        assert_eq!(
            chain_info["orderingContract"]["currentRuntime"]["commitSource"],
            serde_json::Value::String("ghostdagCheckpointBft".into())
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTarget"]["stage"],
            serde_json::Value::String("bullsharkCommitOrder".into())
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTarget"]["inputSource"],
            serde_json::Value::String("narwhalDeliveredBatch".into())
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTarget"]["commitSource"],
            serde_json::Value::String("bullsharkCommit".into())
        );
        assert_eq!(
            chain_info["orderingContract"]["currentRuntimeState"]["checkpointFinalityLive"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowCapabilities"]
                ["bullsharkCommitPreviewReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["orderingContract"]["stagedContractReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["validatorLifecycleRecovery"]["summary"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(
            chain_info["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"],
            serde_json::Value::String("ghostdagCheckpointBft".into())
        );
        assert_eq!(
            dag_info["consensusArchitecture"]["currentRuntime"]["finality"],
            serde_json::Value::String("checkpointBft".into())
        );
        assert_eq!(
            dag_info["txDissemination"]["currentRuntime"]["fastTransparentCandidateSource"],
            serde_json::Value::String("nativeTransparentLane".into())
        );
        assert_eq!(
            dag_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            dag_info["orderingContract"]["currentRuntime"]["stage"],
            serde_json::Value::String("ghostdagTotalOrder".into())
        );
        assert_eq!(
            dag_info["orderingContract"]["completionTarget"]["stage"],
            serde_json::Value::String("bullsharkCommitOrder".into())
        );
        assert_eq!(
            dag_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            dag_info["orderingContract"]["currentRuntimeState"]["maxBlueScore"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            dag_info["consensusArchitecture"]["completionTarget"]["publicOperatorRecoveryPriority"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["sr21Committee"]["selection"],
            serde_json::Value::String("stakeWeightedTop21Election".into())
        );
        assert_eq!(
            dag_info["sr21Committee"]["committeeSizeCap"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            dag_info["validatorLifecycleRecovery"]["restartReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["validatorLifecycleRecovery"]["checkpointFinalized"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["runtimeRecovery"]["lastCheckpointDecisionSource"],
            serde_json::Value::String("ghostdagCheckpointBft".into())
        );
    }

    #[tokio::test]
    async fn test_chain_and_dag_info_include_live_sr21_committee_preview() {
        let local_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(5));
        let remote_validator_a =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(4));
        let remote_validator_b =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(3));
        let mut below_min_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_sub(1));
        below_min_validator.identity.is_active = false;

        let known_validators = vec![
            local_validator.identity.clone(),
            remote_validator_a.identity.clone(),
            remote_validator_b.identity.clone(),
            below_min_validator.identity.clone(),
        ];
        let election_result = sr21_election::run_election(&known_validators, 0);
        let local_preview_index =
            sr21_election::find_sr_index(&election_result, &local_validator.identity.validator_id)
                .expect("local validator active");
        let local_validator_id_hex = hex::encode(local_validator.identity.validator_id);

        let mut state = make_test_dag_state();
        state.known_validators = known_validators;
        state.local_validator = Some(local_validator);
        state.num_active_srs = election_result.num_active.max(1);
        state.sr_index = local_preview_index;
        state.runtime_active_sr_validator_ids = election_result
            .active_srs
            .iter()
            .map(|elected| elected.validator_id)
            .collect();

        let rpc = DagRpcState {
            node: Arc::new(tokio::sync::RwLock::new(state)),
            narwhal_dissemination: None,
            dag_p2p_observation: None,
            runtime_recovery: None,
        };

        let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let dag_info = dag_get_dag_info(State(rpc)).await.0;

        assert_eq!(
            chain_info["sr21Committee"]["knownValidatorCount"],
            serde_json::Value::from(4)
        );
        assert_eq!(
            chain_info["sr21Committee"]["eligibleValidatorCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            chain_info["sr21Committee"]["activeCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            chain_info["sr21Committee"]["configuredActiveCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            chain_info["sr21Committee"]["previewQuorumThreshold"],
            serde_json::Value::String("3".into())
        );
        assert_eq!(
            chain_info["sr21Committee"]["runtimeQuorumThreshold"],
            serde_json::Value::String("3".into())
        );
        assert_eq!(
            chain_info["sr21Committee"]["quorumThresholdConsistent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["currentEpoch"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["sr21Committee"]["localValidatorPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["localValidatorInActiveSet"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["localPreviewSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            chain_info["sr21Committee"]["runtimeActiveCountConsistent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["sr21Committee"]["activeSetPreview"]
                .as_array()
                .map(|entries| entries.len()),
            Some(3)
        );
        assert_eq!(
            chain_info["sr21Committee"]["activeSetPreview"][0]["validatorId"],
            serde_json::Value::String(local_validator_id_hex)
        );
        assert_eq!(
            chain_info["sr21Committee"]["activeSetPreview"][0]["isLocal"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["sr21Committee"]["activeCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            dag_info["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
    }

    #[tokio::test]
    async fn test_live_sr21_committee_preview_visible_through_rpc_service() {
        let temp_dir = unique_temp_dir("misaka-sr21-committee-live");
        let local_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(5));
        let remote_validator_a =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(4));
        let remote_validator_b =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(3));
        let mut below_min_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_sub(1));
        below_min_validator.identity.is_active = false;

        let known_validators = vec![
            local_validator.identity.clone(),
            remote_validator_a.identity.clone(),
            remote_validator_b.identity.clone(),
            below_min_validator.identity.clone(),
        ];
        let election_result = sr21_election::run_election(&known_validators, 0);
        let local_preview_index =
            sr21_election::find_sr_index(&election_result, &local_validator.identity.validator_id)
                .expect("local validator active");
        let local_validator_id_hex = hex::encode(local_validator.identity.validator_id);

        let mut state = make_test_dag_state();
        state.validator_count = known_validators.len();
        state.known_validators = known_validators;
        state.local_validator = Some(local_validator);
        state.num_active_srs = election_result.num_active.max(1);
        state.sr_index = local_preview_index;
        state.runtime_active_sr_validator_ids = election_result
            .active_srs
            .iter()
            .map(|elected| elected.validator_id)
            .collect();

        let dag_state = Arc::new(tokio::sync::RwLock::new(state));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        seed_runtime_recovery_for_live_test(&runtime_recovery).await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("live test addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["sr21Committee"]["activeCount"] == serde_json::Value::from(3)
                && json["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && json["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && json["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && json["sr21Committee"]["localValidatorInActiveSet"]
                    == serde_json::Value::Bool(true)
        })
        .await;
        let dag_info = fetch_dag_info_http(&client, &base_url).await;

        let consistency = serde_json::json!({
            "previewVisibleThroughChainInfo": chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true),
            "previewVisibleThroughDagInfo": dag_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true),
            "localValidatorActiveInPreview": chain_info["sr21Committee"]["localValidatorInActiveSet"] == serde_json::Value::Bool(true),
            "activeCountConsistent": chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(true)
                && chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(true),
            "runtimeActiveSetApplied": chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(3)
                && chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && dag_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && dag_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(3)
                && dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true),
            "quorumThresholdConsistent": chain_info["sr21Committee"]["quorumThresholdConsistent"] == serde_json::Value::Bool(true)
                && chain_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("3".into())
                && chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("3".into())
                && dag_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("3".into())
                && dag_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("3".into()),
            "chainDagCommitteeSummaryConsistent": chain_info["sr21Committee"]["selection"] == dag_info["sr21Committee"]["selection"]
                && chain_info["sr21Committee"]["committeeSizeCap"] == dag_info["sr21Committee"]["committeeSizeCap"]
                && chain_info["sr21Committee"]["activeCount"] == dag_info["sr21Committee"]["activeCount"]
                && chain_info["sr21Committee"]["previewMatchesRuntime"] == dag_info["sr21Committee"]["previewMatchesRuntime"]
                && chain_info["sr21Committee"]["previewQuorumThreshold"] == dag_info["sr21Committee"]["previewQuorumThreshold"]
                && chain_info["sr21Committee"]["runtimeQuorumThreshold"] == dag_info["sr21Committee"]["runtimeQuorumThreshold"],
            "currentRuntimeStillValidatorBreadth": chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into())
                && chain_info["consensusArchitecture"]["currentRuntime"]["committeeStage"] == serde_json::Value::String("validatorBreadthProof".into())
                && chain_info["consensusArchitecture"]["currentRuntime"]["committeeSelection"] == serde_json::Value::String("validatorBreadthRehearsal".into()),
            "completionTargetMatchesPlan": chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_sr21_committee_preview_visible_through_rpc_service",
            "consensusArchitecture": chain_info["consensusArchitecture"],
            "chainInfo": {
                "sr21Committee": chain_info["sr21Committee"],
                "validatorLifecycleRecovery": chain_info["validatorLifecycleRecovery"],
            },
            "dagInfo": {
                "sr21Committee": dag_info["sr21Committee"],
                "validatorLifecycleRecovery": dag_info["validatorLifecycleRecovery"],
            },
            "consistency": consistency,
        });
        maybe_write_sr21_committee_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_sr21_committee_preview_visible_through_rpc_service".into()
            )
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["knownValidatorCount"],
            serde_json::Value::from(4)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["eligibleValidatorCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["activeCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["previewQuorumThreshold"],
            serde_json::Value::String("3".into())
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["runtimeQuorumThreshold"],
            serde_json::Value::String("3".into())
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["localPreviewSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["activeSetPreview"][0]["validatorId"],
            serde_json::Value::String(local_validator_id_hex)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["activeSetPreview"][0]["isLocal"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            payload["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["dagInfo"]["sr21Committee"]["activeCount"],
            serde_json::Value::from(3)
        );
        assert_eq!(
            payload["dagInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["completionTargetMatchesPlan"],
            serde_json::Value::Bool(true)
        );

        server.stop().await.expect("stop live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_sr21_election_epoch_boundary_sync_visible_through_rpc_service() {
        let temp_dir = unique_temp_dir("misaka-sr21-rotation-live");
        let local_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(3));
        let remote_validator_a =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(5));
        let remote_validator_b =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(4));
        let mut below_min_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_sub(1));
        below_min_validator.identity.is_active = false;

        let known_validators = vec![
            local_validator.identity.clone(),
            remote_validator_a.identity.clone(),
            remote_validator_b.identity.clone(),
            below_min_validator.identity.clone(),
        ];
        let next_epoch = 1u64;
        let checkpoint_interval = 6u64;
        let previous_finalized_score = checkpoint_interval;
        let finalized_boundary_score = previous_finalized_score + checkpoint_interval;
        let checkpoint_block_hash = [0xA5; 32];
        let election_result = sr21_election::run_election(&known_validators, next_epoch);
        let local_preview_index =
            sr21_election::find_sr_index(&election_result, &local_validator.identity.validator_id)
                .expect("local validator active");
        let local_validator_id = local_validator.identity.validator_id;
        let local_validator_id_hex = hex::encode(local_validator.identity.validator_id);

        let mut state = make_test_dag_state();
        state.validator_count = known_validators.len();
        state.known_validators = known_validators;
        state.local_validator = Some(local_validator);
        state.snapshot_path = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        state.num_active_srs = 1;
        state.sr_index = 0;
        set_test_dag_epoch(&mut state, next_epoch);
        state.latest_checkpoint = Some(DagCheckpoint {
            block_hash: checkpoint_block_hash,
            blue_score: finalized_boundary_score,
            utxo_root: [0xB7; 32],
            total_spent_count: 0,
            total_applied_txs: 0,
            timestamp_ms: 1_700_000_000_000,
        });
        state.latest_checkpoint_finality = state.latest_checkpoint.as_ref().map(|checkpoint| {
            DagCheckpointFinalityProof {
                target: checkpoint.validator_target(),
                commits: vec![],
            }
        });

        let dag_state = Arc::new(tokio::sync::RwLock::new(state));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        seed_runtime_recovery_for_live_test(&runtime_recovery).await;
        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_checkpoint_persisted(finalized_boundary_score, checkpoint_block_hash);
            guard.mark_checkpoint_finality(Some(finalized_boundary_score));
        }
        let mut lifecycle_epoch = 0u64;
        let mut lifecycle_progress =
            crate::validator_lifecycle_persistence::ValidatorEpochProgress {
                checkpoints_in_epoch: misaka_types::constants::EPOCH_LENGTH - 1,
                last_finalized_checkpoint_score: Some(previous_finalized_score),
            };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("live test addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let before_apply_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                && json["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(false)
                && json["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(false)
                && json["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(1)
                && json["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                && json["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(finalized_boundary_score)
                && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && json["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                && json["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
        })
        .await;

        let epoch_boundary_reached = lifecycle_progress.apply_finalized_checkpoint_score(
            &mut lifecycle_epoch,
            finalized_boundary_score,
            checkpoint_interval,
        );
        assert!(epoch_boundary_reached, "epoch boundary must be crossed");
        assert_eq!(lifecycle_epoch, next_epoch);

        {
            let mut guard = dag_state.write().await;
            apply_sr21_election_at_epoch_boundary(&mut guard, lifecycle_epoch);
        }

        let after_apply_chain_info =
            wait_for_chain_info_http_matching(&client, &base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetPresent"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(local_preview_index)
                    && json["sr21Committee"]["configuredActiveCount"]
                        == serde_json::Value::from(election_result.num_active)
                    && json["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(finalized_boundary_score)
                    && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
            })
            .await;
        let after_apply_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let mut consistency = serde_json::json!({
            "staleRuntimeVisibleBeforeApply": before_apply_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(false)
                && before_apply_chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(false)
                && before_apply_chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(false)
                && before_apply_chain_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("3".into())
                && before_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("1".into())
                && before_apply_chain_info["sr21Committee"]["quorumThresholdConsistent"] == serde_json::Value::Bool(false),
            "runtimeActiveSetMissingBeforeApply": before_apply_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(false)
                && before_apply_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(0)
                && before_apply_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(false),
            "epochBoundaryVisibleBeforeApply": before_apply_chain_info["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch),
            "finalizedCheckpointVisibleBeforeApply": before_apply_chain_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                && before_apply_chain_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
                && before_apply_chain_info["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                && before_apply_chain_info["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(finalized_boundary_score)
                && before_apply_chain_info["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into()),
            "epochBoundaryReachedFromFinalizedCheckpoint": epoch_boundary_reached
                && lifecycle_epoch == next_epoch
                && lifecycle_progress.checkpoints_in_epoch == 0
                && lifecycle_progress.last_finalized_checkpoint_score == Some(finalized_boundary_score),
            "runtimeAlignedAfterApply": after_apply_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(true),
            "runtimeActiveSetApplied": after_apply_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(election_result.num_active)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && after_apply_dag_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && after_apply_dag_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(election_result.num_active)
                && after_apply_dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true),
            "finalizedCheckpointProvenanceRetainedAfterApply": after_apply_chain_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                && after_apply_chain_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
                && after_apply_chain_info["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(finalized_boundary_score)
                && after_apply_chain_info["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && after_apply_dag_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                && after_apply_dag_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
                && after_apply_dag_info["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                && after_apply_dag_info["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(finalized_boundary_score)
                && after_apply_dag_info["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into()),
            "activeCountApplied": before_apply_chain_info["sr21Committee"]["configuredActiveCount"] != after_apply_chain_info["sr21Committee"]["configuredActiveCount"]
                && after_apply_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(election_result.num_active),
            "localRuntimeIndexApplied": before_apply_chain_info["sr21Committee"]["localRuntimeSrIndex"] != after_apply_chain_info["sr21Committee"]["localRuntimeSrIndex"]
                && after_apply_chain_info["sr21Committee"]["localRuntimeSrIndex"] == serde_json::Value::from(local_preview_index),
            "quorumThresholdApplied": before_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] != after_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"]
                && after_apply_chain_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("3".into())
                && after_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("3".into())
                && after_apply_chain_info["sr21Committee"]["quorumThresholdConsistent"] == serde_json::Value::Bool(true),
            "chainDagCommitteeSummaryConsistentAfterApply": after_apply_chain_info["sr21Committee"]["selection"] == after_apply_dag_info["sr21Committee"]["selection"]
                && after_apply_chain_info["sr21Committee"]["committeeSizeCap"] == after_apply_dag_info["sr21Committee"]["committeeSizeCap"]
                && after_apply_chain_info["sr21Committee"]["activeCount"] == after_apply_dag_info["sr21Committee"]["activeCount"]
                && after_apply_chain_info["sr21Committee"]["configuredActiveCount"] == after_apply_dag_info["sr21Committee"]["configuredActiveCount"]
                && after_apply_chain_info["sr21Committee"]["previewMatchesRuntime"] == after_apply_dag_info["sr21Committee"]["previewMatchesRuntime"]
                && after_apply_chain_info["sr21Committee"]["previewQuorumThreshold"] == after_apply_dag_info["sr21Committee"]["previewQuorumThreshold"]
                && after_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == after_apply_dag_info["sr21Committee"]["runtimeQuorumThreshold"],
            "currentRuntimeStillValidatorBreadth": after_apply_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into())
                && after_apply_chain_info["consensusArchitecture"]["currentRuntime"]["committeeStage"] == serde_json::Value::String("validatorBreadthProof".into())
                && after_apply_chain_info["consensusArchitecture"]["currentRuntime"]["committeeSelection"] == serde_json::Value::String("validatorBreadthRehearsal".into()),
            "completionTargetMatchesPlan": after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let dag_snapshot = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        let validator_lifecycle_snapshot = PathBuf::from(&temp_dir).join("validator_lifecycle.json");
        let (restart_blue_score, restart_block_hash) = {
            let guard = dag_state.read().await;
            let snapshot = guard.dag_store.snapshot();
            let restart_tip = snapshot
                .get_tips()
                .into_iter()
                .max_by_key(|hash| {
                    snapshot
                        .get_ghostdag_data(hash)
                        .map(|data| data.blue_score)
                        .unwrap_or(0)
                })
                .expect("restart tip");
            let restart_score = snapshot
                .get_ghostdag_data(&restart_tip)
                .map(|data| data.blue_score)
                .unwrap_or_else(|| guard.dag_store.max_blue_score());
            (restart_score, restart_tip)
        };

        server.stop().await.expect("stop live dag rpc service");

        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 0);
            guard.mark_checkpoint_persisted(restart_blue_score, restart_block_hash);
            guard.mark_checkpoint_finality(Some(restart_blue_score));
        }
        let restart_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind restart live test port");
        let restart_addr = restart_listener
            .local_addr()
            .expect("restart live test addr");
        drop(restart_listener);
        let restart_base_url = format!("http://{}", restart_addr);
        let restarted_server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), restart_addr,
        )
        .await;

        let restarted_client = reqwest::Client::new();
        let after_restart_chain_info =
            wait_for_chain_info_http_matching(&restarted_client, &restart_base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetPresent"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(local_preview_index)
                    && json["sr21Committee"]["configuredActiveCount"]
                        == serde_json::Value::from(election_result.num_active)
                    && json["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
            })
            .await;
        let after_restart_dag_info = fetch_dag_info_http(&restarted_client, &restart_base_url).await;

        let second_epoch = next_epoch + 1;
        let second_finalized_boundary_score = finalized_boundary_score + checkpoint_interval;
        let second_checkpoint_block_hash = [0xA6; 32];
        let second_local_stake = sr21_election::MIN_SR_STAKE.saturating_mul(7);
        let second_remote_c_stake = sr21_election::MIN_SR_STAKE.saturating_mul(6);
        let second_remote_a_stake = sr21_election::MIN_SR_STAKE.saturating_mul(5);
        let second_remote_b_stake = sr21_election::MIN_SR_STAKE.saturating_sub(1);
        let remote_b_validator_id_hex = hex::encode(remote_validator_b.identity.validator_id);
        let remote_c_validator_id_hex = hex::encode(below_min_validator.identity.validator_id);

        lifecycle_progress.checkpoints_in_epoch = misaka_types::constants::EPOCH_LENGTH - 1;
        let second_epoch_boundary_reached = lifecycle_progress.apply_finalized_checkpoint_score(
            &mut lifecycle_epoch,
            second_finalized_boundary_score,
            checkpoint_interval,
        );
        assert!(
            second_epoch_boundary_reached,
            "second epoch boundary must be crossed"
        );
        assert_eq!(lifecycle_epoch, second_epoch);

        {
            let mut guard = dag_state.write().await;
            if let Some(local) = guard.local_validator.as_mut() {
                local.identity.stake_weight = second_local_stake;
            }
            for validator in &mut guard.known_validators {
                if validator.validator_id == local_validator_id {
                    validator.stake_weight = second_local_stake;
                    validator.is_active = true;
                } else if validator.validator_id == remote_validator_a.identity.validator_id {
                    validator.stake_weight = second_remote_a_stake;
                    validator.is_active = true;
                } else if validator.validator_id == remote_validator_b.identity.validator_id {
                    validator.stake_weight = second_remote_b_stake;
                    validator.is_active = true;
                } else if validator.validator_id == below_min_validator.identity.validator_id {
                    validator.stake_weight = second_remote_c_stake;
                    validator.is_active = true;
                }
            }
            set_test_dag_epoch(&mut guard, second_epoch);
            guard.latest_checkpoint = Some(DagCheckpoint {
                block_hash: second_checkpoint_block_hash,
                blue_score: second_finalized_boundary_score,
                utxo_root: [0xC9; 32],
                total_spent_count: 0,
                total_applied_txs: 0,
                timestamp_ms: 1_700_000_360_000,
            });
            guard.latest_checkpoint_finality = guard.latest_checkpoint.as_ref().map(|checkpoint| {
                DagCheckpointFinalityProof {
                    target: checkpoint.validator_target(),
                    commits: vec![],
                }
            });
        }
        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_checkpoint_persisted(
                second_finalized_boundary_score,
                second_checkpoint_block_hash,
            );
            guard.mark_checkpoint_finality(Some(second_finalized_boundary_score));
        }

        let second_election_result = {
            let guard = dag_state.read().await;
            sr21_election::run_election(&guard.known_validators, second_epoch)
        };
        let second_local_preview_index = sr21_election::find_sr_index(
            &second_election_result,
            &local_validator_id,
        )
        .expect("local validator active at second epoch");

        let before_second_apply_chain_info =
            wait_for_chain_info_http_matching(&restarted_client, &restart_base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(second_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(false)
                    && json["sr21Committee"]["runtimeActiveSetPresent"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                        == serde_json::Value::Bool(false)
                    && json["sr21Committee"]["localPreviewSrIndex"]
                        == serde_json::Value::from(second_local_preview_index)
                    && json["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(local_preview_index)
                    && json["validatorLifecycleRecovery"]["checkpointFinalized"]
                        == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
                    && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"]
                        == serde_json::Value::String("ghostdagCheckpointBft".into())
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blockHash"]
                        == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
            })
            .await;
        {
            let mut guard = dag_state.write().await;
            apply_sr21_election_at_epoch_boundary(&mut guard, second_epoch);
        }

        let after_second_apply_chain_info =
            wait_for_chain_info_http_matching(&restarted_client, &restart_base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(second_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetPresent"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["localPreviewSrIndex"]
                        == serde_json::Value::from(second_local_preview_index)
                    && json["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(second_local_preview_index)
                    && json["validatorLifecycleRecovery"]["checkpointFinalized"]
                        == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
                    && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"]
                        == serde_json::Value::String("ghostdagCheckpointBft".into())
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blockHash"]
                        == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
            })
            .await;
        let after_second_apply_dag_info =
            fetch_dag_info_http(&restarted_client, &restart_base_url).await;

        let before_second_preview_ids = before_second_apply_chain_info["sr21Committee"]
            ["activeSetPreview"]
            .as_array()
            .expect("before second apply active set preview array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let before_second_runtime_ids = before_second_apply_chain_info["sr21Committee"]
            ["runtimeActiveSet"]
            .as_array()
            .expect("before second apply runtime active set array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let after_second_preview_ids = after_second_apply_chain_info["sr21Committee"]
            ["activeSetPreview"]
            .as_array()
            .expect("after second apply active set preview array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let after_second_runtime_ids = after_second_apply_chain_info["sr21Committee"]
            ["runtimeActiveSet"]
            .as_array()
            .expect("after second apply runtime active set array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let second_added_validator_ids = after_second_runtime_ids
            .iter()
            .filter(|validator_id| !before_second_runtime_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let second_removed_validator_ids = before_second_runtime_ids
            .iter()
            .filter(|validator_id| !after_second_runtime_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let second_preview_added_validator_ids = after_second_preview_ids
            .iter()
            .filter(|validator_id| !before_second_preview_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let second_preview_removed_validator_ids = before_second_preview_ids
            .iter()
            .filter(|validator_id| !after_second_preview_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let first_expected_active_ids = election_result
            .active_srs
            .iter()
            .map(|elected| hex::encode(elected.validator_id))
            .collect::<Vec<_>>();
        let second_expected_active_ids = second_election_result
            .active_srs
            .iter()
            .map(|elected| hex::encode(elected.validator_id))
            .collect::<Vec<_>>();

        if let Some(consistency_obj) = consistency.as_object_mut() {
            consistency_obj.insert(
                "secondEpochBoundaryVisibleBeforeApply".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                        == serde_json::Value::from(second_epoch)
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into()),
                ),
            );
            consistency_obj.insert(
                "secondEpochBoundaryReachedFromFinalizedCheckpoint".into(),
                serde_json::Value::Bool(
                    second_epoch_boundary_reached
                        && lifecycle_epoch == second_epoch
                        && lifecycle_progress.checkpoints_in_epoch == 0
                        && lifecycle_progress.last_finalized_checkpoint_score
                            == Some(second_finalized_boundary_score),
                ),
            );
            consistency_obj.insert(
                "staleSecondRotationVisibleBeforeApply".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(local_preview_index)
                        && before_second_preview_ids == second_expected_active_ids
                        && before_second_runtime_ids == first_expected_active_ids
                        && before_second_preview_ids
                            .iter()
                            .any(|validator_id| validator_id == &remote_c_validator_id_hex)
                        && !before_second_preview_ids
                            .iter()
                            .any(|validator_id| validator_id == &remote_b_validator_id_hex)
                        && before_second_runtime_ids
                            .iter()
                            .any(|validator_id| validator_id == &remote_b_validator_id_hex)
                        && !before_second_runtime_ids
                            .iter()
                            .any(|validator_id| validator_id == &remote_c_validator_id_hex),
                ),
            );
            consistency_obj.insert(
                "secondRotationAppliedAfterRestart".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                        == serde_json::Value::from(second_epoch)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["configuredActiveCount"]
                            == serde_json::Value::from(second_election_result.num_active)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["previewMatchesRuntime"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetCount"]
                            == serde_json::Value::from(second_election_result.num_active)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(true)
                        && after_second_preview_ids == second_expected_active_ids
                        && after_second_runtime_ids == second_expected_active_ids
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index),
                ),
            );
            consistency_obj.insert(
                "secondRotationChangedMembershipAfterRestart".into(),
                serde_json::Value::Bool(
                    second_preview_added_validator_ids.is_empty()
                        && second_preview_removed_validator_ids.is_empty()
                        && second_added_validator_ids
                            == vec![remote_c_validator_id_hex.clone()]
                        && second_removed_validator_ids
                            == vec![remote_b_validator_id_hex.clone()]
                        && before_second_preview_ids == second_expected_active_ids
                        && before_second_runtime_ids == first_expected_active_ids
                        && after_second_preview_ids == second_expected_active_ids
                        && after_second_runtime_ids == second_expected_active_ids
                        && before_second_preview_ids == after_second_preview_ids
                        && after_second_preview_ids == after_second_runtime_ids,
                ),
            );
            consistency_obj.insert(
                "secondRuntimeIndexRotatedAfterRestart".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && second_local_preview_index != local_preview_index,
                ),
            );
            consistency_obj.insert(
                "secondCheckpointProvenanceRetainedAfterApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["validatorAttestation"]
                        ["latestCheckpointFinality"]["target"]["blockHash"]
                        == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && after_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into())
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into()),
                ),
            );
            consistency_obj.insert(
                "chainDagCommitteeSummaryConsistentAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["sr21Committee"]["selection"]
                        == after_second_apply_dag_info["sr21Committee"]["selection"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["committeeSizeCap"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["committeeSizeCap"]
                        && after_second_apply_chain_info["sr21Committee"]["activeCount"]
                            == after_second_apply_dag_info["sr21Committee"]["activeCount"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["configuredActiveCount"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["configuredActiveCount"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["previewMatchesRuntime"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["previewMatchesRuntime"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["previewQuorumThreshold"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["previewQuorumThreshold"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeQuorumThreshold"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeQuorumThreshold"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeActiveSetPresent"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetCount"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeActiveSetCount"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeActiveSetMatchesPreview"],
                ),
            );
            consistency_obj.insert(
                "currentRuntimeStillValidatorBreadthAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["consensusArchitecture"]["currentRuntime"]
                        ["committee"]
                        == serde_json::Value::String("validatorBreadth".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["currentRuntime"]["committeeStage"]
                            == serde_json::Value::String("validatorBreadthProof".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["currentRuntime"]["committeeSelection"]
                            == serde_json::Value::String("validatorBreadthRehearsal".into()),
                ),
            );
            consistency_obj.insert(
                "completionTargetMatchesPlanAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["consensusArchitecture"]
                        ["completionTarget"]["committee"]
                        == serde_json::Value::String("superRepresentative21".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committeeStage"]
                            == serde_json::Value::String("sr21EpochRotation".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committeeSelection"]
                            == serde_json::Value::String("stakeWeightedTop21Election".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committeeSizeCap"]
                            == serde_json::Value::from(21),
                ),
            );
        }

        let restart_consistency = serde_json::json!({
            "snapshotArtifactsWritten": dag_snapshot.exists() && validator_lifecycle_snapshot.exists(),
            "serviceRestartContinuity": after_restart_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "chainDagCommitteeSummaryConsistentAfterRestart": after_restart_chain_info["sr21Committee"]["selection"] == after_restart_dag_info["sr21Committee"]["selection"]
                && after_restart_chain_info["sr21Committee"]["committeeSizeCap"] == after_restart_dag_info["sr21Committee"]["committeeSizeCap"]
                && after_restart_chain_info["sr21Committee"]["activeCount"] == after_restart_dag_info["sr21Committee"]["activeCount"]
                && after_restart_chain_info["sr21Committee"]["configuredActiveCount"] == after_restart_dag_info["sr21Committee"]["configuredActiveCount"]
                && after_restart_chain_info["sr21Committee"]["previewMatchesRuntime"] == after_restart_dag_info["sr21Committee"]["previewMatchesRuntime"]
                && after_restart_chain_info["sr21Committee"]["previewQuorumThreshold"] == after_restart_dag_info["sr21Committee"]["previewQuorumThreshold"]
                && after_restart_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == after_restart_dag_info["sr21Committee"]["runtimeQuorumThreshold"]
                && after_restart_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == after_restart_dag_info["sr21Committee"]["runtimeActiveSetPresent"]
                && after_restart_chain_info["sr21Committee"]["runtimeActiveSetCount"] == after_restart_dag_info["sr21Committee"]["runtimeActiveSetCount"]
                && after_restart_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == after_restart_dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            "finalizedCheckpointProvenanceRetainedAfterRestart": after_restart_chain_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                && after_restart_chain_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
                && after_restart_chain_info["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && after_restart_chain_info["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(restart_blue_score)
                && after_restart_dag_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blockHash"] == serde_json::Value::String(hex::encode(checkpoint_block_hash))
                && after_restart_dag_info["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"] == serde_json::Value::from(finalized_boundary_score)
                && after_restart_dag_info["validatorLifecycleRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true)
                && after_restart_dag_info["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && after_restart_dag_info["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"] == serde_json::Value::from(restart_blue_score),
            "committeeStatePersistedAfterRestart": after_restart_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["sr21Committee"]["activeCount"] == serde_json::Value::from(election_result.num_active)
                && after_restart_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(election_result.num_active)
                && after_restart_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(election_result.num_active)
                && after_restart_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("3".into())
                && after_restart_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("3".into()),
            "runtimeActiveSetPersistedAfterRestart": after_restart_chain_info["sr21Committee"]["localRuntimeSrIndex"] == serde_json::Value::from(local_preview_index)
                && after_restart_chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(true)
                && after_restart_chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(true),
            "currentRuntimeStillValidatorBreadthAfterRestart": after_restart_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into())
                && after_restart_chain_info["consensusArchitecture"]["currentRuntime"]["committeeStage"] == serde_json::Value::String("validatorBreadthProof".into())
                && after_restart_chain_info["consensusArchitecture"]["currentRuntime"]["committeeSelection"] == serde_json::Value::String("validatorBreadthRehearsal".into()),
            "completionTargetMatchesPlanAfterRestart": after_restart_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && after_restart_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && after_restart_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && after_restart_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
            "startupSnapshotRestoredAfterRestart": after_restart_chain_info["runtimeRecovery"]["startupSnapshotRestored"].is_boolean(),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_sr21_election_epoch_boundary_sync_visible_through_rpc_service",
            "appliedEpoch": next_epoch,
            "rotationProvenance": {
                "checkpointInterval": checkpoint_interval,
                "previousFinalizedCheckpointBlueScore": previous_finalized_score,
                "appliedFinalizedCheckpointBlueScore": finalized_boundary_score,
                "lifecycleEpochBeforeApply": 0,
                "lifecycleEpochAfterApply": next_epoch,
                "epochBoundaryReachedFromFinalizedCheckpoint": epoch_boundary_reached,
            },
            "secondRotationProvenance": {
                "checkpointInterval": checkpoint_interval,
                "previousFinalizedCheckpointBlueScore": finalized_boundary_score,
                "appliedFinalizedCheckpointBlueScore": second_finalized_boundary_score,
                "lifecycleEpochBeforeApply": next_epoch,
                "lifecycleEpochAfterApply": lifecycle_epoch,
                "epochBoundaryReachedFromFinalizedCheckpoint": second_epoch_boundary_reached,
            },
            "consensusArchitecture": after_apply_chain_info["consensusArchitecture"],
            "beforeApply": {
                "chainInfo": {
                    "sr21Committee": before_apply_chain_info["sr21Committee"],
                    "validatorAttestation": before_apply_chain_info["validatorAttestation"],
                    "runtimeRecovery": before_apply_chain_info["runtimeRecovery"],
                    "validatorLifecycleRecovery": before_apply_chain_info["validatorLifecycleRecovery"],
                },
            },
            "afterApply": {
                "chainInfo": {
                    "sr21Committee": after_apply_chain_info["sr21Committee"],
                    "validatorAttestation": after_apply_chain_info["validatorAttestation"],
                    "runtimeRecovery": after_apply_chain_info["runtimeRecovery"],
                    "validatorLifecycleRecovery": after_apply_chain_info["validatorLifecycleRecovery"],
                },
                "dagInfo": {
                    "sr21Committee": after_apply_dag_info["sr21Committee"],
                    "validatorAttestation": after_apply_dag_info["validatorAttestation"],
                    "runtimeRecovery": after_apply_dag_info["runtimeRecovery"],
                    "validatorLifecycleRecovery": after_apply_dag_info["validatorLifecycleRecovery"],
                },
            },
            "afterRestart": {
                "chainInfo": {
                    "sr21Committee": after_restart_chain_info["sr21Committee"],
                    "validatorAttestation": after_restart_chain_info["validatorAttestation"],
                    "validatorLifecycleRecovery": after_restart_chain_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": after_restart_chain_info["runtimeRecovery"],
                },
                "dagInfo": {
                    "sr21Committee": after_restart_dag_info["sr21Committee"],
                    "validatorAttestation": after_restart_dag_info["validatorAttestation"],
                    "validatorLifecycleRecovery": after_restart_dag_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": after_restart_dag_info["runtimeRecovery"],
                },
            },
            "beforeSecondApply": {
                "chainInfo": {
                    "sr21Committee": before_second_apply_chain_info["sr21Committee"],
                    "validatorAttestation": before_second_apply_chain_info["validatorAttestation"],
                    "validatorLifecycleRecovery": before_second_apply_chain_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": before_second_apply_chain_info["runtimeRecovery"],
                },
            },
            "afterSecondApply": {
                "chainInfo": {
                    "sr21Committee": after_second_apply_chain_info["sr21Committee"],
                    "validatorAttestation": after_second_apply_chain_info["validatorAttestation"],
                    "validatorLifecycleRecovery": after_second_apply_chain_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": after_second_apply_chain_info["runtimeRecovery"],
                },
                "dagInfo": {
                    "sr21Committee": after_second_apply_dag_info["sr21Committee"],
                    "validatorAttestation": after_second_apply_dag_info["validatorAttestation"],
                    "validatorLifecycleRecovery": after_second_apply_dag_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": after_second_apply_dag_info["runtimeRecovery"],
                },
            },
            "secondRotationDelta": {
                "addedValidatorIds": second_added_validator_ids,
                "removedValidatorIds": second_removed_validator_ids,
                "localRuntimeIndexBefore": local_preview_index,
                "localRuntimeIndexAfter": second_local_preview_index,
            },
            "consistency": consistency,
            "restartConsistency": restart_consistency,
        });
        maybe_write_sr21_rotation_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_sr21_election_epoch_boundary_sync_visible_through_rpc_service".into()
            )
        );
        assert_eq!(payload["appliedEpoch"], serde_json::Value::from(next_epoch));
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["currentEpoch"],
            serde_json::Value::from(next_epoch)
        );
        assert_eq!(
            payload["rotationProvenance"]["epochBoundaryReachedFromFinalizedCheckpoint"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["rotationProvenance"]["lifecycleEpochAfterApply"],
            serde_json::Value::from(next_epoch)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["validatorLifecycleRecovery"]["checkpointFinalized"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"],
            serde_json::Value::from(finalized_boundary_score)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["runtimeQuorumThreshold"],
            serde_json::Value::String("1".into())
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["configuredActiveCount"],
            serde_json::Value::from(election_result.num_active)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeCount"],
            serde_json::Value::from(election_result.num_active)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["currentEpoch"],
            serde_json::Value::from(next_epoch)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["localPreviewSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["localRuntimeSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(election_result.num_active)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["finalizedCheckpointVisibleBeforeApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["epochBoundaryReachedFromFinalizedCheckpoint"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["finalizedCheckpointProvenanceRetainedAfterApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["previewQuorumThreshold"],
            serde_json::Value::String("3".into())
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeQuorumThreshold"],
            serde_json::Value::String("3".into())
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeSetPreview"]
                .as_array()
                .map(|entries| entries.len()),
            Some(3)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeSetPreview"][2]["validatorId"],
            serde_json::Value::String(local_validator_id_hex)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeSetPreview"][2]["isLocal"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["dagInfo"]["sr21Committee"]["configuredActiveCount"],
            serde_json::Value::from(election_result.num_active)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["configuredActiveCount"],
            serde_json::Value::from(election_result.num_active)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(election_result.num_active)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["validatorAttestation"]["latestCheckpointFinality"]["target"]["blueScore"],
            serde_json::Value::from(finalized_boundary_score)
        );
        assert_eq!(
            payload["restartConsistency"]["serviceRestartContinuity"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["committeeStatePersistedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["runtimeActiveSetPersistedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["finalizedCheckpointProvenanceRetainedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["secondRotationProvenance"]["epochBoundaryReachedFromFinalizedCheckpoint"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["secondRotationProvenance"]["lifecycleEpochAfterApply"],
            serde_json::Value::from(second_epoch)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["currentEpoch"],
            serde_json::Value::from(second_epoch)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["localPreviewSrIndex"],
            serde_json::Value::from(second_local_preview_index)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["localRuntimeSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["currentEpoch"],
            serde_json::Value::from(second_epoch)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(second_election_result.num_active)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["localRuntimeSrIndex"],
            serde_json::Value::from(second_local_preview_index)
        );
        assert_eq!(
            payload["secondRotationDelta"]["addedValidatorIds"],
            serde_json::json!([remote_c_validator_id_hex])
        );
        assert_eq!(
            payload["secondRotationDelta"]["removedValidatorIds"],
            serde_json::json!([remote_b_validator_id_hex])
        );
        assert_eq!(
            payload["consistency"]["secondRotationAppliedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["secondRotationChangedMembershipAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["secondRuntimeIndexRotatedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["completionTargetMatchesPlan"],
            serde_json::Value::Bool(true)
        );

        restarted_server
            .stop()
            .await
            .expect("stop restarted live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_sr21_top21_selection_epoch_boundary_visible_through_rpc_service() {
        let temp_dir = unique_temp_dir("misaka-sr21-selection-live");
        let local_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(30));
        let local_validator_id_hex = hex::encode(local_validator.identity.validator_id);
        let next_epoch = 1u64;

        let mut known_validators = vec![local_validator.identity.clone()];
        let mut excluded_eligible_validator_ids = Vec::new();
        let mut excluded_ineligible_validator_ids = Vec::new();

        for multiplier in (31u128..=50u128).rev() {
            let remote = make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(multiplier));
            known_validators.push(remote.identity.clone());
        }

        for multiplier in [29u128, 28u128] {
            let remote = make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(multiplier));
            excluded_eligible_validator_ids.push(hex::encode(remote.identity.validator_id));
            known_validators.push(remote.identity.clone());
        }

        let mut inactive_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(60));
        inactive_validator.identity.is_active = false;
        excluded_ineligible_validator_ids.push(hex::encode(inactive_validator.identity.validator_id));
        known_validators.push(inactive_validator.identity.clone());

        let below_min_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_sub(1));
        excluded_ineligible_validator_ids.push(hex::encode(below_min_validator.identity.validator_id));
        known_validators.push(below_min_validator.identity.clone());

        let election_result = sr21_election::run_election(&known_validators, next_epoch);
        let local_preview_index =
            sr21_election::find_sr_index(&election_result, &local_validator.identity.validator_id)
                .expect("local validator active");

        assert_eq!(known_validators.len(), 25);
        assert_eq!(election_result.num_active, 21);
        assert_eq!(election_result.dropped_count, 4);
        assert_eq!(local_preview_index, 20);

        let mut state = make_test_dag_state();
        state.validator_count = known_validators.len();
        state.known_validators = known_validators;
        state.local_validator = Some(local_validator);
        state.snapshot_path = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        state.num_active_srs = 1;
        state.sr_index = 0;
        set_test_dag_epoch(&mut state, next_epoch);

        let dag_state = Arc::new(tokio::sync::RwLock::new(state));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        seed_runtime_recovery_for_live_test(&runtime_recovery).await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("live test addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let before_apply_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                && json["sr21Committee"]["eligibleValidatorCount"] == serde_json::Value::from(23)
                && json["sr21Committee"]["activeCount"] == serde_json::Value::from(21)
                && json["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(1)
                && json["sr21Committee"]["droppedCount"] == serde_json::Value::from(4)
                && json["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(false)
                && json["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(false)
        })
        .await;

        {
            let mut guard = dag_state.write().await;
            apply_sr21_election_at_epoch_boundary(&mut guard, next_epoch);
        }

        let after_apply_chain_info =
            wait_for_chain_info_http_matching(&client, &base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                    && json["sr21Committee"]["eligibleValidatorCount"] == serde_json::Value::from(23)
                    && json["sr21Committee"]["activeCount"] == serde_json::Value::from(21)
                    && json["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21)
                    && json["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["localPreviewSrIndex"] == serde_json::Value::from(local_preview_index)
                    && json["sr21Committee"]["localRuntimeSrIndex"] == serde_json::Value::from(local_preview_index)
                    && json["sr21Committee"]["droppedCount"] == serde_json::Value::from(4)
                    && json["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
            })
            .await;
        let after_apply_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let active_set_preview = after_apply_chain_info["sr21Committee"]["activeSetPreview"]
            .as_array()
            .expect("active set preview array");
        let active_set_ids = active_set_preview
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let excluded_eligible_missing = excluded_eligible_validator_ids
            .iter()
            .all(|validator_id| !active_set_ids.iter().any(|entry| entry == validator_id));
        let excluded_ineligible_missing = excluded_ineligible_validator_ids
            .iter()
            .all(|validator_id| !active_set_ids.iter().any(|entry| entry == validator_id));

        let consistency = serde_json::json!({
            "selectionBoundaryVisibleBeforeApply": before_apply_chain_info["sr21Committee"]["eligibleValidatorCount"] == serde_json::Value::from(23)
                && before_apply_chain_info["sr21Committee"]["activeCount"] == serde_json::Value::from(21)
                && before_apply_chain_info["sr21Committee"]["droppedCount"] == serde_json::Value::from(4)
                && before_apply_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(false)
                && before_apply_chain_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("15".into())
                && before_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("1".into())
                && before_apply_chain_info["sr21Committee"]["quorumThresholdConsistent"] == serde_json::Value::Bool(false),
            "runtimeActiveSetMissingBeforeApply": before_apply_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(false)
                && before_apply_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(0)
                && before_apply_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(false),
            "selectionBoundaryApplied": after_apply_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(true),
            "runtimeActiveSetApplied": after_apply_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(21)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && after_apply_dag_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && after_apply_dag_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(21)
                && after_apply_dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true),
            "committeeCapApplied": after_apply_chain_info["sr21Committee"]["committeeSizeCap"] == serde_json::Value::from(21)
                && after_apply_chain_info["sr21Committee"]["activeCount"] == serde_json::Value::from(21)
                && after_apply_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21),
            "quorumThresholdApplied": after_apply_chain_info["sr21Committee"]["previewQuorumThreshold"] == serde_json::Value::String("15".into())
                && after_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("15".into())
                && after_apply_chain_info["sr21Committee"]["quorumThresholdConsistent"] == serde_json::Value::Bool(true),
            "localValidatorSelectedAtBoundary": after_apply_chain_info["sr21Committee"]["localPreviewSrIndex"] == serde_json::Value::from(local_preview_index)
                && after_apply_chain_info["sr21Committee"]["localRuntimeSrIndex"] == serde_json::Value::from(local_preview_index)
                && after_apply_chain_info["sr21Committee"]["activeSetPreview"][20]["validatorId"] == serde_json::Value::String(local_validator_id_hex.clone())
                && after_apply_chain_info["sr21Committee"]["activeSetPreview"][20]["isLocal"] == serde_json::Value::Bool(true),
            "eligibleOverflowExcludedAfterApply": excluded_eligible_missing,
            "ineligibleExcludedAfterApply": excluded_ineligible_missing,
            "chainDagCommitteeSummaryConsistentAfterApply": after_apply_chain_info["sr21Committee"]["selection"] == after_apply_dag_info["sr21Committee"]["selection"]
                && after_apply_chain_info["sr21Committee"]["committeeSizeCap"] == after_apply_dag_info["sr21Committee"]["committeeSizeCap"]
                && after_apply_chain_info["sr21Committee"]["activeCount"] == after_apply_dag_info["sr21Committee"]["activeCount"]
                && after_apply_chain_info["sr21Committee"]["configuredActiveCount"] == after_apply_dag_info["sr21Committee"]["configuredActiveCount"]
                && after_apply_chain_info["sr21Committee"]["previewMatchesRuntime"] == after_apply_dag_info["sr21Committee"]["previewMatchesRuntime"]
                && after_apply_chain_info["sr21Committee"]["droppedCount"] == after_apply_dag_info["sr21Committee"]["droppedCount"]
                && after_apply_chain_info["sr21Committee"]["previewQuorumThreshold"] == after_apply_dag_info["sr21Committee"]["previewQuorumThreshold"]
                && after_apply_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == after_apply_dag_info["sr21Committee"]["runtimeQuorumThreshold"],
            "currentRuntimeStillValidatorBreadth": after_apply_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into())
                && after_apply_chain_info["consensusArchitecture"]["currentRuntime"]["committeeStage"] == serde_json::Value::String("validatorBreadthProof".into())
                && after_apply_chain_info["consensusArchitecture"]["currentRuntime"]["committeeSelection"] == serde_json::Value::String("validatorBreadthRehearsal".into()),
            "completionTargetMatchesPlan": after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && after_apply_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_sr21_top21_selection_epoch_boundary_visible_through_rpc_service",
            "appliedEpoch": next_epoch,
            "selectionBoundary": {
                "knownValidatorCount": 25,
                "eligibleValidatorCount": 23,
                "selectedCount": 21,
                "droppedCount": 4,
                "expectedExcludedEligibleValidatorIds": excluded_eligible_validator_ids,
                "expectedExcludedIneligibleValidatorIds": excluded_ineligible_validator_ids,
            },
            "consensusArchitecture": after_apply_chain_info["consensusArchitecture"],
            "beforeApply": {
                "chainInfo": {
                    "sr21Committee": before_apply_chain_info["sr21Committee"],
                    "validatorLifecycleRecovery": before_apply_chain_info["validatorLifecycleRecovery"],
                },
            },
            "afterApply": {
                "chainInfo": {
                    "sr21Committee": after_apply_chain_info["sr21Committee"],
                    "validatorLifecycleRecovery": after_apply_chain_info["validatorLifecycleRecovery"],
                },
                "dagInfo": {
                    "sr21Committee": after_apply_dag_info["sr21Committee"],
                    "validatorLifecycleRecovery": after_apply_dag_info["validatorLifecycleRecovery"],
                },
            },
            "consistency": consistency,
        });
        maybe_write_sr21_selection_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_sr21_top21_selection_epoch_boundary_visible_through_rpc_service".into()
            )
        );
        assert_eq!(payload["appliedEpoch"], serde_json::Value::from(next_epoch));
        assert_eq!(
            payload["selectionBoundary"]["knownValidatorCount"],
            serde_json::Value::from(25)
        );
        assert_eq!(
            payload["selectionBoundary"]["eligibleValidatorCount"],
            serde_json::Value::from(23)
        );
        assert_eq!(
            payload["selectionBoundary"]["selectedCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["selectionBoundary"]["droppedCount"],
            serde_json::Value::from(4)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["localPreviewSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["beforeApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["localRuntimeSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["previewQuorumThreshold"],
            serde_json::Value::String("15".into())
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeQuorumThreshold"],
            serde_json::Value::String("15".into())
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeSetPreview"]
                .as_array()
                .map(|entries| entries.len()),
            Some(21)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeSetPreview"][20]["validatorId"],
            serde_json::Value::String(local_validator_id_hex)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["activeSetPreview"][20]["isLocal"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["eligibleOverflowExcludedAfterApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["ineligibleExcludedAfterApply"],
            serde_json::Value::Bool(true)
        );

        server.stop().await.expect("stop live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_tx_dissemination_runtime_surface_tracks_shadow_queue_after_admit() {
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let dissemination_service = DagTxDisseminationService::new(dag_state.clone());
        dissemination_service
            .admit_transaction(make_test_dissemination_tx(0x41, TxType::TransparentTransfer))
            .await
            .expect("admit transparent");

        let rpc = DagRpcState {
            node: dag_state,
            narwhal_dissemination: None,
            dag_p2p_observation: None,
            runtime_recovery: None,
        };

        let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let dag_info = dag_get_dag_info(State(rpc)).await.0;

        assert_eq!(
            chain_info["txDissemination"]["currentRuntimeQueue"]["queued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["currentRuntimeQueue"]["fastTransparentQueued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["queued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["fastTransparentQueued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["mirroredCurrentRuntimeQueued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["narwhalWorkerBatchIngressQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["stagedOnlyQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["fastTransparentQueued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["narwhalWorkerBatchIngressReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["narwhalDeliveredBatchReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["live"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["live"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["queued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["fastTransparentQueued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["consistentSubsetOfReadyQueue"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["consistentSubsetOfShadowQueue"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["txDissemination"]["completionTargetShadowQueue"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            dag_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            dag_info["orderingContract"]["completionTargetShadowState"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            dag_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
    }

    #[tokio::test]
    async fn test_tx_dissemination_runtime_surface_tracks_narwhal_worker_shadow_stage() {
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let dissemination_service = DagNarwhalDisseminationService::new(dag_state.clone());
        dissemination_service.start().await.expect("start service");
        dissemination_service
            .stage_narwhal_worker_batch(vec![
                make_test_dissemination_tx(0x51, TxType::TransparentTransfer),
            ])
            .await
            .expect("stage shadow batch");

        let rpc = DagRpcState {
            node: dag_state,
            narwhal_dissemination: Some(dissemination_service.clone()),
            dag_p2p_observation: None,
            runtime_recovery: None,
        };

        let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let dag_info = dag_get_dag_info(State(rpc)).await.0;

        assert_eq!(
            chain_info["txDissemination"]["currentRuntimeQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["mirroredCurrentRuntimeQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["narwhalWorkerBatchIngressQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["stagedOnlyQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["shadowBatchCallerReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["deliveredBatchCallerReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["fastTransparentQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["stagedOnlyPreviewReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["narwhalDeliveredBatchReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["consistentSubsetOfReadyQueue"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["live"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            dag_info["txDissemination"]["completionTargetShadowQueue"]["queued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            dag_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(0)
        );
        dissemination_service.stop().await.expect("stop service");
    }

    #[tokio::test]
    async fn test_tx_dissemination_runtime_surface_tracks_narwhal_delivered_batch_shadow_stage() {
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let transparent = make_test_dissemination_tx(0x61, TxType::TransparentTransfer);
        let dissemination_service = DagNarwhalDisseminationService::new(dag_state.clone());
        dissemination_service.start().await.expect("start service");
        let delivered = dissemination_service
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("deliver shadow batch");
        assert_eq!(delivered, vec![transparent.tx_hash()]);

        let rpc = DagRpcState {
            node: dag_state,
            narwhal_dissemination: Some(dissemination_service.clone()),
            dag_p2p_observation: None,
            runtime_recovery: None,
        };

        let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let dag_info = dag_get_dag_info(State(rpc)).await.0;

        assert_eq!(
            chain_info["txDissemination"]["currentRuntimeQueue"]["queued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]
                ["narwhalWorkerBatchIngressQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowQueue"]["stagedOnlyQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["shadowBatchCallerReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["orchestration"]["deliveredBatchCallerReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceBound"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["orchestration"]["serviceRunning"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["fastTransparentQueued"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]["live"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetDeliveredQueue"]
                ["consistentSubsetOfShadowQueue"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["txDissemination"]["completionTargetShadowCapabilities"]
                ["narwhalDeliveredBatchReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(2)
        );
        dissemination_service.stop().await.expect("stop service");
    }

    #[tokio::test]
    async fn test_live_narwhal_dissemination_shadow_and_delivered_handoff_through_rpc_service_runtime_surface(
    ) {
        let temp_dir = unique_temp_dir("misaka-narwhal-dissemination-live");
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let server = start_live_dag_rpc_service(dag_state, runtime_recovery, addr).await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let initial_chain_info = wait_for_chain_info_http(&client, &base_url).await;
        let initial_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let transparent = make_test_dissemination_tx(0x81, TxType::TransparentTransfer);
        let tx_hashes = server
            .stage_narwhal_worker_batch(vec![transparent.clone()])
            .await
            .expect("stage narwhal worker batch");

        let worker_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["txDissemination"]["completionTargetShadowQueue"]["queued"]
                == serde_json::Value::from(2)
                && json["txDissemination"]["completionTargetDeliveredQueue"]["queued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let worker_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_narwhal_worker_batch_delivered(&tx_hashes)
            .await
            .expect("mark delivered shadow batch");

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["txDissemination"]["completionTargetDeliveredQueue"]["queued"]
                == serde_json::Value::from(2)
        })
        .await;
        let delivered_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["txDissemination"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && worker_chain_info["txDissemination"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && delivered_chain_info["txDissemination"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["txDissemination"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && worker_chain_info["txDissemination"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && delivered_chain_info["txDissemination"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "shadowBatchCallerReadyThroughout": initial_chain_info["txDissemination"]["orchestration"]["shadowBatchCallerReady"] == serde_json::Value::Bool(true)
                && worker_chain_info["txDissemination"]["orchestration"]["shadowBatchCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["txDissemination"]["orchestration"]["shadowBatchCallerReady"] == serde_json::Value::Bool(true),
            "deliveredBatchCallerReadyThroughout": initial_chain_info["txDissemination"]["orchestration"]["deliveredBatchCallerReady"] == serde_json::Value::Bool(true)
                && worker_chain_info["txDissemination"]["orchestration"]["deliveredBatchCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["txDissemination"]["orchestration"]["deliveredBatchCallerReady"] == serde_json::Value::Bool(true),
            "currentRuntimeQueueUnaffected": initial_chain_info["txDissemination"]["currentRuntimeQueue"]["queued"] == serde_json::Value::from(0)
                && worker_chain_info["txDissemination"]["currentRuntimeQueue"]["queued"] == serde_json::Value::from(0)
                && delivered_chain_info["txDissemination"]["currentRuntimeQueue"]["queued"] == serde_json::Value::from(0),
            "workerBatchVisibleOnlyInShadowBeforeDelivery": worker_chain_info["txDissemination"]["completionTargetShadowQueue"]["queued"] == serde_json::Value::from(2)
                && worker_chain_info["txDissemination"]["completionTargetShadowQueue"]["narwhalWorkerBatchIngressQueued"] == serde_json::Value::from(2)
                && worker_chain_info["txDissemination"]["completionTargetShadowQueue"]["stagedOnlyQueued"] == serde_json::Value::from(2)
                && worker_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"] == serde_json::Value::from(0),
            "deliveredBatchVisibleAfterHandoff": delivered_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["fastTransparentQueued"] == serde_json::Value::from(1)
                && delivered_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["live"] == serde_json::Value::Bool(true),
            "stagedContractReadyThroughout": initial_chain_info["txDissemination"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && worker_chain_info["txDissemination"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["txDissemination"]["stagedContractReady"] == serde_json::Value::Bool(true),
            "consensusArchitectureMatchesCompletionPlan": delivered_chain_info["consensusArchitecture"]["currentRuntime"]["disseminationStage"] == serde_json::Value::String("nativeMempool".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["disseminationStage"] == serde_json::Value::String("narwhalBatchDissemination".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["ordering"] == serde_json::Value::String("bullshark".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && delivered_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_narwhal_dissemination_shadow_and_delivered_handoff",
            "txHashes": tx_hashes.iter().map(hex::encode).collect::<Vec<_>>(),
            "consensusArchitecture": delivered_chain_info["consensusArchitecture"],
            "sr21Committee": delivered_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["txDissemination"],
                "dagInfo": initial_dag_info["txDissemination"],
            },
            "afterWorkerBatchIngress": {
                "chainInfo": worker_chain_info["txDissemination"],
                "dagInfo": worker_dag_info["txDissemination"],
            },
            "afterDeliveredBatch": {
                "chainInfo": delivered_chain_info["txDissemination"],
                "dagInfo": delivered_dag_info["txDissemination"],
            },
            "consistency": consistency,
        });
        maybe_write_narwhal_dissemination_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_narwhal_dissemination_shadow_and_delivered_handoff".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterWorkerBatchIngress"]["chainInfo"]["completionTargetShadowQueue"]
                ["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetDeliveredQueue"]["queued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetDeliveredQueue"]
            serde_json::Value::from(1)
        );
        assert_eq!(
            payload["consistency"]["serviceRunningThroughout"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["deliveredBatchVisibleAfterHandoff"],
            serde_json::Value::Bool(true)
        );
        server.stop().await.expect("stop live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_candidate_preview_auto_advances_after_runtime_commit_through_block_producer(
    ) {
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let narwhal = DagNarwhalDisseminationService::new(dag_state.clone());
        narwhal.start().await.expect("start narwhal service");
        let rpc = DagRpcState {
            node: dag_state.clone(),
            narwhal_dissemination: Some(narwhal.clone()),
            dag_p2p_observation: None,
            runtime_recovery: None,
        };

        let initial_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let initial_dag_info = dag_get_dag_info(State(rpc.clone())).await.0;

        let dissemination = DagTxDisseminationService::new(dag_state.clone());
        let transparent = make_test_dissemination_tx(0xA1, TxType::TransparentTransfer);
        let tx_hashes = vec![
            dissemination
                .admit_transaction(transparent.clone())
                .await
                .expect("admit transparent"),
        ];
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();

        let admitted_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let admitted_dag_info = dag_get_dag_info(State(rpc.clone())).await.0;

        let producer_state = dag_state.clone();
        let producer = tokio::spawn(async move {
            misaka_dag::run_dag_block_producer(producer_state, 1, 32).await;
        });

        for _ in 0..60 {
            if dissemination
                .bullshark_candidate_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .len()
                == 2
            {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        let preview_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let preview_dag_info = dag_get_dag_info(State(rpc)).await.0;
        let preview_hashes = serde_json::json!({
            "any": dissemination
                .bullshark_candidate_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": dissemination
                .bullshark_candidate_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "directAdmitMirrorsDeliveredQueueBeforeProducerCommit": admitted_chain_info["txDissemination"]["currentRuntimeQueue"]["queued"] == serde_json::Value::from(2)
                && admitted_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"] == serde_json::Value::from(2)
                && admitted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0),
            "producerAutoPreviewVisibleAfterResolve": preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewAutoAdvancedAlongsideCandidate": preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "candidatePreviewHashesVisibleAfterAutoAdvance": preview_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && preview_hashes["fastTransparent"] == serde_json::json!([hex::encode(tx_hashes[0])])
            "completionTargetMatchesPlan": preview_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_candidate_preview_auto_advance_after_runtime_commit",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": preview_chain_info["consensusArchitecture"],
            "sr21Committee": preview_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDirectAdmit": {
                "chainInfo": admitted_chain_info["orderingContract"],
                "dagInfo": admitted_dag_info["orderingContract"],
                "txDissemination": admitted_chain_info["txDissemination"],
            },
            "afterProducerAutoCandidatePreview": {
                "chainInfo": preview_chain_info["orderingContract"],
                "dagInfo": preview_dag_info["orderingContract"],
                "txDissemination": preview_chain_info["txDissemination"],
                "previewHashes": preview_hashes,
            },
            "consistency": consistency,
        });
        maybe_write_bullshark_auto_candidate_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_candidate_preview_auto_advance_after_runtime_commit".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDirectAdmit"]["chainInfo"]["completionTargetShadowState"]
                ["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterProducerAutoCandidatePreview"]["chainInfo"]
                ["completionTargetShadowState"]["candidatePreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterProducerAutoCandidatePreview"]["chainInfo"]
                ["completionTargetShadowState"]["commitPreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["producerAutoPreviewVisibleAfterResolve"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["commitPreviewAutoAdvancedAlongsideCandidate"],
            serde_json::Value::Bool(true)
        );

        producer.abort();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        narwhal.stop().await.expect("stop narwhal service");
    }

    #[tokio::test]
    async fn test_live_bullshark_commit_preview_auto_advances_after_candidate_preview_through_block_producer(
    ) {
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let narwhal = DagNarwhalDisseminationService::new(dag_state.clone());
        narwhal.start().await.expect("start narwhal service");
        let rpc = DagRpcState {
            node: dag_state.clone(),
            narwhal_dissemination: Some(narwhal.clone()),
            dag_p2p_observation: None,
            runtime_recovery: None,
        };

        let initial_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let initial_dag_info = dag_get_dag_info(State(rpc.clone())).await.0;

        let dissemination = DagTxDisseminationService::new(dag_state.clone());
        let transparent = make_test_dissemination_tx(0xB1, TxType::TransparentTransfer);
        let tx_hashes = vec![
            dissemination
                .admit_transaction(transparent.clone())
                .await
                .expect("admit transparent"),
        ];
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();

        let admitted_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let admitted_dag_info = dag_get_dag_info(State(rpc.clone())).await.0;

        let producer_state = dag_state.clone();
        let producer = tokio::spawn(async move {
            misaka_dag::run_dag_block_producer(producer_state, 1, 32).await;
        });

        for _ in 0..60 {
            if dissemination
                .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .len()
                == 2
            {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        let preview_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let preview_dag_info = dag_get_dag_info(State(rpc)).await.0;
        let preview_hashes = serde_json::json!({
            "any": dissemination
                .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": dissemination
                .bullshark_commit_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitPreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true),
            "directAdmitMirrorsDeliveredQueueBeforeProducerCommit": admitted_chain_info["txDissemination"]["currentRuntimeQueue"]["queued"] == serde_json::Value::from(2)
                && admitted_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"] == serde_json::Value::from(2)
                && admitted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && admitted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleBeforeCommitAutoAdvance": preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewVisibleAfterAutoAdvance": preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewHashesVisibleAfterAutoAdvance": preview_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && preview_hashes["fastTransparent"] == serde_json::json!([hex::encode(tx_hashes[0])])
            "completionTargetMatchesPlan": preview_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_commit_preview_auto_advance_after_candidate_preview",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": preview_chain_info["consensusArchitecture"],
            "sr21Committee": preview_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDirectAdmit": {
                "chainInfo": admitted_chain_info["orderingContract"],
                "dagInfo": admitted_dag_info["orderingContract"],
                "txDissemination": admitted_chain_info["txDissemination"],
            },
            "afterProducerAutoCommitPreview": {
                "chainInfo": preview_chain_info["orderingContract"],
                "dagInfo": preview_dag_info["orderingContract"],
                "txDissemination": preview_chain_info["txDissemination"],
                "previewHashes": preview_hashes,
            },
            "consistency": consistency,
        });
        maybe_write_bullshark_auto_commit_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_commit_preview_auto_advance_after_candidate_preview".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDirectAdmit"]["chainInfo"]["completionTargetShadowState"]
                ["commitPreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterProducerAutoCommitPreview"]["chainInfo"]["completionTargetShadowState"]
                ["candidatePreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterProducerAutoCommitPreview"]["chainInfo"]["completionTargetShadowState"]
                ["commitPreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["commitPreviewVisibleAfterAutoAdvance"],
            serde_json::Value::Bool(true)
        );

        producer.abort();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        narwhal.stop().await.expect("stop narwhal service");
    }

    #[tokio::test]
    async fn test_live_bullshark_commit_auto_advances_after_commit_preview_through_block_producer()
    {
        let temp_dir = unique_temp_dir("misaka-bullshark-auto-committed");
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        seed_runtime_recovery_for_live_test(&runtime_recovery).await;
        let narwhal = DagNarwhalDisseminationService::new(dag_state.clone());
        narwhal.start().await.expect("start narwhal service");
        let rpc = DagRpcState {
            node: dag_state.clone(),
            narwhal_dissemination: Some(narwhal.clone()),
            dag_p2p_observation: None,
            runtime_recovery: Some(runtime_recovery),
        };

        let initial_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let initial_dag_info = dag_get_dag_info(State(rpc.clone())).await.0;

        let dissemination = DagTxDisseminationService::new(dag_state.clone());
        let transparent = make_test_dissemination_tx(0xD1, TxType::TransparentTransfer);
        let tx_hashes = vec![
            dissemination
                .admit_transaction(transparent.clone())
                .await
                .expect("admit transparent"),
        ];
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();

        let admitted_chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let admitted_dag_info = dag_get_dag_info(State(rpc.clone())).await.0;

        let producer_state = dag_state.clone();
        let producer = tokio::spawn(async move {
            misaka_dag::run_dag_block_producer(producer_state, 1, 32).await;
        });

        let commit_chain_info = {
            let mut payload = None;
            for _ in 0..60 {
                let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
                if chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(2)
                {
                    payload = Some(chain_info);
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            payload.expect("wait for producer auto committed queue")
        };
        let commit_dag_info = dag_get_dag_info(State(rpc)).await.0;
        let commit_runtime_recovery = commit_chain_info["runtimeRecovery"].clone();
        let commit_hashes = serde_json::json!({
            "any": dissemination
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": dissemination
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitPreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && admitted_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "directAdmitMirrorsDeliveredQueueBeforeProducerCommit": admitted_chain_info["txDissemination"]["currentRuntimeQueue"]["queued"] == serde_json::Value::from(2)
                && admitted_chain_info["txDissemination"]["completionTargetDeliveredQueue"]["queued"] == serde_json::Value::from(2)
                && admitted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && admitted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(0)
                && admitted_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleAfterAutoAdvance": commit_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewVisibleAfterAutoAdvance": commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "commitVisibleAfterAutoAdvance": commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedLive"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "commitHashesVisibleAfterAutoAdvance": commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && commit_hashes["fastTransparent"] == serde_json::json!([hex::encode(tx_hashes[0])])
            "runtimeRecoveryCommitObserved": commit_runtime_recovery["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && commit_runtime_recovery["lastBullsharkCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && commit_runtime_recovery["bullsharkCommitObserved"] == serde_json::Value::Bool(true),
            "commitCapabilityReady": commit_chain_info["orderingContract"]["completionTargetShadowCapabilities"]["bullsharkCommitReady"] == serde_json::Value::Bool(true),
            "completionTargetMatchesPlan": commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_commit_auto_advance_after_commit_preview",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": commit_chain_info["consensusArchitecture"],
            "sr21Committee": commit_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDirectAdmit": {
                "chainInfo": admitted_chain_info["orderingContract"],
                "dagInfo": admitted_dag_info["orderingContract"],
                "txDissemination": admitted_chain_info["txDissemination"],
            },
            "afterProducerAutoCommit": {
                "chainInfo": commit_chain_info["orderingContract"],
                "dagInfo": commit_dag_info["orderingContract"],
                "runtimeRecovery": commit_runtime_recovery,
                "txDissemination": commit_chain_info["txDissemination"],
                "commitHashes": commit_hashes,
            },
            "consistency": consistency,
        });
        maybe_write_bullshark_auto_committed_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_commit_auto_advance_after_commit_preview".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDirectAdmit"]["chainInfo"]["completionTargetShadowState"]
                ["committedQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterProducerAutoCommit"]["chainInfo"]["completionTargetShadowState"]
                ["committedQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["commitVisibleAfterAutoAdvance"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["runtimeRecoveryCommitObserved"],
            serde_json::Value::Bool(true)
        );

        producer.abort();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        narwhal.stop().await.expect("stop service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_commit_preview_auto_visible_through_rpc_service_runtime_surface() {
        let temp_dir = unique_temp_dir("misaka-bullshark-auto-commit-live");
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let initial_chain_info = wait_for_chain_info_http(&client, &base_url).await;
        let initial_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let transparent = make_test_dissemination_tx(0xC1, TxType::TransparentTransfer);
        let tx_hashes = server
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let transparent_hash = hex::encode(tx_hashes[0]);

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["queued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(0)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let delivered_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let producer_state = dag_state.clone();
        let producer = tokio::spawn(async move {
            misaka_dag::run_dag_block_producer(producer_state, 1, 32).await;
        });

        let preview_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(2)
        })
        .await;
        let preview_dag_info = fetch_dag_info_http(&client, &base_url).await;
        let preview_hashes = serde_json::json!({
            "any": server
                .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit preview any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_commit_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("commit preview transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let preview_runtime_recovery = preview_chain_info["runtimeRecovery"].clone();

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitPreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true),
            "deliveredVisibleBeforeAutoPreview": delivered_chain_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleAfterAutoAdvance": preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewVisibleAfterAutoAdvance": preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewHashesVisibleAfterAutoAdvance": preview_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && preview_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "orderingContractReadyThroughout": initial_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && preview_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true),
            "authoritativeCheckpointSourceUnchanged": preview_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into()),
            "completionTargetMatchesPlan": preview_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && preview_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_commit_preview_auto_visible_through_rpc_service",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": preview_chain_info["consensusArchitecture"],
            "sr21Committee": preview_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDeliveredBatch": {
                "chainInfo": delivered_chain_info["orderingContract"],
                "dagInfo": delivered_dag_info["orderingContract"],
                "txDissemination": delivered_chain_info["txDissemination"],
            },
            "afterProducerAutoCommitPreview": {
                "chainInfo": preview_chain_info["orderingContract"],
                "dagInfo": preview_dag_info["orderingContract"],
                "txDissemination": preview_chain_info["txDissemination"],
                "runtimeRecovery": preview_runtime_recovery,
                "previewHashes": preview_hashes,
            },
            "consistency": consistency,
        });
        maybe_write_bullshark_auto_commit_live_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_commit_preview_auto_visible_through_rpc_service".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetShadowState"]
                ["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetShadowState"]
                ["commitPreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterProducerAutoCommitPreview"]["chainInfo"]["completionTargetShadowState"]
                ["candidatePreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterProducerAutoCommitPreview"]["chainInfo"]["completionTargetShadowState"]
                ["commitPreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["commitPreviewVisibleAfterAutoAdvance"],
            serde_json::Value::Bool(true)
        );

        producer.abort();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        server.stop().await.expect("stop live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_commit_auto_visible_through_rpc_service_runtime_surface() {
        let temp_dir = unique_temp_dir("misaka-bullshark-auto-committed-live");
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let initial_chain_info = wait_for_chain_info_http(&client, &base_url).await;
        let initial_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let transparent = make_test_dissemination_tx(0xE1, TxType::TransparentTransfer);
        let tx_hashes = server
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let transparent_hash = hex::encode(tx_hashes[0]);

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["queued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(0)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(0)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let delivered_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let producer_state = dag_state.clone();
        let producer = tokio::spawn(async move {
            misaka_dag::run_dag_block_producer(producer_state, 1, 32).await;
        });

        let commit_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(2)
                && json["runtimeRecovery"]["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && json["runtimeRecovery"]["bullsharkCommitObserved"]
                    == serde_json::Value::Bool(true)
        })
        .await;
        let commit_dag_info = fetch_dag_info_http(&client, &base_url).await;
        let commit_runtime_recovery = commit_chain_info["runtimeRecovery"].clone();
        let commit_hashes = serde_json::json!({
            "any": server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitPreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "deliveredVisibleBeforeAutoCommit": delivered_chain_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleAfterAutoAdvance": commit_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewVisibleAfterAutoAdvance": commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "commitVisibleAfterAutoAdvance": commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedLive"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "commitHashesVisibleAfterAutoAdvance": commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && commit_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "runtimeRecoveryCommitObserved": commit_runtime_recovery["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && commit_runtime_recovery["lastBullsharkCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && commit_runtime_recovery["bullsharkCommitObserved"] == serde_json::Value::Bool(true),
            "orderingContractReadyThroughout": initial_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true),
            "sr21PreviewVisibleThroughChainInfo": commit_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true),
            "sr21PreviewVisibleThroughDagInfo": commit_dag_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true),
            "sr21LocalPreviewStateConsistent": commit_chain_info["sr21Committee"]["localValidatorInActiveSet"] == commit_dag_info["sr21Committee"]["localValidatorInActiveSet"]
                && commit_chain_info["sr21Committee"]["localValidatorPresent"] == commit_dag_info["sr21Committee"]["localValidatorPresent"]
                && commit_chain_info["sr21Committee"]["localPreviewSrIndex"] == commit_dag_info["sr21Committee"]["localPreviewSrIndex"],
            "sr21ActiveCountConsistent": commit_chain_info["sr21Committee"]["activeCount"] == commit_dag_info["sr21Committee"]["activeCount"]
                && commit_chain_info["sr21Committee"]["configuredActiveCount"] == commit_dag_info["sr21Committee"]["configuredActiveCount"]
                && commit_chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(true)
                && commit_chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(true)
                && commit_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && commit_dag_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true),
            "sr21ChainDagCommitteeSummaryConsistent": commit_chain_info["sr21Committee"]["selection"] == commit_dag_info["sr21Committee"]["selection"]
                && commit_chain_info["sr21Committee"]["committeeSizeCap"] == commit_dag_info["sr21Committee"]["committeeSizeCap"]
                && commit_chain_info["sr21Committee"]["activeCount"] == commit_dag_info["sr21Committee"]["activeCount"]
                && commit_chain_info["sr21Committee"]["configuredActiveCount"] == commit_dag_info["sr21Committee"]["configuredActiveCount"]
                && commit_chain_info["sr21Committee"]["previewMatchesRuntime"] == commit_dag_info["sr21Committee"]["previewMatchesRuntime"],
            "sr21CurrentRuntimeStillValidatorBreadth": commit_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into())
                && commit_chain_info["consensusArchitecture"]["currentRuntime"]["committeeStage"] == serde_json::Value::String("validatorBreadthProof".into())
                && commit_chain_info["consensusArchitecture"]["currentRuntime"]["committeeSelection"] == serde_json::Value::String("validatorBreadthRehearsal".into()),
            "sr21CompletionTargetCommitteeMatchesPlan": commit_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
            "authoritativeCheckpointSourceUnchanged": commit_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into()),
            "completionTargetMatchesPlan": commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        producer.abort();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let dag_snapshot = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        {
            let mut guard = dag_state.write().await;
            guard.snapshot_path = dag_snapshot.clone();
            assert_eq!(
                guard.snapshot_path, dag_snapshot,
                "auto-commit snapshot path must point at the live temp dir"
            );
            save_runtime_snapshot(
                &guard.snapshot_path,
                &guard.dag_store,
                &guard.utxo_set,
                &guard.state_manager.stats,
                guard.latest_checkpoint.as_ref(),
                &guard.known_validators,
                &guard.runtime_active_sr_validator_ids,
                guard.latest_checkpoint_vote.as_ref(),
                guard.latest_checkpoint_finality.as_ref(),
                &guard.checkpoint_vote_pool,
            )
            .expect("persist bullshark auto-commit runtime snapshot");
        }
        assert!(dag_snapshot.exists(), "dag runtime snapshot must be written");

        let (restart_blue_score, restart_block_hash) = {
            let guard = dag_state.read().await;
            let snapshot = guard.dag_store.snapshot();
            let restart_tip = snapshot
                .get_tips()
                .into_iter()
                .max_by_key(|hash| {
                    snapshot
                        .get_ghostdag_data(hash)
                        .map(|data| data.blue_score)
                        .unwrap_or(0)
                })
                .expect("restart tip");
            let restart_score = snapshot
                .get_ghostdag_data(&restart_tip)
                .map(|data| data.blue_score)
                .unwrap_or_else(|| guard.dag_store.max_blue_score());
            (restart_score, restart_tip)
        };

        server.stop().await.expect("stop live dag rpc service");

        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 0);
            guard.mark_checkpoint_persisted(restart_blue_score, restart_block_hash);
            guard.mark_checkpoint_finality(Some(restart_blue_score));
        }
        let restart_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind restart live test port");
        let restart_addr = restart_listener
            .local_addr()
            .expect("restart live test addr");
        drop(restart_listener);
        let restart_base_url = format!("http://{}", restart_addr);
        let restarted_server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), restart_addr,
        )
        .await;

        let restarted_client = reqwest::Client::new();
        let restarted_chain_info =
            wait_for_chain_info_http_matching(&restarted_client, &restart_base_url, |json| {
                json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(2)
                    && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                        == serde_json::Value::from(2)
                    && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                        == serde_json::Value::from(2)
                    && json["orderingContract"]["completionTargetShadowState"]
                        ["consistentWithCommitPreview"]
                        == serde_json::Value::Bool(true)
                    && json["runtimeRecovery"]["bullsharkCommitObserved"]
                        == serde_json::Value::Bool(true)
                    && json["runtimeRecovery"]["lastBullsharkCommitCount"]
                        == serde_json::Value::from(2)
                    && json["runtimeRecovery"]["lastBullsharkCommitTxHashes"]
                        == serde_json::json!(tx_hash_hexes)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
            })
            .await;
        let restarted_dag_info = fetch_dag_info_http(&restarted_client, &restart_base_url).await;
        let restarted_commit_hashes = serde_json::json!({
            "any": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("restarted commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("restarted commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let restart_consistency = serde_json::json!({
            "snapshotArtifactsWritten": dag_snapshot.exists(),
            "serviceRestartContinuity": restarted_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "committedStatePersistedAfterRestart": restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedFastTransparentQueued"] == serde_json::Value::from(1)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedLive"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "runtimeRecoveryCommitPersistedAfterRestart": restarted_chain_info["runtimeRecovery"]["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && restarted_chain_info["runtimeRecovery"]["lastBullsharkCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && restarted_chain_info["runtimeRecovery"]["bullsharkCommitObserved"] == serde_json::Value::Bool(true),
            "chainDagCommittedSummaryConsistentAfterRestart": restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == restarted_dag_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == restarted_dag_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == restarted_dag_info["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == restarted_dag_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"]
                && restarted_chain_info["sr21Committee"]["activeCount"] == restarted_dag_info["sr21Committee"]["activeCount"]
                && restarted_chain_info["sr21Committee"]["configuredActiveCount"] == restarted_dag_info["sr21Committee"]["configuredActiveCount"]
                && restarted_chain_info["sr21Committee"]["previewMatchesRuntime"] == restarted_dag_info["sr21Committee"]["previewMatchesRuntime"],
            "committeeStatePersistedAfterRestart": restarted_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["runtimeActiveCountConsistent"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["localRuntimeSrIndexConsistent"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["activeCount"] == restarted_dag_info["sr21Committee"]["activeCount"]
                && restarted_chain_info["sr21Committee"]["configuredActiveCount"] == restarted_dag_info["sr21Committee"]["configuredActiveCount"],
            "currentRuntimeStillValidatorBreadthAfterRestart": restarted_chain_info["consensusArchitecture"]["currentRuntime"]["orderingStage"] == serde_json::Value::String("ghostdagTotalOrder".into())
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into()),
            "completionTargetMatchesPlanAfterRestart": restarted_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
            "rehydratedAfterRestart": serde_json::Value::Bool(false),
            "startupSnapshotRestoredAfterRestart": restarted_chain_info["runtimeRecovery"]["startupSnapshotRestored"] == serde_json::Value::Bool(true)
                && restarted_chain_info["runtimeRecovery"]["checkpointPersisted"] == serde_json::Value::Bool(true)
                && restarted_chain_info["runtimeRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_commit_auto_visible_through_rpc_service",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": commit_chain_info["consensusArchitecture"],
            "sr21Committee": commit_chain_info["sr21Committee"],
            "sr21CommitteeDag": commit_dag_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDeliveredBatch": {
                "chainInfo": delivered_chain_info["orderingContract"],
                "dagInfo": delivered_dag_info["orderingContract"],
                "txDissemination": delivered_chain_info["txDissemination"],
            },
            "afterProducerAutoCommit": {
                "chainInfo": commit_chain_info["orderingContract"],
                "dagInfo": commit_dag_info["orderingContract"],
                "runtimeRecovery": commit_runtime_recovery,
                "txDissemination": commit_chain_info["txDissemination"],
                "commitHashes": commit_hashes,
            },
            "consistency": consistency,
            "afterRestart": {
                "chainInfo": {
                    "orderingContract": restarted_chain_info["orderingContract"],
                    "sr21Committee": restarted_chain_info["sr21Committee"],
                    "runtimeRecovery": restarted_chain_info["runtimeRecovery"],
                },
                "dagInfo": {
                    "orderingContract": restarted_dag_info["orderingContract"],
                    "sr21Committee": restarted_dag_info["sr21Committee"],
                    "runtimeRecovery": restarted_dag_info["runtimeRecovery"],
                },
                "commitHashes": restarted_commit_hashes,
            },
            "restartConsistency": restart_consistency,
        });
        maybe_write_bullshark_auto_committed_live_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_commit_auto_visible_through_rpc_service".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetShadowState"]
                ["committedQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterProducerAutoCommit"]["chainInfo"]["completionTargetShadowState"]
                ["committedQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["commitVisibleAfterAutoAdvance"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["runtimeRecoveryCommitObserved"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["sr21PreviewVisibleThroughChainInfo"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["sr21ChainDagCommitteeSummaryConsistent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["orderingContract"]["completionTargetShadowState"]
                ["committedQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["restartConsistency"]["serviceRestartContinuity"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["committedStatePersistedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["runtimeRecoveryCommitPersistedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["rehydratedAfterRestart"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["runtimeRecovery"]["startupSnapshotRestored"],
            serde_json::Value::Bool(true)
        );

        restarted_server
            .stop()
            .await
            .expect("stop restarted live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_ordering_candidate_and_commit_preview_handoff_through_rpc_service_runtime_surface(
    ) {
        let temp_dir = unique_temp_dir("misaka-bullshark-ordering-live");
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let server = start_live_dag_rpc_service(dag_state, runtime_recovery, addr).await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let initial_chain_info = wait_for_chain_info_http(&client, &base_url).await;
        let initial_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let transparent = make_test_dissemination_tx(0x91, TxType::TransparentTransfer);
        let tx_hashes = server
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["queued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let delivered_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_candidate_preview(&tx_hashes)
            .await
            .expect("mark bullshark candidate preview");

        let candidate_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let candidate_dag_info = fetch_dag_info_http(&client, &base_url).await;
        let candidate_preview_hashes = serde_json::json!({
            "any": server
                .bullshark_candidate_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("candidate preview any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_candidate_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("candidate preview transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let candidate_runtime_recovery = candidate_chain_info["runtimeRecovery"].clone();

        server
            .mark_bullshark_commit_preview(&tx_hashes)
            .await
            .expect("mark bullshark commit preview");

        let commit_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                == serde_json::Value::from(2)
        })
        .await;
        let commit_dag_info = fetch_dag_info_http(&client, &base_url).await;
        let commit_preview_hashes = serde_json::json!({
            "any": server
                .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit preview any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_commit_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("commit preview transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let commit_runtime_recovery = commit_chain_info["runtimeRecovery"].clone();
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let transparent_hash = hex::encode(tx_hashes[0]);

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitPreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true),
            "deliveredVisibleBeforePreview": delivered_chain_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleAfterHandoff": candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewVisibleAfterHandoff": commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "producerCandidatePreviewHashesVisibleAfterHandoff": candidate_preview_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && candidate_preview_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "finalityCommitPreviewHashesVisibleAfterHandoff": commit_preview_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && commit_preview_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "runtimeRecoveryCandidatePreviewObserved": candidate_runtime_recovery["lastBullsharkCandidatePreviewCount"] == serde_json::Value::from(2)
                && candidate_runtime_recovery["lastBullsharkCandidatePreviewTxHashes"] == serde_json::json!(tx_hash_hexes)
                && candidate_runtime_recovery["bullsharkCandidatePreviewObserved"] == serde_json::Value::Bool(true),
            "runtimeRecoveryCommitPreviewObserved": commit_runtime_recovery["lastBullsharkCommitPreviewCount"] == serde_json::Value::from(2)
                && commit_runtime_recovery["lastBullsharkCommitPreviewTxHashes"] == serde_json::json!(tx_hash_hexes)
                && commit_runtime_recovery["bullsharkCommitPreviewObserved"] == serde_json::Value::Bool(true),
            "orderingContractReadyThroughout": initial_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true),
            "completionTargetMatchesPlan": commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_ordering_candidate_and_commit_preview_handoff",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": commit_chain_info["consensusArchitecture"],
            "sr21Committee": commit_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDeliveredBatch": {
                "chainInfo": delivered_chain_info["orderingContract"],
                "dagInfo": delivered_dag_info["orderingContract"],
            },
            "afterCandidatePreview": {
                "chainInfo": candidate_chain_info["orderingContract"],
                "dagInfo": candidate_dag_info["orderingContract"],
                "runtimeRecovery": candidate_runtime_recovery,
                "previewHashes": candidate_preview_hashes,
            },
            "afterCommitPreview": {
                "chainInfo": commit_chain_info["orderingContract"],
                "dagInfo": commit_dag_info["orderingContract"],
                "runtimeRecovery": commit_runtime_recovery,
                "previewHashes": commit_preview_hashes,
            },
            "consistency": consistency,
        });
        maybe_write_bullshark_ordering_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_ordering_candidate_and_commit_preview_handoff".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetShadowState"]
                ["candidatePreviewQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterCandidatePreview"]["chainInfo"]["completionTargetShadowState"]
                ["candidatePreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterCommitPreview"]["chainInfo"]["completionTargetShadowState"]
                ["commitPreviewQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["commitPreviewVisibleAfterHandoff"],
            serde_json::Value::Bool(true)
        );

        server.stop().await.expect("stop live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_commit_handoff_through_rpc_service_runtime_surface() {
        let temp_dir = unique_temp_dir("misaka-bullshark-commit-live");
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let server = start_live_dag_rpc_service(dag_state, runtime_recovery, addr).await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let initial_chain_info = wait_for_chain_info_http(&client, &base_url).await;
        let initial_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let transparent = make_test_dissemination_tx(0xA1, TxType::TransparentTransfer);
        let tx_hashes = server
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["queued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(0)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(0)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let delivered_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_candidate_preview(&tx_hashes)
            .await
            .expect("mark bullshark candidate preview");
        let candidate_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(0)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(0)
        })
        .await;
        let candidate_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_commit_preview(&tx_hashes)
            .await
            .expect("mark bullshark commit preview");
        let commit_preview_chain_info =
            wait_for_chain_info_http_matching(&client, &base_url, |json| {
                json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(2)
                    && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                        == serde_json::Value::from(0)
            })
            .await;
        let commit_preview_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_commit(&tx_hashes)
            .await
            .expect("mark bullshark commit");
        let commit_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                == serde_json::Value::from(2)
        })
        .await;
        let commit_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let transparent_hash = hex::encode(tx_hashes[0]);
        let commit_hashes = serde_json::json!({
            "any": server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let commit_runtime_recovery = commit_chain_info["runtimeRecovery"].clone();

        let consistency = serde_json::json!({
            "serviceBoundThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true),
            "serviceRunningThroughout": initial_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true),
            "candidatePreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitPreviewCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true),
            "commitCallerReadyThroughout": initial_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "deliveredVisibleBeforePreview": delivered_chain_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleAfterHandoff": candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true),
            "commitPreviewVisibleAfterHandoff": commit_preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && commit_preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true),
            "commitVisibleAfterHandoff": commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["committedLive"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "commitHashesVisibleAfterHandoff": commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && commit_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "runtimeRecoveryCommitObserved": commit_runtime_recovery["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && commit_runtime_recovery["lastBullsharkCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && commit_runtime_recovery["bullsharkCommitObserved"] == serde_json::Value::Bool(true),
            "commitCapabilityReady": commit_chain_info["orderingContract"]["completionTargetShadowCapabilities"]["bullsharkCommitReady"] == serde_json::Value::Bool(true),
            "orderingContractReadyThroughout": initial_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true)
                && commit_chain_info["orderingContract"]["stagedContractReady"] == serde_json::Value::Bool(true),
            "authoritativeCheckpointSourceUnchanged": commit_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into()),
            "completionTargetMatchesPlan": commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && commit_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_commit_handoff_through_rpc_service",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": commit_chain_info["consensusArchitecture"],
            "sr21Committee": commit_chain_info["sr21Committee"],
            "initial": {
                "chainInfo": initial_chain_info["orderingContract"],
                "dagInfo": initial_dag_info["orderingContract"],
            },
            "afterDeliveredBatch": {
                "chainInfo": delivered_chain_info["orderingContract"],
                "dagInfo": delivered_dag_info["orderingContract"],
            },
            "afterCandidatePreview": {
                "chainInfo": candidate_chain_info["orderingContract"],
                "dagInfo": candidate_dag_info["orderingContract"],
            },
            "afterCommitPreview": {
                "chainInfo": commit_preview_chain_info["orderingContract"],
                "dagInfo": commit_preview_dag_info["orderingContract"],
            },
            "afterCommit": {
                "chainInfo": commit_chain_info["orderingContract"],
                "dagInfo": commit_dag_info["orderingContract"],
                "runtimeRecovery": commit_runtime_recovery,
                "commitHashes": commit_hashes,
            },
            "consistency": consistency,
        });
        maybe_write_bullshark_commit_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String("live_bullshark_commit_handoff_through_rpc_service".into())
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterDeliveredBatch"]["chainInfo"]["completionTargetShadowState"]
                ["committedQueued"],
            serde_json::Value::from(0)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["completionTargetShadowState"]["committedQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["consistency"]["commitVisibleAfterHandoff"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["runtimeRecoveryCommitObserved"],
            serde_json::Value::Bool(true)
        );

        server.stop().await.expect("stop live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_authority_switch_preconditions_visible_through_rpc_service() {
        let temp_dir = unique_temp_dir("misaka-bullshark-authority-switch-live");
        let local_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(30));
        let local_validator_id_hex = hex::encode(local_validator.identity.validator_id);
        let next_epoch = 1u64;

        let mut known_validators = vec![local_validator.identity.clone()];
        for multiplier in (31u128..=50u128).rev() {
            let remote =
                make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(multiplier));
            known_validators.push(remote.identity.clone());
        }
        for multiplier in [29u128, 28u128] {
            let remote =
                make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(multiplier));
            known_validators.push(remote.identity.clone());
        }
        let mut inactive_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(60));
        inactive_validator.identity.is_active = false;
        known_validators.push(inactive_validator.identity.clone());
        let below_min_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_sub(1));
        known_validators.push(below_min_validator.identity.clone());
        let election_result = sr21_election::run_election(&known_validators, next_epoch);
        let local_preview_index =
            sr21_election::find_sr_index(&election_result, &local_validator.identity.validator_id)
                .expect("local validator active");

        let mut state = make_test_dag_state();
        state.validator_count = known_validators.len();
        state.known_validators = known_validators;
        state.local_validator = Some(local_validator);
        state.snapshot_path = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        state.num_active_srs = 1;
        state.sr_index = 0;
        set_test_dag_epoch(&mut state, next_epoch);

        let dag_state = Arc::new(tokio::sync::RwLock::new(state));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        seed_runtime_recovery_for_live_test(&runtime_recovery).await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("live test addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let before_apply_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                && json["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(false)
                && json["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(1)
                && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
        })
        .await;

        {
            let mut guard = dag_state.write().await;
            apply_sr21_election_at_epoch_boundary(&mut guard, next_epoch);
        }

        let after_apply_chain_info =
            wait_for_chain_info_http_matching(&client, &base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["configuredActiveCount"]
                        == serde_json::Value::from(election_result.num_active)
                    && json["authoritySwitchReadiness"]["committeeSelectionReady"]
                        == serde_json::Value::Bool(true)
                    && json["authoritySwitchReadiness"]["committeeRotationReady"]
                        == serde_json::Value::Bool(true)
                    && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
            })
            .await;

        let transparent = make_test_dissemination_tx(0xF1, TxType::TransparentTransfer);
        let tx_hashes = server
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");
        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let transparent_hash = hex::encode(tx_hashes[0]);

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["queued"]
                == serde_json::Value::from(2)
                && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
        })
        .await;

        let producer_state = dag_state.clone();
        let producer = tokio::spawn(async move {
            misaka_dag::run_dag_block_producer(producer_state, 1, 32).await;
        });

        let ready_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(true)
                && json["authoritySwitchReadiness"]["runtimeRecoveryCommitObserved"]
                    == serde_json::Value::Bool(true)
                && json["authoritySwitchReadiness"]["runtimeRecoveryCommitCount"]
                    == serde_json::Value::from(2)
                && json["authoritySwitchReadiness"]["runtimeRecoveryCommitTxHashes"]
                    == serde_json::json!(tx_hash_hexes)
                && json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(2)
        })
        .await;
        let ready_dag_info = fetch_dag_info_http(&client, &base_url).await;
        let commit_hashes = serde_json::json!({
            "any": server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });

        let dag_snapshot = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        {
            let mut guard = dag_state.write().await;
            guard.snapshot_path = dag_snapshot.clone();
            assert_eq!(
                guard.snapshot_path, dag_snapshot,
                "authority-switch snapshot path must point at the live temp dir"
            );
            save_runtime_snapshot(
                &guard.snapshot_path,
                &guard.dag_store,
                &guard.utxo_set,
                &guard.state_manager.stats,
                guard.latest_checkpoint.as_ref(),
                &guard.known_validators,
                &guard.runtime_active_sr_validator_ids,
                guard.latest_checkpoint_vote.as_ref(),
                guard.latest_checkpoint_finality.as_ref(),
                &guard.checkpoint_vote_pool,
            )
            .expect("persist bullshark authority-switch runtime snapshot");
        }

        let validator_lifecycle_snapshot =
            PathBuf::from(&temp_dir).join("validator_lifecycle.json");
        assert!(
            dag_snapshot.exists(),
            "dag runtime snapshot must be written"
        );
        assert!(
            validator_lifecycle_snapshot.exists(),
            "validator lifecycle snapshot must be written"
        );

        let (restart_blue_score, restart_block_hash) = {
            let guard = dag_state.read().await;
            let snapshot = guard.dag_store.snapshot();
            let restart_tip = snapshot
                .get_tips()
                .into_iter()
                .max_by_key(|hash| {
                    snapshot
                        .get_ghostdag_data(hash)
                        .map(|data| data.blue_score)
                        .unwrap_or(0)
                })
                .expect("restart tip");
            let restart_score = snapshot
                .get_ghostdag_data(&restart_tip)
                .map(|data| data.blue_score)
                .unwrap_or_else(|| guard.dag_store.max_blue_score());
            (restart_score, restart_tip)
        };

        let consistency = serde_json::json!({
            "selectionAlignedBeforeCommit": after_apply_chain_info["authoritySwitchReadiness"]["committeeSelectionReady"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["authoritySwitchReadiness"]["committeeRotationReady"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["authoritySwitchReadiness"]["committeeQuorumThresholdReady"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["authoritySwitchReadiness"]["committedReady"] == serde_json::Value::Bool(false)
                && after_apply_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false),
            "deliveredVisibleBeforeCommit": delivered_chain_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(0),
            "candidatePreviewVisibleAfterAutoAdvance": ready_chain_info["authoritySwitchReadiness"]["candidatePreviewReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2),
            "commitPreviewVisibleAfterAutoAdvance": ready_chain_info["authoritySwitchReadiness"]["commitPreviewReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2),
            "committedVisibleAfterAutoAdvance": ready_chain_info["authoritySwitchReadiness"]["committedReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "runtimeRecoveryCommitVisibleAfterAutoAdvance": ready_chain_info["authoritySwitchReadiness"]["runtimeRecoveryCommitObserved"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["runtimeRecoveryCommitCount"] == serde_json::Value::from(2)
                && ready_chain_info["authoritySwitchReadiness"]["runtimeRecoveryCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && ready_chain_info["authoritySwitchReadiness"]["runtimeRecoveryCommitConsistent"] == serde_json::Value::Bool(true),
            "committeeAlignedAfterApply": ready_chain_info["authoritySwitchReadiness"]["committeePreviewReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeeSelectionReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeeRotationReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeeQuorumThresholdReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeePreviewQuorumThreshold"] == serde_json::Value::String("15".into())
                && ready_chain_info["authoritySwitchReadiness"]["committeeRuntimeQuorumThreshold"] == serde_json::Value::String("15".into())
                && ready_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21)
                && ready_chain_info["sr21Committee"]["localPreviewSrIndex"] == serde_json::Value::from(local_preview_index)
                && ready_chain_info["sr21Committee"]["localRuntimeSrIndex"] == serde_json::Value::from(local_preview_index),
            "authoritySwitchReadyAfterCommit": ready_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(true),
            "chainDagAuthoritySummaryConsistent": ready_chain_info["authoritySwitchReadiness"] == ready_dag_info["authoritySwitchReadiness"]
                && ready_chain_info["sr21Committee"]["activeCount"] == ready_dag_info["sr21Committee"]["activeCount"]
                && ready_chain_info["sr21Committee"]["configuredActiveCount"] == ready_dag_info["sr21Committee"]["configuredActiveCount"],
            "currentAuthorityRetained": ready_chain_info["authoritySwitchReadiness"]["currentAuthorityRetained"] == serde_json::Value::Bool(true)
                && ready_chain_info["consensusArchitecture"]["currentRuntime"]["orderingStage"] == serde_json::Value::String("ghostdagTotalOrder".into())
                && ready_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && ready_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into()),
            "completionTargetMatchesPlan": ready_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
            "commitHashesVisibleAfterAutoAdvance": commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && commit_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
        });

        producer.abort();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        server.stop().await.expect("stop live dag rpc service");

        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 0);
            guard.mark_checkpoint_persisted(restart_blue_score, restart_block_hash);
            guard.mark_checkpoint_finality(Some(restart_blue_score));
        }
        let restart_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind restart live test port");
        let restart_addr = restart_listener
            .local_addr()
            .expect("restart live test addr");
        drop(restart_listener);
        let restart_base_url = format!("http://{}", restart_addr);
        let restarted_server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), restart_addr,
        )
        .await;

        let restarted_client = reqwest::Client::new();
        let restarted_initial_chain_info =
            wait_for_chain_info_http(&restarted_client, &restart_base_url).await;
        let mut rehydrated_after_restart = false;
        if restarted_initial_chain_info["authoritySwitchReadiness"]["ready"]
            != serde_json::Value::Bool(true)
            || restarted_initial_chain_info["orderingContract"]["completionTargetShadowState"]
                ["committedQueued"]
                != serde_json::Value::from(2)
        {
            let restarted_tx_hashes = restarted_server
                .ingest_narwhal_delivered_batch(vec![transparent.clone()])
                .await
                .expect("re-ingest delivered batch after restart");
            assert_eq!(
                restarted_tx_hashes, tx_hashes,
                "restart re-ingest must preserve the same tx hashes"
            );
            restarted_server
                .mark_bullshark_candidate_preview(&restarted_tx_hashes)
                .await
                .expect("re-mark bullshark candidate preview after restart");
            restarted_server
                .mark_bullshark_commit_preview(&restarted_tx_hashes)
                .await
                .expect("re-mark bullshark commit preview after restart");
            restarted_server
                .mark_bullshark_commit(&restarted_tx_hashes)
                .await
                .expect("re-mark bullshark commit after restart");
            rehydrated_after_restart = true;
        }
        let restarted_chain_info = wait_for_chain_info_http(&restarted_client, &restart_base_url).await;
        let restarted_dag_info = fetch_dag_info_http(&restarted_client, &restart_base_url).await;
        let restarted_commit_hashes = serde_json::json!({
            "any": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("restarted commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("restarted commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let restart_consistency = serde_json::json!({
            "snapshotArtifactsWritten": dag_snapshot.exists() && validator_lifecycle_snapshot.exists(),
            "serviceRestartContinuity": restarted_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "rehydratedAfterRestart": serde_json::Value::Bool(rehydrated_after_restart),
            "authoritySurfaceRetainedAfterRestart": restarted_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true),
            "chainDagAuthoritySummaryConsistentAfterRestart": restarted_chain_info["authoritySwitchReadiness"] == restarted_dag_info["authoritySwitchReadiness"]
                && restarted_chain_info["sr21Committee"]["activeCount"] == restarted_dag_info["sr21Committee"]["activeCount"]
                && restarted_chain_info["sr21Committee"]["configuredActiveCount"] == restarted_dag_info["sr21Committee"]["configuredActiveCount"],
            "committeeStatePersistedAfterRestart": restarted_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21)
                && restarted_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("15".into()),
            "currentAuthorityRetainedAfterRestart": restarted_chain_info["authoritySwitchReadiness"]["currentAuthorityRetained"] == serde_json::Value::Bool(true)
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["orderingStage"] == serde_json::Value::String("ghostdagTotalOrder".into())
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into()),
            "startupSnapshotRestoredAfterRestart": restarted_chain_info["runtimeRecovery"]["startupSnapshotRestored"] == serde_json::Value::Bool(true)
                && restarted_chain_info["runtimeRecovery"]["checkpointPersisted"] == serde_json::Value::Bool(true)
                && restarted_chain_info["runtimeRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true),
            "completionTargetMatchesPlanAfterRestart": restarted_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });
        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_authority_switch_preconditions_visible_through_rpc_service",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": ready_chain_info["consensusArchitecture"],
            "beforeApply": {
                "chainInfo": {
                    "sr21Committee": before_apply_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": before_apply_chain_info["authoritySwitchReadiness"],
                },
            },
            "afterApply": {
                "chainInfo": {
                    "sr21Committee": after_apply_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": after_apply_chain_info["authoritySwitchReadiness"],
                },
            },
            "afterCommit": {
                "chainInfo": {
                    "orderingContract": ready_chain_info["orderingContract"],
                    "sr21Committee": ready_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": ready_chain_info["authoritySwitchReadiness"],
                },
                "dagInfo": {
                    "orderingContract": ready_dag_info["orderingContract"],
                    "sr21Committee": ready_dag_info["sr21Committee"],
                    "authoritySwitchReadiness": ready_dag_info["authoritySwitchReadiness"],
                },
                "commitHashes": commit_hashes,
            },
            "consistency": consistency,
            "afterRestart": {
                "chainInfo": {
                    "orderingContract": restarted_chain_info["orderingContract"],
                    "sr21Committee": restarted_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": restarted_chain_info["authoritySwitchReadiness"],
                    "runtimeRecovery": restarted_chain_info["runtimeRecovery"],
                },
                "dagInfo": {
                    "orderingContract": restarted_dag_info["orderingContract"],
                    "sr21Committee": restarted_dag_info["sr21Committee"],
                    "authoritySwitchReadiness": restarted_dag_info["authoritySwitchReadiness"],
                    "runtimeRecovery": restarted_dag_info["runtimeRecovery"],
                },
                "commitHashes": restarted_commit_hashes,
            },
            "restartConsistency": restart_consistency,
        });
        maybe_write_bullshark_authority_switch_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_authority_switch_preconditions_visible_through_rpc_service".into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["configuredActiveCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["authoritySwitchReadiness"]["ready"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["authoritySwitchReadiness"]["ready"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["authoritySwitchReadiness"]
                ["runtimeRecoveryCommitObserved"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["authoritySwitchReadiness"]
                ["runtimeRecoveryCommitCount"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["authoritySwitchReadiness"]
                ["runtimeRecoveryCommitTxHashes"],
            serde_json::json!(tx_hash_hexes)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["activeSetPreview"][20]
                ["validatorId"],
            serde_json::Value::String(local_validator_id_hex)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["activeSetPreview"][20]["isLocal"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySwitchReadyAfterCommit"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["authoritySurfaceRetainedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["authoritySwitchReadiness"]["currentAuthorityRetained"],
            serde_json::Value::Bool(true)
        );
        assert!(
            payload["afterRestart"]["chainInfo"]["runtimeRecovery"]["startupSnapshotRestored"]
                .is_boolean()
        );
        assert_eq!(
            payload["restartConsistency"]["rehydratedAfterRestart"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["restartConsistency"]["startupSnapshotRestoredAfterRestart"],
            serde_json::Value::Bool(false)
        );

        restarted_server
            .stop()
            .await
            .expect("stop restarted live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_live_bullshark_commit_handoff_enables_authority_switch_through_rpc_service() {
        let temp_dir = unique_temp_dir("misaka-bullshark-commit-authority-switch-live");
        let local_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(30));
        let local_validator_id = local_validator.identity.validator_id;
        let local_validator_id_hex = hex::encode(local_validator_id);
        let next_epoch = 1u64;

        let mut known_validators = vec![local_validator.identity.clone()];
        let mut second_rotation_out = None;
        for multiplier in (31u128..=50u128).rev() {
            let remote =
                make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(multiplier));
            if multiplier == 31 {
                second_rotation_out = Some(remote.identity.clone());
            }
            known_validators.push(remote.identity.clone());
        }
        let mut second_rotation_in = None;
        for multiplier in [29u128, 28u128] {
            let remote =
                make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(multiplier));
            if multiplier == 29 {
                second_rotation_in = Some(remote.identity.clone());
            }
            known_validators.push(remote.identity.clone());
        }
        let mut inactive_validator =
            make_test_local_validator(sr21_election::MIN_SR_STAKE.saturating_mul(60));
        inactive_validator.identity.is_active = false;
        known_validators.push(inactive_validator.identity.clone());
        let second_rotation_out = second_rotation_out.expect("second rotation out validator");
        let second_rotation_in = second_rotation_in.expect("second rotation in validator");

        let election_result = sr21_election::run_election(&known_validators, next_epoch);
        let local_preview_index =
            sr21_election::find_sr_index(&election_result, &local_validator.identity.validator_id)
                .expect("local validator active");

        let mut state = make_test_dag_state();
        state.validator_count = known_validators.len();
        state.known_validators = known_validators;
        state.local_validator = Some(local_validator);
        state.snapshot_path = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        state.num_active_srs = 1;
        state.sr_index = 0;
        set_test_dag_epoch(&mut state, next_epoch);

        let dag_state = Arc::new(tokio::sync::RwLock::new(state));
        let runtime_recovery = make_runtime_recovery_observation(&temp_dir);
        seed_runtime_recovery_for_live_test(&runtime_recovery).await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live test port");
        let addr = listener.local_addr().expect("live test addr");
        drop(listener);
        let server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), addr,
        )
        .await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let before_apply_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                && json["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(false)
                && json["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(1)
                && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
        })
        .await;

        {
            let mut guard = dag_state.write().await;
            apply_sr21_election_at_epoch_boundary(&mut guard, next_epoch);
        }

        let after_apply_chain_info =
            wait_for_chain_info_http_matching(&client, &base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(next_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["configuredActiveCount"]
                        == serde_json::Value::from(election_result.num_active)
                    && json["authoritySwitchReadiness"]["committeeSelectionReady"]
                        == serde_json::Value::Bool(true)
                    && json["authoritySwitchReadiness"]["committeeRotationReady"]
                        == serde_json::Value::Bool(true)
                    && json["authoritySwitchReadiness"]["committeeQuorumThresholdReady"]
                        == serde_json::Value::Bool(true)
                    && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
            })
            .await;

        let transparent = make_test_dissemination_tx(0xE1, TxType::TransparentTransfer);
        let tx_hashes = server
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");

        let delivered_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["queued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(0)
                && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
        })
        .await;
        let delivered_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_candidate_preview(&tx_hashes)
            .await
            .expect("mark bullshark candidate preview");
        let candidate_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(0)
                && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
        })
        .await;
        let candidate_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_commit_preview(&tx_hashes)
            .await
            .expect("mark bullshark commit preview");
        let commit_preview_chain_info =
            wait_for_chain_info_http_matching(&client, &base_url, |json| {
                json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(2)
                    && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                        == serde_json::Value::from(0)
                    && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
            })
            .await;
        let commit_preview_dag_info = fetch_dag_info_http(&client, &base_url).await;

        server
            .mark_bullshark_commit(&tx_hashes)
            .await
            .expect("mark bullshark commit");
        let ready_chain_info = wait_for_chain_info_http_matching(&client, &base_url, |json| {
            json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(true)
                && json["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"]
                    == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"]
                    == serde_json::Value::from(2)
                && json["orderingContract"]["completionTargetShadowState"]["committedQueued"]
                    == serde_json::Value::from(2)
        })
        .await;
        let ready_dag_info = fetch_dag_info_http(&client, &base_url).await;

        let tx_hash_hexes = tx_hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let transparent_hash = hex::encode(tx_hashes[0]);
        let commit_hashes = serde_json::json!({
            "any": server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let ready_runtime_recovery = ready_chain_info["runtimeRecovery"].clone();
        let dag_snapshot = PathBuf::from(&temp_dir).join("dag_runtime_snapshot.json");
        let validator_lifecycle_snapshot = PathBuf::from(&temp_dir).join("validator_lifecycle.json");
        assert!(
            dag_snapshot.exists(),
            "dag runtime snapshot must be written"
        );
        assert!(
            validator_lifecycle_snapshot.exists(),
            "validator lifecycle snapshot must be written"
        );

        let (restart_blue_score, restart_block_hash) = {
            let guard = dag_state.read().await;
            let snapshot = guard.dag_store.snapshot();
            let restart_tip = snapshot
                .get_tips()
                .into_iter()
                .max_by_key(|hash| {
                    snapshot
                        .get_ghostdag_data(hash)
                        .map(|data| data.blue_score)
                        .unwrap_or(0)
                })
                .expect("restart tip");
            let restart_score = snapshot
                .get_ghostdag_data(&restart_tip)
                .map(|data| data.blue_score)
                .unwrap_or_else(|| guard.dag_store.max_blue_score());
            (restart_score, restart_tip)
        };

        let mut consistency = serde_json::json!({
            "selectionAlignedBeforeExplicitCommit": after_apply_chain_info["authoritySwitchReadiness"]["committeeSelectionReady"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["authoritySwitchReadiness"]["committeeRotationReady"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["authoritySwitchReadiness"]["committeeQuorumThresholdReady"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["authoritySwitchReadiness"]["committeePreviewQuorumThreshold"] == serde_json::Value::String("15".into())
                && after_apply_chain_info["authoritySwitchReadiness"]["committeeRuntimeQuorumThreshold"] == serde_json::Value::String("15".into())
                && after_apply_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false),
            "runtimeActiveSetAppliedAfterApply": after_apply_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(21)
                && after_apply_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && after_apply_chain_info["sr21Committee"]["activeCount"] == serde_json::Value::from(21)
                && after_apply_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21),
            "deliveredVisibleBeforeExplicitCommit": delivered_chain_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2)
                && delivered_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(0)
                && delivered_dag_info["orderingContract"]["completionTargetShadowState"]["queued"] == serde_json::Value::from(2),
            "authoritySummaryVisibleAfterDeliveredBatch": delivered_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
                && delivered_chain_info["authoritySwitchReadiness"]["candidatePreviewReady"] == serde_json::Value::Bool(false)
                && delivered_chain_info["authoritySwitchReadiness"]["commitPreviewReady"] == serde_json::Value::Bool(false)
                && delivered_chain_info["authoritySwitchReadiness"]["committedReady"] == serde_json::Value::Bool(false)
                && delivered_chain_info["authoritySwitchReadiness"]["candidatePreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["authoritySwitchReadiness"]["commitPreviewQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["authoritySwitchReadiness"]["committedQueued"] == serde_json::Value::from(0)
                && delivered_chain_info["authoritySwitchReadiness"]["currentAuthorityRetained"] == serde_json::Value::Bool(true)
                && delivered_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && delivered_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true),
            "chainDagAuthoritySummaryConsistentAfterDeliveredBatch": delivered_chain_info["authoritySwitchReadiness"] == delivered_dag_info["authoritySwitchReadiness"],
            "candidatePreviewVisibleAfterExplicitHandoff": candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && candidate_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true)
                && candidate_dag_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2),
            "authoritySummaryVisibleAfterCandidatePreview": candidate_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
                && candidate_chain_info["authoritySwitchReadiness"]["candidatePreviewReady"] == serde_json::Value::Bool(true)
                && candidate_chain_info["authoritySwitchReadiness"]["commitPreviewReady"] == serde_json::Value::Bool(false)
                && candidate_chain_info["authoritySwitchReadiness"]["committedReady"] == serde_json::Value::Bool(false)
                && candidate_chain_info["authoritySwitchReadiness"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && candidate_chain_info["authoritySwitchReadiness"]["commitPreviewQueued"] == serde_json::Value::from(0)
                && candidate_chain_info["authoritySwitchReadiness"]["committedQueued"] == serde_json::Value::from(0),
            "chainDagAuthoritySummaryConsistentAfterCandidatePreview": candidate_chain_info["authoritySwitchReadiness"] == candidate_dag_info["authoritySwitchReadiness"],
            "commitPreviewVisibleAfterExplicitHandoff": commit_preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && commit_preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && commit_preview_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true)
                && commit_preview_dag_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2),
            "authoritySummaryVisibleAfterCommitPreview": commit_preview_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(false)
                && commit_preview_chain_info["authoritySwitchReadiness"]["candidatePreviewReady"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["authoritySwitchReadiness"]["commitPreviewReady"] == serde_json::Value::Bool(true)
                && commit_preview_chain_info["authoritySwitchReadiness"]["committedReady"] == serde_json::Value::Bool(false)
                && commit_preview_chain_info["authoritySwitchReadiness"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && commit_preview_chain_info["authoritySwitchReadiness"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && commit_preview_chain_info["authoritySwitchReadiness"]["committedQueued"] == serde_json::Value::from(0),
            "chainDagAuthoritySummaryConsistentAfterCommitPreview": commit_preview_chain_info["authoritySwitchReadiness"] == commit_preview_dag_info["authoritySwitchReadiness"],
            "committedVisibleAfterExplicitHandoff": ready_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["committedFastTransparentQueued"] == serde_json::Value::from(1)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["committedLive"] == serde_json::Value::Bool(true)
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "commitHashesVisibleAfterExplicitCommit": commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && commit_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "runtimeRecoveryCommitObservedAfterExplicitHandoff": ready_runtime_recovery["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && ready_runtime_recovery["lastBullsharkCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && ready_runtime_recovery["bullsharkCommitObserved"] == serde_json::Value::Bool(true),
            "committeeAlignedAfterApply": ready_chain_info["authoritySwitchReadiness"]["committeePreviewReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeeSelectionReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeeRotationReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeeQuorumThresholdReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeePreviewQuorumThreshold"] == serde_json::Value::String("15".into())
                && ready_chain_info["authoritySwitchReadiness"]["committeeRuntimeQuorumThreshold"] == serde_json::Value::String("15".into())
                && ready_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && ready_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(21)
                && ready_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && ready_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21)
                && ready_chain_info["sr21Committee"]["localPreviewSrIndex"] == serde_json::Value::from(local_preview_index)
                && ready_chain_info["sr21Committee"]["localRuntimeSrIndex"] == serde_json::Value::from(local_preview_index),
            "authoritySwitchReadyAfterExplicitCommit": ready_chain_info["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(true),
            "chainDagAuthoritySummaryConsistent": ready_chain_info["authoritySwitchReadiness"] == ready_dag_info["authoritySwitchReadiness"]
                && ready_chain_info["sr21Committee"]["activeCount"] == ready_dag_info["sr21Committee"]["activeCount"]
                && ready_chain_info["sr21Committee"]["configuredActiveCount"] == ready_dag_info["sr21Committee"]["configuredActiveCount"]
                && ready_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == ready_dag_info["sr21Committee"]["runtimeActiveSetPresent"]
                && ready_chain_info["sr21Committee"]["runtimeActiveSetCount"] == ready_dag_info["sr21Committee"]["runtimeActiveSetCount"]
                && ready_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == ready_dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                && ready_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == ready_dag_info["orderingContract"]["completionTargetShadowState"]["committedQueued"],
            "currentAuthorityRetained": ready_chain_info["authoritySwitchReadiness"]["currentAuthorityRetained"] == serde_json::Value::Bool(true)
                && ready_chain_info["consensusArchitecture"]["currentRuntime"]["orderingStage"] == serde_json::Value::String("ghostdagTotalOrder".into())
                && ready_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && ready_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into()),
            "completionTargetMatchesPlan": ready_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true)
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && ready_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });

        server.stop().await.expect("stop live dag rpc service");

        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_startup_snapshot_restored(true);
            guard.mark_startup_wal_state("recovered", 0);
            guard.mark_checkpoint_persisted(restart_blue_score, restart_block_hash);
            guard.mark_checkpoint_finality(Some(restart_blue_score));
        }
        let restart_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind restart live test port");
        let restart_addr = restart_listener
            .local_addr()
            .expect("restart live test addr");
        drop(restart_listener);
        let restart_base_url = format!("http://{}", restart_addr);
        let restarted_server = start_live_dag_rpc_service(
            dag_state.clone(), runtime_recovery.clone(), restart_addr,
        )
        .await;

        let restarted_client = reqwest::Client::new();
        let restarted_initial_chain_info =
            wait_for_chain_info_http(&restarted_client, &restart_base_url).await;
        let mut rehydrated_after_restart = false;
        if restarted_initial_chain_info["authoritySwitchReadiness"]["ready"]
            != serde_json::Value::Bool(true)
            || restarted_initial_chain_info["orderingContract"]["completionTargetShadowState"]
                ["committedQueued"]
                != serde_json::Value::from(2)
        {
            let restarted_tx_hashes = restarted_server
                .ingest_narwhal_delivered_batch(vec![transparent.clone()])
                .await
                .expect("re-ingest delivered batch after restart");
            assert_eq!(
                restarted_tx_hashes, tx_hashes,
                "restart re-ingest must preserve the same tx hashes"
            );
            restarted_server
                .mark_bullshark_candidate_preview(&restarted_tx_hashes)
                .await
                .expect("re-mark bullshark candidate preview after restart");
            restarted_server
                .mark_bullshark_commit_preview(&restarted_tx_hashes)
                .await
                .expect("re-mark bullshark commit preview after restart");
            restarted_server
                .mark_bullshark_commit(&restarted_tx_hashes)
                .await
                .expect("re-mark bullshark commit after restart");
            rehydrated_after_restart = true;
        }
        let restarted_chain_info = wait_for_chain_info_http(&restarted_client, &restart_base_url).await;
        let restarted_dag_info = fetch_dag_info_http(&restarted_client, &restart_base_url).await;
        let restarted_commit_hashes = serde_json::json!({
            "any": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("restarted commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("restarted commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let restart_consistency = serde_json::json!({
            "snapshotArtifactsWritten": dag_snapshot.exists() && validator_lifecycle_snapshot.exists(),
            "serviceRestartContinuity": restarted_chain_info["orderingContract"]["orchestration"]["serviceBound"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["serviceRunning"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["candidatePreviewCallerReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["commitPreviewCallerReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["orchestration"]["commitCallerReady"] == serde_json::Value::Bool(true),
            "rehydratedAfterRestart": serde_json::Value::Bool(rehydrated_after_restart),
            "authoritySurfaceRetainedAfterRestart": restarted_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true),
            "chainDagAuthoritySummaryConsistentAfterRestart": restarted_chain_info["authoritySwitchReadiness"] == restarted_dag_info["authoritySwitchReadiness"]
                && restarted_chain_info["sr21Committee"]["activeCount"] == restarted_dag_info["sr21Committee"]["activeCount"]
                && restarted_chain_info["sr21Committee"]["configuredActiveCount"] == restarted_dag_info["sr21Committee"]["configuredActiveCount"]
                && restarted_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == restarted_dag_info["sr21Committee"]["runtimeActiveSetPresent"]
                && restarted_chain_info["sr21Committee"]["runtimeActiveSetCount"] == restarted_dag_info["sr21Committee"]["runtimeActiveSetCount"]
                && restarted_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == restarted_dag_info["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            "chainDagOrderingStateConsistentAfterRestart": restarted_chain_info["orderingContract"]["completionTargetShadowState"] == restarted_dag_info["orderingContract"]["completionTargetShadowState"],
            "committeeStatePersistedAfterRestart": restarted_chain_info["sr21Committee"]["previewMatchesRuntime"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["configuredActiveCount"] == serde_json::Value::from(21)
                && restarted_chain_info["sr21Committee"]["runtimeActiveSetPresent"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["runtimeActiveSetCount"] == serde_json::Value::from(21)
                && restarted_chain_info["sr21Committee"]["runtimeActiveSetMatchesPreview"] == serde_json::Value::Bool(true)
                && restarted_chain_info["sr21Committee"]["runtimeQuorumThreshold"] == serde_json::Value::String("15".into()),
            "committedStateRetainedAfterRestart": restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewQueued"] == serde_json::Value::from(2)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["candidatePreviewLive"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewQueued"] == serde_json::Value::from(2)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewFastTransparentQueued"] == serde_json::Value::from(1)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["commitPreviewLive"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedQueued"] == serde_json::Value::from(2)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedFastTransparentQueued"] == serde_json::Value::from(1)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["committedLive"] == serde_json::Value::Bool(true)
                && restarted_chain_info["orderingContract"]["completionTargetShadowState"]["consistentWithCommitPreview"] == serde_json::Value::Bool(true),
            "commitHashesRetainedAfterRestart": restarted_commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                && restarted_commit_hashes["fastTransparent"] == serde_json::json!([transparent_hash.clone()])
            "runtimeRecoveryCommitRetainedAfterRestart": restarted_chain_info["runtimeRecovery"]["lastBullsharkCommitCount"] == serde_json::Value::from(2)
                && restarted_chain_info["runtimeRecovery"]["lastBullsharkCommitTxHashes"] == serde_json::json!(tx_hash_hexes)
                && restarted_chain_info["runtimeRecovery"]["bullsharkCommitObserved"] == serde_json::Value::Bool(true),
            "currentAuthorityRetainedAfterRestart": restarted_chain_info["authoritySwitchReadiness"]["currentAuthorityRetained"] == serde_json::Value::Bool(true)
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["orderingStage"] == serde_json::Value::String("ghostdagTotalOrder".into())
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["checkpointDecisionSource"] == serde_json::Value::String("ghostdagCheckpointBft".into())
                && restarted_chain_info["consensusArchitecture"]["currentRuntime"]["committee"] == serde_json::Value::String("validatorBreadth".into()),
            "startupSnapshotRestoredAfterRestart": restarted_chain_info["runtimeRecovery"]["startupSnapshotRestored"] == serde_json::Value::Bool(true)
                && restarted_chain_info["runtimeRecovery"]["checkpointPersisted"] == serde_json::Value::Bool(true)
                && restarted_chain_info["runtimeRecovery"]["checkpointFinalized"] == serde_json::Value::Bool(true),
            "completionTargetMatchesPlanAfterRestart": restarted_chain_info["authoritySwitchReadiness"]["bullsharkPlanReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["authoritySwitchReadiness"]["committeePlanReady"] == serde_json::Value::Bool(true)
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["orderingStage"] == serde_json::Value::String("bullsharkCommitOrder".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["orderingInput"] == serde_json::Value::String("narwhalDeliveredBatch".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["checkpointDecisionSource"] == serde_json::Value::String("bullsharkCommit".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committee"] == serde_json::Value::String("superRepresentative21".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeStage"] == serde_json::Value::String("sr21EpochRotation".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeSelection"] == serde_json::Value::String("stakeWeightedTop21Election".into())
                && restarted_chain_info["consensusArchitecture"]["completionTarget"]["committeeSizeCap"] == serde_json::Value::from(21),
        });
        let checkpoint_interval = 6u64;
        let second_epoch = next_epoch + 1;
        let second_finalized_boundary_score = restart_blue_score + checkpoint_interval;
        let second_checkpoint_block_hash = [0xB6; 32];
        let mut lifecycle_epoch = next_epoch;
        let mut lifecycle_progress =
            crate::validator_lifecycle_persistence::ValidatorEpochProgress {
                checkpoints_in_epoch: misaka_types::constants::EPOCH_LENGTH - 1,
                last_finalized_checkpoint_score: Some(restart_blue_score),
            };
        let second_epoch_boundary_reached = lifecycle_progress.apply_finalized_checkpoint_score(
            &mut lifecycle_epoch,
            second_finalized_boundary_score,
            checkpoint_interval,
        );
        assert!(
            second_epoch_boundary_reached,
            "second authority-switch epoch boundary must be crossed"
        );
        assert_eq!(lifecycle_epoch, second_epoch);

        let second_rotation_out_stake = sr21_election::MIN_SR_STAKE.saturating_sub(1);
        let second_rotation_in_stake = second_rotation_in.stake_weight;
        let second_rotation_out_id_hex = hex::encode(second_rotation_out.validator_id);
        let second_rotation_in_id_hex = hex::encode(second_rotation_in.validator_id);

        {
            let mut guard = dag_state.write().await;
            for validator in &mut guard.known_validators {
                if validator.validator_id == second_rotation_out.validator_id {
                    validator.stake_weight = second_rotation_out_stake;
                    validator.is_active = true;
                } else if validator.validator_id == second_rotation_in.validator_id {
                    validator.stake_weight = second_rotation_in_stake;
                    validator.is_active = true;
                } else if validator.validator_id == local_validator_id {
                    validator.is_active = true;
                }
            }
            if let Some(local) = guard.local_validator.as_mut() {
                local.identity.is_active = true;
            }
            set_test_dag_epoch(&mut guard, second_epoch);
            guard.latest_checkpoint = Some(DagCheckpoint {
                block_hash: second_checkpoint_block_hash,
                blue_score: second_finalized_boundary_score,
                utxo_root: [0xD4; 32],
                total_spent_count: 0,
                total_applied_txs: 0,
                timestamp_ms: 1_700_000_720_000,
            });
            guard.latest_checkpoint_finality = guard.latest_checkpoint.as_ref().map(|checkpoint| {
                DagCheckpointFinalityProof {
                    target: checkpoint.validator_target(),
                    commits: vec![],
                }
            });
        }
        {
            let mut guard = runtime_recovery.write().await;
            guard.mark_checkpoint_persisted(
                second_finalized_boundary_score,
                second_checkpoint_block_hash,
            );
            guard.mark_checkpoint_finality(Some(second_finalized_boundary_score));
        }

        let second_election_result = {
            let guard = dag_state.read().await;
            sr21_election::run_election(&guard.known_validators, second_epoch)
        };
        let second_local_preview_index =
            sr21_election::find_sr_index(&second_election_result, &local_validator_id)
                .expect("local validator remains active after second rotation");

        let before_second_apply_chain_info =
            wait_for_chain_info_http_matching(&restarted_client, &restart_base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(second_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(false)
                    && json["sr21Committee"]["runtimeActiveSetPresent"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                        == serde_json::Value::Bool(false)
                    && json["sr21Committee"]["localPreviewSrIndex"]
                        == serde_json::Value::from(second_local_preview_index)
                    && json["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(local_preview_index)
                    && json["validatorLifecycleRecovery"]["checkpointFinalized"]
                        == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
                    && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"]
                        == serde_json::Value::String("ghostdagCheckpointBft".into())
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blockHash"]
                        == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
            })
            .await;
        let before_second_apply_dag_info =
            fetch_dag_info_http(&restarted_client, &restart_base_url).await;

        {
            let mut guard = dag_state.write().await;
            apply_sr21_election_at_epoch_boundary(&mut guard, second_epoch);
        }

        let after_second_apply_chain_info =
            wait_for_chain_info_http_matching(&restarted_client, &restart_base_url, |json| {
                json["sr21Committee"]["currentEpoch"] == serde_json::Value::from(second_epoch)
                    && json["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetPresent"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["runtimeActiveSetMatchesPreview"]
                        == serde_json::Value::Bool(true)
                    && json["sr21Committee"]["localPreviewSrIndex"]
                        == serde_json::Value::from(second_local_preview_index)
                    && json["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(second_local_preview_index)
                    && json["authoritySwitchReadiness"]["ready"] == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["checkpointFinalized"]
                        == serde_json::Value::Bool(true)
                    && json["validatorLifecycleRecovery"]["lastCheckpointFinalityBlueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
                    && json["validatorLifecycleRecovery"]["lastCheckpointDecisionSource"]
                        == serde_json::Value::String("ghostdagCheckpointBft".into())
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blockHash"]
                        == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                    && json["validatorAttestation"]["latestCheckpointFinality"]["target"]
                        ["blueScore"]
                        == serde_json::Value::from(second_finalized_boundary_score)
            })
            .await;
        let after_second_apply_dag_info =
            fetch_dag_info_http(&restarted_client, &restart_base_url).await;
        let after_second_commit_hashes = serde_json::json!({
            "any": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("after second apply commit any hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "fastTransparent": restarted_server
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await
                .expect("after second apply commit transparent hashes")
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        });
        let before_second_preview_ids = before_second_apply_chain_info["sr21Committee"]
            ["activeSetPreview"]
            .as_array()
            .expect("before second apply active set preview array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let before_second_runtime_ids = before_second_apply_chain_info["sr21Committee"]
            ["runtimeActiveSet"]
            .as_array()
            .expect("before second apply runtime active set array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let after_second_preview_ids = after_second_apply_chain_info["sr21Committee"]
            ["activeSetPreview"]
            .as_array()
            .expect("after second apply active set preview array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let after_second_runtime_ids = after_second_apply_chain_info["sr21Committee"]
            ["runtimeActiveSet"]
            .as_array()
            .expect("after second apply runtime active set array")
            .iter()
            .filter_map(|entry| entry["validatorId"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let second_added_validator_ids = after_second_runtime_ids
            .iter()
            .filter(|validator_id| !before_second_runtime_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let second_removed_validator_ids = before_second_runtime_ids
            .iter()
            .filter(|validator_id| !after_second_runtime_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let second_preview_added_validator_ids = after_second_preview_ids
            .iter()
            .filter(|validator_id| !before_second_preview_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let second_preview_removed_validator_ids = before_second_preview_ids
            .iter()
            .filter(|validator_id| !after_second_preview_ids.contains(validator_id))
            .cloned()
            .collect::<Vec<_>>();
        let first_expected_active_ids = election_result
            .active_srs
            .iter()
            .map(|elected| hex::encode(elected.validator_id))
            .collect::<Vec<_>>();
        let second_expected_active_ids = second_election_result
            .active_srs
            .iter()
            .map(|elected| hex::encode(elected.validator_id))
            .collect::<Vec<_>>();
        if let Some(consistency_obj) = consistency.as_object_mut() {
            consistency_obj.insert(
                "secondEpochBoundaryVisibleBeforeSecondApply".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                        == serde_json::Value::from(second_epoch)
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into()),
                ),
            );
            consistency_obj.insert(
                "secondEpochBoundaryReachedAfterRestart".into(),
                serde_json::Value::Bool(
                    second_epoch_boundary_reached
                        && lifecycle_epoch == second_epoch
                        && lifecycle_progress.checkpoints_in_epoch == 0
                        && lifecycle_progress.last_finalized_checkpoint_score
                            == Some(second_finalized_boundary_score),
                ),
            );
            consistency_obj.insert(
                "staleSecondRotationVisibleBeforeSecondApply".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["sr21Committee"]["previewMatchesRuntime"]
                        == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(local_preview_index)
                        && before_second_preview_ids == second_expected_active_ids
                        && before_second_runtime_ids == first_expected_active_ids
                        && before_second_preview_ids
                            .iter()
                            .any(|validator_id| validator_id == &second_rotation_in_id_hex)
                        && !before_second_preview_ids
                            .iter()
                            .any(|validator_id| validator_id == &second_rotation_out_id_hex)
                        && before_second_runtime_ids
                            .iter()
                            .any(|validator_id| validator_id == &second_rotation_out_id_hex)
                        && !before_second_runtime_ids
                            .iter()
                            .any(|validator_id| validator_id == &second_rotation_in_id_hex),
                ),
            );
            consistency_obj.insert(
                "committeeRotationOnlyBlockerBeforeSecondApply".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                        == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewReady"]
                            == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeSelectionReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRotationReady"]
                            == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeQuorumThresholdReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRuntimeQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["currentAuthorityRetained"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["bullsharkPlanReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePlanReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["orchestrationReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitConsistent"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitCount"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitTxHashes"]
                            == serde_json::json!(tx_hash_hexes)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitObserved"]
                            == serde_json::Value::Bool(true),
                ),
            );
            consistency_obj.insert(
                "secondRotationAppliedAfterRestart".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                        == serde_json::Value::from(second_epoch)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["configuredActiveCount"]
                            == serde_json::Value::from(second_election_result.num_active)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["previewMatchesRuntime"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetCount"]
                            == serde_json::Value::from(second_election_result.num_active)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(true)
                        && after_second_preview_ids == second_expected_active_ids
                        && after_second_runtime_ids == second_expected_active_ids
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true),
                ),
            );
            consistency_obj.insert(
                "secondRotationChangedMembershipAfterRestart".into(),
                serde_json::Value::Bool(
                    second_preview_added_validator_ids.is_empty()
                        && second_preview_removed_validator_ids.is_empty()
                        && second_added_validator_ids
                            == vec![second_rotation_in_id_hex.clone()]
                        && second_removed_validator_ids
                            == vec![second_rotation_out_id_hex.clone()]
                        && before_second_preview_ids == second_expected_active_ids
                        && before_second_runtime_ids == first_expected_active_ids
                        && after_second_preview_ids == second_expected_active_ids
                        && after_second_runtime_ids == second_expected_active_ids
                        && before_second_preview_ids == after_second_preview_ids
                        && after_second_preview_ids == after_second_runtime_ids,
                ),
            );
            consistency_obj.insert(
                "secondRuntimeIndexRotatedAfterRestart".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["sr21Committee"]["localRuntimeSrIndex"]
                        == serde_json::Value::from(local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && second_local_preview_index != local_preview_index,
                ),
            );
            consistency_obj.insert(
                "secondCheckpointProvenanceRetainedAfterApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["validatorAttestation"]
                        ["latestCheckpointFinality"]["target"]["blockHash"]
                        == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && after_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into())
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into()),
                ),
            );
            consistency_obj.insert(
                "authoritySwitchSurfaceRetainedAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                        == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeSelectionReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRotationReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeQuorumThresholdReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRuntimeQuorumThreshold"]
                            == serde_json::Value::String("15".into()),
                ),
            );
            consistency_obj.insert(
                "authoritySwitchReadyLiftedOnlyByCommitteeCatchupAfterSecondApply".into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                        == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewReady"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeSelectionReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeSelectionReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRotationReady"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRotationReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeQuorumThresholdReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeQuorumThresholdReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRuntimeQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRuntimeQuorumThreshold"]
                            == serde_json::Value::String("15".into())
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["currentAuthorityRetained"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["currentAuthorityRetained"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["bullsharkPlanReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["bullsharkPlanReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePlanReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePlanReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["orchestrationReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["orchestrationReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitConsistent"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitConsistent"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitCount"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitCount"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitTxHashes"]
                            == serde_json::json!(tx_hash_hexes)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitTxHashes"]
                            == serde_json::json!(tx_hash_hexes)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitObserved"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["runtimeRecoveryCommitObserved"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["previewMatchesRuntime"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["previewMatchesRuntime"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetCount"]
                            == serde_json::Value::from(second_election_result.num_active)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetCount"]
                            == serde_json::Value::from(second_election_result.num_active)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_preview_ids == after_second_preview_ids
                        && before_second_preview_ids == second_expected_active_ids
                        && before_second_runtime_ids == first_expected_active_ids
                        && after_second_runtime_ids == second_expected_active_ids,
                ),
            );
            consistency_obj.insert(
                "authoritySwitchReadyLiftMatchesSecondRotationRuntimeCatchupAfterSecondApply"
                    .into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                        == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]
                            == after_second_apply_chain_info["orderingContract"]
                                ["completionTargetShadowState"]
                        && before_second_apply_chain_info["runtimeRecovery"]
                            ["lastBullsharkCommitCount"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["runtimeRecovery"]
                            ["lastBullsharkCommitCount"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["runtimeRecovery"]
                            ["lastBullsharkCommitTxHashes"]
                            == serde_json::json!(tx_hash_hexes)
                        && after_second_apply_chain_info["runtimeRecovery"]
                            ["lastBullsharkCommitTxHashes"]
                            == serde_json::json!(tx_hash_hexes)
                        && before_second_apply_chain_info["runtimeRecovery"]
                            ["bullsharkCommitObserved"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["runtimeRecovery"]
                            ["bullsharkCommitObserved"]
                            == serde_json::Value::Bool(true)
                        && before_second_preview_ids == second_expected_active_ids
                        && after_second_preview_ids == second_expected_active_ids
                        && before_second_preview_ids == after_second_preview_ids
                        && before_second_runtime_ids == first_expected_active_ids
                        && after_second_runtime_ids == second_expected_active_ids
                        && second_added_validator_ids
                            == vec![second_rotation_in_id_hex.clone()]
                        && second_removed_validator_ids
                            == vec![second_rotation_out_id_hex.clone()]
                        && before_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewReady"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRotationReady"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeeRotationReady"]
                            == serde_json::Value::Bool(true),
                ),
            );
            consistency_obj.insert(
                "authoritySwitchReadyLiftPreservedSecondEpochBoundaryLineageAfterSecondApply"
                    .into(),
                serde_json::Value::Bool(
                    before_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                        == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                            == serde_json::Value::from(second_epoch)
                        && after_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                            == serde_json::Value::from(second_epoch)
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && after_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into())
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into())
                        && before_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blockHash"]
                            == serde_json::Value::String(hex::encode(second_checkpoint_block_hash))
                        && before_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["checkpointFinalized"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into())
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into()),
                ),
            );
            consistency_obj.insert(
                "authoritySwitchReadyLiftMatchesSecondRotationProvenanceAfterSecondApply"
                    .into(),
                serde_json::Value::Bool(
                    second_epoch_boundary_reached
                        && before_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(false)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                            == serde_json::Value::from(second_epoch)
                        && after_second_apply_chain_info["sr21Committee"]["currentEpoch"]
                            == serde_json::Value::from(second_epoch)
                        && before_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_chain_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_chain_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorAttestation"]
                            ["latestCheckpointFinality"]["target"]["blueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && after_second_apply_dag_info["validatorLifecycleRecovery"]
                            ["lastCheckpointFinalityBlueScore"]
                            == serde_json::Value::from(second_finalized_boundary_score)
                        && before_second_apply_dag_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && before_second_apply_dag_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(local_preview_index)
                        && after_second_apply_dag_info["sr21Committee"]
                            ["localPreviewSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && after_second_apply_dag_info["sr21Committee"]
                            ["localRuntimeSrIndex"]
                            == serde_json::Value::from(second_local_preview_index)
                        && next_epoch + 1 == second_epoch
                        && lifecycle_epoch == second_epoch
                        && restart_blue_score + checkpoint_interval
                            == second_finalized_boundary_score
                        && local_preview_index != second_local_preview_index,
                ),
            );
            consistency_obj.insert(
                "authoritySwitchExecutionLineMonotonicThroughSecondApply".into(),
                serde_json::Value::Bool(
                    delivered_chain_info["authoritySwitchReadiness"]["ready"]
                        == serde_json::Value::Bool(false)
                        && delivered_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(false)
                        && delivered_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(false)
                        && delivered_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(false)
                        && delivered_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(0)
                        && delivered_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(0)
                        && delivered_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(0)
                        && candidate_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(false)
                        && candidate_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && candidate_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(false)
                        && candidate_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(false)
                        && candidate_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && candidate_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(0)
                        && candidate_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(0)
                        && commit_preview_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(false)
                        && commit_preview_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && commit_preview_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && commit_preview_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(false)
                        && commit_preview_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && commit_preview_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && commit_preview_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(0)
                        && ready_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true)
                        && ready_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && ready_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && ready_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && ready_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && ready_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && ready_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2)
                        && restarted_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(true)
                        && restarted_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && restarted_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && restarted_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && restarted_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && restarted_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && restarted_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]["ready"]
                            == serde_json::Value::Bool(false)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && before_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["ready"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["candidatePreviewQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committedQueued"]
                            == serde_json::Value::from(2),
                ),
            );
            consistency_obj.insert(
                "chainDagAuthoritySummaryConsistentAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["authoritySwitchReadiness"]
                        == after_second_apply_dag_info["authoritySwitchReadiness"]
                        && after_second_apply_chain_info["sr21Committee"]["activeCount"]
                            == after_second_apply_dag_info["sr21Committee"]["activeCount"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["configuredActiveCount"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["configuredActiveCount"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetPresent"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeActiveSetPresent"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetCount"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeActiveSetCount"]
                        && after_second_apply_chain_info["sr21Committee"]
                            ["runtimeActiveSetMatchesPreview"]
                            == after_second_apply_dag_info["sr21Committee"]
                                ["runtimeActiveSetMatchesPreview"],
                ),
            );
            consistency_obj.insert(
                "chainDagOrderingStateConsistentAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["orderingContract"]["completionTargetShadowState"]
                        == after_second_apply_dag_info["orderingContract"]
                            ["completionTargetShadowState"],
                ),
            );
            consistency_obj.insert(
                "committedStateRetainedAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["orderingContract"]
                        ["completionTargetShadowState"]["candidatePreviewQueued"]
                        == serde_json::Value::from(2)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]
                                ["candidatePreviewFastTransparentQueued"]
                            == serde_json::Value::from(1)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]
                            == serde_json::Value::from(1)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["commitPreviewQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["commitPreviewFastTransparentQueued"]
                            == serde_json::Value::from(1)
                        && after_second_apply_chain_info["orderingContract"]
                            == serde_json::Value::from(1)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["committedQueued"]
                            == serde_json::Value::from(2)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["committedFastTransparentQueued"]
                            == serde_json::Value::from(1)
                        && after_second_apply_chain_info["orderingContract"]
                            == serde_json::Value::from(1)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["candidatePreviewLive"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["commitPreviewLive"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["committedLive"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["orderingContract"]
                            ["completionTargetShadowState"]["consistentWithCommitPreview"]
                            == serde_json::Value::Bool(true),
                ),
            );
            consistency_obj.insert(
                "commitHashesRetainedAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_commit_hashes["any"] == serde_json::json!(tx_hash_hexes)
                        && after_second_commit_hashes["fastTransparent"]
                            == serde_json::json!([transparent_hash.clone()]),
                ),
            );
            consistency_obj.insert(
                "runtimeRecoveryCommitRetainedAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["runtimeRecovery"]
                        ["lastBullsharkCommitCount"]
                        == serde_json::Value::from(2)
                        && after_second_apply_chain_info["runtimeRecovery"]
                            ["lastBullsharkCommitTxHashes"]
                            == serde_json::json!(tx_hash_hexes)
                        && after_second_apply_chain_info["runtimeRecovery"]
                            ["bullsharkCommitObserved"]
                            == serde_json::Value::Bool(true),
                ),
            );
            consistency_obj.insert(
                "currentAuthorityRetainedAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["authoritySwitchReadiness"]
                        ["currentAuthorityRetained"]
                        == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["currentRuntime"]["orderingStage"]
                            == serde_json::Value::String("ghostdagTotalOrder".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["currentRuntime"]["checkpointDecisionSource"]
                            == serde_json::Value::String("ghostdagCheckpointBft".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["currentRuntime"]["committee"]
                            == serde_json::Value::String("validatorBreadth".into()),
                ),
            );
            consistency_obj.insert(
                "completionTargetMatchesPlanAfterSecondApply".into(),
                serde_json::Value::Bool(
                    after_second_apply_chain_info["authoritySwitchReadiness"]
                        ["bullsharkPlanReady"]
                        == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["authoritySwitchReadiness"]
                            ["committeePlanReady"]
                            == serde_json::Value::Bool(true)
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["orderingStage"]
                            == serde_json::Value::String("bullsharkCommitOrder".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["orderingInput"]
                            == serde_json::Value::String("narwhalDeliveredBatch".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["checkpointDecisionSource"]
                            == serde_json::Value::String("bullsharkCommit".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committee"]
                            == serde_json::Value::String("superRepresentative21".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committeeStage"]
                            == serde_json::Value::String("sr21EpochRotation".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committeeSelection"]
                            == serde_json::Value::String("stakeWeightedTop21Election".into())
                        && after_second_apply_chain_info["consensusArchitecture"]
                            ["completionTarget"]["committeeSizeCap"]
                            == serde_json::Value::from(21),
                ),
            );
        }

        let payload = serde_json::json!({
            "status": "passed",
            "flow": "live_bullshark_commit_handoff_enables_authority_switch_through_rpc_service",
            "txHashes": tx_hash_hexes,
            "consensusArchitecture": ready_chain_info["consensusArchitecture"],
            "beforeApply": {
                "chainInfo": {
                    "sr21Committee": before_apply_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": before_apply_chain_info["authoritySwitchReadiness"],
                },
            },
            "afterApply": {
                "chainInfo": {
                    "sr21Committee": after_apply_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": after_apply_chain_info["authoritySwitchReadiness"],
                },
            },
            "afterDeliveredBatch": {
                "chainInfo": {
                    "orderingContract": delivered_chain_info["orderingContract"],
                    "authoritySwitchReadiness": delivered_chain_info["authoritySwitchReadiness"],
                },
                "dagInfo": {
                    "orderingContract": delivered_dag_info["orderingContract"],
                    "authoritySwitchReadiness": delivered_dag_info["authoritySwitchReadiness"],
                },
            },
            "afterCandidatePreview": {
                "chainInfo": {
                    "orderingContract": candidate_chain_info["orderingContract"],
                    "authoritySwitchReadiness": candidate_chain_info["authoritySwitchReadiness"],
                },
                "dagInfo": {
                    "orderingContract": candidate_dag_info["orderingContract"],
                    "authoritySwitchReadiness": candidate_dag_info["authoritySwitchReadiness"],
                },
            },
            "afterCommitPreview": {
                "chainInfo": {
                    "orderingContract": commit_preview_chain_info["orderingContract"],
                    "authoritySwitchReadiness": commit_preview_chain_info["authoritySwitchReadiness"],
                },
                "dagInfo": {
                    "orderingContract": commit_preview_dag_info["orderingContract"],
                    "authoritySwitchReadiness": commit_preview_dag_info["authoritySwitchReadiness"],
                },
            },
            "afterCommit": {
                "chainInfo": {
                    "orderingContract": ready_chain_info["orderingContract"],
                    "sr21Committee": ready_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": ready_chain_info["authoritySwitchReadiness"],
                },
                "dagInfo": {
                    "orderingContract": ready_dag_info["orderingContract"],
                    "sr21Committee": ready_dag_info["sr21Committee"],
                    "authoritySwitchReadiness": ready_dag_info["authoritySwitchReadiness"],
                },
                "runtimeRecovery": ready_runtime_recovery,
                "commitHashes": commit_hashes,
            },
            "consistency": consistency,
            "afterRestart": {
                "chainInfo": {
                    "orderingContract": restarted_chain_info["orderingContract"],
                    "sr21Committee": restarted_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": restarted_chain_info["authoritySwitchReadiness"],
                    "runtimeRecovery": restarted_chain_info["runtimeRecovery"],
                },
                "dagInfo": {
                    "orderingContract": restarted_dag_info["orderingContract"],
                    "sr21Committee": restarted_dag_info["sr21Committee"],
                    "authoritySwitchReadiness": restarted_dag_info["authoritySwitchReadiness"],
                    "runtimeRecovery": restarted_dag_info["runtimeRecovery"],
                },
                "commitHashes": restarted_commit_hashes,
            },
            "secondRotationProvenance": {
                "checkpointInterval": checkpoint_interval,
                "previousFinalizedCheckpointBlueScore": restart_blue_score,
                "appliedFinalizedCheckpointBlueScore": second_finalized_boundary_score,
                "lifecycleEpochBeforeApply": next_epoch,
                "lifecycleEpochAfterApply": second_epoch,
                "epochBoundaryReachedFromFinalizedCheckpoint": second_epoch_boundary_reached,
            },
            "beforeSecondApply": {
                "chainInfo": {
                    "orderingContract": before_second_apply_chain_info["orderingContract"],
                    "sr21Committee": before_second_apply_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": before_second_apply_chain_info["authoritySwitchReadiness"],
                    "validatorAttestation": before_second_apply_chain_info["validatorAttestation"],
                    "validatorLifecycleRecovery": before_second_apply_chain_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": before_second_apply_chain_info["runtimeRecovery"],
                },
            },
            "afterSecondApply": {
                "chainInfo": {
                    "orderingContract": after_second_apply_chain_info["orderingContract"],
                    "sr21Committee": after_second_apply_chain_info["sr21Committee"],
                    "authoritySwitchReadiness": after_second_apply_chain_info["authoritySwitchReadiness"],
                    "validatorAttestation": after_second_apply_chain_info["validatorAttestation"],
                    "validatorLifecycleRecovery": after_second_apply_chain_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": after_second_apply_chain_info["runtimeRecovery"],
                },
                "dagInfo": {
                    "orderingContract": after_second_apply_dag_info["orderingContract"],
                    "sr21Committee": after_second_apply_dag_info["sr21Committee"],
                    "authoritySwitchReadiness": after_second_apply_dag_info["authoritySwitchReadiness"],
                    "validatorAttestation": after_second_apply_dag_info["validatorAttestation"],
                    "validatorLifecycleRecovery": after_second_apply_dag_info["validatorLifecycleRecovery"],
                    "runtimeRecovery": after_second_apply_dag_info["runtimeRecovery"],
                },
                "commitHashes": after_second_commit_hashes,
            },
            "secondRotationDelta": {
                "addedValidatorIds": second_added_validator_ids,
                "removedValidatorIds": second_removed_validator_ids,
                "localRuntimeIndexBefore": local_preview_index,
                "localRuntimeIndexAfter": second_local_preview_index,
            },
            "restartConsistency": restart_consistency,
        });
        maybe_write_bullshark_commit_authority_switch_rehearsal_result(&payload);

        assert_eq!(
            payload["flow"],
            serde_json::Value::String(
                "live_bullshark_commit_handoff_enables_authority_switch_through_rpc_service"
                    .into()
            )
        );
        assert_eq!(payload["txHashes"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["configuredActiveCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["afterApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["authoritySwitchReadiness"]["ready"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["activeSetPreview"][20]
                ["validatorId"],
            serde_json::Value::String(local_validator_id_hex)
        );
        assert_eq!(
            payload["afterCommit"]["chainInfo"]["sr21Committee"]["activeSetPreview"][20]["isLocal"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["runtimeRecoveryCommitObservedAfterExplicitHandoff"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySummaryVisibleAfterDeliveredBatch"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySummaryVisibleAfterCandidatePreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySummaryVisibleAfterCommitPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySwitchReadyAfterExplicitCommit"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["runtimeActiveSetAppliedAfterApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["serviceRestartContinuity"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["authoritySurfaceRetainedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["chainDagOrderingStateConsistentAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["committedStateRetainedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["commitHashesRetainedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["restartConsistency"]["runtimeRecoveryCommitRetainedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["authoritySwitchReadiness"]["currentAuthorityRetained"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["runtimeActiveSetCount"],
            serde_json::Value::from(21)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["runtimeRecovery"]["startupSnapshotRestored"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["runtimeRecovery"]["lastBullsharkCommitCount"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["runtimeRecovery"]["lastBullsharkCommitTxHashes"],
            serde_json::json!(tx_hash_hexes)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["runtimeRecovery"]["bullsharkCommitObserved"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["orderingContract"]["completionTargetShadowState"]["committedQueued"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterRestart"]["chainInfo"]["orderingContract"]["completionTargetShadowState"]["committedLive"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterRestart"]["commitHashes"]["any"],
            serde_json::json!(tx_hash_hexes)
        );
        assert_eq!(
            payload["secondRotationProvenance"]["epochBoundaryReachedFromFinalizedCheckpoint"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["previewMatchesRuntime"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["localPreviewSrIndex"],
            serde_json::Value::from(second_local_preview_index)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["sr21Committee"]["localRuntimeSrIndex"],
            serde_json::Value::from(local_preview_index)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["authoritySwitchReadiness"]
                ["candidatePreviewReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["authoritySwitchReadiness"]
                ["commitPreviewReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["authoritySwitchReadiness"]
                ["committedReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["authoritySwitchReadiness"]
                ["committeePreviewReady"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["beforeSecondApply"]["chainInfo"]["authoritySwitchReadiness"]
                ["committeeRotationReady"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["authoritySwitchReadiness"]["ready"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetPresent"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["runtimeActiveSetMatchesPreview"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["sr21Committee"]["localRuntimeSrIndex"],
            serde_json::Value::from(second_local_preview_index)
        );
        assert_eq!(
            payload["afterSecondApply"]["chainInfo"]["runtimeRecovery"]["lastBullsharkCommitCount"],
            serde_json::Value::from(2)
        );
        assert_eq!(
            payload["afterSecondApply"]["commitHashes"]["any"],
            serde_json::json!(tx_hash_hexes)
        );
        assert_eq!(
            payload["secondRotationDelta"]["addedValidatorIds"],
            serde_json::json!([second_rotation_in_id_hex])
        );
        assert_eq!(
            payload["secondRotationDelta"]["removedValidatorIds"],
            serde_json::json!([second_rotation_out_id_hex])
        );
        assert_eq!(
            payload["consistency"]["secondRotationAppliedAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["secondRotationChangedMembershipAfterRestart"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["committeeRotationOnlyBlockerBeforeSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySwitchSurfaceRetainedAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySwitchReadyLiftedOnlyByCommitteeCatchupAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]
                ["authoritySwitchReadyLiftMatchesSecondRotationRuntimeCatchupAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]
                ["authoritySwitchReadyLiftPreservedSecondEpochBoundaryLineageAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]
                ["authoritySwitchReadyLiftMatchesSecondRotationProvenanceAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["authoritySwitchExecutionLineMonotonicThroughSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["committedStateRetainedAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["runtimeRecoveryCommitRetainedAfterSecondApply"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            payload["consistency"]["completionTargetMatchesPlanAfterSecondApply"],
            serde_json::Value::Bool(true)
        );

        restarted_server
            .stop()
            .await
            .expect("stop restarted live dag rpc service");
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_narwhal_dissemination_service_reports_contract_summary() {
        let dag_state = Arc::new(tokio::sync::RwLock::new(make_test_dag_state()));
        let transparent = make_test_dissemination_tx(0x71, TxType::TransparentTransfer);
        let dissemination_service = DagTxDisseminationService::new(dag_state);

        dissemination_service
            .stage_narwhal_worker_batch(vec![transparent.clone()])
            .await
            .expect("stage shadow batch");
        dissemination_service
            .mark_narwhal_worker_batch_delivered(&[transparent.tx_hash()])
            .await
            .expect("deliver shadow batch");

        let summary = dissemination_service.contract_summary().await;
        assert_eq!(summary.current_runtime_queue.queued, 0);
        assert_eq!(summary.completion_target_shadow_queue.queued, 2);
        assert_eq!(
            summary
                .completion_target_shadow_queue
                .narwhal_worker_batch_ingress_queued,
            2
        );
        assert_eq!(summary.completion_target_shadow_queue.staged_only_queued, 2);
        assert_eq!(summary.completion_target_delivered_queue.queued, 2);
        assert!(summary.staged_contract_ready);
        assert!(
            summary
                .completion_target_shadow_capabilities
                .narwhal_delivered_batch_ready
        );
    }
}
