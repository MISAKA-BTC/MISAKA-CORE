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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::rpc_auth::{require_api_key, ApiKeyState};

use misaka_mempool::UtxoMempool;
use misaka_pqc::{default_privacy_backend, PrivacyBackendFamily};
// Consumer surface status and privacy path status are inlined below.
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::UtxoTransaction;
use misaka_types::validator::{DagCheckpointFinalityProof, DagCheckpointVote, ValidatorIdentity};

use crate::dag_p2p_surface::DagP2pObservationState;
use crate::{expected_dag_quorum_threshold, ingest_checkpoint_vote};
use misaka_dag::{
    save_runtime_snapshot,
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
    pub dag_p2p_observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    pub runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    /// Shielded module state. None when shielded module is disabled.
    pub shielded: Option<misaka_shielded::SharedShieldedState>,
    // Stop line:
    // DAG P2P handle is intentionally not exposed here yet. Adding it changes
    // the live relay surface and should be aligned with the DAG/ZK track.
    // pub p2p: Arc<DagP2pNetwork>,
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
    }

    pub fn mark_checkpoint_finality(&mut self, blue_score: Option<u64>) {
        self.last_checkpoint_finality_blue_score = blue_score;
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
        "summary": summary,
    })
}

/// Interim peer-gossip ingress for checkpoint votes.
///
/// This stays separate from the API-key protected control plane because peers
/// still submit signed votes without HTTP auth headers. The payload is still
/// validated by `ingest_checkpoint_vote()` before it touches state.
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
    #[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
    {
        if tx.zk_proof.is_some() {
            return PrivacyBackendFamily::ZeroKnowledge;
        }
    }
    PrivacyBackendFamily::ZeroKnowledge
}

fn verify_dag_pre_admission(
    tx: &UtxoTransaction,
    utxo_set: &UtxoSet,
    now_ms: u64,
) -> Result<PrivacyBackendFamily, String> {
    let admission_path = dag_admission_path(tx);
    let mut verifier_pool = UtxoMempool::new(1);

    let result = match admission_path {
        PrivacyBackendFamily::ZeroKnowledge => verifier_pool.admit(tx.clone(), utxo_set, now_ms),
        PrivacyBackendFamily::Transparent => verifier_pool.admit(tx.clone(), utxo_set, now_ms),
    };

    result
        .map_err(|e| format!("dag pre-admission failed: {}", e))?;

    // ── A-1: ML-DSA-65 Signature Verification ──
    // For transparent transfers, verify each input's proof (ML-DSA-65 sig)
    // against the spending_pubkey stored in the UTXO set.
    // Coinbase/Faucet/Shielded TXs skip this (no UTXO inputs).
    if !tx.inputs.is_empty() && tx.proof_scheme == misaka_types::utxo::PROOF_SCHEME_TRANSPARENT {
        let signing_digest = tx.signing_digest();
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
                    misaka_pqc::pq_sign::ml_dsa_verify(&pk, &signing_digest, &sig)
                        .map_err(|e| format!(
                            "input[{}]: ML-DSA-65 signature verification failed: {}",
                            i, e
                        ))?;
                } else {
                    tracing::warn!(
                        "input[{}]: spending_pubkey not found in UTXO set for {:?} — skipping sig verify",
                        i, source_ref
                    );
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
        "totalKeyImages": checkpoint.total_key_images,
        "totalAppliedTxs": checkpoint.total_applied_txs,
        "timestampMs": checkpoint.timestamp_ms,
        "validatorTarget": {
            "blockHash": hex::encode(target.block_hash),
            "blueScore": target.blue_score,
            "utxoRoot": hex::encode(target.utxo_root),
            "totalKeyImages": target.total_key_images,
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

fn checkpoint_vote_json(vote: &DagCheckpointVote) -> serde_json::Value {
    serde_json::json!({
        "voter": hex::encode(vote.voter),
        "signatureBytes": vote.signature.bytes.len(),
        "target": {
            "blockHash": hex::encode(vote.target.block_hash),
            "blueScore": vote.target.blue_score,
            "utxoRoot": hex::encode(vote.target.utxo_root),
            "totalKeyImages": vote.target.total_key_images,
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
            "totalKeyImages": proof.target.total_key_images,
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
        "totalKeyImages": target.total_key_images,
        "totalAppliedTxs": target.total_applied_txs,
    })
}

fn checkpoint_vote_pool_json(
    state: &DagNodeState,
) -> (Option<serde_json::Value>, Vec<serde_json::Value>) {
    let quorum_threshold = expected_dag_quorum_threshold(state.validator_count);
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
    let quorum_threshold = expected_dag_quorum_threshold(state.validator_count);
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
    let bridge_readiness = current["bridgeReadiness"]
        .as_str()
        .unwrap_or("checkpointDependent");
    let explorer_confirmation_level = current["explorerConfirmationLevel"]
        .as_str()
        .unwrap_or("checkpointAware");

    serde_json::json!({
        "validatorAttestation": {
            "available": true,
            "bridgeReadiness": bridge_readiness,
            "explorerConfirmationLevel": explorer_confirmation_level
        },
        "txStatusVocabulary": [
            "pending",
            "ordered",
            "finalized",
            "failedNullifierConflict",
            "failedKeyImageConflict",
            "failedInvalidSignature",
            "failedRingMemberNotFound"
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

fn tx_apply_status_label(status: misaka_dag::TxApplyStatus) -> &'static str {
    match status {
        misaka_dag::TxApplyStatus::Applied => "applied",
        misaka_dag::TxApplyStatus::FailedKeyImageConflict { .. } => "failedKeyImageConflict",
        misaka_dag::TxApplyStatus::FailedNullifierConflict { .. } => "failedNullifierConflict",
        misaka_dag::TxApplyStatus::FailedInvalidSignature => "failedInvalidSignature",
        misaka_dag::TxApplyStatus::FailedRingMemberNotFound => "failedRingMemberNotFound",
    }
}

fn checkpoint_finality_blue_score(state: &DagNodeState) -> Option<u64> {
    let target = state
        .latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.validator_target())?;
    let proof = state.latest_checkpoint_finality.as_ref()?;
    if proof.target == target {
        Some(proof.target.blue_score)
    } else {
        None
    }
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
        Some(misaka_dag::TxApplyStatus::FailedKeyImageConflict {
            conflicting_key_image,
            prior_tx_hash,
        }) => (
            "failed_conflict",
            true,
            false,
            true,
            serde_json::json!({
                "conflictingKeyImage": hex::encode(conflicting_key_image),
                "priorTxHash": hex::encode(prior_tx_hash),
            }),
        ),
        Some(other) => (
            tx_apply_status_label(other),
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
pub async fn run_dag_rpc_server(state: DagSharedState, addr: SocketAddr, chain_id: u32) -> anyhow::Result<()> {
    run_dag_rpc_server_with_observation(
        state,
        None,
        None,
        None,
        Arc::new(RwLock::new(0)),
        None,
        None, // shielded_state: disabled in simple mode
        addr,
        chain_id,
    )
    .await
}

pub async fn run_dag_rpc_server_with_observation(
    state: DagSharedState,
    dag_p2p_observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    validator_registry: Option<Arc<RwLock<misaka_consensus::staking::StakingRegistry>>>,
    current_epoch: Arc<RwLock<u64>>,
    epoch_progress: Option<
        Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>,
    >,
    // Shielded module shared state. Pass `None` to disable shielded routes
    // (transparent-only mode). Build with `ShieldedConfig::disabled()` for CEX nodes.
    shielded_state: Option<misaka_shielded::SharedShieldedState>,
    addr: SocketAddr,
    chain_id: u32,
) -> anyhow::Result<()> {
    let rpc_state = DagRpcState {
        node: state,
        dag_p2p_observation,
        runtime_recovery,
        shielded: shielded_state,
    };

    // ── API Key configuration ──
    // SEC-FIX: Use from_env_checked so mainnet (chain_id=1) REQUIRES an API key.
    let auth_state = ApiKeyState::from_env_checked(chain_id)?;
    if auth_state.is_enabled() {
        info!("DAG RPC: API key authentication ENABLED for write endpoints");
        warn!("DAG RPC: checkpoint vote gossip ingress remains PUBLIC as an interim signed path");
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
        .route("/api/get_virtual_state", post(dag_get_virtual_state))
        .route("/api/get_utxos_by_address", post(dag_get_utxos_by_address))
        .route("/api/get_decoy_utxos", post(dag_get_decoy_utxos))
        .route("/api/get_anonymity_set", post(dag_get_anonymity_set))
        .route("/api/get_mempool_info", get(dag_get_mempool_info))
        .route("/api/fee_estimate", get(dag_fee_estimate))
        .route("/api/shielded/tx_summary", post(dag_get_shielded_tx_summary))
        .route("/health", get(dag_health))
        .route("/api/openapi.yaml", get(dag_openapi_spec))
        .route("/docs", get(dag_swagger_ui));

    // ── Write endpoints (auth required when MISAKA_RPC_API_KEY is set) ──
    // `submit_tx` is the user-facing write path. Checkpoint votes use a
    // separate interim gossip ingress because peers do not yet attach HTTP
    // auth headers.
    let write_routes = Router::new()
        .route("/api/submit_tx", post(dag_submit_tx))
        .route("/api/faucet", post(dag_faucet))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            require_api_key,
        ));

    // ── Shielded module routes (opt-in, feature-flagged at config level) ──
    let shielded_state_for_rpc = rpc_state.shielded.clone();
    let dag_state_for_shielded = rpc_state.node.clone(); // P1: clone before move
    let mut app = public_routes
        .merge(dag_checkpoint_vote_gossip_router())
        .merge(write_routes)
        .with_state(rpc_state);

    if let Some(shielded) = shielded_state_for_rpc {
        use crate::shielded_rpc::{shielded_public_router, shielded_write_router, ShieldedRpcState};
        let sh_state = ShieldedRpcState::with_dag(shielded, dag_state_for_shielded);
        let sh_write = shielded_write_router(sh_state.clone())
            .route_layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                require_api_key,
            ));
        app = app
            .merge(shielded_public_router(sh_state))
            .merge(sh_write);
        info!("DAG RPC: Shielded module routes enabled at /api/shielded/* (P1: mempool integration active)");
    } else {
        info!("DAG RPC: Shielded module DISABLED (transparent-only mode)");
    }

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
    let cors = match std::env::var("MISAKA_CORS_ORIGINS") {
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
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
        Err(_) => {
            // No env var set: allow localhost + approved Chrome extensions (dev default)
            use tower_http::cors::AllowOrigin;

            #[allow(clippy::unwrap_used)] // static string parse never fails
            let localhost_origins: Vec<axum::http::HeaderValue> = vec![
                "http://localhost:3000".parse().expect("static origin"),
                "http://localhost:3001".parse().expect("static origin"),
                "http://localhost:5173".parse().expect("static origin"),
                "http://127.0.0.1:3000".parse().expect("static origin"),
                "http://127.0.0.1:3001".parse().expect("static origin"),
            ];

            // SEC-P0-5: Chrome extension CORS policy.
            //
            // The previous code allowed ALL chrome-extension:// origins.
            // A malicious Chrome extension installed on the user's machine
            // could access the node's RPC endpoints (read chain state,
            // submit TXs on behalf of the user, etc.).
            //
            // Fix: Only allow explicitly approved extension IDs.
            // Set MISAKA_CORS_EXTENSIONS="ext-id-1,ext-id-2" to allow.
            // When unset, NO extensions are allowed (fail-closed for production).
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

            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(move |origin, _| {
                    let origin_str = origin.to_str().unwrap_or("");
                    // SEC-P0-5: Only allow explicitly listed extension IDs
                    if origin_str.starts_with("chrome-extension://") {
                        return allowed_extensions
                            .iter()
                            .any(|ext| origin_str == ext.as_str());
                    }
                    // Allow configured localhost origins
                    localhost_origins.iter().any(|o| o == origin)
                }))
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
    };

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
    let privacy_backend = default_privacy_backend();
    let (current_checkpoint_votes, vote_pool) = checkpoint_vote_pool_json(s);
    let dag_p2p_observation = dag_p2p_observation_json(rpc.dag_p2p_observation.as_ref()).await;
    let runtime_recovery = dag_runtime_recovery_json(rpc.runtime_recovery.as_ref()).await;
    let validator_lifecycle_recovery =
        validator_lifecycle_recovery_json(rpc.runtime_recovery.as_ref()).await;

    let max_score = s.dag_store.max_blue_score();
    let block_count = s.dag_store.block_count();
    let tip_count = s.dag_store.tip_count();

    Json(serde_json::json!({
        "networkName": "MISAKA DAG Testnet",
        "networkVersion": "v2.0.0-alpha",
        "consensus": "GhostDAG",
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
        "latestCheckpoint": s.latest_checkpoint.as_ref().map(latest_checkpoint_json),
        "dagP2pObservation": dag_p2p_observation,
        "runtimeRecovery": runtime_recovery,
        "validatorLifecycleRecovery": validator_lifecycle_recovery,
        "privacyPathSurface": dag_privacy_path_surface_json("zeroKnowledge"),
        "consumerSurfaces": dag_consumer_surfaces_json(s),
        "privacyBackend": serde_json::to_value(privacy_backend).unwrap_or(serde_json::json!({
            "schemeName": "UnifiedZKP-v1",
            "statusNote": "privacy backend descriptor serialization failed"
        })),
    }))
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: Submit TX (DAG Mempool 経由)
// ═══════════════════════════════════════════════════════════════

/// `/api/submit_tx` — TX を DAG Mempool に投入する。
///
/// v1 との違い:
/// - `mempool.admit()` → `dag_mempool.insert()` に変更
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

    // ── 4. DAG Mempool に投入 ──
    let mut guard = rpc.node.write().await;
    let s = &mut *guard;

    let admission_path = match verify_dag_pre_admission(&tx, &s.utxo_set, now_ms) {
        Ok(path) => path,
        Err(e) => {
            warn!(
                "TX rejected before DAG ingest: {} | reason: {}",
                &hash_hex[..16],
                e
            );
            return Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": false,
                "admissionPath": match dag_admission_path(&tx) {
                    PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                PrivacyBackendFamily::Transparent => "transparent",
                },
                "error": e
            }));
        }
    };

    // KI 既使用チェックは DagStateManager 経由
    // Disjoint field borrow: mempool (mut) + state_manager (immut)
    let state_mgr = &s.state_manager;
    let result = s.mempool.insert(tx, |ki| state_mgr.is_key_image_spent(ki));

    match result {
        Ok(()) => {
            info!(
                "TX admitted to DAG mempool: {} | pool={} | admission_path={:?}",
                &hash_hex[..16],
                s.mempool.len(),
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
                "TX rejected from DAG mempool: {} | reason: {}",
                &hash_hex[..16],
                e
            );
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": false,
                "admissionPath": match admission_path {
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

/// Interim checkpoint vote ingress for validator gossip.
///
/// This endpoint is intentionally separate from the API-key protected write
/// path. Votes are still rejected unless the payload verifies against the
/// current validator set.
async fn dag_submit_checkpoint_vote(
    State(rpc): State<DagRpcState>,
    Json(req): Json<DagCheckpointVoteRequest>,
) -> Json<serde_json::Value> {
    let mut guard = rpc.node.write().await;
    let state = &mut *guard;

    match ingest_checkpoint_vote(state, req.vote.clone(), req.validator_identity) {
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
                "quorumThreshold": expected_dag_quorum_threshold(state.validator_count).to_string(),
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
        // ── Shielded tx lookup ──
        // If not found in transparent DAG store, check shielded nullifier set.
        // Shielded txs show only type/fee/status (no amount/sender/recipient).
        if let Some(ref shielded) = rpc.shielded {
            let s = shielded.read();
            let nf = misaka_shielded::Nullifier(tx_hash);
            if let Some(record) = s.nullifier_set.get_record(&nf) {
                return Ok(Json(serde_json::json!({
                    "txHash": q.hash,
                    "txType": "ShieldedSpend",
                    "blockHeight": record.block_height,
                    "status": "confirmed",
                    "shielded": true,
                    "note": "Shielded transaction: amount, sender, and recipient are not disclosed."
                })));
            }
        }
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(serde_json::json!({
        "txHash": q.hash,
        "txStatus": status,
    })))
}

/// `/api/shielded/tx_summary` — shielded tx のメタデータのみ返す（秘匿情報なし）。
/// explorer 表示用: type / fee / nullifier_count / commitment_count / anchor のみ。
async fn dag_get_shielded_tx_summary(
    State(rpc): State<DagRpcState>,
    Json(q): Json<DagTxQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let shielded = rpc.shielded.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let tx_hash_bytes: [u8; 32] = hex::decode(&q.hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let s = shielded.read();
    let nf = misaka_shielded::Nullifier(tx_hash_bytes);
    match s.nullifier_set.get_record(&nf) {
        Some(record) => Ok(Json(serde_json::json!({
            "txHash": q.hash,
            "txType": "ShieldedSpend",
            "blockHeight": record.block_height,
            "status": "confirmed",
            "shielded": true,
            "privacyNote": "Amount, sender, and recipient are not publicly disclosed."
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: DAG 固有情報
// ═══════════════════════════════════════════════════════════════

/// `/api/get_dag_info` — DAG 固有のメトリクス。
async fn dag_get_dag_info(State(rpc): State<DagRpcState>) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;
    let (current_checkpoint_votes, vote_pool) = checkpoint_vote_pool_json(s);
    let runtime_recovery = dag_runtime_recovery_json(rpc.runtime_recovery.as_ref()).await;
    let validator_lifecycle_recovery =
        validator_lifecycle_recovery_json(rpc.runtime_recovery.as_ref()).await;

    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    Json(serde_json::json!({
        "ghostdagK": s.ghostdag.k,
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
        "latestCheckpoint": s.latest_checkpoint.as_ref().map(latest_checkpoint_json),
        "runtimeRecovery": runtime_recovery,
        "validatorLifecycleRecovery": validator_lifecycle_recovery,
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
        .body(axum::body::Body::from(include_str!("../../../docs/api/openapi.yaml")))
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
                        let (accepted, reason) = match status {
                            Some(misaka_dag::TxApplyStatus::Applied) => (true, "".to_string()),
                            Some(misaka_dag::TxApplyStatus::FailedKeyImageConflict {
                                conflicting_key_image,
                                ..
                            }) => (
                                false,
                                format!(
                                    "key_image_conflict:{}",
                                    hex::encode(&conflicting_key_image[..8])
                                ),
                            ),
                            Some(misaka_dag::TxApplyStatus::FailedNullifierConflict {
                                conflicting_nullifier,
                                ..
                            }) => (
                                false,
                                format!(
                                    "nullifier_conflict:{}",
                                    hex::encode(&conflicting_nullifier[..8])
                                ),
                            ),
                            Some(misaka_dag::TxApplyStatus::FailedInvalidSignature) => {
                                (false, "invalid_signature".to_string())
                            }
                            Some(misaka_dag::TxApplyStatus::FailedRingMemberNotFound) => {
                                (false, "ring_member_not_found".to_string())
                            }
                            None => (true, "".to_string()), // No status recorded → assume accepted
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
        "nullifierCount": snapshot.nullifier_count,
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

#[derive(Deserialize)]
struct GetUtxosByAddressReq {
    address: String,
}

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

    for (outref, pk_bytes) in s.utxo_set.all_spending_keys() {
        let derived = derive_address_from_spending_key(pk_bytes, s.chain_id);
        if derived != address {
            continue;
        }

        if let Some(entry) = s.utxo_set.get(outref) {
            balance = balance.saturating_add(entry.output.amount);
            utxos.push(serde_json::json!({
                "txHash": hex::encode(outref.tx_hash),
                "outputIndex": outref.output_index,
                "amount": entry.output.amount,
                "oneTimeAddress": hex::encode(entry.output.one_time_address),
                "spendingPubkey": hex::encode(pk_bytes),
                "createdAt": entry.created_at,
            }));
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
/// Return same-amount UTXOs with their spending_pubkey for lattice ZKP proof construction.
/// Compatible with the CLI `transfer.rs` decoy fetching format.
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
                format!("{}:{}", hex::encode(&outref.tx_hash[..8]), outref.output_index),
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
async fn dag_get_mempool_info(
    State(rpc): State<DagRpcState>,
) -> Json<serde_json::Value> {
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
async fn dag_fee_estimate(
    State(rpc): State<DagRpcState>,
) -> Json<serde_json::Value> {
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
        .ok().and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000_000); // default 1 MISAKA; set MISAKA_FAUCET_AMOUNT for more

    let spending_pubkey = if !spending_pubkey_hex.is_empty() {
        hex::decode(&spending_pubkey_hex).ok()
    } else {
        None
    };

    let faucet_tx = misaka_types::utxo::UtxoTransaction {
        version: misaka_types::utxo::UTXO_TX_VERSION,
        proof_scheme: misaka_types::utxo::PROOF_SCHEME_TRANSPARENT,
        tx_type: misaka_types::utxo::TxType::Faucet,
        inputs: vec![],
        outputs: vec![misaka_types::utxo::TxOutput {
            amount: faucet_amount,
            one_time_address: ota_bytes,
            pq_stealth: None,
            spending_pubkey,
        }],
        fee: 0,
        extra: vec![],
        zk_proof: None,
    };

    let tx_hash = faucet_tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);

    // Submit to mempool — the TX will be included in the next block
    // through normal block production. This is the ONLY correct path.
    // Faucet TXs have no inputs, so ki_spent check always returns false.
    let mempool_result = s.mempool.insert(faucet_tx.clone(), |_ki| false);
    if mempool_result.is_err() {
        warn!("Faucet TX {} rejected by mempool: {:?}", hash_hex, mempool_result);
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
    use crate::dag_p2p_surface::{DagP2pDirection, DagP2pObservationState, DagP2pSurface};
    use misaka_dag::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
    use misaka_dag::dag_store::ThreadSafeDagStore;
    use misaka_dag::reachability::ReachabilityStore;
    use misaka_dag::{DagCheckpoint, DagMempool, DagStateManager, GhostDagEngine, TxApplyStatus};
    use misaka_pqc::pq_ring::{Poly, SpendingKeypair};
    use misaka_pqc::pq_sign::MlDsaKeypair;
    #[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
    use misaka_pqc::{materialize_zkmp_stub_tx, ZkmpInputWitness};
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, PROOF_SCHEME_DEPRECATED_LOGRING,
        UTXO_TX_VERSION_V3,
    };
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;

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
                one_time_address: [0x80 + i as u8; 32],
                pq_stealth: None,
                spending_pubkey: Some(wallet.public_poly.to_bytes()),
            };
            utxo_set.add_output(outref.clone(), output, 0).unwrap();
            utxo_set.register_spending_key(outref, wallet.public_poly.to_bytes());
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
            version: UTXO_TX_VERSION_V3,
            proof_scheme: PROOF_SCHEME_DEPRECATED_LOGRING,
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                utxo_refs,
                proof: vec![0xAA; 32],
                key_image: [0x11; 32],
                ki_proof: vec![0xBB; 32],
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                one_time_address: [0x42; 32],
                pq_stealth: None,
                spending_pubkey: Some(wallets[0].public_poly.to_bytes()),
            }],
            fee: 100,
            extra: vec![],
            zk_proof: None,
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
            shielded_hook: None,
        }
    }

    #[test]
    fn test_latest_checkpoint_json_includes_validator_target() {
        let cp = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 12,
            utxo_root: [0xBB; 32],
            total_key_images: 5,
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
            voter: [0x11; 20],
            target: misaka_types::validator::DagCheckpointTarget {
                block_hash: [0x22; 32],
                blue_score: 77,
                utxo_root: [0x33; 32],
                total_key_images: 9,
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
            validator_id: [0x55; 20],
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

    #[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
    #[test]
    fn test_verify_dag_pre_admission_accepts_materialized_zkmp_tx() {
        let (utxo_set, wallets) = setup_utxo_with_uniform_ring();
        let mut tx = make_ring_tx(&wallets);
        let ring_pubkeys = vec![wallets
            .iter()
            .map(|w| w.public_poly.clone())
            .collect::<Vec<Poly>>()];
        let witness = ZkmpInputWitness {
            secret_poly: wallets[0].secret_poly.clone(),
            spent_one_time_address: [0x44; 32],
        };

        let (_constraints, statement, build) =
            materialize_zkmp_stub_tx(&mut tx, &[10_000], &ring_pubkeys, &[witness]).unwrap();
        assert_eq!(
            statement.backend_family,
            PrivacyBackendFamily::ZeroKnowledge
        );
        assert_eq!(tx.inputs[0].key_image, build.target_nullifiers[0]);

        let admission = verify_dag_pre_admission(&tx, &utxo_set, 1_700_000_000_000).unwrap();
        assert_eq!(admission, PrivacyBackendFamily::ZeroKnowledge);
    }

    #[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
    #[test]
    fn test_verify_dag_pre_admission_rejects_unmaterialized_zk_tx() {
        let (utxo_set, wallets) = setup_utxo_with_uniform_ring();
        let mut tx = make_ring_tx(&wallets);
        tx.zk_proof = Some(misaka_types::utxo::ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x99; 32],
        });

        let err = verify_dag_pre_admission(&tx, &utxo_set, 1_700_000_000_000).unwrap_err();
        assert!(err.contains("dag pre-admission failed"));
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
        let mut tx_conflict = make_ring_tx(&wallets);
        tx_conflict.inputs[0].key_image = [0x77; 32];

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
        state.dag_store.set_tx_status(
            tx_conflict.tx_hash(),
            TxApplyStatus::FailedKeyImageConflict {
                conflicting_key_image: [0x77; 32],
                prior_tx_hash: tx_applied.tx_hash(),
            },
        );

        let checkpoint = DagCheckpoint {
            block_hash,
            blue_score: 10,
            utxo_root: [0x88; 32],
            total_key_images: 1,
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
                "failedNullifierConflict",
                "failedKeyImageConflict",
                "failedInvalidSignature",
                "failedRingMemberNotFound"
            ])
        );

        let checkpoint = DagCheckpoint {
            block_hash: [0xAA; 32],
            blue_score: 7,
            utxo_root: [0xBB; 32],
            total_key_images: 1,
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
    async fn test_dag_p2p_observation_json_exposes_recent_surface() {
        let mut observation = DagP2pObservationState::default();
        observation.record(
            DagP2pDirection::Inbound,
            &misaka_dag::dag_p2p::DagP2pMessage::GetDagTips,
            Some(&[0xAA; 20]),
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
            dag_p2p_observation: None,
            runtime_recovery: Some(observation),
            shielded: None,
        };

        let chain_info = dag_get_chain_info(State(rpc.clone())).await.0;
        let dag_info = dag_get_dag_info(State(rpc)).await.0;

        assert_eq!(
            chain_info["validatorLifecycleRecovery"]["available"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["validatorLifecycleRecovery"]["summary"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(
            dag_info["validatorLifecycleRecovery"]["restartReady"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            dag_info["validatorLifecycleRecovery"]["checkpointFinalized"],
            serde_json::Value::Bool(true)
        );
    }
}
