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
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use misaka_mempool::UtxoMempool;
use misaka_pqc::{default_privacy_backend, PrivacyBackendFamily};
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::UtxoTransaction;
use misaka_types::validator::{DagCheckpointFinalityProof, DagCheckpointVote, ValidatorIdentity};

use crate::{expected_dag_quorum_threshold, ingest_checkpoint_vote};
use misaka_dag::{
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
    // TODO: Phase 3 で DAG P2P handle を追加
    // pub p2p: Arc<DagP2pNetwork>,
}

fn dag_admission_path(tx: &UtxoTransaction) -> PrivacyBackendFamily {
    #[cfg(feature = "stark-stub")]
    {
        if tx.zk_proof.is_some() {
            return PrivacyBackendFamily::ZeroKnowledge;
        }
    }
    PrivacyBackendFamily::RingSignature
}

fn verify_dag_pre_admission(
    tx: &UtxoTransaction,
    utxo_set: &UtxoSet,
    now_ms: u64,
) -> Result<PrivacyBackendFamily, String> {
    let admission_path = dag_admission_path(tx);
    let mut verifier_pool = UtxoMempool::new(1);

    let result = match admission_path {
        PrivacyBackendFamily::RingSignature => verifier_pool.admit(tx.clone(), utxo_set, now_ms),
        PrivacyBackendFamily::ZeroKnowledge => {
            #[cfg(feature = "stark-stub")]
            {
                verifier_pool.admit_zero_knowledge(tx.clone(), utxo_set, now_ms)
            }
            #[cfg(not(feature = "stark-stub"))]
            {
                Err(misaka_mempool::MempoolError::Structural(
                    "zero-knowledge admission unavailable without stark-stub feature".into(),
                ))
            }
        }
    };

    result
        .map(|_| admission_path)
        .map_err(|e| format!("dag pre-admission failed: {}", e))
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

fn tx_apply_status_label(status: misaka_dag::TxApplyStatus) -> &'static str {
    match status {
        misaka_dag::TxApplyStatus::Applied => "applied",
        misaka_dag::TxApplyStatus::FailedKeyImageConflict { .. } => "failedKeyImageConflict",
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
                PrivacyBackendFamily::RingSignature => "ringSignature",
            },
            "backendFamily": match admission_path {
                PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
                PrivacyBackendFamily::RingSignature => "ringSignature",
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
            PrivacyBackendFamily::RingSignature => "ringSignature",
        },
        "backendFamily": match backend_family {
            PrivacyBackendFamily::ZeroKnowledge => "zeroKnowledge",
            PrivacyBackendFamily::RingSignature => "ringSignature",
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
pub async fn run_dag_rpc_server(state: DagSharedState, addr: SocketAddr) -> anyhow::Result<()> {
    let rpc_state = DagRpcState { node: state };

    let app = Router::new()
        .route("/api/get_chain_info", post(dag_get_chain_info))
        .route("/api/submit_tx", post(dag_submit_tx))
        .route("/api/get_tx_by_hash", post(dag_get_tx_by_hash))
        .route(
            "/api/submit_checkpoint_vote",
            post(dag_submit_checkpoint_vote),
        )
        .route("/api/get_dag_info", post(dag_get_dag_info))
        .route("/api/get_dag_tips", post(dag_get_tips))
        .route("/api/get_dag_block", post(dag_get_block))
        // v8: Kaspa-style Virtual Chain API
        .route("/api/get_virtual_chain", post(dag_get_virtual_chain))
        .route("/api/get_virtual_state", post(dag_get_virtual_state))
        .route("/health", get(dag_health))
        .with_state(rpc_state);

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
            // No env var set: restrictive localhost-only default (same as v1)
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:3000".parse().expect("static origin"),
                    "http://localhost:3001".parse().expect("static origin"),
                    "http://127.0.0.1:3000".parse().expect("static origin"),
                    "http://127.0.0.1:3001".parse().expect("static origin"),
                ])
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
    };

    let app = app.layer(cors);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("DAG RPC server listening on {}", addr);
    axum::serve(listener, app).await?;
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
        "privacyBackend": serde_json::to_value(privacy_backend).unwrap_or(serde_json::json!({
            "schemeName": "LogRing-v1",
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
                    PrivacyBackendFamily::RingSignature => "ringSignature",
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
                    PrivacyBackendFamily::RingSignature => "ringSignature",
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
                    PrivacyBackendFamily::RingSignature => "ringSignature",
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
    let (current_checkpoint_votes, vote_pool) = checkpoint_vote_pool_json(s);

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
        sp_chain.iter().map(|block_hash| {
            let txs = s.dag_store.get_block_txs(block_hash);
            let tx_results: Vec<serde_json::Value> = txs.iter().map(|tx| {
                let tx_hash = tx.tx_hash();
                let status = s.dag_store.get_tx_status(&tx_hash);
                let (accepted, reason) = match status {
                    Some(misaka_dag::TxApplyStatus::Applied) => (true, "".to_string()),
                    Some(misaka_dag::TxApplyStatus::FailedKeyImageConflict { conflicting_key_image, .. }) =>
                        (false, format!("key_image_conflict:{}", hex::encode(&conflicting_key_image[..8]))),
                    Some(misaka_dag::TxApplyStatus::FailedNullifierConflict { conflicting_nullifier, .. }) =>
                        (false, format!("nullifier_conflict:{}", hex::encode(&conflicting_nullifier[..8]))),
                    Some(misaka_dag::TxApplyStatus::FailedInvalidSignature) =>
                        (false, "invalid_signature".to_string()),
                    Some(misaka_dag::TxApplyStatus::FailedRingMemberNotFound) =>
                        (false, "ring_member_not_found".to_string()),
                    None => (true, "".to_string()), // No status recorded → assume accepted
                };
                serde_json::json!({
                    "txHash": hex::encode(tx_hash),
                    "accepted": accepted,
                    "rejectionReason": reason,
                })
            }).collect();

            serde_json::json!({
                "blockHash": hex::encode(block_hash),
                "blueScore": snapshot.get_ghostdag_data(block_hash)
                    .map(|d| d.blue_score).unwrap_or(0),
                "txResults": tx_results,
            })
        }).collect()
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
            "blocksReverted": vs.stats.blocks_reverted,
            "reorgs": vs.stats.reorgs,
            "deepestReorg": vs.stats.deepest_reorg,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_dag::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
    use misaka_dag::dag_store::ThreadSafeDagStore;
    use misaka_dag::{DagCheckpoint, DagMempool, DagStateManager, GhostDagEngine, TxApplyStatus};
    use misaka_dag::reachability::ReachabilityStore;
    use misaka_pqc::pq_ring::{Poly, SpendingKeypair};
    use misaka_pqc::pq_sign::MlDsaKeypair;
    #[cfg(feature = "stark-stub")]
    use misaka_pqc::{materialize_zkmp_stub_tx, ZkmpInputWitness};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use misaka_types::utxo::{
        OutputRef, RingInput, TxOutput, TxType, UtxoTransaction, RING_SCHEME_LOGRING,
        UTXO_TX_VERSION_V3,
    };

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
        let ring_members: Vec<OutputRef> = wallets
            .iter()
            .enumerate()
            .map(|(i, _)| OutputRef {
                tx_hash: [(i + 1) as u8; 32],
                output_index: 0,
            })
            .collect();

        UtxoTransaction {
            version: UTXO_TX_VERSION_V3,
            ring_scheme: RING_SCHEME_LOGRING,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members,
                ring_signature: vec![0xAA; 32],
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
            ingestion_pipeline: misaka_dag::IngestionPipeline::new([genesis_hash].into_iter().collect()),
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count: 2,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
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

    #[cfg(feature = "stark-stub")]
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

    #[cfg(feature = "stark-stub")]
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
            serde_json::Value::String("ringSignature".into())
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
        assert_eq!(conflict_json["failedConflict"], serde_json::Value::Bool(true));
        assert_eq!(
            conflict_json["conflict"]["priorTxHash"],
            serde_json::Value::String(hex::encode(tx_applied.tx_hash()))
        );
    }
}
