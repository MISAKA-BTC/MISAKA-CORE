//! Shielded RPC Handlers
//!
//! `/api/shielded/*` 系エンドポイントの実装。
//!
//! # Route 設計
//!
//! ## Public (認証不要)
//! - GET  `/api/shielded/module_status`       — module の有効/無効と統計
//! - POST `/api/shielded/nullifier_status`    — nullifier の消費状態確認
//! - GET  `/api/shielded/root`                — 現在の Merkle root
//! - POST `/api/shielded/encrypted_notes`     — 暗号化 note のページネーション取得
//! - POST `/api/shielded/spent_nullifiers`    — 消費済み nullifier のページネーション
//! - POST `/api/shielded/verify_payment_proof`— payment proof 検証
//!
//! ## Write (MISAKA_RPC_API_KEY 認証)
//! - POST `/api/shielded/submit_deposit`      — ShieldDepositTx 投入
//! - POST `/api/shielded/submit_transfer`     — ShieldedTransferTx 投入
//! - POST `/api/shielded/submit_withdraw`     — ShieldWithdrawTx 投入
//! - POST `/api/shielded/simulate`            — tx 検証のみ（submit しない）
//!
//! # Security Notes
//! - module disabled の場合でも summary read (`module_status` / `root`) は維持する
//! - disabled 時は write route を 503 で fail-closed にし、public route も空/invalid へ寄せる
//! - proof 検証は ShieldedState 経由で行い、raw bytes を直接扱わない
//! - encrypted note の内容（平文）はレスポンスに含めない

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use misaka_shielded::{
    rpc_types::{
        EncryptedNoteEntry, GetEncryptedNotesSinceRequest, GetEncryptedNotesSinceResponse,
        GetNullifierStatusRequest, GetNullifierStatusResponse, GetShieldedRootResponse,
        GetSpentNullifiersSinceRequest, GetSpentNullifiersSinceResponse,
        ShieldedModuleStatusResponse, ShieldedTxTypeTag, SimulateShieldedTxRequest,
        SimulateShieldedTxResponse, SubmitShieldDepositRequest, SubmitShieldWithdrawRequest,
        SubmitShieldedTransferRequest, TxSubmitResponse, VerifyPaymentProofRequest,
        VerifyPaymentProofResponse,
    },
    NoteCommitment, Nullifier, SharedShieldedState,
};

// ─── Privacy Guard ──────────────────────────────────────────────────────────

/// Sanitize shielded transfer data for public RPC output.
/// Removes any fields that should not be observer-visible.
///
/// This function MUST be used whenever returning shielded transfer information
/// through any public-facing RPC endpoint. It ensures that value, recipient_pk,
/// rcm, nk_commit, and other secret fields are never exposed to observers.
pub fn sanitize_shielded_for_rpc(
    tx: &misaka_shielded::ShieldedTransferTx,
) -> serde_json::Value {
    serde_json::json!({
        "type": "shielded_transfer",
        "nullifiers": tx.nullifiers.iter().map(|n| hex::encode(n.0)).collect::<Vec<_>>(),
        "output_commitments": tx.output_commitments.iter().map(|c| hex::encode(c.0)).collect::<Vec<_>>(),
        "anchor": hex::encode(tx.anchor.0),
        "circuit_version": tx.circuit_version.0,
        "encrypted_output_count": tx.encrypted_outputs.len(),
        "proof_size": tx.proof.bytes.len(),
        "has_memo": tx.public_memo.is_some(),
    })
}

// ─── State ────────────────────────────────────────────────────────────────────

/// Shielded RPC のハンドラに共有される状態
#[derive(Clone)]
pub struct ShieldedRpcState {
    pub shielded: SharedShieldedState,
    /// P1: DAG state for mempool insertion
    pub dag_state: Option<crate::dag_rpc::DagSharedState>,
}

impl ShieldedRpcState {
    pub fn new(shielded: SharedShieldedState) -> Self {
        Self {
            shielded,
            dag_state: None,
        }
    }

    pub fn with_dag(shielded: SharedShieldedState, dag: crate::dag_rpc::DagSharedState) -> Self {
        Self {
            shielded,
            dag_state: Some(dag),
        }
    }
}

// ─── Router 構築 ──────────────────────────────────────────────────────────────

/// public (read-only) shielded routes を返す
pub fn shielded_public_router(state: ShieldedRpcState) -> Router {
    Router::new()
        .route("/api/shielded/module_status", get(get_module_status))
        .route("/api/shielded/root", get(get_shielded_root))
        .route("/api/shielded/nullifier_status", post(get_nullifier_status))
        .route("/api/shielded/encrypted_notes", post(get_encrypted_notes))
        .route("/api/shielded/spent_nullifiers", post(get_spent_nullifiers))
        .route(
            "/api/shielded/verify_payment_proof",
            post(verify_payment_proof),
        )
        .with_state(state)
}

/// write (authenticated) shielded routes を返す
/// 呼び出し側で auth middleware を適用すること
pub fn shielded_write_router(state: ShieldedRpcState) -> Router {
    Router::new()
        .route("/api/shielded/submit_deposit", post(submit_deposit))
        .route("/api/shielded/submit_transfer", post(submit_transfer))
        .route("/api/shielded/submit_withdraw", post(submit_withdraw))
        .route("/api/shielded/simulate", post(simulate_tx))
        .route("/api/shielded/merkle_witness", post(get_merkle_witness))
        .with_state(state)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn module_disabled_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "shielded module is disabled on this node",
            "code": "SHIELDED_MODULE_DISABLED"
        })),
    )
}

fn dag_wrapper_tx_hash(utxo_tx: &misaka_types::utxo::UtxoTransaction) -> ([u8; 32], String) {
    let tx_hash_bytes = utxo_tx.tx_hash();
    let tx_hash_hex = hex::encode(tx_hash_bytes);
    (tx_hash_bytes, tx_hash_hex)
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

// ─── GET /api/shielded/module_status ─────────────────────────────────────────

async fn get_module_status(
    State(state): State<ShieldedRpcState>,
) -> Json<ShieldedModuleStatusResponse> {
    let s = state.shielded.read();
    let root = s.current_root();
    Json(ShieldedModuleStatusResponse {
        enabled: s.is_enabled(),
        current_root: hex::encode(root.as_bytes()),
        commitment_count: s.commitment_count(),
        nullifier_count: s.nullifier_count(),
        accepted_circuit_versions: s
            .accepted_circuit_versions()
            .into_iter()
            .map(|v| v.0)
            .collect(),
        transparent_only_mode: !s.is_enabled(),
        layer4_status: s.layer4_status(),
    })
}

// ─── GET /api/shielded/root ───────────────────────────────────────────────────

async fn get_shielded_root(State(state): State<ShieldedRpcState>) -> Json<GetShieldedRootResponse> {
    let s = state.shielded.read();
    let root = s.current_root();
    Json(GetShieldedRootResponse {
        root: hex::encode(root.as_bytes()),
        commitment_count: s.commitment_count(),
        nullifier_count: s.nullifier_count(),
        enabled: s.is_enabled(),
    })
}

// ─── POST /api/shielded/nullifier_status ─────────────────────────────────────

async fn get_nullifier_status(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<GetNullifierStatusRequest>,
) -> Result<Json<GetNullifierStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let nf_bytes = parse_hex32(&req.nullifier).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid nullifier hex (expected 64 hex chars)"})),
        )
    })?;
    let nf = Nullifier(nf_bytes);
    let s = state.shielded.read();
    let spent = s.nullifier_set.is_confirmed_spent(&nf);
    let record = s.nullifier_set.get_record(&nf);

    Ok(Json(GetNullifierStatusResponse {
        nullifier: req.nullifier,
        spent,
        block_height: record.map(|r| r.block_height),
        tx_hash: record.map(|r| hex::encode(r.tx_hash)),
    }))
}

// ─── POST /api/shielded/encrypted_notes ──────────────────────────────────────
//
// P0: DB スキャンの実装は misaka-dag / misaka-storage 側のロールアウト後に
//     フル実装する。現時点では commitment_count と root のみ返す stub。

async fn get_encrypted_notes(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<GetEncryptedNotesSinceRequest>,
) -> Json<GetEncryptedNotesSinceResponse> {
    let s = state.shielded.read();

    if !s.is_enabled() {
        return Json(GetEncryptedNotesSinceResponse {
            notes: vec![],
            next_from_block: req.from_block,
            has_more: false,
        });
    }

    let limit = req.limit.min(1000) as usize;
    let notes = s.get_encrypted_notes_since(req.from_block, limit + 1);
    let has_more = notes.len() > limit;
    let result_notes: Vec<_> = notes.into_iter().take(limit).collect();
    let next_block = result_notes
        .last()
        .map(|n| n.block_height + 1)
        .unwrap_or(req.from_block);

    // Convert to RPC response format
    let rpc_notes: Vec<EncryptedNoteEntry> = result_notes
        .iter()
        .map(|n| EncryptedNoteEntry {
            position: n.position,
            epk: hex::encode(n.encrypted_note.epk),
            ciphertext: hex::encode(&n.encrypted_note.ciphertext),
            tag: hex::encode(n.encrypted_note.tag),
            view_tag: n.encrypted_note.view_tag,
            block_height: n.block_height,
            tx_hash: hex::encode(n.tx_hash),
        })
        .collect();

    Json(GetEncryptedNotesSinceResponse {
        notes: rpc_notes,
        next_from_block: next_block,
        has_more,
    })
}

// ─── POST /api/shielded/spent_nullifiers ─────────────────────────────────────

async fn get_spent_nullifiers(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<GetSpentNullifiersSinceRequest>,
) -> Json<GetSpentNullifiersSinceResponse> {
    let s = state.shielded.read();

    if !s.is_enabled() {
        return Json(GetSpentNullifiersSinceResponse {
            nullifiers: vec![],
            next_from_block: req.from_block,
            has_more: false,
        });
    }

    // P0 stub: block-indexed nullifier scan は P1 で実装
    tracing::debug!(
        "get_spent_nullifiers: from_block={} limit={} (P0 stub)",
        req.from_block,
        req.limit
    );
    Json(GetSpentNullifiersSinceResponse {
        nullifiers: vec![],
        next_from_block: req.from_block,
        has_more: false,
    })
}

// ─── POST /api/shielded/verify_payment_proof ─────────────────────────────────

async fn verify_payment_proof(
    State(_state): State<ShieldedRpcState>,
    Json(req): Json<VerifyPaymentProofRequest>,
) -> Result<Json<VerifyPaymentProofResponse>, (StatusCode, Json<serde_json::Value>)> {
    use misaka_shielded::IncomingViewKey;

    let ivk_bytes = parse_hex32(&req.ivk_hex).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid ivk_hex"})),
        )
    })?;
    let cm_bytes = parse_hex32(&req.commitment_hex).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid commitment_hex"})),
        )
    })?;

    let ivk = IncomingViewKey(ivk_bytes);
    let cm = NoteCommitment(cm_bytes);
    let valid = req.proof.verify(&ivk, &cm);

    Ok(Json(VerifyPaymentProofResponse {
        valid,
        amount: if valid { Some(req.proof.amount) } else { None },
        block_height: if valid {
            Some(req.proof.block_height)
        } else {
            None
        },
    }))
}

// ─── POST /api/shielded/submit_deposit ───────────────────────────────────────

async fn submit_deposit(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<SubmitShieldDepositRequest>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Phase 1: Sync validation (parking_lot guard dropped before any .await)
    let validation_result = {
        let s = state.shielded.read();
        if !s.is_enabled() {
            return Err(module_disabled_response());
        }
        s.validate_deposit(&req.tx)
    };

    match validation_result {
        Ok(()) => {
            // ── P1: Convert ShieldDepositTx → UtxoTransaction and insert into DAG mempool ──
            let serialized_deposit = serde_json::to_vec(&req.tx).unwrap_or_default();

            // Build a UtxoTransaction wrapper for DAG mempool ordering
            // P2: transparent inputs consume UTXOs, change outputs return excess
            let utxo_tx = misaka_types::utxo::UtxoTransaction {
                version: misaka_types::utxo::UTXO_TX_VERSION,
                proof_scheme: misaka_types::utxo::PROOF_SCHEME_TRANSPARENT,
                tx_type: misaka_types::utxo::TxType::ShieldDeposit,
                inputs: req.transparent_inputs.clone(),
                outputs: req.change_outputs.clone(),
                fee: req.tx.fee,
                extra: serialized_deposit, // Full ShieldDepositTx for hook deserialization
                zk_proof: None,
            };
            let (tx_hash_bytes, tx_hash_hex) = dag_wrapper_tx_hash(&utxo_tx);

            // Insert into DAG mempool via shared state
            if let Some(ref dag) = state.dag_state {
                let mut guard = dag.write().await;
                let s = &mut *guard;
                let state_mgr = &s.state_manager;
                let result = s
                    .mempool
                    .insert(utxo_tx, |ki| state_mgr.is_key_image_spent(ki));
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "submit_deposit: accepted into DAG mempool | tx={} amount={} from={}",
                            &tx_hash_hex[..16],
                            req.tx.amount,
                            hex::encode(req.tx.from)
                        );
                        Ok(Json(TxSubmitResponse::accepted(tx_hash_bytes)))
                    }
                    Err(e) => {
                        tracing::warn!("submit_deposit: mempool rejected: {}", e);
                        Ok(Json(TxSubmitResponse::rejected(format!(
                            "mempool rejected: {}",
                            e
                        ))))
                    }
                }
            } else {
                // Fallback: no DAG state (transparent-only wiring)
                tracing::info!(
                    "submit_deposit: validated (no DAG state wired) tx={}",
                    &tx_hash_hex[..16]
                );
                Ok(Json(TxSubmitResponse::validated_only(tx_hash_bytes)))
            }
        }
        Err(e) => {
            tracing::warn!("submit_deposit: rejected: {}", e);
            Ok(Json(TxSubmitResponse::rejected(e.to_string())))
        }
    }
}

// ─── POST /api/shielded/submit_transfer ──────────────────────────────────────

async fn submit_transfer(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<SubmitShieldedTransferRequest>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<serde_json::Value>)> {
    let validation_result = {
        let s = state.shielded.read();
        if !s.is_enabled() {
            return Err(module_disabled_response());
        }
        s.validate_shielded_transfer(&req.tx)
    };

    match validation_result {
        Ok(()) => {
            let serialized = serde_json::to_vec(&req.tx).unwrap_or_default();

            let utxo_tx = misaka_types::utxo::UtxoTransaction {
                version: misaka_types::utxo::UTXO_TX_VERSION,
                proof_scheme: misaka_types::utxo::PROOF_SCHEME_TRANSPARENT,
                tx_type: misaka_types::utxo::TxType::ShieldedTransfer,
                inputs: vec![],
                outputs: vec![],
                fee: req.tx.fee,
                extra: serialized,
                zk_proof: None,
            };
            let (tx_hash_bytes, tx_hash_hex) = dag_wrapper_tx_hash(&utxo_tx);

            if let Some(ref dag) = state.dag_state {
                let mut guard = dag.write().await;
                let s = &mut *guard;
                let state_mgr = &s.state_manager;
                let result = s
                    .mempool
                    .insert(utxo_tx, |ki| state_mgr.is_key_image_spent(ki));
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "submit_transfer: accepted into DAG mempool | tx={}",
                            &tx_hash_hex[..16]
                        );
                        Ok(Json(TxSubmitResponse::accepted(tx_hash_bytes)))
                    }
                    Err(e) => {
                        tracing::warn!("submit_transfer: mempool rejected: {}", e);
                        Ok(Json(TxSubmitResponse::rejected(format!(
                            "mempool rejected: {}",
                            e
                        ))))
                    }
                }
            } else {
                tracing::info!(
                    "submit_transfer: validated (no DAG state) tx={}",
                    &tx_hash_hex[..16]
                );
                Ok(Json(TxSubmitResponse::validated_only(tx_hash_bytes)))
            }
        }
        Err(e) => {
            tracing::warn!("submit_transfer: rejected: {}", e);
            Ok(Json(TxSubmitResponse::rejected(e.to_string())))
        }
    }
}

// ─── POST /api/shielded/submit_withdraw ──────────────────────────────────────

async fn submit_withdraw(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<SubmitShieldWithdrawRequest>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<serde_json::Value>)> {
    let validation_result = {
        let s = state.shielded.read();
        if !s.is_enabled() {
            return Err(module_disabled_response());
        }
        s.validate_withdraw(&req.tx)
    };

    match validation_result {
        Ok(()) => {
            let serialized = serde_json::to_vec(&req.tx).unwrap_or_default();

            // Build UtxoTransaction with transparent output for the withdrawal recipient
            let utxo_tx = misaka_types::utxo::UtxoTransaction {
                version: misaka_types::utxo::UTXO_TX_VERSION,
                proof_scheme: misaka_types::utxo::PROOF_SCHEME_TRANSPARENT,
                tx_type: misaka_types::utxo::TxType::ShieldWithdraw,
                inputs: vec![],
                outputs: vec![misaka_types::utxo::TxOutput {
                    amount: req.tx.withdraw_amount,
                    one_time_address: req.tx.withdraw_recipient,
                    pq_stealth: None,
                    spending_pubkey: req.recipient_spending_pubkey.clone(),
                }],
                fee: req.tx.fee,
                extra: serialized,
                zk_proof: None,
            };
            let (tx_hash_bytes, tx_hash_hex) = dag_wrapper_tx_hash(&utxo_tx);

            if let Some(ref dag) = state.dag_state {
                let mut guard = dag.write().await;
                let s = &mut *guard;
                let state_mgr = &s.state_manager;
                let result = s
                    .mempool
                    .insert(utxo_tx, |ki| state_mgr.is_key_image_spent(ki));
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "submit_withdraw: accepted into DAG mempool | tx={} amount={} to={}",
                            &tx_hash_hex[..16],
                            req.tx.withdraw_amount,
                            hex::encode(req.tx.withdraw_recipient)
                        );
                        Ok(Json(TxSubmitResponse::accepted(tx_hash_bytes)))
                    }
                    Err(e) => {
                        tracing::warn!("submit_withdraw: mempool rejected: {}", e);
                        Ok(Json(TxSubmitResponse::rejected(format!(
                            "mempool rejected: {}",
                            e
                        ))))
                    }
                }
            } else {
                tracing::info!(
                    "submit_withdraw: validated (no DAG state) tx={}",
                    &tx_hash_hex[..16]
                );
                Ok(Json(TxSubmitResponse::validated_only(tx_hash_bytes)))
            }
        }
        Err(e) => {
            tracing::warn!("submit_withdraw: rejected: {}", e);
            Ok(Json(TxSubmitResponse::rejected(e.to_string())))
        }
    }
}

// ─── POST /api/shielded/merkle_witness ────────────────────────────────────────

#[derive(serde::Deserialize)]
struct MerkleWitnessRequest {
    position: u64,
}

async fn get_merkle_witness(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<MerkleWitnessRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let s = state.shielded.read();
    if !s.is_enabled() {
        return Err(module_disabled_response());
    }

    match s.commitment_tree().witness(req.position) {
        Ok(witness) => {
            let siblings: Vec<String> = witness.auth_path.iter().map(hex::encode).collect();
            Ok(Json(serde_json::json!({
                "position": witness.position,
                "depth": witness.auth_path.len(),
                "siblings": siblings,
                "current_root": hex::encode(s.current_root().0),
            })))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}

// ─── POST /api/shielded/simulate ─────────────────────────────────────────────

async fn simulate_tx(
    State(state): State<ShieldedRpcState>,
    Json(req): Json<SimulateShieldedTxRequest>,
) -> Json<SimulateShieldedTxResponse> {
    let s = state.shielded.read();

    if !s.is_enabled() {
        return Json(SimulateShieldedTxResponse {
            valid: false,
            error: Some("shielded module is disabled".to_string()),
            estimated_fee: None,
        });
    }

    let result = match req.tx_type {
        ShieldedTxTypeTag::Deposit => req
            .deposit
            .as_ref()
            .map(|tx| s.validate_deposit(tx).map(|_| tx.fee))
            .unwrap_or(Err(misaka_shielded::ShieldedError::Internal(
                "missing deposit tx".into(),
            ))),
        ShieldedTxTypeTag::Transfer => req
            .transfer
            .as_ref()
            .map(|tx| s.validate_shielded_transfer(tx).map(|_| tx.fee))
            .unwrap_or(Err(misaka_shielded::ShieldedError::Internal(
                "missing transfer tx".into(),
            ))),
        ShieldedTxTypeTag::Withdraw => req
            .withdraw
            .as_ref()
            .map(|tx| s.validate_withdraw(tx).map(|_| tx.fee))
            .unwrap_or(Err(misaka_shielded::ShieldedError::Internal(
                "missing withdraw tx".into(),
            ))),
    };

    match result {
        Ok(fee) => Json(SimulateShieldedTxResponse {
            valid: true,
            error: None,
            estimated_fee: Some(fee),
        }),
        Err(e) => Json(SimulateShieldedTxResponse {
            valid: false,
            error: Some(e.to_string()),
            estimated_fee: None,
        }),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::shielded_hook_impl::NodeShieldedHook;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use misaka_dag::{ShieldedBlockHook, ShieldedTxPayload};
    use misaka_shielded::{
        parse_verifying_key_artifact,
        sha3_proof::{ProofInput, ProofOutput},
        CircuitVersion, EncryptedNote, NoteCommitment, Nullifier, ProofBackendKind,
        Sha3TransferProofBackend, Sha3TransferProofBuilder, ShieldDepositTx,
        ShieldedAuthoritativeBackendTargetTag, ShieldedConfig, ShieldedState, ShieldedTransferTx,
        ShieldedVkPolicyModeTag, MIN_SHIELDED_FEE,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    fn stub_state() -> SharedShieldedState {
        let mut state = ShieldedState::new(ShieldedConfig::testnet());
        state
            .register_stub_backend_for_testnet()
            .expect("testnet stub");
        std::sync::Arc::new(parking_lot::RwLock::new(state))
    }

    fn production_state() -> SharedShieldedState {
        let mut state = ShieldedState::new(ShieldedConfig::default());
        state.register_sha3_backend();
        std::sync::Arc::new(parking_lot::RwLock::new(state))
    }

    fn build_vk_artifact(
        kind: ProofBackendKind,
        version: CircuitVersion,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MSVK");
        out.push(1);
        out.push(match kind {
            ProofBackendKind::Groth16 => 1,
            ProofBackendKind::Plonk => 2,
            ProofBackendKind::Sha3Merkle => 3,
            ProofBackendKind::Sha3Transfer => 4,
            ProofBackendKind::Stub => 5,
        });
        out.extend_from_slice(&version.0.to_le_bytes());
        out.push(1);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn production_state_with_shell_contracts() -> SharedShieldedState {
        let mut state = ShieldedState::new(ShieldedConfig::default());
        state.register_sha3_backend();
        state.set_authoritative_target(ShieldedAuthoritativeBackendTargetTag::Groth16);
        let groth16_artifact = parse_verifying_key_artifact(
            &build_vk_artifact(
                ProofBackendKind::Groth16,
                CircuitVersion::GROTH16_V1,
                &[1, 2, 3],
            ),
            ProofBackendKind::Groth16,
            CircuitVersion::GROTH16_V1,
        )
        .expect("groth16 artifact");
        state.configure_groth16_shell_contract_from_artifact(
            ShieldedVkPolicyModeTag::Require,
            Some(groth16_artifact),
        );
        state.configure_plonk_shell_contract(ShieldedVkPolicyModeTag::Observe, vec![]);
        std::sync::Arc::new(parking_lot::RwLock::new(state))
    }

    fn disabled_state() -> SharedShieldedState {
        std::sync::Arc::new(parking_lot::RwLock::new(ShieldedState::new(
            ShieldedConfig::disabled(),
        )))
    }

    fn make_deposit_with_commitment(
        output_commitment: NoteCommitment,
        note_byte: u8,
        amount: u64,
    ) -> ShieldDepositTx {
        use misaka_pqc::pq_sign::MlDsaKeypair;
        use sha3::{Digest, Sha3_256};

        let kp = MlDsaKeypair::generate();
        let pubkey_bytes = kp.public_key.as_bytes().to_vec();

        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(&pubkey_bytes);
        let hash = h.finalize();
        let mut from = [0u8; 32];
        from.copy_from_slice(&hash);

        let mut tx = ShieldDepositTx {
            from,
            amount,
            asset_id: 0,
            fee: MIN_SHIELDED_FEE,
            output_commitment,
            encrypted_note: EncryptedNote {
                epk: [note_byte; 32],
                ciphertext: vec![note_byte; 64],
                tag: [0u8; 16],
                view_tag: 0,
            },
            signature_bytes: vec![],
            sender_pubkey: pubkey_bytes,
        };

        let payload = tx.signing_payload();
        let sig = misaka_pqc::ml_dsa_sign(&kp.secret_key, &payload).expect("sign ok");
        tx.signature_bytes = sig.as_bytes().to_vec();
        tx
    }

    fn make_real_sha3_transfer_fixture(
        shared: &SharedShieldedState,
    ) -> (ShieldedTransferTx, Nullifier, [u8; 32], String) {
        let mut state = shared.write();

        let input_value = 10_000_000u64;
        let output_value = input_value - MIN_SHIELDED_FEE;
        let nk_commit = [0x71u8; 32];
        let input_rcm = [0x52u8; 32];
        let output_rcm = [0x99u8; 32];
        let recipient_pk = [0x55u8; 32];

        let input_commitment = NoteCommitment(Sha3TransferProofBackend::compute_commitment(
            input_value,
            0,
            &nk_commit,
            &input_rcm,
        ));
        let deposit_tx = make_deposit_with_commitment(input_commitment, 0xD4, input_value);
        let (_, deposit_receipt) = state
            .apply_deposit(&deposit_tx, [0x11u8; 32], 100)
            .expect("deposit ok");

        let witness = state.merkle_witness(0).expect("witness");
        let mut builder = Sha3TransferProofBuilder::new(MIN_SHIELDED_FEE);
        builder.add_input(ProofInput {
            position: witness.position as u32,
            merkle_siblings: witness.auth_path,
            value: input_value,
            asset_id: 0,
            rcm: input_rcm,
            nk_commit,
        });
        builder.add_output(ProofOutput {
            value: output_value,
            asset_id: 0,
            recipient_pk,
            rcm: output_rcm,
        });
        let (proof, nullifiers, commitments) = builder.build().expect("proof build");

        let tx = ShieldedTransferTx {
            nullifiers: nullifiers.clone(),
            output_commitments: commitments,
            anchor: deposit_receipt.new_root,
            fee: MIN_SHIELDED_FEE,
            encrypted_outputs: vec![EncryptedNote {
                epk: [0x22u8; 32],
                ciphertext: vec![0x44u8; 64],
                tag: [0u8; 16],
                view_tag: 0,
            }],
            proof,
            circuit_version: CircuitVersion::SHA3_TRANSFER_V2,
            public_memo: Some(b"shielded rpc full path".to_vec()),
        };

        (
            tx,
            nullifiers[0],
            deposit_receipt.new_root.0,
            hex::encode(deposit_receipt.new_root.as_bytes()),
        )
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

    fn test_app(state: SharedShieldedState) -> Router {
        let rpc_state = ShieldedRpcState::new(state);
        shielded_public_router(rpc_state.clone()).merge(shielded_write_router(rpc_state))
    }

    #[tokio::test]
    async fn test_module_status_reports_stub_only_layer4_state_for_testnet() {
        let Json(resp) = get_module_status(State(ShieldedRpcState::new(stub_state()))).await;
        assert!(resp.enabled);
        assert_eq!(
            resp.current_root,
            hex::encode(misaka_shielded::TreeRoot::empty().as_bytes())
        );
        assert_eq!(resp.commitment_count, 0);
        assert_eq!(resp.nullifier_count, 0);
        assert!(!resp.transparent_only_mode);
        assert_eq!(resp.accepted_circuit_versions, vec![1]);
        assert_eq!(resp.layer4_status.backend_selection_mode, "testnet_stub");
        assert!(!resp.layer4_status.real_backend_ready);
        assert!(!resp.layer4_status.transfer_backend_ready);
        assert!(!resp.layer4_status.groth16_plonk_ready);
        assert_eq!(resp.layer4_status.registered_backends.len(), 1);
        assert_eq!(
            resp.layer4_status.registered_backends[0].backend_id,
            "stub-v1"
        );
        assert!(resp.layer4_status.registered_backends[0].verifier_body_implemented);
        assert!(!resp.layer4_status.registered_backends[0].verifying_key_required);
        assert!(!resp.layer4_status.registered_backends[0].verifying_key_loaded);
    }

    #[tokio::test]
    async fn test_module_status_reports_sha3_real_backend_and_groth16_plonk_gap() {
        let Json(resp) = get_module_status(State(ShieldedRpcState::new(production_state()))).await;
        assert!(resp.enabled);
        assert_eq!(
            resp.current_root,
            hex::encode(misaka_shielded::TreeRoot::empty().as_bytes())
        );
        assert_eq!(resp.commitment_count, 0);
        assert_eq!(resp.nullifier_count, 0);
        assert!(!resp.transparent_only_mode);
        assert!(resp.accepted_circuit_versions.contains(&50));
        assert!(resp.accepted_circuit_versions.contains(&51));
        assert!(resp.accepted_circuit_versions.contains(&52));
        assert_eq!(resp.layer4_status.backend_selection_mode, "production_real");
        assert!(resp.layer4_status.real_backend_ready);
        assert!(resp.layer4_status.transfer_backend_ready);
        assert!(!resp.layer4_status.groth16_plonk_ready);
        assert_eq!(
            resp.layer4_status.preferred_production_backend.as_deref(),
            Some("sha3-transfer-v2")
        );
        assert!(resp.layer4_status.registered_backends.iter().any(|b| {
            b.backend_id == "sha3-transfer-v2"
                && b.production_ready
                && b.verifier_body_implemented
                && !b.verifying_key_required
        }));
        assert!(!resp
            .layer4_status
            .registered_backends
            .iter()
            .any(|b| b.backend_id == "stub-v1"));
    }

    #[tokio::test]
    async fn test_module_status_reports_shell_contract_vk_readiness_without_registering_shells() {
        let Json(resp) = get_module_status(State(ShieldedRpcState::new(
            production_state_with_shell_contracts(),
        )))
        .await;

        let groth16 = resp
            .layer4_status
            .catalog_backends
            .iter()
            .find(|b| b.backend_id == "groth16-shell-v1")
            .expect("groth16 shell");
        assert!(groth16.verifying_key_loaded);
        assert!(groth16.verifying_key_required);
        assert!(groth16.verifying_key_fingerprint.is_some());
        assert!(!groth16.verifier_body_implemented);

        let plonk = resp
            .layer4_status
            .catalog_backends
            .iter()
            .find(|b| b.backend_id == "plonk-shell-v1")
            .expect("plonk shell");
        assert!(!plonk.verifying_key_loaded);
        assert!(plonk.verifying_key_required);
        assert!(plonk.verifying_key_fingerprint.is_none());
        assert!(!plonk.verifier_body_implemented);

        assert!(!resp
            .layer4_status
            .registered_backends
            .iter()
            .any(|b| b.backend_id == "groth16-shell-v1" || b.backend_id == "plonk-shell-v1"));
        assert_eq!(
            resp.layer4_status.verifier_contract.authoritative_target,
            ShieldedAuthoritativeBackendTargetTag::Groth16
        );
        assert!(
            !resp
                .layer4_status
                .verifier_contract
                .authoritative_target_ready
        );
        assert!(resp
            .layer4_status
            .verifier_contract
            .groth16_vk_fingerprint
            .is_some());
        assert!(resp
            .layer4_status
            .verifier_contract
            .plonk_vk_fingerprint
            .is_none());
        assert_eq!(
            resp.layer4_status
                .verifier_contract
                .canonical_public_input_schema,
            1
        );
        assert_eq!(
            resp.layer4_status
                .verifier_contract
                .shell_proof_envelope_schema,
            1
        );
    }

    #[tokio::test]
    async fn test_module_status_route_reports_disabled_mode_shape() {
        let app = test_app(disabled_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/shielded/module_status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["enabled"], false);
        assert_eq!(json["transparent_only_mode"], true);
        assert_eq!(json["layer4_status"]["backendSelectionMode"], "disabled");
        assert_eq!(json["layer4_status"]["groth16PlonkReady"], false);
        assert!(json["layer4_status"]["registeredBackends"].is_array());
        assert!(json["layer4_status"]["catalogBackends"].is_array());
        assert_eq!(
            json["layer4_status"]["verifierContract"]["authoritativeTarget"],
            "groth16_or_plonk"
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["canonicalPublicInputSchema"],
            1
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["shellProofEnvelopeSchema"],
            1
        );
        let verifier_contract = json["layer4_status"]["verifierContract"]
            .as_object()
            .expect("verifierContract object");
        assert!(verifier_contract.get("groth16VkArtifactSchema").is_none());
        assert!(verifier_contract.get("plonkVkArtifactSchema").is_none());
        assert!(verifier_contract
            .get("groth16VkFingerprintAlgorithm")
            .is_none());
        assert!(verifier_contract
            .get("plonkVkFingerprintAlgorithm")
            .is_none());
        assert!(verifier_contract
            .get("groth16VkArtifactPayloadLength")
            .is_none());
        assert!(verifier_contract
            .get("plonkVkArtifactPayloadLength")
            .is_none());
    }

    #[tokio::test]
    async fn test_module_status_route_reports_shell_vk_policy_shape_without_acceptance_expansion() {
        let app = test_app(production_state_with_shell_contracts());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/shielded/module_status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let versions = json["accepted_circuit_versions"].as_array().expect("array");
        assert!(versions.contains(&serde_json::json!(50)));
        assert!(versions.contains(&serde_json::json!(51)));
        assert!(versions.contains(&serde_json::json!(52)));
        assert_eq!(json["layer4_status"]["groth16PlonkReady"], false);
        assert_eq!(
            json["layer4_status"]["preferredProductionBackend"],
            "sha3-transfer-v2"
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["authoritativeTarget"],
            "groth16"
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["canonicalPublicInputSchema"],
            1
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["shellProofEnvelopeSchema"],
            1
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["authoritativeTargetReady"],
            false
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["groth16VkPolicy"],
            "require"
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["plonkVkPolicy"],
            "observe"
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["groth16VkArtifactSchema"],
            1
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["groth16VkFingerprintAlgorithm"],
            1
        );
        assert_eq!(
            json["layer4_status"]["verifierContract"]["groth16VkArtifactPayloadLength"],
            3
        );
        let verifier_contract = json["layer4_status"]["verifierContract"]
            .as_object()
            .expect("verifierContract object");
        assert!(verifier_contract.get("plonkVkArtifactSchema").is_none());
        assert!(verifier_contract
            .get("plonkVkFingerprintAlgorithm")
            .is_none());
        assert!(verifier_contract
            .get("plonkVkArtifactPayloadLength")
            .is_none());

        let registered = json["layer4_status"]["registeredBackends"]
            .as_array()
            .expect("registered array");
        assert!(!registered.iter().any(|b| b["backendId"] == "stub-v1"));
        assert!(!registered.iter().any(|b| {
            matches!(
                b["backendId"].as_str(),
                Some("groth16-shell-v1") | Some("plonk-shell-v1")
            )
        }));

        let catalog = json["layer4_status"]["catalogBackends"]
            .as_array()
            .expect("catalog array");
        let groth16 = catalog
            .iter()
            .find(|b| b["backendId"] == "groth16-shell-v1")
            .expect("groth16 catalog");
        assert_eq!(groth16["phase"], "shell");
        assert_eq!(groth16["verifyingKeyRequired"], true);
        assert_eq!(groth16["verifyingKeyLoaded"], true);
        assert_eq!(groth16["verifierBodyImplemented"], false);

        let plonk = catalog
            .iter()
            .find(|b| b["backendId"] == "plonk-shell-v1")
            .expect("plonk catalog");
        assert_eq!(plonk["phase"], "shell");
        assert_eq!(plonk["verifyingKeyRequired"], true);
        assert_eq!(plonk["verifyingKeyLoaded"], false);
        assert_eq!(plonk["verifierBodyImplemented"], false);
    }

    #[tokio::test]
    async fn test_disabled_public_and_write_routes_follow_current_fail_closed_contract() {
        let app = test_app(disabled_state());

        let encrypted_notes_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/encrypted_notes")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"from_block":0,"limit":10}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(encrypted_notes_response.status(), StatusCode::OK);
        let encrypted_notes_body = to_bytes(encrypted_notes_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let encrypted_notes_json: serde_json::Value =
            serde_json::from_slice(&encrypted_notes_body).expect("json");
        assert_eq!(encrypted_notes_json["notes"], serde_json::json!([]));
        assert_eq!(encrypted_notes_json["has_more"], false);

        let spent_nullifiers_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/spent_nullifiers")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"from_block":0,"limit":10}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(spent_nullifiers_response.status(), StatusCode::OK);
        let spent_nullifiers_body = to_bytes(spent_nullifiers_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let spent_nullifiers_json: serde_json::Value =
            serde_json::from_slice(&spent_nullifiers_body).expect("json");
        assert_eq!(spent_nullifiers_json["nullifiers"], serde_json::json!([]));
        assert_eq!(spent_nullifiers_json["has_more"], false);

        let simulate_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/simulate")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"tx_type":"deposit","deposit":null}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(simulate_response.status(), StatusCode::OK);
        let simulate_body = to_bytes(simulate_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let simulate_json: serde_json::Value =
            serde_json::from_slice(&simulate_body).expect("json");
        assert_eq!(simulate_json["valid"], false);
        assert_eq!(simulate_json["error"], "shielded module is disabled");

        for (route, body) in [
            (
                "/api/shielded/submit_deposit",
                r#"{"tx":{"from":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"amount":1,"asset_id":0,"fee":1000,"output_commitment":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"encrypted_note":{"epk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[],"tag":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"view_tag":0},"signature_bytes":[],"sender_pubkey":[]}}"#,
            ),
            ("/api/shielded/merkle_witness", r#"{"position":0}"#),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn test_root_route_stays_summary_only_when_disabled() {
        let app = test_app(disabled_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/shielded/root")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["enabled"], false);
        assert!(json["root"].is_string());
        assert_eq!(json["commitment_count"], 0);
        assert_eq!(json["nullifier_count"], 0);
        assert!(json.get("layer4Status").is_none());
        assert!(json.get("registeredBackends").is_none());
    }

    #[tokio::test]
    async fn test_nullifier_status_route_rejects_invalid_hex_and_remains_summary_only() {
        let app = test_app(disabled_state());

        let bad_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/nullifier_status")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"nullifier":"abcd"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(bad_response.status(), StatusCode::BAD_REQUEST);

        let ok_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/nullifier_status")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"nullifier":"{}"}}"#,
                        "00".repeat(32)
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(ok_response.status(), StatusCode::OK);

        let body = to_bytes(ok_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["spent"], false);
        assert!(json["block_height"].is_null());
        assert!(json["tx_hash"].is_null());
        assert!(json.get("notes").is_none());
        assert!(json.get("proof").is_none());
    }

    #[tokio::test]
    async fn test_verify_payment_proof_route_rejects_malformed_hex_inputs() {
        let app = test_app(stub_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/verify_payment_proof")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                            "proof":{
                                "tx_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                                "amount":1,
                                "asset_id":0,
                                "recipient_commitment":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                                "block_height":1,
                                "memo":null,
                                "created_at_ms":1
                            },
                            "ivk_hex":"abcd",
                            "commitment_hex":"00"
                        }"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_submit_transfer_full_path_updates_root_nullifier_and_encrypted_notes() {
        let state = production_state();
        let (transfer_tx, expected_nullifier, root_before_bytes, root_before_hex) =
            make_real_sha3_transfer_fixture(&state);
        let app = test_app(state.clone());

        let root_before_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/shielded/root")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(root_before_response.status(), StatusCode::OK);
        let root_before_body = to_bytes(root_before_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let root_before_json: serde_json::Value =
            serde_json::from_slice(&root_before_body).expect("json");
        assert_eq!(root_before_json["root"], root_before_hex);
        assert_eq!(root_before_json["nullifier_count"], 0);

        let submit_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/submit_transfer")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&SubmitShieldedTransferRequest {
                            tx: transfer_tx.clone(),
                        })
                        .expect("submit json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(submit_response.status(), StatusCode::OK);
        let submit_body = to_bytes(submit_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let submit_json: serde_json::Value = serde_json::from_slice(&submit_body).expect("json");
        assert_eq!(submit_json["status"], "validated_only");
        let tx_hash_hex = submit_json["tx_hash"].as_str().expect("tx_hash");
        let tx_hash = parse_hex32(tx_hash_hex).expect("tx hash hex");

        let pre_commit_nullifier_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/nullifier_status")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "nullifier": hex::encode(expected_nullifier.as_bytes())
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(pre_commit_nullifier_response.status(), StatusCode::OK);
        let pre_commit_nullifier_body =
            to_bytes(pre_commit_nullifier_response.into_body(), usize::MAX)
                .await
                .expect("body");
        let pre_commit_nullifier_json: serde_json::Value =
            serde_json::from_slice(&pre_commit_nullifier_body).expect("json");
        assert_eq!(pre_commit_nullifier_json["spent"], false);

        let temp_dir = unique_temp_dir("misaka-shielded-rpc-full-path");
        let hook = NodeShieldedHook::new(state.clone(), &temp_dir);
        hook.on_block_committed(
            101,
            &[0x22u8; 32],
            &[ShieldedTxPayload::Transfer {
                tx_hash,
                serialized: serde_json::to_vec(&transfer_tx).expect("serialized"),
            }],
        );

        let root_after_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/shielded/root")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(root_after_response.status(), StatusCode::OK);
        let root_after_body = to_bytes(root_after_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let root_after_json: serde_json::Value =
            serde_json::from_slice(&root_after_body).expect("json");
        assert_ne!(root_after_json["root"], hex::encode(root_before_bytes));
        assert_eq!(root_after_json["nullifier_count"], 1);

        let post_commit_nullifier_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/nullifier_status")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "nullifier": hex::encode(expected_nullifier.as_bytes())
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(post_commit_nullifier_response.status(), StatusCode::OK);
        let post_commit_nullifier_body =
            to_bytes(post_commit_nullifier_response.into_body(), usize::MAX)
                .await
                .expect("body");
        let post_commit_nullifier_json: serde_json::Value =
            serde_json::from_slice(&post_commit_nullifier_body).expect("json");
        assert_eq!(post_commit_nullifier_json["spent"], true);
        assert_eq!(post_commit_nullifier_json["block_height"], 101);
        assert_eq!(post_commit_nullifier_json["tx_hash"], tx_hash_hex);

        let encrypted_notes_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shielded/encrypted_notes")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "from_block": 101u64,
                            "limit": 10u64
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(encrypted_notes_response.status(), StatusCode::OK);
        let encrypted_notes_body = to_bytes(encrypted_notes_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let encrypted_notes_json: serde_json::Value =
            serde_json::from_slice(&encrypted_notes_body).expect("json");
        let notes = encrypted_notes_json["notes"]
            .as_array()
            .expect("notes array");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0]["block_height"], 101);
        assert_eq!(notes[0]["tx_hash"], tx_hash_hex);
        assert_eq!(encrypted_notes_json["has_more"], false);

        let module_status_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/shielded/module_status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(module_status_response.status(), StatusCode::OK);
        let module_status_body = to_bytes(module_status_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let module_status_json: serde_json::Value =
            serde_json::from_slice(&module_status_body).expect("json");
        let versions = module_status_json["accepted_circuit_versions"].as_array().expect("array");
        assert!(versions.contains(&serde_json::json!(50)));
        assert!(versions.contains(&serde_json::json!(51)));
        assert!(versions.contains(&serde_json::json!(52)));
        assert_eq!(
            module_status_json["layer4_status"]["backendSelectionMode"],
            "production_real"
        );
        assert_eq!(
            module_status_json["layer4_status"]["preferredProductionBackend"],
            "sha3-transfer-v2"
        );
        assert_eq!(module_status_json["nullifier_count"], 1);

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
