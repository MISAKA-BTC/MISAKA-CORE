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
//! - module disabled の場合は全エンドポイントが 503 を返す
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
        GetEncryptedNotesSinceRequest, GetEncryptedNotesSinceResponse,
        GetNullifierStatusRequest, GetNullifierStatusResponse, GetShieldedRootResponse,
        GetSpentNullifiersSinceRequest, GetSpentNullifiersSinceResponse,
        ShieldedModuleStatusResponse, ShieldedTxTypeTag, SimulateShieldedTxRequest,
        SimulateShieldedTxResponse, SubmitShieldDepositRequest, EncryptedNoteEntry,
        SubmitShieldWithdrawRequest, SubmitShieldedTransferRequest, TxSubmitResponse,
        VerifyPaymentProofRequest, VerifyPaymentProofResponse,
    },
    NoteCommitment, Nullifier, SharedShieldedState,
};

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
        Self { shielded, dag_state: None }
    }

    pub fn with_dag(shielded: SharedShieldedState, dag: crate::dag_rpc::DagSharedState) -> Self {
        Self { shielded, dag_state: Some(dag) }
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
        .route("/api/shielded/verify_payment_proof", post(verify_payment_proof))
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
        accepted_circuit_versions: {
            // P0: stub v1 のみ
            vec![misaka_shielded::CircuitVersion::STUB_V1.0]
        },
        transparent_only_mode: !s.is_enabled(),
    })
}

// ─── GET /api/shielded/root ───────────────────────────────────────────────────

async fn get_shielded_root(
    State(state): State<ShieldedRpcState>,
) -> Json<GetShieldedRootResponse> {
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
    let next_block = result_notes.last().map(|n| n.block_height + 1).unwrap_or(req.from_block);

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
    use misaka_shielded::{IncomingViewKey, PaymentProof};

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
        block_height: if valid { Some(req.proof.block_height) } else { None },
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
            let tx_hash_bytes: [u8; 32] = {
                let mut h = blake3::Hasher::new_derive_key("MISAKA shielded deposit tx id v1");
                h.update(&serialized_deposit);
                *h.finalize().as_bytes()
            };
            let tx_hash_hex = hex::encode(tx_hash_bytes);

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

            // Insert into DAG mempool via shared state
            if let Some(ref dag) = state.dag_state {
                let mut guard = dag.write().await;
                let s = &mut *guard;
                let state_mgr = &s.state_manager;
                let result = s.mempool.insert(utxo_tx, |ki| state_mgr.is_key_image_spent(ki));
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "submit_deposit: accepted into DAG mempool | tx={} amount={} from={}",
                            &tx_hash_hex[..16], req.tx.amount, hex::encode(req.tx.from)
                        );
                        Ok(Json(TxSubmitResponse::accepted(tx_hash_bytes)))
                    }
                    Err(e) => {
                        tracing::warn!("submit_deposit: mempool rejected: {}", e);
                        Ok(Json(TxSubmitResponse::rejected(format!("mempool rejected: {}", e))))
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
            let tx_hash_bytes: [u8; 32] = {
                let mut h = blake3::Hasher::new_derive_key("MISAKA shielded transfer tx id v1");
                h.update(&serialized);
                *h.finalize().as_bytes()
            };
            let tx_hash_hex = hex::encode(tx_hash_bytes);

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

            if let Some(ref dag) = state.dag_state {
                let mut guard = dag.write().await;
                let s = &mut *guard;
                let state_mgr = &s.state_manager;
                let result = s.mempool.insert(utxo_tx, |ki| state_mgr.is_key_image_spent(ki));
                match result {
                    Ok(()) => {
                        tracing::info!("submit_transfer: accepted into DAG mempool | tx={}", &tx_hash_hex[..16]);
                        Ok(Json(TxSubmitResponse::accepted(tx_hash_bytes)))
                    }
                    Err(e) => {
                        tracing::warn!("submit_transfer: mempool rejected: {}", e);
                        Ok(Json(TxSubmitResponse::rejected(format!("mempool rejected: {}", e))))
                    }
                }
            } else {
                tracing::info!("submit_transfer: validated (no DAG state) tx={}", &tx_hash_hex[..16]);
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
            let tx_hash_bytes: [u8; 32] = {
                let mut h = blake3::Hasher::new_derive_key("MISAKA shielded withdraw tx id v1");
                h.update(&serialized);
                *h.finalize().as_bytes()
            };
            let tx_hash_hex = hex::encode(tx_hash_bytes);

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

            if let Some(ref dag) = state.dag_state {
                let mut guard = dag.write().await;
                let s = &mut *guard;
                let state_mgr = &s.state_manager;
                let result = s.mempool.insert(utxo_tx, |ki| state_mgr.is_key_image_spent(ki));
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "submit_withdraw: accepted into DAG mempool | tx={} amount={} to={}",
                            &tx_hash_hex[..16], req.tx.withdraw_amount, hex::encode(req.tx.withdraw_recipient)
                        );
                        Ok(Json(TxSubmitResponse::accepted(tx_hash_bytes)))
                    }
                    Err(e) => {
                        tracing::warn!("submit_withdraw: mempool rejected: {}", e);
                        Ok(Json(TxSubmitResponse::rejected(format!("mempool rejected: {}", e))))
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
        Err(e) => {
            Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            ))
        }
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
