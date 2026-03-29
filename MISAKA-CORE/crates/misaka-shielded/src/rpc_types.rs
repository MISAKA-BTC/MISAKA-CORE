//! Shielded RPC Types
//!
//! wallet ↔ node 間の shielded 系 RPC エンドポイントの型定義。
//!
//! # Endpoint 設計方針
//!
//! - transparent 系: 完全公開、制限なし
//! - shielded 系: wallet との専用通信。一部は ivk 認証を要求する。
//!   ただし ivk は **node に送らない** のが理想。
//!   P0 では利便性のためにノードへの問い合わせを許容するが、
//!   P1 以降はウォレット側でフルスキャンを行う方針に移行する。
//!
//! # Explorer 向け注意
//! shielded tx の RPC レスポンスは commitment 数・nullifier 数・fee・type のみ。
//! amount / sender / recipient は**絶対に含めない**。

use crate::{
    tx_types::{ShieldDepositTx, ShieldWithdrawTx, ShieldedTransferTx},
    types::{EncryptedNote},
    wallet_scanner::PaymentProof,
};
use serde::{Deserialize, Serialize};

// ─── Submit エンドポイント ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitShieldDepositRequest {
    pub tx: ShieldDepositTx,
    /// P2: Transparent UTXO inputs to consume (burn into shielded pool)
    #[serde(default)]
    pub transparent_inputs: Vec<misaka_types::utxo::TxInput>,
    /// P2: Change output(s) if UTXO value exceeds deposit + fee
    #[serde(default)]
    pub change_outputs: Vec<misaka_types::utxo::TxOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitShieldedTransferRequest {
    pub tx: ShieldedTransferTx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitShieldWithdrawRequest {
    pub tx: ShieldWithdrawTx,
    /// Recipient's spending pubkey for UTXO index registration (balance lookup)
    #[serde(default)]
    pub recipient_spending_pubkey: Option<Vec<u8>>,
}

/// tx submit の共通レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSubmitResponse {
    pub status: TxSubmitStatus,
    pub tx_hash: String, // hex
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxSubmitStatus {
    Accepted,
    Rejected,
    /// SEC-FIX [Audit #7]: Tx was validated but NOT enqueued in the DAG mempool.
    /// Clients must NOT assume it will be mined. P0 shielded submit uses this.
    ValidatedOnly,
}

impl TxSubmitResponse {
    pub fn accepted(tx_hash: [u8; 32]) -> Self {
        Self {
            status: TxSubmitStatus::Accepted,
            tx_hash: hex::encode(tx_hash),
            error: None,
        }
    }
    /// SEC-FIX [Audit #7]: Return validated_only instead of accepted
    /// when the tx has been validated but not yet routed to the DAG mempool.
    pub fn validated_only(tx_hash: [u8; 32]) -> Self {
        Self {
            status: TxSubmitStatus::ValidatedOnly,
            tx_hash: hex::encode(tx_hash),
            error: None,
        }
    }
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: TxSubmitStatus::Rejected,
            tx_hash: String::new(),
            error: Some(reason.into()),
        }
    }
}

// ─── Query エンドポイント ─────────────────────────────────────────────────────

/// GET /api/shielded/root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetShieldedRootResponse {
    pub root: String, // hex
    pub commitment_count: u64,
    pub nullifier_count: usize,
    pub enabled: bool,
}

/// GET /api/shielded/nullifier_status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNullifierStatusRequest {
    pub nullifier: String, // hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNullifierStatusResponse {
    pub nullifier: String,
    pub spent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// GET /api/shielded/encrypted_notes_since
/// wallet の note スキャンに使用する。
/// ノードが暗号化 note をそのまま返す（平文は返さない）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEncryptedNotesSinceRequest {
    pub from_block: u64,
    /// 一回の応答の最大 note 数（デフォルト 1000）
    #[serde(default = "default_limit")]
    pub limit: u64,
}

fn default_limit() -> u64 {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNoteEntry {
    pub position: u64,
    pub tx_hash: String,
    pub block_height: u64,
    /// ephemeral public key (hex)
    pub epk: String,
    /// ciphertext (hex)
    pub ciphertext: String,
    /// AEAD tag (hex)
    pub tag: String,
    /// view tag byte
    pub view_tag: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEncryptedNotesSinceResponse {
    pub notes: Vec<EncryptedNoteEntry>,
    pub next_from_block: u64,
    pub has_more: bool,
}

/// GET /api/shielded/spent_nullifiers_since
/// wallet の spent note 検出に使用する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpentNullifiersSinceRequest {
    pub from_block: u64,
    #[serde(default = "default_limit")]
    pub limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentNullifierEntry {
    pub nullifier: String, // hex
    pub block_height: u64,
    pub tx_hash: String, // hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpentNullifiersSinceResponse {
    pub nullifiers: Vec<SpentNullifierEntry>,
    pub next_from_block: u64,
    pub has_more: bool,
}

// ─── Simulate エンドポイント ──────────────────────────────────────────────────

/// POST /api/shielded/simulate
/// tx を実際に submit せずに検証だけ行う（wallet の事前チェック用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateShieldedTxRequest {
    pub tx_type: ShieldedTxTypeTag,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit: Option<ShieldDepositTx>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer: Option<ShieldedTransferTx>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdraw: Option<ShieldWithdrawTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedTxTypeTag {
    Deposit,
    Transfer,
    Withdraw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateShieldedTxResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_fee: Option<u64>,
}

// ─── PaymentProof エンドポイント ──────────────────────────────────────────────

/// POST /api/shielded/verify_payment_proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyPaymentProofRequest {
    pub proof: PaymentProof,
    /// 検証者の incoming view key (hex)
    pub ivk_hex: String,
    /// 対象 commitment (hex)
    pub commitment_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyPaymentProofResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

// ─── Explorer 向け shielded tx サマリー ──────────────────────────────────────

/// explorer が shielded tx を表示する際の情報。
/// 秘匿情報（amount / sender / recipient）を含まない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedTxSummary {
    pub tx_hash: String,
    pub tx_type: ShieldedTxTypeTag,
    /// 手数料（公開）
    pub fee: u64,
    /// 消費された nullifier 数
    pub nullifier_count: usize,
    /// 生成された commitment 数
    pub commitment_count: usize,
    /// 使用した Merkle root（anchor）
    pub anchor: String,
    /// block_height
    pub block_height: u64,
    /// ShieldDeposit の場合のみ: 預入額（公開）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit_amount: Option<u64>,
    /// ShieldWithdraw の場合のみ: 出金先アドレス・額（公開）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdraw_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdraw_recipient: Option<String>,
}

// ─── Module status ────────────────────────────────────────────────────────────

/// GET /api/shielded/module_status
/// ノードが shielded module を有効にしているか確認する（CEX 統合向け）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedModuleStatusResponse {
    pub enabled: bool,
    pub current_root: String,
    pub commitment_count: u64,
    pub nullifier_count: usize,
    /// 受け付け可能な circuit version 範囲
    pub accepted_circuit_versions: Vec<u16>,
    /// transparent-only モード（shielded tx を拒否するノード向け）
    pub transparent_only_mode: bool,
}
