//! Shielded transaction types.
//!
//! # Tx type 分類
//!
//! - `ShieldDepositTx`:   transparent funds → shielded pool
//! - `ShieldedTransferTx`: shielded pool 内の note 消費と新 note 生成 (P1)
//! - `ShieldWithdrawTx`:  shielded pool → transparent address
//!
//! これらは `misaka-types::transaction::Transaction` の variant として
//! `misaka-types` 側に `ShieldDeposit` / `ShieldedTransfer` / `ShieldWithdraw`
//! を追加するが、payload の型はこのクレートで定義する。

use crate::types::{
    CircuitVersion, EncryptedNote, NoteCommitment, Nullifier, ShieldedProof, TreeRoot,
};
use serde::{Deserialize, Serialize};

// ─── Limits ───────────────────────────────────────────────────────────────────

/// tx あたりの最大 nullifier 数
pub const MAX_NULLIFIERS_PER_TX: usize = 4;
/// tx あたりの最大 output commitment 数
pub const MAX_OUTPUTS_PER_TX: usize = 4;
/// encrypted note の最大バイト数（memo サイズ制限）
pub const MAX_ENCRYPTED_NOTE_SIZE: usize = 4096;
/// shielded tx の最低手数料 (base units)
pub const MIN_SHIELDED_FEE: u64 = 1_000;

// ─── ShieldDepositTx ──────────────────────────────────────────────────────────

/// transparent funds を shielded pool に預けるトランザクション。
///
/// # Public Information (on-chain で公開)
/// - `from`:              送信元 transparent address (32 bytes)
/// - `amount`:            預入額
/// - `asset_id`:          資産 ID
/// - `fee`:               手数料
/// - `output_commitment`: 生成される note の commitment
///
/// # Hidden Information
/// - note の recipient（encrypted_note を保有者の ivk で解読することで判明）
/// - note の rcm / blinding factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldDepositTx {
    /// 送信元 transparent address (32 bytes)
    pub from: [u8; 32],
    /// 預入額（公開）
    pub amount: u64,
    /// 資産 ID（0 = native MISAKA token）
    pub asset_id: u64,
    /// 手数料（公開）
    pub fee: u64,
    /// 生成される note の commitment（公開）
    pub output_commitment: NoteCommitment,
    /// 暗号化済み note（recipient が自分宛かを確認するために必要）
    pub encrypted_note: EncryptedNote,
    /// 送信元の ML-DSA-65 署名（signing payload に対して）
    pub signature_bytes: Vec<u8>,
    /// SEC-FIX [Audit #4]: 送信元の ML-DSA-65 公開鍵。
    /// validate_deposit で pubkey→address 導出チェック + 署名検証を完結させる。
    #[serde(default)]
    pub sender_pubkey: Vec<u8>,
}

impl ShieldDepositTx {
    /// signing payload: fee を除く全フィールドの canonical bytes
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"MISAKA:shield_deposit:v1:");
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.asset_id.to_le_bytes());
        buf.extend_from_slice(&self.fee.to_le_bytes());
        buf.extend_from_slice(self.output_commitment.as_bytes());
        buf
    }

    /// structural validation（crypto は呼び出し側で検証）
    pub fn validate_structure(&self) -> Result<(), ShieldedTxError> {
        if self.amount == 0 {
            return Err(ShieldedTxError::ZeroAmount);
        }
        if self.fee < MIN_SHIELDED_FEE {
            return Err(ShieldedTxError::FeeTooLow {
                actual: self.fee,
                minimum: MIN_SHIELDED_FEE,
            });
        }
        if self.output_commitment == NoteCommitment::zero() {
            return Err(ShieldedTxError::ZeroCommitment);
        }
        if self.encrypted_note.ciphertext.is_empty() {
            return Err(ShieldedTxError::MissingEncryptedNote);
        }
        if self.encrypted_note.ciphertext.len() > MAX_ENCRYPTED_NOTE_SIZE {
            return Err(ShieldedTxError::EncryptedNoteTooLarge {
                actual: self.encrypted_note.ciphertext.len(),
                limit: MAX_ENCRYPTED_NOTE_SIZE,
            });
        }
        if self.signature_bytes.is_empty() {
            return Err(ShieldedTxError::MissingSignature);
        }
        // SEC-FIX [Audit #4]: Require ML-DSA-65 signature (3309 bytes) and pubkey (1952 bytes).
        if self.signature_bytes.len() != 3309 {
            return Err(ShieldedTxError::MissingSignature);
        }
        if self.sender_pubkey.len() != 1952 {
            return Err(ShieldedTxError::MissingSignature);
        }
        Ok(())
    }
}

// ─── ShieldedTransferTx ───────────────────────────────────────────────────────

/// shielded pool 内での note 消費と新 note 生成。
///
/// # Public Information (on-chain で公開)
/// - `nullifiers`:         消費された note の nullifiers（二重使用防止に必要）
/// - `output_commitments`: 生成される note の commitments
/// - `anchor`:             使用する Merkle root（inclusion 証明の基点）
/// - `fee`:                手数料
/// - `circuit_version`:    使用 circuit バージョン
///
/// # Hidden Information (ZK proof で間接的に証明)
/// - note の value / amount
/// - sender / recipient
/// - note の rcm
///
/// # P0 Note
/// P0 では proof は stub。P1 で real Groth16/PLONK proof に差し替える。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedTransferTx {
    /// 消費する note の nullifiers（公開）
    pub nullifiers: Vec<Nullifier>,
    /// 生成する note の commitments（公開）
    pub output_commitments: Vec<NoteCommitment>,
    /// anchor（public root, ZK proof の基点）
    pub anchor: TreeRoot,
    /// 手数料（公開）
    pub fee: u64,
    /// 暗号化済み output notes（recipient のみ解読可能）
    pub encrypted_outputs: Vec<EncryptedNote>,
    /// ZK proof
    pub proof: ShieldedProof,
    /// circuit バージョン
    pub circuit_version: CircuitVersion,
    /// optional public memo
    pub public_memo: Option<Vec<u8>>,
}

impl ShieldedTransferTx {
    pub fn validate_structure(&self) -> Result<(), ShieldedTxError> {
        if self.nullifiers.is_empty() {
            return Err(ShieldedTxError::EmptyNullifiers);
        }
        if self.nullifiers.len() > MAX_NULLIFIERS_PER_TX {
            return Err(ShieldedTxError::TooManyNullifiers {
                actual: self.nullifiers.len(),
                limit: MAX_NULLIFIERS_PER_TX,
            });
        }
        if self.output_commitments.is_empty() {
            return Err(ShieldedTxError::EmptyOutputs);
        }
        if self.output_commitments.len() > MAX_OUTPUTS_PER_TX {
            return Err(ShieldedTxError::TooManyOutputs {
                actual: self.output_commitments.len(),
                limit: MAX_OUTPUTS_PER_TX,
            });
        }
        if self.output_commitments.len() != self.encrypted_outputs.len() {
            return Err(ShieldedTxError::OutputCountMismatch {
                commitments: self.output_commitments.len(),
                encrypted: self.encrypted_outputs.len(),
            });
        }
        if self.fee < MIN_SHIELDED_FEE {
            return Err(ShieldedTxError::FeeTooLow {
                actual: self.fee,
                minimum: MIN_SHIELDED_FEE,
            });
        }
        // duplicate nullifier check
        let unique: std::collections::HashSet<_> = self.nullifiers.iter().collect();
        if unique.len() != self.nullifiers.len() {
            return Err(ShieldedTxError::DuplicateNullifier);
        }
        // zero commitment check
        for cm in &self.output_commitments {
            if *cm == NoteCommitment::zero() {
                return Err(ShieldedTxError::ZeroCommitment);
            }
        }
        Ok(())
    }
}

// ─── ShieldWithdrawTx ─────────────────────────────────────────────────────────

/// shielded pool から transparent address に戻すトランザクション。
///
/// # Public Information (on-chain で公開)
/// - `nullifiers`:          消費された note の nullifiers
/// - `anchor`:              Merkle root
/// - `withdraw_amount`:     出金額（公開）
/// - `withdraw_recipient`:  受取先 transparent address（公開）
/// - `fee`:                 手数料
///
/// CEX送金前の標準経路。
/// CEX は transparent address で受け取るためこの経路を通す必要がある。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldWithdrawTx {
    /// 消費する note の nullifiers（公開）
    pub nullifiers: Vec<Nullifier>,
    /// Merkle root（公開）
    pub anchor: TreeRoot,
    /// 出金額（公開）
    pub withdraw_amount: u64,
    /// 受取先 transparent address（公開, 32 bytes）
    pub withdraw_recipient: [u8; 32],
    /// 手数料（公開）
    pub fee: u64,
    /// ZK proof
    pub proof: ShieldedProof,
    /// circuit バージョン
    pub circuit_version: CircuitVersion,
}

impl ShieldWithdrawTx {
    pub fn validate_structure(&self) -> Result<(), ShieldedTxError> {
        if self.nullifiers.is_empty() {
            return Err(ShieldedTxError::EmptyNullifiers);
        }
        if self.nullifiers.len() > MAX_NULLIFIERS_PER_TX {
            return Err(ShieldedTxError::TooManyNullifiers {
                actual: self.nullifiers.len(),
                limit: MAX_NULLIFIERS_PER_TX,
            });
        }
        if self.withdraw_amount == 0 {
            return Err(ShieldedTxError::ZeroAmount);
        }
        if self.fee < MIN_SHIELDED_FEE {
            return Err(ShieldedTxError::FeeTooLow {
                actual: self.fee,
                minimum: MIN_SHIELDED_FEE,
            });
        }
        // SECURITY [M1]: withdraw_amount + fee の u64 オーバーフロー検査。
        // オーバーフロー時に wrap-around すると、ノードが amount > balance を
        // 正当な残高として扱う可能性がある。
        if self.withdraw_amount.checked_add(self.fee).is_none() {
            return Err(ShieldedTxError::AmountOverflow);
        }
        // zero recipient check
        if self.withdraw_recipient == [0u8; 32] {
            return Err(ShieldedTxError::ZeroAddress);
        }
        // duplicate nullifier check
        let unique: std::collections::HashSet<_> = self.nullifiers.iter().collect();
        if unique.len() != self.nullifiers.len() {
            return Err(ShieldedTxError::DuplicateNullifier);
        }
        Ok(())
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ShieldedTxError {
    #[error("zero amount is not allowed")]
    ZeroAmount,
    #[error("zero commitment is not allowed")]
    ZeroCommitment,
    #[error("zero recipient address is not allowed")]
    ZeroAddress,
    #[error("fee too low: {actual} < minimum {minimum}")]
    FeeTooLow { actual: u64, minimum: u64 },
    #[error("nullifiers list is empty")]
    EmptyNullifiers,
    #[error("outputs list is empty")]
    EmptyOutputs,
    #[error("too many nullifiers: {actual} > {limit}")]
    TooManyNullifiers { actual: usize, limit: usize },
    #[error("too many outputs: {actual} > {limit}")]
    TooManyOutputs { actual: usize, limit: usize },
    #[error("output count mismatch: {commitments} commitments vs {encrypted} encrypted notes")]
    OutputCountMismatch {
        commitments: usize,
        encrypted: usize,
    },
    #[error("duplicate nullifier in tx")]
    DuplicateNullifier,
    #[error("missing encrypted note")]
    MissingEncryptedNote,
    #[error("encrypted note too large: {actual} > {limit}")]
    EncryptedNoteTooLarge { actual: usize, limit: usize },
    #[error("missing signature")]
    MissingSignature,
    #[error("amount + fee overflows u64")]
    AmountOverflow,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::ShieldedProof;

    fn make_deposit() -> ShieldDepositTx {
        ShieldDepositTx {
            from: [1u8; 32],
            amount: 1_000_000,
            asset_id: 0,
            fee: MIN_SHIELDED_FEE,
            output_commitment: NoteCommitment([2u8; 32]),
            encrypted_note: EncryptedNote {
                epk: [3u8; 32],
                ciphertext: vec![0u8; 64],
                tag: [0u8; 16],
                view_tag: 0,
            },
            // SEC-FIX [Audit #4]: ML-DSA-65 signature (3309 bytes) + pubkey (1952 bytes)
            // validate_structure() は正しいサイズのみ許可する
            signature_bytes: vec![0u8; 3309],
            sender_pubkey: vec![0u8; 1952],
        }
    }

    #[test]
    fn valid_deposit_structure() {
        make_deposit()
            .validate_structure()
            .expect("should be valid");
    }

    #[test]
    fn deposit_zero_amount_rejected() {
        let mut tx = make_deposit();
        tx.amount = 0;
        assert!(matches!(
            tx.validate_structure(),
            Err(ShieldedTxError::ZeroAmount)
        ));
    }

    #[test]
    fn deposit_low_fee_rejected() {
        let mut tx = make_deposit();
        tx.fee = MIN_SHIELDED_FEE - 1;
        assert!(matches!(
            tx.validate_structure(),
            Err(ShieldedTxError::FeeTooLow { .. })
        ));
    }

    fn make_withdraw() -> ShieldWithdrawTx {
        ShieldWithdrawTx {
            nullifiers: vec![Nullifier([1u8; 32])],
            anchor: TreeRoot::empty(),
            withdraw_amount: 500_000,
            withdraw_recipient: [2u8; 32],
            fee: MIN_SHIELDED_FEE,
            proof: ShieldedProof::dev_testnet_stub(),
            circuit_version: CircuitVersion::STUB_V1,
        }
    }

    #[test]
    fn valid_withdraw_structure() {
        make_withdraw()
            .validate_structure()
            .expect("should be valid");
    }

    #[test]
    fn withdraw_duplicate_nullifier_rejected() {
        let mut tx = make_withdraw();
        tx.nullifiers.push(Nullifier([1u8; 32])); // duplicate
        assert!(matches!(
            tx.validate_structure(),
            Err(ShieldedTxError::DuplicateNullifier)
        ));
    }
}
