//! L1-Native Validator Staking Transactions
//!
//! # 概要
//!
//! MISAKA L1 上で直接バリデーター登録とステーキングを行うトランザクション型。
//! Solana 依存なしで完結する。
//!
//! # トランザクション種別
//!
//! ```text
//! ValidatorStakeTx::Register   — 新規登録 + ステーク locked
//! ValidatorStakeTx::StakeMore  — 既存バリデーターへの追加ステーク
//! ValidatorStakeTx::BeginExit  — アンボンディング開始
//! ```
//!
//! # セキュリティ設計
//!
//! - 署名は ML-DSA-65 (FIPS 204) のみ（ECC/Ed25519 禁止）
//! - signing_payload は domain tag + canonical serialization
//! - ステーク量は UTXO 参照で証明（残高の二重カウント防止）
//! - `stake_amount + fee` のオーバーフロー検査を validate_structure() で強制
//!
//! # ステーク量の単位
//!
//! MISAKA トークンの最小単位 (base units, 9 decimals)
//! 1 MISAKA = 1_000_000_000 base units
//! Mainnet 最低: 10_000_000 MISAKA = 10_000_000_000_000_000 base units
//! Testnet 最低:  1_000_000 MISAKA =  1_000_000_000_000_000 base units

use crate::mcs1;
use serde::{Deserialize, Serialize};

// ─── 定数 ────────────────────────────────────────────────────────────────────

/// アンボンディング期間の最低エポック数（ノードの config より大きい方が有効）
pub const MIN_UNBONDING_EPOCHS: u64 = 100;
/// メモフィールドの最大バイト数
pub const MAX_STAKE_TX_MEMO_SIZE: usize = 256;
/// コミッション率の最大値 (BPS, 100% = 10000)
pub const MAX_COMMISSION_BPS: u32 = 5_000; // 50%

// ─── ValidatorStakeTx ────────────────────────────────────────────────────────

/// L1 ネイティブのバリデーターステーキングトランザクション。
///
/// このトランザクションを含む L1 ブロックが finalized されると、
/// `misaka-consensus::StakingRegistry` が状態を更新する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStakeTx {
    /// トランザクション種別
    pub kind: StakeTxKind,
    /// バリデーター ID (20 bytes, ML-DSA-65 公開鍵の SHA3-256 先頭 20 bytes)
    pub validator_id: [u8; 32],
    /// ステーク資金元の UTXO 参照群（残高の on-chain 証明）
    /// StakeMore: 追加ステーク分の UTXO
    /// Register: 初期ステーク分の UTXO
    /// BeginExit: 空でよい（アンボンディング開始のみ）
    pub stake_inputs: Vec<StakeInput>,
    /// ガス手数料
    pub fee: u64,
    /// nonce: replay 防止（validator_id + nonce でユニーク）
    pub nonce: u64,
    /// 任意のメモ（バリデーター自己紹介等）
    pub memo: Option<String>,
    /// 種別固有の追加パラメータ
    pub params: StakeTxParams,
    /// 送信者の ML-DSA-65 署名 (signing_payload に対する)
    pub signature: Vec<u8>,
}

/// ステーキング UTXO 参照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInput {
    /// UTXO の tx_hash
    pub tx_hash: [u8; 32],
    /// UTXO の output index
    pub output_index: u32,
    /// このインプットが提供するステーク額（base units）
    pub amount: u64,
}

/// トランザクション種別
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeTxKind {
    /// 新規バリデーター登録 + 初期ステーク
    Register,
    /// 既存バリデーターへの追加ステーク（reward_weight 向上）
    StakeMore,
    /// アンボンディング開始（unbonding_epochs 後に unlock 可能）
    BeginExit,
}

impl StakeTxKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::StakeMore => "stake_more",
            Self::BeginExit => "begin_exit",
        }
    }
}

/// 種別固有のパラメータ
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StakeTxParams {
    /// Register 用パラメータ
    Register(RegisterParams),
    /// StakeMore 用パラメータ
    StakeMore(StakeMoreParams),
    /// BeginExit 用パラメータ（追加パラメータなし）
    BeginExit,
}

/// 新規登録パラメータ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterParams {
    /// バリデーターの ML-DSA-65 コンセンサス公開鍵 (1952 bytes)
    pub consensus_pubkey: Vec<u8>,
    /// 報酬受け取りアドレス（20 bytes）
    pub reward_address: [u8; 32],
    /// コミッション率 (BPS, 0-5000)
    pub commission_bps: u32,
    /// P2P エンドポイント（例: "49.212.136.189:30333"）
    pub p2p_endpoint: Option<String>,
    /// バリデーターの自己紹介（任意）
    pub moniker: Option<String>,
}

/// 追加ステーク パラメータ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeMoreParams {
    /// 追加するステーク額の合計（stake_inputs の sum と一致すること）
    pub additional_amount: u64,
}

impl ValidatorStakeTx {
    // ─── signing_payload ───────────────────────────────────────────────────

    /// ML-DSA-65 署名対象のバイト列。
    ///
    /// domain tag を先頭に付けて他の tx との混同を防ぐ。
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // domain tag
        buf.extend_from_slice(b"MISAKA:validator_stake_tx:v1:");
        buf.extend_from_slice(self.kind.as_str().as_bytes());
        buf.push(b':');
        // validator_id
        buf.extend_from_slice(&self.validator_id);
        // nonce
        mcs1::write_u64(&mut buf, self.nonce);
        // fee
        mcs1::write_u64(&mut buf, self.fee);
        // stake_inputs (deterministic order)
        mcs1::write_u32(&mut buf, self.stake_inputs.len() as u32);
        for inp in &self.stake_inputs {
            mcs1::write_fixed(&mut buf, &inp.tx_hash);
            mcs1::write_u32(&mut buf, inp.output_index);
            mcs1::write_u64(&mut buf, inp.amount);
        }
        // kind-specific params
        match &self.params {
            StakeTxParams::Register(p) => {
                mcs1::write_bytes(&mut buf, &p.consensus_pubkey);
                mcs1::write_fixed(&mut buf, &p.reward_address);
                mcs1::write_u32(&mut buf, p.commission_bps);
            }
            StakeTxParams::StakeMore(p) => {
                mcs1::write_u64(&mut buf, p.additional_amount);
            }
            StakeTxParams::BeginExit => {}
        }
        buf
    }

    // ─── validate_structure ────────────────────────────────────────────────

    /// Crypto 検証を含まない構造バリデーション。
    ///
    /// `cargo test` で呼べるように crypto クレートには依存しない。
    pub fn validate_structure(&self) -> Result<(), StakeTxError> {
        // kind と params の整合性チェック
        match (&self.kind, &self.params) {
            (StakeTxKind::Register, StakeTxParams::Register(_)) => {}
            (StakeTxKind::StakeMore, StakeTxParams::StakeMore(_)) => {}
            (StakeTxKind::BeginExit, StakeTxParams::BeginExit) => {}
            _ => return Err(StakeTxError::KindParamsMismatch),
        }

        // fee ゼロ禁止
        if self.fee == 0 {
            return Err(StakeTxError::ZeroFee);
        }

        // memo サイズ制限
        if let Some(ref m) = self.memo {
            if m.len() > MAX_STAKE_TX_MEMO_SIZE {
                return Err(StakeTxError::MemoTooLarge {
                    actual: m.len(),
                    limit: MAX_STAKE_TX_MEMO_SIZE,
                });
            }
        }

        // 署名バイト非空チェック
        if self.signature.is_empty() {
            return Err(StakeTxError::MissingSignature);
        }

        // stake_inputs の基本チェック
        let mut seen = std::collections::HashSet::new();
        let mut total_input: u64 = 0;
        for inp in &self.stake_inputs {
            let key = (inp.tx_hash, inp.output_index);
            if !seen.insert(key) {
                return Err(StakeTxError::DuplicateStakeInput {
                    tx_hash: inp.tx_hash,
                    output_index: inp.output_index,
                });
            }
            if inp.amount == 0 {
                return Err(StakeTxError::ZeroAmountInput);
            }
            total_input = total_input
                .checked_add(inp.amount)
                .ok_or(StakeTxError::AmountOverflow)?;
        }

        // kind 別の追加チェック
        match &self.params {
            StakeTxParams::Register(p) => {
                // consensus_pubkey は ML-DSA-65 (1952 bytes)
                if p.consensus_pubkey.len() != 1952 {
                    return Err(StakeTxError::InvalidPubkeyLength {
                        actual: p.consensus_pubkey.len(),
                        expected: 1952,
                    });
                }
                // commission 範囲チェック
                if p.commission_bps > MAX_COMMISSION_BPS {
                    return Err(StakeTxError::CommissionTooHigh {
                        actual: p.commission_bps,
                        max: MAX_COMMISSION_BPS,
                    });
                }
                // Register は stake_inputs が必須
                if self.stake_inputs.is_empty() {
                    return Err(StakeTxError::NoStakeInputsForRegister);
                }
                // fee のオーバーフローチェック（total_input - fee が有効であること）
                if total_input < self.fee {
                    return Err(StakeTxError::InsufficientInputsForFee {
                        total_input,
                        fee: self.fee,
                    });
                }
            }
            StakeTxParams::StakeMore(p) => {
                // additional_amount が stake_inputs の合計と一致する必要がある
                if p.additional_amount == 0 {
                    return Err(StakeTxError::ZeroAdditionalStake);
                }
                if self.stake_inputs.is_empty() {
                    return Err(StakeTxError::NoStakeInputsForStakeMore);
                }
                // total_input >= additional_amount + fee (fee を含む)
                let required = p
                    .additional_amount
                    .checked_add(self.fee)
                    .ok_or(StakeTxError::AmountOverflow)?;
                if total_input < required {
                    return Err(StakeTxError::InsufficientInputsForFee {
                        total_input,
                        fee: required,
                    });
                }
            }
            StakeTxParams::BeginExit => {
                // BeginExit は stake_inputs 不要
                if !self.stake_inputs.is_empty() {
                    return Err(StakeTxError::UnexpectedStakeInputs);
                }
            }
        }

        Ok(())
    }

    /// stake_inputs の合計ステーク額（fee を含む raw 合計）
    pub fn total_input_amount(&self) -> u64 {
        self.stake_inputs.iter().map(|i| i.amount).sum()
    }

    /// 実際に locked されるステーク額（= total_input - fee）
    /// Register / StakeMore で使用する。BeginExit は 0 を返す。
    pub fn net_stake_amount(&self) -> u64 {
        match &self.params {
            StakeTxParams::StakeMore(p) => p.additional_amount,
            StakeTxParams::Register(_) => self.total_input_amount().saturating_sub(self.fee),
            StakeTxParams::BeginExit => 0,
        }
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StakeTxError {
    #[error("tx kind and params mismatch")]
    KindParamsMismatch,

    #[error("fee must be > 0")]
    ZeroFee,

    #[error("missing ML-DSA-65 signature")]
    MissingSignature,

    #[error("memo too large: {actual} bytes (limit {limit})")]
    MemoTooLarge { actual: usize, limit: usize },

    #[error(
        "duplicate stake input: tx_hash={} output_index={output_index}",
        hex::encode(tx_hash)
    )]
    DuplicateStakeInput {
        tx_hash: [u8; 32],
        output_index: u32,
    },

    #[error("stake input amount is zero")]
    ZeroAmountInput,

    #[error("amount overflow (u64)")]
    AmountOverflow,

    #[error("invalid consensus pubkey length: {actual} bytes (expected {expected})")]
    InvalidPubkeyLength { actual: usize, expected: usize },

    #[error("commission too high: {actual} bps (max {max})")]
    CommissionTooHigh { actual: u32, max: u32 },

    #[error("register tx requires at least one stake input")]
    NoStakeInputsForRegister,

    #[error("stake_more tx requires at least one stake input")]
    NoStakeInputsForStakeMore,

    #[error("begin_exit tx must not have stake inputs")]
    UnexpectedStakeInputs,

    #[error("total inputs {total_input} < required {fee}")]
    InsufficientInputsForFee { total_input: u64, fee: u64 },

    #[error("additional_amount must be > 0")]
    ZeroAdditionalStake,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_input(amount: u64) -> StakeInput {
        StakeInput {
            tx_hash: [0xABu8; 32],
            output_index: 0,
            amount,
        }
    }

    fn make_register(stake_amount: u64) -> ValidatorStakeTx {
        ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id: [1u8; 20],
            stake_inputs: vec![make_input(stake_amount + 1_000)], // +fee
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: vec![0u8; 1952],
                reward_address: [2u8; 20],
                commission_bps: 500,
                p2p_endpoint: Some("49.212.136.189:30333".into()),
                moniker: Some("MISAKA-Node-1".into()),
            }),
            signature: vec![0u8; 32],
        }
    }

    fn make_stake_more(additional: u64) -> ValidatorStakeTx {
        ValidatorStakeTx {
            kind: StakeTxKind::StakeMore,
            validator_id: [1u8; 20],
            stake_inputs: vec![make_input(additional + 1_000)],
            fee: 1_000,
            nonce: 1,
            memo: None,
            params: StakeTxParams::StakeMore(StakeMoreParams {
                additional_amount: additional,
            }),
            signature: vec![0u8; 32],
        }
    }

    fn make_begin_exit() -> ValidatorStakeTx {
        ValidatorStakeTx {
            kind: StakeTxKind::BeginExit,
            validator_id: [1u8; 20],
            stake_inputs: vec![],
            fee: 1_000,
            nonce: 2,
            memo: None,
            params: StakeTxParams::BeginExit,
            signature: vec![0u8; 32],
        }
    }

    #[test]
    fn register_structure_valid() {
        make_register(10_000_000)
            .validate_structure()
            .expect("valid register");
    }

    #[test]
    fn stake_more_structure_valid() {
        make_stake_more(5_000_000)
            .validate_structure()
            .expect("valid stake_more");
    }

    #[test]
    fn begin_exit_structure_valid() {
        make_begin_exit()
            .validate_structure()
            .expect("valid begin_exit");
    }

    #[test]
    fn register_zero_fee_rejected() {
        let mut tx = make_register(10_000_000);
        tx.fee = 0;
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::ZeroFee)
        ));
    }

    #[test]
    fn register_missing_signature_rejected() {
        let mut tx = make_register(10_000_000);
        tx.signature.clear();
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::MissingSignature)
        ));
    }

    #[test]
    fn register_wrong_pubkey_length_rejected() {
        let mut tx = make_register(10_000_000);
        if let StakeTxParams::Register(ref mut p) = tx.params {
            p.consensus_pubkey = vec![0u8; 100]; // wrong length
        }
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::InvalidPubkeyLength { .. })
        ));
    }

    #[test]
    fn register_commission_too_high_rejected() {
        let mut tx = make_register(10_000_000);
        if let StakeTxParams::Register(ref mut p) = tx.params {
            p.commission_bps = 9_999;
        }
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::CommissionTooHigh { .. })
        ));
    }

    #[test]
    fn duplicate_stake_inputs_rejected() {
        let mut tx = make_register(10_000_000);
        tx.stake_inputs.push(tx.stake_inputs[0].clone()); // duplicate
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::DuplicateStakeInput { .. })
        ));
    }

    #[test]
    fn begin_exit_with_inputs_rejected() {
        let mut tx = make_begin_exit();
        tx.stake_inputs.push(make_input(1_000));
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::UnexpectedStakeInputs)
        ));
    }

    #[test]
    fn stake_more_insufficient_inputs_rejected() {
        let mut tx = make_stake_more(5_000_000);
        // inputs only cover additional, not fee
        tx.stake_inputs = vec![make_input(5_000_000)];
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::InsufficientInputsForFee { .. })
        ));
    }

    #[test]
    fn kind_params_mismatch_rejected() {
        // Register kind + StakeMore params
        let mut tx = make_register(10_000_000);
        tx.kind = StakeTxKind::StakeMore;
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::KindParamsMismatch)
        ));
    }

    #[test]
    fn net_stake_amount_correct() {
        let tx = make_register(10_000_000);
        // total_input = 10_000_000 + 1_000, fee = 1_000 → net = 10_000_000
        assert_eq!(tx.net_stake_amount(), 10_000_000);

        let tx2 = make_stake_more(5_000_000);
        assert_eq!(tx2.net_stake_amount(), 5_000_000);

        let tx3 = make_begin_exit();
        assert_eq!(tx3.net_stake_amount(), 0);
    }

    #[test]
    fn signing_payload_deterministic() {
        let tx = make_register(10_000_000);
        let p1 = tx.signing_payload();
        let p2 = tx.signing_payload();
        assert_eq!(p1, p2);
    }

    #[test]
    fn signing_payload_differs_by_kind() {
        let r = make_register(10_000_000);
        let s = make_stake_more(5_000_000);
        assert_ne!(r.signing_payload(), s.signing_payload());
    }

    #[test]
    fn memo_too_large_rejected() {
        let mut tx = make_register(10_000_000);
        tx.memo = Some("x".repeat(MAX_STAKE_TX_MEMO_SIZE + 1));
        assert!(matches!(
            tx.validate_structure(),
            Err(StakeTxError::MemoTooLarge { .. })
        ));
    }
}
