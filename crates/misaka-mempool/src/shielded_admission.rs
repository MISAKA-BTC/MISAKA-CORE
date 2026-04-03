//! Shielded Mempool Integration
//!
//! `UtxoMempool` への shielded tx admission は、既存の lattice ZKP proof/ZKP
//! パスとは独立した追加ロジックで行う。
//!
//! # Design
//!
//! shielded tx（ShieldDeposit / ShieldedTransfer / ShieldWithdraw）は
//! `UtxoTransaction` の envelope に包まれず、専用の admission 関数で処理する。
//! これにより既存の transparent/ring/ZKP フローを一切変更しない。
//!
//! # P0 vs P1
//!
//! P0: shielded tx は validate → ShieldedState.reserve_nullifiers のみ。
//!     DAG ordering への統合は P1 フェーズで実装する。
//!
//! P1: shielded tx を DAG vertex に包んで ordering に投入する。

use misaka_shielded::{
    Nullifier, SharedShieldedState, ShieldDepositTx, ShieldWithdrawTx, ShieldedError,
    ShieldedTransferTx,
};

// ─── ShieldedMempoolEntry ─────────────────────────────────────────────────────

/// Mempool 内の shielded tx エントリ。
#[derive(Debug, Clone)]
pub enum ShieldedMempoolTx {
    Deposit(ShieldDepositTx),
    Transfer(ShieldedTransferTx),
    Withdraw(ShieldWithdrawTx),
}

impl ShieldedMempoolTx {
    /// この tx が使用する nullifiers を返す
    pub fn nullifiers(&self) -> Vec<Nullifier> {
        match self {
            Self::Deposit(_) => vec![],
            Self::Transfer(t) => t.nullifiers.clone(),
            Self::Withdraw(t) => t.nullifiers.clone(),
        }
    }

    pub fn fee(&self) -> u64 {
        match self {
            Self::Deposit(t) => t.fee,
            Self::Transfer(t) => t.fee,
            Self::Withdraw(t) => t.fee,
        }
    }
}

// ─── ShieldedMempool ──────────────────────────────────────────────────────────

/// shielded tx 専用の mempool サブシステム。
/// `UtxoMempool` と並列に存在し、`ShieldedState` の reservation を使う。
pub struct ShieldedMempool {
    entries: std::collections::HashMap<[u8; 32], ShieldedMempoolEntry>,
    max_size: usize,
    shielded: SharedShieldedState,
}

struct ShieldedMempoolEntry {
    tx: ShieldedMempoolTx,
}

impl ShieldedMempool {
    pub fn new(max_size: usize, shielded: SharedShieldedState) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            max_size,
            shielded,
        }
    }

    /// shielded tx を mempool に admit する。
    ///
    /// # 手順
    /// 1. 構造バリデーション
    /// 2. 容量チェック
    /// 3. dedup
    /// 4. ShieldedState.validate_*
    /// 5. nullifier reservation
    /// 6. 挿入
    pub fn admit(
        &mut self,
        tx: ShieldedMempoolTx,
        _now_ms: u64,
    ) -> Result<[u8; 32], ShieldedMempoolError> {
        // ── 1. capacity ──
        if self.entries.len() >= self.max_size {
            return Err(ShieldedMempoolError::CapacityFull);
        }

        // ── 2. validate + tx_hash ──
        let tx_hash = compute_shielded_tx_hash(&tx);

        // ── 3. dedup ──
        if self.entries.contains_key(&tx_hash) {
            return Ok(tx_hash);
        }

        // ── 4. ShieldedState validate ──
        {
            let state = self.shielded.read();
            match &tx {
                ShieldedMempoolTx::Deposit(t) => {
                    state
                        .validate_deposit(t)
                        .map_err(ShieldedMempoolError::Shielded)?;
                }
                ShieldedMempoolTx::Transfer(t) => {
                    state
                        .validate_shielded_transfer(t)
                        .map_err(ShieldedMempoolError::Shielded)?;
                }
                ShieldedMempoolTx::Withdraw(t) => {
                    state
                        .validate_withdraw(t)
                        .map_err(ShieldedMempoolError::Shielded)?;
                }
            }
        }

        // ── 5. nullifier reservation ──
        let nullifiers = tx.nullifiers();
        if !nullifiers.is_empty() {
            self.shielded
                .write()
                .reserve_nullifiers(&nullifiers, tx_hash)
                .map_err(|e| ShieldedMempoolError::NullifierConflict(e.to_string()))?;
        }

        // ── 6. insert ──
        self.entries.insert(tx_hash, ShieldedMempoolEntry { tx });

        tracing::debug!(
            "ShieldedMempool::admit: tx={} nullifiers={}",
            hex::encode(tx_hash),
            nullifiers.len()
        );

        Ok(tx_hash)
    }

    /// tx が block に取り込まれた後 or evict 時に呼ぶ
    pub fn remove(&mut self, tx_hash: &[u8; 32]) {
        if self.entries.remove(tx_hash).is_some() {
            // nullifier reservation を解放
            self.shielded.write().release_nullifier_reservation(tx_hash);
            tracing::debug!("ShieldedMempool::remove: tx={}", hex::encode(tx_hash));
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// pending tx 一覧（block 生成時に使用）
    pub fn pending_txs(&self) -> Vec<&ShieldedMempoolTx> {
        let mut txs: Vec<_> = self.entries.values().map(|e| &e.tx).collect();
        // fee 降順にソート
        txs.sort_by(|a, b| b.fee().cmp(&a.fee()));
        txs
    }
}

// ─── Hash ─────────────────────────────────────────────────────────────────────

fn compute_shielded_tx_hash(tx: &ShieldedMempoolTx) -> [u8; 32] {
    let domain = match tx {
        ShieldedMempoolTx::Deposit(_) => "MISAKA shielded deposit tx id v1",
        ShieldedMempoolTx::Transfer(_) => "MISAKA shielded transfer tx id v1",
        ShieldedMempoolTx::Withdraw(_) => "MISAKA shielded withdraw tx id v1",
    };
    let bytes = match tx {
        ShieldedMempoolTx::Deposit(t) => serde_json::to_vec(t).unwrap_or_default(),
        ShieldedMempoolTx::Transfer(t) => serde_json::to_vec(t).unwrap_or_default(),
        ShieldedMempoolTx::Withdraw(t) => serde_json::to_vec(t).unwrap_or_default(),
    };
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ShieldedMempoolError {
    #[error("mempool is full")]
    CapacityFull,
    #[error("shielded validation failed: {0}")]
    Shielded(#[from] ShieldedError),
    #[error("nullifier conflict: {0}")]
    NullifierConflict(String),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use misaka_shielded::{
        new_shared_state, EncryptedNote, NoteCommitment, ShieldDepositTx, ShieldedConfig,
        MIN_SHIELDED_FEE,
    };

    fn make_deposit_tx() -> ShieldedMempoolTx {
        ShieldedMempoolTx::Deposit(ShieldDepositTx {
            from: [1u8; 32],
            amount: 1_000_000,
            asset_id: 0,
            fee: MIN_SHIELDED_FEE,
            output_commitment: NoteCommitment([2u8; 32]),
            encrypted_note: EncryptedNote {
                epk: [0u8; 32],
                ciphertext: vec![0u8; 32],
                tag: [0u8; 16],
                view_tag: 0,
            },
            signature_bytes: vec![0u8; 3309],
            sender_pubkey: vec![0u8; 1952],
        })
    }

    #[test]
    fn disabled_module_rejects() {
        let shared = new_shared_state(ShieldedConfig::disabled());
        let mut pool = ShieldedMempool::new(100, shared);
        let result = pool.admit(make_deposit_tx(), 0);
        // disabled → ShieldedError::ModuleDisabled
        assert!(matches!(result, Err(ShieldedMempoolError::Shielded(_))));
    }

    #[test]
    fn capacity_full_rejects() {
        let shared = new_shared_state(ShieldedConfig::disabled());
        let pool = ShieldedMempool::new(0, shared); // max_size = 0
        assert_eq!(pool.len(), 0);
        // Can't admit anything
        let mut pool = ShieldedMempool::new(0, new_shared_state(ShieldedConfig::disabled()));
        let result = pool.admit(make_deposit_tx(), 0);
        assert!(matches!(result, Err(ShieldedMempoolError::CapacityFull)));
    }
}
