//! Shielded Block Hook
//!
//! `misaka-dag` が `misaka-shielded` に依存しないために、
//! 型消去された hook trait でブロック確定後の shielded state 更新を注入する。
//!
//! # Design
//!
//! DAG block が atomic commit された後、この trait の `on_block_committed`
//! を呼び出す。misaka-node 側でこの trait を実装し、`ShieldedState` への
//! ShieldedWriteSet 適用と nullifier reservation 解放を行う。
//!
//! # Atomic Guarantee
//!
//! DAG の RocksDB WriteBatch commit **後** に shielded state を更新するため、
//! DAG 側は既に永続化済み。shielded 側の write に失敗した場合はパニックせず、
//! ログ + metrics に記録し、次回起動時に DB からリカバリする設計にする。
//!
//! P0 フェーズ: hook は RPC layer でのバリデーションのみ呼ばれる。
//! P1 フェーズ: block_producer が hook を呼んで ShieldedState を更新する。

use std::sync::Arc;

/// ブロック確定後に呼ばれる shielded state update hook。
///
/// `Arc<dyn ShieldedBlockHook>` で保持し、block producer に注入する。
pub trait ShieldedBlockHook: Send + Sync + std::fmt::Debug {
    /// DAG block が atomic commit された直後に呼ばれる。
    fn on_block_committed(
        &self,
        block_height: u64,
        block_hash: &[u8; 32],
        shielded_txs: &[ShieldedTxPayload],
    );

    /// Reorg: ブロックが revert された際に呼ばれる。
    /// shielded state からこのブロックの変更を巻き戻す。
    fn on_block_reverted(
        &self,
        block_height: u64,
        block_hash: &[u8; 32],
        shielded_txs: &[ShieldedTxPayload],
    );

    /// mempool から evict された shielded tx の nullifier reservation を解放する。
    fn on_tx_evicted(&self, tx_hash: &[u8; 32]);
}

/// ブロック内の shielded tx ペイロード（型消去済み）
#[derive(Debug, Clone)]
pub enum ShieldedTxPayload {
    /// ShieldDeposit tx（シリアライズ済み JSON bytes）
    Deposit {
        tx_hash: [u8; 32],
        serialized: Vec<u8>,
    },
    /// ShieldedTransfer tx
    Transfer {
        tx_hash: [u8; 32],
        serialized: Vec<u8>,
    },
    /// ShieldWithdraw tx
    Withdraw {
        tx_hash: [u8; 32],
        serialized: Vec<u8>,
    },
}

impl ShieldedTxPayload {
    pub fn tx_hash(&self) -> &[u8; 32] {
        match self {
            Self::Deposit { tx_hash, .. } => tx_hash,
            Self::Transfer { tx_hash, .. } => tx_hash,
            Self::Withdraw { tx_hash, .. } => tx_hash,
        }
    }
}

/// No-op hook（shielded module が disabled のノードや unit test 用）
#[derive(Debug, Default, Clone)]
pub struct NoOpShieldedHook;

impl ShieldedBlockHook for NoOpShieldedHook {
    fn on_block_committed(
        &self,
        _block_height: u64,
        _block_hash: &[u8; 32],
        _shielded_txs: &[ShieldedTxPayload],
    ) {
        // nothing
    }

    fn on_block_reverted(
        &self,
        _block_height: u64,
        _block_hash: &[u8; 32],
        _shielded_txs: &[ShieldedTxPayload],
    ) {
        // nothing
    }

    fn on_tx_evicted(&self, _tx_hash: &[u8; 32]) {
        // nothing
    }
}

/// Arc 型エイリアス
pub type SharedShieldedHook = Arc<dyn ShieldedBlockHook>;

/// No-op hook の共有インスタンスを生成する
pub fn noop_hook() -> SharedShieldedHook {
    Arc::new(NoOpShieldedHook)
}
