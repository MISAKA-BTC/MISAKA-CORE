//! Shielded Block Hook — misaka-node 実装
//!
//! `misaka-dag::ShieldedBlockHook` の具体実装。
//! DAG block が atomic commit された後に `ShieldedState` を更新する。
//!
//! # P0 → P1 移行計画
//!
//! P0: DAG WriteBatch commit 後に hook でインメモリ更新。
//!     失敗時は warn ログのみ（再起動で DB から復元）。
//!
//! P1: `StoreWriteBatch` に shielded フィールドを追加し、
//!     DAG の RocksDB WriteBatch と同一バッチで atomic commit。

use misaka_dag::{ShieldedBlockHook, ShieldedTxPayload};
use misaka_shielded::{
    SharedShieldedState, ShieldDepositTx, ShieldWithdrawTx, ShieldedTransferTx,
    ShieldedConfig, ShieldedState,
};
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{error, info, warn};

// ─── NodeShieldedHook ─────────────────────────────────────────────────────────

/// `ShieldedBlockHook` の実装。
#[derive(Debug)]
pub struct NodeShieldedHook {
    shielded: SharedShieldedState,
    snapshot_path: String,
}

impl NodeShieldedHook {
    pub fn new(shielded: SharedShieldedState, data_dir: &str) -> Self {
        let snapshot_path = format!("{}/shielded_state.json", data_dir);
        Self { shielded, snapshot_path }
    }
}

impl ShieldedBlockHook for NodeShieldedHook {
    fn on_block_committed(
        &self,
        block_height: u64,
        block_hash: &[u8; 32],
        shielded_txs: &[ShieldedTxPayload],
    ) {
        if shielded_txs.is_empty() {
            self.shielded.write().on_block_finalized(block_height);
            return;
        }

        let mut state = self.shielded.write();

        for payload in shielded_txs {
            let tx_hash = *payload.tx_hash();

            let result = match payload {
                ShieldedTxPayload::Deposit { serialized, .. } => {
                    match serde_json::from_slice::<ShieldDepositTx>(serialized) {
                        Ok(tx) => state.apply_deposit(&tx, tx_hash, block_height).map(|_| ()),
                        Err(e) => {
                            error!("ShieldedHook: deposit deserialize failed tx={}: {}", hex::encode(tx_hash), e);
                            continue;
                        }
                    }
                }
                ShieldedTxPayload::Transfer { serialized, .. } => {
                    match serde_json::from_slice::<ShieldedTransferTx>(serialized) {
                        Ok(tx) => state.apply_shielded_transfer(&tx, tx_hash, block_height).map(|_| ()),
                        Err(e) => {
                            error!("ShieldedHook: transfer deserialize failed tx={}: {}", hex::encode(tx_hash), e);
                            continue;
                        }
                    }
                }
                ShieldedTxPayload::Withdraw { serialized, .. } => {
                    match serde_json::from_slice::<ShieldWithdrawTx>(serialized) {
                        Ok(tx) => state.apply_withdraw(&tx, tx_hash, block_height).map(|_| ()),
                        Err(e) => {
                            error!("ShieldedHook: withdraw deserialize failed tx={}: {}", hex::encode(tx_hash), e);
                            continue;
                        }
                    }
                }
            };

            match result {
                Ok(()) => tracing::debug!(
                    "ShieldedHook: applied tx={} block={}", hex::encode(tx_hash), block_height
                ),
                Err(e) => warn!(
                    "ShieldedHook: apply failed tx={} block={}: {} — restart to recover",
                    hex::encode(tx_hash), block_height, e
                ),
            }
        }

        state.on_block_finalized(block_height);

        // A-2: Persist shielded state snapshot after every block with shielded TXs
        if let Err(e) = state.save_snapshot(&self.snapshot_path) {
            warn!("ShieldedHook: failed to save snapshot: {} — state will recover from DAG on restart", e);
        }
    }

    fn on_block_reverted(
        &self,
        block_height: u64,
        block_hash: &[u8; 32],
        shielded_txs: &[ShieldedTxPayload],
    ) {
        if shielded_txs.is_empty() {
            return;
        }
        let mut state = self.shielded.write();
        let hash_hex = hex::encode(block_hash);

        // Undo nullifier confirmations for this block's shielded TXs
        for payload in shielded_txs {
            match payload {
                ShieldedTxPayload::Deposit { tx_hash, serialized } => {
                    if let Ok(tx) = serde_json::from_slice::<ShieldDepositTx>(serialized) {
                        // Remove commitment (revert append) — commitment tree is append-only,
                        // so we truncate by restoring the previous snapshot.
                        // For now, log the revert and rely on snapshot restoration.
                        info!(
                            "ShieldedHook: REVERT deposit tx={} block={} height={}",
                            hex::encode(&tx_hash[..8]), &hash_hex[..8], block_height
                        );
                    }
                }
                ShieldedTxPayload::Transfer { tx_hash, serialized } => {
                    if let Ok(tx) = serde_json::from_slice::<ShieldedTransferTx>(serialized) {
                        // Undo nullifier confirmations
                        for nf in &tx.nullifiers {
                            state.nullifier_set.remove_confirmed(nf);
                        }
                        info!(
                            "ShieldedHook: REVERT transfer tx={} nullifiers={} block={}",
                            hex::encode(&tx_hash[..8]), tx.nullifiers.len(), &hash_hex[..8]
                        );
                    }
                }
                ShieldedTxPayload::Withdraw { tx_hash, serialized } => {
                    if let Ok(tx) = serde_json::from_slice::<ShieldWithdrawTx>(serialized) {
                        for nf in &tx.nullifiers {
                            state.nullifier_set.remove_confirmed(nf);
                        }
                        info!(
                            "ShieldedHook: REVERT withdraw tx={} block={}",
                            hex::encode(&tx_hash[..8]), &hash_hex[..8]
                        );
                    }
                }
            }
        }

        // Save snapshot after revert
        if let Err(e) = state.save_snapshot(&self.snapshot_path) {
            warn!("ShieldedHook: failed to save snapshot after revert: {}", e);
        }
    }

    fn on_tx_evicted(&self, tx_hash: &[u8; 32]) {
        self.shielded.write().release_nullifier_reservation(tx_hash);
    }
}

// ─── ShieldedBootstrap ────────────────────────────────────────────────────────

/// ノード起動時の shielded state 初期化。
pub struct ShieldedBootstrap;

impl ShieldedBootstrap {
    /// 設定から shielded state を初期化する。
    /// disabled の場合は None を返す（transparent-only モード）。
    pub fn from_node_config(
        enabled: bool,
        testnet_mode: bool,
        max_anchor_age: u64,
        min_shielded_fee: u64,
    ) -> Option<SharedShieldedState> {
        if !enabled {
            info!("ShieldedBootstrap: DISABLED (transparent-only mode)");
            return None;
        }
        let config = ShieldedConfig {
            enabled: true,
            mempool_proof_verify: false,
            max_anchor_age_blocks: max_anchor_age,
            min_shielded_fee,
            testnet_mode,
        };
        let mut state = ShieldedState::new(config);
        if testnet_mode {
            state.register_stub_backend();
            info!("ShieldedBootstrap: stub backend registered (testnet only)");
        } else {
            // C-1: Register SHA3 Merkle proof backend for production
            state.register_sha3_backend();
            info!("ShieldedBootstrap: SHA3 Merkle proof backend registered (production)");
        }
        info!(
            "ShieldedBootstrap: ENABLED (testnet={}, anchor_age={}, min_fee={})",
            testnet_mode, max_anchor_age, min_shielded_fee
        );
        Some(Arc::new(RwLock::new(state)))
    }

    /// Load shielded state snapshot from disk if available.
    pub fn load_snapshot(shared: &SharedShieldedState, data_dir: &str) {
        let path = format!("{}/shielded_state.json", data_dir);
        if std::path::Path::new(&path).exists() {
            let mut state = shared.write();
            match state.load_snapshot(&path) {
                Ok(()) => info!("ShieldedBootstrap: restored snapshot from {}", path),
                Err(e) => warn!("ShieldedBootstrap: failed to load snapshot: {} — starting fresh", e),
            }
        } else {
            info!("ShieldedBootstrap: no snapshot found at {} — starting fresh", path);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use misaka_dag::ShieldedTxPayload;
    use misaka_shielded::{
        NoteCommitment, ShieldDepositTx, EncryptedNote, Nullifier, MIN_SHIELDED_FEE,
    };

    fn enabled_state() -> SharedShieldedState {
        ShieldedBootstrap::from_node_config(true, true, 100, MIN_SHIELDED_FEE).unwrap()
    }

    fn deposit_payload() -> ShieldedTxPayload {
        use misaka_pqc::pq_sign::MlDsaKeypair;
        use sha3::{Digest, Sha3_256};

        // ML-DSA-65 キーペア生成 → 有効な署名付き deposit
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
            amount: 1_000_000,
            asset_id: 0,
            fee: MIN_SHIELDED_FEE,
            output_commitment: NoteCommitment([0xAAu8; 32]),
            encrypted_note: EncryptedNote {
                epk: [0u8; 32],
                ciphertext: vec![0u8; 64],
                tag: [0u8; 16],
                view_tag: 0,
            },
            signature_bytes: vec![],
            sender_pubkey: pubkey_bytes,
        };
        let payload = tx.signing_payload();
        let sig = misaka_pqc::ml_dsa_sign(&kp.secret_key, &payload).expect("sign ok");
        tx.signature_bytes = sig.as_bytes().to_vec();

        ShieldedTxPayload::Deposit {
            tx_hash: [0xBBu8; 32],
            serialized: serde_json::to_vec(&tx).unwrap(),
        }
    }

    #[test]
    fn hook_applies_deposit() {
        let shared = enabled_state();
        let hook = NodeShieldedHook::new(shared.clone());
        assert_eq!(shared.read().commitment_count(), 0);
        hook.on_block_committed(1, &[0u8; 32], &[deposit_payload()]);
        assert_eq!(shared.read().commitment_count(), 1);
    }

    #[test]
    fn hook_records_finalization_on_empty_block() {
        let shared = enabled_state();
        let hook = NodeShieldedHook::new(shared.clone());
        let root_before = shared.read().current_root();
        hook.on_block_committed(5, &[0u8; 32], &[]);
        assert_eq!(shared.read().current_root(), root_before);
    }

    #[test]
    fn hook_releases_reservation_on_evict() {
        let shared = enabled_state();
        let hook = NodeShieldedHook::new(shared.clone());
        let nf = Nullifier([0x42u8; 32]);
        let tx = [0x99u8; 32];
        shared.write().reserve_nullifiers(&[nf], tx).unwrap();
        assert!(shared.read().nullifier_set.is_reserved(&nf));
        hook.on_tx_evicted(&tx);
        assert!(!shared.read().nullifier_set.is_reserved(&nf));
    }

    #[test]
    fn bootstrap_disabled_returns_none() {
        assert!(ShieldedBootstrap::from_node_config(false, false, 100, 1000).is_none());
    }
}
