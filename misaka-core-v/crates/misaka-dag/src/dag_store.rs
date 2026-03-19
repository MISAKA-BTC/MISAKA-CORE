//! # RocksDB-Backed DAG Store (MISAKA-CORE v2)
//!
//! ## Column Families (v1 との互換)
//!
//! v1 の `block_store.rs` の CF 構造を拡張し、DAG 固有のデータを追加する。
//!
//! | CF Name          | Key                     | Value                 | Purpose                    |
//! |------------------|-------------------------|-----------------------|----------------------------|
//! | `dag_headers`    | block_hash (32)         | DagBlockHeader (JSON) | DAG ブロックヘッダ         |
//! | `dag_ghostdag`   | block_hash (32)         | GhostDagData (JSON)   | GhostDAG メタデータ        |
//! | `dag_children`   | parent_hash (32)        | Vec<Hash> (JSON)      | 親→子逆参照               |
//! | `dag_block_txs`  | block_hash (32)         | Vec<UtxoTx> (bincode) | ブロック内 TX              |
//! | `dag_relations`  | "tips"                  | Vec<Hash> (JSON)      | 現在の DAG Tips            |
//! | `dag_tx_status`  | tx_hash (32)            | TxApplyStatus (JSON)  | TX 適用結果                |
//!
//! v1 の CF (`utxos`, `nullifiers`, `spending_keys`) はそのまま維持。
//!
//! ## Tips 管理
//!
//! DAG の Tips (子を持たないブロック群) は新ブロック追加時に更新される。
//! - 新ブロック追加: 新ブロックを Tips に追加 + 新ブロックの parents を Tips から除去
//! - これにより Tips は常に最新の「葉ノード」集合を反映する。

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use tracing::{info, debug, warn};

use crate::dag_block::{Hash, DagBlockHeader, GhostDagData, ZERO_HASH};
use crate::ghostdag::DagStore;
use crate::dag_state_manager::TxApplyStatus;

// ═══════════════════════════════════════════════════════════════
//  Thread-Safe In-Memory DAG Store (プロトタイプ / テストネット)
// ═══════════════════════════════════════════════════════════════

/// スレッドセーフなインメモリ DAG ストア。
///
/// テストネット Phase 1 では RocksDB の代わりにこれを使用し、
/// Phase 2 で RocksDB バックエンドに切り替える。
///
/// 全操作は `RwLock` で保護される。
pub struct ThreadSafeDagStore {
    inner: RwLock<DagStoreInner>,
}

struct DagStoreInner {
    headers: HashMap<Hash, DagBlockHeader>,
    ghostdag: HashMap<Hash, GhostDagData>,
    children: HashMap<Hash, Vec<Hash>>,
    tips: HashSet<Hash>,
    block_txs: HashMap<Hash, Vec<misaka_types::utxo::UtxoTransaction>>,
    tx_status: HashMap<[u8; 32], TxApplyStatus>,
    /// Genesis ハッシュ。
    genesis_hash: Hash,
    /// 全ブロック数。
    block_count: u64,
}

impl ThreadSafeDagStore {
    /// 新しい ThreadSafeDagStore を Genesis ブロックで初期化する。
    pub fn new(genesis_hash: Hash, genesis_header: DagBlockHeader) -> Self {
        let mut inner = DagStoreInner {
            headers: HashMap::new(),
            ghostdag: HashMap::new(),
            children: HashMap::new(),
            tips: HashSet::new(),
            block_txs: HashMap::new(),
            tx_status: HashMap::new(),
            genesis_hash,
            block_count: 0,
        };

        // Genesis を挿入
        inner.headers.insert(genesis_hash, genesis_header);
        inner.ghostdag.insert(genesis_hash, GhostDagData::default());
        inner.tips.insert(genesis_hash);
        inner.block_count = 1;

        Self { inner: RwLock::new(inner) }
    }

    /// 新しいブロックを DAG に追加する。
    ///
    /// # 処理
    ///
    /// 1. ヘッダを保存
    /// 2. 親→子逆参照を更新
    /// 3. Tips を更新 (parents を除去 + 新ブロックを追加)
    /// 4. TX を保存 (オプション)
    ///
    /// # 返り値
    ///
    /// `Ok(())` — 追加成功
    /// `Err(String)` — 親が存在しない場合
    pub fn insert_block(
        &self,
        hash: Hash,
        header: DagBlockHeader,
        txs: Vec<misaka_types::utxo::UtxoTransaction>,
    ) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());

        // 親の存在チェック
        for parent in &header.parents {
            if *parent != ZERO_HASH && !inner.headers.contains_key(parent) {
                return Err(format!(
                    "parent {} not found in DAG",
                    hex::encode(&parent[..8])
                ));
            }
        }

        // 親→子逆参照
        for parent in &header.parents {
            inner.children.entry(*parent).or_default().push(hash);
        }

        // Tips 更新: parents を Tips から除去
        for parent in &header.parents {
            inner.tips.remove(parent);
        }
        // 新ブロックを Tips に追加
        inner.tips.insert(hash);

        // 保存
        inner.headers.insert(hash, header);
        if !txs.is_empty() {
            inner.block_txs.insert(hash, txs);
        }
        inner.block_count += 1;

        debug!(
            "DAG: inserted block {} (total={}, tips={})",
            hex::encode(&hash[..4]),
            inner.block_count,
            inner.tips.len(),
        );

        Ok(())
    }

    /// GhostDagData を保存する。
    pub fn set_ghostdag(&self, hash: Hash, data: GhostDagData) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.ghostdag.insert(hash, data);
    }

    /// TX 適用結果を保存する。
    pub fn set_tx_status(&self, tx_hash: [u8; 32], status: TxApplyStatus) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.tx_status.insert(tx_hash, status);
    }

    /// ブロック内の TX を取得する。
    pub fn get_block_txs(&self, hash: &Hash) -> Vec<misaka_types::utxo::UtxoTransaction> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.block_txs.get(hash).cloned().unwrap_or_default()
    }

    /// 現在の Tips 数を取得する。
    pub fn tip_count(&self) -> usize {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.tips.len()
    }

    /// 全ブロック数を取得する。
    pub fn block_count(&self) -> u64 {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.block_count
    }

    /// DAG の最大 blue_score を取得する (論理高度)。
    pub fn max_blue_score(&self) -> u64 {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.ghostdag.values()
            .map(|d| d.blue_score)
            .max()
            .unwrap_or(0)
    }

    /// DagStore trait を使う関数に渡すための Snapshot を取得する。
    ///
    /// GhostDAG 計算には `&DagStore` が必要だが、`RwLock` の参照を
    /// そのまま渡せないため、スナップショットをコピーして渡す。
    pub fn snapshot(&self) -> DagStoreSnapshot {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        DagStoreSnapshot {
            headers: inner.headers.clone(),
            ghostdag: inner.ghostdag.clone(),
            children: inner.children.clone(),
            tips: inner.tips.clone(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  DagStore Snapshot (GhostDAG 計算用の immutable ビュー)
// ═══════════════════════════════════════════════════════════════

/// DAG ストアの読み取り専用スナップショット。
///
/// `GhostDagManager` の関数は `&dyn DagStore` を受け取るため、
/// `ThreadSafeDagStore` から一時的にコピーを作成して渡す。
pub struct DagStoreSnapshot {
    headers: HashMap<Hash, DagBlockHeader>,
    ghostdag: HashMap<Hash, GhostDagData>,
    children: HashMap<Hash, Vec<Hash>>,
    tips: HashSet<Hash>,
}

impl DagStore for DagStoreSnapshot {
    fn get_header(&self, hash: &Hash) -> Option<&DagBlockHeader> {
        self.headers.get(hash)
    }

    fn get_ghostdag_data(&self, hash: &Hash) -> Option<&GhostDagData> {
        self.ghostdag.get(hash)
    }

    fn set_ghostdag_data(&mut self, hash: Hash, data: GhostDagData) {
        self.ghostdag.insert(hash, data);
    }

    fn get_children(&self, hash: &Hash) -> Vec<Hash> {
        self.children.get(hash).cloned().unwrap_or_default()
    }

    fn all_hashes(&self) -> Vec<Hash> {
        self.headers.keys().copied().collect()
    }

    fn get_tips(&self) -> Vec<Hash> {
        self.tips.iter().copied().collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::DAG_VERSION;

    fn make_header(parents: Vec<Hash>) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION,
            parents,
            timestamp_ms: 1700000000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        }
    }

    #[test]
    fn test_tips_tracking() {
        let genesis = [0x00; 32];
        let store = ThreadSafeDagStore::new(genesis, make_header(vec![]));
        assert_eq!(store.tip_count(), 1); // genesis is the only tip

        // Add block A (parent: genesis)
        let a_hash = [0x0A; 32];
        store.insert_block(a_hash, make_header(vec![genesis]), vec![]).unwrap();
        assert_eq!(store.tip_count(), 1); // genesis removed, A is tip

        // Add block B (parent: genesis) — parallel to A
        let b_hash = [0x0B; 32];
        // genesis was already removed from tips by A, but B still references it.
        // Tips: { A, B }
        store.insert_block(b_hash, make_header(vec![genesis]), vec![]).unwrap();
        assert_eq!(store.tip_count(), 2);

        // Add block C (parents: A, B) — merge
        let c_hash = [0x0C; 32];
        store.insert_block(c_hash, make_header(vec![a_hash, b_hash]), vec![]).unwrap();
        assert_eq!(store.tip_count(), 1); // only C is tip
    }

    #[test]
    fn test_missing_parent_rejected() {
        let genesis = [0x00; 32];
        let store = ThreadSafeDagStore::new(genesis, make_header(vec![]));

        let unknown_parent = [0xFF; 32];
        let result = store.insert_block(
            [0x01; 32],
            make_header(vec![unknown_parent]),
            vec![],
        );
        assert!(result.is_err());
    }
}
