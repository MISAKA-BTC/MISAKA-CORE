//! # Legacy GhostDAG Module — DagStore Trait + InMemoryDagStore
//!
//! ## v4 変更
//!
//! `GhostDagManager` (BFS-based, O(N)) は完全に削除された。
//! 全コードパスは `GhostDagV2` (O(1) reachability-indexed) を使用する。
//!
//! このモジュールには以下のみが残る:
//! - `DagStore` trait — ブロックストレージ抽象化
//! - `InMemoryDagStore` — テスト・プロトタイプ用実装

use std::collections::HashMap;

use crate::dag_block::{DagBlockHeader, GhostDagData, Hash, ZERO_HASH};

// ═══════════════════════════════════════════════════════════════
//  DAG ストア Trait
// ═══════════════════════════════════════════════════════════════

/// DAG ブロックのストレージ抽象化。
///
/// GhostDAG エンジンはこの Trait を通じてブロックヘッダと GhostDagData に
/// アクセスする。実装は in-memory HashMap でも、RocksDB ベースでもよい。
pub trait DagStore {
    /// ブロックヘッダを取得。
    fn get_header(&self, hash: &Hash) -> Option<&DagBlockHeader>;

    /// GhostDAG メタデータを取得。
    fn get_ghostdag_data(&self, hash: &Hash) -> Option<&GhostDagData>;

    /// GhostDAG メタデータを保存。
    fn set_ghostdag_data(&mut self, hash: Hash, data: GhostDagData);

    /// あるブロックの全子ブロック (children) を取得。
    fn get_children(&self, hash: &Hash) -> Vec<Hash>;

    /// DAG に含まれる全ブロックハッシュを取得 (デバッグ・テスト用)。
    fn all_hashes(&self) -> Vec<Hash>;

    /// DAG の Tips (子を持たないブロック群) を取得。
    fn get_tips(&self) -> Vec<Hash>;
}

// ═══════════════════════════════════════════════════════════════
//  In-Memory DAG Store (テスト・プロトタイプ用)
// ═══════════════════════════════════════════════════════════════

/// テスト用のインメモリ DAG ストア。
pub struct InMemoryDagStore {
    headers: HashMap<Hash, DagBlockHeader>,
    ghostdag: HashMap<Hash, GhostDagData>,
    children: HashMap<Hash, Vec<Hash>>,
}

impl InMemoryDagStore {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            ghostdag: HashMap::new(),
            children: HashMap::new(),
        }
    }

    /// ブロックヘッダを追加し、親→子の逆参照を更新する。
    pub fn insert_header(&mut self, hash: Hash, header: DagBlockHeader) {
        for parent in &header.parents {
            self.children.entry(*parent).or_default().push(hash);
        }
        self.headers.insert(hash, header);
    }
}

impl DagStore for InMemoryDagStore {
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
        self.headers
            .keys()
            .filter(|h| self.children.get(*h).map(|c| c.is_empty()).unwrap_or(true))
            .copied()
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::DAG_VERSION;
    use crate::ghostdag_v2::{GhostDagV2, UniformStakeProvider, DEFAULT_K};
    use crate::reachability::ReachabilityStore;

    fn make_header(parents: Vec<Hash>, ts: u64) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION,
            parents,
            timestamp_ms: ts,
            tx_root: ZERO_HASH,
            proposer_id: [0; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        }
    }

    /// Diamond DAG test using GhostDagV2 (GhostDagManager removed in v4).
    #[test]
    fn test_simple_diamond_dag_v2() {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0x01; 32]);
        let genesis_hash = [0x01; 32];
        let engine = GhostDagV2::new(DEFAULT_K, genesis_hash);
        let stake = UniformStakeProvider;

        let g = genesis_hash;
        store.insert_header(g, make_header(vec![], 1000));
        store.set_ghostdag_data(
            g,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 1,
                blues_anticone_sizes: vec![],
            },
        );

        let a = [0x0A; 32];
        store.insert_header(a, make_header(vec![g], 2000));
        reach.add_child(g, a).unwrap();
        let a_data = engine
            .try_calculate(&a, &[g], &store, &reach, &stake)
            .unwrap();
        assert_eq!(a_data.selected_parent, g);
        assert_eq!(a_data.blue_score, 1);
        store.set_ghostdag_data(a, a_data);

        let b = [0x0B; 32];
        store.insert_header(b, make_header(vec![g], 2100));
        reach.add_child(g, b).unwrap();
        let b_data = engine
            .try_calculate(&b, &[g], &store, &reach, &stake)
            .unwrap();
        assert_eq!(b_data.blue_score, 1);
        store.set_ghostdag_data(b, b_data);

        let c = [0x0C; 32];
        store.insert_header(c, make_header(vec![a, b], 3000));
        let sp_c = engine.select_parent_public(&[a, b], &store);
        reach.add_child(sp_c, c).unwrap();
        let c_data = engine
            .try_calculate(&c, &[a, b], &store, &reach, &stake)
            .unwrap();
        assert!(c_data.blue_score >= 2);
        store.set_ghostdag_data(c, c_data);

        let order = engine.get_total_ordering(&store);
        assert!(order.contains(&g));
        assert!(order.contains(&a));
        assert!(order.contains(&b));
        assert!(order.contains(&c));
    }
}
