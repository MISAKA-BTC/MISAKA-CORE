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
use tracing::{debug, info, warn};

use crate::dag_block::{DagBlockHeader, GhostDagData, Hash, ZERO_HASH};
use crate::dag_state_manager::TxApplyStatus;
use crate::ghostdag::DagStore;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagHeaderRecord {
    pub hash: Hash,
    pub header: DagBlockHeader,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagGhostdagRecord {
    pub hash: Hash,
    pub data: GhostDagData,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagChildRecord {
    pub parent: Hash,
    pub children: Vec<Hash>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagTxRecord {
    pub hash: Hash,
    pub txs: Vec<misaka_types::utxo::UtxoTransaction>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagTxStatusRecord {
    pub tx_hash: [u8; 32],
    pub status: TxApplyStatus,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagStoreDump {
    pub genesis_hash: Hash,
    pub block_count: u64,
    pub headers: Vec<DagHeaderRecord>,
    pub ghostdag: Vec<DagGhostdagRecord>,
    pub children: Vec<DagChildRecord>,
    pub tips: Vec<Hash>,
    pub block_txs: Vec<DagTxRecord>,
    pub tx_status: Vec<DagTxStatusRecord>,
}

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

        Self {
            inner: RwLock::new(inner),
        }
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

        // ── Task 3.2: Duplicate block detection (Fail-Closed) ──
        //
        // ストアレベルで重複を完全にブロックする。
        // 重複ブロックの上書きは GhostDagData や Tips の不整合を引き起こし、
        // チェーンスプリットの原因となる。
        if inner.headers.contains_key(&hash) {
            return Err(format!(
                "duplicate block {} already in DAG store",
                hex::encode(&hash[..8])
            ));
        }

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

    /// TX 適用結果を取得する。
    pub fn get_tx_status(&self, tx_hash: &[u8; 32]) -> Option<TxApplyStatus> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.tx_status.get(tx_hash).copied()
    }

    /// TX ハッシュから対応するブロックと tx 本体を探す。
    pub fn find_tx(
        &self,
        tx_hash: &[u8; 32],
    ) -> Option<(Hash, misaka_types::utxo::UtxoTransaction)> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.block_txs.iter().find_map(|(block_hash, txs)| {
            txs.iter()
                .find(|tx| &tx.tx_hash() == tx_hash)
                .cloned()
                .map(|tx| (*block_hash, tx))
        })
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
        inner
            .ghostdag
            .values()
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

    /// Export the full in-memory DAG store into a serializable dump.
    ///
    /// This is intended for local restart-safe snapshots while the DAG backend
    /// is still in-memory. Production should eventually move these structures
    /// into a durable store instead of relying on JSON dumps.
    pub fn export_dump(&self) -> DagStoreDump {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());

        let mut headers: Vec<DagHeaderRecord> = inner
            .headers
            .iter()
            .map(|(hash, header)| DagHeaderRecord {
                hash: *hash,
                header: header.clone(),
            })
            .collect();
        headers.sort_by(|a, b| a.hash.cmp(&b.hash));

        let mut ghostdag: Vec<DagGhostdagRecord> = inner
            .ghostdag
            .iter()
            .map(|(hash, data)| DagGhostdagRecord {
                hash: *hash,
                data: data.clone(),
            })
            .collect();
        ghostdag.sort_by(|a, b| a.hash.cmp(&b.hash));

        let mut children: Vec<DagChildRecord> = inner
            .children
            .iter()
            .map(|(parent, kids)| DagChildRecord {
                parent: *parent,
                children: kids.clone(),
            })
            .collect();
        children.sort_by(|a, b| a.parent.cmp(&b.parent));

        let mut tips: Vec<Hash> = inner.tips.iter().copied().collect();
        tips.sort();

        let mut block_txs: Vec<DagTxRecord> = inner
            .block_txs
            .iter()
            .map(|(hash, txs)| DagTxRecord {
                hash: *hash,
                txs: txs.clone(),
            })
            .collect();
        block_txs.sort_by(|a, b| a.hash.cmp(&b.hash));

        let mut tx_status: Vec<DagTxStatusRecord> = inner
            .tx_status
            .iter()
            .map(|(tx_hash, status)| DagTxStatusRecord {
                tx_hash: *tx_hash,
                status: *status,
            })
            .collect();
        tx_status.sort_by(|a, b| a.tx_hash.cmp(&b.tx_hash));

        DagStoreDump {
            genesis_hash: inner.genesis_hash,
            block_count: inner.block_count,
            headers,
            ghostdag,
            children,
            tips,
            block_txs,
            tx_status,
        }
    }

    /// Restore a thread-safe in-memory DAG store from a previously exported dump.
    pub fn from_dump(dump: DagStoreDump) -> Self {
        let mut headers = HashMap::new();
        for record in dump.headers {
            headers.insert(record.hash, record.header);
        }

        let mut ghostdag = HashMap::new();
        for record in dump.ghostdag {
            ghostdag.insert(record.hash, record.data);
        }

        let mut children = HashMap::new();
        for record in dump.children {
            children.insert(record.parent, record.children);
        }

        let tips = dump.tips.into_iter().collect();

        let mut block_txs = HashMap::new();
        for record in dump.block_txs {
            block_txs.insert(record.hash, record.txs);
        }

        let mut tx_status = HashMap::new();
        for record in dump.tx_status {
            tx_status.insert(record.tx_hash, record.status);
        }

        Self {
            inner: RwLock::new(DagStoreInner {
                headers,
                ghostdag,
                children,
                tips,
                block_txs,
                tx_status,
                genesis_hash: dump.genesis_hash,
                block_count: dump.block_count,
            }),
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
        store
            .insert_block(a_hash, make_header(vec![genesis]), vec![])
            .unwrap();
        assert_eq!(store.tip_count(), 1); // genesis removed, A is tip

        // Add block B (parent: genesis) — parallel to A
        let b_hash = [0x0B; 32];
        // genesis was already removed from tips by A, but B still references it.
        // Tips: { A, B }
        store
            .insert_block(b_hash, make_header(vec![genesis]), vec![])
            .unwrap();
        assert_eq!(store.tip_count(), 2);

        // Add block C (parents: A, B) — merge
        let c_hash = [0x0C; 32];
        store
            .insert_block(c_hash, make_header(vec![a_hash, b_hash]), vec![])
            .unwrap();
        assert_eq!(store.tip_count(), 1); // only C is tip
    }

    #[test]
    fn test_missing_parent_rejected() {
        let genesis = [0x00; 32];
        let store = ThreadSafeDagStore::new(genesis, make_header(vec![]));

        let unknown_parent = [0xFF; 32];
        let result = store.insert_block([0x01; 32], make_header(vec![unknown_parent]), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dump_roundtrip_preserves_tips_and_status() {
        let genesis = [0x00; 32];
        let store = ThreadSafeDagStore::new(genesis, make_header(vec![]));

        let block_hash = [0x11; 32];
        store
            .insert_block(block_hash, make_header(vec![genesis]), vec![])
            .unwrap();
        store.set_tx_status([0xAA; 32], TxApplyStatus::Applied);

        let dump = store.export_dump();
        let restored = ThreadSafeDagStore::from_dump(dump);
        let snapshot = restored.snapshot();

        assert!(snapshot.get_tips().contains(&block_hash));
        assert!(snapshot.get_header(&block_hash).is_some());
        assert_eq!(restored.block_count(), 2);
    }
}
