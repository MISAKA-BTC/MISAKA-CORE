//! # DAG Block — Multi-parent Block Header for GhostDAG (MISAKA-CORE v2)
//!
//! ## 設計思想 (Design Philosophy)
//!
//! v1 の線形チェーン (`parent_hash: [u8; 32]`) を廃止し、複数の親ブロックを
//! 参照する DAG 構造に移行する。各ブロックは GhostDAG アルゴリズムにより
//! `blue_score` (累積 Blue work) を持ち、DAG 全体のトポロジカル順序を
//! 決定論的に算出する基盤となる。
//!
//! ## v1 BlockHeader との互換性
//!
//! | v1 フィールド       | v2 対応                                  |
//! |--------------------|------------------------------------------|
//! | `parent_hash`      | `parents: Vec<Hash>` (先頭が Selected Parent) |
//! | `height`           | `blue_score` (DAG 累積 Blue 深度)          |
//! | `state_root`       | **遅延評価** — ブロック生成時には未確定     |
//! | `proposer_index`   | 維持 (BFT Proposer or PoW miner ID)       |
//!
//! ## Kaspa/GhostDAG 参照
//!
//! 本設計は Kaspa の GhostDAG 実装 (PHANTOM GHOSTDAG paper, Yonatan Sompolinsky)
//! を基盤とし、MISAKA 固有の格子暗号ベース匿名トランザクション層(Lattice ZKP)と統合している。

use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════
//  型エイリアス (Type Aliases)
// ═══════════════════════════════════════════════════════════════

/// ブロックハッシュ — SHA3-256 (32 bytes)。
/// DAG 内の全ノードはこのハッシュで一意に識別される。
pub type Hash = [u8; 32];

/// ゼロハッシュ — Genesis ブロックの parent 参照用。
pub const ZERO_HASH: Hash = [0u8; 32];

// ═══════════════════════════════════════════════════════════════
//  GhostDAG メタデータ
// ═══════════════════════════════════════════════════════════════

/// GhostDAG アルゴリズムで各ブロックに付与されるメタデータ。
///
/// これらの値はブロック受信後に **ローカルで計算** され、ブロックヘッダ自体には
/// 含まれない（Kaspa と同様）。ただし `blue_score` はヘッダに含めることで
/// 軽量ノードの検証を高速化するオプションもある。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhostDagData {
    /// Selected parent — Blue score が最も高い親。
    /// DAG のメインチェーン (Selected Parent Chain) を構成する。
    pub selected_parent: Hash,

    /// Blue set — この (ブロック ∪ parents) の anticone 内で
    /// GhostDAG パラメータ `k` 以下の anticone サイズを持つブロック群。
    /// "正直なマイナー/バリデータ" のブロックと見なされる。
    ///
    /// # v6 Ordering Guarantee
    ///
    /// canonical mergeset order (blue_score ASC, hash ASC) で格納。
    /// BFS 発見順には依存しない。
    pub mergeset_blues: Vec<Hash>,

    /// Red set — anticone サイズが `k` を超えるブロック群。
    /// 悪意ある並列生成の可能性があるブロック。
    /// Red ブロックの TX は順序付けされるが、Key Image 競合時に
    /// Blue 側が優先される。
    ///
    /// # v6 Ordering Guarantee
    ///
    /// canonical mergeset order (blue_score ASC, hash ASC) で格納。
    pub mergeset_reds: Vec<Hash>,

    /// Blue score — Genesis からこのブロックまでの累積 Blue ブロック数。
    /// DAG の「論理的な高さ」に相当し、ファイナリティ判定に使用。
    pub blue_score: u64,

    /// Blue work — Blue score の重み付き累積 (PoW difficulty 統合用)。
    /// PoS モードでは blue_score と同値でよい。
    pub blue_work: u128,

    /// 各 Blue mergeset block の anticone サイズ (blue_set ∩ anticone)。
    ///
    /// `blues_anticone_sizes[i]` は `mergeset_blues[i]` の
    /// blue anticone サイズに対応する (同一インデックス)。
    ///
    /// # k-cluster 不変条件
    ///
    /// 全ての `i` について `blues_anticone_sizes[i] <= k` が成立する。
    /// この不変条件は分類時に検証される。
    ///
    /// # 用途
    ///
    /// - k-cluster validity の高速検証
    /// - anticone サイズの再計算回避
    /// - Kaspa 互換の GhostDAG metadata
    #[serde(default)]
    pub blues_anticone_sizes: Vec<u64>,
}

// ═══════════════════════════════════════════════════════════════
//  DAG ブロックヘッダ
// ═══════════════════════════════════════════════════════════════

/// DAG ブロックヘッダ — v1 `StoredBlockHeader` の後継。
///
/// # 主要な変更点
///
/// 1. `parents: Vec<Hash>` — 複数の親を参照 (DAG 構造)
/// 2. `blue_score` — GhostDAG 由来の論理高度
/// 3. `state_root` 廃止 — 遅延状態評価のためブロック時点では未確定
///
/// # ハッシュ計算
///
/// `block_hash = SHA3-256("MISAKA_DAG_V2:" || parents || timestamp || tx_root || nonce_or_proposer)`
///
/// parents は辞書順ソートしてからハッシュに含める (決定論性の保証)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagBlockHeader {
    /// DAG protocol version (0x02 for v2)。
    pub version: u8,

    /// 親ブロックハッシュ群。
    ///
    /// - `parents[0]` は Selected Parent (blue_score 最大の親) であるべき
    /// - Genesis ブロックの場合は空 (`vec![]`) or `vec![ZERO_HASH]`
    /// - 最大親数: `MAX_PARENTS` (Kaspa default: 10)
    pub parents: Vec<Hash>,

    /// ブロック生成時刻 (Unix ms)。
    /// DAG では厳密な単調増加は不要だが、過度の未来タイムスタンプは拒否する。
    pub timestamp_ms: u64,

    /// このブロックに含まれる全 TX の Merkle Root (SHA3-256)。
    /// TX が 0 件の場合は ZERO_HASH。
    pub tx_root: Hash,

    /// ブロック提案者の識別子 (validator index or miner pubkey hash)。
    pub proposer_id: [u8; 32],

    /// PoW nonce (PoW ベースの場合) or 0 (PoS の場合)。
    pub nonce: u64,

    /// GhostDAG Blue score — ヘッダに含めるかはオプション。
    /// 含める場合、受信ノードはローカル計算と照合して検証する。
    pub blue_score: u64,

    /// Bits (difficulty target) — PoW モードのみ。PoS では 0。
    pub bits: u32,
}

/// DAG ブロックヘッダの最大親数 — SSOT (constants.rs) から参照。
pub use crate::constants::MAX_PARENTS;

/// DAG protocol version tag。
pub const DAG_VERSION: u8 = 0x02;

/// タイムスタンプの未来許容範囲 (2 分)。
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = 120_000;

impl DagBlockHeader {
    /// ブロックハッシュを計算する。
    ///
    /// parents は **辞書順 (lexicographic)** にソートしてからハッシュに含める。
    /// これにより、同一の parents セットからは常に同一のハッシュが得られる。
    pub fn compute_hash(&self) -> Hash {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_DAG_V2:");
        h.update([self.version]);

        // Parents: 辞書順ソートして決定論的にハッシュ
        let mut sorted_parents = self.parents.clone();
        sorted_parents.sort();
        h.update((sorted_parents.len() as u32).to_le_bytes());
        for p in &sorted_parents {
            h.update(p);
        }

        h.update(self.timestamp_ms.to_le_bytes());
        h.update(&self.tx_root);
        h.update(&self.proposer_id);
        h.update(self.nonce.to_le_bytes());
        h.update(self.bits.to_le_bytes());

        h.finalize().into()
    }

    /// 構造的バリデーション (暗号検証なし)。
    pub fn validate_structure(&self, now_ms: u64) -> Result<(), DagBlockError> {
        // Version check
        if self.version != DAG_VERSION {
            return Err(DagBlockError::UnsupportedVersion(self.version));
        }
        // Parents bounds
        if self.parents.is_empty() && self.blue_score > 0 {
            return Err(DagBlockError::NoParents);
        }
        if self.parents.len() > MAX_PARENTS {
            return Err(DagBlockError::TooManyParents {
                count: self.parents.len(),
                max: MAX_PARENTS,
            });
        }
        // Duplicate parents
        let unique: HashSet<&Hash> = self.parents.iter().collect();
        if unique.len() != self.parents.len() {
            return Err(DagBlockError::DuplicateParent);
        }
        // Timestamp bounds
        if self.timestamp_ms > now_ms + MAX_TIMESTAMP_DRIFT_MS {
            return Err(DagBlockError::TimestampTooFarInFuture {
                block_ts: self.timestamp_ms,
                now: now_ms,
            });
        }
        Ok(())
    }

    /// このブロックが Genesis かどうか。
    pub fn is_genesis(&self) -> bool {
        self.parents.is_empty() || (self.parents.len() == 1 && self.parents[0] == ZERO_HASH)
    }
}

// ═══════════════════════════════════════════════════════════════
//  完全な DAG ブロック (ヘッダ + トランザクション)
// ═══════════════════════════════════════════════════════════════

/// DAG ブロック本体 — ヘッダ + トランザクション群。
///
/// `UtxoTransaction` は v1 と同一の型を再利用する。
/// DAG レイヤーはトランザクションの内容には関知せず、
/// 順序付けと Key Image 競合解決のみを担当する。
#[derive(Debug, Clone)]
pub struct DagBlock {
    /// ブロックヘッダ。
    pub header: DagBlockHeader,

    /// このブロックに含まれる UTXO トランザクション群。
    /// v1 の `UtxoTransaction` 型をそのまま使用。
    pub transactions: Vec<misaka_types::utxo::UtxoTransaction>,

    /// キャッシュされたブロックハッシュ (遅延計算)。
    cached_hash: Option<Hash>,
}

impl DagBlock {
    /// 新しい DagBlock を作成する。
    pub fn new(
        header: DagBlockHeader,
        transactions: Vec<misaka_types::utxo::UtxoTransaction>,
    ) -> Self {
        Self {
            header,
            transactions,
            cached_hash: None,
        }
    }

    /// ブロックハッシュを取得 (キャッシュあり)。
    pub fn hash(&mut self) -> Hash {
        if let Some(h) = self.cached_hash {
            return h;
        }
        let h = self.header.compute_hash();
        self.cached_hash = Some(h);
        h
    }

    /// TX root を計算する (全 TX の signing_digest の Merkle Root)。
    pub fn compute_tx_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return ZERO_HASH;
        }
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_TXROOT_V2:");
        h.update((self.transactions.len() as u32).to_le_bytes());
        for tx in &self.transactions {
            h.update(&tx.signing_digest());
        }
        h.finalize().into()
    }

    /// 全 TX から Key Image を抽出する。
    /// DAG 状態マネージャでの競合検出に使用。
    pub fn extract_key_images(&self) -> Vec<[u8; 32]> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.inputs.iter().map(|inp| inp.key_image))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  エラー型
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum DagBlockError {
    #[error("unsupported DAG block version: 0x{0:02x}")]
    UnsupportedVersion(u8),

    #[error("non-genesis block must have at least one parent")]
    NoParents,

    #[error("too many parents: {count} > {max}")]
    TooManyParents { count: usize, max: usize },

    #[error("duplicate parent hash")]
    DuplicateParent,

    #[error("timestamp too far in future: block={block_ts}, now={now}")]
    TimestampTooFarInFuture { block_ts: u64, now: u64 },

    #[error("parent block not found in DAG: {0}")]
    ParentNotFound(String),

    #[error("tx_root mismatch: header={header}, computed={computed}")]
    TxRootMismatch { header: String, computed: String },
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis_header() -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1700000000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0xAA; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        }
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let h1 = genesis_header().compute_hash();
        let h2 = genesis_header().compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_parent_order_independence() {
        let parent_a = [0x11; 32];
        let parent_b = [0x22; 32];

        let mut h1 = genesis_header();
        h1.parents = vec![parent_a, parent_b];

        let mut h2 = genesis_header();
        h2.parents = vec![parent_b, parent_a];

        // ソートされるので同一ハッシュ
        assert_eq!(h1.compute_hash(), h2.compute_hash());
    }

    #[test]
    fn test_validate_duplicate_parent() {
        let mut hdr = genesis_header();
        let dup = [0x11; 32];
        hdr.parents = vec![dup, dup];
        assert!(matches!(
            hdr.validate_structure(u64::MAX),
            Err(DagBlockError::DuplicateParent)
        ));
    }

    #[test]
    fn test_validate_too_many_parents() {
        let mut hdr = genesis_header();
        hdr.parents = (0..=MAX_PARENTS as u8).map(|i| [i; 32]).collect();
        assert!(matches!(
            hdr.validate_structure(u64::MAX),
            Err(DagBlockError::TooManyParents { .. })
        ));
    }

    #[test]
    fn test_is_genesis() {
        assert!(genesis_header().is_genesis());
        let mut hdr = genesis_header();
        hdr.parents = vec![[0x11; 32]];
        assert!(!hdr.is_genesis());
    }
}
