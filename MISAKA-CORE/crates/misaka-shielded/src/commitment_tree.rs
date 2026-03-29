//! Incremental Merkle Commitment Tree
//!
//! Blake3 ベースの depth-32 incremental Merkle tree。
//! note commitment の append-only 管理と Merkle root の計算を行う。
//!
//! # Design
//! - depth = 32 → 最大 2^32 ≈ 40 億 note をサポート
//! - hash function: Blake3 with domain separation
//! - empty leaf hash: Blake3("MISAKA shielded empty leaf v1")
//! - internal node: Blake3("MISAKA shielded node v1", left || right)
//! - append-only (reorg に備えて root 履歴を保持)
//!
//! # Persistence
//! CommitmentTree は純粋なインメモリ構造。
//! 呼び出し側 (ShieldedState) が WriteBatch 経由で永続化する。

use crate::types::{MerkleWitness, NoteCommitment, TreeRoot};
use serde::{Deserialize, Serialize};

pub const TREE_DEPTH: usize = 32;
pub const MAX_LEAVES: u64 = (1u64 << TREE_DEPTH) - 1;

// ─── hash helpers ─────────────────────────────────────────────────────────────

/// 空の leaf hash
fn empty_leaf() -> [u8; 32] {
    blake3::derive_key("MISAKA shielded empty leaf v1", &[])
}

/// 内部ノードの hash
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// depth d の空サブツリーの root を計算
fn empty_root_at_depth(d: usize) -> [u8; 32] {
    let mut cur = empty_leaf();
    for _ in 0..d {
        cur = node_hash(&cur, &cur);
    }
    cur
}

// ─── MerkleFrontier ───────────────────────────────────────────────────────────

/// Incremental Merkle tree の状態を最小限で保持する frontier。
///
/// frontier[i] = depth i のノードが「確定している」場合はその hash、
///               まだ fill されていない場合は None。
///
/// 新しい leaf を append するたびに O(depth) で root を更新できる。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleFrontier {
    /// frontier[0] = leaf level, frontier[31] = root の 1 手前のレベル（private）
    pub(crate) nodes: Vec<Option<[u8; 32]>>,
    /// 挿入済み leaf 数（private — size() アクセサ経由で読む）
    pub(crate) size: u64,
    /// 重複 commitment 検出用キャッシュ（O(1) lookup）
    #[serde(default)]
    pub(crate) inserted_commitments: std::collections::HashSet<NoteCommitment>,
    /// Ordered list of all inserted leaves (for Merkle path computation)
    #[serde(default)]
    pub(crate) leaves: Vec<[u8; 32]>,
}

impl MerkleFrontier {
    pub fn new() -> Self {
        Self {
            nodes: vec![None; TREE_DEPTH],
            size: 0,
            inserted_commitments: std::collections::HashSet::new(),
            leaves: Vec::new(),
        }
    }

    /// 挿入済み leaf 数を返す
    pub fn size(&self) -> u64 {
        self.size
    }

    /// leaf cm を追加し、更新後の root を返す。
    pub fn append(&mut self, cm: NoteCommitment) -> TreeRoot {
        let mut cur = cm.0;
        let mut carry_pos = self.size;

        for i in 0..TREE_DEPTH {
            if carry_pos & 1 == 0 {
                // 左側ノード: 次の carry を待つ
                self.nodes[i] = Some(cur);
                break;
            } else {
                // 右側ノード: 左側の確定ノードと合成して上へ
                let left = self.nodes[i].unwrap_or_else(|| empty_root_at_depth(i));
                cur = node_hash(&left, &cur);
                self.nodes[i] = None;
                carry_pos >>= 1;
            }
        }

        self.inserted_commitments.insert(cm);
        self.leaves.push(cm.0);
        self.size += 1;
        self.root()
    }

    /// 現在の root を計算する。
    pub fn root(&self) -> TreeRoot {
        let cur = empty_root_at_depth(0); // 空の「右側」の積み上げ
        let size = self.size;

        // frontier の各レベルを bottom-up に合成
        // 存在するノードを左側、存在しない場合は empty を左側として上へ
        let mut carry = empty_root_at_depth(0);
        let mut has_carry = false;

        for i in 0..TREE_DEPTH {
            let bit = (size >> i) & 1;
            if bit == 1 {
                let left = self.nodes[i].unwrap_or_else(|| empty_root_at_depth(i));
                if has_carry {
                    // carry は右側に来る
                    carry = node_hash(&left, &carry);
                } else {
                    carry = left;
                    has_carry = true;
                }
            } else if has_carry {
                let right = empty_root_at_depth(i);
                carry = node_hash(&carry, &right);
            }
        }

        // carry をそのまま root の計算に使う
        // ただし size == 0 の場合は empty root
        let _ = cur; // suppress unused warning
        if self.size == 0 {
            TreeRoot::empty()
        } else {
            // 最終的な root を再計算（より確実な方法）
            self.compute_root_from_scratch()
        }
    }

    /// frontier を使わず、フルスキャンで root を再計算する（デバッグ・検証用）
    fn compute_root_from_scratch(&self) -> TreeRoot {
        // frontier の情報から root を正確に計算
        // 各 bit が 1 のレベルの確定ノードを bottom-up に合成
        let mut acc: Option<[u8; 32]> = None;

        for i in 0..TREE_DEPTH {
            let bit = (self.size >> i) & 1;
            let node = if bit == 1 {
                self.nodes[i].unwrap_or_else(|| empty_root_at_depth(i))
            } else {
                empty_root_at_depth(i)
            };

            acc = Some(match acc {
                None => node,
                Some(prev) => {
                    if bit == 1 {
                        node_hash(&node, &prev)
                    } else {
                        node_hash(&prev, &node)
                    }
                }
            });
        }

        TreeRoot(acc.unwrap_or_else(|| TreeRoot::empty().0))
    }

    /// シリアライズ（DB 保存用）
    pub fn serialize(&self) -> Vec<u8> {
        bincode_serialize(self)
    }

    /// デシリアライズ（DB 復元用）
    pub fn deserialize(bytes: &[u8]) -> Result<Self, FrontierError> {
        bincode_deserialize(bytes).map_err(|e| FrontierError::Deserialize(e.to_string()))
    }
}

impl Default for MerkleFrontier {
    fn default() -> Self {
        Self::new()
    }
}

/// 簡易 bincode 代替（serde_json ベース、依存を増やさない）
#[allow(clippy::unwrap_or_default)]
fn bincode_serialize<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn bincode_deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

// ─── CommitmentTree ────────────────────────────────────────────────────────────

/// Commitment Tree — shielded module のメイン状態。
///
/// 永続化は呼び出し側が WriteBatch 経由で行う。
/// このオブジェクト自体はインメモリ。
///
/// # SECURITY [M2]: フィールドは private / pub(crate)
/// 外部から直接 frontier を書き換えると commitment の重複検出が
/// バイパスされる可能性があるため、pub アクセスを排除する。
#[derive(Debug, Clone)]
pub struct CommitmentTree {
    /// インクリメンタル frontier（private — append/contains 経由でのみ操作）
    pub(crate) frontier: MerkleFrontier,
    /// root 履歴（pub(crate) — 同モジュールのテスト・storage から読む）
    pub(crate) root_history: std::collections::VecDeque<(u64 /* block_height */, TreeRoot)>,
    /// anchor として許容する最大ブロック数
    pub(crate) max_anchor_age: u64,
}

impl CommitmentTree {
    pub fn new(max_anchor_age: u64) -> Self {
        Self {
            frontier: MerkleFrontier::new(),
            root_history: std::collections::VecDeque::new(),
            max_anchor_age,
        }
    }

    /// frontier から復元（DB からのロード用）
    pub fn restore(frontier: MerkleFrontier, root_history: Vec<(u64, TreeRoot)>, max_anchor_age: u64) -> Self {
        Self {
            frontier,
            root_history: root_history.into_iter().collect(),
            max_anchor_age,
        }
    }

    /// commitment を追加し、leaf position を返す。
    pub fn append(&mut self, cm: NoteCommitment) -> Result<u64, TreeError> {
        let position = self.frontier.size;
        if position >= MAX_LEAVES {
            return Err(TreeError::Full);
        }
        self.frontier.append(cm);
        Ok(position)
    }

    /// 指定した commitment がすでに tree に含まれているかを確認する。
    ///
    /// SECURITY: duplicate commitment による二重挿入（同一 commitment が複数 leaf に存在すると
    /// ZK proof が同一 note を複数回 spend できる可能性がある）を防ぐ。
    ///
    /// # 実装
    /// `MerkleFrontier.inserted_commitments` (HashSet) を参照する。O(1) lookup。
    /// このフィールドは serde_json で frontier と一緒に永続化されるため、
    /// 通常の起動/復元では正しく保持される。
    ///
    /// # Migration
    /// v9.1 以前の frontier データには `inserted_commitments` フィールドがない場合がある。
    /// その場合は `bulk_load_commitments()` で DB の CF_SHIELD_COMMITMENTS から復元する必要がある。
    pub fn contains(&self, cm: &NoteCommitment) -> bool {
        self.frontier.inserted_commitments.contains(cm)
    }

    /// DB 再起動・マイグレーション時に commitment キャッシュを復元する。
    ///
    /// v9.1 以前の frontier データには `inserted_commitments` フィールドがないため、
    /// node 起動時に DB の CF_SHIELD_COMMITMENTS から全 commitment を読み込んで
    /// このメソッドで復元する必要がある。
    ///
    /// v9.1 以降の frontier データは `inserted_commitments` を含むため、
    /// 通常は呼び出し不要。ただし、frontier の serde_json サイズが巨大になる場合は
    /// `inserted_commitments` の永続化を止め、毎起動で bulk_load する設計も検討する。
    pub fn bulk_load_commitments(&mut self, commitments: impl IntoIterator<Item = NoteCommitment>) {
        for cm in commitments {
            self.frontier.inserted_commitments.insert(cm);
        }
        tracing::debug!(
            "CommitmentTree: bulk loaded {} commitments into cache",
            self.frontier.inserted_commitments.len(),
        );
    }

    /// 現在の root
    pub fn root(&self) -> TreeRoot {
        self.frontier.root()
    }

    /// block 確定時に root を履歴に記録する
    pub fn record_root(&mut self, block_height: u64) {
        let root = self.root();
        self.root_history.push_back((block_height, root));
        // 古い履歴を削除
        while self.root_history.len() > self.max_anchor_age as usize + 1 {
            self.root_history.pop_front();
        }
    }

    /// anchor として有効な root かどうかを確認する
    pub fn is_valid_anchor(&self, anchor: &TreeRoot) -> bool {
        if *anchor == self.root() {
            return true;
        }
        self.root_history.iter().any(|(_, r)| r == anchor)
    }

    /// 現在の leaf 数
    pub fn size(&self) -> u64 {
        self.frontier.size
    }

    /// Merkle witness を計算する（wallet が ZK proof 生成時に使用）。
    ///
    /// Rebuilds the full Merkle tree from stored leaves and extracts
    /// the authentication path for the given position.
    pub fn witness(&self, position: u64) -> Result<MerkleWitness, TreeError> {
        if position >= self.frontier.size {
            return Err(TreeError::PositionOutOfRange(position));
        }

        let n = self.frontier.size as usize;
        let leaves = &self.frontier.leaves;

        if leaves.len() < n {
            tracing::warn!(
                "CommitmentTree::witness: leaves.len()={} < size={} — incomplete leaf history",
                leaves.len(), n
            );
            return Err(TreeError::PositionOutOfRange(position));
        }

        // Build tree layer by layer
        // Layer 0 = leaves (padded to next power of 2 with empty_leaf)
        let depth = TREE_DEPTH.min(32); // practical depth
        let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n.next_power_of_two());
        for leaf in &leaves[..n] {
            layer.push(*leaf);
        }
        // Pad to next power of 2
        let padded = if n.is_power_of_two() { n } else { n.next_power_of_two() };
        while layer.len() < padded {
            layer.push(empty_leaf());
        }

        let mut auth_path = Vec::with_capacity(depth);
        let mut pos = position as usize;

        // Walk up the tree
        for _level in 0..depth {
            if layer.len() <= 1 {
                // Tree height is less than TREE_DEPTH, pad remaining with empty roots
                auth_path.push(empty_root_at_depth(_level));
                continue;
            }
            // Sibling index
            let sibling = if pos & 1 == 0 { pos + 1 } else { pos - 1 };
            if sibling < layer.len() {
                auth_path.push(layer[sibling]);
            } else {
                auth_path.push(empty_root_at_depth(_level));
            }

            // Compute next layer
            let mut next_layer = Vec::with_capacity((layer.len() + 1) / 2);
            for chunk in layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(node_hash(&chunk[0], &chunk[1]));
                } else {
                    next_layer.push(node_hash(&chunk[0], &empty_root_at_depth(_level)));
                }
            }
            layer = next_layer;
            pos >>= 1;
        }

        Ok(MerkleWitness {
            position,
            auth_path,
        })
    }

    /// frontier をシリアライズ（DB 保存用）
    pub fn serialize_frontier(&self) -> Vec<u8> {
        self.frontier.serialize()
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FrontierError {
    #[error("deserialize failed: {0}")]
    Deserialize(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("position {0} is out of range")]
    PositionOutOfRange(u64),
    #[error("tree is full")]
    Full,
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_cm(i: u8) -> NoteCommitment {
        NoteCommitment([i; 32])
    }

    #[test]
    fn empty_tree_has_deterministic_root() {
        let t1 = CommitmentTree::new(100);
        let t2 = CommitmentTree::new(100);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn append_changes_root() {
        let mut tree = CommitmentTree::new(100);
        let r0 = tree.root();
        tree.append(make_cm(1)).unwrap();
        let r1 = tree.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn append_multiple_deterministic() {
        let mut t1 = CommitmentTree::new(100);
        let mut t2 = CommitmentTree::new(100);
        for i in 0..10u8 {
            t1.append(make_cm(i)).unwrap();
            t2.append(make_cm(i)).unwrap();
        }
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn anchor_validation() {
        let mut tree = CommitmentTree::new(10);
        tree.record_root(1); // root_0
        tree.append(make_cm(42)).unwrap();
        let root_0 = tree.root_history.iter().last().map(|(_, r)| *r).unwrap();
        tree.record_root(2);

        // 現在の root は有効
        assert!(tree.is_valid_anchor(&tree.root()));
        // 直前の root も有効（anchor age 内）
        assert!(tree.is_valid_anchor(&root_0));
    }

    #[test]
    fn size_increments() {
        let mut tree = CommitmentTree::new(100);
        assert_eq!(tree.size(), 0);
        tree.append(make_cm(1)).unwrap();
        assert_eq!(tree.size(), 1);
        tree.append(make_cm(2)).unwrap();
        assert_eq!(tree.size(), 2);
    }
}
