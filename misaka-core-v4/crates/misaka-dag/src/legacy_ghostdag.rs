//! # GhostDAG コンセンサスエンジン (MISAKA-CORE v2)
//!
//! ## 概要
//!
//! GhostDAG (Generalized PHANTOM) アルゴリズムにより、DAG 内の全ブロックを
//! Blue set (正直なノード群) と Red set (攻撃的/遅延ブロック) に分類し、
//! **決定論的なトポロジカル順序 (Total Order)** を算出する。
//!
//! ## アルゴリズム要約
//!
//! 1. 新ブロック `B` が到着したら、`B.parents` の中から blue_score 最大の親を
//!    **Selected Parent** とする。
//! 2. `B` の mergeset (= B.parents の past の和集合 \\ selected_parent の past)
//!    に含まれるブロック群を、anticone サイズに基づいて Blue/Red に分類。
//! 3. `B.blue_score = selected_parent.blue_score + |mergeset_blues| + 1`
//! 4. Total Order: Selected Parent Chain を軸に、各ブロックの mergeset を
//!    Blue → Red の順で挿入して線形化。
//!
//! ## パラメータ `k`
//!
//! GhostDAG パラメータ `k` は、正直なノードが同時に生成しうるブロック数の
//! 上限推定値。`k` が大きいほど高スループットだがファイナリティが遅くなる。
//! Kaspa は `k=18` をデフォルトとしている。MISAKA v2 では `k=18` から開始。
//!
//! ## 参考文献
//!
//! - PHANTOM GHOSTDAG: <https://eprint.iacr.org/2018/104>
//! - Kaspa GhostDAG impl: <https://github.com/kaspanet/rusty-kaspa>

use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, warn};

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
//  GhostDAG エンジン
// ═══════════════════════════════════════════════════════════════

/// GhostDAG コンセンサスエンジン。
///
/// ブロック追加・Blue/Red 分類・Total Order 算出を担当。
/// 状態遷移 (UTXO 更新) には一切関与しない (SRP: Single Responsibility)。
pub struct GhostDagManager {
    /// GhostDAG パラメータ k。
    /// anticone サイズが k 以下のブロックを Blue と判定する。
    pub k: u64,

    /// Genesis ブロックハッシュ。
    pub genesis_hash: Hash,
}

impl GhostDagManager {
    /// 新しい GhostDagManager を作成する。
    pub fn new(k: u64, genesis_hash: Hash) -> Self {
        Self { k, genesis_hash }
    }

    // ─── コア GhostDAG 計算 ───────────────────────────────────

    /// 新しいブロックの GhostDagData を計算する。
    ///
    /// # アルゴリズム (GhostDAG Core)
    ///
    /// 1. `parents` の中から `blue_score` 最大の親を Selected Parent とする。
    /// 2. Mergeset = `parents` の reachable set ∖ `selected_parent` の past。
    ///    (= selected_parent から見て「新しく合流する」ブロック群)
    /// 3. Mergeset 内の各ブロック `M` について:
    ///    - `M` の anticone (= M と並行に生成されたブロック群) のうち
    ///      Blue set に属するものの数が `k` 以下 → M は Blue
    ///    - それ以外 → M は Red
    /// 4. `blue_score = selected_parent.blue_score + |mergeset_blues| + 1`
    ///
    /// # 引数
    ///
    /// - `block_hash`: 新ブロックのハッシュ
    /// - `parents`: 新ブロックの親ハッシュ群
    /// - `store`: DAG ストア (読み取り用)
    ///
    /// # 戻り値
    ///
    /// 計算された `GhostDagData`。呼び出し側が `store.set_ghostdag_data()` で保存する。
    pub fn calculate_ghostdag_data<S: DagStore>(
        &self,
        block_hash: &Hash,
        parents: &[Hash],
        store: &S,
    ) -> GhostDagData {
        // ── Genesis の特殊処理 ──
        if parents.is_empty() || (parents.len() == 1 && parents[0] == ZERO_HASH) {
            return GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
            };
        }

        // ── Step 1: Selected Parent = blue_score 最大の親 ──
        let selected_parent = self.select_parent(parents, store);

        // ── Step 2: Mergeset 計算 ──
        //
        // Mergeset = { B ∈ past(block) : B ∉ past(selected_parent) }
        // 実装上は parents のうち selected_parent 以外 + その past のうち
        // selected_parent の past に含まれないものを BFS で収集する。
        let mergeset = self.compute_mergeset(&selected_parent, parents, store);

        // ── Step 3: Blue/Red 分類 ──
        let (blues, reds) = self.classify_mergeset(&selected_parent, &mergeset, store);

        // ── Step 4: Blue score 計算 ──
        let parent_blue_score = store
            .get_ghostdag_data(&selected_parent)
            .map(|d| d.blue_score)
            .unwrap_or(0);

        // +1 はこのブロック自身 (自身は常に Blue 扱い)
        let blue_score = parent_blue_score + blues.len() as u64 + 1;
        let blue_work = blue_score as u128; // PoS では重み付けなし

        debug!(
            "GhostDAG: block={} selected_parent={} blues={} reds={} score={}",
            hex::encode(&block_hash[..4]),
            hex::encode(&selected_parent[..4]),
            blues.len(),
            reds.len(),
            blue_score,
        );

        GhostDagData {
            selected_parent,
            mergeset_blues: blues,
            mergeset_reds: reds,
            blue_score,
            blue_work,
        }
    }

    /// Selected Parent を選択する — blue_score が最大の親。
    /// タイブレークは辞書順 (ハッシュ値比較)。
    fn select_parent<S: DagStore>(&self, parents: &[Hash], store: &S) -> Hash {
        parents
            .iter()
            .max_by(|a, b| {
                let score_a = store
                    .get_ghostdag_data(a)
                    .map(|d| d.blue_score)
                    .unwrap_or(0);
                let score_b = store
                    .get_ghostdag_data(b)
                    .map(|d| d.blue_score)
                    .unwrap_or(0);
                score_a.cmp(&score_b).then_with(|| a.cmp(b))
            })
            .copied()
            .unwrap_or(ZERO_HASH)
    }

    /// Mergeset を計算する。
    ///
    /// selected_parent の past に含まれないブロックのうち、
    /// 現ブロックの parents から到達可能なブロック群を BFS で収集。
    ///
    /// **簡略化**: 完全な past(selected_parent) の計算は O(DAG size) になるため、
    /// 実際の実装では pruning window + 再帰的 blue_score 比較で効率化する。
    /// ここではインターフェースとコアロジックのスケルトンを示す。
    fn compute_mergeset<S: DagStore>(
        &self,
        selected_parent: &Hash,
        parents: &[Hash],
        store: &S,
    ) -> Vec<Hash> {
        let selected_past = self.collect_past(selected_parent, store);
        let mut mergeset = Vec::new();

        // selected_parent 以外の parents とその past を BFS 探索
        let mut queue: VecDeque<Hash> = parents
            .iter()
            .filter(|p| *p != selected_parent)
            .copied()
            .collect();
        let mut visited: HashSet<Hash> = queue.iter().copied().collect();

        while let Some(current) = queue.pop_front() {
            if selected_past.contains(&current) {
                continue; // selected_parent の past に既に含まれる → skip
            }
            if current == ZERO_HASH || current == self.genesis_hash {
                continue;
            }
            mergeset.push(current);

            // current の parents を BFS 展開
            if let Some(header) = store.get_header(&current) {
                for p in &header.parents {
                    if visited.insert(*p) {
                        queue.push_back(*p);
                    }
                }
            }
        }

        mergeset
    }

    /// あるブロックの past 全体を収集する (BFS)。
    ///
    /// **注意**: 本番実装では pruning depth で制限する必要がある。
    /// スケルトンではフル BFS を示す。
    fn collect_past<S: DagStore>(&self, hash: &Hash, store: &S) -> HashSet<Hash> {
        let mut past = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(*hash);

        while let Some(current) = queue.pop_front() {
            if current == ZERO_HASH || !past.insert(current) {
                continue;
            }
            if let Some(header) = store.get_header(&current) {
                for p in &header.parents {
                    queue.push_back(*p);
                }
            }
        }
        past
    }

    /// Mergeset 内のブロックを Blue/Red に分類する。
    ///
    /// # 分類基準
    ///
    /// ブロック M について、M の anticone のうち Blue set に属するブロック数が
    /// `k` 以下であれば M は Blue、それ以外は Red。
    ///
    /// Anticone(M) = { B : B ∉ past(M) ∧ M ∉ past(B) }
    /// (= M と因果関係を持たない並行ブロック群)
    fn classify_mergeset<S: DagStore>(
        &self,
        selected_parent: &Hash,
        mergeset: &[Hash],
        store: &S,
    ) -> (Vec<Hash>, Vec<Hash>) {
        // 初期 Blue set: selected_parent の Blue set を継承
        let mut current_blues: HashSet<Hash> = HashSet::new();
        if let Some(parent_data) = store.get_ghostdag_data(selected_parent) {
            current_blues.extend(&parent_data.mergeset_blues);
        }
        current_blues.insert(*selected_parent);

        let mut blues = Vec::new();
        let mut reds = Vec::new();

        for &block in mergeset {
            let block_past = self.collect_past(&block, store);

            // Anticone ∩ Blue set のサイズを計算
            let blue_anticone_count = current_blues
                .iter()
                .filter(|&&blue_block| {
                    // blue_block が block の past にない、かつ
                    // block が blue_block の past にない
                    !block_past.contains(&blue_block) && {
                        let blue_past = self.collect_past(&blue_block, store);
                        !blue_past.contains(&block)
                    }
                })
                .count() as u64;

            if blue_anticone_count <= self.k {
                blues.push(block);
                current_blues.insert(block);
            } else {
                reds.push(block);
            }
        }

        (blues, reds)
    }

    // ─── Total Order (トポロジカルソート) ─────────────────────

    /// DAG 全体の **決定論的な Total Order** を算出する。
    ///
    /// # アルゴリズム
    ///
    /// 1. DAG の Virtual Block (= 全 Tips を親とする仮想ブロック) から
    ///    Selected Parent Chain を逆順にたどる。
    /// 2. 各 Selected Parent Chain ブロック `C` について、`C` の mergeset を
    ///    **Blue first, then Red** の順で挿入する。
    /// 3. 最終的に Genesis → Tips の順で線形化されたブロックリストが得られる。
    ///
    /// # 決定論性の保証
    ///
    /// - Blue set 内のソート: `blue_score` 昇順 → ハッシュ辞書順
    /// - Red set 内のソート: 同上
    /// - これにより、全ノードが同一の Total Order を得る。
    ///
    /// # 戻り値
    ///
    /// ブロックハッシュの線形リスト (Genesis 側 → Tips 側の順)。
    pub fn get_total_ordering<S: DagStore>(&self, store: &S) -> Vec<Hash> {
        // ── Step 1: Virtual block から Selected Parent Chain を構築 ──
        let tips = store.get_tips();
        if tips.is_empty() {
            return vec![self.genesis_hash];
        }

        // Virtual block の selected parent = tips のうち blue_score 最大
        let virtual_selected = self.select_parent(&tips, store);
        let chain = self.build_selected_parent_chain(&virtual_selected, store);

        // ── Step 2: Chain に沿って mergeset を挿入 ──
        let mut ordered = Vec::new();
        let mut included: HashSet<Hash> = HashSet::new();

        for chain_block in &chain {
            // Chain block 自体を挿入
            if included.insert(*chain_block) {
                ordered.push(*chain_block);
            }

            // Mergeset (Blue → Red) を挿入
            if let Some(data) = store.get_ghostdag_data(chain_block) {
                let mut blues_sorted = data.mergeset_blues.clone();
                self.sort_by_blue_score(&mut blues_sorted, store);
                for b in blues_sorted {
                    if included.insert(b) {
                        ordered.push(b);
                    }
                }

                let mut reds_sorted = data.mergeset_reds.clone();
                self.sort_by_blue_score(&mut reds_sorted, store);
                for r in reds_sorted {
                    if included.insert(r) {
                        ordered.push(r);
                    }
                }
            }
        }

        ordered
    }

    /// Selected Parent Chain を構築する (virtual → genesis 方向)。
    /// 戻り値は Genesis → virtual の順。
    fn build_selected_parent_chain<S: DagStore>(&self, from: &Hash, store: &S) -> Vec<Hash> {
        let mut chain = Vec::new();
        let mut current = *from;

        loop {
            chain.push(current);
            if current == self.genesis_hash || current == ZERO_HASH {
                break;
            }
            match store.get_ghostdag_data(&current) {
                Some(data) if data.selected_parent != ZERO_HASH => {
                    current = data.selected_parent;
                }
                _ => break,
            }
        }

        chain.reverse(); // Genesis first
        chain
    }

    /// ブロック群を blue_score 昇順 → ハッシュ辞書順でソートする。
    fn sort_by_blue_score<S: DagStore>(&self, hashes: &mut Vec<Hash>, store: &S) {
        hashes.sort_by(|a, b| {
            let score_a = store
                .get_ghostdag_data(a)
                .map(|d| d.blue_score)
                .unwrap_or(0);
            let score_b = store
                .get_ghostdag_data(b)
                .map(|d| d.blue_score)
                .unwrap_or(0);
            score_a.cmp(&score_b).then_with(|| a.cmp(b))
        });
    }

    // ─── ファイナリティ ──────────────────────────────────────

    /// あるブロックの確認深度 (Confirmation Depth) を算出する。
    ///
    /// `depth = virtual_blue_score - block_blue_score`
    ///
    /// depth が十分大きければ (例: 100 以上)、そのブロックの TX は
    /// 安全にファイナルと見なせる。
    ///
    /// # デコイ選択の安全基準
    ///
    /// Ring 署名のデコイに使う UTXO は、この depth が `MIN_DECOY_DEPTH`
    /// 以上のブロックからのみ選択する。これにより、DAG の並び替えで
    /// 無効化されるリスクのある UTXO をデコイに使うことを防ぐ。
    pub fn confirmation_depth<S: DagStore>(&self, block_hash: &Hash, store: &S) -> u64 {
        let tips = store.get_tips();
        let virtual_score = tips
            .iter()
            .filter_map(|t| store.get_ghostdag_data(t))
            .map(|d| d.blue_score)
            .max()
            .unwrap_or(0);

        let block_score = store
            .get_ghostdag_data(block_hash)
            .map(|d| d.blue_score)
            .unwrap_or(0);

        virtual_score.saturating_sub(block_score)
    }
}

/// リング署名デコイ選択の最小確認深度。
///
/// この深度未満のブロックに含まれる UTXO は、DAG の並び替えにより
/// 無効化される可能性があるため、デコイとして選択してはならない。
///
/// 値は GhostDAG パラメータ `k` の数倍が目安。
/// k=18 に対して depth=100 は十分保守的。
pub const MIN_DECOY_DEPTH: u64 = 100;

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

    /// テスト DAG 構造:
    ///
    /// ```text
    ///     G (genesis)
    ///    / \
    ///   A   B     (parallel blocks)
    ///    \ /
    ///     C       (merges A and B)
    /// ```
    #[test]
    fn test_simple_diamond_dag() {
        let mut store = InMemoryDagStore::new();
        let genesis_hash = [0x01; 32];
        let manager = GhostDagManager::new(18, genesis_hash);

        // Genesis
        let g_hash = genesis_hash;
        let g_header = make_header(vec![], 1000);
        store.insert_header(g_hash, g_header);
        let g_data = manager.calculate_ghostdag_data(&g_hash, &[], &store);
        store.set_ghostdag_data(g_hash, g_data);

        // Block A (parent: G)
        let a_hash = [0x0A; 32];
        let a_header = make_header(vec![g_hash], 2000);
        store.insert_header(a_hash, a_header);
        let a_data = manager.calculate_ghostdag_data(&a_hash, &[g_hash], &store);
        assert_eq!(a_data.selected_parent, g_hash);
        assert_eq!(a_data.blue_score, 1); // genesis(0) + 0 mergeset + 1
        store.set_ghostdag_data(a_hash, a_data);

        // Block B (parent: G) — parallel to A
        let b_hash = [0x0B; 32];
        let b_header = make_header(vec![g_hash], 2100);
        store.insert_header(b_hash, b_header);
        let b_data = manager.calculate_ghostdag_data(&b_hash, &[g_hash], &store);
        assert_eq!(b_data.blue_score, 1);
        store.set_ghostdag_data(b_hash, b_data);

        // Block C (parents: A, B) — merge point
        let c_hash = [0x0C; 32];
        let c_header = make_header(vec![a_hash, b_hash], 3000);
        store.insert_header(c_hash, c_header);
        let c_data = manager.calculate_ghostdag_data(&c_hash, &[a_hash, b_hash], &store);

        // C の selected parent は A or B (both score=1, tiebreak by hash)
        // blue_score = parent_score(1) + mergeset_blues + 1
        assert!(c_data.blue_score >= 2);
        store.set_ghostdag_data(c_hash, c_data);

        // Total ordering should include all 4 blocks
        let order = manager.get_total_ordering(&store);
        assert!(order.contains(&g_hash));
        assert!(order.contains(&a_hash));
        assert!(order.contains(&b_hash));
        assert!(order.contains(&c_hash));
    }
}
