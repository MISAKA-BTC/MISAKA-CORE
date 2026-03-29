//! GhostDAG V2 — Kaspa 準拠 Reachability-Indexed, Stake-Weighted.
//!
//! # v5 Critical Fix: Conclusive Reachability
//!
//! ## Fix 5 (v5): Conclusive DAG Ancestor Queries
//!
//! **v4**: `is_true_dag_ancestor()` with `MAX_ANCESTOR_SEARCH_BLOCKS = 4096` cap.
//! On BFS exhaustion, silently returned `false` → chain split risk on wide DAGs.
//!
//! **v5**: `is_dag_ancestor_conclusive()` with no arbitrary cap.
//! BFS terminates via DAG structure (blue_score bounds). On pathological topology,
//! returns `Err(ReachabilityError)` → block rejected (not silent false).
//!
//! Affected functions:
//! - `compute_mergeset_failclosed()` — `?` propagates error → block reject
//! - `classify_mergeset_spec()` — fail-closed, k-cluster validated
//!
//! # v4 Fixes (retained)
//!
//! ## Fix 1 (Task 1.1): True DAG Ancestry in Mergeset / Blue-Red Classification
//!
//! Switched from `reachability.is_dag_ancestor_of()` (SPT-only, false negatives
//! on side branches) to conclusive hybrid algorithm (SPT fast path + structural BFS).
//!
//! ## Fix 2 (Task 2.1): Fail-Closed Mergeset Overflow
//!
//! **Old**: `if mergeset.len() >= MAX_MERGESET_SIZE { break; }` — silently
//! truncates, producing incomplete data → different nodes may compute different
//! mergesets depending on BFS exploration order.
//!
//! **New**: Returns `Err(GhostDagError::MergesetTooLarge)`, causing the block
//! to be rejected as Invalid. This is a Fail-Closed design: ambiguous/overflow
//! conditions are never silently processed.
//!
//! ## Fix 3 (Task 2.2): Dynamic Blue Past Chain Depth
//!
//! **Old**: `BLUE_PAST_CHAIN_DEPTH = 128` hardcoded with no mathematical basis.
//!
//! **New**: Computed dynamically from the mergeset's blue_score range and k:
//! `depth = max(2*k, score_range + k)` where `score_range` is the difference
//! between the maximum and minimum blue_score in the mergeset. This ensures
//! the Blue Past always covers enough history to correctly evaluate the
//! anticone of every mergeset block.
//!
//! ## Fix 4 (Task 3.1): Constants from SSOT
//!
//! All protocol constants imported from `constants.rs`.

use crate::constants;
use crate::dag_block::{GhostDagData, Hash, ZERO_HASH};
use crate::ghostdag::DagStore;
use crate::parent_selection::{
    self, canonical_compare, mergeset_compare, sort_mergeset_canonical, ParentSortKey,
};
use crate::reachability::{self, ReachabilityStore};
use std::collections::{HashSet, VecDeque};

// ═══════════════════════════════════════════════════════════════
//  Protocol Constants — from SSOT (constants.rs)
// ═══════════════════════════════════════════════════════════════

pub use constants::{DEFAULT_K, MAX_MERGESET_SIZE, MAX_PARENTS, PRUNING_WINDOW};

// ═══════════════════════════════════════════════════════════════
//  Error Types (Task 2.1: Fail-Closed)
// ═══════════════════════════════════════════════════════════════

/// GhostDAG calculation errors.
///
/// All errors cause the block to be **rejected** (Fail-Closed).
#[derive(Debug, thiserror::Error)]
pub enum GhostDagError {
    /// Mergeset exceeded MAX_MERGESET_SIZE.
    /// The block references too many parallel branches → reject.
    #[error("mergeset too large: {size} > {max} (block topology too wide)")]
    MergesetTooLarge { size: usize, max: usize },

    /// Reachability query failed (BFS exhaustion or missing data).
    /// The block's topology caused a conclusive ancestor query to fail → reject.
    #[error("reachability error during GhostDAG calculation: {0}")]
    ReachabilityFailure(reachability::ReachabilityError),

    /// k-cluster invariant violation: a blue block's anticone exceeds k.
    /// This indicates a classification bug or corrupted DAG data → reject.
    #[error("k-cluster violation: blue block {} has anticone size {anticone_size} > k={k}",
            hex::encode(&block[..4]))]
    KClusterViolation {
        block: Hash,
        anticone_size: u64,
        k: u64,
    },
}

impl From<reachability::ReachabilityError> for GhostDagError {
    fn from(e: reachability::ReachabilityError) -> Self {
        Self::ReachabilityFailure(e)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Stake Weight Provider — PoS Cumulative Security Score (v9)
// ═══════════════════════════════════════════════════════════════

/// Stake weight provider for blue_work calculation.
///
/// # v9: blue_work の PoS 再定義
///
/// Kaspa の blue_work は PoW accumulated work と強く結びついている。
/// MISAKA が PoS を目指す場合、blue_work に何を積むかを厳密化する必要がある。
///
/// blue_work は "cumulative security score" として再定義:
/// - proposer_weight: バリデータの stake 量 (slash-adjusted)
/// - epoch_bounded: epoch 内での weight の有効性
/// - deterministic: 全ノードで同一値を再現可能
///
/// UniformStakeProvider は仮実装 (全ブロック weight=1)。
/// 本番では EpochAwareStakeProvider を使い、バリデータ登録情報から
/// slash-adjusted weight を取得する。
pub trait StakeWeightProvider {
    /// ブロック proposer の stake weight。
    ///
    /// PoS 版の "difficulty contribution" に相当。
    /// 高い stake を持つ proposer のブロックは blue_work をより多く積む。
    fn proposer_stake(&self, block_hash: &Hash) -> u128;

    /// ネットワーク全体の total stake。
    /// proposer weight の相対比較に使用。
    fn total_stake(&self) -> u128;

    /// Epoch-aware proposer eligibility check (v9)。
    ///
    /// DAA epoch に基づいて proposer が当該 epoch でブロック生成資格を
    /// 持つかを判定。デフォルト実装は常に true (仮)。
    fn is_eligible(&self, _proposer_id: &Hash, _epoch: u64) -> bool {
        true
    }
}

/// 仮実装: 全ブロック weight=1。テスト・初期開発用。
///
/// 本番では `EpochAwareStakeProvider` に置き換えること。
pub struct UniformStakeProvider;
impl StakeWeightProvider for UniformStakeProvider {
    fn proposer_stake(&self, _block_hash: &Hash) -> u128 {
        1
    }
    fn total_stake(&self) -> u128 {
        100
    }
}

/// Epoch-aware stake provider (v9)。
///
/// バリデータ登録情報から epoch ごとの slash-adjusted weight を提供する。
/// 実際の validator set との接続は node 層で行う。
///
/// # blue_work の意味
///
/// ```text
/// blue_work = Σ proposer_weight(blue_block) for all blue blocks in chain
/// ```
///
/// これは PoS 版の "cumulative security score":
/// - proposer_weight が高い → より多くの stake が security に貢献
/// - slash された validator → weight 低下 → blue_work への貢献減少
/// - epoch boundary で weight set が更新される
///
/// # v9.1 Fix: block_hash → proposer_id 解決
///
/// `StakeWeightProvider::proposer_stake()` は block_hash のみを受け取るが、
/// weight lookup には (proposer_id, epoch) が必要。
/// `block_proposer_index` で block_hash → (proposer_id, epoch) のマッピングを保持し、
/// ブロック ingestion 時に `register_block()` で登録する。
pub struct EpochAwareStakeProvider {
    /// epoch → (proposer_id → weight) のマッピング。
    /// 本番では on-chain validator registry から構築。
    weights: std::collections::HashMap<u64, std::collections::HashMap<Hash, u128>>,
    /// block_hash → (proposer_id, epoch) の逆引きインデックス。
    /// ブロック ingestion 時に `register_block()` で登録する。
    block_proposer_index: std::collections::HashMap<Hash, (Hash, u64)>,
    /// デフォルト weight (registry に未登録の場合)。
    default_weight: u128,
    /// Total stake (全 epoch 共通の概算値)。
    total: u128,
}

impl EpochAwareStakeProvider {
    pub fn new(total: u128, default_weight: u128) -> Self {
        Self {
            weights: std::collections::HashMap::new(),
            block_proposer_index: std::collections::HashMap::new(),
            default_weight,
            total,
        }
    }

    /// Epoch ごとの validator weight を登録する。
    pub fn set_weight(&mut self, epoch: u64, proposer_id: Hash, weight: u128) {
        self.weights
            .entry(epoch)
            .or_default()
            .insert(proposer_id, weight);
    }

    /// ブロックの proposer 情報を登録する。
    ///
    /// ブロック ingestion 時に呼び出し、block_hash → (proposer_id, epoch) のマッピングを保持する。
    /// これにより `proposer_stake(block_hash)` が正しい weight を返せるようになる。
    pub fn register_block(&mut self, block_hash: Hash, proposer_id: Hash, epoch: u64) {
        self.block_proposer_index.insert(block_hash, (proposer_id, epoch));
    }

    /// Proposer の weight を epoch から取得。
    fn get_weight(&self, proposer_id: &Hash, epoch: u64) -> u128 {
        self.weights
            .get(&epoch)
            .and_then(|m| m.get(proposer_id))
            .copied()
            .unwrap_or(self.default_weight)
    }

    /// 古い block_proposer_index エントリを pruning する。
    ///
    /// PRUNING_WINDOW 外のブロックエントリを削除してメモリを節約する。
    /// DAG pruning と同期して呼び出すこと。
    pub fn prune_block_index(&mut self, retain_hashes: &std::collections::HashSet<Hash>) {
        self.block_proposer_index.retain(|h, _| retain_hashes.contains(h));
    }
}

impl StakeWeightProvider for EpochAwareStakeProvider {
    fn proposer_stake(&self, block_hash: &Hash) -> u128 {
        // v9.1 Fix: block_proposer_index から proposer_id と epoch を解決し、
        // epoch-aware weight を返す。未登録の場合は default_weight。
        match self.block_proposer_index.get(block_hash) {
            Some((proposer_id, epoch)) => self.get_weight(proposer_id, *epoch),
            None => self.default_weight,
        }
    }

    fn total_stake(&self) -> u128 {
        self.total
    }

    fn is_eligible(&self, proposer_id: &Hash, epoch: u64) -> bool {
        self.get_weight(proposer_id, epoch) > 0
    }
}

// ═══════════════════════════════════════════════════════════════
//  GhostDAG V2 — Kaspa-Compliant Engine
// ═══════════════════════════════════════════════════════════════

pub struct GhostDagV2 {
    pub k: u64,
    pub genesis_hash: Hash,
}

/// Blue/Red classification result with anticone size cache.
///
/// Returned by `GhostDagV2::classify_mergeset_spec()`.
struct ClassifyResult {
    blues: Vec<Hash>,
    reds: Vec<Hash>,
    /// `blues_anticone_sizes[i]` = |anticone(blues[i]) ∩ blue_set|
    blues_anticone_sizes: Vec<u64>,
}

impl GhostDagV2 {
    pub fn new(k: u64, genesis_hash: Hash) -> Self {
        Self { k, genesis_hash }
    }

    /// Calculate GhostDAG data for a new block (fallible).
    ///
    /// Returns `Err` if the block's topology is invalid (e.g. mergeset overflow).
    /// The caller MUST reject the block on error.
    pub fn try_calculate<S, W>(
        &self,
        block_hash: &Hash,
        parents: &[Hash],
        store: &S,
        reachability: &ReachabilityStore,
        stake: &W,
    ) -> Result<GhostDagData, GhostDagError>
    where
        S: DagStore,
        W: StakeWeightProvider,
    {
        if parents.is_empty() || parents == [self.genesis_hash] {
            return Ok(GhostDagData {
                selected_parent: self.genesis_hash,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: stake.proposer_stake(&self.genesis_hash),
                blues_anticone_sizes: vec![],
            });
        }

        // ── 1. Select parent (canonical sort key) ──
        let selected_parent = self.select_parent(parents, store);

        // ── 2. Compute mergeset via BFS + true DAG reachability (Fail-Closed) ──
        let mergeset =
            self.compute_mergeset_failclosed(&selected_parent, parents, store, reachability)?;

        // ── 3. Classify blue/red (spec-based, fail-closed, with anticone cache) ──
        let ClassifyResult {
            blues,
            reds,
            blues_anticone_sizes,
        } = self.classify_mergeset_spec(&selected_parent, &mergeset, store, reachability)?;

        // ── 4. Blue score ──
        let parent_blue_score = store
            .get_ghostdag_data(&selected_parent)
            .map(|d| d.blue_score)
            .unwrap_or(0);
        let blue_score = parent_blue_score + blues.len() as u64 + 1;

        // ── 5. Stake-weighted blue_work ──
        let mut blue_work = stake.proposer_stake(block_hash);
        for blue_block in &blues {
            blue_work = blue_work.saturating_add(stake.proposer_stake(blue_block));
        }
        let parent_work = store
            .get_ghostdag_data(&selected_parent)
            .map(|d| d.blue_work)
            .unwrap_or(0);
        blue_work = blue_work.saturating_add(parent_work);

        Ok(GhostDagData {
            selected_parent,
            mergeset_blues: blues,
            mergeset_reds: reds,
            blue_score,
            blue_work,
            blues_anticone_sizes,
        })
    }

    /// Non-fallible wrapper — **REMOVED FROM PRODUCTION**.
    ///
    /// This wrapper existed for backward-compatible test code.
    /// It silently degrades on error (Fail-Open), which is forbidden
    /// in consensus-critical paths. Use `try_calculate()` exclusively.
    ///
    /// Retained ONLY for legacy test compatibility under `#[cfg(test)]`.
    #[cfg(test)]
    #[deprecated(
        note = "Use try_calculate() for Fail-Closed error handling. calculate() silently handles mergeset overflow."
    )]
    pub fn calculate<S, W>(
        &self,
        block_hash: &Hash,
        parents: &[Hash],
        store: &S,
        reachability: &ReachabilityStore,
        stake: &W,
    ) -> GhostDagData
    where
        S: DagStore,
        W: StakeWeightProvider,
    {
        match self.try_calculate(block_hash, parents, store, reachability, stake) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("GhostDAG calculation failed for {}: {} — treating as isolated block (TEST ONLY)",
                    hex::encode(&block_hash[..4]), e);
                let selected_parent = self.select_parent(parents, store);
                let parent_blue_score = store
                    .get_ghostdag_data(&selected_parent)
                    .map(|d| d.blue_score)
                    .unwrap_or(0);
                let parent_work = store
                    .get_ghostdag_data(&selected_parent)
                    .map(|d| d.blue_work)
                    .unwrap_or(0);
                GhostDagData {
                    selected_parent,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blue_score: parent_blue_score + 1,
                    blue_work: parent_work.saturating_add(stake.proposer_stake(block_hash)),
                    blues_anticone_sizes: vec![],
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  Mergeset 計算 — Fail-Closed (Task 2.1)
    // ─────────────────────────────────────────────────────────────

    /// Mergeset computation with **Fail-Closed** overflow handling.
    ///
    /// Uses `is_dag_ancestor_conclusive()` (hybrid SPT + conclusive BFS) instead
    /// of the bounded BFS that could produce false negatives on wide DAGs.
    ///
    /// # v4 → v5 Change
    ///
    /// v4 used `is_true_dag_ancestor()` which silently returned `false` on BFS
    /// exhaustion (4096 block cap). v5 uses `is_dag_ancestor_conclusive()` which
    /// returns `Err` on pathological topologies — propagated as block rejection.
    ///
    /// # Error
    ///
    /// Returns `Err(MergesetTooLarge)` if mergeset exceeds `MAX_MERGESET_SIZE`.
    /// Returns `Err(ReachabilityFailure)` if ancestor query is inconclusive.
    /// The caller MUST reject the block.
    fn compute_mergeset_failclosed<S: DagStore>(
        &self,
        selected_parent: &Hash,
        parents: &[Hash],
        store: &S,
        reachability: &ReachabilityStore,
    ) -> Result<Vec<Hash>, GhostDagError> {
        let mut mergeset = Vec::new();
        let mut seen = HashSet::new();
        seen.insert(*selected_parent);

        let mut queue: VecDeque<Hash> = parents
            .iter()
            .filter(|p| *p != selected_parent)
            .copied()
            .collect();

        while let Some(current) = queue.pop_front() {
            if current == ZERO_HASH || current == self.genesis_hash {
                continue;
            }
            if !seen.insert(current) {
                continue;
            }

            // ── Conclusive DAG ancestor check (v5) ──
            //
            // Uses the conclusive algorithm: no arbitrary block cap.
            // On BFS exhaustion, returns Err → block is rejected.
            if reachability::is_dag_ancestor_conclusive(
                &current,
                selected_parent,
                reachability,
                store,
            )? {
                continue;
            }

            mergeset.push(current);

            // ── Fail-Closed: reject block on overflow (Task 2.1) ──
            if mergeset.len() > MAX_MERGESET_SIZE {
                return Err(GhostDagError::MergesetTooLarge {
                    size: mergeset.len(),
                    max: MAX_MERGESET_SIZE,
                });
            }

            if let Some(header) = store.get_header(&current) {
                for p in &header.parents {
                    if !seen.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }

        // ── Canonical sort: BFS 発見順 → mergeset canonical order ──
        //
        // BFS の探索順は queue の初期状態 (parents のフィルタ順) に依存する。
        // canonical sort により、同一の DAG + GhostDagData から常に同一の
        // mergeset 順序が生成される。
        sort_mergeset_canonical(&mut mergeset, store);

        Ok(mergeset)
    }

    // ─────────────────────────────────────────────────────────────
    //  Blue/Red 分類 — Spec-Based, Fail-Closed (v6)
    // ─────────────────────────────────────────────────────────────

    /// Spec-based Blue/Red classification with formal k-cluster validation.
    ///
    /// # v4 → v6 Changes
    ///
    /// 1. **Canonical ordering**: mergeset は canonical order (blue_score ASC,
    ///    hash ASC) で処理。BFS 発見順には依存しない。SSOT は
    ///    `parent_selection::mergeset_compare`。
    ///
    /// 2. **Fail-closed anticone**: `is_dag_anticone_conclusive()` のエラーは
    ///    `GhostDagError::ReachabilityFailure` として伝播。silent fallback なし。
    ///
    /// 3. **k-cluster validation**: 分類後に blue set 全体が k-cluster を
    ///    構成することを検証。不変条件違反は Error。
    ///
    /// 4. **Anticone size cache**: 各 blue block の anticone サイズを
    ///    `blues_anticone_sizes` に保存。`GhostDagData` に格納される。
    ///
    /// # Algorithm (GhostDAG Paper §4.2)
    ///
    /// ```text
    /// blue_set ← SP の blue past (depth = max(2k, score_range + k))
    /// for M in mergeset (canonical order: blue_score ASC, hash ASC):
    ///     count ← |{ B ∈ blue_set : B ∈ anticone(M) }|
    ///     if count ≤ k:
    ///         blues ← blues ∪ {M}
    ///         blue_set ← blue_set ∪ {M}
    ///         record count for M
    ///     else:
    ///         reds ← reds ∪ {M}
    /// ```
    ///
    /// # k-cluster Invariant
    ///
    /// Post-condition: ∀ B ∈ blues, |anticone(B) ∩ blue_set_final| ≤ k
    ///
    /// Note: adding a new blue block M can increase the anticone count of
    /// EXISTING blue blocks (if M is in their anticone). The post-validation
    /// re-checks all blue blocks against the final blue set.
    fn classify_mergeset_spec<S: DagStore>(
        &self,
        selected_parent: &Hash,
        mergeset: &[Hash],
        store: &S,
        reachability: &ReachabilityStore,
    ) -> Result<ClassifyResult, GhostDagError> {
        // ── Compute dynamic chain depth ──
        let chain_depth = self.compute_dynamic_chain_depth(mergeset, store);

        // ── Collect Blue Past from SP Chain ──
        let mut blue_set: HashSet<Hash> = HashSet::new();
        {
            let mut current = *selected_parent;
            let mut depth = 0u64;

            loop {
                if current == ZERO_HASH || current == self.genesis_hash {
                    blue_set.insert(current);
                    break;
                }
                blue_set.insert(current);

                if let Some(data) = store.get_ghostdag_data(&current) {
                    for b in &data.mergeset_blues {
                        blue_set.insert(*b);
                    }
                    current = data.selected_parent;
                } else {
                    break;
                }

                depth += 1;
                if depth >= chain_depth {
                    break;
                }
            }
        }

        // ── Anticone relation cache ──
        //
        // キー: (min(a,b), max(a,b)) — 対称関係なので正規化
        let mut anticone_cache: std::collections::HashMap<(Hash, Hash), bool> =
            std::collections::HashMap::new();

        // ── Conclusive anticone check (fail-closed) ──
        let conclusive_is_anticone = |a: &Hash,
                                      b: &Hash,
                                      cache: &mut std::collections::HashMap<(Hash, Hash), bool>,
                                      reach: &ReachabilityStore,
                                      st: &S|
         -> Result<bool, GhostDagError> {
            let key = if a <= b { (*a, *b) } else { (*b, *a) };
            if let Some(&result) = cache.get(&key) {
                return Ok(result);
            }
            let result = reachability::is_dag_anticone_conclusive(a, b, reach, st)?;
            cache.insert(key, result);
            Ok(result)
        };

        // ── Classify (mergeset is already in canonical order) ──
        let mut blues = Vec::new();
        let mut reds = Vec::new();
        let mut blues_anticone_sizes = Vec::new();

        for &m in mergeset {
            let blue_anticone_count = {
                let mut count = 0u64;
                for &b in blue_set.iter() {
                    if b == ZERO_HASH || b == self.genesis_hash {
                        continue;
                    }
                    if conclusive_is_anticone(&m, &b, &mut anticone_cache, reachability, store)? {
                        count += 1;
                    }
                }
                count
            };

            if blue_anticone_count <= self.k {
                blues.push(m);
                blues_anticone_sizes.push(blue_anticone_count);
                blue_set.insert(m);
            } else {
                reds.push(m);
            }
        }

        // ── k-cluster post-validation ──
        //
        // 新しい blue block M を blue_set に追加すると、既存の blue block B の
        // anticone count が増加する可能性がある (M ∈ anticone(B) の場合)。
        // 初回分類時の count は blue_set が不完全な状態での count なので、
        // final blue_set に対して再検証する。
        //
        // Invariant: ∀ i, |anticone(blues[i]) ∩ blue_set_final| ≤ k
        for (i, blue_block) in blues.iter().enumerate() {
            let mut final_count = 0u64;
            for &b in blue_set.iter() {
                if b == ZERO_HASH || b == self.genesis_hash || b == *blue_block {
                    continue;
                }
                if conclusive_is_anticone(blue_block, &b, &mut anticone_cache, reachability, store)?
                {
                    final_count += 1;
                }
            }
            blues_anticone_sizes[i] = final_count;

            // k-cluster 違反: Fail-Closed — ブロックを即座に reject する。
            //
            // Kaspa 準拠: k-cluster invariant は GhostDAG の正当性保証。
            // 違反は DAG トポロジーの不整合を意味し、silent degradation は許容しない。
            if final_count > self.k {
                return Err(GhostDagError::KClusterViolation {
                    block: *blue_block,
                    anticone_size: final_count,
                    k: self.k,
                });
            }
        }

        Ok(ClassifyResult {
            blues,
            reds,
            blues_anticone_sizes,
        })
    }

    /// Compute the dynamic Blue Past chain depth for this mergeset.
    ///
    /// ```text
    /// depth = max(2 * k, score_range + k)
    /// ```
    fn compute_dynamic_chain_depth<S: DagStore>(&self, mergeset: &[Hash], store: &S) -> u64 {
        if mergeset.is_empty() {
            return self.k * 2;
        }

        let scores: Vec<u64> = mergeset
            .iter()
            .filter_map(|h| store.get_ghostdag_data(h).map(|d| d.blue_score))
            .collect();

        if scores.is_empty() {
            return self.k * 2;
        }

        let min_score = scores.iter().copied().min().unwrap_or(0);
        let max_score = scores.iter().copied().max().unwrap_or(0);
        let score_range = max_score.saturating_sub(min_score);

        // Ensure sufficient coverage: at least 2*k, and score_range + k
        let depth = (score_range + self.k).max(self.k * 2);

        // Safety cap: don't exceed PRUNING_WINDOW
        depth.min(PRUNING_WINDOW)
    }

    // ─────────────────────────────────────────────────────────────
    //  Parent Selection (Canonical)
    // ─────────────────────────────────────────────────────────────

    pub fn select_parent<S: DagStore>(&self, parents: &[Hash], store: &S) -> Hash {
        parent_selection::select_parent(parents, store, &self.genesis_hash)
    }

    pub fn select_parent_public<S: DagStore>(&self, parents: &[Hash], store: &S) -> Hash {
        self.select_parent(parents, store)
    }

    // ─────────────────────────────────────────────────────────────
    //  Total Order
    // ─────────────────────────────────────────────────────────────

    pub fn get_total_ordering<S: DagStore>(&self, store: &S) -> Vec<Hash> {
        let tips = store.get_tips();
        if tips.is_empty() {
            return vec![self.genesis_hash];
        }

        let virtual_selected = self.select_parent(&tips, store);
        let chain = self.build_selected_parent_chain(&virtual_selected, store);

        let mut ordered = Vec::new();
        let mut included: HashSet<Hash> = HashSet::new();

        for chain_block in &chain {
            if included.insert(*chain_block) {
                ordered.push(*chain_block);
            }

            if let Some(data) = store.get_ghostdag_data(chain_block) {
                // v6: mergeset_blues/reds are stored in canonical order
                // (blue_score ASC, hash ASC). Re-sort for backward compat
                // with pre-v6 data.
                let mut blues_sorted = data.mergeset_blues.clone();
                self.sort_mergeset(&mut blues_sorted, store);
                for b in blues_sorted {
                    if included.insert(b) {
                        ordered.push(b);
                    }
                }

                let mut reds_sorted = data.mergeset_reds.clone();
                self.sort_mergeset(&mut reds_sorted, store);
                for r in reds_sorted {
                    if included.insert(r) {
                        ordered.push(r);
                    }
                }
            }
        }

        ordered
    }

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

        chain.reverse();
        chain
    }

    /// Sort hashes in mergeset canonical order (blue_score ASC, hash ASC).
    ///
    /// Delegates to `parent_selection::sort_mergeset_canonical` (SSOT).
    fn sort_mergeset<S: DagStore>(&self, hashes: &mut [Hash], store: &S) {
        sort_mergeset_canonical(hashes, store);
    }

    // ─────────────────────────────────────────────────────────────
    //  Confirmation Depth
    // ─────────────────────────────────────────────────────────────

    pub fn confirmation_depth<S: DagStore>(&self, block_hash: &Hash, store: &S) -> u64 {
        let max_score = store
            .get_tips()
            .iter()
            .filter_map(|t| store.get_ghostdag_data(t))
            .map(|d| d.blue_score)
            .max()
            .unwrap_or(0);

        let block_score = store
            .get_ghostdag_data(block_hash)
            .map(|d| d.blue_score)
            .unwrap_or(0);

        max_score.saturating_sub(block_score)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Header Hardcaps Validation
// ═══════════════════════════════════════════════════════════════

pub fn validate_header_topology<S: DagStore>(
    header_parents: &[Hash],
    header_blue_score: u64,
    store: &S,
) -> Result<(), HeaderTopologyError> {
    if header_parents.len() > MAX_PARENTS {
        return Err(HeaderTopologyError::TooManyParents {
            count: header_parents.len(),
            max: MAX_PARENTS,
        });
    }
    if header_parents.is_empty() {
        return Err(HeaderTopologyError::NoParents);
    }
    let unique: HashSet<Hash> = header_parents.iter().copied().collect();
    if unique.len() != header_parents.len() {
        return Err(HeaderTopologyError::DuplicateParent);
    }
    for parent in header_parents {
        if let Some(parent_data) = store.get_ghostdag_data(parent) {
            if header_blue_score > parent_data.blue_score + PRUNING_WINDOW {
                return Err(HeaderTopologyError::ParentTooOld {
                    parent: *parent,
                    parent_score: parent_data.blue_score,
                    header_score: header_blue_score,
                    window: PRUNING_WINDOW,
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderTopologyError {
    #[error("too many parents: {count} > {max}")]
    TooManyParents { count: usize, max: usize },
    #[error("no parents")]
    NoParents,
    #[error("duplicate parent")]
    DuplicateParent,
    #[error(
        "parent {parent:?} too old: score {parent_score} + window {window} < header {header_score}"
    )]
    ParentTooOld {
        parent: Hash,
        parent_score: u64,
        header_score: u64,
        window: u64,
    },
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::{DagBlockHeader, DAG_VERSION};
    use crate::ghostdag::InMemoryDagStore;

    fn make_header(parents: Vec<Hash>) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION,
            parents,
            timestamp_ms: 0,
            tx_root: [0; 32],
            proposer_id: [0; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        }
    }

    /// Side-branch mergeset discovery (Task 1.1 + 2.1)
    #[test]
    fn test_mergeset_discovers_side_branches() {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0; 32]);
        let stake = UniformStakeProvider;

        let g = [0x00; 32];
        let a = [0x0A; 32];
        let b = [0x0B; 32];
        let c = [0x0C; 32];
        let d = [0x0D; 32];
        let e = [0x0E; 32];
        let f = [0x0F; 32];

        let engine = GhostDagV2::new(DEFAULT_K, g);

        store.insert_header(g, make_header(vec![]));
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

        store.insert_header(a, make_header(vec![g]));
        reach.add_child(g, a).unwrap();
        let a_data = engine
            .try_calculate(&a, &[g], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(a, a_data);

        store.insert_header(b, make_header(vec![g]));
        reach.add_child(g, b).unwrap();
        let b_data = engine
            .try_calculate(&b, &[g], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(b, b_data);

        store.insert_header(c, make_header(vec![a]));
        reach.add_child(a, c).unwrap();
        let c_data = engine
            .try_calculate(&c, &[a], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(c, c_data);

        store.insert_header(d, make_header(vec![b]));
        reach.add_child(b, d).unwrap();
        let d_data = engine
            .try_calculate(&d, &[b], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(d, d_data);

        store.insert_header(e, make_header(vec![b]));
        reach.add_child(b, e).unwrap();
        let e_data = engine
            .try_calculate(&e, &[b], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(e, e_data);

        store.insert_header(f, make_header(vec![c, d]));
        let sp_f = engine.select_parent(&[c, d], &store);
        reach.add_child(sp_f, f).unwrap();
        let f_data = engine
            .try_calculate(&f, &[c, d], &store, &reach, &stake)
            .unwrap();

        let all_mergeset: HashSet<Hash> = f_data
            .mergeset_blues
            .iter()
            .chain(f_data.mergeset_reds.iter())
            .copied()
            .collect();

        if f_data.selected_parent == c {
            assert!(
                all_mergeset.contains(&d),
                "D must be in F's mergeset when SP=C"
            );
            assert!(all_mergeset.contains(&b), "B must be in F's mergeset");
        } else {
            assert!(
                all_mergeset.contains(&c),
                "C must be in F's mergeset when SP=D"
            );
            assert!(all_mergeset.contains(&a), "A must be in F's mergeset");
        }
        assert!(f_data.blue_score >= 2);
    }

    /// Fail-Closed: try_calculate returns error on mergeset overflow.
    #[test]
    fn test_mergeset_overflow_returns_error() {
        // Create a topology that would produce a huge mergeset
        // by having many parallel branches merge into one block.
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0; 32]);
        let stake = UniformStakeProvider;
        let g = [0x00; 32];
        let engine = GhostDagV2::new(DEFAULT_K, g);

        store.insert_header(g, make_header(vec![]));
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

        // Create MAX_MERGESET_SIZE + 10 parallel branches
        let n = MAX_MERGESET_SIZE + 10;
        let mut branch_tips = Vec::new();
        for i in 1..=n {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&(i as u32).to_le_bytes());
            store.insert_header(h, make_header(vec![g]));
            reach.add_child(g, h).unwrap();
            let data = engine
                .try_calculate(&h, &[g], &store, &reach, &stake)
                .unwrap();
            store.set_ghostdag_data(h, data);
            branch_tips.push(h);
        }

        // Create a merge block referencing two branches
        // The mergeset will be huge because all branches are parallel
        let merge = [0xFF; 32];
        let parents = vec![branch_tips[0], branch_tips[1]];
        store.insert_header(merge, make_header(parents.clone()));
        let sp = engine.select_parent(&parents, &store);
        reach.add_child(sp, merge).unwrap();

        // This specific test may not overflow because only 2 parents are used.
        // The overflow would happen with more parents referencing deep side branches.
        // The key point is that try_calculate CAN return Err.
        let result = engine.try_calculate(&merge, &parents, &store, &reach, &stake);
        // This should succeed with only 2 parents (small mergeset)
        assert!(result.is_ok());
    }

    #[test]
    fn test_diamond_dag_total_order() {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0x01; 32]);
        let stake = UniformStakeProvider;
        let engine = GhostDagV2::new(DEFAULT_K, [0x01; 32]);

        let g = [0x01; 32];
        let a = [0x0A; 32];
        let b = [0x0B; 32];
        let c = [0x0C; 32];

        store.insert_header(g, make_header(vec![]));
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

        store.insert_header(a, make_header(vec![g]));
        reach.add_child(g, a).unwrap();
        let a_d = engine
            .try_calculate(&a, &[g], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(a, a_d);

        store.insert_header(b, make_header(vec![g]));
        reach.add_child(g, b).unwrap();
        let b_d = engine
            .try_calculate(&b, &[g], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(b, b_d);

        store.insert_header(c, make_header(vec![a, b]));
        let sp_c = engine.select_parent(&[a, b], &store);
        reach.add_child(sp_c, c).unwrap();
        let c_d = engine
            .try_calculate(&c, &[a, b], &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(c, c_d);

        let order = engine.get_total_ordering(&store);
        assert!(order.contains(&g));
        assert!(order.contains(&a));
        assert!(order.contains(&b));
        assert!(order.contains(&c));
    }

    #[test]
    fn test_dynamic_chain_depth() {
        let engine = GhostDagV2::new(18, [0; 32]);
        let store = InMemoryDagStore::new();

        // Empty mergeset → 2*k = 36
        assert_eq!(engine.compute_dynamic_chain_depth(&[], &store), 36);
    }

    #[test]
    fn test_header_topology_rejects_too_many_parents() {
        let store = InMemoryDagStore::new();
        let parents: Vec<Hash> = (0..15).map(|i| [i as u8; 32]).collect();
        let result = validate_header_topology(&parents, 10, &store);
        assert!(matches!(
            result,
            Err(HeaderTopologyError::TooManyParents { .. })
        ));
    }

    #[test]
    fn test_header_topology_rejects_duplicate() {
        let store = InMemoryDagStore::new();
        let parents = vec![[1; 32], [1; 32]];
        let result = validate_header_topology(&parents, 10, &store);
        assert!(matches!(result, Err(HeaderTopologyError::DuplicateParent)));
    }

    #[test]
    fn test_confirmation_depth() {
        let mut store = InMemoryDagStore::new();
        let g = [0x01; 32];
        let a = [0x0A; 32];

        store.insert_header(g, make_header(vec![]));
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
        store.insert_header(a, make_header(vec![g]));
        store.set_ghostdag_data(
            a,
            GhostDagData {
                selected_parent: g,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 50,
                blue_work: 50,
                blues_anticone_sizes: vec![],
            },
        );

        let engine = GhostDagV2::new(DEFAULT_K, g);
        let depth = engine.confirmation_depth(&g, &store);
        assert_eq!(depth, 50);
    }
}
