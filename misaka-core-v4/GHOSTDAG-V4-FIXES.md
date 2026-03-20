# MISAKA Core v4 — GHOSTDAG 決定性・正確性・検証強靭化 完了報告

## 変更サマリー

| タスク | 重大度 | ファイル | 変更内容 |
|--------|--------|---------|----------|
| 1.1 | CRITICAL | `reachability.rs` | SPT-only → ハイブリッド祖先判定 (SPT O(1) + Bounded BFS) |
| 1.2 | CRITICAL | `dag_block_producer.rs` | `assemble_dag_block` 内で parents 辞書順正規化を強制 |
| 2.1 | CRITICAL | `ghostdag_v2.rs`, `block_processor.rs` | Mergeset 超過時 `break` → `Err(MergesetTooLarge)` (Fail-Closed) |
| 2.2 | HIGH | `ghostdag_v2.rs` | `BLUE_PAST_CHAIN_DEPTH=128` 固定値 → `max(2k, score_range+k)` 動的計算 |
| 3.1 | HIGH | `constants.rs` (新規), `dag_finality.rs`, `pruning.rs`, `reachability.rs`, `dag_block.rs`, `header_validation.rs`, `ghostdag.rs`, `lib.rs` | 定数 SSOT 集約 + 矛盾解消 |
| 3.2 | HIGH | `dag_store.rs` | `insert_block()` 冒頭に重複検知 → `Err` |
| 4.1 | HIGH | `tests/property_tests.rs` (新規) | proptest: 到着順/親配列順/タイブレーク決定論性 |

---

## Phase 1: トポロジーと親選択の完全な正規化

### タスク 1.1: 真正の DAG 祖先判定

**ファイル:** `crates/misaka-dag/src/reachability.rs`

**バグ:** `is_dag_ancestor_of()` は Selected Parent Tree (SPT) の区間包含のみで判定。サイドブランチの祖先を `false` と誤判定。

```text
Example:
    G
   / \
  A   B         ← Both children of G on SPT
   \ /
    C (SP=A)    ← C is child of A on SPT

Query: is_dag_ancestor_of(B, C)?
SPT: B.interval ⊄ C.interval → false  ← WRONG
DAG: C.parents = [A, B] → B ∈ Past(C) → true
```

**修正:** ハイブリッドアルゴリズム

1. **O(1) Fast-Path ACCEPT:** SPT 区間包含 → true (false positive なし)
2. **Bounded BFS:** SPT で検出できない場合、descendant から ancestor に向かって全 DAG 親を BFS。`blue_score` 差と `MAX_ANCESTOR_SEARCH_BLOCKS=4096` でバウンド。

```rust
pub fn is_true_dag_ancestor<S: DagStore>(
    ancestor: &Hash, descendant: &Hash,
    reachability: &ReachabilityStore, store: &S,
) -> bool {
    if ancestor == descendant { return true; }
    // Fast-path: SPT interval (O(1), no false positives)
    if reachability.is_sp_tree_ancestor_of(ancestor, descendant) { return true; }
    // blue_score bound: ancestor must have lower score
    // ... then Bounded BFS through actual DAG parents ...
}
```

**数学的正当性:** DAG の到達可能性はグラフの構造的性質であり、BFS の探索順に依存しない。全ノードで同一の DAG + GhostDagData → 同一の結果。

**影響範囲:** `ghostdag_v2.rs` の `compute_mergeset_failclosed()` と `classify_mergeset_dynamic()` が `is_true_dag_ancestor()` / `is_true_dag_anticone()` を使用するように変更。

### タスク 1.2: 親配列のカノニカル化

**ファイル:** `crates/misaka-dag/src/dag_block_producer.rs`

**修正:** `assemble_dag_block()` 内部で `parents.sort()` (辞書順) を強制。呼び出し元を信用しない防御的設計。

```rust
let mut parents: Vec<Hash> = tips.iter().take(MAX_PARENTS).copied().collect();
parents.sort(); // Lexicographic: deterministic regardless of input order
```

**注記:** `compute_hash()` は既に辞書順ソートを行うため、ハッシュの決定論性は以前から保証されている。本修正は parents 配列自体の正規化を追加するもの。完全な ParentSortKey ソート (blue_work → blue_score → proposer_id → hash) は `select_parent()` / GhostDAG 計算段階で DagStore アクセスと共に実行される。

---

## Phase 2: GHOSTDAG アルゴリズムの正確性修復

### タスク 2.1: Mergeset の Fail-Closed 上限処理

**ファイル:** `crates/misaka-dag/src/ghostdag_v2.rs`, `crates/misaka-dag/src/block_processor.rs`

**バグ:**
```rust
// 旧コード (致命的)
if mergeset.len() >= MAX_MERGESET_SIZE {
    break; // 残りを無視 → 不完全な mergeset → ノード間不一致
}
```

**修正:**
```rust
// 新コード (Fail-Closed)
if mergeset.len() > MAX_MERGESET_SIZE {
    return Err(GhostDagError::MergesetTooLarge {
        size: mergeset.len(), max: MAX_MERGESET_SIZE,
    });
}
```

新しい `try_calculate()` API:
```rust
pub fn try_calculate(...) -> Result<GhostDagData, GhostDagError>
```

`block_processor.rs` も `try_calculate()` に切り替え、エラー時はブロックを reject:
```rust
let ghostdag_data = engine.try_calculate(...)
    .map_err(|e| BlockProcessError::GhostDag(e.to_string()))?;
```

後方互換のために非 fallible `calculate()` ラッパーも維持 (テスト用)。

### タスク 2.2: 動的な Blue Past 収集深度

**ファイル:** `crates/misaka-dag/src/ghostdag_v2.rs`

**バグ:** `BLUE_PAST_CHAIN_DEPTH = 128` がハードコードされ、k パラメータやトポロジーとの関係がない。

**修正:** 動的計算

$$\text{depth} = \max(2k, \text{score\_range} + k)$$

ここで $\text{score\_range} = \max(\text{mergeset.blue\_score}) - \min(\text{mergeset.blue\_score})$

```rust
fn compute_dynamic_chain_depth(&self, mergeset: &[Hash], store: &S) -> u64 {
    // ... compute min/max blue_score from mergeset ...
    let depth = (score_range + self.k).max(self.k * 2);
    depth.min(PRUNING_WINDOW) // Safety cap
}
```

**数学的正当性:** k-cluster 制約により、mergeset ブロック M の anticone は M の blue_score から ±k の範囲にしか存在しない。score_range + k は全 mergeset ブロックの anticone を正確にカバーする最小深度。

---

## Phase 3: Finality, Pruning, Storage の堅牢化

### タスク 3.1: 定数の単一情報源 (SSOT)

**新規ファイル:** `crates/misaka-dag/src/constants.rs`

**バグ:** 同名の定数が 3 ファイルで矛盾:

| 定数 | `reachability.rs` | `dag_finality.rs` | `pruning.rs` |
|------|---:|---:|---:|
| `FINALITY_DEPTH` | **200** | **100** | — |
| `PRUNING_DEPTH` | **1000** | **500** | **500** |

→ ノード A が blue_score=150 を Final と判定、ノード B が未確定と判定 → **チェーンスプリット**

**修正:** 全定数を `constants.rs` に集約。他ファイルは `pub use crate::constants::*` で参照。

```rust
pub const MIN_DECOY_DEPTH: u64 = 100;
pub const FINALITY_DEPTH: u64 = 200;
pub const PRUNING_DEPTH: u64 = 1000;
pub const PRUNING_WINDOW: u64 = PRUNING_DEPTH; // 同義
pub const ACCUMULATOR_RETENTION_DEPTH: u64 = 2000;

// Compile-time assertions
const _: () = {
    assert!(MIN_DECOY_DEPTH <= FINALITY_DEPTH);
    assert!(FINALITY_DEPTH < PRUNING_DEPTH);
    assert!(PRUNING_WINDOW == PRUNING_DEPTH);
    assert!(FINALITY_DEPTH > DEFAULT_K * 10);
};
```

**影響ファイル:** `dag_finality.rs`, `pruning.rs`, `reachability.rs`, `ghostdag_v2.rs`, `ghostdag.rs`, `dag_block.rs`, `header_validation.rs`, `lib.rs` — 全てローカル定義を削除し SSOT からインポート。

### タスク 3.2: Storage 層の重複検知

**ファイル:** `crates/misaka-dag/src/dag_store.rs`

**バグ:** `insert_block()` が重複ブロックを黙って上書き → GhostDagData や Tips の不整合。

**修正:**
```rust
pub fn insert_block(&self, hash: Hash, ...) -> Result<(), String> {
    let mut inner = self.inner.write()...;
    // Task 3.2: Duplicate block detection (Fail-Closed)
    if inner.headers.contains_key(&hash) {
        return Err(format!("duplicate block {} already in DAG store", ...));
    }
    // ... rest of insertion ...
}
```

---

## Phase 4: プロパティテスト

### タスク 4.1: 決定論的 Total Ordering の証明

**新規ファイル:** `crates/misaka-dag/tests/property_tests.rs`

**Property 1: 到着順序不変性** — 同じ DAG トポロジーに対し、ブロック挿入順をランダムに入れ替えても `get_total_ordering()` が完全一致。

```rust
proptest! {
    #[test]
    fn total_order_invariant_under_insertion_order(
        perm1 in arb_permutation(4),
        perm2 in arb_permutation(4),
    ) {
        // Diamond DAG, Wide Merge DAG, Chain-with-Branches DAG
        // で検証
    }
}
```

**Property 2: 親配列順序不変性** — 各ブロックの parents 配列内の順序を入れ替えても Total Order が一致。

**Property 3: タイブレーク決定論性** — blue_score/blue_work が同一の並列ブロック 10 本を 50 回異なる順序で挿入し、全て同一の Total Order を生成。

**テスト DAG トポロジー:**
- Diamond (4 blocks): G → {A, B} → C
- Wide Merge (8 blocks): G → {1,2,3} → {4,5,6} → 7
- Chain with Branches (6 blocks): G → 1 → {2,3} → {4} → 5

---

## ファイル変更一覧

| ファイル | 種別 | 行数 (概算) |
|---------|------|------------|
| `src/constants.rs` | **新規** | ~170 |
| `src/reachability.rs` | 全面書き換え | ~400 |
| `src/ghostdag_v2.rs` | 全面書き換え | ~530 |
| `src/block_processor.rs` | パッチ | ~5行変更 |
| `src/dag_block_producer.rs` | パッチ | ~10行変更 |
| `src/dag_finality.rs` | パッチ | ~3行変更 |
| `src/pruning.rs` | パッチ | ~20行変更 |
| `src/dag_store.rs` | パッチ | ~8行追加 |
| `src/dag_block.rs` | パッチ | ~2行変更 |
| `src/header_validation.rs` | パッチ | ~2行変更 |
| `src/ghostdag.rs` | パッチ | ~3行変更 |
| `src/lib.rs` | パッチ | ~5行変更 |
| `Cargo.toml` | パッチ | +1行 (proptest) |
| `tests/property_tests.rs` | **新規** | ~420 |

---

## 残存リスク

1. **`virtual_state.rs`** の `is_dag_ancestor_of()` は SPT-only のまま。false negative → 不必要な reorg パスに入るが、最終的な状態は同一なので安全。パフォーマンス最適化の余地あり。

2. **`legacy_ghostdag.rs`** に `MIN_DECOY_DEPTH` のローカル定義が残存。この定数は `ghostdag.rs` 経由ではなく `constants.rs` から re-export されるようになったため、参照者がなければ dead code。

3. **proptest のケースカバレッジ** はデフォルト 256 ケース。CI で `PROPTEST_CASES=10000` を設定することを推奨。
