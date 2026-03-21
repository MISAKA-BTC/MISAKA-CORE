# MISAKA DAG v6: GhostDAG Mergeset/Blue-Red Spec Fix

## Summary

GhostDAG の mergeset 計算と blue/red 分類を仕様ベースで再整理。
BFS 発見順の決定論性リーク排除、ソート関数の SSOT 化、
anticone エラーの fail-closed 伝播、k-cluster 不変条件の post-validation、
blues_anticone_sizes キャッシュの追加。

## 修正した5つの問題

### Problem 1: Mergeset の BFS 順序リーク

`compute_mergeset_failclosed()` が BFS 発見順で Vec を返していた。
BFS の初期 queue は `parents.iter().filter()` の順序に依存するため、
同一 DAG でもノード実装の微妙な差で mergeset の内部順序が変わり得た。

**Fix:** mergeset を返す前に `sort_mergeset_canonical()` で正規化。
blue_score ASC, hash ASC の canonical order で格納。

### Problem 2: ソート関数が3箇所に分散

- `classify_mergeset`: インライン closure (blue_score ASC, hash ASC)
- `sort_by_blue_score`: 別のインライン closure (同一ロジック)
- `canonical_compare`: parent_selection.rs (blue_work DESC — 別目的)

同一ロジックの重複 = 将来の不整合リスク。

**Fix:** `parent_selection.rs` に `mergeset_compare()` と
`sort_mergeset_canonical()` を SSOT として集約。
ghostdag_v2 内の全ソートはこの関数に委譲。

### Problem 3: classify_mergeset が Error を飲み込む

v5 で `is_dag_anticone_conclusive()` に切り替えたが、
エラー時に `true` (conservative) を返して silent に処理していた。
エラーが呼び出し元に伝播しないため、異常検知が遅れる。

**Fix:** `classify_mergeset_spec()` が `Result<ClassifyResult, GhostDagError>`
を返す。anticone 判定エラーは `?` で即座に伝播 → ブロック reject。

### Problem 4: k-cluster 不変条件の検証なし

blue/red 分類後に blue set 全体が実際に k-cluster を構成するか
検証していなかった。インクリメンタル分類では、後から追加された
blue block M が既存 blue block B の anticone に入る場合、
B の anticone count が初回計算時より増加する。

**Fix:** 分類完了後に全 blue block の anticone サイズを final blue set
に対して再計算 (k-cluster post-validation)。違反検出時は warn ログ。

### Problem 5: blues_anticone_sizes 未キャッシュ

Kaspa は各 blue block の anticone サイズを GhostDagData に保持する。
MISAKA v4 はこの情報を捨てていたため、再検証時に毎回再計算が必要。

**Fix:** `GhostDagData.blues_anticone_sizes: Vec<u64>` を追加。
`blues_anticone_sizes[i]` = `|anticone(mergeset_blues[i]) ∩ blue_set_final|`。
`#[serde(default)]` で旧データとの後方互換を保証。

## Modified Files

### `crates/misaka-dag/src/parent_selection.rs` — SSOT

- **Added:** `mergeset_compare()` — blue_score ASC, hash ASC
- **Added:** `sort_mergeset_canonical()` — in-place ソート

### `crates/misaka-dag/src/dag_block.rs` — Data Model

- **Added:** `GhostDagData.blues_anticone_sizes: Vec<u64>`
- `#[serde(default)]` for backward compat

### `crates/misaka-dag/src/ghostdag_v2.rs` — Core Algorithm

- **`compute_mergeset_failclosed()`:** canonical sort before return
- **`classify_mergeset_dynamic`** → **`classify_mergeset_spec`:**
  - Returns `Result<ClassifyResult, GhostDagError>`
  - No silent error swallowing
  - k-cluster post-validation
  - `blues_anticone_sizes` collection
- **`sort_by_blue_score`** → **`sort_mergeset`:** delegates to SSOT
- **`try_calculate()`:** includes `blues_anticone_sizes` in output

### Other (blues_anticone_sizes field propagation)

- `reachability.rs` — 13 test GhostDagData literals
- `virtual_state.rs` — 2 test literals
- `persistent_store.rs` — 3 literals
- `pruning.rs` — 5 test literals
- `legacy_ghostdag.rs` — 1 literal
- `property_tests.rs` — 3 literals
- `dag_rpc.rs` — 1 literal

## Diff Stats

```
ghostdag_v2.rs:       +175  -71
dag_block.rs:         +27   -0
parent_selection.rs:  +41   -1
reachability.rs:      +403  -97   (v5 fix, carried forward)
virtual_state.rs:     +26   -23   (v5 fix + field)
lib.rs:               +6    -0
persistent_store.rs:  +3    -0
pruning.rs:           +5    -0
legacy_ghostdag.rs:   +1    -0
property_tests.rs:    +3    -0
dag_rpc.rs:           +1    -1
```

## Invariants (compile-time + runtime)

| Invariant | Enforcement |
|-----------|-------------|
| mergeset は canonical order で格納 | `sort_mergeset_canonical()` before return |
| ソートロジックは1箇所のみ | `parent_selection::mergeset_compare` (SSOT) |
| anticone 判定エラーは伝播 | `classify_mergeset_spec` returns `Result` |
| `blues_anticone_sizes.len() == mergeset_blues.len()` | 同一ループで push |
| ∀ i, `blues_anticone_sizes[i] ≤ k` | post-validation with warn log |
| 旧データはデシリアライズ可能 | `#[serde(default)]` on new field |
