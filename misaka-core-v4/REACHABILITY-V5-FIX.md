# MISAKA DAG v5: Conclusive Reachability Fix

## Summary

Consensus-critical パスから arbitrary BFS block cap (4096) を排除し、
DAG 構造自体による BFS 終了を保証する conclusive algorithm に置き換え。

## Problem (v4)

`is_true_dag_ancestor()` は `MAX_ANCESTOR_SEARCH_BLOCKS = 4096` の探索上限で
BFS を打ち切り、`false` を返していた。

**攻撃シナリオ:**

```
攻撃者: 200+ 並列ブランチ × 深さ 20+ の wide DAG を構築
  → ノード A: BFS で祖先を発見 (探索順の偶然) → true
  → ノード B: 4096 ブロック以内に未発見 → false
  → mergeset / blue-red 分類が分岐 → chain split
```

**根本原因:** 到達可能性はグラフの構造的性質だが、v4 は計算資源の都合
(block count cap) で結果を決定していた。同一の DAG でもノードの内部状態
(BFS queue の探索順) により結果が変わり得る設計だった。

## Fix (v5)

### New API

| Function | Returns | Consensus-safe | Use case |
|----------|---------|:-:|----------|
| `is_dag_ancestor_conclusive()` | `Result<bool, ReachabilityError>` | ✅ | GhostDAG mergeset, blue/red |
| `is_dag_anticone_conclusive()` | `Result<bool, ReachabilityError>` | ✅ | Blue/red classification |
| `is_true_dag_ancestor()` | `bool` | ❌ deprecated | Non-consensus utils only |
| `is_true_dag_anticone()` | `bool` | ❌ deprecated | Non-consensus utils only |

### Algorithm: `is_dag_ancestor_conclusive(A, B)`

```
1. A == B                    → Ok(true)
2. SPT interval A ⊇ B       → Ok(true)          O(1)
3. A.blue_score ≥ B.score    → Ok(false)         O(1)
4. Structural BFS from B:
   - queue empty             → Ok(false)         確定的
   - found A                 → Ok(true)          確定的
   - block.score < A.score   → skip (到達不可能)
   - SPT ancestor of A       → skip
5. 500K blocks visited       → Err(BfsExhausted) ブロック reject
```

### Why BFS terminates

- `blue_score` pruning: BFS は `A.score ≤ score ≤ B.score` の範囲のみ訪問
- `visited` set: 各ブロックは高々 1 回訪問
- Active window は有限 (PRUNING_WINDOW × DAG 幅)
- Safety hard cap (500K) は Error を返す (`false` ではない)

### Error handling

`ReachabilityError` は以下の 2 バリアント:

- `BfsExhausted` — DAG が病的に巨大 (500K ブロック訪問)
- `MissingGhostDagData` — store 不整合

呼び出し元 (GhostDAG, VirtualState) はエラーを伝播し、ブロックを reject。
全ノードが同一のエラーで同一のブロックを reject → コンセンサス一致。

## Modified Files

### `crates/misaka-dag/src/reachability.rs` — Core

- **Added:** `is_dag_ancestor_conclusive()` — conclusive algorithm
- **Added:** `is_dag_anticone_conclusive()` — conclusive anticone
- **Added:** `ReachabilityError` enum (manual Display impl)
- **Added:** `CONCLUSIVE_BFS_HARD_CAP = 500_000`
- **Deprecated:** `is_true_dag_ancestor()` — delegates to conclusive, falls back on error
- **Deprecated:** `is_true_dag_anticone()` — same
- **Tests:** 6 new tests (wide DAG, missing data, identity, symmetry)

### `crates/misaka-dag/src/ghostdag_v2.rs` — Consensus caller

- **`compute_mergeset_failclosed()`:** `is_true_dag_ancestor` → `is_dag_ancestor_conclusive`
  - `ReachabilityError` は `GhostDagError::ReachabilityFailure` に変換 → block reject
- **`classify_mergeset_dynamic()`:** `is_true_dag_anticone` → `is_dag_anticone_conclusive`
  - エラー時は conservative (anticone と判定 → Red 分類 = 安全側)
- **`GhostDagError`:** `ReachabilityFailure` variant 追加

### `crates/misaka-dag/src/virtual_state.rs` — State caller

- **`update_virtual()`:** `is_true_dag_ancestor` → `is_dag_ancestor_conclusive`
  - simple advance / reorg common ancestor 検索の両方を修正
- **`VirtualStateError`:** `ReachabilityFailure` variant 追加

### `crates/misaka-dag/src/lib.rs` — Exports

- **Added:** `is_dag_ancestor_conclusive`, `is_dag_anticone_conclusive`, `ReachabilityError`, `CONCLUSIVE_BFS_HARD_CAP`
- **Deprecated (kept):** `is_true_dag_ancestor`, `is_true_dag_anticone` (with `#[allow(deprecated)]`)

### Unchanged

- **`pruning.rs`:** Uses `is_dag_ancestor_of()` (SPT-only) — conservative for pruning, safe
- **`constants.rs`:** `MAX_ANCESTOR_SEARCH_BLOCKS` retained for reference, no longer used in consensus
- **`block_processor.rs`:** Calls `engine.try_calculate()` which propagates errors via `.to_string()`

## Test Coverage

| Test | What it verifies |
|------|-----------------|
| `test_conclusive_detects_side_branch_ancestor` | Diamond DAG side-branch detection |
| `test_conclusive_detects_deep_side_branch` | Multi-hop transitive ancestry |
| `test_conclusive_wide_dag_no_false_negative` | 200 branches × 5 deep, no false negatives |
| `test_conclusive_missing_data_returns_error` | MissingGhostDagData → Err, not false |
| `test_conclusive_identity` | A is always its own ancestor |
| `test_conclusive_anticone_symmetric` | anticone(A,B) == anticone(B,A) |

## Migration Guide

### Consensus code (MUST migrate)

```rust
// v4 (UNSAFE):
if reachability::is_true_dag_ancestor(&a, &b, &reach, &store) { ... }

// v5 (SAFE):
if reachability::is_dag_ancestor_conclusive(&a, &b, &reach, &store)? { ... }
// Error propagation via ? → block reject
```

### Non-consensus code (optional migration)

```rust
// Deprecated but functional — delegates to conclusive internally
#[allow(deprecated)]
let is_ancestor = reachability::is_true_dag_ancestor(&a, &b, &reach, &store);
```
