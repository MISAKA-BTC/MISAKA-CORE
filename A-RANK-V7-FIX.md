# MISAKA DAG v7: A-Rank — ResolveVirtual / persistent_store / virtual parents

## Summary

3つの A ランクタスクを統合実装。VirtualState に ResolveVirtual 中心 API を追加、
persistent_store に virtual state / acceptance / diff journal CF を追加、
parent_selection に virtual block 中心の親選択ロジックを追加。

## A1: ResolveVirtual (`virtual_state.rs`)

### 新 API

| Method | Returns | Purpose |
|--------|---------|---------|
| `resolve()` | `ResolveResult` | 中心 API — tips 変化後に呼ぶ |
| `snapshot()` | `VirtualStateSnapshot` | 永続化用スナップショット |
| `compute_virtual_selected_parent()` | `Hash` | Virtual SP 計算 (static) |

### 新型

| Type | Purpose |
|------|---------|
| `ResolveResult` | resolve の結果 (chain changes, state root, stats) |
| `VirtualChainChanged` | SP chain の変更通知 (added/removed hashes + acceptance) |
| `BlockAcceptanceData` | 1 ブロック内の TX 受理結果 |
| `TxAcceptance` | 1 TX の accepted/rejected + reason |
| `VirtualStateSnapshot` | 永続化用スナップショット (tip, score, counts, state root) |

### Kaspa 対応

Kaspa の `consensus.ResolveVirtual()` に相当。UTXO diff 適用、
acceptance data 生成、chain change notification を一つの API に統合。

## A2: persistent_store 本番化 (`persistent_store.rs`)

### 新 CF

| CF | Key | Value | Purpose |
|----|-----|-------|---------|
| `dag_virtual` | `"virtual_snapshot"` | VirtualStateSnapshot JSON | 状態スナップショット |
| `dag_acceptance` | block_hash(32) | BlockAcceptanceData JSON | ブロック毎の受理結果 |
| `dag_diffs` | block_hash(32) | StateDiff JSON | 状態差分ジャーナル |

### 新 PersistentDagBackend メソッド

- `save_virtual_snapshot()` / `load_virtual_snapshot()`
- `save_state_diff()` / `load_state_diff()`
- `save_acceptance()` / `load_acceptance()`

### Restart Recovery フロー

```
1. Load virtual snapshot from dag_virtual
2. Load diff journal from dag_diffs (diffs after snapshot)
3. Replay diffs → reconstruct in-memory VirtualState
4. No full history replay needed
```

## A3: virtual parent selection (`parent_selection.rs`)

### 新 API

| Function | Returns | Purpose |
|----------|---------|---------|
| `pick_virtual_parents()` | `VirtualParents` | Virtual-aware 親選択 |

### VirtualParents struct

```rust
pub struct VirtualParents {
    pub parents: Vec<Hash>,       // フィルタ済み、canonical 順
    pub selected_parent: Hash,    // 最良の親
    pub filtered_count: usize,    // 除外された tips 数
}
```

### フィルタ

1. **Pruning window**: `virtual_score - tip_score > PRUNING_WINDOW` → 除外
2. **Merge depth**: `virtual_score - tip_score > MAX_MERGE_DEPTH(256)` → 除外
3. **Canonical sort**: 残った tips を canonical order で上位 max_parents 選択

### v4 との差

v4: `tips.iter().take(MAX_PARENTS)` + lexicographic sort
v7: virtual SP 起点で pruning/merge-depth フィルタ → canonical sort

## Diff Stats

```
virtual_state.rs:     +237  -52
persistent_store.rs:  +148  -11
parent_selection.rs:  +218  -1
lib.rs:               +18   -2
```

## Test Coverage (18 new tests total)

| File | Tests |
|------|-------|
| virtual_state.rs | 6 (including existing) |
| persistent_store.rs | 6 (3 new: snapshot, diff, acceptance roundtrip) |
| parent_selection.rs | 6 (2 new: stale filter, empty tips) |
