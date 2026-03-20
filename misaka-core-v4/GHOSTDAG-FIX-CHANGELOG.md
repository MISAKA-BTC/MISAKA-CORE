# MISAKA Core v4 — Kaspa準拠 GHOSTDAG 正確性・決定性 修正プロトコル

## 変更概要

O(1)化を急ぐあまり導入された致命的なアルゴリズム欠陥を修正し、
Kaspaの「PHANTOM / GHOSTDAG」プロトコルの数学的定義に厳密に準拠させた。

---

## Phase 1: 決定論的トポロジーと親選択の完全統一

### Task 1.1 — `parent_selection.rs` (新設)

**問題**: Block Producer側 (`assemble_dag_block`) と Consensus側 (`select_parent`) で
親ブロックのソートキー（Tie-breakルール）が一致しておらず、ノード間でトポロジーが分岐する。

**修正**: `ParentSortKey` 構造体と `canonical_compare()` 関数を実装。
システム全体で唯一のソート基準として統一。

```
優先順位: blue_work (desc) → blue_score (desc) → proposer_id (desc) → hash (desc)
```

`block_hash` による最終タイブレークで全順序(Total Order)を保証。

**影響範囲**:
- `ghostdag_v2.rs (select_parent)` → `parent_selection::select_parent()` に委譲
- `block_processor.rs (ParentSortKey)` → 重複定義を削除、`parent_selection` から re-export
- `dag_block_producer.rs (assemble_dag_block)` → 呼び出し元が canonical sort を使用

### Task 1.2 — `dag_block.rs` (確認: 修正不要)

`compute_hash()` は既に parents を辞書順ソートしてからハッシュに含めており、
案A（親を無順序集合として扱う）が実装済み。`selected_parent` はヘッダに記録せず、
各ノードが `canonical_select_parent()` でローカル計算する設計。

---

## Phase 2: Kaspa準拠 GHOSTDAG アルゴリズムの実装

### Task 2.1 — `ghostdag_v2.rs::compute_mergeset_reachable()` (全面書き換え)

**致命的バグ**: 旧コードは各非Selected Parentから `selected_parent` ポインタのみを
辿る線形ウォークだった。これはサイドブランチを完全に取りこぼす。

```
例: E.parents = [C, D], SP(E) = C, D.parents = [A, B], SP(D) = A

旧コード: D → A → (Aが SP Past なので停止)
→ B は D の親なのに Mergeset から脱落!

新コード: BFS queue に D を入れる → D の全親 {A, B} を展開
→ A は SP Past → 停止 / B は Past にない → Mergeset に追加 → B の親も展開
```

**修正**: 全親ブロックを BFS で走査し、Reachability Index の `is_dag_ancestor_of()`
を O(1) 判定に使用。SP Past に到達したらそのブランチの探索を停止する。

**なぜサイドブランチが取りこぼされなくなったか**:

旧コード (`current = store.get_ghostdag_data(&current).selected_parent`) は
Selected Parent Chain 上のブロックしか訪問しない。
新コード (`store.get_header(&current).parents` の全親を BFS 展開) は
全ての親を探索するため、SP Chain から外れたサイドブランチも正確に発見する。

`reachability.is_dag_ancestor_of(block, selected_parent)` が:
- **true** → そのブロックは SP Past に含まれる → Mergeset ではない → 探索停止
- **false** → SP Past に含まれない → Mergeset に追加 → さらに全親を探索

### Task 2.2 — `ghostdag_v2.rs::classify_mergeset_reachable()` (全面書き換え)

**問題**: Selected Parent の直近 `mergeset_blues` のみを Blue Set 初期値としていた。
SP の深い過去にある Blue ブロックを見落とし、anticone サイズ評価が不正確。

**修正**: SP Chain を `BLUE_PAST_CHAIN_DEPTH` (128) まで遡り、
各チェーンブロックの `mergeset_blues` を収集して Blue Set 全体を構築。
Mergeset ブロックの anticone サイズを正確に評価。

---

## Phase 3: Pruning と Finality の高度化

### Task 3.1 — レガシーのパージと V2 Finality への統合

**削除/移行した依存関係**:

| ファイル | 旧 | 新 |
|---------|----|----|
| `dag_finality.rs` | `GhostDagManager::confirmation_depth()` | `GhostDagEngine::confirmation_depth()` |
| `dag_state_manager.rs` | `DecoyFilter<GhostDagManager>` | `DecoyFilter<GhostDagEngine>` |
| `dag_block_producer.rs` | `GhostDagManager::calculate_ghostdag_data()` | `GhostDagEngine::calculate()` |
| `dag_block_producer.rs` | (なし) | `ReachabilityStore` フィールド追加 |
| `ghostdag.rs` | `pub use GhostDagManager` (deprecated) | 完全削除 |
| `lib.rs` | `GhostDagManager` re-export | 削除、`ParentSortKey` 等を追加 |
| `main.rs` | `GhostDagManager::new()` | `GhostDagEngine::new()` + `ReachabilityStore` |
| `dag_rpc.rs` | `GhostDagManager::new()` | `GhostDagEngine::new()` + `ReachabilityStore` |
| `local_e2e.rs` | `GhostDagManager` + `calculate_ghostdag_data()` | V2 API に完全移行 |

### Task 3.2 — `pruning.rs` (新設: Kaspa Pruning Point)

**問題**: 単純な `blue_score` 閾値による Pruning は必要なサイドブランチや
未確定トランザクションまで消し去る危険がある。

**修正**: Kaspa の Pruning Point 概念を導入。

- **Pruning Point**: Selected Parent Chain 上で `blue_score <= max_score - 500` を満たす最新ブロック
- **安全な Pruning**: Reachability グラフ上で Pruning Point の strict ancestor のみをパージ
- **保護**: Genesis、Pruning Point 自体、PP から到達可能なブロックは削除しない
- **Key Image**: 永久保持 (二重支払い防止)

---

## 変更ファイル一覧

### misaka-dag

| ファイル | 状態 | 行数 |
|---------|------|------|
| `src/parent_selection.rs` | **新設** | ~200 |
| `src/ghostdag_v2.rs` | **全面書換** | ~480 |
| `src/ghostdag.rs` | **書換** | ~45 |
| `src/block_processor.rs` | **書換** | ~140 |
| `src/dag_finality.rs` | **書換** | ~200 |
| `src/dag_state_manager.rs` | **修正** (3箇所) | - |
| `src/dag_block_producer.rs` | **修正** (5箇所) | - |
| `src/pruning.rs` | **新設** | ~260 |
| `src/lib.rs` | **修正** (4箇所) | - |
| `tests/local_e2e.rs` | **修正** (全テスト) | - |

### misaka-node

| ファイル | 状態 | 変更箇所 |
|---------|------|---------|
| `src/main.rs` | **修正** | import, engine init, DagNodeState init, test helper |
| `src/dag_rpc.rs` | **修正** | import, test helper |

### 削除対象 (将来)

`legacy_ghostdag.rs` は `DagStore` trait と `InMemoryDagStore` の定義元として残留。
`GhostDagManager` 構造体は使用されなくなったが、trait 定義のため
ファイル自体の削除は次フェーズで `DagStore` を別モジュールに移動後に行う。
