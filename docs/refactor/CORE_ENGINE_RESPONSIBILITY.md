# core_engine.rs 責務マップ

## 現状: 943 行, 27 pub 関数 + 14 アクセサ = 41 関数

## 関数一覧と分類

### 構築 / 設定 (3 関数) — 残す
| 関数 | 行 | 責務 | production path? |
|------|---|------|-----------------|
| `new()` | 109 | コンストラクタ | Yes |
| `set_metrics()` | 145 | メトリクス注入 | Yes |
| `change_epoch()` | 632 | エポック切替 | Yes |

### ブロック提案 (3 関数) — **統合対象**
| 関数 | 行 | 責務 | production path? | 問題 |
|------|---|------|-----------------|------|
| `propose_block()` | 155 | naive 祖先で提案 | **不明** | smart と重複 |
| `propose_block_raw()` | 200 | 低レベル (round/ancestors 明示) | Yes (内部) | 共通の inner |
| `propose_block_smart()` | 436 | AncestorSelector 経由で提案 | Yes | propose_block と 90% 重複 |

**統合方針**: `propose_block(ctx: ProposeContext)` に統合。`propose_block_raw` は private inner に。旧 `propose_block` / `propose_block_smart` を削除。

### ブロック処理 (1 関数) — 残す、強化
| 関数 | 行 | 責務 |
|------|---|------|
| `process_block()` | 243 | verify → accept → commit → linearize → finalize |

### リーダータイムアウト (6 関数) — **統合候補**
| 関数 | 行 | 責務 | 統合 |
|------|---|------|------|
| `start_leader_timeout()` | 492 | タイマー開始 | 残す |
| `cancel_leader_timeout()` | 501 | タイマー取消 | 残す |
| `check_leader_timeout()` | 512 | 期限チェック | 残す |
| `handle_leader_timeout()` | 522 | timeout 発火時の処理 | 残す |
| `record_timeout()` | 561 | legacy backoff API | **削除** (leader_timeout が担当) |
| `timeout_ms()` | 569 | legacy backoff 値取得 | **削除** |

### Propagation / Scoring (2 関数) — 残す
| 関数 | 行 | 責務 |
|------|---|------|
| `update_ancestor_scores()` | 477 | AncestorSelector feed |
| `ancestor_selector()` | 483 | テスト用アクセサ |

### Recovery (1 関数) — 残す、強化
| 関数 | 行 | 責務 |
|------|---|------|
| `recover_from_state()` | 594 | DAG state からの復旧 |

### Liveness (1 関数) — 残す
| 関数 | 行 | 責務 |
|------|---|------|
| `should_propose()` | 579 | 提案タイミング判定 |

### アクセサ (14 関数) — 残す
`authority_index`, `epoch`, `last_proposed_round`, `current_round`,
`committee`, `epoch_manager`, `blocks_processed`, `commits_produced`,
`leader_timeout_state`, `set_last_proposed_round`

## 統合計画

### 削除対象 (5 関数)
1. `propose_block()` → `propose_block(ctx)` に吸収
2. `propose_block_smart()` → `propose_block(ctx)` に吸収
3. `record_timeout()` → 削除 (leader_timeout モジュールが担当)
4. `timeout_ms()` → 削除 (leader_timeout.current_timeout() を使用)
5. `ancestor_selector()` → 残すが `#[cfg(test)]` に移動

### 新規追加 (12 シナリオ駆動)
1. `handle_late_leader_arrival()` — シナリオ 1
2. `handle_lag_signal()` — シナリオ 4
3. `handle_lead_signal()` — シナリオ 5
4. `retry_ancestor_selection()` — シナリオ 6
5. `handle_equivocation()` — シナリオ 7
6. `settle_undecided_leaders()` — シナリオ 8
7. `apply_synced_commits()` — シナリオ 11

シナリオ 2,3,9,10,12 は既存関数の強化で対応。

### 結果予測
- 関数数: 41 → ~35 (5 削除, ~7 新規追加, アクセサはカウント除外で ~35)
- 行数: 943 → ~1,400 (シナリオ駆動の実装 + テスト)
