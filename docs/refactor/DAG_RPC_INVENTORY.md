# dag_rpc.rs 責務インベントリ

## 概要

| セクション | 行数 | 比率 |
|-----------|------|------|
| Production code (lines 1-2833) | 2,834 | 8.7% |
| Test code (lines 2834-32658) | 29,824 | 91.3% |
| **Total** | **32,658** | 100% |

## Production コード分類 (~50 関数, 2,834 行)

### Group 1: Server Setup (行 78-1587, ~1,500 行)

| 関数 | 行 | 責務 | 切り出し先 |
|------|---|------|----------|
| `build_dag_cors_layer()` | 78 | CORS 設定 | `rpc/server.rs` |
| `DagRpcState::new()` | 162 | RPC 状態構築 | `rpc/state.rs` |
| `DagRpcState::mark_*()` | 190-234 | 起動状態マーカー | `rpc/state.rs` |
| `sync_runtime_recovery_from_shadow_state()` | 240 | 復旧同期 | `rpc/internal.rs` |
| `dag_*_json()` (helper 群) | 291-1377 | JSON シリアライズヘルパー | `rpc/types.rs` |
| `run_dag_rpc_server*()` | 1378-1587 | サーバー起動 + ルーティング | `rpc/mod.rs` |

### Group 2: Query Handlers (行 1588-2598, ~1,010 行)

| 関数 | 行 | 責務 |
|------|---|------|
| `dag_get_chain_info()` | 1588 | チェーン情報取得 |
| `dag_get_dag_info()` | 1910 | DAG 状態取得 |
| `dag_get_tips()` | 1971 | DAG tips 取得 |
| `dag_get_block()` | 1999 | ブロック取得 |
| `dag_get_tx_by_hash()` | 1820 | TX ハッシュ検索 |
| `dag_get_shielded_tx_summary()` | 1868 | Shielded TX サマリ |
| `dag_get_virtual_chain()` | 2158 | 仮想チェーン取得 |
| `dag_get_virtual_state()` | 2301 | 仮想状態取得 |
| `dag_get_utxos_by_address()` | 2383 | UTXO アドレス検索 |
| `dag_get_decoy_utxos()` | 2436 | デコイ UTXO 取得 |
| `dag_get_anonymity_set()` | 2488 | 匿名セット取得 |
| `dag_get_mempool_info()` | 2630 | メンプール情報 |
| `dag_fee_estimate()` | 2648 | 手数料見積もり |

→ **切り出し先: `rpc/query.rs`**

### Group 3: TX Submission (行 1666-1819, ~153 行)

| 関数 | 行 | 責務 |
|------|---|------|
| `dag_submit_tx()` | 1666 | TX 提出 |
| `dag_submit_checkpoint_vote()` | 1763 | チェックポイント投票提出 |
| `verify_dag_pre_admission()` | 449 | TX 事前検証 |
| `dag_admission_path()` | 430 | プライバシーパス判定 |

→ **切り出し先: `rpc/tx_submission.rs`**

### Group 4: Admin / Faucet (行 2690-2833, ~143 行)

| 関数 | 行 | 責務 |
|------|---|------|
| `dag_faucet()` | 2690 | テスト用フォーセット |
| `dag_health()` | 2049 | ヘルスチェック |
| `dag_openapi_spec()` | 2059 | OpenAPI 仕様 |
| `dag_swagger_ui()` | 2074 | Swagger UI |

→ **切り出し先: `rpc/admin.rs`**

### Group 5: JSON Helper Functions (~28 関数, ~1,000 行)

`*_json()` 関数群。RPC レスポンスのシリアライズ。

→ **切り出し先: `rpc/types.rs`**

## テストコード分類 (29,824 行)

| カテゴリ | 推定行数 | 内容 |
|---------|---------|------|
| Live RPC integration tests | ~20,000 | `bind live test port` → HTTP リクエスト → assert |
| Shielded e2e tests | ~5,000 | ZKP proof → submit → verify |
| Checkpoint/finality tests | ~3,000 | 投票 → finalize → verify |
| Faucet/misc tests | ~1,824 | 小テスト群 |

→ **切り出し先: `tests/dag_rpc_integration.rs` (misaka-node/tests/)**

## 分割計画

### 新ディレクトリ: `crates/misaka-node/src/rpc/`

```
rpc/
├── mod.rs              (~150 行: Router 構築 + mount のみ)
├── state.rs            (~100 行: DagRpcState struct)
├── types.rs            (~1,000 行: JSON helper 群)
├── query.rs            (~1,000 行: get_* ハンドラ)
├── tx_submission.rs    (~200 行: submit_* ハンドラ)
├── admin.rs            (~200 行: faucet + health + swagger)
└── internal.rs         (~200 行: recovery + metrics export)
```

合計: ~2,850 行 (production)

テスト 29,824 行 → `tests/dag_rpc_integration.rs` に移動

### 結果

| Before | After |
|--------|-------|
| dag_rpc.rs: 32,658 | **削除** |
| rpc/ 新規: 0 | **~2,850** |
| tests/ 移動: 0 | **~29,824** (既存テストそのまま) |
| **misaka-node 合計**: 56,117 | **~26,300** (-29,817) |

## 他の重ファイルの処遇

| ファイル | 行数 | 処遇 |
|---------|------|------|
| `dag_p2p_network.rs` | 2,105 | → `misaka-dag` network モジュールへ |
| `dag_p2p_transport.rs` | 1,971 | → `misaka-dag` network モジュールへ |
| `rpc_server.rs` | 1,600 | → `rpc/` に統合 |
| `shielded_rpc.rs` | 1,496 | → `misaka-shielded` RPC ハンドラへ |
| `shielded_hook_impl.rs` | 1,288 | → `misaka-shielded` へ |
| `validator_api.rs` | 1,128 | → `rpc/validator.rs` へ |
| `p2p_network.rs` | 1,042 | → `misaka-p2p` へ |
