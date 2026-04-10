# misaka-node 解体計画

## 現状: 56,117 行 / 31 ファイル

## ファイル責務マップ

### Tier 1: 巨大ファイル (> 1,000 行)

| ファイル | 行数 | 責務 | 切り出し先 |
|---------|------|------|----------|
| `dag_rpc.rs` | 32,658 | DAG RPC プロトコル定義 + 2,834行 production + 29,824行テスト | **misaka-rpc** (production部分), テストは tests/ に分離 |
| `main.rs` | 4,527 | 起動・設定・コンポーネント組立・shutdown | **残留** (大幅縮小) |
| `dag_p2p_network.rs` | 2,105 | DAG P2P ネットワーク管理 | **misaka-dag** (narwhal_dag/network.rs と統合) |
| `dag_p2p_transport.rs` | 1,971 | DAG P2P トランスポート層 | **misaka-dag** (narwhal_dag/anemo_network.rs と統合) |
| `rpc_server.rs` | 1,600 | HTTP/WS RPC サーバー起動 | **misaka-rpc** |
| `shielded_rpc.rs` | 1,496 | Shielded 用 RPC ハンドラ | **misaka-rpc** |
| `shielded_hook_impl.rs` | 1,288 | Shielded TX フック実装 | **misaka-shielded** |
| `validator_api.rs` | 1,128 | バリデータ API (staking 等) | **misaka-rpc** |
| `p2p_network.rs` | 1,042 | 一般 P2P ネットワーク (非DAG) | **misaka-p2p** |

### Tier 2: 中規模 (200-1,000 行)

| ファイル | 行数 | 責務 | 切り出し先 |
|---------|------|------|----------|
| `validator_lifecycle_persistence.rs` | 706 | バリデータ状態永続化 | **misaka-consensus** |
| `solana_stake_verify.rs` | 646 | Solana stake 検証 | **misaka-bridge** |
| `indexer.rs` | 617 | ブロック/TX インデクサ | 新 **misaka-indexer** |
| `dag_narwhal_dissemination_service.rs` | 608 | ブロック配布 | **misaka-dag** |
| `shielded_verifier_adapters.rs` | 578 | ZKP 検証アダプタ | **misaka-shielded** |
| `bft_event_loop.rs` | 572 | BFT イベントループ | **misaka-dag** (runtime.rs と統合) |
| `block_producer.rs` | 569 | ブロック生成 | **misaka-dag** (core_engine と統合) |
| `config.rs` | 472 | ノード設定構造体 | 新 **misaka-config** |
| `metrics.rs` | 453 | メトリクス定義 | **misaka-metrics** |
| `rpc_auth.rs` | 395 | RPC 認証 | **misaka-rpc** (auth.rs と統合) |
| `dag_tx_dissemination_service.rs` | 367 | TX 配布 | **misaka-dag** |
| `dag_p2p_surface.rs` | 341 | P2P 状態面 | **misaka-dag** |
| `config_validation.rs` | 313 | 設定バリデーション | 新 **misaka-config** |
| `dag_rpc_service.rs` | 293 | DAG RPC サービス管理 | **misaka-rpc** |
| `chain_store.rs` | 291 | チェーンストア | **misaka-storage** |
| `rpc_rate_limit.rs` | 285 | RPC レート制限 | **misaka-rpc** |

### Tier 3: 小規模 (< 200 行)

| ファイル | 行数 | 切り出し先 |
|---------|------|----------|
| `narwhal_runtime_bridge.rs` | 205 | **misaka-dag** (runtime.rs) |
| `sync.rs` | 195 | **misaka-dag** (synchronizer) |
| `sr21_election.rs` | 186 | **misaka-consensus** |
| `sync_relay_transport.rs` | 135 | **misaka-p2p** |
| `narwhal_consensus.rs` | 67 | **misaka-dag** (core_engine) |
| `test_env.rs` | 8 | 削除 (空ファイル) |

## 切り出し計画 (依存の浅い順)

### PR 1: config 切り出し (785 行)
- `config.rs` + `config_validation.rs` → 新 `crates/misaka-config/`
- misaka-node は `misaka-config` を依存に追加
- node 側は `use misaka_config::*` で参照

### PR 2: metrics 統合 (453 行)
- `metrics.rs` → `crates/misaka-metrics/` に統合
- ノード固有のメトリクス定義を metrics crate の `node.rs` モジュールへ

### PR 3: RPC 統合 (4,872 行)
- `rpc_server.rs` + `rpc_auth.rs` + `rpc_rate_limit.rs` + `validator_api.rs` + `shielded_rpc.rs` + `dag_rpc_service.rs` → `crates/misaka-rpc/`
- `dag_rpc.rs` の production 部分 (2,834行) → `misaka-rpc/`、テスト (29,824行) は `misaka-rpc/tests/`

### PR 4: DAG 統合 (5,469 行)
- `dag_p2p_network.rs` + `dag_p2p_transport.rs` + `dag_p2p_surface.rs` + `dag_narwhal_dissemination_service.rs` + `dag_tx_dissemination_service.rs` → `misaka-dag` の narwhal_dag/network/ サブモジュール
- `narwhal_runtime_bridge.rs` + `narwhal_consensus.rs` + `bft_event_loop.rs` → `misaka-dag` の narwhal_dag/runtime

### PR 5: Shielded 統合 (1,866 行)
- `shielded_hook_impl.rs` + `shielded_verifier_adapters.rs` → `misaka-shielded`

### PR 6: その他 (2,514 行)
- `block_producer.rs` → `misaka-dag` (core_engine integration)
- `chain_store.rs` → `misaka-storage`
- `indexer.rs` → 新 `misaka-indexer` (または `misaka-storage/indexer`)
- `solana_stake_verify.rs` → `misaka-bridge`
- `validator_lifecycle_persistence.rs` → `misaka-consensus`
- `sr21_election.rs` → `misaka-consensus`
- `sync.rs` + `sync_relay_transport.rs` → `misaka-dag` / `misaka-p2p`

### PR 7: main.rs 薄化
- 残った main.rs を `main.rs` + `assembly.rs` + `shutdown.rs` に分離
- 目標: 合計 500 行以下

## 数値目標

| 指標 | Before | After |
|------|--------|-------|
| misaka-node LoC | 56,117 | **< 5,000** |
| misaka-node ファイル数 | 31 | **3-5** |
| main.rs | 4,527 | **< 200** |

## 依存方向

```
misaka-node (binary)
├── misaka-config    (設定ロード)
├── misaka-metrics   (メトリクス起動)
├── misaka-rpc       (RPC サーバー起動)
├── misaka-dag       (コンセンサス起動)
├── misaka-p2p       (P2P 起動)
├── misaka-consensus (バリデータ管理)
├── misaka-shielded  (shielded 起動)
├── misaka-bridge    (ブリッジ起動)
└── misaka-storage   (ストア起動)
```

循環なし。`misaka-types` は全 crate から参照可能 (最下層)。
