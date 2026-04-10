# バリデータ運用マニュアル

## 前提

- OS: Ubuntu 22.04+ / macOS 14+
- Rust: 1.78+
- ディスク: SSD 100GB+
- メモリ: 8GB+
- ネットワーク: 公開IP (Active バリデータ)、NAT/outbound-only (Backup)

## 起動手順

### 1. ビルド

```bash
cargo build --release -p misaka-node
```

### 2. 設定ファイル

`config.json` を作成:

```json
{
  "chain_id": 2,
  "listen_addr": "0.0.0.0",
  "listen_port": 16111,
  "data_dir": "./data",
  "shielded_enabled": false,
  "ws_checkpoint": null,
  "log_level": "info"
}
```

mainnet (`chain_id: 1`) では `ws_checkpoint` が**必須**。

### 3. ML-DSA-65 鍵生成

```bash
./target/release/misaka-node keygen --output ./keys/
```

生成物:
- `validator_pk.bin` (1,952 bytes) — 公開鍵
- `validator_sk.bin` (4,032 bytes) — 秘密鍵（0600 パーミッション必須）

### 4. 起動

```bash
./target/release/misaka-node \
  --config ./config.json \
  --key-dir ./keys/ \
  --peers "validator-0:16111,validator-1:16111,validator-2:16111"
```

### 5. PM2 での運用 (Sakura VPS)

```bash
pm2 start ./target/release/misaka-node \
  --name misaka \
  -- --config ./config.json --key-dir ./keys/
pm2 save
pm2 startup
```

## 監視

### ヘルスチェック

```bash
curl http://localhost:16112/health
```

応答: `{"status":"ok","round":42,"blocks":1234}`

### メトリクス

```bash
curl http://localhost:16112/metrics
```

Prometheus 形式で出力。

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| `round not advancing` | ネットワーク分断 or リーダータイムアウト | peers 設定確認、ログで `Leader timeout` を検索 |
| `equivocation detected` | Byzantine ノード | ログの `EquivocationProof` を保全、コミュニティに報告 |
| `BFS aborted` | equivocation flooding 攻撃 | `Decision::Undecided` で安全に再試行される。通常運用では発生しない |
| `StubDisabledInProduction` | StubProofBackend が起動 | release ビルドで `dev-stub-proof` feature を外す |
