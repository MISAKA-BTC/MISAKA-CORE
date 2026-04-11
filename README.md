# MISAKA Network

**Post-Quantum Native Layer 1 Blockchain**

A high-performance BlockDAG with Narwhal/Bullshark consensus, ML-DSA-65 (FIPS 204) post-quantum signatures, and ML-KEM-768 (FIPS 203) P2P key exchange.

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Narwhal/Bullshark DAG Consensus         │
│         21 Super Representatives (DPoS)          │
├─────────────────────────────────────────────────┤
│   ML-DSA-65 (FIPS 204)  │  ML-KEM-768 (P2P)    │
│   SHA3-256 / BLAKE3      │  Post-Quantum Safe    │
├─────────────────────────────────────────────────┤
│          Transparent UTXO Model                  │
└─────────────────────────────────────────────────┘
```

## Key Features

| Feature | Specification |
|---------|--------------|
| Consensus | Narwhal/Bullshark DAG (Sui-aligned) |
| Cryptography | ML-DSA-65 (NIST FIPS 204) -- 128-bit quantum security |
| Block Time | ~2s |
| Finality | BFT checkpoint voting |
| Max Supply | 10,000,000,000 MISAKA |
| Decimals | 9 |
| Min Stake | 10,000,000 MISAKA |
| P2P Encryption | ML-KEM-768 + ChaCha20-Poly1305 |
| Transaction Model | Transparent UTXO (sender, receiver, amount visible on-chain) |
| Bridge | Solana SPL ↔ MISAKA (Anchor program) |

## Project Structure

```
MISAKA-CORE/
├── crates/
│   ├── misaka-types/        # Core types, constants, address encoding
│   ├── misaka-crypto/       # ML-DSA-65, Blake3, key derivation
│   ├── misaka-pqc/          # Post-quantum ring signatures, key management
│   ├── misaka-dag/          # GhostDAG consensus, block production, virtual state
│   ├── misaka-node/         # Full node: P2P, RPC, block producer, validator
│   ├── misaka-api/          # REST API proxy (explorer, faucet, wallet)
│   ├── misaka-cli/          # Command-line wallet and tools
│   ├── misaka-storage/      # UTXO set, persistent storage
│   ├── misaka-mempool/      # Transaction mempool with fee-rate priority
│   ├── misaka-mining/       # Block template construction
│   ├── misaka-consensus/    # Staking registry, validator lifecycle
│   ├── misaka-rpc/          # RPC types and handlers
│   ├── misaka-txscript/     # Script engine (Kaspa-compatible + PQ opcodes)
│   ├── misaka-security/     # Overflow protection, constant-time ops, fuzzing
│   ├── misaka-tokenomics/   # Inflation schedule, block rewards, fee distribution
│   └── misaka-notify/       # Event notification system
├── configs/
│   ├── mainnet.toml
│   └── testnet.toml
├── solana-bridge/
│   └── programs/
│       ├── misaka-bridge/   # Anchor: lock/unlock SPL tokens
│       └── misaka-staking/  # Anchor: validator staking (deployed)
├── relayer/                 # Solana ↔ MISAKA bridge relayer
├── wallet/core/             # Wallet core library
└── docs/                    # Testnet deploy, validator guide
```

---

## Public Node (テストネット参加ガイド)

ソースからビルドせずに、リリースバイナリを使ってすぐにテストネットに参加できます。

### 1. ダウンロードと展開

[Releases ページ](https://github.com/sasakiyuuu/misaka-test-net/releases) から最新版をダウンロードします。

```bash
# Linux x86_64
wget https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz
tar xzf misaka-public-node-linux-x86_64.tar.gz
cd misaka-public-node-linux-x86_64

# macOS arm64 (Apple Silicon)
curl -LO https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-macos-arm64.tar.gz
tar xzf misaka-public-node-macos-arm64.tar.gz
cd misaka-public-node-linux-x86_64
```

展開後のディレクトリ構成:

```
misaka-public-node-linux-x86_64/
├── misaka-node              # ノードバイナリ
├── misaka-api               # REST API プロキシ
├── start-public-node.sh     # 起動スクリプト
├── config/
│   ├── public-node.toml     # ノード設定
│   ├── genesis_committee.toml
│   ├── seeds.txt            # 接続先ピア
│   └── seed-pubkeys.txt     # ピア公開鍵
└── misaka-data/             # (初回起動時に自動生成)
```

### 2. 起動方法

#### 方法 A: 起動スクリプト (推奨・初回)

```bash
chmod +x start-public-node.sh
./start-public-node.sh
```

スクリプトは初回起動時にオブザーバー用の鍵を自動生成し、CORS や RPC 認証を適切に設定します。
`Ctrl+C` で停止できます。

#### 方法 B: 直接起動 (カスタム設定)

```bash
export MISAKA_RPC_AUTH_MODE=open   # ローカル開発用 (本番では API Key を設定)

./misaka-node \
  --config ./config/public-node.toml \
  --data-dir ./misaka-data \
  --genesis-path ./config/genesis_committee.toml \
  --chain-id 2 \
  --rpc-port 3001
```

主なオプション:

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--config` | ノード設定ファイル | (必須) |
| `--data-dir` | データディレクトリ | `./misaka-data` |
| `--rpc-port` | RPC ポート | `3001` |
| `--chain-id` | チェーン ID (テストネット=2) | `2` |
| `--seeds` | 接続先ピア (カンマ区切り) | (なし: ソロモード) |
| `--advertise-addr` | 外部公開アドレス | (自動検出) |

#### 方法 C: API プロキシも一緒に起動

ブロックエクスプローラーや外部アクセスが必要な場合は、`misaka-api` も起動します:

```bash
# ノード (バックグラウンド)
nohup ./misaka-node --config ./config/public-node.toml \
  --data-dir ./misaka-data \
  --genesis-path ./config/genesis_committee.toml \
  --chain-id 2 > node.log 2>&1 &

# API プロキシ (ポート 4000)
export MISAKA_API_CORS_ORIGINS="*"
nohup ./misaka-api --node http://127.0.0.1:3001 --port 4000 > api.log 2>&1 &
```

### 3. バックグラウンド運用 (Linux)

#### systemd (推奨)

```bash
sudo tee /etc/systemd/system/misaka-node.service << 'EOF'
[Unit]
Description=MISAKA Testnet Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/misaka/misaka-public-node-linux-x86_64
Environment=MISAKA_RPC_AUTH_MODE=open
ExecStart=/home/ubuntu/misaka/misaka-public-node-linux-x86_64/misaka-node \
  --config ./config/public-node.toml \
  --data-dir ./misaka-data \
  --genesis-path ./config/genesis_committee.toml \
  --chain-id 2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now misaka-node

# ログ確認
journalctl -u misaka-node -f
```

API も同様に:

```bash
sudo tee /etc/systemd/system/misaka-api.service << 'EOF'
[Unit]
Description=MISAKA API Proxy
After=misaka-node.service
Requires=misaka-node.service

[Service]
Type=simple
User=ubuntu
Environment=MISAKA_API_CORS_ORIGINS=*
ExecStart=/home/ubuntu/misaka/misaka-public-node-linux-x86_64/misaka-api \
  --node http://127.0.0.1:3001 --port 4000
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now misaka-api
```

#### pm2 (Node.js ユーザー向け)

pm2 は Node.js 以外のプロセスも管理できます。自動再起動・ログローテーション付き。

```bash
# pm2 インストール (未導入の場合)
npm install -g pm2

# ノード起動
cd /home/ubuntu/misaka/misaka-public-node-linux-x86_64
pm2 start ./misaka-node \
  --name misaka-node \
  --cwd /home/ubuntu/misaka/misaka-public-node-linux-x86_64 \
  -- --config ./config/public-node.toml \
     --data-dir ./misaka-data \
     --genesis-path ./config/genesis_committee.toml \
     --chain-id 2

# API 起動
MISAKA_API_CORS_ORIGINS="*" pm2 start ./misaka-api \
  --name misaka-api \
  -- --node http://127.0.0.1:3001 --port 4000

# OS 再起動時に自動起動
pm2 save
pm2 startup

# ログ確認
pm2 logs misaka-node --lines 50

# 状態確認
pm2 status
```

#### Docker (近日対応予定)

公式 Docker イメージは準備中です。

### 4. 更新方法

新バージョンがリリースされたら、以下の手順で更新します。
UTXO スナップショットはディスクに永続化されるため、ブロック高やウォレット残高は再起動後も維持されます。

#### 手動更新

```bash
cd /home/ubuntu/misaka

# 1. 新バージョンをダウンロード
wget https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz -O new-release.tar.gz
tar xzf new-release.tar.gz -C /tmp/

# 2. 新バイナリのバージョン確認
/tmp/misaka-public-node-linux-x86_64/misaka-node --version

# 3. ノード停止
pkill -f misaka-node
pkill -f misaka-api
# または systemd: sudo systemctl stop misaka-node misaka-api
# または pm2:     pm2 stop misaka-node misaka-api

# 4. バイナリ差し替え (旧バイナリはバックアップ)
cp misaka-public-node-linux-x86_64/misaka-node misaka-public-node-linux-x86_64/misaka-node.bak
cp misaka-public-node-linux-x86_64/misaka-api  misaka-public-node-linux-x86_64/misaka-api.bak
cp /tmp/misaka-public-node-linux-x86_64/misaka-node misaka-public-node-linux-x86_64/misaka-node
cp /tmp/misaka-public-node-linux-x86_64/misaka-api  misaka-public-node-linux-x86_64/misaka-api

# 5. 再起動
# 起動スクリプト:
cd misaka-public-node-linux-x86_64 && ./start-public-node.sh
# または systemd: sudo systemctl start misaka-node misaka-api
# または pm2:     pm2 restart misaka-node misaka-api

# 6. 確認
curl -s http://127.0.0.1:3001/api/health
```

#### ワンライナー更新スクリプト

```bash
#!/usr/bin/env bash
set -euo pipefail
DIR="$HOME/misaka/misaka-public-node-linux-x86_64"
TMP="/tmp/misaka-update-$$"
mkdir -p "$TMP"

echo "==> Downloading latest release..."
wget -q https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz -O "$TMP/release.tar.gz"
tar xzf "$TMP/release.tar.gz" -C "$TMP/"

NEW_VER=$("$TMP/misaka-public-node-linux-x86_64/misaka-node" --version 2>&1 || echo "unknown")
CUR_VER=$("$DIR/misaka-node" --version 2>&1 || echo "unknown")
echo "==> Current: $CUR_VER → New: $NEW_VER"

echo "==> Stopping services..."
pkill -f "misaka-node" 2>/dev/null || true
pkill -f "misaka-api"  2>/dev/null || true
sleep 2

echo "==> Replacing binaries..."
cp "$DIR/misaka-node" "$DIR/misaka-node.bak"
cp "$DIR/misaka-api"  "$DIR/misaka-api.bak"  2>/dev/null || true
cp "$TMP/misaka-public-node-linux-x86_64/misaka-node" "$DIR/misaka-node"
cp "$TMP/misaka-public-node-linux-x86_64/misaka-api"  "$DIR/misaka-api"  2>/dev/null || true
chmod +x "$DIR/misaka-node" "$DIR/misaka-api" 2>/dev/null || true

echo "==> Starting..."
cd "$DIR" && bash ./start-public-node.sh &
rm -rf "$TMP"
echo "==> Done!"
```

### 5. データについて

| ディレクトリ / ファイル | 内容 | 再起動後 |
|----------------------|------|---------|
| `misaka-data/` | DAG ブロックデータ、WAL | 自動復旧 |
| `misaka-data/validator.key` | オブザーバー鍵 (初回自動生成) | 維持 |
| `misaka-data/narwhal_utxo_snapshot.json` | UTXO 状態スナップショット | 維持 (100コミット毎に自動保存) |

- ブロック高・残高は UTXO スナップショットから復旧されます
- `misaka-data/` を削除するとフルリセット (新しい鍵が生成され、ブロック高は 0 から再開)
- ディスク使用量は通常 100MB 未満 (テストネット規模)

### 6. トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| `RPC auth config error: FATAL` | API Key 未設定 | `export MISAKA_RPC_AUTH_MODE=open` するか、`start-public-node.sh` を使う |
| `OBSERVER MODE` ログ | 正常動作。ジェネシス委員会に含まれない鍵で起動 | 対処不要。ブロック受信・検証は行われる |
| `sub-DAG block data unavailable` | リスタート後の DAG ギャップ | 通常は自動回復 (100 ラウンド以内) |
| ブロック高が 0 に戻る | `narwhal_utxo_snapshot.json` が存在しない | 100 コミット以上進むまで待つ (自動保存) |
| `502 Bad Gateway` (API 経由) | ノード RPC がビジー | 数秒待って再試行。3 秒タイムアウト付き |
| macOS `quarantine` エラー | Gatekeeper ブロック | `xattr -d com.apple.quarantine ./misaka-node` |

---

## ソースからビルド

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- Linux (Ubuntu 22.04+) or macOS
- cmake (ML-DSA-65 ビルドに必要)

### Build

```bash
cargo build --release --features "dag,faucet"
```

### Generate Wallet

```bash
./target/release/misaka-cli keygen --name my-wallet
```

### Run Validator Node

```bash
# 1. Setup validator (interactive guide)
./target/release/misaka-cli setup-validator --data-dir ./data --chain-id 2

# 2. Generate validator key
export MISAKA_VALIDATOR_PASSPHRASE="your-secure-passphrase"
./target/release/misaka-node --keygen-only --name validator-0 --data-dir ./data

# 3. Start node
./target/release/misaka-node \
  --validator \
  --validator-index 0 \
  --validators 21 \
  --data-dir ./data \
  --chain-id 2 \
  --advertise-addr YOUR_IP:6690
```

### Connect Peer Node

```bash
./target/release/misaka-node \
  --validator \
  --validator-index 1 \
  --validators 21 \
  --data-dir ./data \
  --seeds SEED_IP:6690 \
  --advertise-addr YOUR_IP:6690
```

---

## CLI Commands

### Wallet & Transfers

```bash
# ウォレット生成
misaka-cli keygen --name my-wallet

# 残高確認
misaka-cli balance <ADDRESS> --rpc http://127.0.0.1:3001

# 送金 (ML-DSA-65 署名)
misaka-cli send <TO_ADDRESS> <AMOUNT> --rpc http://127.0.0.1:3001

# Faucet (テストネット)
curl -s http://127.0.0.1:3001/api/faucet -X POST \
  -H "Content-Type: application/json" \
  -d '{"address":"<ADDR>","spendingPubkey":"<PK_HEX>"}'
```

### Privacy Model

MISAKA v1.0 is a transparent blockchain. All transactions reveal sender,
receiver, and amount on-chain. Confidential transaction features were removed
before mainnet because the available ZK proof systems (Groth16, PLONK over
BLS12-381) rely on pairing-based cryptography broken by Shor's algorithm.
See [docs/whitepaper_errata.md](docs/whitepaper_errata.md) for details.

### Validator Setup

```bash
# Interactive SR21 setup guide
misaka-cli setup-validator --data-dir ./data --chain-id 2

# Check stake on Solana
misaka-cli check-stake --key-file data/l1-public-key.json
```

## RPC API

### Node Direct (port 3001)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | ノードヘルスチェック |
| `/api/ready` | GET | ノード準備状態 |
| `/api/status` | GET | 詳細ステータス |
| `/api/get_chain_info` | GET | チェーン情報 (高さ、ピア数、safe mode 等) |
| `/api/get_recent_blocks` | GET | 直近 64 ブロック |
| `/api/get_balance` | POST | アドレスの残高 |
| `/api/get_utxos_by_address` | POST | アドレスの UTXO 一覧 |
| `/api/get_indexed_utxos` | POST | インデックス済み UTXO |
| `/api/get_tx_status` | POST | TX ステータス (pending/confirmed/unknown) |
| `/api/submit_tx` | POST | トランザクション送信 |
| `/api/faucet` | POST | テストネット Faucet |
| `/api/get_peers` | GET | 接続中ピア一覧 |

### API Proxy (port 4000)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chain/info` | GET | チェーン情報 (整形済み) |
| `/v1/wallet/balance/:address` | GET | 残高照会 |
| `/v1/wallet/utxos/:address` | GET | UTXO 一覧 |
| `/v1/tx/submit` | POST | TX 送信 |
| `/v1/tx/:hash` | GET | TX 詳細 |
| `/api/v1/faucet/request` | POST | Faucet (レート制限付き) |
| `/api/v1/faucet/status` | GET | Faucet キュー状態 |
| `/api/v1/explorer/blocks` | GET | ブロック一覧 |
| `/api/v1/explorer/stats` | GET | ネットワーク統計 |
| `/explorer` | GET | ブロックエクスプローラー UI |

## Tokenomics

| Parameter | Value |
|-----------|-------|
| Total Supply | 10,000,000,000 MISAKA |
| Decimals | 9 |
| Initial Block Reward | 50 MISAKA |
| Min Validator Stake | 10,000,000 MISAKA |
| Staking Program | `27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG` |

## Block Timing

| Wall-Clock | Blocks (~2s each) |
|------------|-------------------|
| 1 minute | ~30 |
| 1 hour | ~1,800 |
| 24 hours | ~43,200 |
| 7 days | ~302,400 |

## Solana Bridge

Lock-and-mint bridge between Solana SPL tokens and MISAKA:

```
Solana → MISAKA: lock_tokens() → Relayer → MISAKA mint
MISAKA → Solana: MISAKA burn → Relayer → unlock_tokens() (M-of-N committee)
```

Bridge program: `solana-bridge/programs/misaka-bridge/`
Staking program: `solana-bridge/programs/misaka-staking/`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MISAKA_RPC_AUTH_MODE` | RPC 認証モード (`open` / `key`) | `key` (API Key 必須) |
| `MISAKA_RPC_API_KEY` | RPC write エンドポイント認証キー | (未設定でエラー) |
| `MISAKA_API_CORS_ORIGINS` | API CORS 許可オリジン (カンマ区切り) | localhost のみ |
| `MISAKA_FAUCET_AMOUNT` | Faucet 配布量 (base units) | `1000000000` (= 1 MISAKA) |
| `MISAKA_VALIDATOR_PASSPHRASE` | バリデーター鍵暗号化パスフレーズ | (バリデーター時必須) |
| `MISAKA_SOLANA_RPC_URL` | Solana RPC (ステーク検証用) | (optional) |
| `MISAKA_STAKING_PROGRAM_ID` | Staking プログラムアドレス | `27WjgCA...` |
| `MISAKA_ACCEPT_OBSERVERS` | オブザーバーノード受け入れ | `0` |
| `MISAKA_LOG_FORMAT` | ログ形式 (`compact` / `json`) | `compact` |

## Security

- **Post-Quantum**: ML-DSA-65 (NIST FIPS 204) for all signatures
- **P2P Encryption**: ML-KEM-768 key exchange + ChaCha20-Poly1305
- **Bridge**: M-of-N Ed25519 committee signatures with replay protection
- **Signature Verification**: All transparent TX inputs verified at admission
- **Supply Cap**: Hard-enforced MAX_TOTAL_SUPPLY at consensus execution layer
- **RPC Auth**: API Key 認証 (デフォルト有効)、IP ホワイトリスト対応
- **Faucet Rate Limit**: IP + アドレス単位のクールダウン (デフォルト 300 秒)

## Testnet Deployment

See [docs/TESTNET_DEPLOY_GUIDE.md](docs/TESTNET_DEPLOY_GUIDE.md) for full testnet setup and operation instructions, and [docs/VALIDATOR_GUIDE.md](docs/VALIDATOR_GUIDE.md) for validator participation.

## License

Apache-2.0
