# MISAKA Testnet Launcher

MISAKA testnet に初心者でも参加しやすい形で入るための配布 repo です。

**現在のノード配布バージョン: v0.8.6**（[`misaka-test-net` Releases](https://github.com/sasakiyuuu/misaka-test-net/releases/latest)）

## ダウンロード

| Platform | File |
|---|---|
| Windows x86_64 | [misaka-public-node-windows-x86_64.zip](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-windows-x86_64.zip) |
| macOS arm64 | [misaka-public-node-macos-arm64.tar.gz](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-macos-arm64.tar.gz) |
| Linux x86_64 | [misaka-public-node-linux-x86_64.tar.gz](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz) |
| SHA256 | [SHA256SUMS](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/SHA256SUMS) |
| 署名 (Sigstore) | [SHA256SUMS.sig](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/SHA256SUMS.sig) + [SHA256SUMS.pem](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/SHA256SUMS.pem) |

最新 release 一覧: <https://github.com/sasakiyuuu/misaka-test-net/releases/latest>

## 使い方

### Windows

1. zip を展開
2. `start-public-node.bat` をダブルクリック

### macOS

1. tar.gz を展開
2. `start-public-node.command` をダブルクリック

もし macOS が「Mac に損害を与える可能性があるため開けません」などと表示した場合は、展開したフォルダに対して一度だけ quarantine を外してください。

```bash
xattr -dr com.apple.quarantine <展開したフォルダ名>
```

### Linux

1. tar.gz を展開
2. `./start-public-node.sh` を実行

## 動作確認

ノード起動後、別のターミナルで状態を確認できます:

```bash
curl http://127.0.0.1:3001/api/health
# => {"status":"ok","consensus":"mysticeti-equivalent",
#     "blocks":N,"round":N,"safeMode":{"halted":false}}

curl http://127.0.0.1:3001/api/get_chain_info
# => {"chainId":2,"version":"0.8.6","topology":"joined",
#     "nodeMode":"public","role":"observer","peerCount":1,...}
```

`topology` が `joined` になっていれば、運営 testnet のピアと接続している状態です。
`solo` の場合はピアに繋がれていない状態 (seed 到達不能や firewall など)。

### フィールドの意味

- **`topology`**: `solo` (peerCount=0) / `joined` (peerCount>0) — ネットワーク接続状態
- **`nodeMode`**: `public` / `hidden` / `seed` — CLI/config で指定した運用モード
- **`role`**: `observer` / `validator` — propose loop が回っているかどうか
- **`mode`**: `topology` の back-compat alias (将来削除予定)

## バックグラウンド運用 (Linux)

### systemd (推奨)

```bash
sudo tee /etc/systemd/system/misaka-node.service << 'EOF'
[Unit]
Description=MISAKA Testnet Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/misaka/misaka-public-node-linux-x86_64
ExecStart=/home/$USER/misaka/misaka-public-node-linux-x86_64/start-public-node.sh
Environment=MISAKA_RPC_AUTH_MODE=open
Environment=MISAKA_ACCEPT_OBSERVERS=1
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

### pm2 (Node.js ユーザー向け)

pm2 は Node.js 以外のプロセスも管理できます。自動再起動・ログローテーション付き。

```bash
# pm2 インストール (未導入の場合)
npm install -g pm2

# ノード起動
cd ~/misaka/misaka-public-node-linux-x86_64
pm2 start ./start-public-node.sh --name misaka-node

# API プロキシも起動する場合
MISAKA_API_CORS_ORIGINS="*" pm2 start ./misaka-api \
  --name misaka-api -- --node http://127.0.0.1:3001 --port 4000

# OS 再起動時に自動起動
pm2 save
pm2 startup

# ログ確認・状態確認
pm2 logs misaka-node --lines 50
pm2 status
```

## 更新方法

新バージョンがリリースされたら、以下の手順でバイナリを差し替えます。
`misaka-data/` は残るため、ブロック高やウォレット残高は再起動後も維持されます。

```bash
cd ~/misaka

# 1. 新バージョンをダウンロード
wget https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz -O new.tar.gz
tar xzf new.tar.gz -C /tmp/

# 2. ノード停止
pm2 stop misaka-node misaka-api        # pm2 の場合
# sudo systemctl stop misaka-node      # systemd の場合

# 3. バイナリ差し替え
cp /tmp/misaka-public-node-linux-x86_64/misaka-node misaka-public-node-linux-x86_64/
cp /tmp/misaka-public-node-linux-x86_64/misaka-api  misaka-public-node-linux-x86_64/

# 4. 再起動
pm2 restart misaka-node misaka-api     # pm2 の場合
# sudo systemctl start misaka-node     # systemd の場合

# 5. 確認
curl -s http://127.0.0.1:3001/api/health
```

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| `RPC auth config error: FATAL` | API Key 未設定 | `export MISAKA_RPC_AUTH_MODE=open` するか `start-public-node.sh` を使う |
| `OBSERVER MODE` ログ | 正常動作 | 対処不要。ブロック受信・検証は行われる |
| `SOLO MODE` ログ | seeds 未指定 | `start-public-node.sh` を使うか `--seeds` + `--seed-pubkeys` を指定 |
| `sub-DAG block data unavailable` | 再起動後の DAG ギャップ | 自動回復を待つ (100 ラウンド以内) |
| ブロック高が 0 に戻る | スナップショット未作成 | 100 コミット以上進むまで待つ |
| macOS `quarantine` エラー | Gatekeeper ブロック | `xattr -d com.apple.quarantine ./misaka-node` |
| Windows `was unexpected at this time` | パス中の括弧 | パスに `(` `)` を含まないフォルダに展開 |
| GitHub の `releases/latest/download/...` が **404** | 別リポジトリの URL や、リリース未作成のタグ | **Assets** から直接取得: [misaka-test-net Releases](https://github.com/sasakiyuuu/misaka-test-net/releases/latest) |

## seed / genesis 情報

公開 testnet の正本:

- **Seed**: `133.167.126.51:16110` (Narwhal relay port)
- **Seed pubkey (ML-DSA-65)**: `config/seed-pubkeys.txt` に同梱済み
- **Genesis**: `config/genesis_committee.toml` に同梱済み
- **Chain ID**: `2`

配布パッケージにはこれらが全て揃っているので、追加のファイル編集なしで起動できます。seed pubkey は Narwhal relay の PK-pinning 必須なので、`seeds.txt` と `seed-pubkeys.txt` が 1:1 対応していることが `start-public-node.*` の内部で自動チェックされます。不一致なら launcher は solo mode に fallback します。

## バリデーター登録 / 削除 API

テストネットでは、バリデーターの登録・削除を REST API で行えます。

公開エンドポイントは **`https://misakascan.com`** に向けてください。
misaka-api は MISAKA testnet オペレーターが運用する https://misakascan.com 配下にリバースプロキシされています。直接 IP + ポート（例 `http://<validator-ip>:4000`）や `seed.misakachain.com` / `testnet.misaka-network.com` といった旧ドメインは現在使えません。

### 登録

```bash
curl -X POST https://misakascan.com/api/register_validator \
  -H 'Content-Type: application/json' \
  -d '{
    "public_key": "0x<ML-DSA-65 公開鍵 hex>",
    "network_address": "203.0.113.10:16110",
    "intent_signature": "0x<ML-DSA-65 sig hex, 任意>",
    "solana_stake_signature": "<Solana TX signature, 任意>"
  }'
# => {
#   "ok": true,
#   "message": "registered as validator #2",
#   "note": "committee reloaded (no restart needed)",
#   "intent_verified": true,
#   "stake_verification": "pending"
# }
```

同じ `public_key` で再度呼んだ場合は `"already registered"` が返り、重複登録にはなりません。

**0.9.0 β-3 以降**: `intent_signature` と `solana_stake_signature` の意味、`stake_verification` レスポンスフィールド (`pending` / `skipped` / `bypassed`)、および testnet 専用の `--allow-unverified-validators` フラグについては [`docs/VALIDATOR_GUIDE.md` §7](docs/VALIDATOR_GUIDE.md) を参照してください。

### 削除

`public_key` または `network_address`（もしくは両方）を指定して、登録済みバリデーターを削除します。

```bash
# public_key で削除
curl -X POST https://misakascan.com/api/deregister_validator \
  -H 'Content-Type: application/json' \
  -d '{"public_key": "0x<削除したい公開鍵 hex>"}'

# network_address で削除
curl -X POST https://misakascan.com/api/deregister_validator \
  -H 'Content-Type: application/json' \
  -d '{"network_address": "[2a01:4f9:c012:71e8::1]:6691"}'
# => {"ok":true,"message":"removed 1 validator(s)","remaining":1,"note":"committee reloaded (no restart needed)"}
```

### コミッティ確認

現在登録されているバリデーター一覧を取得できます。

```bash
curl https://misakascan.com/api/get_committee
# => {"epoch":0,"validators":[{"authority_index":0,...},{"authority_index":1,...}]}
```

### Python スクリプト

`scripts/register_validator_example.py` でも登録・削除が行えます。

```bash
pip install requests

# 登録
python3 scripts/register_validator_example.py register \
  --public-key 0xabcdef... --address 203.0.113.10:16110

# 削除 (アドレス指定)
python3 scripts/register_validator_example.py deregister \
  --address "[2a01:4f9:c012:71e8::1]:6691"

# 削除 (公開鍵指定)
python3 scripts/register_validator_example.py deregister \
  --public-key 0xabcdef...
```

> **注意**: 登録・削除後はシードノードの再起動が必要です。反映までタイムラグがあります。

### トラブルシューティング

| 症状 | 原因 | 対処 |
|---|---|---|
| `nslookup seed.misakachain.com` が NXDOMAIN | 旧ドメイン。現在未使用 | `https://misakascan.com` を使う |
| `Test-NetConnection <host> -Port 4000` TcpTestSucceeded : False | ポート 4000 は外部公開されていない（nginx 経由のみ） | HTTPS (443) 経由で `https://misakascan.com/api/...` を叩く |
| 登録後も `observer mode` のまま | ノード起動時に `--validator` フラグが付いていない、または committee hot-reload が 1 サイクル分遅延 | 起動コマンドに `--validator` を追加し、数秒後に `GET https://misakascan.com/api/get_committee` で自分が含まれているか確認 |
| `stake_verification: "pending"` のまま | Solana stake 未検証。testnet ではネットワーク側が `--allow-unverified-validators` でない限り昇格しない | testnet 運営に連絡するか、ガイド §7 の Solana 環境変数を確認 |

外部から到達性を確認する最小コマンド:

```bash
# DNS + TLS 疎通
curl -s https://misakascan.com/v1/chain/info | head -c 200

# 登録 API の疎通 (POST body は何でも良い — 404/400 以外が返れば到達している)
curl -s -X POST https://misakascan.com/api/register_validator   -H Content-Type: application/json   -d {}
```

Windows PowerShell:

```powershell
Resolve-DnsName misakascan.com    # → 133.167.126.51 が返れば OK
Test-NetConnection misakascan.com -Port 443
Invoke-RestMethod https://misakascan.com/v1/chain/info
```


## 含まれているもの

各プラットフォームの配布物は以下の構成です:

```
misaka-public-node-<platform>/
├── misaka-node(.exe)             # ノードバイナリ
├── start-public-node.sh          # Linux / macOS 起動スクリプト
├── start-public-node.command     # macOS 用ダブルクリック launcher (macOS only)
├── start-public-node.bat         # Windows 用ダブルクリック launcher (Windows only)
└── config/
    ├── public-node.toml          # ノード設定 (chain_id=2)
    ├── genesis_committee.toml    # 起動用委員会マニフェスト (operator pubkey pinned)
    ├── seeds.txt                 # 公式 seed 接続先
    └── seed-pubkeys.txt          # seed の ML-DSA-65 公開鍵 (PK-pinning 必須)
```

**v0.8.x 配布では `bundled-validator.key` は含まれません**。起動時に ephemeral な `validator.key` が `misaka-data/` に自動生成され、ノードは observer mode で動作します (運営の authority からブロックを受信・検証するだけで、自分では提案しない)。

## 検証（オプション）

リリースアセットは Sigstore cosign で keyless 署名されています。

**cosign 2.x 以降** — そのまま verify:

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github\.com/sasakiyuuu/misaka-test-net/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

**cosign 1.x または直接検証がエラーになる場合** — `SHA256SUMS.pem` / `SHA256SUMS.sig` は base64 1 行テキストで、一部の古い cosign では先に decode が必要です:

```bash
base64 -d SHA256SUMS.pem > SHA256SUMS.decoded.pem
base64 -d SHA256SUMS.sig > SHA256SUMS.decoded.sig
cosign verify-blob \
  --certificate SHA256SUMS.decoded.pem \
  --signature SHA256SUMS.decoded.sig \
  --certificate-identity-regexp 'https://github\.com/sasakiyuuu/misaka-test-net/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

`Verified OK` が出れば、SHA256SUMS は当該リポジトリの GitHub Actions ワークフローから生成されたものであることが暗号学的に保証されます。次に SHA256 ハッシュの一致確認:

```bash
sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS
```

## Docker (source build)

```bash
cd misaka-core-v4/misaka-core-v4/docker
docker compose up -d
```

v0.5.12+ 以降、`docker/node-compose.yml` は `MISAKA_RPC_AUTH_MODE=open` をデフォルトで設定します (testnet のみ)。mainnet 相当で固めたい場合は `.env` で `MISAKA_RPC_AUTH_MODE=require` + `MISAKA_RPC_API_KEY=<key>` を明示してください。

## ソースからビルド

```bash
cd misaka-core-v4/misaka-core-v4
cargo build --release -p misaka-node --features dag,testnet
```

必要な依存: Rust stable (rustup)、clang / libclang、cmake。RocksDB bindgen が `stdbool.h` を要求するため、一部の minimal Linux image では追加設定が必要です。

### `librocksdb-sys` で `stdbool.h not found` エラーが出る場合

ホスト環境によっては bindgen が system header を見つけられず、以下のエラーで build が止まることがあります:

```
fatal error: 'stdbool.h' file not found
```

これは bindgen の clang が libc headers の場所を知らないのが原因です。`BINDGEN_EXTRA_CLANG_ARGS` で include path を明示して回避できます:

```bash
# Ubuntu 22.04 / gcc 11
BINDGEN_EXTRA_CLANG_ARGS='-isystem /usr/lib/gcc/x86_64-linux-gnu/11/include' \
  cargo build --release -p misaka-node --features dag,testnet

# Ubuntu 24.04 / gcc 13
BINDGEN_EXTRA_CLANG_ARGS='-isystem /usr/lib/gcc/x86_64-linux-gnu/13/include' \
  cargo build --release -p misaka-node --features dag,testnet

# macOS (brew install llvm)
export LIBCLANG_PATH=$(brew --prefix llvm)/lib
cargo build --release -p misaka-node --features dag,testnet
```

CI の Linux ランナーでは apt の `clang` + `libclang-dev` で問題なく build が通っています (参照: [`.github/workflows/build-public-node.yml`](.github/workflows/build-public-node.yml))。

## GitHub Actions（配布ビルド）

- **ワークフロー**: [`.github/workflows/build-public-node.yml`](.github/workflows/build-public-node.yml) — Linux / Windows / macOS で `misaka-public-node-*` アーカイブを生成
- **手動実行**: リポジトリの **Actions** → **build-public-node** → **Run workflow**
- **Release 公開**: タグ `v*`（例: `v0.8.6`）を push → `[workspace.package] version`（`misaka-core-v4/Cargo.toml`）と一致させる（CI が検証）→ Assets と `SHA256SUMS`（Sigstore 署名付き）が付く
- **404 で落とせない場合**: [Releases](https://github.com/sasakiyuuu/misaka-test-net/releases/latest) の **Assets** から直接取得。別リポジトリの `releases/latest/download/...` は 404 になります

## 技術仕様

- **署名**: ML-DSA-65 (FIPS 204, Post-Quantum)
- **鍵交換 (P2P)**: ML-KEM-768 (FIPS 203) + ChaCha20-Poly1305 AEAD
- **コンセンサス**: Narwhal DAG-based BFT (Mysticeti-equivalent)
- **ブロック時間**: ~100 ms (fast lane)
- **Chain ID**: 2 (testnet)

## 運用上の注意

### RPC ポートの公開

launcher は `MISAKA_RPC_AUTH_MODE=open` で起動します。RPC (port 3001) は **loopback (127.0.0.1)** のみにバインドされるので、デフォルトではインターネットから直接叩けません。リバースプロキシ経由で外部公開する場合は Bearer auth と IP allowlist を必ず設定してください。

### ブロック放送チャネル

内部の `block_broadcast_tx` チャネルは容量 **500** の `tokio::mpsc` で、コンセンサスループは `try_send` で non-blocking に送信します。チャネルが満杯のときは **新規ブロックをドロップ**して `Block broadcast channel full` を WARN ログに出します (意図的な挙動 — コンセンサスループを P2P バックプレッシャで詰まらせないため)。

### WAL ストア

プロダクションビルド (`--features dag,testnet`) では **WAL ストア必須**です。`spawn_consensus_runtime` が `store = None` で呼ばれると即 panic します。

### Safe-mode halt

v0.5.9 以降、`state_root` 不一致を検知すると安全側で halt します:

- コミットループが停止
- propose loop が停止
- write RPC (`/api/submit_tx`, `/api/faucet` 等) が 503 相当を返す
- `/api/health` と `/api/get_chain_info` に `safeMode: {halted: true, haltedAtCommit, reason}` が surface する

halt は process global で、inside からは解除できません。運営が状態の不一致を調査してから restart してください。

## 補足

- 一般参加者向けの入口は `start-public-node.*` のみです
- Docker 向け設定と source は `misaka-core-v4` に入っています
- クロスプラットフォームビルドは GitHub Actions で自動化されています
- 過去バージョンのセキュリティ修正履歴は `misaka-core-v4/docs/` および各 release の notes を参照
