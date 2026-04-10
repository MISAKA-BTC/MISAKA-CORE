# MISAKA Testnet Launcher

MISAKA testnet に初心者でも参加しやすい形で入るための配布 repo です。

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
# => {"chainId":2,"version":"0.5.13","topology":"joined",
#     "nodeMode":"public","role":"observer","peerCount":1,...}
```

`topology` が `joined` になっていれば、運営 testnet のピアと接続している状態です。
`solo` の場合はピアに繋がれていない状態 (seed 到達不能や firewall など)。

### フィールドの意味

- **`topology`**: `solo` (peerCount=0) / `joined` (peerCount>0) — ネットワーク接続状態
- **`nodeMode`**: `public` / `hidden` / `seed` — CLI/config で指定した運用モード
- **`role`**: `observer` / `validator` — propose loop が回っているかどうか
- **`mode`**: `topology` の back-compat alias (将来削除予定)

## seed / genesis 情報

公開 testnet の正本:

- **Seed**: `133.167.126.51:16110` (Narwhal relay port)
- **Seed pubkey (ML-DSA-65)**: `config/seed-pubkeys.txt` に同梱済み
- **Genesis**: `config/genesis_committee.toml` に同梱済み
- **Chain ID**: `2`

配布パッケージにはこれらが全て揃っているので、追加のファイル編集なしで起動できます。seed pubkey は Narwhal relay の PK-pinning 必須なので、`seeds.txt` と `seed-pubkeys.txt` が 1:1 対応していることが `start-public-node.*` の内部で自動チェックされます。不一致なら launcher は solo mode に fallback します。

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

**v0.5.7+ から `bundled-validator.key` は配布されません**。起動時に ephemeral な `validator.key` が `misaka-data/` に自動生成され、ノードは observer mode で動作します (運営の authority からブロックを受信・検証するだけで、自分では提案しない)。

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
cd misaka-core-v4/docker
docker compose up -d
```

v0.5.12+ 以降、`docker/node-compose.yml` は `MISAKA_RPC_AUTH_MODE=open` をデフォルトで設定します (testnet のみ)。mainnet 相当で固めたい場合は `.env` で `MISAKA_RPC_AUTH_MODE=require` + `MISAKA_RPC_API_KEY=<key>` を明示してください。

## ソースからビルド

```bash
cd misaka-core-v4
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

CI の Linux ランナーでは apt の `clang` + `libclang-dev` で問題なく build が通っています (参照: `.github/workflows/build-public-node.yml`)。

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
