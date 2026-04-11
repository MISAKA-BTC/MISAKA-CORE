# MISAKA Testnet — Public Node

この README は **stock public observer package** の使い方だけを扱います。

- public observer package の入口: `start-public-node.sh` / `start-public-node.command` / `start-public-node.bat`
- 公式 public testnet operator の入口: `scripts/testnet-deploy.sh`
- 既存 operator へ self-host validator として参加する入口: `scripts/testnet-join.sh --genesis-path ... --index ...`
- `scripts/start-node.sh` は generic source-build launcher であり、public package の入口ではありません
- `config/self-host-seeds.txt` は self-host / rehearsal 用の補助ファイルで、`start-public-node.*` は読みません

## ワンクリック起動

| OS | ファイル | 使い方 |
|---|---|---|
| **macOS** | `start-public-node.command` | Finder でダブルクリック（初回は右クリック→「開く」で Gatekeeper 回避） |
| **Windows** | `start-public-node.bat` | エクスプローラーでダブルクリック（SmartScreen は「詳細情報」→「実行」） |
| **Linux** | `start-public-node.sh` | ターミナルで `./start-public-node.sh` またはファイラから |

## パッケージ構成

```
<platform>/
├── misaka-node(.exe)               # 実行バイナリ
├── start-public-node.{sh,.command,.bat}  # ワンクリック launcher
└── config/
    ├── public-node.toml            # ノード設定 (chain_id=2)
    ├── genesis_committee.toml      # testnet genesis + operator pubkey
    ├── seeds.txt                   # 公式 seed (133.167.126.51:16110)
    └── seed-pubkeys.txt            # seed の ML-DSA-65 公開鍵 (PK-pinning 必須)
```

**v0.5.7+ から `bundled-validator.key` は配布されません**。起動時に ephemeral な `validator.key` が `misaka-data/` に自動生成され、ノードは observer mode で動作します (運営の authority からブロックを受信・検証するだけで、提案はしない)。

## 起動フロー

1. launcher を実行すると `misaka-data/validator.key` が自動生成される
2. `OBSERVER MODE` メッセージが出て、運営 seed `133.167.126.51:16110` に接続
3. 運営 authority からブロックが流れ始め、`highest_accepted_round` が増加
4. `curl http://127.0.0.1:3001/api/get_chain_info` で `"topology":"joined"`, `"peerCount":1` を確認

**運営側の要件**: observer mode は運営サーバーが `MISAKA_ACCEPT_OBSERVERS=1` で起動していることが前提です。公開 testnet の運営ノードは既にこの設定で稼働しています。

## 接続確認

```bash
curl http://127.0.0.1:3001/api/health
# => {"status":"ok","consensus":"mysticeti-equivalent",
#     "blocks":N,"round":N,"safeMode":{"halted":false}}

curl http://127.0.0.1:3001/api/get_chain_info
# => {"chain":"MISAKA Network","chainId":2,
#     "consensus":"Mysticeti-equivalent",
#     "version":"0.5.13","topology":"joined","nodeMode":"public",
#     "role":"observer","peerCount":1,
#     "status":{"current_round":N,"highest_accepted_round":N,...}}
```

正常に動作していれば `commitsTotal` が時間とともに増加します。

## ディレクトリ

- `misaka-data/` — チェーン状態と validator 鍵（初回起動時に作成）
- データを削除して初期化するには `misaka-data/` 全体を削除してから再起動

## 停止

ターミナルで `Ctrl+C`、または起動したウインドウを閉じてください。

## トラブル

| 症状 | 対処 |
|---|---|
| ポート 3001 / 16110 使用中 | 他プロセスを停止してから再起動 |
| macOS Gatekeeper | `start-public-node.command` を右クリック → 「開く」 |
| Windows SmartScreen | 「詳細情報」→「実行」 |
| Linux: 権限エラー | `chmod +x start-public-node.sh misaka-node` |
| `insufficient ancestors` / `peer_sig_verify_failed` ログ | v0.5.8 未満を使っている証拠です。v0.5.13 以降へアップグレードしてください |
| launcher が `seeds.txt / seed-pubkeys.txt mismatch` で停止 | stock package の config が壊れています。2 つのファイルを同じ件数に揃えて再試行 |
| `seeds.txt と seed-pubkeys.txt が空` で停止 | stock package の config が欠落しています。public observer package は official/public seed への join 専用で、solo self-host mode には入りません |
| `validator.key が genesis validator と一致` で停止 | operator/shared validator key を public package に混ぜています。`misaka-data/validator.key` を削除して observer key を再生成してください |
| `mode:"solo"` のまま | 運営 seed が到達不能、またはファイアウォールが 16110 を塞いでいる可能性 |

## セキュリティ

### 公開ポート

- **16110/tcp** (Narwhal relay) — 運営と他クライアントとの P2P 通信に使用。必要に応じて inbound を開けてください
- **3001/tcp** (RPC) — **loopback (127.0.0.1) にのみバインド**されます。**インターネットに晒さないでください**
- launcher は `MISAKA_RPC_AUTH_MODE=open` を設定するので、RPC が外部に露出すると認証なしで読み書きされます。公開が必要なら reverse proxy + Bearer auth + IP allowlist を別途設定してください

### Release asset の署名検証 (Sigstore cosign keyless)

GitHub Release の `SHA256SUMS` は Sigstore の keyless signing で署名されています (`SHA256SUMS.sig` + `SHA256SUMS.pem`)。配布経路全体の改竄検知ができます。

**cosign 2.x 以降** — そのまま verify できます:

```bash
# cosign のインストール: https://docs.sigstore.dev/system_config/installation/
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github\.com/sasakiyuuu/misaka-test-net/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

**cosign 1.x または検証がエラーになる場合** — GitHub Release の `SHA256SUMS.pem` / `SHA256SUMS.sig` は base64 1 行テキストで、一部の古い cosign は直接解釈できません。`base64 -d` を明示的に挟んでください:

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

`Verified OK` が出れば、この SHA256SUMS は当該リポジトリの GitHub Actions ワークフローから生成されたものであることが暗号学的に保証されます。

### ダウンロードしたアーカイブの SHA256 検証

```bash
# macOS / Linux
shasum -a 256 -c SHA256SUMS

# Windows (PowerShell)
Get-FileHash misaka-public-node-windows-x86_64.zip -Algorithm SHA256
```

`SHA256SUMS` 内のハッシュと一致することを確認してから展開してください。

### 運営 authority の fingerprint

`config/genesis_committee.toml` には運営の ML-DSA-65 公開鍵が焼き込まれています。`python3 -c "import hashlib; import re; ..."` で SHA3-256 fingerprint を計算し、GitHub Release の notes と照合することで、配布ミラーの改竄を検出できます。

## 別役割の入口

この README の対象は public observer package です。operator / self-host / source-build helper は別の入口を使ってください。

1. **公式 public testnet operator**
   - 入口は `scripts/testnet-deploy.sh`
   - `MISAKA_ACCEPT_OBSERVERS=1` と `--advertise-addr <public-ip>:16110` が前提です
   - RPC は原則 `127.0.0.1:3001` のまま扱い、外へ開ける場合だけ reverse proxy + auth を前段で付与します

2. **既存 operator へ self-host validator として参加**
   - 入口は `scripts/testnet-join.sh --genesis-path ... --index ...`
   - operator から共有された `genesis_committee.toml` を使います
   - `scripts/testnet-join.sh` は official `configs/testnet-seeds.txt` / `configs/testnet-seed-pubkeys.txt` を既定で読みます

3. **generic source-build launcher / custom topology / private rehearsal**
   - 入口は `scripts/start-node.sh`
   - これは lower-level helper です。`GENESIS_PATH` が無いまま `VALIDATORS=1` で実行すると local single-node genesis を自動生成します
   - public testnet へ join したいときの一次入口にはしないでください
