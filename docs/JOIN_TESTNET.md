# MISAKA Testnet — 参加ガイド（v0.9.0）

> このドキュメントは **MISAKA 公式 testnet に validator として新規参加** するための
> 単一経路ガイドです。これを上から順に実行するだけで testnet に参加できます。
>
> **observer mode（同期だけする、validator ではない）** で参加したい方は
> [`distribution/public-node/README.md`](../distribution/public-node/README.md)
> を参照してください。本書は**提案権を持つ validator になる**場合の手順です。

---

## 📣 現在のアナウンス状況

- **v0.9.0 testnet は準備中です**（2026-04-19 時点）
- 運営から公式 announce（Discord / X）が出るまでは **鍵生成まで先行して準備可能**
- Announce 受領後に `§5 運営への鍵登録` 以降を実行してください

運営 announce 内容の想定：
- 起動日時（UTC）
- 4 seed node の IP / ポート
- `genesis_committee.toml` の配布 URL
- `chain_id`（2 = testnet、固定）

---

## 0. このチェーンでやること

| 項目 | 内容 |
|---|---|
| Consensus | Narwhal / Bullshark DAG（Mysticeti 系） |
| Signature | ML-DSA-65（FIPS 204 / Post-Quantum） |
| State commitment | Sparse Merkle Tree（v5、v0.9.0 ハードフォーク後 canonical） |
| Block time | 10 秒（fast lane） |
| Chain ID | `2`（testnet） |
| Min stake | 100,000 MSK（testnet は faucet で配布） |

---

## 1. 事前準備（マシン要件）

### ハードウェア

| 用途 | 最小 | 推奨 |
|---|---|---|
| CPU | 2 コア | 4 コア |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 50 GB（90 日運用） |
| Network | 上り下り 10 Mbps | 100 Mbps |

### ソフトウェア

- Ubuntu 22.04 LTS（推奨）または macOS 13+
- `sudo` 権限
- ポート **16110/tcp**（Narwhal relay）が inbound 到達可能
- ポート **3001/tcp**（RPC）は **loopback のみ**でよい（外部に出すな）

### 依存パッケージ（Ubuntu）

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev clang libclang-dev cmake curl git
```

### Rust（ビルドから入れる場合のみ）

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install stable
```

Pre-built binary を使う場合は Rust 不要（§2-B 参照）。

---

## 2. バイナリ入手

### A. Source から build（推奨、最新版が確実に入る）

```bash
cd ~
git clone https://github.com/MISAKA-BTC/MISAKA-CORE.git
cd MISAKA-CORE
git checkout main
cargo build --release -p misaka-node --features "dag,testnet"
```

成功すると `target/release/misaka-node` にバイナリが生成されます（約 16 MiB）。

### B. Pre-built release asset

v0.9.0 の release asset は [GitHub Releases](https://github.com/MISAKA-BTC/MISAKA-CORE/releases) で配布予定です。
Announce 後に以下のように取得：

```bash
# announce 後に実際の URL に置換
VERSION="0.9.0"
curl -L -o misaka-node.tar.gz \
  "https://github.com/MISAKA-BTC/MISAKA-CORE/releases/download/v${VERSION}/misaka-node-linux-amd64.tar.gz"
tar -xzf misaka-node.tar.gz
chmod +x misaka-node
```

配布 asset には Sigstore cosign keyless 署名が付きます。検証コマンドは
[`distribution/public-node/README.md` §Release asset の署名検証](../distribution/public-node/README.md) を参照。

---

## 3. データディレクトリ + 設定

```bash
# データ置き場を作る（鍵 + chain state）
sudo mkdir -p /var/lib/misaka
sudo chown $USER:$USER /var/lib/misaka
chmod 700 /var/lib/misaka

# 設定ファイル置き場
mkdir -p ~/misaka-config
```

### 設定ファイル `~/misaka-config/validator.toml`

announce 後にリリースされる `genesis_committee.toml` は別ファイルです。
`validator.toml` はあなた固有の起動設定：

```toml
[chain]
chain_id = 2
chain_name = "MISAKA Testnet"

[node]
mode = "validator"
data_dir = "/var/lib/misaka"
log_level = "info"

[p2p]
# Narwhal relay は genesis_committee.toml の network_address で決まるため
# ここは legacy GhostDAG 互換パスのみで使われる fallback 値。変更不要。
port = 6691
max_inbound_peers = 32
max_outbound_peers = 8

[rpc]
# RPC は loopback のみ。外部に出す場合は reverse proxy + Bearer auth 必須。
port = 3001

[consensus]
fast_block_time_secs = 10   # v0.8.9 以降は 10 秒

[faucet]
enabled = false             # testnet 参加者は disable で良い

[security]
require_encrypted_keystore = true

[prune_mode]
# "Archival" (全履歴保持) または "Pruned { keep_rounds = N }" (N round 超を prune)
mode = "Archival"
```

---

## 4. Validator 鍵の生成

**パスフレーズを決めてください**（16 文字以上、忘れないもの、パスワードマネージャー推奨）。
**このパスフレーズは運営に送らない**。公開鍵のみ送ります。

```bash
# PASSPHRASE 環境変数に入れて keygen
export MISAKA_VALIDATOR_PASSPHRASE="<あなたの長いパスフレーズ>"

~/MISAKA-CORE/target/release/misaka-node \
  --chain-id 2 \
  --data-dir /var/lib/misaka \
  keygen
```

生成されるファイル：
- `/var/lib/misaka/l1-secret-key.json` — **暗号化済み秘密鍵**（漏らさない、バックアップ取る）
- `/var/lib/misaka/l1-public-key.json` — 公開鍵（これを運営に送る）

### パスフレーズは環境変数で持ち回りたくない場合

Docker secrets 方式（本番向け、詳細は [`VALIDATOR_GUIDE.md`](VALIDATOR_GUIDE.md) §2）：

```bash
sudo mkdir -p /run/secrets
echo "<パスフレーズ>" | sudo tee /run/secrets/validator_passphrase > /dev/null
sudo chmod 600 /run/secrets/validator_passphrase
```

起動時に `/run/secrets/validator_passphrase` を自動で読みます。

### バックアップ（超重要）

```bash
# 秘密鍵を暗号化したまま別マシンにコピー
scp /var/lib/misaka/l1-secret-key.json user@backup-host:/safe/place/
```

**秘密鍵を失うと validator 権限を復旧できません**。
slashing 回避のため一度だけバックアップしてください。

---

## 5. 運営への鍵登録（announce 後）

運営 announce に従って、`l1-public-key.json` の内容を提出してください。
想定される提出方法（announce で決定）：

- **Discord フォーム**（`#validator-registration` チャンネル）
- **GitHub Issue template**
- **REST API**（`POST /api/v1/validator/register`）

**提出する内容**：

```bash
cat /var/lib/misaka/l1-public-key.json
# → { "public_key": "0xABCDEF...", "scheme": "MlDsa65", "fingerprint": "..." }
```

この JSON 全体を貼り付け。他の情報（パスフレーズ、IP、任意のメモ等）は求められない限り不要。

運営側で genesis に取り込む処理が完了すると、次の announce で
`genesis_committee.toml` の更新版と起動日時が告知されます。

---

## 6. Genesis + seed の配置

Announce で告知される URL から `genesis_committee.toml` を取得して `~/misaka-config/` に置きます：

```bash
curl -L -o ~/misaka-config/genesis_committee.toml \
  "<announce で公開される URL>"

# SHA-256 を検証（announce に記載される値と一致することを確認）
sha256sum ~/misaka-config/genesis_committee.toml
```

中身は概ね：

```toml
[chain]
chain_id = 2
genesis_hash = "0x..."

[[validators]]
public_key = "0x..."
network_address = "1.2.3.4:16110"
reward_address = "misakatest1..."

# (validators エントリが人数分続く)
```

---

## 7. 起動

### A. 手動起動（動作確認用）

```bash
export MISAKA_VALIDATOR_PASSPHRASE="<あなたのパスフレーズ>"

~/MISAKA-CORE/target/release/misaka-node \
  --config ~/misaka-config/validator.toml \
  --genesis-path ~/misaka-config/genesis_committee.toml \
  run
```

起動ログの確認ポイント：

```
[INFO]  validator mode: VALIDATOR
[INFO]  peer 1.2.3.4:16110 connected
[INFO]  epoch=0 round=0 committee_size=N
[INFO]  Committed: index=1, txs=0 (accepted=0), ...
```

`Committed: index=X` が増えていけば正常参加成功です。

### B. systemd で常駐（推奨、本番運用）

`/etc/systemd/system/misaka-node.service`：

```ini
[Unit]
Description=MISAKA Network Validator Node
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu
Environment="MISAKA_VALIDATOR_PASSPHRASE_FILE=/run/secrets/validator_passphrase"
ExecStart=/home/ubuntu/MISAKA-CORE/target/release/misaka-node \
  --config /home/ubuntu/misaka-config/validator.toml \
  --genesis-path /home/ubuntu/misaka-config/genesis_committee.toml \
  run
Restart=always
RestartSec=10
LimitNOFILE=65536
StandardOutput=append:/var/log/misaka-node.log
StandardError=append:/var/log/misaka-node.log

[Install]
WantedBy=multi-user.target
```

有効化：

```bash
sudo systemctl daemon-reload
sudo systemctl enable misaka-node
sudo systemctl start misaka-node
sudo systemctl status misaka-node
```

ログ確認：

```bash
sudo tail -f /var/log/misaka-node.log
# または
sudo journalctl -u misaka-node -f
```

### Logrotate（推奨）

`/etc/logrotate.d/misaka`：

```
/var/log/misaka-node.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

---

## 8. 動作確認

### REST API で自ノード状態

```bash
curl -s http://127.0.0.1:3001/api/health | jq .
# → {"status":"ok","consensus":"mysticeti-equivalent",
#    "blocks":N,"round":N,"safeMode":{"halted":false}}

curl -s http://127.0.0.1:3001/api/get_chain_info | jq .
# → { "chainId": 2, "version": "0.9.0", "topology": "joined",
#     "nodeMode": "validator", "role": "validator",
#     "peerCount": N, ...}

curl -s http://127.0.0.1:3001/api/get_peers | jq .
# → [他の validator + observer の一覧]
```

### 正常条件

- `/api/health` → `"status": "ok"`、`"safeMode.halted": false`
- `/api/get_chain_info` → `"role": "validator"`、`"peerCount"` が committee サイズ-1 に達する
- `current_round` が時間とともに **1 分で 6 round 程度** 進む（10 秒/block）
- ログに `Committed: index=...` が継続的に出現
- **エラーログに `quarantined` / `CRITICAL` / `Epoch race` が出ない**

---

## 9. よくあるエラー → 対処

詳細は [`JOIN_TESTNET_TROUBLESHOOTING.md`](JOIN_TESTNET_TROUBLESHOOTING.md) 参照。
頻出 3 件：

### A. `peer X quarantined (reason: ...)`

原因：古いバイナリ、または genesis mismatch。
対処：
```bash
# バイナリと genesis の sha256 を再確認
sha256sum ~/MISAKA-CORE/target/release/misaka-node
sha256sum ~/misaka-config/genesis_committee.toml
# announce に記載されている期待値と一致するか
```

### B. `Insufficient ancestors` / `peer_sig_verify_failed`

原因：PEER_REPLAY_ROUND_WINDOW が届かない古いバイナリ。
対処：v0.9.0 以降に upgrade（`git pull && cargo build --release ...` または release asset 更新）。

### C. `validator.key が genesis validator と一致しない`

原因：observer mode 用に生成された鍵で validator mode に入ろうとしている、または鍵を生成し直した。
対処：運営に register した public key と `/var/lib/misaka/l1-public-key.json` の fingerprint が一致するか確認。
違っている場合：

```bash
# 秘密鍵を消して再登録（運営 announce 前なら問題なし）
rm /var/lib/misaka/l1-*.json
# §4 から再実行して再提出
```

---

## 10. セキュリティ注意点

### 絶対やってはいけない

- ❌ RPC (3001/tcp) を `0.0.0.0` にバインドして公開
- ❌ パスフレーズを Git 管理下のファイルに書く
- ❌ 秘密鍵 (`l1-secret-key.json`) を複数 validator で使い回す（**slashing 事由**）
- ❌ 同じ validator key で複数ノードを起動（**self-equivocation → 即 slash**）

### やるべき

- ✅ Narwhal relay port (16110/tcp) のみ inbound 開放、RPC は loopback のみ
- ✅ 秘密鍵を暗号化したまま別マシンにバックアップ
- ✅ systemd + logrotate + 自動 restart (`Restart=always`)
- ✅ ディスク空き容量を週次でチェック（Archival mode は 1 日 200-350 MB 増加目安）
- ✅ v0.9.0 → 次リリースへの upgrade は announce に従う

---

## 11. 停止・退出

### 一時停止

```bash
sudo systemctl stop misaka-node
```

### 完全に退出（validator から抜ける）

```bash
# 1. 運営に退出申請（Discord / GitHub Issue）
# 2. 運営が次の epoch 境界で active → exiting に遷移
# 3. Unbonding 期間（testnet は短く設定）後、stake が返却
# 4. ノード停止
sudo systemctl stop misaka-node
sudo systemctl disable misaka-node

# 5. データ削除（再参加予定がないなら）
sudo rm -rf /var/lib/misaka
```

**途中で勝手に停止 → slashing 対象**になりえます。運営に連絡を。

---

## 12. サポート / 質問

- **Discord** — `#testnet-support`（announce で URL 公開）
- **GitHub Issue** — https://github.com/MISAKA-BTC/MISAKA-CORE/issues（label: `question`, `testnet-join`）
- **troubleshooting 詳細** — [`docs/JOIN_TESTNET_TROUBLESHOOTING.md`](JOIN_TESTNET_TROUBLESHOOTING.md)
- **operator 向け runbook** — [`docs/ops/VALIDATOR_RUNBOOK.md`](ops/VALIDATOR_RUNBOOK.md)

---

## 付録 A: Quick checklist

announce 受領後、上から順にチェック：

- [ ] §1 のハードウェア / OS 要件を満たす
- [ ] §2 で `misaka-node` バイナリを入手（source build か release asset）
- [ ] §3 で `/var/lib/misaka` と `~/misaka-config/validator.toml` を作成
- [ ] §4 で validator 鍵を生成（パスフレーズをパスワードマネージャーに保存）
- [ ] `l1-secret-key.json` をバックアップ
- [ ] §5 で `l1-public-key.json` を運営に提出
- [ ] §6 で `genesis_committee.toml` を配置（sha256 確認）
- [ ] §7 で起動（systemd 推奨）
- [ ] §8 で `/api/health` と `/api/get_chain_info` を確認
- [ ] §10 のセキュリティチェックリストを確認
- [ ] Discord `#testnet-support` に join して Announce ch を watch

---

## 付録 B: Glossary

- **Committee** — 当該 epoch の active validator の集合
- **Epoch** — MISAKA の時代区分（testnet は 1 epoch = 1 hour 想定、announce で確定）
- **Narwhal relay (16110)** — 他 validator + observer との P2P 通信
- **RPC (3001)** — ローカル管理・情報取得用 HTTP API
- **Observer mode** — 提案権を持たず chain 同期のみ行うノード
- **Validator mode** — committee の一員として block 提案・投票を行うノード
- **Self-equivocation** — 同じ round で複数のブロックに署名する byzantine behavior、自動検出 → slashing

---

_最終更新：2026-04-19（v0.9.0 base）_
