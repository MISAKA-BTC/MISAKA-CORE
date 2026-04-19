# MISAKA Testnet — Troubleshooting（v0.9.0）

> [`JOIN_TESTNET.md`](JOIN_TESTNET.md) の手順で躓いたときの個別対処集。
> 「これとこれを試してダメなら Discord `#testnet-support` に貼って」レベルの粒度で書いてあります。

---

## 目次

1. [ビルド / インストール編](#1-ビルド--インストール編)
2. [鍵生成編](#2-鍵生成編)
3. [起動失敗編](#3-起動失敗編)
4. [起動はしたが sync しない編](#4-起動はしたが-sync-しない編)
5. [peer 関連編](#5-peer-関連編)
6. [Quarantine / Slashing 編](#6-quarantine--slashing-編)
7. [Disk 容量 / 性能編](#7-disk-容量--性能編)
8. [アップグレード編](#8-アップグレード編)
9. [情報提出テンプレ](#9-情報提出テンプレ)

---

## 1. ビルド / インストール編

### 1.1 `error: could not find Cargo.toml` / `rust not found`

**原因**：Rust toolchain が PATH に通っていない。

**対処**：
```bash
source "$HOME/.cargo/env"
# または
export PATH="$HOME/.cargo/bin:$PATH"
```

`~/.bashrc` に上の line を追加しておくと再ログイン後も有効。

### 1.2 `linker 'cc' not found` / `libclang not found`

**原因**：build 依存パッケージ不足。

**対処**（Ubuntu）：
```bash
sudo apt install -y build-essential pkg-config libssl-dev clang libclang-dev cmake
```

macOS：
```bash
xcode-select --install
brew install cmake openssl
```

### 1.3 `cargo build` が OOM killed

**原因**：RAM 不足（`release` build は 3-4 GB 使う）。

**対処**：
- swap を 4 GB 増設：
  ```bash
  sudo fallocate -l 4G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  ```
- または pre-built release asset を使う（§2-B）

### 1.4 `git clone` が遅い / 途中で切れる

**対処**：shallow clone で十分：
```bash
git clone --depth 1 --branch main https://github.com/MISAKA-BTC/MISAKA-CORE.git
```

---

## 2. 鍵生成編

### 2.1 `keygen` コマンドが `unknown subcommand` で落ちる

**原因**：古い binary、または `--features dag,testnet` なしで build された binary。

**対処**：
```bash
cd ~/MISAKA-CORE
cargo clean
cargo build --release -p misaka-node --features "dag,testnet"
```

### 2.2 `MISAKA_VALIDATOR_PASSPHRASE is not set`

**原因**：環境変数未設定。

**対処**：
```bash
export MISAKA_VALIDATOR_PASSPHRASE="your-long-passphrase"
# 同じシェルで keygen を実行
```

systemd 運用時は `Environment=` か `MISAKA_VALIDATOR_PASSPHRASE_FILE=/run/secrets/...` を使う（[`JOIN_TESTNET.md`](JOIN_TESTNET.md) §7-B）。

### 2.3 `passphrase too short (minimum 8 chars)`

**対処**：16 文字以上推奨。パスワードマネージャー（Bitwarden, 1Password 等）で生成。

### 2.4 「パスフレーズ忘れた」

**対処**：復旧不可。`/var/lib/misaka/l1-*.json` を削除して新しい鍵で再登録する。運営 announce 前なら問題なし。announce 後は運営に古い public key の invalidate 依頼 + 新 key 提出。

---

## 3. 起動失敗編

### 3.1 `failed to open data dir: Permission denied`

**原因**：`/var/lib/misaka` の owner が root。

**対処**：
```bash
sudo chown -R $USER:$USER /var/lib/misaka
chmod 700 /var/lib/misaka
```

### 3.2 `failed to bind RPC: address already in use`

**原因**：port 3001 が他プロセスで使用中。

**対処**：
```bash
sudo ss -tlnp | grep 3001
# プロセスを特定して停止、または validator.toml で port 変更
```

### 3.3 `failed to bind P2P: address already in use` (port 16110)

**対処**：同じ要領で 16110 を確認。ホスト上で複数 node を走らせないこと。

### 3.4 `genesis hash mismatch: expected X, got Y`

**原因**：`genesis_committee.toml` が壊れている / 古い。

**対処**：
```bash
sha256sum ~/misaka-config/genesis_committee.toml
# announce 記載の期待 sha256 と比較
# 違ったら re-download
```

### 3.5 `genesis file not found`

**原因**：`--genesis-path` の指定ミス、または config 内 `genesis_path` 誤り。

**対処**：絶対パスで指定：
```bash
--genesis-path /home/ubuntu/misaka-config/genesis_committee.toml
```

### 3.6 `keystore decrypt failed` / `invalid passphrase`

**原因**：
- パスフレーズ typo
- `MISAKA_VALIDATOR_PASSPHRASE_FILE` の改行（末尾に `\n` が入っている）

**対処**：
```bash
# 末尾改行の有無を確認
xxd /run/secrets/validator_passphrase | tail -1

# 改行なしで書き直す
echo -n "your-passphrase" | sudo tee /run/secrets/validator_passphrase > /dev/null
sudo chmod 600 /run/secrets/validator_passphrase
```

### 3.7 `validator.key が genesis validator と一致しない`

**原因**：
- 運営に登録した public key と異なる鍵で起動している
- ephemeral observer key が validator mode で使われている

**対処**：
```bash
# 登録した fingerprint と今の fingerprint を比較
cat /var/lib/misaka/l1-public-key.json | jq -r .fingerprint

# 違っていたら、提出済み public key と一致する l1-secret-key.json を復元
# または運営に新 key を再提出
```

---

## 4. 起動はしたが sync しない編

### 4.1 `peerCount: 0` のまま 5 分以上

**原因候補**：
- Inbound 16110 が firewall で塞がれている
- Seed node が一時的に down
- 自ノードの advertise address が誤り（NAT 内で private IP を広報等）

**対処**：
1. Firewall 確認：
   ```bash
   sudo ufw status
   sudo iptables -L -n | head
   # 16110/tcp が REJECT/DROP されていないか
   ```
2. Seed 到達性：
   ```bash
   # announce で告知される seed IP
   nc -zv <seed-ip> 16110
   ```
3. `MISAKA_ADVERTISE_ADDR` 設定（NAT/Docker 環境）：
   ```bash
   export MISAKA_ADVERTISE_ADDR="<外向き IP>:16110"
   ```

### 4.2 `highest_accepted_round` が増えない

**原因**：committee に自分が入っていない（genesis に提出した public key が反映されていない）。

**対処**：
```bash
curl -s http://127.0.0.1:3001/api/get_chain_info | jq '.role,.peerCount'
# role が "observer" のままなら committee 外
```

→ 運営に `l1-public-key.json` が取り込まれたか確認。反映は next epoch 境界の場合がある。

### 4.3 `safeMode.halted: true`

**原因**：state_root mismatch 検出 → chain halt（自ノードのみ）。

**対処**：
```bash
# まず log を確認
grep -i "safe_mode\|state_root mismatch\|CRITICAL" /var/log/misaka-node.log | tail -20
```

→ 高確率で binary version mismatch（他 validator と別の commit）。
`sha256sum ~/MISAKA-CORE/target/release/misaka-node` を運営 announce の期待値と比較。
違う場合は upgrade。

安全な recovery：
```bash
sudo systemctl stop misaka-node
sudo rm -rf /var/lib/misaka/narwhal_consensus*
# 鍵は残す（l1-*.json は触らない）
sudo systemctl start misaka-node
```

---

## 5. peer 関連編

### 5.1 `peer X quarantined (reason: invalid_sig)`

**原因**：peer が古いバイナリで壊れた署名を流している、または自ノードの検証ロジックが古い。

**対処**：
- 自ノード binary を v0.9.0 に update
- それでも出る場合：運営に peer IP + log 抜粋を報告

### 5.2 `peer X quarantined (reason: equivocation)`

**原因**：peer が self-equivocation（同じ round で 2 ブロック署名）。Slashing 対象 byzantine behavior。

**対処**：自ノード側は自動で quarantine 済。運営に IP を報告（証拠は自動で `narwhal_consensus/equivocation_ledger/` に保存される）。

### 5.3 `block_request_response RTT > 5s`

**原因**：peer が loaded / ネットワーク遅延。

**対処**：一時的なら無視。継続する場合は `peer_scores.json` を見て低スコア peer を特定：
```bash
cat /var/lib/misaka/peer_scores.json | jq -r 'to_entries | sort_by(.value.score)[:5]'
```

---

## 6. Quarantine / Slashing 編

### 6.1 自分が Slash された

```bash
curl -s http://127.0.0.1:3001/api/validator/me | jq .state,.slash_history
```

- `state: "Slashed"` — active 外。stake から slashing 分が引かれた
- `slash_history` に理由が記録

**よくある slashing 事由**：
- **Downtime (1%)** — 0 blocks 提案で epoch 越え → uptime 0%
- **Self-equivocation (5-10%)** — 同じ key で複数ノード起動が原因大多数
- **Invalid block (varies)** — ルール違反ブロックを提案

**予防**：
- **1 key = 1 node の厳守**。鍵を別マシンで test 起動しない
- systemd `Restart=always` で downtime を最小化
- upgrade は 1 node ずつ staggered に

### 6.2 Quarantine 解除したい

Quarantine は peer-level で自動 expire（round window で）。手動解除は通常不要。
恒久化している場合：
```bash
# 該当 peer がもう正常に戻っている前提で
sudo systemctl restart misaka-node
```

---

## 7. Disk 容量 / 性能編

### 7.1 `/var/lib/misaka` が急増

**v0.9.0 基準の目安**：
- 初回起動時：< 100 MB
- 1 時間後：~30 MB 増（10 秒/block × 360 blocks ≈ 360 commits）
- 24 時間後：200-350 MB（目標）、最悪 500 MB

これを超えて膨らんでいる場合：
```bash
du -sh /var/lib/misaka/narwhal_consensus/*
```

- `blob-*.blob` が巨大（ZSTD が効いていない） → binary version 確認
- `sst/*.sst` が数万ファイル → compaction が追いついていない（CPU/disk i/o 不足）

**対処**：
- Archival mode を Pruned に切り替え（`validator.toml` の `[prune_mode]` 参照）
  ```toml
  [prune_mode]
  mode = "Pruned"
  keep_rounds = 10000     # 約 27 時間分、最小は 1000
  ```
- 上記を反映後 restart。古い SST は次の compaction で回収される

### 7.2 `/var/log/misaka-node.log` が 1 GB 超

**原因**：logrotate 未設定 または `log_level = "debug"`。

**対処**：
- `validator.toml` の `log_level = "info"` 確認
- logrotate 設定（[`JOIN_TESTNET.md`](JOIN_TESTNET.md) §7-B 末尾）

### 7.3 CPU 100% 張り付き

**原因候補**：
- 起動直後の catch-up（1-5 分、正常）
- compaction が連続発生
- 古い binary でメモリリーク

**対処**：
```bash
top -p $(pgrep misaka-node)
# %CPU が 5 分以上 100% なら
perf top -p $(pgrep misaka-node)     # もし perf が入っているなら
```

5 分超の 100% は abnormal。ログ抜粋を Discord に。

---

## 8. アップグレード編

### 8.1 v0.9.0 → v0.9.x minor upgrade

```bash
cd ~/MISAKA-CORE
git fetch origin main
git checkout main
git pull origin main
cargo build --release -p misaka-node --features "dag,testnet"

# Staggered restart（いきなり stop しない）
sudo systemctl stop misaka-node
sleep 2
sudo systemctl start misaka-node

# verification
curl http://127.0.0.1:3001/api/get_chain_info | jq '.version'
```

### 8.2 v0.9.x → v1.0 major upgrade（future）

**予定**：v1.0 は hard fork を含むため、announce で指定される activation epoch までに全 validator が upgrade 必要。
手順は announce 時に別 doc で提供されます。

### 8.3 アップグレード後に起動しない

**典型症状**：`schema version mismatch: expected 3, got 2`

**対処**：
```bash
sudo systemctl stop misaka-node
~/MISAKA-CORE/target/release/misaka-node \
  --data-dir /var/lib/misaka \
  migrate --to 3
sudo systemctl start misaka-node
```

---

## 9. 情報提出テンプレ

Discord `#testnet-support` や GitHub Issue に貼る用：

```
## 環境
- OS: Ubuntu 22.04
- CPU / RAM / Disk: 4 cores / 8 GB / 50 GB
- Binary version: `misaka-node --version` の出力
- Binary SHA256: `sha256sum ~/MISAKA-CORE/target/release/misaka-node` の出力

## 事象
<何をしようとして、何が起きたか。時系列で>

## ログ
<journalctl -u misaka-node --since "10 minutes ago" の関連 20-50 行>
（SECRET: パスフレーズ / 秘密鍵 / RPC Bearer token は含めないで）

## API 状態
curl -s http://127.0.0.1:3001/api/health
curl -s http://127.0.0.1:3001/api/get_chain_info
curl -s http://127.0.0.1:3001/api/get_peers | head -50

## 試した対処
<上のドキュメントの §N の項目を試した結果>
```

---

_最終更新：2026-04-19（v0.9.0 base）_
