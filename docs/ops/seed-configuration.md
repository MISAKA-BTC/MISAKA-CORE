# Operator Guide — Seed Configuration（v0.9.0+）

このドキュメントは **validator / observer を seed node に接続する** ときの運用ガイドです。
設計根拠は [`docs/design/phase_p0_multi_seed.md`](../design/phase_p0_multi_seed.md) を参照。

---

## 1. Seed とは

**Seed = bootstrap 用の既知 peer**。chain state のない新規 node が最初に接続する相手で、
committee membership や peer gossip を通じて network に合流します。MISAKA testnet は
4 seed 構成（`authority_index 0..3`）を推奨しています。

### Seed の責務

- **Inbound 16110/tcp を公開**して新規 node からの dial を受ける
- **自ノードの PK を公開**して、接続者が PK-pinning できる状態にする
- 24/7 稼働（1 seed down では network は維持されるが、複数 down で新規 join が困難に）

### Seed と通常 validator の違い

機能差はありません。**同じバイナリが CLI の `--seeds` に自分以外の 3 台を指定すれば seed**です。
MISAKA は TOFU を取らない設計なので、seed の PK は誰でも `--emit-validator-pubkey` で取得可能。

---

## 2. 必須パラメータ

v0.9.0 以降の `misaka-node` は **PK pinning を必須化**しています（TOFU 廃止、Phase 2a）。
以下の 2 つは 1-to-1 で対応必要：

| CLI / TOML | 内容 | 必須 |
|---|---|---|
| `--seeds` / `[[seeds]]` | `host:port` のリスト | ✅ |
| `--seed-pubkeys` / `transport_pubkey` | 各 seed の ML-DSA-65 PK（hex）| ✅ |

count 不一致、addr 不正、hex 不正、key 長不正の **いずれも FATAL → exit(1)**。TOFU での
起動継続はありません。

---

## 3. 設定例

### 3.1 CLI（開発 / rehearsal）

```bash
misaka-node \
    --chain-id 2 \
    --data-dir /var/lib/misaka \
    --seeds "163.43.225.27:6690,133.167.126.51:6690,163.43.142.150:6690,163.43.208.209:6690" \
    --seed-pubkeys "0x<3904hex>,0x<3904hex>,0x<3904hex>,0x<3904hex>" \
    run
```

### 3.2 TOML config（本番 / systemd 運用）

`~/misaka-config/validator.toml`（[`distribution/testnet-validator/validator.toml`](../../distribution/testnet-validator/validator.toml) テンプレート参照）:

```toml
[[seeds]]
address = "163.43.225.27:6690"
transport_pubkey = "0x<3904 hex chars>"

[[seeds]]
address = "133.167.126.51:6690"
transport_pubkey = "0x<3904 hex chars>"

[[seeds]]
address = "163.43.142.150:6690"
transport_pubkey = "0x<3904 hex chars>"

[[seeds]]
address = "163.43.208.209:6690"
transport_pubkey = "0x<3904 hex chars>"
```

**ホストの PK は運営 announce で配布される `genesis_committee.toml` に含まれます。**
別途コピーする場合は以下で取得：

```bash
# Seed ホスト側で
ssh ubuntu@<seed-ip> "sudo cat /var/lib/misaka/l1-public-key.json"
# → { "public_key": "0x...", "scheme": "MlDsa65", "fingerprint": "..." }
# "public_key" の hex 部分を --seed-pubkeys に貼る
```

---

## 4. Seed failure tolerance の確認手順

P0（multi-seed）が効いていれば「1 seed down で他 3 から bootstrap 成功」が成立します。
Testnet smoke / 本番 deploy 後に確認するための手順：

### 4.1 10 分 smoke（`scripts/test_cold_reset.sh` 済）

10 分 smoke 成功時点で **4 node 全部が他 3 node と handshake できている** → parallel dial OK。

### 4.2 Seed failure simulation

```bash
# Step 1. Seed の 1 つ（27）を停止
ssh -i ~/.ssh/claude_key ubuntu@163.43.225.27 "sudo systemctl stop misaka-node"

# Step 2. 60 秒待つ（他 node の peerCount が 3 → 2 に落ちるのを見る）
sleep 60
for ip in 133.167.126.51 163.43.142.150 163.43.208.209; do
    printf "$ip peerCount: "
    ssh -i ~/.ssh/claude_key ubuntu@$ip "curl -s http://127.0.0.1:3001/api/get_chain_info | jq .peerCount"
done
# 期待: 各 node で peerCount=2（27 を除く 2 台の sibling）

# Step 3. 51 を restart（27 down 状態で bootstrap）
ssh -i ~/.ssh/claude_key ubuntu@133.167.126.51 "sudo systemctl restart misaka-node"
sleep 60

# Step 4. 51 の bootstrap 確認
ssh -i ~/.ssh/claude_key ubuntu@133.167.126.51 \
    "curl -s http://127.0.0.1:3001/api/get_chain_info | jq '.role, .peerCount, .current_round'"
# 期待: role="validator", peerCount=2（150 or 208 から handshake 成功）、current_round 前進

# Step 5. 27 を復帰
ssh -i ~/.ssh/claude_key ubuntu@163.43.225.27 "sudo systemctl start misaka-node"
```

**合格条件**: Step 4 で 51 が `peerCount >= 2` を達成。1 seed down 状態で残り 2 seed から
bootstrap できる = P0 の核心要求充足。

### 4.3 Metrics 観測

```bash
curl -s http://127.0.0.1:3001/api/metrics/node | grep "misaka_bootstrap_"
# misaka_bootstrap_seeds_configured  4
# misaka_bootstrap_seeds_connected   3    # 27 down なので 3
# misaka_bootstrap_seed_dial_failures_total{reason="refused"}  N
```

---

## 5. 運用上の注意

### 5.1 Seed 追加

新 seed `X` を足したい場合（4 node → 5 node committee）：

1. `X` を立てて `keygen` で PK 取得
2. 既存 4 node の config に `[[seeds]]` エントリ追加 → systemd restart
3. 運営が `genesis_committee.toml` を更新して re-announce
4. 参加者 validator も config 更新

**手順中は seed 数が bumpy になる**（4 → 5）が、parallel dial で即座に新 seed へ handshake 試行されます。

### 5.2 Seed の PK 再生成（compromised / lost passphrase）

1. 運営に compromise を報告
2. 該当 seed ノードを停止、`/var/lib/misaka/l1-*.json` 削除
3. 新 passphrase + 新 keygen
4. 運営が genesis を次 epoch で更新
5. 参加者全員に PK 更新 announce → config 修正 → restart

古い PK の `[[seeds]]` エントリが残っていると **その seed への PK mismatch で dial 失敗**
（`exit(1)` ではなく dial loop）になります。ログで検知可能。

### 5.3 Seed 削除

1 seed を恒久的に閉じる場合：

1. 運営が announce
2. 各 node の config から該当 `[[seeds]]` エントリ削除
3. systemd restart → parallel dial で閉じた seed はスキップされる

削除を**忘れても**、dial failure の `misaka_bootstrap_seed_dial_failures_total{reason="refused"}`
が立ち続けるだけで、他 seed から bootstrap できれば運用継続可能。

---

## 6. トラブルシュート

| 症状 | 確認コマンド | 原因 / 対処 |
|---|---|---|
| `FATAL: --seeds provided but --seed-pubkeys is empty` | ログ先頭 | `--seed-pubkeys` が漏れている。PK を明示提供 |
| `FATAL: --seed-pubkeys count != --seeds count` | ログ先頭 | 1-to-1 で並べ直す |
| `FATAL: --seeds entry 'X' is not a valid SocketAddr` | ログ先頭 | `host:port` の形式が壊れている（port 欠落等）|
| `FATAL: --seed-pubkeys entry for 'X' is not valid hex` | ログ先頭 | hex 文字 `0-9a-f`（大文字も可）以外が混入 |
| `FATAL: --seed-pubkeys entry for 'X' is not a valid ML-DSA-65 public key` | ログ先頭 | 1952 bytes（3904 hex chars）未満、または format 不正 |
| `peerCount: 0` のまま 5 分 | `/api/get_chain_info` | 全 seed unreachable の可能性。`misaka_bootstrap_seed_dial_failures_total` を確認 |
| 自分だけ `peerCount` が上がらない | `/api/get_peers` | 自ノードのファイアウォールが outbound を絞っている、または NAT で SYN が seed に届いていない |
| `seed mismatch` / `handshake failed` がログに | `grep -i handshake` | Seed 側が PK 再生成した可能性。運営 announce を確認 |

**失敗セッションの情報提供テンプレ**：[`docs/JOIN_TESTNET_TROUBLESHOOTING.md §9`](../JOIN_TESTNET_TROUBLESHOOTING.md#9-情報提出テンプレ)

---

## 7. Mainnet での追加要件

Testnet（chain_id=2）と mainnet（chain_id=1）の差分：

| 項目 | Testnet | Mainnet |
|---|---|---|
| 最小 seed 数 | 1（動く、非推奨）| 3 以上必須 |
| PK pinning | 必須 | 必須 |
| Seed の地理分散 | 任意 | 最低 2 region 推奨 |
| Seed 運営者の分散 | 任意 | 複数 operator 推奨（単一 operator 全停止リスク軽減）|

Mainnet 本番では **`ws_checkpoint` が `validator.toml` に必須**（起動時 validation 失敗）。
Testnet は任意。

---

## 8. 関連ドキュメント

- 設計根拠: [`docs/design/phase_p0_multi_seed.md`](../design/phase_p0_multi_seed.md)
- 参加手順: [`docs/JOIN_TESTNET.md`](../JOIN_TESTNET.md) §5-6
- トラブル対処: [`docs/JOIN_TESTNET_TROUBLESHOOTING.md`](../JOIN_TESTNET_TROUBLESHOOTING.md)
- Config テンプレート: [`distribution/testnet-validator/validator.toml`](../../distribution/testnet-validator/validator.toml)
- Upgrade 手順: [`docs/ops/UPGRADE_PROCEDURE.md`](UPGRADE_PROCEDURE.md)

---

_最終更新：2026-04-19（v0.9.1 closure）_
