# MISAKA Testnet — Validator template（v0.9.0）

このディレクトリは **新規 validator 参加者がコピーして使う** config / systemd / logrotate テンプレート集です。

詳しい手順は [`docs/JOIN_TESTNET.md`](../../docs/JOIN_TESTNET.md) を参照。

## ファイル

| ファイル | 置き場 | 用途 |
|---|---|---|
| `validator.toml` | `~/misaka-config/validator.toml` | Node 起動設定（node mode, ports, prune_mode 等） |
| `misaka-node.service` | `/etc/systemd/system/misaka-node.service` | systemd unit（`Restart=always`） |
| `misaka.logrotate` | `/etc/logrotate.d/misaka` | ログ日次ローテート（14 日保持） |

## 使い方

```bash
# 1. テンプレートを home にコピー
mkdir -p ~/misaka-config
cp distribution/testnet-validator/validator.toml ~/misaka-config/

# 2. systemd unit をコピー + 編集
sudo cp distribution/testnet-validator/misaka-node.service /etc/systemd/system/
# WorkingDirectory と ExecStart のパスを自環境に合わせる
sudo nano /etc/systemd/system/misaka-node.service

# 3. logrotate
sudo cp distribution/testnet-validator/misaka.logrotate /etc/logrotate.d/misaka

# 4. reload + start
sudo systemctl daemon-reload
sudo systemctl enable --now misaka-node
sudo systemctl status misaka-node
```

## 注意

- `validator.toml` は **chain_id=2**（testnet）固定。mainnet 向けではありません
- `genesis_committee.toml` は運営 announce で配布される **別ファイル**。`~/misaka-config/genesis_committee.toml` に置きます
- 秘密鍵（`/var/lib/misaka/l1-secret-key.json`）は **このテンプレートに含まれません**。[`docs/JOIN_TESTNET.md`](../../docs/JOIN_TESTNET.md) §4 の手順で各自生成してください
- パスフレーズは `/run/secrets/validator_passphrase`（600 permission）経由で systemd unit が読みます
