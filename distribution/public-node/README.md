# MISAKA Testnet — Public Node

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
├── README.md                       # この文書
└── config/
    ├── public-node.toml            # ノード設定 (chain_id=2)
    ├── genesis_committee.toml      # testnet genesis + validator pubkey
    ├── seeds.txt                   # 公式 seed 接続先
    └── bundled-validator.key       # 初回起動用 bootstrap key (暗号化)
```

## 接続確認

ノード起動後、別のターミナルで:

```bash
curl http://localhost:3001/api/health
# => {"blocks":N,"round":N,"status":"ok"}

curl http://localhost:3001/api/get_chain_info
# => {"chain":"MISAKA Network","chainId":2,"consensus":"Mysticeti-equivalent",
#     "metrics":{"blocksProposed":N,"commitsTotal":M},...}
```

正常に動作していれば `commitsTotal` が時間とともに増加します。

## ディレクトリ

- `misaka-data/` — チェーン状態と validator 鍵（初回起動時に作成）
- データを削除して初期化するには `misaka-data/` を削除してから再起動

## 停止

ターミナルで `Ctrl+C`、または起動したウインドウを閉じてください。

## トラブル

| 症状 | 対処 |
|---|---|
| ポート 3001 / 6691 使用中 | 他プロセスを停止、または `config/public-node.toml` で変更 |
| macOS Gatekeeper | `start-public-node.command` を右クリック → 「開く」 |
| Windows SmartScreen | 「詳細情報」→「実行」 |
| Linux: 権限エラー | `chmod +x start-public-node.sh misaka-node` |

## セキュリティ

同梱の `bundled-validator.key` は **暗号化された testnet bootstrap 鍵** です。
複数ノードが同じ鍵で公式 testnet に参加すると equivocation を起こすため、
**単独テスト / self-host 用途のみで使用してください**。

公式 testnet の validator として参加する場合は、運営から配布される鍵と
genesis に差し替えが必要です。
