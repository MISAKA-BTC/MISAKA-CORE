# MISAKA Testnet — Public Node

## 起動方法

| OS | ファイル | 方法 |
|---|---|---|
| Windows | `start-public-node.bat` | ダブルクリック |
| macOS | `start-public-node.command` | ダブルクリック |
| Linux | `start-public-node.sh` | ターミナルで実行 |

### macOS quarantine 解除

```bash
xattr -dr com.apple.quarantine <展開したフォルダ名>
```

## Seed が落ちている時

| OS | ファイル |
|---|---|
| Windows | `start-self-hosted-testnet.bat` |
| macOS | `start-self-hosted-testnet.command` |
| Linux | `start-self-hosted-testnet.sh` |

## ネットワーク診断

| OS | ファイル |
|---|---|
| Windows | `show-network-guide.bat` |
| macOS | `show-network-guide.command` |
| Linux | `show-network-guide.sh` |

## seeds.txt の編集

`config/seeds.txt` を編集して seed ノードの接続先を変更できます。
起動中でも定期的に再読込されます。

## 含まれるファイル

```
config/
  public-node.toml      # public node 設定
  seed-node.toml        # seed node 設定
  validator-node.toml   # validator 設定
  seeds.txt             # 接続先 seed 一覧
  self-host-seeds.txt   # セルフホスト用
  offline-seeds.txt     # オフライン確認用
```
