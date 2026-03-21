# MISAKA Testnet Launcher

MISAKA testnet に初心者でも参加しやすい形で入るための配布 repo です。

## ダウンロード

- Windows x86_64: [misaka-public-node-windows-x86_64.zip](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-windows-x86_64.zip)
- macOS arm64: [misaka-public-node-macos-arm64.tar.gz](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-macos-arm64.tar.gz)
- Linux x86_64: [misaka-public-node-linux-x86_64.tar.gz](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz)

## 使い方

### Windows

1. zip を展開
2. `misaka-launcher.exe` をダブルクリック

### macOS

1. tar.gz を展開
2. `start-public-node.command` をダブルクリック

### Linux

1. tar.gz を展開
2. `./start-public-node.sh` を実行

## seed の差し替え

公開 seed が落ちた場合は、配布物の `config/seeds.txt` を編集してください。

- 1 行に 1 つ `HOST:PORT`
- node 再起動後だけでなく、起動中も定期的に再読込します

## 含まれているもの

- `misaka-node`
- `misaka-launcher`
- `config/public-node.toml`
- `config/seed-node.toml`
- `config/validator-node.toml`
- `config/seeds.txt`

## 補足

- 一般参加者向けの入口は launcher です
- Docker 向け設定と source は [misaka-core-v4](./misaka-core-v4) に入っています
- クロスプラットフォーム build は GitHub Actions で回します
