# MISAKA Testnet Launcher

MISAKA testnet に初心者でも参加しやすい形で入るための配布 repo です。

## ダウンロード

| Platform | File |
|---|---|
| Windows x86_64 | `misaka-public-node-windows-x86_64.zip` |
| macOS arm64 | `misaka-public-node-macos-arm64.tar.gz` |
| Linux x86_64 | `misaka-public-node-linux-x86_64.tar.gz` |
| SHA256 | `SHA256SUMS` |

最新 release 一覧: https://github.com/sasakiyuuu/misaka-test-net/releases/latest

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

## 公式 seed が落ちている時

共有 VPS が止まっていても、配布物だけでローカル接続確認はできます。

- Windows: `start-self-hosted-testnet.bat`
- macOS: `start-self-hosted-testnet.command`
- Linux: `./start-self-hosted-testnet.sh`

これは `seed node` と `public node` を同梱 package 内で一緒に起動して、public node を `127.0.0.1:6690` に向けます。

## ポート開放の考え方

まず `show-network-guide.*` を実行してください。

- 参加だけなら router のポート開放は必須ではありません
- 他ノードから見える public node にしたいなら `TCP 6691`
- 自分で seed を配るなら `TCP 6690`

router の設定画面は機種ごとに違うので、port forwarding 自体を完全自動化することはしていません。代わりに package 内で必要ポートと現在の LAN 情報を表示します。

## seed の差し替え

公開 seed が落ちた場合は、配布物の `config/seeds.txt` を編集してください。

- 1 行に 1 つ `HOST:PORT`
- node 再起動後だけでなく、起動中も定期的に再読込します

## 含まれているもの

```
misaka-public-node-<platform>/
├── misaka-node(.exe)             # ノードバイナリ
├── start-public-node.*           # Public node 起動
├── start-seed-node.*             # Seed node 起動
├── start-self-hosted-testnet.*   # ローカル 3 validator テスト
├── show-network-guide.*          # ネットワーク診断
├── README.md
└── config/
    ├── public-node.toml
    ├── seed-node.toml
    ├── validator-node.toml
    ├── seeds.txt
    ├── self-host-seeds.txt
    └── offline-seeds.txt
```

## Docker

```bash
cd misaka-core-v4/docker
docker compose up -d
```

## ビルド (ソースから)

```bash
cd misaka-core-v4
cargo build --release -p misaka-node --features dag,testnet
```

## 技術仕様

- **署名**: ML-DSA-65 (FIPS 204, Post-Quantum)
- **鍵交換**: ML-KEM-768 (FIPS 203, Post-Quantum)
- **コンセンサス**: Narwhal DAG-based BFT
- **ブロック時間**: ~2 秒 (fast lane)
- **Chain ID**: 2 (testnet)

## 補足

- 一般参加者向けの入口は `start-public-node.*` です
- Docker 向け設定と source は `misaka-core-v4` に入っています
- クロスプラットフォーム build は GitHub Actions で回します
