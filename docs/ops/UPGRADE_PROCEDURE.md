# アップグレード手順

## 原則

- **ローリングアップグレード**: 1 ノードずつ更新。同時に f+1 以上を停止しない。
- **後方互換**: 新バイナリは旧バイナリとの P2P ハンドシェイクに成功すること。
- **ロールバック可能**: 問題発生時は旧バイナリに戻せること。

## 手順

### 1. ビルド

```bash
git pull origin main
cargo build --release -p misaka-node
```

### 2. テスト

```bash
cargo test --release -p misaka-dag
cargo test --release -p misaka-consensus
```

全テスト合格を確認。

### 3. ノード停止

```bash
pm2 stop misaka
```

### 4. バイナリ差し替え

```bash
cp target/release/misaka-node /usr/local/bin/misaka-node
```

### 5. 再起動

```bash
pm2 start misaka
```

### 6. 確認

```bash
# ヘルスチェック
curl http://localhost:16112/health

# round が進行していることを確認
watch -n 5 'curl -s http://localhost:16112/health | jq .round'
```

### 7. 次のノードへ

前のノードが正常に round を進行していることを確認してから、次のノードを更新。

## Sakura VPS SCP デプロイ

```bash
# ローカルでビルド
cargo build --release -p misaka-node --target x86_64-unknown-linux-gnu

# SCP で転送
scp target/x86_64-unknown-linux-gnu/release/misaka-node user@sakura-vps:/home/misaka/bin/

# リモートで再起動
ssh user@sakura-vps 'pm2 restart misaka'
```

## ハードフォーク (protocol_upgrade)

プロトコルアップグレード (feature activation) はエポック境界で自動発動。

1. 新バイナリに upgrade gate 番号を埋め込み
2. 全ノードが新バイナリに更新されたことを確認
3. 指定エポックで自動 activate

```rust
// crates/misaka-consensus/src/protocol_upgrade.rs
// Upgrade 0x04: Q-DAG-CT confidential transactions
```

## ロールバック

問題が発生した場合:

```bash
pm2 stop misaka
cp /home/misaka/bin/misaka-node.bak /home/misaka/bin/misaka-node
pm2 start misaka
```

WAL は前方互換なので、新バイナリが書いた WAL を旧バイナリが読める必要がある。
WAL フォーマットを変更するアップグレードは**ハードフォーク扱い**。
