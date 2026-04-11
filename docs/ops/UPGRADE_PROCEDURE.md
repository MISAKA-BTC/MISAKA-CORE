# アップグレード手順

> この文書は upgrade 参考手順です。`v0.5.13` の public testnet 開始ラインの正本ではありません。
> current の入口と運用真値は `distribution/public-node/README.md` と
> `local-start-docs-v0513/07_operator_startup_runbook_v0513.ja.md` を優先してください。
> public observer package は release asset の差し替えと launcher 再実行が前提で、operator / self-host validator は `systemd` と `testnet-deploy.sh` / `testnet-join.sh` を前提にします。

## 原則

- **ローリングアップグレード**: 1 ノードずつ更新。同時に f+1 以上を停止しない。
- **後方互換**: 新バイナリは旧バイナリとの P2P ハンドシェイクに成功すること。
- **ロールバック可能**: 問題発生時は旧バイナリに戻せること。

## 入口の切り分け

- **Public observer package**: `distribution/public-node/start-public-node.*` が入口です。upgrade 時も package を更新して launcher を再実行します。`scripts/start-node.sh` に置き換えません。
- **Public testnet operator / self-host validator**: `scripts/testnet-deploy.sh` または `scripts/testnet-join.sh` を起点にした `systemd` サービス `misaka-node` が current line です。
- **Source checkout の local smoke**: `scripts/start-node.sh` / `scripts/start-testnet.sh` を使います。以下の手順は operator / self-host validator を主対象にしています。

## Rolling Upgrade Procedure

### 1. 事前確認

```bash
sudo systemctl cat misaka-node | sed -n '/ExecStart/p'
curl -s http://127.0.0.1:3001/api/get_chain_info | jq '{version, role, topology, peerCount, metrics}'
```

`misaka-node` がどの binary path を使っているか、更新前の role / topology / commit 進行がどう見えているかを記録します。

### 2. ビルド

```bash
git pull --ff-only origin main
cargo build --release -p misaka-node --features dag,testnet
```

testnet operator surface は `dag,testnet` feature を前提にします。  
コード変更を伴う upgrade 前は、軽量確認として `cargo check -p misaka-node --features dag,testnet` と `bash ./check` を別途通す運用が current truth です。

### 3. バックアップ

現在の service が参照する binary を退避しておきます。例:

```bash
sudo install -m 755 target/release/misaka-node /usr/local/bin/misaka-node.new
sudo cp /usr/local/bin/misaka-node /usr/local/bin/misaka-node.bak.$(date +%Y%m%d%H%M%S)
```

実際の `ExecStart` が repo worktree 直下を向いている場合は、その path に合わせて退避先を調整してください。

### 4. 1 ノードずつ停止して差し替え

```bash
sudo systemctl stop misaka-node
sudo install -m 755 target/release/misaka-node /usr/local/bin/misaka-node
sudo systemctl start misaka-node
sudo journalctl -u misaka-node -n 100 --no-pager
```

service が repo worktree の `target/release/misaka-node` を直接参照している構成なら、
binary copy は不要で `cargo build` 後に `sudo systemctl restart misaka-node` だけで済みます。

### 5. 確認

```bash
curl -s http://127.0.0.1:3001/api/health | jq .
curl -s http://127.0.0.1:3001/api/get_chain_info | jq '{version, role, topology, peerCount, metrics, status}'
curl -s http://127.0.0.1:3001/api/metrics | egrep 'misaka_consensus_(current_round|commits_total|sync_failed_total|wal_errors_total)'
```

確認観点:

- `/api/health` が `status:"ok"` を返す
- `safeMode.halted` が `false`
- `metrics.commitsTotal` または `misaka_consensus_commits_total` が再び増加する
- validator / observer の role が意図通りで、`topology:"joined"` に戻る

### 6. 次のノードへ

前のノードが正常に round を進行していることを確認してから、次のノードを更新。

## Public Observer Package の更新

- stock package を新しい release asset に入れ替えます
- `start-public-node.sh` / `.command` / `.bat` を再実行します
- 確認は `curl -s http://127.0.0.1:3001/api/health` と `curl -s http://127.0.0.1:3001/api/get_chain_info`
- 旧 `scripts/start-node.sh` に public observer の入口を寄せないでください

public observer の current start line を `scripts/start-node.sh` に切り替えないでください。

## ロールバック

問題が発生した場合:

```bash
sudo systemctl stop misaka-node
sudo install -m 755 /usr/local/bin/misaka-node.bak.YYYYMMDDHHMMSS /usr/local/bin/misaka-node
sudo systemctl start misaka-node
sudo journalctl -u misaka-node -n 100 --no-pager
```

repo worktree 直下の binary を参照している構成では、退避した旧 binary を元の path に戻してください。
ロールバック後も `/api/health` と `/api/get_chain_info` で round / commit 進行を再確認します。
