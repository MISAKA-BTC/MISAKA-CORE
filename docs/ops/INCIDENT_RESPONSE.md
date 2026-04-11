# インシデント対応手順

> この文書は consensus / ops の参考手順です。`v0.5.13` の public testnet 開始ラインの正本ではありません。
> current の入口と運用真値は `distribution/public-node/README.md` と
> `local-start-docs-v0513/07_operator_startup_runbook_v0513.ja.md` を優先してください。
> public observer package の障害は `start-public-node.*` と release asset 更新で扱い、PM2 / old local smoke 手順には戻しません。

## Current Operational Surface

- public testnet operator / self-host validator の標準サービスは `systemd` の `misaka-node` です。
- health は `http://127.0.0.1:3001/api/health`、chain info は `http://127.0.0.1:3001/api/get_chain_info`、metrics は `http://127.0.0.1:3001/api/metrics` を使います。
- `scripts/start-node.sh` の local smoke だけは既定 RPC が `3000` です。`16112/health` や PM2 前提の old 手順は使いません。
- public observer package は `distribution/public-node/start-public-node.*` を再実行し、`topology:"joined"` と `role:"observer"` の復帰を確認します。

## 重要度分類

| レベル | 定義 | 応答時間 |
|--------|------|---------|
| **P0** | ネットワーク停止 / 資金喪失リスク | 即座 |
| **P1** | 機能低下 / 一部ノード障害 | 1時間以内 |
| **P2** | パフォーマンス劣化 | 24時間以内 |

## P0: ネットワーク停止

### 症状
- 全ノードで `round not advancing` が 5 分以上継続
- `misaka_consensus_commits_total` または `metrics.commitsTotal` が増加しない
- `safeMode.halted` が `true` になる、または `peerCount` が 0 のまま戻らない

### 対応
1. **確認**:
   ```bash
   curl -s http://127.0.0.1:3001/api/health | jq .
   curl -s http://127.0.0.1:3001/api/get_chain_info | jq '{role, topology, peerCount, metrics, status}'
   curl -s http://127.0.0.1:3001/api/metrics | egrep 'misaka_consensus_(current_round|highest_accepted_round|commits_total|sync_failed_total|sync_inflight)'
   ```
2. **原因切り分け**:
   - 全ノード同じ round で停止 → round timeout / leader skip 連鎖を疑う
   - `topology:"solo"` や `peerCount:0` → seed 到達性、`16110/tcp`、`--advertise-addr`、seed pubkey mismatch を確認
   - round がバラバラ → ネットワーク分断または genesis / seed metadata の不一致
3. **復旧**:
   - 単独ノード障害: `sudo systemctl restart misaka-node`
   - public observer package: launcher を再実行し、`/api/get_chain_info` で `topology:"joined"` に戻ることを確認
   - ネットワーク分断: seed / seed-pubkeys / firewall / public relay `16110` を確認

### エスカレーション
- 10 分以内に復旧しない場合は、`sudo journalctl -u misaka-node --since '15 min ago'` を保全して operator に共有
- WAL / disk エラーが見える場合は `misaka_consensus_wal_errors_total` と journal を採取してから復旧判断

## P0: Equivocation 攻撃

### 症状
- ログに `equivocation detected` が連続出力
- `EquivocationProof` がダンプされる
- `misaka_consensus_equivocations_total` が増加する

### 対応
1. **証拠保全**: ログの `EquivocationProof` をファイルに保存
2. **影響評価**: equivocating authority の stake 比率を確認
3. **短期**: 正直ノードは `Decision::Undecided` (BFS Aborted) で安全側に倒れる
4. **中期**: equivocating authority をバリデータセットから除外 (エポックローテーション)

## P1: ノード クラッシュ

### 復旧手順
1. `sudo systemctl status misaka-node --no-pager`
2. `sudo journalctl -u misaka-node -n 200 --no-pager`
3. `sudo systemctl restart misaka-node`
4. WAL からの復旧後に `curl -s http://127.0.0.1:3001/api/health | jq .`
5. `curl -s http://127.0.0.1:3001/api/get_chain_info | jq '{peerCount, topology, status}'`

## P2: 遅延増加

### 確認
```bash
curl -s http://127.0.0.1:3001/api/metrics | egrep 'misaka_consensus_(leaders_skipped_total|round_timeouts_total|sync_failed_total|sync_inflight|highest_accepted_round|current_round)'
```

### 対応
- `sync_failed_total` や `sync_inflight` が増える → seed 到達性、relay `16110/tcp`、packet loss を確認
- `leaders_skipped_total` や `round_timeouts_total` が増える → leader 側の遅延またはネットワーク断続を確認
- `peerCount` が減る → firewall、`MISAKA_ACCEPT_OBSERVERS`、`--advertise-addr`、seed metadata を再確認
