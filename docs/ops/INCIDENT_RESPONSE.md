# インシデント対応手順

## 重要度分類

| レベル | 定義 | 応答時間 |
|--------|------|---------|
| **P0** | ネットワーク停止 / 資金喪失リスク | 即座 |
| **P1** | 機能低下 / 一部ノード障害 | 1時間以内 |
| **P2** | パフォーマンス劣化 | 24時間以内 |

## P0: ネットワーク停止

### 症状
- 全ノードで `round not advancing` が 5 分以上継続
- commit 数が増加しない

### 対応
1. **確認**: `curl http://localhost:16112/health` で各ノードの round を取得
2. **原因切り分け**:
   - 全ノード同じ round で停止 → リーダータイムアウトが連鎖
   - round がバラバラ → ネットワーク分断
3. **復旧**:
   - リーダータイムアウト連鎖: 最も進んだノードの round を確認し、遅れたノードを再起動
   - ネットワーク分断: peers 設定を確認、ファイアウォールルールを検証

### エスカレーション
- 10 分以内に復旧しない場合 → 全ノード同時再起動 (WAL から自動復旧)
- WAL 破損の場合 → スナップショットからリストア

## P0: Equivocation 攻撃

### 症状
- ログに `equivocation detected` が連続出力
- `EquivocationProof` がダンプされる

### 対応
1. **証拠保全**: ログの `EquivocationProof` をファイルに保存
2. **影響評価**: equivocating authority の stake 比率を確認
3. **短期**: 正直ノードは `Decision::Undecided` (BFS Aborted) で安全側に倒れる
4. **中期**: equivocating authority をバリデータセットから除外 (エポックローテーション)

## P1: ノード クラッシュ

### 復旧手順
1. `pm2 restart misaka` で再起動
2. WAL から自動復旧される
3. `curl /health` で round が進行していることを確認
4. `recovery complete` ログメッセージを確認

## P2: 遅延増加

### 確認
```bash
curl http://localhost:16112/metrics | grep propagation_delay
```

### 対応
- propagation_delay > 5 → ネットワーク帯域確認
- propagation_delay > 10 → ピア接続数確認、追加ピアを設定
