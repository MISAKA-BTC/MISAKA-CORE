# MISAKA DAG v6-p2p: Header-First Sync Protocol

## Summary

`dag_p2p.rs` を全面書き直し。Tips交換→BFS full-block download の
スケルトンから、Kaspa寄りの header-first, pruning-point-anchored sync に。

## v4 → v6 比較

| Feature | v4 | v6 |
|---------|----|----|
| Header-first sync | ❌ | ✅ ヘッダ先行 → 検証 → body batch |
| Pruning point anchor | ❌ | ✅ DagHello に pruning_point |
| IBD / steady-state 分離 | ❌ | ✅ 状態マシン 6 states |
| Block locator | ❌ | ✅ SP chain 指数サンプリング |
| Peer quality tracking | ❌ | ✅ penalty → ban |
| Malicious peer ban | ❌ | ✅ BAN_THRESHOLD=100 |
| Score-window inventory | スケルトン | ✅ DagInventory |
| Action-based API | ❌ | ✅ SyncAction enum |

## Sync Flow

```
Handshaking → NegotiatingPast → DownloadingHeaders → DownloadingBodies → Synced
                                                                          ↕
                                                                    steady-state relay
                                                                    
                (any state) → Banned (on penalty threshold)
```

## New Components

### Block Locator (`build_block_locator`)
SP chain を指数バックオフでサンプリング。O(log N) で chain 全体をカバー。
Bitcoin の block locator と同原理だが DAG の SP chain 上で動作。

### Peer Quality (`PeerQuality`)
- `add_penalty(points, reason)` — 不正データでペナルティ加算
- `record_good_response()` — 正常レスポンスを記録
- `is_stale()` — タイムアウト検出
- `BAN_THRESHOLD = 100` — 超過で ban

| Violation | Penalty |
|-----------|---------|
| Empty block locator | 20 |
| Empty headers (has_more=true) | 10 |
| Headers in wrong state | 5 |
| Invalid block/header | 25 |

### SyncAction (呼び出し元への指示)
- `Send(msg)` — peer にメッセージ送信
- `Ban(reason)` — peer を ban して切断
- `ProcessBlock { hash, header, txs }` — ブロック処理パイプラインへ
- `ValidateHeader { hash, header }` — ヘッダ検証パイプラインへ

## Test Coverage (11 tests)

| Test | Verifies |
|------|----------|
| `test_block_locator_linear` | SP chain sampling |
| `test_block_locator_single` | Genesis-only chain |
| `test_find_shared_block_found` | Locator → shared ancestor |
| `test_find_shared_block_none` | No shared block |
| `test_full_sync_flow` | Complete: handshake → headers → bodies → synced |
| `test_already_synced` | All tips known → immediate sync |
| `test_peer_ban` | Penalty accumulation → ban |
| `test_validation_failure` | Invalid header → penalty |
| `test_steady_state_relay` | New block with missing/known parents |
| `test_multi_batch_headers` | Multi-batch header download |
| `test_peer_quality_stale` | Stale timeout detection |

## Future Work (Aランク以降)

- `wire_protocol.rs` に新メッセージ型 ID 追加
- Pruning point proof 検証
- Snapshot fast sync
- Peer scoring に latency/bandwidth を反映
- Concurrent peer sync (複数 peer から並行 header download)
