# MISAKA SLO 定義書

本文書はメトリクス実装の唯一の入力。ここに無いメトリクスは追加しない。

---

## 1. Liveness SLO

### L1: commit_rate_bps
- **メトリクス**: `misaka_consensus_commits_per_second` (Gauge)
- **測定方法**: 直近 60 秒間の commit 数 / 60
- **目標**: ≥ 0.5 commits/sec (= ≥ 30 commits/min)
- **アラート**: < 0.1 commits/sec が 120 秒継続
- **初動**: Round 進行停止を確認 → リーダータイムアウトログ確認 → ピア接続確認

### L2: finality_latency_seconds
- **メトリクス**: `misaka_consensus_finality_latency_seconds` (Histogram)
- **測定方法**: block.timestamp_ms → commit 記録時刻の差
- **buckets**: [0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 30.0]
- **目標**: p99 ≤ 3.0 秒
- **アラート**: p99 > 5.0 秒 が 60 秒継続
- **初動**: propagation_delay 確認 → ancestor exclusion 状態確認

### L3: leader_skip_rate
- **メトリクス**: `misaka_consensus_leader_skips_total` (Counter)
- **測定方法**: skip / (commit + skip) の比率を dashboard で計算
- **関連メトリクス**: `misaka_consensus_leader_commits_total` (Counter)
- **目標**: ≤ 5%
- **アラート**: 直近 5 分で > 15%
- **初動**: skip された leader の authority を特定 → そのノードの死活確認

### L4: round_advancement_rate
- **メトリクス**: `misaka_consensus_current_round` (Gauge)
- **測定方法**: round の単調増加を監視
- **目標**: 60 秒以内に少なくとも 1 round 進行
- **アラート**: 120 秒 round 変化なし
- **初動**: threshold clock の quorum 到達状況確認

### L5: fast_path_certification_rate
- **メトリクス**: `misaka_certifier_certified_txs_total` (Counter)
- **メトリクス**: `misaka_certifier_pending_blocks` (Gauge)
- **目標**: 受信 TX の 90% 以上が fast-path で certify
- **アラート**: certify 率が 50% 未満
- **初動**: reject vote 率を確認

---

## 2. Safety SLO (= 即アラート)

### S1: equivocation_detected
- **メトリクス**: `misaka_dag_equivocations_detected_total` (Counter)
- **測定方法**: `DagState::accept_block()` → `AcceptedWithEquivocation` のカウント
- **目標**: 0 (正常時は発生しない)
- **アラート**: > 0 → 即時 P0 アラート
- **初動**: equivocating authority を特定 → 証拠保全 → コミュニティ通報

### S2: signature_verification_failure
- **メトリクス**: `misaka_crypto_sig_verify_failures_total` (Counter, label: context=tx|block|vote|bridge)
- **測定方法**: `ml_dsa_verify*()` の Err 返却をカウント
- **目標**: 0 (正当な TX/block のみ来る場合)
- **アラート**: > 10/min → P1 アラート
- **初動**: 発信元 peer を特定 → ban 検討

### S3: bfs_aborted
- **メトリクス**: `misaka_committer_bfs_aborted_total` (Counter)
- **測定方法**: `causal_history_search()` → `BfsResult::Aborted` のカウント
- **目標**: 0 (通常は発生しない)
- **アラート**: > 0 → P1 アラート (equivocation flooding 攻撃の可能性)
- **初動**: equivocation 検知メトリクスと相関確認

### S4: commit_finalizer_rejected_txs
- **メトリクス**: `misaka_finalizer_rejected_txs_total` (Counter)
- **測定方法**: `CommitFinalizerV2` → reject 判定のカウント
- **目標**: 通常 0
- **アラート**: > 100/min → 調査

---

## 3. Network SLO

### N1: peer_count
- **メトリクス**: `misaka_p2p_connected_peers` (Gauge)
- **測定方法**: 現在接続中の peer 数
- **目標**: ≥ 10
- **アラート**: < 5 が 60 秒継続
- **初動**: ネットワーク設定・ファイアウォール確認

### N2: block_propagation_delay
- **メトリクス**: `misaka_prober_propagation_delay_rounds` (Gauge)
- **測定方法**: `RoundProber::propagation_delay()`
- **目標**: ≤ 2 rounds
- **アラート**: > 5 rounds が 60 秒継続
- **初動**: ネットワーク帯域確認 → 遅い peer を特定

### N3: sync_requests
- **メトリクス**: `misaka_sync_requests_sent_total` (Counter)
- **メトリクス**: `misaka_sync_responses_received_total` (Counter)
- **メトリクス**: `misaka_sync_timeouts_total` (Counter)
- **目標**: timeout 率 ≤ 5%
- **アラート**: timeout 率 > 20% が 120 秒継続

### N4: block_accept_rate
- **メトリクス**: `misaka_dag_blocks_accepted_total` (Counter)
- **メトリクス**: `misaka_dag_blocks_rejected_total` (Counter, label: reason=duplicate|below_eviction|invalid_author|verify_fail)
- **目標**: reject 率 ≤ 1% (duplicate 除く)

---

## 4. Resource SLO

### R1: mempool_depth
- **メトリクス**: `misaka_mempool_pending_txs` (Gauge)
- **目標**: ≤ 5,000
- **アラート**: > 10,000

### R2: dag_block_count
- **メトリクス**: `misaka_dag_blocks_in_memory` (Gauge)
- **目標**: ≤ 50,000
- **アラート**: > 100,000

### R3: storage_write_latency
- **メトリクス**: `misaka_storage_write_batch_seconds` (Histogram)
- **buckets**: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
- **目標**: p99 ≤ 100ms
- **アラート**: p99 > 500ms

### R4: leader_timeout_backoff
- **メトリクス**: `misaka_consensus_leader_timeout_ms` (Gauge)
- **メトリクス**: `misaka_consensus_leader_timeouts_total` (Counter)
- **目標**: timeout_ms ≤ 2000 (通常)
- **アラート**: timeout_ms > 8000 (backoff 上限到達)

---

## メトリクス名一覧 (24 メトリクス)

| # | 名前 | 型 | SLO |
|---|------|---|-----|
| 1 | `misaka_consensus_commits_per_second` | Gauge | L1 |
| 2 | `misaka_consensus_finality_latency_seconds` | Histogram | L2 |
| 3 | `misaka_consensus_leader_skips_total` | Counter | L3 |
| 4 | `misaka_consensus_leader_commits_total` | Counter | L3 |
| 5 | `misaka_consensus_current_round` | Gauge | L4 |
| 6 | `misaka_certifier_certified_txs_total` | Counter | L5 |
| 7 | `misaka_certifier_pending_blocks` | Gauge | L5 |
| 8 | `misaka_dag_equivocations_detected_total` | Counter | S1 |
| 9 | `misaka_crypto_sig_verify_failures_total` | Counter | S2 |
| 10 | `misaka_committer_bfs_aborted_total` | Counter | S3 |
| 11 | `misaka_finalizer_rejected_txs_total` | Counter | S4 |
| 12 | `misaka_p2p_connected_peers` | Gauge | N1 |
| 13 | `misaka_prober_propagation_delay_rounds` | Gauge | N2 |
| 14 | `misaka_sync_requests_sent_total` | Counter | N3 |
| 15 | `misaka_sync_responses_received_total` | Counter | N3 |
| 16 | `misaka_sync_timeouts_total` | Counter | N3 |
| 17 | `misaka_dag_blocks_accepted_total` | Counter | N4 |
| 18 | `misaka_dag_blocks_rejected_total` | Counter | N4 |
| 19 | `misaka_mempool_pending_txs` | Gauge | R1 |
| 20 | `misaka_dag_blocks_in_memory` | Gauge | R2 |
| 21 | `misaka_storage_write_batch_seconds` | Histogram | R3 |
| 22 | `misaka_consensus_leader_timeout_ms` | Gauge | R4 |
| 23 | `misaka_consensus_leader_timeouts_total` | Counter | R4 |
| 24 | `misaka_consensus_commits_total` | Counter | L1 (rate 計算用) |
