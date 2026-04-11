# MISAKA SLO 定義書

この文書は `v0.5.13` の operator 向け current runtime surface に寄せた SLO メモです。
SSOT は runtime が実際に返す `/api/metrics` と `/api/get_chain_info` であり、
`slo_metrics.rs` に名前があっても export されていないものは current operator truth ではありません。
public observer package と local rehearsal は role が違うため、この文書の主眼は operator / validator 側です。

## 0. Scope

- operator / genesis validator / self-host validator の監視基準を定義します
- public observer package は `joined` と `commitsTotal` の確認が主で、validator-only metrics をそのまま適用しません
- local rehearsal は `peerCount` と `commitsTotal` を確認する補助線であり、production SLO の置き換えではありません

## 1. Current Sources

| Source | Use |
|---|---|
| `GET /api/metrics` | `narwhal_dag::prometheus::PrometheusExporter` が出す current runtime metrics |
| `GET /api/get_chain_info` | `role`, `topology`, `peerCount`, `metrics.commitsTotal`, `status.current_round`, `status.highest_accepted_round` |
| `GET /api/health` | `status`, `consensus`, `round`, `blocks`, `safeMode` |

## 2. Current SLO Signals

| ID | Signal | Target / alert shape | First response |
|---|---|---|---|
| L1 | `misaka_consensus_commits_total` と `metrics.commitsTotal` | active public testnet で 120 秒以上増えなければ page | `/api/health`, `/api/get_chain_info`, relay `16110/tcp`, seed reachability |
| L2 | `misaka_consensus_current_round`, `misaka_consensus_highest_accepted_round` | 60 秒以上 round が動かない場合は investigate | `peerCount`, `topology`, `safeMode.halted`, leader timeout の増加を確認 |
| L3 | `misaka_consensus_leaders_skipped_total`, `misaka_consensus_round_timeouts_total` | 継続的な増加は degraded liveness | leader 遅延、packet loss、seed/operator の負荷を確認 |
| S1 | `misaka_consensus_equivocations_total` | 0 を維持。増加は即 P0 | 証拠保全、authority 特定、operator escalation |
| N1 | `misaka_consensus_sync_completed_total`, `misaka_consensus_sync_failed_total`, `misaka_consensus_sync_inflight` | failed が継続増加せず、inflight が詰まらない | seed pubkeys, firewall, network split, stale genesis を確認 |
| N2 | `misaka_consensus_blocks_accepted_total`, `misaka_consensus_blocks_rejected_total`, `misaka_consensus_blocks_duplicate_total` | reject が継続的に増えない | genesis / validator set / transport PK pinning mismatch を確認 |
| R1 | `misaka_consensus_wal_writes_total`, `misaka_consensus_wal_errors_total`, `misaka_consensus_store_checkpoints_total` | `wal_errors_total = 0` | disk, fsync latency, journal, restart safety を確認 |
| R2 | `misaka_consensus_dag_blocks`, `misaka_consensus_dag_suspended_blocks`, `misaka_consensus_dag_blocks_evicted_total` | suspended や evicted が異常増加しない | memory pressure, stalled sync, prolonged partitions を確認 |

## 3. Exported Runtime Metrics

現在の `/api/metrics` で直接追うべき名前は少なくとも次です。

- `misaka_consensus_blocks_accepted_total`
- `misaka_consensus_blocks_rejected_total`
- `misaka_consensus_blocks_suspended_total`
- `misaka_consensus_blocks_unsuspended_total`
- `misaka_consensus_blocks_duplicate_total`
- `misaka_consensus_equivocations_total`
- `misaka_consensus_blocks_proposed_total`
- `misaka_consensus_current_round`
- `misaka_consensus_highest_accepted_round`
- `misaka_consensus_round_timeouts_total`
- `misaka_consensus_commits_total`
- `misaka_consensus_commits_direct_total`
- `misaka_consensus_commits_indirect_total`
- `misaka_consensus_leaders_skipped_total`
- `misaka_consensus_transactions_committed_total`
- `misaka_consensus_checkpoints_finalized_total`
- `misaka_consensus_dag_blocks`
- `misaka_consensus_dag_suspended_blocks`
- `misaka_consensus_dag_blocks_evicted_total`
- `misaka_consensus_sync_completed_total`
- `misaka_consensus_sync_failed_total`
- `misaka_consensus_sync_inflight`
- `misaka_consensus_wal_writes_total`
- `misaka_consensus_wal_errors_total`
- `misaka_consensus_store_checkpoints_total`

## 4. Not Current Runtime Truth

次の名前は old docs には出てきますが、`v0.5.13` の runtime export をそのまま表してはいません。
dashboard や alert の基準値に使う前に、実装側で export されているかを確認してください。

- `misaka_consensus_commits_per_second`
- `misaka_consensus_finality_latency_seconds`
- `misaka_certifier_certified_txs_total`
- `misaka_certifier_pending_blocks`
- `misaka_dag_equivocations_detected_total`
- `misaka_p2p_connected_peers`
- `misaka_prober_propagation_delay_rounds`
- `misaka_sync_responses_received_total`
- `misaka_mempool_pending_txs`
- `misaka_storage_write_batch_seconds`
