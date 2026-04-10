# Commit Subsystem Decomposition

## 1. 現状の責務分布

### bft.rs (409 行)
- BFT 状態マシン (Propose → Prevote → Precommit → Committed)
- Per-digest vote 集計 (prevotes_by_digest / precommits_by_digest)
- Vote equivocation 検知 (prevote_digests / precommit_digests)
- ML-DSA-65 署名検証 (verifier.verify())
- Locked prevote digest (safety)
- Finality 判定 (threshold 到達チェック)

**問題**: 6 つの責務が 1 ファイルに混在。vote_monitor と finality 計算が分離不能。

### pipeline.rs (399 行)
- PipelinedCommitter: multi-slot commit orchestration
- Anchor-based indirect/skip commit rule
- Sub-DAG 構築 (frontier traversal)
- CommitObserver: reputation score 蓄積
- Sequential commit indexing + chain linkage

**問題**: ordering と observation が同居。reputation scoring が commit 決定と同じファイル。

### leader_schedule.rs (358 行, うち ThresholdClock 50 行)
- ThresholdClock: round advancement via stake quorum
- StakeAggregator: per-round stake tracking
- LeaderSchedule: reputation-weighted leader election
- ReputationScores: score container
- TimeoutBackoff: exponential timeout

**問題**: ThresholdClock は leader_schedule と無関係。分離すべき。

### checkpoint_manager.rs (326 行)
- Checkpoint 生成 (every CHECKPOINT_INTERVAL commits)
- Vote 集計 (per-checkpoint quorum)
- 署名検証
- Bounded finalized storage

**問題**: bft.rs の BFT 状態マシンと一部重複する quorum ロジック。

## 2. 分解計画

### 新モジュール 5 つ

```
narwhal_dag/
├── threshold_clock.rs       ← leader_schedule.rs から ThresholdClock + StakeAggregator を抽出
├── commit_vote_monitor.rs   ← bft.rs から equivocation 検知 + vote liveness を抽出
├── commit_observer.rs       ← pipeline.rs から CommitObserver を抽出
├── commit_syncer.rs         ← 新規実装 (遅延ノードのキャッチアップ)
└── (commit_finalizer.rs)    ← Phase 3 で既に作成済み
```

### bft.rs の残り (薄いオーケストレータ)
- BftPhase 状態マシンの遷移ロジックのみ
- vote 集計は commit_vote_monitor へ委譲
- finality 判定は commit_finalizer/checkpoint_manager との連携

## 3. モジュール間依存

```
threshold_clock ← dag_state (ブロック到着で observe)
       ↓
core_engine → leader_timeout (round 進行 → timeout 開始)
       ↓
commit_vote_monitor ← bft.rs (vote 到着で update)
       ↓
commit_observer ← committer (commit 決定を通知)
       ↓
commit_syncer ← sync_fetcher (遅延コミットを fetch)
       ↓
commit_finalizer ← executor (finalized TX を渡す)
```

依存方向: 上 → 下。循環なし。

## 4. finality crate との境界

| 責務 | narwhal_dag 側 | misaka-consensus 側 |
|------|--------------|-------------------|
| Commit ordering | UniversalCommitter | — |
| Per-TX reject voting | commit_finalizer.rs | — |
| BFT checkpoint voting | bft.rs (薄い状態マシン) | — |
| Checkpoint persistence | checkpoint_manager.rs | — |
| Economic finality (PoS) | — | economic_finality.rs |
| Validator slashing | — | validator_system_v2.rs |

原則: **DAG 内部の finality は narwhal_dag、PoS 経済的 finality は misaka-consensus。**

## 5. 移行戦略 (段階的)

1. **threshold_clock.rs**: leader_schedule.rs から ThresholdClock + StakeAggregator を move。
   leader_schedule.rs は re-export で後方互換維持。
2. **commit_vote_monitor.rs**: bft.rs から equivocation 検知を extract。
   bft.rs は monitor を呼ぶだけに。
3. **commit_observer.rs**: pipeline.rs から CommitObserver を move。
   pipeline.rs は re-export。
4. **commit_syncer.rs**: 新規実装。sync_fetcher.rs と連携。
5. **bft.rs 薄化**: 残った状態マシンのみ。目標 < 150 行。

各ステップで既存テスト全通しを確認。
