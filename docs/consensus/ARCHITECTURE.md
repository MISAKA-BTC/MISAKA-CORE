# MISAKA コンセンサスアーキテクチャ

## 概要

MISAKA は Sui Mysticeti から派生した Narwhal/Bullshark DAG コンセンサスを採用。
GhostDAG は v6 で完全に除去され、全ての順序付けは Narwhal/Bullshark が担当する。

## パイプライン

```
1. Block Proposal (core_engine.rs)
   ├─ ML-DSA-65 署名
   ├─ ancestor selection (ancestor.rs) — 評判ベース親選択
   └─ commit vote piggy-back

2. Block Reception (block_manager.rs)
   ├─ 重複排除
   ├─ 祖先追跡 (missing → suspend)
   └─ unsuspend cascade

3. Block Verification (block_verifier.rs)
   ├─ ML-DSA-65 署名検証 (MlDsa65Verifier)
   ├─ author / epoch / round チェック
   ├─ ancestor ≥ 2f+1 検証
   └─ timestamp drift チェック

4. DAG Acceptance (dag_state.rs)
   ├─ BlockAcceptResult enum (#[must_use])
   ├─ equivocation 検知 (AcceptedWithEquivocation)
   └─ write batch → atomic persistence

5. Commit Decision (base_committer.rs + universal_committer.rs)
   ├─ Direct: ≥2f+1 votes at R+1 → commit
   ├─ Indirect: anchor has leader in causal history → commit
   ├─ Skip: anchor does NOT have leader → skip
   ├─ Undecided: need more blocks
   ├─ BFS safety: Aborted → Undecided (not Skip)
   └─ VoteRegistry: equivocation-safe vote tracking

6. Transaction Certification (transaction_certifier.rs)
   ├─ Fast-path: ≥2f+1 implicit accept → certified
   └─ Independent of commit pipeline

7. Commit Finalization (commit_finalizer.rs)
   ├─ Direct finalize: no reject votes → immediate
   ├─ Indirect finalize: wait INDIRECT_DEPTH rounds
   └─ Reject: quorum reject votes

8. Linearization (linearizer.rs)
   ├─ Sort by (round, authority)
   └─ Sequential delivery

9. BFT Checkpoint (narwhal_finality/)
   ├─ Per-digest quorum voting
   └─ Checkpoint every 100 commits
```

## 安全性保証

| 性質 | 保証 | 根拠 |
|------|------|------|
| Safety | 2つの quorum は >f members を共有 | `2Q - N > f`, `Q = N - floor((N-1)/3)` |
| Liveness | f 台までの Byzantine で進行 | 2f+1 threshold clock で round 進行 |
| Equivocation | 検知 + 証拠保全 | `BlockAcceptResult::AcceptedWithEquivocation`, `VoteEquivocation` |
| BFS 安全性 | cap 枯渇時は Undecided (Skip ではない) | `BfsResult::Aborted` |

## PQ 署名

全ブロック署名は ML-DSA-65 (FIPS 204 / Dilithium3)。
Ed25519 は完全に排除。PQ native。
