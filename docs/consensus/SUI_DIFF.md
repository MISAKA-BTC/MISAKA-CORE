# Sui Mysticeti との差分表

## 意図的な差分

| 項目 | Sui | MISAKA | 理由 |
|------|-----|--------|------|
| 署名方式 | Ed25519 | ML-DSA-65 | Post-quantum native。FIPS 204 準拠。 |
| 署名集約 | BLS aggregated certificates | なし (implicit certification) | ML-DSA-65 に効率的な集約スキームがないため。implicit accept/reject で代替。 |
| トランザクションモデル | Shared objects + owned objects | UTXO | 設計思想の違い。UTXO は並列検証に有利。 |
| Execution layer | Move VM | NativeExecutor (Phase 0 Executor trait) | VM は将来追加。Phase 0 で境界面を凍結済み。 |
| Quorum formula | `N - (N-1)/3` | `N - (N-1)/3` | **同一**。v90 で修正済み (旧: `ceil(2N/3)`)。 |
| State root | Move object store hash | `StateRoot { native, vm, combined }` | vm フィールドは将来 VM 用。現状 zero。 |
| Validator management | On-chain staking with slashing | ADA-style no-slash + score + demotion | 元本没収なし方針。Active 21 固定 + Backup 自由参加。 |

## 構造的な差分

| Sui file | Lines | MISAKA equivalent | Lines | 差分理由 |
|----------|-------|-------------------|-------|---------|
| `core.rs` | 4,065 | `core_engine.rs` | 877 | Sui は async event loop + tokio channel を core.rs 内に持つ。MISAKA は `runtime.rs` (446行) が担当。 |
| `commit_finalizer.rs` | 1,617 | `commit_finalizer.rs` | 410 | Sui は shared object の reject vote 集約が複雑。MISAKA UTXO は reject 集約が単純。 |
| `transaction_certifier.rs` | 962 | `transaction_certifier.rs` | 377 | Sui は BLS certificate 生成が含まれる。MISAKA は implicit certification (署名集約なし)。 |
| `dag_state.rs` | ~2,600 | `dag_state.rs` | 750 | Sui は SubscriberState + SignedBlock verification を dag_state 内に持つ。MISAKA は block_verifier が分離。 |

## MISAKA が Sui より改善している点

| 項目 | 説明 |
|------|------|
| BFS safety | `BfsResult::Aborted → Undecided`。Sui は cap 到達で `false` を返す (同じリスクが存在する可能性)。 |
| `BlockAcceptResult` enum | `#[must_use]` で equivocation 無視バグをコンパイル時に防止。Sui は `bool` 返却。 |
| `VoteRegistry` | BTreeMap + explicit `VoteEquivocation` 型。Sui は HashMap で暗黙の重複排除。 |
| `debug_assert!(2*q > total+f)` | Construction 時に safety invariant を検証。Sui にもあるが assert message が不明瞭。 |

## MISAKA が Sui に劣る点

| 項目 | 説明 |
|------|------|
| Async integration | Sui の core.rs は完全に async。MISAKA は sync + 外部 runtime。 |
| Shared object fast-path | Sui はオブジェクトタイプ別の最適化あり。MISAKA は UTXO 単一パス。 |
| Production-tested | Sui は mainnet で 1 年以上稼働。MISAKA は未稼働。 |
| Comprehensive metrics | Sui は Prometheus + Grafana 完全統合。MISAKA は基本的な counter のみ。 |
