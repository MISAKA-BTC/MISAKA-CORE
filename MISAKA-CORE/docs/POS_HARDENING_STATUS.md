# MISAKA PoS L1 強化 — 実装ステータス
# BTC / Kaspa / XMR 級の堅牢性ロードマップ

> 最終更新: 2026-03-25
> 対象: misaka-core v5.2

---

## 実装完了サマリ

### Phase 1: PoS コンセンサスプロトコル ✅ COMPLETE

| モジュール | ファイル | 行数 | 状態 |
|-----------|---------|------|------|
| VRF Proposer | `vrf_proposer.rs` | 476 | ✅ ML-DSA-65 VRF, stake-weighted selection, RANDAO |
| BFT Types | `bft_types.rs` | 688 | ✅ Proposal, Vote, QC, Commit, Evidence, Timeout |
| BFT State Machine | `bft_state_machine.rs` | 906 | ✅ Tendermint 3-phase, locked value, round advance |
| Slash Detector | `slash_detector.rs` | 567 | ✅ DoubleProposal/Vote/Precommit, Surround Vote |
| Fork Choice | `fork_choice.rs` | 546 | ✅ GhostDAG + BFT finality anchor, chain tip |

**合計: 3,183行の新規 BFT コンセンサスコード**

### Phase 2: PoS 経済安全性 ✅ COMPLETE (本セッション)

| モジュール | ファイル | 行数 | 状態 |
|-----------|---------|------|------|
| Delegation | `delegation.rs` | 370 | ✅ delegate/undelegate/withdraw, reward distribution, slash propagation |

### Phase 5: プロトコルレベル安全性 ✅ COMPLETE (本セッション)

| モジュール | ファイル | 行数 | 状態 |
|-----------|---------|------|------|
| Inactivity Leak | `inactivity.rs` | 340 | ✅ Inactivity leak, correlation penalty, epoch boundary |
| Weak Subjectivity | `weak_subjectivity.rs` | 230 | ✅ Checkpoint guard, stale detection, long-range prevention |

### 既存の強固な基盤 (セッション前から完了)

| モジュール | 行数 | 比較対象 |
|-----------|------|----------|
| GhostDAG v2 | 20,898 | Kaspa GhostDAG 準拠 |
| PQC (ring sig, ZKP) | 17,000+ | XMR Triptych 以上 |
| UTXO + Stealth | 3,000+ | XMR Seraphis 準拠 |
| Staking Registry | 819 | Cosmos SDK staking に匹敵 |
| Economic Finality | 469 | BFT 2/3 checkpoint |
| Block Validation | 688 | Proposer sig 必須, ring enforcement |
| Tokenomics | 2,000+ | Integer-only inflation |
| P2P + Handshake | 5,342 | ML-KEM-768 encrypted transport |

---

## 残作業 (優先順位順)

### 🔴 Priority 1: Node Integration (BFT → main event loop)

**現状**: BFT state machine は pure logic として完成。ただし `misaka-node/src/main.rs` の
block production loop にまだ統合されていない。

**必要な作業**:

1. **`main.rs` の block producer loop を BFT 対応に改修**
   - 現在: `block_time_secs` ごとに無条件ブロック生成
   - 目標: VRF で proposer 判定 → BFT 3-phase → commit 後に finality
   
2. **P2P message routing for BFT**
   - `BftMessage` を P2P gossip に統合
   - prevote/precommit をリアルタイムで全 validator に配信
   
3. **Timeout handler**
   - `tokio::time::sleep` ベースの BFT timeout 管理
   - Round advance のトリガー

```
推定工数: 2-3 セッション
依存: なし (全 consensus モジュールは完成済み)
```

### 🟡 Priority 2: P2P GossipSub

**現状**: 基本的な P2P (peer discovery, handshake, sync) はあるが structured gossip なし。

**必要な作業**:

1. `crates/misaka-p2p/src/gossipsub.rs` — Topic-based pub/sub
2. BFT messages 用の dedicated topic
3. Peer scoring と GossipSub mesh management の統合
4. Flood publishing for latency-critical BFT votes

```
推定工数: 2 セッション
依存: Priority 1 (BFT integration)
```

### 🟡 Priority 3: State Sync Protocol

**現状**: 新規ノードは genesis からの full replay が必要。

**必要な作業**:

1. Header sync: BFT checkpoint chain のダウンロード
2. State snapshot: UTXO set の Merkle proof 付き取得
3. Block catch-up: finalized tip からの DAG sync
4. Pruning proof integration

```
推定工数: 3 セッション
依存: Priority 1 (BFT commits needed for checkpoint chain)
```

### 🟠 Priority 4: RocksDB Backend

**現状**: インメモリ UTXO set + WAL crash recovery。

**必要な作業**:

1. `rocks_backend.rs` — Column family 設計
2. Atomic write batch for block application
3. WAL 統合 (RocksDB built-in WAL に移行)
4. 既存の `UtxoSet` API を RocksDB 実装に切り替え

```
推定工数: 2 セッション
依存: なし
```

### 🟠 Priority 5: Light Client

**現状**: なし。

**必要な作業**:

1. BFT checkpoint + validator sig の軽量検証
2. TX inclusion Merkle proof
3. Chrome wallet extension への統合

```
推定工数: 2 セッション
依存: Priority 1 (BFT commits for checkpoint chain)
```

---

## BTC / Kaspa / XMR 比較 (現在の達成状況)

| 特性 | BTC | Kaspa | XMR | MISAKA 現在 | MISAKA 目標 |
|------|-----|-------|-----|-------------|-------------|
| コンセンサス | PoW | GhostDAG PoW | RandomX PoW | ✅ GhostDAG+BFT PoS | ✅ |
| Finality | 確率的 60分 | 確率的 10秒 | 確率的 20分 | ✅ 決定的 BFT | ✅ |
| プライバシー | 疑似匿名 | 疑似匿名 | Ring+Stealth | ✅ PQ Ring+Stealth+ZKP | ✅ |
| 量子耐性 | ❌ | ❌ | ❌ | ✅ ML-DSA/ML-KEM | ✅ |
| DAG 構造 | Linear | DAG | Linear | ✅ DAG | ✅ |
| VRF Proposer | N/A (PoW) | N/A (PoW) | N/A (PoW) | ✅ ML-DSA VRF | ✅ |
| BFT Safety | N/A | N/A | N/A | ✅ Tendermint-style | ✅ |
| Slashing | N/A | N/A | N/A | ✅ Auto-detection | ✅ |
| Delegation | N/A | N/A | N/A | ✅ DPoS | ✅ |
| Inactivity Leak | N/A | N/A | N/A | ✅ Casper-inspired | ✅ |
| Weak Subjectivity | N/A | N/A | N/A | ✅ Checkpoint guard | ✅ |
| Correlation Penalty | N/A | N/A | N/A | ✅ Quadratic penalty | ✅ |
| Nothing-at-Stake | N/A | N/A | N/A | ✅ 3-layer defense | ✅ |
| Node Integration | ✅ | ✅ | ✅ | 🔴 未統合 | Priority 1 |
| GossipSub P2P | ✅ | ✅ | ✅ | 🟡 Basic P2P のみ | Priority 2 |
| State Sync | ✅ | ✅ | ✅ | 🟡 Full replay のみ | Priority 3 |
| Persistent Storage | LevelDB | Custom | LMDB | 🟠 In-memory+WAL | Priority 4 |
| Light Client | SPV | N/A | N/A | 🟠 なし | Priority 5 |

---

## 新規モジュール統計

```
Phase 1 (前回):
  vrf_proposer.rs      476 lines
  bft_types.rs         688 lines
  bft_state_machine.rs 906 lines
  slash_detector.rs    567 lines
  fork_choice.rs       546 lines
  ──────────────────────────
  Phase 1 合計:      3,183 lines

Phase 2+5 (本セッション):
  delegation.rs        370 lines
  inactivity.rs        340 lines
  weak_subjectivity.rs 230 lines
  ──────────────────────────
  Phase 2+5 合計:      940 lines

全PoS強化合計:       4,123 lines
(テスト含む、全て misaka-consensus crate 内)
```

---

## 次のセッションで実行すべきプロンプト

### Priority 1 実行用プロンプト:

```
MISAKA-CORE v5.2 の Node Integration を実行してください。

対象ファイル:
- crates/misaka-node/src/main.rs (block producer loop の BFT 対応)
- crates/misaka-node/src/block_producer.rs (VRF proposer 判定)
- crates/misaka-node/src/dag_p2p_network.rs (BFT message routing)

以下を統合:
1. bft_state_machine.rs の BftStateMachine を main event loop に接続
2. vrf_proposer.rs の VRF evaluate/verify を block production に接続
3. slash_detector.rs を P2P message handler に接続
4. fork_choice.rs を DAG block ingestion に接続
5. delegation.rs の effective_stake を validator_set の weight 計算に統合
6. inactivity.rs を epoch boundary handler に統合
7. weak_subjectivity.rs を node 起動時の sync check に統合

既存の block_producer.rs の INVARIANT を維持:
「block_producer は state を直接変更しない — 全て execute_block() 経由」

既存の 60秒 block_time を BFT slot_time として使用。
BFT timeout は TimeoutConfig::default() (3秒 base + 1秒/round)。
```

---

## Config 変更 (本セッション)

`configs/mainnet.toml` に追加:
- `[staking] min_delegation = 1_000_000_000`
- `[weak_subjectivity] checkpoint = ""` (operator が初回設定)
- `[weak_subjectivity] ws_period_epochs = 10080`
