# MISAKA PoS L1 — BFT Node Integration 完了報告

> Date: 2026-03-25
> Version: v5.2 (BFT PoS Integration)

## 完了したこと

BFT コンセンサスプロトコルの **全レイヤー** が node runtime に接続された。

```
┌─────────────────────────────────────────────────────────────────┐
│  misaka-node (main.rs)                                          │
│                                                                 │
│  ┌─────────────────────┐      ┌──────────────────────────────┐ │
│  │ DAG Block Producer   │      │ BFT Event Loop (NEW)         │ │
│  │ (dag_block_producer) │      │ (bft_event_loop.rs)          │ │
│  │                      │      │                              │ │
│  │ • Tips 取得           │      │ • Slot timer (= block_time) │ │
│  │ • TX 選択             │      │ • VRF proposer check        │ │
│  │ • GhostDAG 計算       │      │ • BFT 3-phase voting        │ │
│  │ • VirtualState resolve│      │ • Timeout management        │ │
│  │ • Snapshot persist    │      │ • Slash auto-detection      │ │
│  └──────────┬───────────┘      │ • Epoch boundary processing │ │
│             │                  └──────────┬───────────────────┘ │
│             │                             │                     │
│  ┌──────────▼─────────────────────────────▼──────────────────┐ │
│  │              Shared DagNodeState (Arc<RwLock>)             │ │
│  └──────────┬────────────────────────────────────────────────┘ │
│             │                                                   │
│  ┌──────────▼────────────────────────────────────────────────┐ │
│  │ P2P Event Loop (dag_p2p_network.rs)                        │ │
│  │                                                            │ │
│  │  DAG messages ─────────► DAG sync/ingestion pipeline       │ │
│  │  BFT messages ─────────► bft_msg_tx → BFT Event Loop      │ │
│  │  Slash evidence ───────► log + forward                     │ │
│  └──────────┬────────────────────────────────────────────────┘ │
│             │                                                   │
│  ┌──────────▼────────────────────────────────────────────────┐ │
│  │ PQ Transport (ML-KEM-768 + ChaCha20-Poly1305)             │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## メッセージフロー (End-to-End)

```
Slot N fires
  │
  ├─► BFT Event Loop: on_new_slot()
  │     │
  │     ├─► VRF evaluate(sk, slot, epoch_randomness)
  │     │     └─► am_i_proposer? → yes/no
  │     │
  │     ├─► [If proposer] DAG state read → block_hash, dag_checkpoint
  │     │     └─► BftStateMachine::on_new_round(am_i_proposer=true)
  │     │           └─► BftAction::BroadcastProposal
  │     │                 └─► sign with ML-DSA-65
  │     │                       └─► P2P outbound: DagP2pMessage::BftProposal
  │     │
  │     └─► [If not proposer] schedule proposal timeout
  │
  ▼
Remote validator receives BftProposal via P2P
  │
  ├─► dag_p2p_network::handle_inbound()
  │     └─► match DagP2pMessage::BftProposal
  │           └─► decode_bft_p2p_message()
  │                 └─► bft_msg_tx.try_send(BftInboundEvent)
  │
  ├─► BFT Event Loop: handle_bft_message()
  │     ├─► SlashDetector::check_message() (passive equivocation check)
  │     └─► BftStateMachine::on_proposal()
  │           └─► verify_proposal_vrf()
  │                 └─► vrf_verify(pk, slot, epoch_randomness)
  │           └─► decide_prevote() (Tendermint locked value rules)
  │                 └─► BftAction::BroadcastPrevote
  │                       └─► sign → P2P outbound: BftPrevote
  │
  ▼
2/3+ prevotes collected
  │
  └─► BftStateMachine::on_prevote() (quorum check)
        └─► polka detected → lock value
              └─► BftAction::BroadcastPrecommit
                    └─► sign → P2P outbound: BftPrecommit

2/3+ precommits collected
  │
  └─► BftStateMachine::on_precommit() (quorum check)
        └─► BftAction::Commit(BftCommit)
              │
              ├─► bft_driver::on_bft_commit()
              │     ├─► ForkChoiceState::on_bft_finality()
              │     ├─► SlashDetector::purge_below_slot()
              │     └─► BftStateMachine::gc_old_rounds()
              │
              ├─► Epoch boundary check (slot % EPOCH_LENGTH == 0?)
              │     └─► bft_driver::on_epoch_boundary()
              │           ├─► EpochRandomness::accumulate() (RANDAO)
              │           ├─► InactivityTracker::on_epoch_boundary()
              │           │     ├─► inactivity leak penalties
              │           │     └─► correlation penalties
              │           └─► WeakSubjectivityGuard::update_checkpoint()
              │
              └─► StakingRegistry::slash() (if equivocation detected)
```

## 全ファイル一覧 (BFT PoS 関連)

### misaka-consensus crate (9 modules, 5,288 行)

| File | Lines | Role |
|------|-------|------|
| `bft_types.rs` | 688 | BFT message types: Proposal, Vote, QC, Commit, Evidence, Timeout |
| `bft_state_machine.rs` | 906 | Tendermint 3-phase state machine: NewRound→Prevote→Precommit→Committed |
| `bft_driver.rs` | 720 | 統合ドライバー: VRF + BFT + Slash + ForkChoice + Inactivity + WS |
| `vrf_proposer.rs` | 476 | ML-DSA-65 VRF, stake-weighted selection, RANDAO |
| `slash_detector.rs` | 567 | DoubleProposal/Prevote/Precommit + Surround Vote (Casper FFG) |
| `fork_choice.rs` | 565 | GhostDAG + BFT finality anchor hybrid fork choice |
| `delegation.rs` | 594 | DPoS: delegate/undelegate/withdraw, reward split, slash propagation |
| `inactivity.rs` | 467 | Inactivity leak (Casper式) + Correlation penalty (二次関数) |
| `weak_subjectivity.rs` | 319 | Long-range attack prevention: trusted checkpoint guard |

### misaka-node crate (1 new module + 2 modified)

| File | Lines | Role |
|------|-------|------|
| `bft_event_loop.rs` | 570 | Async event loop: slot ticks, BFT msg recv, timeout mgmt |
| `main.rs` (modified) | +55 | Layer 5c: BftConsensusState init, BftEventLoop spawn, channel wiring |
| `dag_p2p_network.rs` (modified) | +70 | BFT message routing: BftProposal/Prevote/Precommit → BFT event loop |

### misaka-dag crate (1 modified)

| File | Change | Role |
|------|--------|------|
| `dag_p2p.rs` | +20 | BFT message variants in DagP2pMessage enum |

### Config (1 modified)

| File | Change |
|------|--------|
| `mainnet.toml` | `min_delegation`, `[weak_subjectivity]` section |

## 合計統計

```
BFT consensus logic (misaka-consensus):   5,302 lines
BFT node integration (misaka-node):         570 lines
P2P protocol extension (misaka-dag):         20 lines
main.rs wiring:                              55 lines
dag_p2p_network routing:                     70 lines
────────────────────────────────────────────────────
Total new/modified code:                   6,017 lines
```

## BTC / Kaspa / XMR 比較 (最終達成状況)

| Property | BTC | Kaspa | XMR | MISAKA |
|----------|-----|-------|-----|--------|
| Consensus | Nakamoto PoW | GhostDAG PoW | RandomX PoW | ✅ GhostDAG + BFT PoS |
| Finality | Probabilistic ~60min | Probabilistic ~10s | Probabilistic ~20min | ✅ Deterministic (BFT commit) |
| Privacy | Pseudonymous | Pseudonymous | Ring+Stealth | ✅ PQ Ring+Stealth+ZKP |
| Quantum Resistance | ❌ | ❌ | ❌ | ✅ ML-DSA-65/ML-KEM-768 |
| Block Structure | Linear | DAG | Linear | ✅ DAG (GhostDAG v2) |
| Proposer Selection | PoW mining | PoW mining | PoW mining | ✅ VRF (ML-DSA-65) |
| BFT Safety | N/A | N/A | N/A | ✅ Tendermint 3-phase |
| Equivocation Detection | N/A | N/A | N/A | ✅ Automatic (slash detector) |
| Slashing | N/A | N/A | N/A | ✅ Auto slash + reporter reward |
| Delegation | N/A | N/A | N/A | ✅ DPoS with commission |
| Inactivity Leak | N/A | N/A | N/A | ✅ Casper-inspired |
| Correlation Penalty | N/A | N/A | N/A | ✅ Quadratic |
| Long-range Defense | N/A (PoW) | N/A (PoW) | N/A (PoW) | ✅ Weak subjectivity |
| Fork Choice | Longest chain | GhostDAG blue | Longest chain | ✅ GhostDAG + BFT anchor |
| P2P BFT Messages | N/A | N/A | N/A | ✅ Proposal/Prevote/Precommit |
| Node Integration | ✅ | ✅ | ✅ | ✅ **BFT event loop connected** |

## 残りの作業 (テストネットデプロイ前)

### 🟡 Priority 1: Integration Test (1-2 sessions)

```
- 3-node local testnet で BFT commit が成立することを検証
- docker-compose + scripts/dag_release_gate.sh の BFT 対応
- BFT メッセージの P2P 往復を end-to-end で確認
```

### 🟡 Priority 2: GossipSub (2 sessions)

```
- 現在: HTTP RPC 経由の checkpoint vote gossip
- 目標: topic-based pub/sub for BFT messages (低レイテンシ)
```

### 🟠 Priority 3: State Sync (2-3 sessions)

```
- Header sync: BFT checkpoint chain download
- State snapshot: Merkle proof 付き UTXO set
- Block catch-up: finalized tip 以降の DAG sync
```

### 🟠 Priority 4: Light Client (2 sessions)

```
- BFT checkpoint + validator sig の軽量検証
- Chrome wallet extension への統合
```
