# MISAKA-CORE v2: Privacy BlockDAG Architecture Blueprint

## Overview

This document describes the complete architecture for migrating MISAKA-CORE from
a linear blockchain (v1) to a Privacy BlockDAG (v2) using GhostDAG consensus
with LogRing anonymous transactions.

---

## Module Map

```
crates/misaka-dag/src/
├── lib.rs                   # Crate root, re-exports, ASCII architecture diagram
├── dag_block.rs             # Phase 1: DAG block header (multi-parent)
├── ghostdag.rs              # Phase 1: GhostDAG consensus (Blue/Red, Total Order)
├── dag_state_manager.rs     # Phase 1: Delayed state evaluation (KI conflict resolution)
├── dag_store.rs             # Phase 2: Thread-safe DAG store + DagStore snapshot
├── dag_block_producer.rs    # Phase 2: DAG block producer + DAG mempool
├── dag_p2p.rs               # Phase 2: P2P protocol messages + sync state machine
└── dag_finality.rs          # Phase 2: Finality, checkpoints, pruning, Virtual Block
```

---

## Three Core Challenges — How They're Solved

### Challenge 1: DAG Ordering (Topological Ordering)

**Module:** `ghostdag.rs`

| Component | Purpose |
|-----------|---------|
| `DagStore` trait | Storage abstraction for headers + GhostDagData |
| `GhostDagManager::calculate_ghostdag_data()` | Selected Parent + Blue/Red classification |
| `GhostDagManager::get_total_ordering()` | Deterministic linearization of entire DAG |
| `InMemoryDagStore` / `DagStoreSnapshot` | Test + production snapshot implementations |

**Algorithm:** For each new block:
1. Select parent with highest `blue_score`
2. Compute mergeset (blocks reachable from parents but not from selected parent's past)
3. Classify mergeset: anticone ∩ Blue ≤ k → Blue, else Red
4. `blue_score = selected_parent.blue_score + |mergeset_blues| + 1`

**Total Order:** Walk Selected Parent Chain from genesis → virtual tip, inserting
each block's mergeset (Blues first, Reds second) in blue_score-ascending order.

### Challenge 2: Delayed State Evaluation & Key Image Conflict

**Module:** `dag_state_manager.rs`

| Component | Purpose |
|-----------|---------|
| `DagStateManager` | Walks Total Order, applies TXs, resolves KI conflicts |
| `TxApplyStatus` enum | Applied / FailedKeyImageConflict / FailedInvalidSignature |
| `UtxoAction` callback | Dependency-inverted UTXO mutations |
| `OrderedBlockData` / `OrderedTxData` | Input structs from Total Order |

**Core Logic:**
```
for each block in total_order:
  for each tx in block.transactions:
    if any tx.key_image ∈ applied_key_images:
      → mark TX as FailedKeyImageConflict
      → generate ZERO outputs
      → block remains valid (fail-soft)
    else:
      → record all key_images
      → generate outputs via callback
```

**Critical Properties:**
- **Atomicity:** If any KI in a multi-input TX conflicts, the ENTIRE TX fails.
  Other KIs in that TX remain unspent (available for other TXs).
- **Fail-soft:** Block validity is independent of TX validity.
- **Determinism:** Same Total Order → same UTXO Set on all nodes.

### Challenge 3: Safe Decoy Selection

**Module:** `dag_state_manager.rs` (`DecoyFilter`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `MIN_DECOY_DEPTH` | 100 | Minimum confirmation depth for ring member UTXOs |
| `FINALITY_DEPTH` | 100 | Blocks beyond this are reorg-proof |
| `PRUNING_DEPTH` | 500 | TX data retained (must > FINALITY + DECOY depth) |

**Filter Rules:**
1. UTXO's block must have `confirmation_depth ≥ MIN_DECOY_DEPTH`
2. UTXO must not be from a Failed TX
3. Amount must match (same-amount ring requirement)

---

## v1 → v2 Migration Map

### Data Structures

| v1 | v2 | Notes |
|----|-----|-------|
| `StoredBlockHeader.parent_hash` | `DagBlockHeader.parents: Vec<Hash>` | Single → multi-parent |
| `StoredBlockHeader.height` | `GhostDagData.blue_score` | Linear height → DAG score |
| `StoredBlockHeader.state_root` | Removed (delayed eval) | State unknown at block time |
| `UtxoTransaction` | **Unchanged** | Reused directly |
| `RingInput` | **Unchanged** | Reused directly |
| `TxOutput` / `OutputRef` | **Unchanged** | Reused directly |
| `UtxoSet` | **Unchanged** | Updated via `UtxoAction` callback |
| `BlockCandidate` | `DagBlock` | Wraps `DagBlockHeader` + TXs |

### Execution Path

| v1 | v2 |
|----|-----|
| `block_producer` → `execute_block()` → `validate_and_apply_block()` | `dag_block_producer` → `GhostDAG` → `Total Order` → `apply_ordered_transactions()` |
| Direct `utxo_set` mutation in `execute_block` | `UtxoAction` callbacks (dependency inversion) |
| Block invalid if any TX invalid | Block valid even if TXs fail (fail-soft) |

### P2P Protocol

| v1 | v2 |
|----|-----|
| `NewBlock { height, parent_hash }` | `NewDagBlock { parents, blue_score }` |
| `GetBlocks(from_height, to_height)` | `GetDagBlocks { hashes }` |
| Height-based sync | Tips-exchange + BFS ancestor download |
| N/A | `DagSyncManager` state machine (Handshaking → Downloading → Synced) |

---

## Constants Summary

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `DAG_VERSION` | `0x02` | `dag_block.rs` | Protocol version |
| `MAX_PARENTS` | `10` | `dag_block.rs` | Max parent references |
| `MAX_TIMESTAMP_DRIFT_MS` | `120,000` | `dag_block.rs` | 2 min future tolerance |
| `GhostDAG k` | `18` | `ghostdag.rs` | Anticone threshold |
| `MIN_DECOY_DEPTH` | `100` | `ghostdag.rs` | Safe ring member depth |
| `FINALITY_DEPTH` | `100` | `dag_finality.rs` | Reorg-proof depth |
| `PRUNING_DEPTH` | `500` | `dag_finality.rs` | TX data retention |

---

## Test Coverage

Each module includes unit tests:

- **`dag_block.rs`**: Hash determinism, parent order independence, structural validation
- **`ghostdag.rs`**: Diamond DAG (G→A,B→C), blue_score computation, total ordering
- **`dag_state_manager.rs`**: Basic apply, KI conflict resolution, multi-KI atomicity,
  failed TX output suppression
- **`dag_store.rs`**: Tips tracking, missing parent rejection
- **`dag_block_producer.rs`**: Block assembly, mempool KI dedup
- **`dag_p2p.rs`**: Sync manager basic flow, chain download
- **`dag_finality.rs`**: Checkpoint interval, creation

---

## Next Steps (Phase 3)

1. **RocksDB backend**: Replace `ThreadSafeDagStore` with RocksDB-backed impl
   using v1's CF pattern
2. **LogRing integration**: Wire `logring_verify()` into `dag_state_manager`'s
   signature verification path
3. **Differential state application**: Optimize `apply_ordered_transactions()`
   to only process new blocks since last checkpoint (not full replay)
4. **Wire protocol**: Implement actual TCP/Noise XX framing for `DagP2pMessage`
5. **Future**: Additional consensus integration points for cross-shard validation
