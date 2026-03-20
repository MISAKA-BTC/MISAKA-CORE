# MISAKA-CORE v2: DAG Integration Wiring Guide

## Dependency Injection Graph

```
                         ┌────────────────────┐
                         │     main.rs         │
                         │  (Orchestrator)     │
                         └────────┬───────────┘
                                  │ creates & wires
                    ┌─────────────┼─────────────┐
                    │             │              │
                    ▼             ▼              ▼
          ┌──────────────┐ ┌──────────┐ ┌──────────────┐
          │ dag_store    │ │ utxo_set │ │ ghostdag     │
          │ (Arc)        │ │ (owned)  │ │ (owned)      │
          └──────┬───────┘ └────┬─────┘ └──────┬───────┘
                 │              │               │
                 └──────────────┼───────────────┘
                                │
                                ▼
                   ┌────────────────────────┐
                   │    DagNodeState        │
                   │  (Arc<RwLock<...>>)    │
                   │                        │
                   │  .dag_store  ──────────┼──→ ThreadSafeDagStore
                   │  .ghostdag   ──────────┼──→ GhostDagManager
                   │  .state_manager ───────┼──→ DagStateManager
                   │  .utxo_set  ───────────┼──→ UtxoSet (v1 reused)
                   │  .mempool   ───────────┼──→ DagMempool
                   │  .proposer_id ─────────┼──→ [u8; 32]
                   │  .genesis_hash ────────┼──→ Hash
                   └────────────┬───────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │            │
                    ▼           ▼            ▼
          ┌──────────────┐ ┌────────┐ ┌──────────────┐
          │ DAG Block    │ │ DAG    │ │ Finality     │
          │ Producer     │ │ RPC    │ │ Monitor      │
          │ (tokio task) │ │ (task) │ │ (tokio task) │
          └──────────────┘ └────────┘ └──────────────┘
```

## Startup Sequence

```
main()
  │
  ├── 1. CLI parsing + config validation (shared with v1)
  │
  ├── 2. Feature branch: #[cfg(feature = "dag_consensus")]
  │     │
  │     └── start_dag_node()
  │           │
  │           ├── Layer 1: Storage
  │           │   ├── UtxoSet::new(1000)
  │           │   ├── genesis_header = DagBlockHeader { parents: [], ... }
  │           │   ├── genesis_hash = genesis_header.compute_hash()
  │           │   └── dag_store = Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header))
  │           │
  │           ├── Layer 2: Consensus
  │           │   ├── ghostdag = GhostDagManager::new(k=18, genesis_hash)
  │           │   └── finality = FinalityManager::new(checkpoint_interval=50)
  │           │
  │           ├── Layer 3: Execution
  │           │   └── state_manager = DagStateManager::new(HashSet::new())
  │           │
  │           ├── Layer 4: Mempool
  │           │   └── mempool = DagMempool::new(10000)
  │           │
  │           ├── DI Binding: DagNodeState { dag_store, ghostdag, state_manager, utxo_set, mempool, ... }
  │           │   └── shared_state = Arc::new(RwLock::new(dag_node_state))
  │           │
  │           ├── tokio::spawn → run_dag_rpc_server(shared_state.clone())
  │           │
  │           ├── tokio::spawn → run_finality_monitor(shared_state.clone())
  │           │
  │           └── run_dag_block_producer(shared_state, block_time, max_txs)  ← blocks
  │
  └── 3. (v1 fallback): start_v1_node()  [unchanged from v0.4.1]
```

## Data Flow: Transaction Lifecycle in DAG

```
                    User/Wallet
                        │
                  POST /api/submit_tx
                        │
                        ▼
              ┌──────────────────┐
              │   dag_rpc.rs     │
              │   submit_tx()    │
              │                  │
              │  1. Size check   │
              │  2. Deserialize  │
              │  3. Validate     │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │   DagMempool     │
              │   .insert(tx)    │
              │                  │
              │  KI check:       │
              │  • pool dedup    │
              │  • DAG spent?    │──→ state_manager.is_key_image_spent()
              └────────┬─────────┘
                       │
                       │ (waits in pool)
                       │
              ┌────────▼─────────┐
              │ DagBlockProducer │
              │                  │
              │  1. get_tips()   │──→ dag_store.snapshot()
              │  2. top_by_fee() │──→ mempool
              │  3. assemble()   │
              │  4. insert()     │──→ dag_store.insert_block()
              │  5. GhostDAG     │──→ ghostdag.calculate_ghostdag_data()
              │  6. Total Order  │──→ ghostdag.get_total_ordering()
              │  7. Apply TXs    │──→ state_manager.apply_ordered_transactions()
              │     ┌────────────┤
              │     │  for each TX in Total Order:
              │     │    if KI fresh → Applied (create outputs)
              │     │    if KI conflict → Failed (zero outputs, block stays valid)
              │     └────────────┤
              │  8. Cleanup      │──→ mempool.evict_spent_ki()
              └──────────────────┘
```

## Feature Flag Usage

```toml
# Default build: v1 linear chain (no DAG crate compiled)
cargo build -p misaka-node

# DAG build: v2 GhostDAG consensus
cargo build -p misaka-node --features dag_consensus

# Development with DAG:
cargo build -p misaka-node --features "dag_consensus,dev"

# Run DAG validator:
cargo run -p misaka-node --features dag_consensus -- --validator --dag-k 18

# Run DAG full node (no block production):
cargo run -p misaka-node --features dag_consensus
```

## CLI Arguments (DAG-specific)

| Argument | Default | Description |
|----------|---------|-------------|
| `--dag-k` | 18 | GhostDAG k parameter (concurrent block tolerance) |
| `--dag-checkpoint-interval` | 50 | Checkpoint creation interval (blue_score units) |
| `--dag-max-txs` | 256 | Maximum TXs per DAG block |
| `--dag-mempool-size` | 10000 | Maximum mempool size |

## Files Modified/Created

| File | Action | Purpose |
|------|--------|---------|
| `crates/misaka-node/src/main.rs` | **Modified** | Feature-gated v1/v2 startup |
| `crates/misaka-node/src/dag_rpc.rs` | **Created** | DAG RPC adapter (submit_tx → DagMempool) |
| `crates/misaka-node/Cargo.toml` | **Modified** | `dag_consensus` feature + `misaka-dag` dep |
| `crates/misaka-dag/` | **Created** (Phase 1+2) | All 7 DAG modules |

## Thread Safety Guarantees

| Component | Wrapper | Shared Between |
|-----------|---------|----------------|
| `DagNodeState` | `Arc<RwLock<...>>` | RPC, BlockProducer, FinalityMonitor |
| `ThreadSafeDagStore` | Internal `RwLock` + `Arc` in DagNodeState | All tasks via DagNodeState |
| `UtxoSet` | Owned by DagNodeState | Protected by DagNodeState's RwLock |
| `DagMempool` | Owned by DagNodeState | Protected by DagNodeState's RwLock |
| `DagStateManager` | Owned by DagNodeState | Protected by DagNodeState's RwLock |
| `GhostDagManager` | Owned by DagNodeState | Stateless reads via DagStore snapshots |
