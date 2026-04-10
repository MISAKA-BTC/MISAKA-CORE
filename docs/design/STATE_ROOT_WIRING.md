# State Root Wiring Design

## CR-2: chain_store state_root was [u8;32] with zero default

## Current State (partially fixed)

`block_producer.rs:350` already computes a real state root:
```rust
let state_root = s.utxo_set.compute_state_root();
```

However, the type is `[u8; 32]` not the Phase 0 designed `StateRoot { native, vm, combined }`.
And `store_genesis` still uses `[0u8; 32]`.

## Fix Plan

### 1. Genesis state_root

`store_genesis` will use a well-defined genesis root:
```
genesis_state_root = SHA3("MISAKA-GENESIS-STATE-ROOT:v1:")
```
This is NOT zero — it's a deterministic non-zero value that all nodes agree on.

### 2. append_block validation

After genesis, `append_block` will reject zero state_root:
```rust
if height > 0 && state_root == GENESIS_STATE_ROOT_BYTES {
    return Err(ChainStoreError::GenesisRootAfterGenesis);
}
```

### 3. Type safety (future)

Full `StateRoot { native, vm, combined }` migration requires changes to:
- StoredBlockHeader serialization format (breaking)
- All callers of compute_hash
- Storage migration for existing chain data

This is deferred to Phase 19 (non-blocking for mainnet because
block_producer already computes real roots).

### 4. What this phase fixes

- Genesis uses a deterministic non-zero root (distinguishable from "unset")
- append_block validates state_root is not genesis root after height 0
- Documentation of who computes state_root and where
