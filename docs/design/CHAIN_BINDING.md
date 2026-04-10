# Chain Context Binding — CR-2 Fix (Phase 30)

## Problem

Block digest computation included (epoch, round, author, timestamp, ancestors,
transactions, commit_votes, tx_reject_votes) but NOT chain_id or genesis_hash.

A validator using the same ML-DSA-65 keypair on testnet and mainnet would
produce identical signatures for identical blocks. An attacker could replay
a testnet-signed block on mainnet.

## Solution

### ChainContext type (`misaka-types/src/chain_context.rs`)
```
ChainContext { chain_id: u32, genesis_hash: [u8; 32] }
```

Compact 32-byte digest: `SHA3-256("MISAKA-CHAIN-CTX:v1:" || chain_id || genesis_hash)`

### Block signing digest

`Block::signing_digest(chain_ctx)` includes chain context digest
at the start of the BLAKE3 hash:
```
BLAKE3("MISAKA:narwhal:block:v2:" || chain_ctx.digest() || epoch || round || ...)
```

Domain separator bumped from `v1` to `v2` to prevent confusion.

### What is bound where

| Message type | chain_id | genesis_hash | epoch |
|-------------|----------|-------------|-------|
| Block signing | Yes | Yes | Yes (in block) |
| Vote signing | Yes | Yes | (via block reference) |
| TX signing | Yes (in TxType) | No | No |
| Bridge event | Yes | No | No |

### genesis_hash derivation

At node startup, genesis_hash is derived from the genesis committee:
```
SHA3-256("MISAKA-GENESIS:v1:" || chain_id || pk[0] || pk[1] || ... || pk[N-1])
```

This ensures different validator sets produce different genesis hashes
even with the same chain_id.

## Components modified

- `BlockVerifier` — carries `ChainContext`, uses `signing_digest()`
- `CoreEngine` — carries `ChainContext`, signs with `signing_digest()`
- `ConsensusRuntime` — passes `ChainContext` through to both
- `spawn_consensus_runtime` — accepts `ChainContext` parameter
- `main.rs::start_narwhal_node` — constructs `ChainContext` from CLI chain_id + committee

## Backward compatibility

None required — mainnet has not launched. Existing testnet data requires
storage wipe after this change (block digests differ).

## Regression tests

1. `cr2_testnet_block_rejected_on_mainnet` — different chain_id
2. `cr2_fork_block_rejected_on_main_chain` — same chain_id, different genesis
3. `cr2_same_chain_context_verifies` — positive case
