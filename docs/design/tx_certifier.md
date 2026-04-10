# Transaction Certifier — Design Document

## Sui Equivalent
`consensus/core/src/transaction_certifier.rs` (962 lines)

## Purpose
Enable fast-path transaction finality independent of the commit pipeline.
This is Mysticeti v2's key latency optimization: transactions are certified
(ready for execution) when a quorum of validators implicitly accept them,
without waiting for the full Bullshark commit cycle.

## Architecture

```
Block proposed at round R with TXs [T1, T2, T3]
    │
    ▼ (round R+1 blocks arrive)
TransactionCertifier tracks:
    T1: 3 accepts, 0 rejects → CERTIFIED (fast path)
    T2: 2 accepts, 1 reject  → PENDING
    T3: 0 accepts, 3 rejects → REJECTED
    │
    ├─ Certified TXs → user notified immediately (sub-second)
    └─ Commit pipeline → eventual total ordering (confirmation)
```

## PQ Signature Considerations

Sui uses Ed25519 aggregated signatures for certificates. MISAKA cannot
aggregate ML-DSA-65 signatures (Dilithium has no efficient aggregation).
Instead:

- Certification is **implicit**: inclusion in a block without reject vote = accept
- No explicit "certificate" object with aggregated sig
- Certification is proved by showing ≥2f+1 blocks that include the TX's
  block as ancestor and do NOT reject the TX
- This is equivalent to Sui's v2 fast path but without the signature savings

## Vote Semantics

- **Implicit accept**: authority B includes block A (which contains TX) as
  ancestor in B's block. B does NOT include A in `tx_reject_votes`.
- **Explicit reject**: authority B includes A as ancestor AND includes A in
  `tx_reject_votes`. B is saying "I saw the TX but consider it invalid."
- **No vote**: authority B does not include A as ancestor (hasn't seen it yet).

## GC and Memory
- Blocks below GC round are cleaned up
- Max pending blocks cap with LRU eviction

## File Location
`crates/misaka-dag/src/narwhal_dag/transaction_certifier.rs`

## Key Types
- `TxCertifier` — main engine
- `CertificationStatus { Pending, Certified, Rejected }`
- `CertifiedOutput { block_hash, certified_txs, rejected_txs }`
