# Mempool Audit R3

## Verified Fixes
- ✅ Nullifier TOCTOU (C4): &mut self guarantees atomic check+insert
- ✅ TX hash canonical encoding: tx_hash_without_zk_proof() enforced
- ✅ Per-peer rate gate: 30 TX/60s per peer
- ✅ Cheap size gate: 2MiB TX limit, 256KiB proof limit

## MEDIUM
- **M5** No Replace-by-Fee mechanism. Low-fee TX clogs slot indefinitely.
