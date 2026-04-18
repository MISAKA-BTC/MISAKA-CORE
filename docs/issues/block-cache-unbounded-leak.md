# BUG: `block_cache` grows unbounded (memory leak)

**Severity**: HIGH (memory), not blocking testnet smoke, **must-fix before mainnet**.
**Status**: Open. Discovered 2026-04-18 during hotfix/peer-replay-window validation.
**Not caused by**: the hotfix — this is pre-existing.

## Evidence

- `crates/misaka-node/src/main.rs:1935`:
  ```rust
  let block_cache: Arc<RwLock<BTreeMap<BlockRef, NarwhalBlock>>> =
      Arc::new(RwLock::new(BTreeMap::new()));
  ```
- Insert call sites:
  - `main.rs:3411` — on block broadcast (every proposed block)
  - `main.rs:3629` — on accepted inbound block
  - `main.rs:3711` — on BlockResponse-delivered block
- Eviction call sites: **none**. Zero matches for `block_cache.remove`, `clear`, `retain`, `drain`, `pop` anywhere in the tree.

## Growth rate (observed, v0.8.8 2 s blocks)

From `hotfix_w100` harness run, `cache_total` field in the enriched `narwhal_peer_replay` log line:

| Wall-clock since start | Reported `cache_total` |
|---|---|
| T+0:00 | 0 |
| T+0:15 | 22 |
| T+2:30 | 528 |
| T+3:00 | 4500 |
| T+5:00 | 4669 |

≈ 1000 blocks / minute under current v0.8.8 block rate. Projected:

- **1 hour**: ~60 000 blocks
- **1 day**: ~1.4 million blocks
- Block size ~70 KB (ML-DSA signature + header + tx envelopes)
- **Daily memory growth: ~100 GB per node** under sustained operation

## Interaction with the hotfix

`PEER_REPLAY_ROUND_WINDOW = 100` bounds what is *sent* from the cache on reconnect, but does not bound what is *kept*. The hotfix trades consensus liveness against memory safety — the cache grows regardless. On a fresh cold-reset or short-lived chain the cache stays small, so the hotfix does not regress memory behavior; on a long-running chain the unbounded growth was already present at `PEER_REPLAY_ROUND_WINDOW = 3`.

## Fix options (for a future PR, NOT this hotfix)

### A. LRU by insertion time
Wrap `block_cache` in an LRU with a capacity cap (e.g. 10 000 blocks ≈ 700 MB). Simplest. Eviction is time-of-insert, independent of round.

### B. Prune by round below committed_round - PEER_REPLAY_ROUND_WINDOW
Periodically drop entries where `BlockRef.round < committed_round - PEER_REPLAY_ROUND_WINDOW`. Aligned with the replay window semantics, so nothing the replay path would send ever gets evicted. Needs a wake-up task (background tokio loop) or opportunistic pruning on write.

### C. Drop the cache entirely, fetch-on-demand from RocksDB
`BlockRequest` handler at `main.rs:3723` already has the block store wired; reading from disk is a few ms per block. Removes the whole memory class.

**Recommendation**: B. Keeps the hot path in-memory for the replay window that the hotfix depends on, but bounds total size to a small multiple of that window.

## Why not fix now

- Hotfix scope principle: single root cause per PR.
- Pre-existing; v0.8.9 testnet smoke is not meaningfully affected over the <24 h observation window (cache stays < ~100 GB).
- Fixing this correctly (option B) requires touching the broadcast/accept/response hot path and the lock discipline; warrants its own review.

## Related

- `docs/issues/unbonding-27-years.md` — same pattern (pre-existing, documented, deferred).
- Hotfix PR on `hotfix/peer-replay-window` (`355d023`, `3f75eac`) — this doc and the leak were discovered during its validation.
