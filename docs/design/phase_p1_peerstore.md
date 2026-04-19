# Phase P1 — Peerstore persistence (v0.9.2)

Status: **Foundation shipped in this commit. Full wiring (RocksDB handle, updater task, CLI / RPC, bootstrap integration) lands in follow-on commits.**
Branch: `main` (continuous development).

Cross-references:
- `crates/misaka-storage/src/peerstore.rs` — schema + pure-logic event policy (this commit).
- `crates/misaka-storage/src/columns.rs` — `StorageCf::Peerstore` variant.
- `crates/misaka-p2p/src/discovery.rs` — existing in-memory `PeerStore` + `DiscoveryBackend` trait.

---

## 1. Summary

Phase P1 of the [P2P Discovery improvement series](../ops/p-series-index.md) moves the
peer record cache from process-memory-only into RocksDB so a node that restarts can
recover its peer set without re-consulting the seed list. Combined with P0 (multi-seed
+ PK pinning) and P2 (PEX), this moves MISAKA from "single-seed bootstrap SPOF" to
"Cosmos / Bitcoin-class decentralised discovery".

## 2. What's shipped this commit

### 2.1 `StorageCf::Peerstore` variant

New column family in `crates/misaka-storage/src/columns.rs`:

- Canonical name: `"peerstore"`
- Owned by `StorageCf::ALL` (index 5)
- Added to the exhaustiveness test (`all_is_exhaustive_and_unique`)
- `names_match_pre_refactor_literals` pins the string so a rename would break disk compat

### 2.2 Schema types (`crates/misaka-storage/src/peerstore.rs`)

- `PeerId` = `[u8; 32]` — derived from the peer's ML-DSA-65 transport public key
  (same identifier space as Phase P0's `SeedEntry`).
- `PeerStoreRecord` — versioned per-peer record with:
  - Public key (optional for temp addr-only entries)
  - Multiple `PeerAddr` entries (host:port + per-address last_success + failure_count)
  - Observation timestamps (`first_seen`, `last_seen`, `last_dial_*`)
  - Cumulative connection counters (`successful_connections` / `failed_connections`)
  - Self-declared `PeerRole`
  - `TrustScore` with decay-aware `updated_at`
  - `banned_until` (optional unban deadline)
  - `PeerSource` (where we first learned of this peer)
- `PeerEvent` — 8 event variants that the hot path emits (connection events, block
  validation events, equivocation, protocol violations, advertise validation failures).

### 2.3 Pure-logic event policy

`apply_peer_event(&mut PeerStoreRecord, &PeerEvent, now: u64)` — no I/O, fully
deterministic. Trust-score deltas:

| Event | Δ |
|---|---|
| `ConnectionEstablished` | +0.05, bumps `successful_connections` |
| `ConnectionFailedUnreachable` | −0.02, bumps `failed_connections` |
| `HandshakeFailed` | −0.10, bumps `failed_connections` |
| `ValidBlockReceived` | +0.01 |
| `InvalidBlockReceived` | −0.30 |
| `EquivocationDetected` | → 0.0 immediately + 24 h auto-ban |
| `ProtocolViolation` | −0.50 |
| `AdvertiseValidationFailed` | −0.20 |

Clamped to `[0.0, 1.0]`. Falling below `BAN_TRUST_THRESHOLD = 0.1` on any non-ban
event triggers the same 24 h auto-ban. Tests cover:

- Initial record shape (neutral trust 0.5, unbanned, current schema version)
- Each event variant's effect
- Score clamping (repeated +/− drives to 1.0 / 0.0)
- `banned_until` semantics (strict inequality on expiry)
- Bincode serde round-trip preserves the record exactly
- Two-step ban threshold crossing (first `InvalidBlockReceived` stays above threshold,
  second crosses and fires auto-ban)

### 2.4 Constants

Public constants for downstream modules:

- `INITIAL_TRUST_SCORE = 0.5`
- `BAN_TRUST_THRESHOLD = 0.1`
- `PROMOTE_TRUST_THRESHOLD = 0.8`
- `AUTO_BAN_DURATION_SECS = 86_400`
- `DEFAULT_MAX_PEERSTORE_ENTRIES = 10_000`
- `DEFAULT_INACTIVE_PEER_TTL_SECS = 2_592_000` (30 days)
- `PEERSTORE_SCHEMA_VERSION = 1`

## 3. Scope deferred to follow-on commits

The P1 spec in `phase_p1_peerstore_prompt.md` requires full wiring. Split as:

### 3.1 `PeerstoreUpdater` background task

Hot path: `tx.try_send((peer_id, event))` → bounded mpsc → background task:

```rust
pub struct PeerstoreUpdater {
    rx: mpsc::Receiver<(PeerId, PeerEvent)>,
    store: Arc<dyn PeerstoreBackend>,
}

impl PeerstoreUpdater {
    pub async fn run(mut self) {
        while let Some((peer_id, event)) = self.rx.recv().await {
            // get → apply_peer_event → put
        }
    }
}
```

### 3.2 `PeerstoreBackend` trait + `RocksPeerstore`

```rust
pub trait PeerstoreBackend: Send + Sync {
    fn get(&self, peer_id: &PeerId) -> Result<Option<PeerStoreRecord>>;
    fn put(&self, record: &PeerStoreRecord) -> Result<()>;
    fn delete(&self, peer_id: &PeerId) -> Result<()>;
    fn list(&self, filter: PeerFilter) -> Result<Vec<PeerStoreRecord>>;
    fn prune_inactive(&self, cutoff: u64) -> Result<usize>;
    fn ban(&self, peer_id: &PeerId, until: u64) -> Result<()>;
    fn unban(&self, peer_id: &PeerId) -> Result<()>;
}

pub struct RocksPeerstore {
    db: Arc<DB>,
}
```

Key encoding: `peer_id` raw (32 bytes). Value: `bincode::serialize(&record)`.

### 3.3 Bootstrap integration

`misaka-node/src/main.rs` — on startup:
1. Open RocksDB, resolve the Peerstore CF handle
2. `list(PeerFilter { banned: Some(false), active_within_secs: Some(7 * 24 * 3600), limit: Some(32) })`
3. Merge into the parallel-dial candidate set alongside `parsed_seeds`
4. On every successful handshake, emit `ConnectionEstablished` to the updater

### 3.4 CLI + RPC

- `misaka-cli peer {list, info, ban, unban, forget, prune}`
- `GET /api/peers`, `GET /api/peers/:peer_id`,
  `POST /api/peers/:peer_id/{ban, unban}`, `DELETE /api/peers/:peer_id`,
  `POST /api/peers/prune`

### 3.5 Metrics

- `misaka_peerstore_entries{role=…}`
- `misaka_peerstore_active_peers`
- `misaka_peerstore_banned_peers`
- `misaka_peerstore_trust_score_{p50,p99}`
- `misaka_peerstore_updates_total{event=…}`
- `misaka_peerstore_pruned_total`

### 3.6 Bounded growth

- Max entries: `NodeConfig.max_peerstore_entries` (default 10,000)
- On reaching cap: evict the bottom 10% by trust score (banned entries exempt — kept
  as evidence for operator audit)
- Inactive TTL: `DEFAULT_INACTIVE_PEER_TTL_SECS = 30 d`; `prune_inactive` sweeps
  non-banned records whose `last_seen` predates the cutoff

## 4. Migration / compatibility

- Pre-v0.9.2 databases lack the `peerstore` CF. The DB-open path auto-creates missing
  CFs (existing behaviour for `StorageCf::BlockMeta` additions etc.) so this is a
  one-shot additive migration.
- Schema version byte prefix on every `PeerStoreRecord` — future v2 records MUST be
  rejected by v1 decoders rather than silently misparsed. The test
  `serde_roundtrip_preserves_record_exactly` pins v1 layout.

## 5. Non-goals for P1

- **PEX protocol** (P2). Peerstore is populated only from: (a) the P0 seed config,
  (b) observed inbound connections on the Narwhal relay, (c) CLI / RPC manual adds.
  Gossip-based discovery waits for P2.
- **Committee on-chain registry** (P3). Resolving committee addrs from chain state
  is a hardfork-level change — deferred to v0.10.0.
- **Trust-score decay**. The index mentions "1 / day decay towards neutral"; this is
  deferred until we have real gossip traffic (P2) to size the decay rate against.
  Until then, the score stays where events left it.

## 6. Test plan status

### 6.1 Shipped (this commit)

- 8 unit tests in `peerstore::tests` (all pass).
- 3 unit tests in `columns::tests` updated for the new variant (all pass).

### 6.2 To add with 3.2 (RocksPeerstore)

- Integration: put → get round-trip against a tempdir RocksDB
- Integration: `prune_inactive` cutoff behaviour
- Integration: max-entries eviction preserves banned records
- Integration: concurrent event update atomicity

### 6.3 To add with 3.3 (bootstrap integration)

- 4-node testnet: peerstore populated from Narwhal handshake events
- Restart-with-empty-seeds: node restarts with seed list cleared, recovers via
  peerstore entries only
- Malicious peer injection: synthetic equivocation event ⇒ auto-ban persists across
  restart

---

_最終更新：2026-04-19（P1 foundation shipped）_
