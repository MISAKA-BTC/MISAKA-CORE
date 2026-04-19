# Phase P0 — Multi-seed list (v0.9.1 closure)

Status: **Core shipped in Phase 2a/2b. P0 closure adds metrics + docs only.**
Branch: integrated on `main` (v0.9.0 base).

Cross-references:
- `crates/misaka-types/src/seed_entry.rs` — `SeedEntry` struct with mandatory PK pinning
- `crates/misaka-node/src/main.rs` — CLI `--seeds` + `--seed-pubkeys` parsing (~line 900-950)
- `crates/misaka-node/src/narwhal_block_relay_transport.rs` — parallel dial implementation (~line 725-741)
- `docs/ops/seed-configuration.md` — operator-facing guide

---

## 1. Summary

Phase P0 of the [P2P Discovery improvement series](../ops/p-series-index.md) targets removing
the single-seed bootstrap SPOF. The original P0 prompt proposed migrating a hypothetical
`seed: String` scalar field to a `Vec<SeedAddr>` with parallel dial and PK pinning.

**Reality check (Step 0.1 survey on `origin/main` @ cceffa1)**: the core work is **already shipped**
in Phase 2a / Phase 2b (v0.8.x):

| P0 requirement | Status | Evidence |
|---|---|---|
| Seeds is a list, not a scalar | ✅ Done | `seeds: Vec<String>` in CLI + config (main.rs:282, config.rs:205) |
| Mandatory PK pinning per seed | ✅ Done | `SeedEntry { address, transport_pubkey: String }`, validated at load (seed_entry.rs:28-90) |
| Hard fail on PK / addr / count mismatch | ✅ Done | `exit(1)` with structured FATAL log at main.rs:904-938 (not TOFU-fallback, not warn-and-continue) |
| Parallel dial across seeds | ✅ Done | `tokio::spawn(connect_outbound_peer(...))` per peer at narwhal_block_relay_transport.rs:738 |
| `force_dial=true` for NAT traversal | ✅ Done | Seeds bypass the `peer.authority_index > self.authority_index` ordering filter (relay_transport.rs:729) |
| No TOFU | ✅ Done | Explicitly documented in-code: "there is no TOFU mode" (main.rs:891) |
| Dynamic committee hot-reload | ✅ Done | `relay_update_rx` spawns new outbound dials for newly-registered validators (relay_transport.rs:754-785) |

**Remaining gap** (this doc + accompanying commit):
1. Bootstrap metrics export (`misaka_bootstrap_*`) — not currently surfaced to `/api/metrics/node`.
2. Design / ops documentation (this file + `docs/ops/seed-configuration.md`).
3. README TOML example showing the `SeedEntry` shape with `transport_pubkey`.

Rationale for ship-as-closure: the core P0 protocol properties are live; re-implementing
them under a "new" design would risk breaking the existing Phase 2a/2b PK-pinning contract
that has been smoke-tested on the current testnet. The right closure is to document what
shipped and backfill the observability gap.

---

## 2. Current data model

### 2.1 CLI surface

```bash
misaka-node \
    --seeds "163.43.225.27:6690,133.167.126.51:6690,163.43.142.150:6690,163.43.208.209:6690" \
    --seed-pubkeys "0x<1952B hex>,0x<1952B hex>,0x<1952B hex>,0x<1952B hex>" \
    --chain-id 2 \
    run
```

- `--seeds`: comma-separated `host:port` list (4 addresses recommended for testnet)
- `--seed-pubkeys`: comma-separated `0x<hex>` list, MUST match `--seeds` in count + order
- Count mismatch → `exit(1)` with FATAL (see `main.rs:914-921`)
- Invalid address / hex / ML-DSA key → `exit(1)` with FATAL (main.rs:1990-2015)

### 2.2 Config surface (`SeedEntry`)

```toml
# ~/misaka-config/validator.toml (see distribution/testnet-validator/validator.toml)
[[seeds]]
address = "163.43.225.27:6690"
transport_pubkey = "0x<3904 hex chars>"

[[seeds]]
address = "133.167.126.51:6690"
transport_pubkey = "0x<3904 hex chars>"

# ... 4 entries for testnet; pk_hex is the ML-DSA-65 transport PK
```

The `transport_pubkey` field is validated at config-load time:
- Length MUST be 3904 hex chars (`1952 bytes` for ML-DSA-65 pk)
- MUST be valid hex (optional `0x` prefix)
- Empty `address` or missing `host:port` format → validation error

Obtaining a seed's PK: `misaka-node --emit-validator-pubkey` prints it on stdout.

### 2.3 Legacy scalar `seed = "..."` fallback

**Not supported**. Phase 2a intentionally dropped TOFU because single-scalar seed without PK
was the attack surface P0 aims to close. Operators upgrading from pre-v0.8.x configs
MUST migrate to the array form; there is no silent deprecation path.

---

## 3. Dial semantics

### 3.1 Parallel dial

At relay-transport startup (`narwhal_block_relay_transport.rs:725-741`) every peer in
the configured list is dialed concurrently via `tokio::spawn`:

```rust
for peer in config.peers.iter()
    .filter(|peer| peer.force_dial
                || config.observer_self
                || peer.authority_index > config.authority_index)
    .cloned()
{
    let registry = registry.clone();
    let inbound_tx = inbound_tx.clone();
    let config = config.clone();
    tokio::spawn(async move {
        connect_outbound_peer(peer, config, registry, inbound_tx).await;
    });
}
```

Seeds always pass the filter because they are configured with `force_dial = true`
(main.rs:2023). This means:
- **Bootstrap time** is bounded by the slowest successful seed, not the sum of all seeds
- Seed failures in parallel don't block each other
- A NAT-ed validator can always proactively dial the seed, even when the seed's
  `authority_index` is lower than its own

### 3.2 PK pinning verification

`connect_outbound_peer` drives the Narwhal relay handshake which mutually validates both
sides' ML-DSA-65 identity (see handshake implementation in relay transport). PK mismatch
→ connection drop, no fallback. This is the MITM-resistance property P0 required.

### 3.3 Retry strategy

- Dial timeout / connection refused: natural `tokio::spawn` tasks complete with `Err`; the
  other parallel tasks are unaffected.
- Handshake (PK mismatch): connection drops, error logged, no retry on that peer.
- All seeds unreachable: the relay transport surfaces the node as 0-peer until at least
  one seed dial succeeds. There is no explicit "all seeds unreachable, exit(1)" guard
  today — a node with all-dead seeds simply runs isolated and surfaces via
  `/api/get_chain_info.peerCount = 0`.

Rationale for NOT adding the `exit(1)` guard: the relay maintains a reconnection loop
that periodically retries failed peers, so transient all-seed outages are recoverable
without operator intervention. The operational signal is `peerCount=0` + commit rate = 0
(detectable via metrics), not startup-time exit.

---

## 4. Observability (this phase's new work)

### 4.1 Bootstrap metrics (`/api/metrics/node`)

Added in this commit (see `crates/misaka-dag/src/narwhal_dag/slo_metrics.rs`):

- `misaka_bootstrap_seeds_configured` (IntGauge) — count from CLI / config
- `misaka_bootstrap_seeds_connected` (IntGauge) — current successful seed handshakes
- `misaka_bootstrap_seed_dial_failures_total{reason}` (IntCounter) — cumulative dial failures
  labeled by reason (`timeout` / `refused` / `pk_mismatch` / `handshake` / `other`)

### 4.2 Existing signals (already exported)

- `/api/get_chain_info.peerCount` — current live peer count, surfaces multi-seed health
- `/api/get_peers` — full peer list with per-peer status
- Structured FATAL logs on config errors (grep-able by `FATAL: --seeds` / `FATAL: --seed-pubkeys`)

---

## 5. Operator quick reference

See [`docs/ops/seed-configuration.md`](../ops/seed-configuration.md) for the full operator
runbook. Key points:

- 4 seeds recommended for testnet; 3+ for any PoC
- All seeds MUST have PKs; there is no TOFU path
- If an operator loses a seed's PK: no recovery — regenerate the validator key on that node
  and re-register
- Removing a seed from the list does NOT ban it — it just drops it from the dial set on
  next restart

---

## 6. Non-goals for P0

- **Peerstore** (P1) — persisting peer records across restarts so seed list isn't
  re-consulted every boot
- **PEX** (P2) — discovering peers via gossip from other peers
- **Committee on-chain registry** (P3) — dissolving the seed concept entirely, resolving
  committee addrs from chain state

These remain in the P-series pipeline and land in v0.9.2 / v0.9.3 / v0.10.0 respectively.

---

## 7. Test coverage

### 7.1 Already exercised

- `SeedEntry::validate` unit tests (`crates/misaka-types/src/seed_entry.rs` tests module)
- `TestnetConfig::validate` integration tests cover seed parsing + count matching
  (`crates/misaka-node/src/config_validation.rs`)
- 10-min cold-reset harness (`scripts/test_cold_reset.sh`) exercises parallel dial with
  4-seed config

### 7.2 Added as part of P0 closure

- `seed-failure-tolerance` smoke scenario in `docs/ops/seed-configuration.md` §4
- Metrics assertion: `misaka_bootstrap_seeds_connected > 0` within 30s of boot

### 7.3 Continuous (smoke + testnet parallel)

Per the v1.0 plan, smoke runs alongside live testnet. The standing check:
```bash
for node in <seeds>; do
    curl -s http://$node:3001/api/metrics/node \
        | grep "misaka_bootstrap_seeds_connected"
done
```

All committee nodes must report `>= 3` (connected to 3 of 4 sibling seeds).

---

_最終更新：2026-04-19（v0.9.1 closure）_
