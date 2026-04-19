# v0.8.9: Storage optimization + 10 s block time (combined PR)

Branch: `feature/v089-storage-and-interval`
Base: `feat/blocker-m-rocksdb-zstd` (commit `3f4000a`) — itself based on main after BLOCKER A..K completion.

## Commits

| SHA | Title |
|-----|-------|
| `3f4000a` | feat(storage): v0.8.9 BLOCKER M — ZSTD + BlobDB + WAL cap + log hygiene |
| `00a79fe` | feat(timing): v0.8.9 Phase 0.5a — FAST_LANE_BLOCK_TIME_SECS 2 → 10 |
| `eebc66e` | docs(issue): track mainnet unbonding_epochs=10080 = 27.6y bug |

## Summary

- **Part A (timing)**: `FAST_LANE_BLOCK_TIME_SECS: 2 → 10` in `crates/misaka-types/src/constants.rs:52`. Single lever; all `fast_depth()`-derived depths cascade. Wall-clock semantics preserved.
- **Part A side-fix**: `CHECKPOINT_INTERVAL: 100 → 20` for ~200 s checkpoint cadence at 10 s blocks.
- **Parts B-E (storage)**: RocksDB ZSTD + BlobDB for signature CFs + WAL ZSTD + 512 MiB WAL cap + logrotate + tuned `RUST_LOG` — already delivered in commit `3f4000a`.
- **Part F (measurement)**: `scripts/measure_storage.sh` — already in `3f4000a`.

## Expected impact (24 h, per node)

| Metric | Baseline (2 s, no ZSTD) | After (10 s + Phase 1 storage) |
|---|---|---|
| Block generation | 43,200 / day | 8,640 / day (5× reduction) |
| DB growth | ~6 GB / day | **200–350 MB / day** (target < 500 MB) |
| Log volume | ~91 MB / day raw | < 10 MB / day raw, < 1 MB compressed |
| Finality wall-clock | 60 s | 60 s (preserved) |
| Coinbase maturity wall-clock | 10 min | 10 min (preserved) |
| Epoch length wall-clock | 24 h | 24 h (preserved) |
| Pruning depth wall-clock | 7 days | 7 days (preserved) |
| Genesis hash | unchanged | unchanged (no fork) |

## Investigation (Phase 0.5b, transcribed)

Full report: `docs/investigations/round-interval-10s-impact.md` on branch `investigation/round-interval-10s-impact` (NOT pushed; summary below).

### Key finding

The prompt-assumed `round_interval_ms` field does not exist. The actual lever is `FAST_LANE_BLOCK_TIME_SECS` in `crates/misaka-types/src/constants.rs:52`. All depth constants (`EPOCH_LENGTH`, `FINALITY_DEPTH_FAST`, `COINBASE_MATURITY_FAST`, `PRUNING_DEPTH`, `DIFFICULTY_WINDOW_SIZE`, `MEDIAN_TIME_WINDOW_SIZE`, `RECOVERY_DEPTH_FAST`, `SHIELDED_ANCHOR_AGE_FAST`) are computed as `fast_depth(wall_secs) = wall_secs / FAST_LANE_BLOCK_TIME_SECS`. Changing `2 → 10` preserves wall-clock semantics by reducing the depth counts 5×.

### Subsystem impact matrix

| Subsystem | Time-based? | Impact |
|---|---|---|
| Staking epoch | BLOCKS via `fast_depth` | None — auto-scaled |
| Unbonding window | EPOCHS (= 24 h each) | None (pre-existing 10,080-epoch mainnet sizing is a separate bug, tracked in `docs/issues/unbonding-27-years.md`) |
| Solana bridge | NOT IMPLEMENTED | None |
| Mempool TTL | TIME (`received_at_ms`) | None |
| Sync timeouts | TIME (`Duration::from_secs(10)`) | None |
| Checkpoint cadence | COMMITS (raw) | **Side-fix**: `CHECKPOINT_INTERVAL 100 → 20` |
| Metrics | Async counters | None |
| Explorer poll | 10 s wall-clock (hardcoded) | Serendipitous fit |
| Wallet confirmations | BLOCKS | UI-visible: 100 s finality instead of 20 s (docs only) |
| Genesis hash | chain_id + committee_pks only | None — no fork |

### GO / HOLD: **GO**

## Out of scope (deferred separately)

- Mainnet `unbonding_epochs: 10_080` — 27.6-year unbonding. Pre-existing, NOT caused by this change. Tracked in `docs/issues/unbonding-27-years.md`. Fix belongs in a staking PR.
- `CHECKPOINT_INTERVAL` fold into `fast_depth(TIME_200_SECS)` — Phase 2 retrofit.
- `misaka-storage/src/checkpoint.rs::CHECKPOINT_INTERVAL = 500` — different subsystem (state snapshot, not finality checkpoint). Left as-is.
- Epoch-config migration of timing (adaptive rate) — Phase 3.
- Wallet extension confirmation UI copy update.

## Verification

### Build
- `cargo build --release -p misaka-node` — passes (1m 15s, 16 MB binary).
- Workspace-wide `cargo build --release` fails on the pre-existing `test-utils` feature-unification guard in `misaka-dag/src/lib.rs:20`; same failure exists on the base commit (`3f4000a` and earlier). Not introduced by this PR.

### Tests (dev mode)
- misaka-types: 128 / 0
- misaka-config: all passed
- misaka-protocol-config: doctest passed
- misaka-consensus: 221 / 0
- misaka-dag: 422 / 0
- misaka-storage: 79 / 0
- misaka-mempool: 37 / 0
- misaka-test-cluster: 5 / 0
- misaka-node bin: 199 / 0

Compile-time asserts in `constants.rs:183-189` updated to match the new derived depths (6 / 60 / 8640 / 60480) and verify cascade correctness at build time.

## Deploy + smoke plan

### 4-node atomic reset (operator runs)

```bash
# 1. Stop all 4 nodes
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    ssh -i ~/.ssh/claude_key ubuntu@$ip "sudo systemctl stop misaka-node || pkill -f misaka-node || true"
done

# 2. Wipe state on each (keep genesis + identity)
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    ssh -i ~/.ssh/claude_key ubuntu@$ip <<'REMOTE'
cd /home/ubuntu/v0.9.0-dev
rm -rf data/narwhal_consensus* data/mysticeti_store* data/lifecycle*
rm -rf data/*.atomic-* data/*.smt-* data/*.bak-*
REMOTE
done

# 3. Baseline measurement (optional — if pre-change state is still around)
# scripts/measure_storage.sh  already lives in repo — run after boot

# 4. Deploy new binary
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    scp -i ~/.ssh/claude_key target/release/misaka-node ubuntu@$ip:/home/ubuntu/v0.9.0-dev/misaka-node.v089
done
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    ssh -i ~/.ssh/claude_key ubuntu@$ip "cd /home/ubuntu/v0.9.0-dev && mv misaka-node misaka-node.v088.bak 2>/dev/null; mv misaka-node.v089 misaka-node && chmod +x misaka-node"
done

# 5. Co-start within 60 s
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    ssh -i ~/.ssh/claude_key ubuntu@$ip "sudo systemctl start misaka-node" &
done
wait
```

### Success criteria (verify within 10 min)

```bash
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    echo "=== $ip ==="
    ssh -i ~/.ssh/claude_key ubuntu@$ip "tail -20 /home/ubuntu/node.log | grep -E 'round=|Committed'"
done
```

- All 4 nodes advancing `round=0,1,2,...`
- Round cadence **9–11 s** (±1 s jitter)
- No `timestamp too far in past` rejections
- Committee forms within 10 min

### 1 h + 24 h smoke

```bash
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    ssh -i ~/.ssh/claude_key ubuntu@$ip \
        "/home/ubuntu/v0.9.0-dev/scripts/measure_storage.sh /home/ubuntu/v0.9.0-dev/data" \
        > docs/benchmarks/v089_after_${ip}_1h.txt
done
```

Expected at 24 h per node:
- `du -sh data/narwhal_consensus` < 500 MB (goal 200–350 MB)
- `*.blob` files present (signature-tier evidence)
- WAL total ≤ 512 MiB
- Commit count over 24 h: ~8,640 ± 10%
- `tail /home/ubuntu/node.log` clean

### Rollback

```bash
for ip in 163.43.142.150 163.43.208.209 163.43.133.51 163.43.225.27; do
    ssh -i ~/.ssh/claude_key ubuntu@$ip <<'REMOTE'
sudo systemctl stop misaka-node
cd /home/ubuntu/v0.9.0-dev
rm -rf data/narwhal_consensus* data/mysticeti_store* data/lifecycle*
mv misaka-node misaka-node.v089.bak
mv misaka-node.v088.bak misaka-node
sudo systemctl start misaka-node
REMOTE
done
```

State wipe is required on rollback because v0.8.9 produces `*.blob` files that v0.8.8 cannot read (BlobDB tier).
