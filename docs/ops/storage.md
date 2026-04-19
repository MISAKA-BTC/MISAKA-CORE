# MISAKA storage footprint — ops notes

## Where we were (v0.8.8 baseline)

- **~6 GB / day / node** on-disk growth
- Snappy-compressed SSTs, no BlobDB, no WAL compression, no WAL size cap
- 60–70 % of bytes were ML-DSA-65 signatures (3 309 B each, ~10–23 KB/cert)
- Root cause: PQ signatures are close to incompressible and were being
  duplicated through the full LSM compaction pipeline at every level-up.

## What v0.8.9 (BLOCKER M / Phase 1) changes

Non-consensus-impacting, same RocksDB on-disk layout — safe for rolling
upgrade, safe for rollback (new DB can be wiped; v0.8.8 can re-read its
own DB).

| Change | Where | Expected gain |
|---|---|---|
| ZSTD compression (level 3, bottommost ZSTD) on every data-bearing CF | `crates/misaka-dag/.../rocksdb_store.rs::cf_opts` | 2–3× on metadata / refs / TX payload; near-zero on raw sigs |
| BlobDB enabled on `blocks` / `commits` / `equivocation` CFs (min_blob_size=512 B) | same file, `cf_opts_with_blob` | Large values leave the LSM tree → write amplification drops ~5× on compactions; blob files are ZSTD-compressed as a unit |
| WAL compression (ZSTD) | `open_with_sync` `set_wal_compression_type` | 2–3× less WAL write traffic |
| WAL total size cap (512 MiB) | `open_with_sync` `set_max_total_wal_size` | Memtables auto-flush when WAL hits cap → WAL files never accumulate past 512 MiB |
| rocksdb crate feature flag: `snappy` → `zstd` | every `Cargo.toml` | enables the ZSTD binding so the above options actually compile |

Expected footprint: **6 GB/day → 1.5–2 GB/day** (3–4× reduction).

## Measuring it

Run the reporter before and after the binary swap:

```bash
# Before the swap
scripts/measure_storage.sh /home/ubuntu/v0.9.0-dev/data \
    > docs/benchmarks/v088_baseline_$(date +%Y%m%d).txt

# Swap binary, let the node run for 1 hour under normal load

# After
scripts/measure_storage.sh /home/ubuntu/v0.9.0-dev/data \
    > docs/benchmarks/v089_after_$(date +%Y%m%d).txt
```

The difference should show:

- Total size roughly halved (at minimum)
- A new `*.blob` column with non-zero bytes (this is the sig tier)
- WAL total no larger than 512 MiB

## Rolling upgrade procedure

v0.8.9 is **wire-compatible** with v0.8.8: only on-disk layout changes,
and RocksDB transparently reads mixed-compression SSTs. Therefore the
cluster does NOT need an atomic reset.

```bash
# Per-validator, one at a time:
systemctl stop misaka-node
cp /path/to/misaka-node-v0.8.9 /home/ubuntu/v0.9.0-dev/misaka-node
systemctl start misaka-node

# Wait until the node has caught up (see /api/status num_commits) before
# moving on to the next validator. With 4 nodes this means at most one
# validator is offline at a time and the 3-of-4 quorum always holds.
```

Fresh DB state is NOT required. The new compression only takes effect
on newly written SSTs; existing SSTs stay Snappy-compressed until
natural compaction rewrites them. To force faster rewrite:

```bash
# Optional: trigger a full manual compaction (blocks the node for
# several minutes on a 2–5 GB database; use sparingly).
misaka-node admin compact --data-dir /home/ubuntu/v0.9.0-dev/data
```

## Rollback

1. `systemctl stop misaka-node`
2. Replace binary with v0.8.8
3. `systemctl start`

RocksDB can read the ZSTD-tagged SSTs that v0.8.9 wrote back with the
v0.8.8 binary **as long as** the v0.8.8 rocksdb crate was compiled with
both `snappy` and `zstd` features. If not, a DB wipe + atomic reset is
required (the normal recovery dance this cluster has used before).

The blob tier (`*.blob` files) is INVISIBLE to a `snappy`-only v0.8.8
build. That means downgrading loses the ability to read blocks /
commits whose signature bytes were blob-externalised by v0.8.9. For a
safe downgrade, the recommendation is to always keep the v0.8.9 binary
installed as the rollback target, not to attempt v0.8.8.

## Future work (explicitly deferred)

- **v0.9.x (Phase 2)**: Column Family split (headers / certificates /
  votes_index / payload / metadata / checkpoints / equivocation),
  prefix extractors, full pruning API with safety margin around the
  unbonding window, archival/pruned mode flag, checkpoint snapshots.
  Schema migration tool required.
- **v0.10.x (Phase 3)**: Signature externalization (votes CF + bitvec
  cert skeleton), reactive adaptive round rate keyed off mempool
  pressure, epoch-boundary deterministic round-config re-calibration.
  Wire-protocol V2, hardfork required.

Phase 1 (this document) takes us from 6 GB/day to ≈ 1.5 GB/day.
Phase 2 is projected to add another 3–5× reduction on pruned nodes.
Phase 3 closes the gap for idle-network operation.
