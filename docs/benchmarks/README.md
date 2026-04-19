# MISAKA benchmarks

Storage and latency measurements captured around major releases.

## Conventions

- Filename format: `<version>_<label>_<YYYYMMDD>.txt`
  - e.g. `v088_baseline_20260418.txt`, `v089_after_20260419.txt`
- Produced by `scripts/measure_storage.sh <data_dir>`.
- Each file corresponds to a single validator, typically run for 1 hour
  of normal testnet load between samples.

## Current baseline (2026-04-18)

`v088_baseline_20260418.txt` — captured on authority 0 (27) shortly
after the 4-node atomic reset that recovered the chain from the
"timestamp too far in past" deadlock. Binary: v0.9.0-dev commit
`c9df6fd0` (Snappy SSTs, no BlobDB, no WAL compression, no WAL cap).

After the v0.8.9 binary is rolled out, capture `v089_after_*.txt`
under the same load and commit both files side by side; the
`docs/ops/storage.md` rolling-upgrade procedure explains the deploy
order.

## Storage delta check list (post-v0.8.9)

- [ ] Total size reduced ≥ 2× vs baseline
- [ ] `*.blob` column non-zero (BlobDB active)
- [ ] WAL size ≤ 512 MiB (max_total_wal_size honored)
- [ ] Chain still at 4-of-4 quorum after swap
