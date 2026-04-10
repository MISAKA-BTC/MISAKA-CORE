# MISAKA-DAG Performance Baseline

## Measurement Environment
- Date: 2026-04-08
- Build: `cargo build --features dag --release -p misaka-node`
- Compiler: rustc (edition 2021)
- Status: Pre-measurement (values to be filled after first VPS deployment)

## Baseline Values (TODO: measure)

| Metric | Value | Notes |
|--------|-------|-------|
| Block serialize (JSON) | TBD ms | `serde_json::to_vec(&block)` |
| Block deserialize (JSON) | TBD ms | `serde_json::from_slice` |
| Block serialize (bcs, target) | TBD ms | Phase 2.1 comparison |
| ML-DSA-65 sign (1 block) | ~2 ms | `ml_dsa_sign_with_domain` |
| ML-DSA-65 verify (1 block) | ~1 ms | `ml_dsa_verify_with_domain` |
| ML-DSA-65 verify batch (64 blocks, 4 cores) | TBD ms | `verify_batch` with rayon |
| 4-validator 1 round time | TBD ms | `core_engine` propose+process cycle |
| 10-validator 1 round time | TBD ms | |
| 21-validator 1 round time | TBD ms | SR21 production config |
| TCP peer connect → block accept p50 | TBD ms | |
| TCP peer connect → block accept p99 | TBD ms | |

## Target Values (Phase 1-4)

| Metric | Target | Justification |
|--------|--------|---------------|
| Block serialize | 5x faster (bcs) | Phase 2.1 |
| 1 round time | ≤ baseline | No regression |
| Parallel execution speedup | ≥3x (4 cores) | Phase 2.3 |
| Simtest stability | 9/9 scenarios | Phase 2.4 |
