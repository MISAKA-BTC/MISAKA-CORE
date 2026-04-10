# Consensus Migration Status

## Current State (2026-04-08)

MISAKA uses a Sui Mysticeti-derived DAG consensus engine (`crates/misaka-dag`).
The `feature = "dag"` (enabled by default) activates the Mysticeti path.

### What's active
- Narwhal/Bullshark DAG with multi-parent blocks
- ML-DSA-65 block signatures (post-quantum native)
- UniversalCommitter with direct/indirect commit rules
- NarwhalTxExecutor for committed TX validation

### Legacy GhostDAG
- `feature = "ghostdag-compat"` enables the legacy Kaspa-derived GhostDAG path
- NOT in default features — must be explicitly enabled
- Being phased out; not recommended for new deployments

### Naming
- Code uses `narwhal_*` naming (historical). This refers to Mysticeti, not Narwhal.
- Renaming to `mysticeti_*` is planned for a future release.
