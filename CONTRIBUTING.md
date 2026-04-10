# Contributing to MISAKA Network

## Getting Started

### Prerequisites

- Rust toolchain compatible with the current local workspace
- RocksDB development libraries
- C/C++ toolchain for `librocksdb-sys` / bindgen

### Local Validation

Use the repo check script first:

```bash
./check
```

This currently runs:

- `cargo fmt --all -- --check`
- `cargo check --workspace --message-format short`

Optional heavier validation:

```bash
MISAKA_RUN_TARGETED_TESTS=1 ./check
MISAKA_RUN_EXTENDED_GATE=1 ./check
```

Notes:

- `MISAKA_RUN_TARGETED_TESTS=1` adds `cargo test -p misaka-node --bin misaka-node --quiet`
- `MISAKA_RUN_EXTENDED_GATE=1` adds `scripts/dag_release_gate_extended.sh`
- `cargo-nextest` is not yet a hard prerequisite on this local line

### Build

```bash
cargo build
cargo build --release
```

The current host line uses the following defaults when running `./check`:

```bash
BINDGEN_EXTRA_CLANG_ARGS='-I/usr/lib/gcc/x86_64-linux-gnu/13/include'
CC=gcc
CXX=g++
```

## Current Project Shape

The current local line is centered on:

- `crates/misaka-node`
- `crates/misaka-shielded`
- `crates/misaka-api`
- `scripts/dag_release_gate*.sh`
- `scripts/shielded_*`

Authoritative design/runtime docs:

- [docs/review-20260330/README.md](./docs/review-20260330/README.md)
- [docs/current-share/README.md](./docs/current-share/README.md)

## Quality Expectations

### Fail-Closed Direction

- prefer explicit config over implicit fallback
- prefer startup/runtime validation over deferred failure
- preserve current shielded/operator artifact contracts

### Proof/Gate Line Protection

When changing runtime structure, do not break these without explicitly updating
their contracts and artifacts:

- `scripts/dag_release_gate_extended.sh`
- `scripts/shielded_live_bounded_e2e.sh`
- `scripts/shielded_live_bounded_e2e_groth16.sh`
- `scripts/shielded_live_full_path_e2e.sh`
- `scripts/shielded_live_full_path_e2e_groth16.sh`

### Current Import Policy

`MISAKA-CORE (1)` is being used as a confined import source, not as a blind overwrite.

Current intended order:

1. repo/meta
2. `testing/integration` / `rpc/core` audit
3. `misaka-node` decomposition slices
4. toolchain uplift

## Commit Scope

Keep changes confined and explain which line they affect:

- proof/completion line
- import/breadth line

Avoid mixing both in one change unless the coupling is real and unavoidable.
