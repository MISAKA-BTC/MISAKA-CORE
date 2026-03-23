# MISAKA-CORE-v5.1 Parallel Round Status

## Purpose

This file tracks the current parallel implementation round.

- Authoritative repo: `MISAKA-CORE-v5.1`
- Current mode: multiple independent workstreams, one integration coordinator
- Constraint: keep `v5.1` semantics authoritative

## Active Parallel Round

```mermaid
flowchart LR
    A[WS1 Build closure]
    B[WS2 Validator auth]
    C[WS3 RPC P2P relay]
    D[WS4 Ops and release scaffolding]
    E[Coordinator integration]

    A --> E
    B --> E
    C --> E
    D --> E
```

## Current Known Stop Lines

```mermaid
flowchart TD
    S0[v5.1 current stop lines]
    S1[workspace/build is not green]
    S2[validator write plane is not closed by default]
    S3[RPC P2P vocabulary is only partially normalized]
    S4[recovery and onboarding are not operator-grade]

    S0 --> S1
    S0 --> S2
    S0 --> S3
    S0 --> S4
```

## Fresh Coordinator Check

From the current local validation pass:

- `misaka-types --lib` no longer stops on the earlier source-level blocker, but test execution inside the Docker image hit a host/target `glibc` mismatch because the mounted `target/` already contains binaries built against a newer host libc.
- `misaka-node --features qdag_ct` now moves past the earlier `misaka-types` blocker and stops later in `misaka-consensus` and `misaka-dag`.

Current concrete compile blockers seen by the coordinator:

- [crates/misaka-consensus/src/reward_epoch.rs](../../crates/misaka-consensus/src/reward_epoch.rs)
  - wrong import path for `ValidatorId`
- [crates/misaka-consensus/src/staking.rs](../../crates/misaka-consensus/src/staking.rs)
  - mutable/immutable borrow conflict in `activate`
- [crates/misaka-dag/src/atomic_pipeline.rs](../../crates/misaka-dag/src/atomic_pipeline.rs)
  - `SpentUtxo` not imported into scope
- [crates/misaka-dag/src/dag_block_producer.rs](../../crates/misaka-dag/src/dag_block_producer.rs)
  - `insert_block_atomic` call requires the right backend trait path / implementation visibility

## Merge Policy For This Round

```mermaid
flowchart TD
    M0[Merge policy]
    M1[Prefer narrow fixes]
    M2[Do not redefine protocol semantics]
    M3[Keep write sets disjoint]
    M4[Re-run narrow tests before integration]

    M0 --> M1
    M0 --> M2
    M0 --> M3
    M0 --> M4
```

## Expected Outputs

- WS1:
  - fewer compile blockers
  - explicit workspace shape
- WS2:
  - safer validator write boundary
  - clearer auth behavior
- WS3:
  - cleaner transport and consumer-facing surface
- WS4:
  - better release/onboarding scaffolding

## Integration After Workers Return

1. Apply returned patches in dependency order.
2. Re-run narrow cargo checks/tests.
3. Update [00_parallel_ai_workstream_map.md](./00_parallel_ai_workstream_map.md) with completed items.
4. Record new remaining blockers.

## Current Outcome

See [02_parallel_round_implementation_report.md](./02_parallel_round_implementation_report.md).

- The first parallel round has landed.
- `misaka-node` now builds in a clean Docker environment with `qdag_ct`.
- Remaining work has shifted from early compile closure to recovery, onboarding, and lifecycle semantics.
