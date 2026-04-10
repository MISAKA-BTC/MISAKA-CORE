# Consensus Deduplication Inventory

## Duplicate Files

| Module | misaka-consensus | narwhal_dag | Production wire | Action |
|--------|-----------------|-------------|-----------------|--------|
| round_prober | 443 lines | 309 lines | narwhal_dag | **DELETE consensus** |
| leader_scoring | 536 lines | 336 lines | narwhal_dag | **DELETE consensus** |
| transaction_certifier | 618 lines | 377 lines | narwhal_dag | **DELETE consensus** |
| dag_state | 1,009 lines | 750 lines | narwhal_dag | **DELETE consensus** |
| block_manager | 1,316 lines | 280 lines | narwhal_dag | **DELETE consensus** |
| commit_finalizer | 631 lines | 592 lines | narwhal_dag | **DELETE consensus** |
| core_engine | 1,490 lines | 1,385 lines | narwhal_dag | **DELETE consensus** |
| synchronizer | 956 lines | 220 lines | narwhal_dag | **DELETE consensus** |
| ancestor_scoring | 388 lines | (in ancestor.rs) | narwhal_dag | **DELETE consensus** |

## Pass 1: DAG duplicates — 7,387 lines deleted

## External references (all in test files, also deleted):
- commit_test_fixture.rs:8-10 → references core_engine, commit_finalizer, transaction_certifier
- commit_rule_tests.rs → references test_dag_builder (cfg(test) module)

## Pass 2: Orphan modules (commented out, 0 external imports) — 2,694 lines

| Module | Lines | Reason |
|--------|-------|--------|
| delegation.rs | 594 | Replaced by validator_system_v2 (ADA-style, no-slash) |
| fork_choice.rs | 565 | Not applicable to DAG consensus |
| role_scoring.rs | 390 | Replaced by validator_registry + epoch_rotation |
| unified_node.rs | 331 | Replaced by validator_registry + epoch_rotation |
| vrf_proposer.rs | 478 | Leader election handled in narwhal_dag/leader_schedule |
| weak_subjectivity.rs | 336 | Not applicable to DAG consensus with checkpoints |

## Grand total: 10,081 lines of dead code deleted

## What remains in misaka-consensus after deletion:
- finality.rs (finality proof verification — used by main.rs)
- validator_set.rs (BFT quorum)
- block_validation.rs (TX verification)
- state_root.rs (state root computation)
- economic_finality.rs (PoS finality)
- staking.rs / epoch.rs / epoch_rotation.rs
- validator_system_v2.rs
- equivocation_detector.rs (Phase 20)
- stores/ (GhostDAG persistent stores)
- pipeline/ (header/body/virtual/pruning processors)
- processes/ (TX validator, coinbase, difficulty)
- All validator/reward/scoring modules

These are the **economic/staking/validation layer** — correctly separate from DAG consensus.
