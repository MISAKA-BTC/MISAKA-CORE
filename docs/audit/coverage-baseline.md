# Test Coverage Baseline (2026-04-08)

## Existing Test Files

### crates/misaka-dag/tests/ (integration tests)
- `narwhal_integration.rs` -- block verifier integration, basic consensus flow
- `narwhal_byzantine.rs` -- invalid authority block rejection
- `narwhal_crash_recovery.rs` -- crash recovery scenarios
- `narwhal_proptest.rs` -- property-based tests
- `base_committer_declarative.rs` -- declarative committer tests
- `shielded_tx_in_narwhal_mode.rs` -- shielded tx in DAG mode
- `e2e_tx_lifecycle.rs` -- end-to-end transaction lifecycle
- `narwhal_byzantine.rs` -- byzantine fault tests

### crates/misaka-dag/src/ (inline #[cfg(test)] modules)
- `narwhal_finality/checkpoint_manager.rs`
- `narwhal_finality/bft.rs`
- `narwhal_dag/block_verifier.rs` (9 tests: valid block, invalid author, round zero, wrong epoch, empty signature, future timestamp, too many txs, duplicate ancestor, future round ancestor)
- `narwhal_dag/dag_state.rs`
- `narwhal_dag/core_engine.rs` (verifier_rejects_empty_signature, leader_timeout_backoff, leader_timeout_integration, leader_timeout_fires_on_check)
- `narwhal_dag/anemo_network.rs`
- `narwhal_dag/block_manager.rs`
- `narwhal_dag/vote_registry.rs` (test_vote_stake, equivocator_counted_once_in_stake)
- `narwhal_dag/core_thread.rs`
- `narwhal_dag/runtime.rs`
- `narwhal_dag/leader_schedule.rs` (round_robin_leader, threshold_clock, stake_aggregator)
- `narwhal_dag/peer_scorer.rs` (leader_excluded_peers)
- `narwhal_dag/admission.rs`
- `narwhal_dag/consensus_wal.rs`
- `narwhal_dag/stake_aggregator.rs` (no tests found -- file has quorum references but no #[test])
- `narwhal_dag/transaction_certifier.rs` (certification_quorum, rejection_quorum)
- `narwhal_dag/slo_metrics.rs`
- `narwhal_types/committee.rs` (sr15_quorum, sr18_quorum, sr21_quorum, n4_quorum, n7_quorum, n10_quorum, n1_quorum, non_multiple_of_3, safety_invariant_exhaustive, reached_quorum, committee_accessors)
- `narwhal_types/block.rs`
- `narwhal_dag/commit_finalizer.rs` (direct_finalization, reject_quorum, indirect_finalization_after_depth, late_reject_causes_rejection, duplicate_late_reject_ignored, idempotent_reprocess, reorg_prevention, recovery, gc_bounds_memory, backpressure, metrics)
- `narwhal_dag/commit_syncer.rs`
- `narwhal_dag/commit_observer.rs`
- `narwhal_dag/commit_vote_monitor.rs` (test_vote_quorum)
- `narwhal_dag/threshold_clock.rs` (advance_on_quorum, no_advance_below_quorum, stake_aggregator_dedup, stake_aggregator_quorum)
- `narwhal_ordering/base_committer.rs` (test_leader_round)
- `narwhal_ordering/linearizer.rs` (commit_finalizer_sequential, commit_finalizer_starts_at_zero)
- `narwhal_ordering/universal_committer.rs` (test_no_commit_without_quorum)
- `narwhal_dag/leader_scoring.rs` (leader_scorer_window)
- `narwhal_dag/round_prober.rs` (quorum_round_calculation)
- `narwhal_dag/ancestor.rs` (excluded_stake_cap)
- `narwhal_dag/leader_timeout.rs`
- `narwhal_ordering/pipeline.rs`
- `narwhal_dag/epoch.rs`
- `narwhal_dag/metrics.rs`
- `narwhal_dag/synchronizer.rs`
- `testing/commit_fixture.rs`
- `testing/dag_parser.rs`
- `testing/dag_builder.rs`
- `constants.rs`
- `lib.rs`
- `qdag_verify.rs`
- `narwhal_dag/store.rs`
- `narwhal_dag/network.rs`
- `narwhal_dag/sync_fetcher.rs`
- `narwhal_dag/prometheus.rs`

## Coverage Gaps (P0)

### quorum_threshold edge cases
- [x] N=1 quorum -- `test_n1_quorum` in committee.rs
- [x] N=4 quorum (exactly 2/3+1) -- `test_n4_quorum` in committee.rs
- [x] Non-multiple-of-3 -- `test_non_multiple_of_3` in committee.rs
- [x] Exhaustive safety invariant -- `test_safety_invariant_exhaustive` in committee.rs
- [x] No commit without quorum -- `test_no_commit_without_quorum` in universal_committer.rs
- [ ] Zero-validator committee (N=0) -- no test found
- [ ] Very large committee (N=100+) -- no test found

### block_validation invalid signature rejection
- [x] Empty signature rejected -- `test_empty_signature_rejected` in block_verifier.rs, `test_verifier_rejects_empty_signature` in core_engine.rs
- [x] Invalid authority -- `test_invalid_author` in block_verifier.rs, `test_invalid_authority_blocks_rejected` in narwhal_byzantine.rs
- [ ] Malformed signature bytes (non-empty but invalid) -- no dedicated test found
- [ ] Signature from wrong validator key -- no dedicated test found

### commit_finalizer leader election
- [x] Direct finalization -- `test_direct_finalization` in commit_finalizer.rs
- [x] Indirect finalization after depth -- `test_indirect_finalization_after_depth`
- [x] Reject quorum -- `test_reject_quorum`
- [x] Reorg prevention -- `test_reorg_prevention`
- [x] Round-robin leader -- `test_round_robin_leader` in base_committer.rs
- [ ] Leader election under stake inequality -- no test found
- [ ] Leader election with exactly f+1 honest validators -- no test found

### stake_aggregator stake computation
- [x] Stake aggregator quorum -- `test_stake_aggregator_quorum` in threshold_clock.rs
- [x] Stake aggregator dedup -- `test_stake_aggregator_dedup` in threshold_clock.rs
- [x] Vote stake -- `test_vote_stake` in vote_registry.rs
- [x] Equivocator counted once -- `test_equivocator_counted_once_in_stake` in vote_registry.rs
- [x] Excluded stake cap -- `test_excluded_stake_cap` in ancestor.rs
- [ ] **stake_aggregator.rs has no inline tests** -- quorum logic exists but no unit tests in file
- [ ] Zero-stake validator handling -- no test found
- [ ] Overflow protection for very large stake values -- no test found

## Coverage Gaps (P1)

- [ ] WAL crash recovery under partial writes (consensus_wal.rs)
- [ ] Sync fetcher timeout and retry logic
- [ ] Epoch transition with pending commits
- [ ] Network partition recovery (split-brain scenarios beyond basic byzantine tests)
- [ ] Block manager cache eviction under memory pressure

## Recommendation

Run `cargo tarpaulin --workspace --out Html` on VPS to get actual line coverage numbers.
Priority targets for new tests:
1. `stake_aggregator.rs` -- has zero inline unit tests despite containing quorum logic
2. Block verifier with malformed (non-empty) signatures
3. Zero-validator edge case for committee quorum
4. Leader election under asymmetric stake distribution
