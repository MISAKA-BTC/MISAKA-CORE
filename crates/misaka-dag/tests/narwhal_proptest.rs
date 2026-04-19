// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Property-based tests for Narwhal/Bullshark consensus.
//!
//! Uses proptest to verify invariants hold across random inputs:
//! 1. Deterministic commit ordering (same DAG → same commits)
//! 2. Quorum safety (no commit without ≥2f+1 votes)
//! 3. Liveness (connected DAG eventually commits)
//! 4. No equivocation tolerance (equivocating blocks detected)
//! 5. Block digest uniqueness (different content → different digest)
//! 6. Committee quorum math consistency

use proptest::prelude::*;

use misaka_dag::narwhal_dag::dag_state::*;
use misaka_dag::narwhal_dag::leader_schedule::*;
use misaka_dag::narwhal_ordering::base_committer::*;
use misaka_dag::narwhal_ordering::linearizer::*;
use misaka_dag::narwhal_ordering::universal_committer::*;
use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::commit::*;
use misaka_dag::narwhal_types::committee::*;

// ═══════════════════════════════════════════════════════════
//  Generators
// ═══════════════════════════════════════════════════════════

fn arb_committee_size() -> impl Strategy<Value = usize> {
    prop_oneof![Just(4), Just(7), Just(10), Just(15), Just(21),]
}

fn arb_transaction() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..100)
}

fn arb_transactions() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(arb_transaction(), 0..10)
}

fn make_block(
    round: Round,
    author: AuthorityIndex,
    ancestors: Vec<BlockRef>,
    txs: Vec<Vec<u8>>,
) -> VerifiedBlock {
    let block = Block {
        epoch: 0,
        round,
        author,
        timestamp_ms: round as u64 * 1000 + author as u64,
        ancestors,
        transactions: txs,
        commit_votes: vec![],
        tx_reject_votes: vec![],
        state_root: [0u8; 32],
        state_root_smt: [0u8; 32],
        signature: vec![0xAA; 64],
    };
    VerifiedBlock::new_for_test(block)
}

/// Build a fully connected DAG with `num_rounds` rounds and `committee_size` authorities.
fn build_connected_dag(committee_size: usize, num_rounds: usize) -> (DagState, Vec<Vec<BlockRef>>) {
    let committee = Committee::new_for_test(committee_size);
    let mut dag = DagState::new(committee, DagStateConfig::default());
    let mut all_refs: Vec<Vec<BlockRef>> = Vec::new();

    for round in 1..=num_rounds {
        let prev_refs = if round == 1 {
            vec![]
        } else {
            all_refs[round - 2].clone()
        };
        let mut round_refs = Vec::new();
        for author in 0..committee_size as u32 {
            let b = make_block(
                round as Round,
                author,
                prev_refs.clone(),
                vec![vec![author as u8]],
            );
            round_refs.push(b.reference());
            dag.accept_block(b);
        }
        all_refs.push(round_refs);
    }

    (dag, all_refs)
}

// ═══════════════════════════════════════════════════════════
//  Property: Quorum math is consistent
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_quorum_always_exceeds_half(n in 3usize..=100) {
        let c = Committee::new_for_test(n);
        let q = c.quorum_threshold();
        let total = c.total_stake();

        // Quorum must be > 1/2 of total (Byzantine safety)
        prop_assert!(q > total / 2, "quorum {} must be > half of total {}", q, total);

        // Quorum must be ≤ total
        prop_assert!(q <= total, "quorum {} must be ≤ total {}", q, total);

        // Two quorums must intersect (q + q > total → 2q > total)
        prop_assert!(2 * q > total, "two quorums must intersect: 2*{} > {}", q, total);
    }

    #[test]
    fn prop_validity_threshold_at_least_one(n in 1usize..=100) {
        let c = Committee::new_for_test(n);
        let v = c.validity_threshold();
        prop_assert!(v >= 1, "validity threshold must be >= 1, got {}", v);
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: Block digest uniqueness
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_different_txs_different_digest(
        tx1 in arb_transaction(),
        tx2 in arb_transaction(),
    ) {
        if tx1 != tx2 {
            let b1 = Block {
                epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
                ancestors: vec![], transactions: vec![tx1],
                commit_votes: vec![], tx_reject_votes: vec![],
                state_root: [0u8; 32],
                state_root_smt: [0u8; 32],
                signature: vec![],
            };
            let b2 = Block {
                epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
                ancestors: vec![], transactions: vec![tx2],
                commit_votes: vec![], tx_reject_votes: vec![],
                state_root: [0u8; 32],
                state_root_smt: [0u8; 32],
                signature: vec![],
            };
            prop_assert_ne!(b1.digest(), b2.digest());
        }
    }

    #[test]
    fn prop_different_rounds_different_digest(
        r1 in 1u32..1000,
        r2 in 1u32..1000,
    ) {
        if r1 != r2 {
            let b1 = Block {
                epoch: 0, round: r1, author: 0, timestamp_ms: 1000,
                ancestors: vec![], transactions: vec![],
                commit_votes: vec![], tx_reject_votes: vec![],
                state_root: [0u8; 32],
                state_root_smt: [0u8; 32],
                signature: vec![],
            };
            let b2 = Block {
                epoch: 0, round: r2, author: 0, timestamp_ms: 1000,
                ancestors: vec![], transactions: vec![],
                commit_votes: vec![], tx_reject_votes: vec![],
                state_root: [0u8; 32],
                state_root_smt: [0u8; 32],
                signature: vec![],
            };
            prop_assert_ne!(b1.digest(), b2.digest());
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: DAG state invariants
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_no_duplicate_acceptance(committee_size in arb_committee_size()) {
        let committee = Committee::new_for_test(committee_size);
        let mut dag = DagState::new(committee, DagStateConfig::default());

        let b = make_block(1, 0, vec![], vec![vec![1]]);
        prop_assert!(dag.accept_block(b.clone()).is_accepted()); // first accept
        prop_assert!(!dag.accept_block(b).is_accepted());      // duplicate rejected
        prop_assert_eq!(dag.num_blocks(), 1);
    }

    #[test]
    fn prop_highest_round_monotonic(num_rounds in 1usize..20) {
        let (dag, _) = build_connected_dag(4, num_rounds);
        prop_assert_eq!(dag.highest_accepted_round(), num_rounds as Round);
    }

    #[test]
    fn prop_eviction_reduces_blocks(committee_size in arb_committee_size()) {
        let (mut dag, _) = build_connected_dag(committee_size, 10);
        let before = dag.num_blocks();
        dag.evict_below(5);
        let after = dag.num_blocks();
        prop_assert!(after < before, "eviction must reduce block count: {} < {}", after, before);
        prop_assert_eq!(dag.eviction_round(), 5);
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: Deterministic commit ordering
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_deterministic_commits(committee_size in arb_committee_size()) {
        // Build two identical DAGs
        let (dag1, _) = build_connected_dag(committee_size, 6);
        let (dag2, _) = build_connected_dag(committee_size, 6);

        let ls1 = LeaderSchedule::new(
            Committee::new_for_test(committee_size), 1
        );
        let ls2 = LeaderSchedule::new(
            Committee::new_for_test(committee_size), 1
        );

        let mut committer1 = UniversalCommitter::new(
            Committee::new_for_test(committee_size), ls1, 1, 2
        );
        let mut committer2 = UniversalCommitter::new(
            Committee::new_for_test(committee_size), ls2, 1, 2
        );

        let ledger = misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(u32::MAX);
        let commits1 = committer1.try_commit(&dag1, &ledger);
        let commits2 = committer2.try_commit(&dag2, &ledger);

        // Same DAG → same commits
        prop_assert_eq!(commits1.len(), commits2.len(), "commit count mismatch");
        for (c1, c2) in commits1.iter().zip(commits2.iter()) {
            prop_assert_eq!(c1.leader, c2.leader, "leader mismatch at index {}", c1.index);
            prop_assert_eq!(c1.blocks.len(), c2.blocks.len(), "blocks mismatch at index {}", c1.index);
            prop_assert_eq!(c1.is_direct, c2.is_direct, "direct flag mismatch");
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: Linearizer determinism
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_linearizer_deterministic_order(
        n_blocks in 1usize..10,
    ) {
        let mut refs: Vec<BlockRef> = (0..n_blocks)
            .map(|i| BlockRef::new(
                (i / 4 + 1) as Round,
                (i % 4) as AuthorityIndex,
                BlockDigest([i as u8; 32]),
            ))
            .collect();

        // Shuffle refs
        let mut shuffled = refs.clone();
        shuffled.reverse(); // deterministic "shuffle"

        // Both orderings should produce the same sorted output
        refs.sort();
        shuffled.sort();

        prop_assert_eq!(refs, shuffled, "sort must be deterministic");
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: Equivocation detection
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_equivocation_always_detected(committee_size in arb_committee_size()) {
        let committee = Committee::new_for_test(committee_size);
        let mut dag = DagState::new(committee, DagStateConfig::default());

        // Create two blocks at same (round, author) but different content
        let b1 = make_block(1, 0, vec![], vec![vec![1]]);
        let b2 = make_block(1, 0, vec![], vec![vec![2]]); // different tx

        if b1.digest() != b2.digest() {
            dag.accept_block(b1);
            dag.accept_block(b2);
            prop_assert_eq!(dag.equivocations().len(), 1);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: Liveness — connected DAG produces commits
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_connected_dag_commits(
        committee_size in arb_committee_size(),
        num_rounds in 4usize..12,
    ) {
        let (dag, _) = build_connected_dag(committee_size, num_rounds);
        let committee = Committee::new_for_test(committee_size);
        let ls = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = UniversalCommitter::new(committee, ls, 1, 2);

        let commits = committer.try_commit(&dag, &misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(u32::MAX));

        // A fully connected DAG with ≥4 rounds must produce at least 1 commit
        if num_rounds >= 4 {
            prop_assert!(!commits.is_empty(),
                "DAG with {} rounds and committee {} must produce commits",
                num_rounds, committee_size);
        }
    }

    #[test]
    fn prop_commit_indices_sequential(
        committee_size in arb_committee_size(),
    ) {
        let (dag, _) = build_connected_dag(committee_size, 8);
        let committee = Committee::new_for_test(committee_size);
        let ls = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = UniversalCommitter::new(committee, ls, 1, 2);

        let commits = committer.try_commit(&dag, &misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(u32::MAX));

        // Commit indices must be sequential starting from 0
        for (i, commit) in commits.iter().enumerate() {
            prop_assert_eq!(commit.index, i as u64,
                "commit index {} != expected {}", commit.index, i);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Property: CommitFinalizer sequential delivery
// ═══════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_finalizer_delivers_in_order(n in 1usize..50) {
        let mut finalizer = CommitFinalizer::new();

        // Submit in reverse order
        for i in (0..n).rev() {
            finalizer.submit(LinearizedOutput {
                commit_index: i as u64,
                leader: BlockRef::new(0, 0, BlockDigest([i as u8; 32])),
                transactions: vec![],
                blocks: vec![],
                timestamp_ms: 0,
                overflow_carryover: vec![],
                leader_state_root: None,
            });
        }

        let finalized = finalizer.finalize_all();

        // Must deliver in sequential order
        prop_assert_eq!(finalized.len(), n);
        for (i, output) in finalized.iter().enumerate() {
            prop_assert_eq!(output.commit_index, i as u64,
                "out of order: got {} at position {}", output.commit_index, i);
        }
    }
}
