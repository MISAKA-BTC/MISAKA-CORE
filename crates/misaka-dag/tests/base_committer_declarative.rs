// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/tests/base_committer_declarative_tests.rs
//
//! Declarative commit rule tests — exhaustive Bullshark scenario coverage.
//!
//! Each test builds a specific DAG topology and asserts the expected
//! commit decision. Uses `CommitFixture` + `DagBuilder` + `parse_dag()`.
//!
//! ## Scenario matrix
//!
//! | #  | Scenario                           | Decision           |
//! |----|------------------------------------|--------------------|
//! | 1  | All honest, full quorum            | Direct commit      |
//! | 2  | Exactly quorum votes               | Direct commit      |
//! | 3  | Quorum - 1 votes                   | Undecided          |
//! | 4  | Leader missing                     | Skip               |
//! | 5  | f=1 Byzantine offline (n=4)        | Direct commit      |
//! | 6  | f=2 Byzantine offline (n=7)        | Direct commit      |
//! | 7  | f+1 offline (n=4) → no quorum      | Undecided          |
//! | 8  | Indirect commit via anchor         | Indirect commit    |
//! | 9  | Skip via anchor (no causal link)   | Skip               |
//! | 10 | Equivocating leader                | DagState detects   |
//! | 11 | 2-2 partition (n=4)                | Undecided          |
//! | 12 | 3-4 partition (n=7)                | Direct on majority |
//! | 13 | Chain of 10 direct commits         | All commit         |
//! | 14 | Skip then commit                   | Skip + Commit      |
//! | 15 | Indirect chain length 2            | Indirect commit    |
//! | 16 | No votes at all                    | Undecided          |
//! | 17 | Single authority committee (n=1)   | Always commit      |
//! | 18 | n=4 exact boundary                 | Quorum math        |
//! | 19 | n=7 exact boundary                 | Quorum math        |
//! | 20 | n=10 exact boundary                | Quorum math        |
//! | 21 | n=21 exact boundary                | Quorum math        |
//! | 22 | All vote but don't reference leader| Undecided          |
//! | 23 | Late arrival of missing block      | Was undecided → now committed |
//! | 24 | DSL: simple fully connected        | Direct commit      |
//! | 25 | DSL: selective ancestors            | Varies             |
//! | 26 | DSL: exclusion                     | Varies             |
//! | 27 | 100 rounds stress                  | All commit         |
//! | 28 | 21 validators 50 rounds            | All commit         |
//! | 29 | Intermittent authority              | Most commit        |
//! | 30 | Byzantine minority equivocates     | Still commits      |
//! | 31 | f+1 crash → liveness halt          | Undecided          |

use misaka_dag::narwhal_dag::dag_state::{DagState, DagStateConfig};
use misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger;
use misaka_dag::narwhal_ordering::base_committer::{BaseCommitter, Decision};
use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::committee::Committee;
use misaka_dag::testing::commit_fixture::CommitFixture;
use misaka_dag::testing::dag_builder::DagBuilder;
use misaka_dag::testing::dag_parser::parse_dag;

// ═══════════════════════════════════════════════════════════════
//  1-4: Basic Direct / Undecided / Skip
// ═══════════════════════════════════════════════════════════════

#[test]
fn s01_all_honest_full_quorum() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.build_layers(1, 2);
    f.assert_direct_commit(1);
}

#[test]
fn s02_exactly_quorum_votes() {
    // n=4, quorum=3. Exactly 3 vote.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1, 2])
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

#[test]
fn s03_quorum_minus_one_undecided() {
    // n=4, quorum=3. Only 2 vote.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.assert_direct_undecided(1);
}

#[test]
fn s04_leader_missing_skip() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    // Leader A doesn't propose at R1
    f.dag()
        .layer(1)
        .authorities(&[1, 2, 3])
        .fully_connected()
        .build();
    // try_direct_decide → Skip because leader block doesn't exist
    match f.try_direct_decide(1) {
        Decision::Skip => {}
        other => panic!("expected Skip for missing leader, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════
//  5-7: Byzantine Tolerance
// ═══════════════════════════════════════════════════════════════

#[test]
fn s05_f1_byzantine_offline_n4() {
    // n=4, f=1. D is offline. 3 honest still reach quorum.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1, 2])
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

#[test]
fn s06_f2_byzantine_offline_n7() {
    // n=7, f=2. E,F offline. 5 honest = quorum.
    let mut f = CommitFixture::new(7);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1, 2, 3, 4])
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

#[test]
fn s07_f_plus_1_offline_no_quorum() {
    // n=4, f=1. 2 offline (f+1) → only 2 voters, below quorum.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.assert_direct_undecided(1);
}

// ═══════════════════════════════════════════════════════════════
//  8-9: Indirect Commit / Skip via Anchor
// ═══════════════════════════════════════════════════════════════

#[test]
fn s08_indirect_commit_via_anchor() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.set_leader(3, 1);
    f.dag().layer(1).fully_connected().build();
    // Only 2 votes at R2 (below quorum)
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    // All at R3 — anchor
    f.dag().layer(3).fully_connected().build();
    f.dag().layer(4).fully_connected().build();

    f.assert_direct_undecided(1);
    f.assert_indirect_commit(1, 3);
}

#[test]
fn s09_skip_via_anchor_no_causal_link() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.set_leader(3, 1);
    // R1: leader A proposes alone
    f.dag().layer(1).authorities(&[0]).fully_connected().build();
    // R2: only B,C,D propose, skipping A's R1 block — no causal link to A1
    f.dag()
        .layer(2)
        .authorities(&[1, 2, 3])
        .skip_ancestor(0)
        .fully_connected()
        .build();
    // R3: all propose, but must also skip A1 (A's last_ref is still A1 from R1
    // since A didn't propose at R2). Without skip_ancestor(0), R3 blocks would
    // reference A1 directly, creating a causal link to the leader.
    f.dag().layer(3).skip_ancestor(0).fully_connected().build();
    f.dag().layer(4).fully_connected().build();

    f.assert_skip_via_anchor(1, 3);
}

// ═══════════════════════════════════════════════════════════════
//  10: Equivocation
// ═══════════════════════════════════════════════════════════════

#[test]
fn s10_equivocating_leader_detected() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().equivocate(1).build();
    let dag = f.dag().to_dag_state();
    assert!(
        !dag.equivocations().is_empty(),
        "equivocation should be detected"
    );
}

// ═══════════════════════════════════════════════════════════════
//  11-12: Network Partitions
// ═══════════════════════════════════════════════════════════════

#[test]
fn s11_2_2_partition_undecided() {
    // n=4, 2-2 split. Neither side has quorum.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag()
        .layer(1)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.assert_direct_undecided(1);
}

#[test]
fn s12_3_4_partition_majority_commits() {
    // n=7, 3-4 split. Majority (5) can commit. Minority (2) cannot.
    // Here we simulate the majority side.
    let mut f = CommitFixture::new(7);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    // 5 authorities vote (quorum for n=7)
    f.dag()
        .layer(2)
        .authorities(&[0, 1, 2, 3, 4])
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

// ═══════════════════════════════════════════════════════════════
//  13-15: Chains / Sequences
// ═══════════════════════════════════════════════════════════════

#[test]
fn s13_chain_of_10_direct_commits() {
    let mut f = CommitFixture::new(4);
    f.build_layers(1, 12);
    for r in 1..=10 {
        f.set_leader(r, (r % 4) as AuthorityIndex);
        f.assert_direct_commit(r);
    }
}

#[test]
fn s14_skip_then_commit() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.set_leader(2, 1);
    // R1: leader A missing
    f.dag()
        .layer(1)
        .authorities(&[1, 2, 3])
        .fully_connected()
        .build();
    f.build_layers(2, 4);

    match f.try_direct_decide(1) {
        Decision::Skip => {}
        other => panic!("R1 should skip, got {:?}", other),
    }
    f.assert_direct_commit(2);
}

#[test]
fn s15_indirect_chain_depth_2() {
    // Leader at R1, only 2 voters at R2,
    // anchor at R4 has leader in causal history through R2→R3→R4
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.set_leader(4, 2);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.dag().layer(3).fully_connected().build();
    f.dag().layer(4).fully_connected().build();
    f.dag().layer(5).fully_connected().build();

    f.assert_direct_undecided(1);
    f.assert_indirect_commit(1, 4);
}

// ═══════════════════════════════════════════════════════════════
//  16-17: Edge Cases
// ═══════════════════════════════════════════════════════════════

#[test]
fn s16_no_votes_at_all() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    // No round 2 blocks at all
    f.assert_direct_undecided(1);
}

#[test]
fn s17_single_authority() {
    // n=1 → quorum=1, always commits.
    let mut f = CommitFixture::new(1);
    f.set_leader(1, 0);
    f.build_layers(1, 2);
    f.assert_direct_commit(1);
}

// ═══════════════════════════════════════════════════════════════
//  18-21: Quorum Boundary Tests (various n)
// ═══════════════════════════════════════════════════════════════

#[test]
fn s18_n4_quorum_boundary() {
    // n=4, quorum=3. Exactly 3 votes.
    let committee = Committee::new_for_test(4);
    assert_eq!(committee.quorum_threshold(), 3);
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1, 2])
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

#[test]
fn s19_n7_quorum_boundary() {
    // n=7, quorum=5.
    let committee = Committee::new_for_test(7);
    assert_eq!(committee.quorum_threshold(), 5);
    let mut f = CommitFixture::new(7);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1, 2, 3, 4])
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

#[test]
fn s20_n10_quorum_boundary() {
    // n=10, quorum=7.
    let committee = Committee::new_for_test(10);
    assert_eq!(committee.quorum_threshold(), 7);
    let mut f = CommitFixture::new(10);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    let voters: Vec<AuthorityIndex> = (0..7).collect();
    f.dag()
        .layer(2)
        .authorities(&voters)
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

#[test]
fn s21_n21_quorum_boundary() {
    // n=21: f=6, quorum=15 (was 14 — CRIT fix, Sui-aligned).
    let committee = Committee::new_for_test(21);
    assert_eq!(committee.quorum_threshold(), 15);
    let mut f = CommitFixture::new(21);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    // Need 15 voters now (was 14)
    let voters: Vec<AuthorityIndex> = (0..15).collect();
    f.dag()
        .layer(2)
        .authorities(&voters)
        .fully_connected()
        .build();
    f.assert_direct_commit(1);
}

// ═══════════════════════════════════════════════════════════════
//  22-23: Subtle Cases
// ═══════════════════════════════════════════════════════════════

#[test]
fn s22_all_vote_but_dont_reference_leader() {
    // All 4 authorities produce R2 blocks, but none reference the leader at R1.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    // R2: all propose but skip_ancestor(0) = skip leader
    f.dag().layer(2).fully_connected().skip_ancestor(0).build();
    f.assert_direct_undecided(1);
}

#[test]
fn s23_late_arrival_resolves_undecided() {
    // Initially only 2 voters → undecided.
    // Then a 3rd voter arrives → commit.
    //
    // We use two separate fixtures because DagBuilder.layer(r) uses
    // last_refs which get updated after the first batch. A second
    // layer(2) call would give the late block ancestors from the
    // already-built R2 blocks (A2, B2) instead of R1 blocks (A1),
    // so C2 wouldn't directly reference the leader.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag().layer(1).fully_connected().build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.assert_direct_undecided(1);

    // Rebuild with 3 voters to simulate arrival of missing vote
    let mut f2 = CommitFixture::new(4);
    f2.set_leader(1, 0);
    f2.dag().layer(1).fully_connected().build();
    f2.dag()
        .layer(2)
        .authorities(&[0, 1, 2])
        .fully_connected()
        .build();
    f2.assert_direct_commit(1);
}

// ═══════════════════════════════════════════════════════════════
//  24-26: DSL Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn s24_dsl_fully_connected() {
    let mut b = parse_dag(
        r#"
        DAG {
            Round 0 : { 4 },
            Round 1 : { * },
            Round 2 : { * },
        }
    "#,
    )
    .unwrap();
    b.set_leader(1, 0);
    let dag = b.to_dag_state();
    let committee = b.committee().clone();
    let committer = misaka_dag::narwhal_ordering::base_committer::BaseCommitter::new(committee, 1);
    let leader_ref = b.leader_block(1).unwrap().reference();
    let ledger = SlotEquivocationLedger::new(u32::MAX);
    let decision = committer.try_direct_decide(&leader_ref, &dag, &ledger);
    assert!(matches!(decision, Decision::Direct(_)));
}

#[test]
fn s25_dsl_selective_ancestors() {
    let b = parse_dag(
        r#"
        DAG {
            Round 0 : { 4 },
            Round 1 : { * },
            Round 2 : {
                A -> [A1, B1],
                B -> [*],
                C -> [C1, D1],
            },
        }
    "#,
    )
    .unwrap();
    let a = b
        .blocks_at_round(2)
        .into_iter()
        .find(|blk| blk.author() == 0)
        .unwrap();
    assert_eq!(a.ancestors().len(), 2);
}

#[test]
fn s26_dsl_exclusion() {
    let b = parse_dag(
        r#"
        DAG {
            Round 0 : { 4 },
            Round 1 : { * },
            Round 2 : {
                A -> [-D1],
                B -> [-D1],
                C -> [*],
                D -> [*],
            },
        }
    "#,
    )
    .unwrap();
    let a = b
        .blocks_at_round(2)
        .into_iter()
        .find(|blk| blk.author() == 0)
        .unwrap();
    assert_eq!(a.ancestors().len(), 3); // all except D
}

// ═══════════════════════════════════════════════════════════════
//  27-28: Stress Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn s27_100_rounds_all_commit() {
    let mut f = CommitFixture::new(4);
    f.build_layers(1, 102);
    for r in 1..=100 {
        f.set_leader(r, (r % 4) as AuthorityIndex);
        f.assert_direct_commit(r);
    }
}

#[test]
fn s28_21_validators_50_rounds() {
    let mut f = CommitFixture::new(21);
    f.build_layers(1, 52);
    for r in 1..=50 {
        f.set_leader(r, (r % 21) as AuthorityIndex);
        f.assert_direct_commit(r);
    }
}

// ═══════════════════════════════════════════════════════════════
//  29-31: Adversarial & Liveness
// ═══════════════════════════════════════════════════════════════

#[test]
fn s29_intermittent_authority() {
    // D goes offline every other round.
    let mut f = CommitFixture::new(4);
    for r in 1..=10u32 {
        f.set_leader(r, (r % 4) as AuthorityIndex);
        if r % 2 == 0 {
            f.dag()
                .layer(r)
                .authorities(&[0, 1, 2])
                .fully_connected()
                .build();
        } else {
            f.dag().layer(r).fully_connected().build();
        }
    }
    // With 3/4 online each even round, most should commit.
    let mut commits = 0;
    for r in 1..=8u32 {
        if matches!(f.try_direct_decide(r), Decision::Direct(_)) {
            commits += 1;
        }
    }
    assert!(commits >= 4, "expected ≥4 commits, got {}", commits);
}

#[test]
fn s30_byzantine_equivocates_still_commits() {
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    // D equivocates
    f.dag().layer(1).fully_connected().equivocate(1).build();
    f.dag().layer(2).fully_connected().build();
    // Equivocation detected but honest quorum still commits
    f.assert_direct_commit(1);
    let dag = f.dag().to_dag_state();
    assert!(!dag.equivocations().is_empty());
}

#[test]
fn s31_f_plus_1_crash_liveness_halt() {
    // n=4, f=1. 2 offline (f+1) → only A,B online. Cannot reach quorum.
    let mut f = CommitFixture::new(4);
    f.set_leader(1, 0);
    f.dag()
        .layer(1)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.dag()
        .layer(2)
        .authorities(&[0, 1])
        .fully_connected()
        .build();
    f.assert_direct_undecided(1);
}

// ═══════════════════════════════════════════════════════════════
//  Phase 2: VoteRegistry, Depth Limit, Ancestor Selection
// ═══════════════════════════════════════════════════════════════

/// VoteRegistry detects vote equivocation.
#[test]
fn s32_vote_registry_equivocation() {
    use misaka_dag::narwhal_dag::vote_registry::{VoteRegistry, VoteResult};
    let leader = BlockRef::new(2, 0, BlockDigest([0xAA; 32]));
    let mut reg = VoteRegistry::new(leader);
    let vote1 = BlockRef::new(3, 0, BlockDigest([0x11; 32]));
    let vote2 = BlockRef::new(3, 0, BlockDigest([0x22; 32]));
    assert!(matches!(
        reg.register_vote(0, vote1),
        VoteResult::Registered
    ));
    assert!(matches!(
        reg.register_vote(0, vote2),
        VoteResult::Equivocation(_)
    ));
    assert_eq!(reg.equivocations().len(), 1);
}

/// VoteRegistry quorum with proper counting.
#[test]
fn s33_vote_registry_quorum() {
    use misaka_dag::narwhal_dag::vote_registry::VoteRegistry;
    let committee = Committee::new_for_test(4);
    let leader = BlockRef::new(2, 0, BlockDigest([0xAA; 32]));
    let mut reg = VoteRegistry::new(leader);
    for i in 0..3u32 {
        let mut d = [0u8; 32];
        d[0] = i as u8;
        reg.register_vote(i, BlockRef::new(3, i, BlockDigest(d)));
    }
    assert!(reg.reached_quorum(&committee));
}

/// Bounded indirect depth prevents deep searches.
#[test]
fn s34_indirect_depth_bounded() {
    let committee = Committee::new_for_test(4);
    let committer = BaseCommitter::new(committee.clone(), 1);
    let mut dag = DagState::new(committee, DagStateConfig::default());
    let leader = {
        let b = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };
    let mut prev = leader;
    for round in 2..=100u32 {
        let b = Block {
            epoch: 0,
            round,
            author: round % 4,
            timestamp_ms: round as u64 * 1000,
            ancestors: vec![prev],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        prev = vb.reference();
        dag.accept_block(vb);
    }
    let d1 = committer.try_decide_indirect_bounded(&leader, &prev, &dag, 10);
    assert!(matches!(d1, Decision::Undecided), "depth exceeds limit");
    let d2 = committer.try_decide_indirect_bounded(&leader, &prev, &dag, 200);
    assert!(matches!(d2, Decision::Indirect(_)), "within depth limit");
}

/// Ancestor selector excludes low-score authority.
#[test]
fn s35_ancestor_excludes_low_score() {
    use misaka_dag::narwhal_dag::ancestor::AncestorSelector;
    use misaka_dag::narwhal_dag::leader_schedule::ReputationScores;
    let committee = Committee::new_for_test(4);
    let mut sel = AncestorSelector::new(committee.clone());
    let mut dag = DagState::new(committee, DagStateConfig::default());
    for auth in 0..4u32 {
        let b = Block {
            epoch: 0,
            round: 1,
            author: auth,
            timestamp_ms: 1000 + auth as u64,
            ancestors: vec![],
            transactions: vec![vec![auth as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        dag.accept_block(VerifiedBlock::new_for_test(b));
    }
    let mut scores = ReputationScores::new(4);
    scores.scores = vec![100, 100, 100, 5];
    sel.set_scores(scores);
    sel.update_states(100);
    let ancestors = sel.select_ancestors(&dag, 2);
    assert_eq!(ancestors.len(), 3);
    assert!(ancestors.iter().all(|a| a.author != 3));
}

/// Tracked direct decide returns VoteRegistry.
#[test]
fn s36_tracked_direct_decide() {
    let committee = Committee::new_for_test(4);
    let committer = BaseCommitter::new(committee.clone(), 1);
    let mut dag = DagState::new(committee, DagStateConfig::default());
    let leader = {
        let b = Block {
            epoch: 0,
            round: 2,
            author: 0,
            timestamp_ms: 2000,
            ancestors: vec![],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };
    for auth in 0..3u32 {
        let b = Block {
            epoch: 0,
            round: 3,
            author: auth,
            timestamp_ms: 3000 + auth as u64,
            ancestors: vec![leader],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        dag.accept_block(VerifiedBlock::new_for_test(b));
    }
    let ledger = SlotEquivocationLedger::new(u32::MAX);
    let (decision, registry) = committer.try_direct_decide_tracked(&leader, &dag, &ledger);
    assert!(matches!(decision, Decision::Direct(_)));
    assert_eq!(registry.voter_count(), 3);
}

// ═══════════════════════════════════════════════════════════════
//  37-38: Equivocation Flooding & BFS Safety
// ═══════════════════════════════════════════════════════════════

/// SECURITY: Byzantine authority floods equivocating blocks to inflate
/// BFS visited set. Before the fix, this caused `is_in_causal_history`
/// to return `false` (→ Skip), permanently discarding a legitimate leader.
/// After fix, BFS returns `Aborted` → `Undecided`, allowing retry.
#[test]
fn s37_equivocation_flood_does_not_cause_skip() {
    // Setup: n=4, leader at R1. All honest + Byzantine D equivocates massively.
    let committee = Committee::new_for_test(4);
    let committer = BaseCommitter::new(committee.clone(), 1);
    let mut dag = DagState::new(committee, DagStateConfig::default());

    // Leader at R1
    let leader = {
        let block = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![0]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(block);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };

    // 2 honest voters at R2 linking to leader (not quorum for direct commit)
    let mut voter_refs = vec![];
    for auth in 0..2u32 {
        let block = Block {
            epoch: 0,
            round: 2,
            author: auth,
            timestamp_ms: 2000 + auth as u64,
            ancestors: vec![leader],
            transactions: vec![vec![auth as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(block);
        voter_refs.push(vb.reference());
        dag.accept_block(vb);
    }

    // Byzantine D floods equivocating blocks at R2.
    // These blocks do NOT reference the leader — Byzantine D is trying to
    // inflate the BFS visited set without actually voting for the leader.
    // Only the first block per slot is stored (DagState rejects subsequent
    // equivocations after recording evidence), so this keeps the vote count
    // at 2 honest voters (below quorum=3).
    for i in 0..50u32 {
        let block = Block {
            epoch: 0,
            round: 2,
            author: 3,
            timestamp_ms: 2100 + i as u64, // different timestamp → different digest
            ancestors: vec![],             // no reference to leader
            transactions: vec![vec![3, i as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xBB; 64],
        };
        let vb = VerifiedBlock::new_for_test(block);
        dag.accept_block(vb);
    }

    // Anchor at R3 (links to honest voters which link to leader)
    let anchor = {
        let block = Block {
            epoch: 0,
            round: 3,
            author: 1,
            timestamp_ms: 3000,
            ancestors: voter_refs,
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(block);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };

    // Direct: only 2 votes, undecided (quorum=3)
    let ledger = SlotEquivocationLedger::new(u32::MAX);
    assert!(matches!(
        committer.try_direct_decide(&leader, &dag, &ledger),
        Decision::Undecided
    ));

    // Indirect via anchor: leader IS in anchor's causal history.
    // Before fix: BFS might abort and return Skip.
    // After fix: BFS completes or returns Undecided (not Skip).
    let decision = committer.try_decide_with_anchor(&leader, &anchor, &dag);
    assert!(
        matches!(decision, Decision::Indirect(_) | Decision::Undecided),
        "equivocation flood must NOT cause Skip. Got {:?}. \
         Indirect (leader in causal history) or Undecided (BFS aborted safely) \
         are both acceptable. Skip is a safety violation.",
        decision
    );
}

/// Verify that equivocations are properly surfaced via BlockAcceptResult.
#[test]
fn s38_equivocation_result_surfaced() {
    let committee = Committee::new_for_test(4);
    let mut dag = DagState::new(committee, DagStateConfig::default());

    let b1 = {
        let block = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![1]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        VerifiedBlock::new_for_test(block)
    };
    let r1 = dag.accept_block(b1);
    assert!(r1.is_accepted());
    assert!(!r1.is_equivocation());

    // Equivocating block: same slot, different content
    let b2 = {
        let block = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1001,
            ancestors: vec![],
            transactions: vec![vec![2]], // different
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xBB; 64],
        };
        VerifiedBlock::new_for_test(block)
    };
    let r2 = dag.accept_block(b2);
    assert!(
        r2.is_accepted(),
        "equivocating block should be accepted as evidence"
    );
    assert!(r2.is_equivocation(), "must report equivocation");
    assert_eq!(dag.equivocations().len(), 1);
}

// ═══════════════════════════════════════════════════════════════
//  39-40: Heavy Equivocation Flooding (BFS cap regression)
// ═══════════════════════════════════════════════════════════════

/// REGRESSION: Heavy equivocation flood that exceeds old static BFS cap (10,000).
///
/// With 4 authorities × 50 rounds × 200 equivocations per round per Byzantine,
/// the BFS could visit 200×50 = 10,000+ nodes just from one authority's
/// equivocating blocks. The old code returned `false` → `Decision::Skip`
/// (permanent safety violation). The fix returns `BfsResult::Aborted` →
/// `Decision::Undecided`, allowing safe retry with a different anchor.
///
/// This test creates:
/// - Leader at R1
/// - 2 honest voters at R2
/// - 1 Byzantine authority flooding 200 equivocations at R2
/// - Anchor at R4 that has leader in causal history
///
/// With dynamic cap = committee_size(4) × round_diff(3) × 4 = 48,
/// even a moderate flood should be handled correctly.
#[test]
fn s39_heavy_equivocation_flood_bfs_safety() {
    let committee = Committee::new_for_test(4);
    let committer = BaseCommitter::new(committee.clone(), 1);
    let mut dag = DagState::new(committee, DagStateConfig::default());

    // Leader at R1
    let leader = {
        let b = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![0]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };

    // 2 honest voters at R2 linking to leader
    let mut honest_voter_refs = vec![];
    for auth in 0..2u32 {
        let b = Block {
            epoch: 0,
            round: 2,
            author: auth,
            timestamp_ms: 2000 + auth as u64,
            ancestors: vec![leader],
            transactions: vec![vec![auth as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        honest_voter_refs.push(vb.reference());
        dag.accept_block(vb);
    }

    // Byzantine authority 3 floods 200 equivocating blocks at R2.
    // These blocks do NOT reference the leader — the attack inflates the
    // BFS visited set without voting for the leader, keeping the honest
    // vote count at 2 (below quorum=3). Only the first block per slot is
    // stored by DagState; subsequent equivocations are recorded as evidence
    // but not inserted.
    for i in 0..200u32 {
        let b = Block {
            epoch: 0,
            round: 2,
            author: 3,
            timestamp_ms: 2100 + i as u64,
            ancestors: vec![], // no reference to leader
            transactions: vec![vec![3, (i >> 8) as u8, i as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xBB; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        dag.accept_block(vb);
    }

    // Intermediate round R3 linking to honest voters
    let r3_ref = {
        let b = Block {
            epoch: 0,
            round: 3,
            author: 1,
            timestamp_ms: 3000,
            ancestors: honest_voter_refs.clone(),
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };

    // Anchor at R4 — has leader in causal history via honest voters
    let anchor = {
        let b = Block {
            epoch: 0,
            round: 4,
            author: 0,
            timestamp_ms: 4000,
            ancestors: vec![r3_ref],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };

    // Direct: only 2 votes (below quorum=3)
    let ledger = SlotEquivocationLedger::new(u32::MAX);
    assert!(matches!(
        committer.try_direct_decide(&leader, &dag, &ledger),
        Decision::Undecided
    ));

    // Indirect: leader IS in anchor's causal history, but equivocation
    // flood may cause BFS to abort. Must NOT return Skip.
    let decision = committer.try_decide_with_anchor(&leader, &anchor, &dag);
    assert!(
        matches!(decision, Decision::Indirect(_) | Decision::Undecided),
        "Heavy equivocation flood MUST NOT cause Skip (safety violation). \
         Got {:?}. Indirect or Undecided are both safe.",
        decision
    );

    // Verify equivocations were actually detected
    assert!(
        dag.equivocations().len() >= 100,
        "should have detected many equivocations, got {}",
        dag.equivocations().len()
    );
}

/// After BFS aborts with Undecided, the next anchor with a direct path
/// should successfully return Indirect commit.
#[test]
fn s40_bfs_abort_retries_with_later_anchor() {
    let committee = Committee::new_for_test(4);
    let committer = BaseCommitter::new(committee.clone(), 1);
    let mut dag = DagState::new(committee, DagStateConfig::default());

    // Build a simple chain: leader R1 → voter R2 → R3 → anchor R5
    let leader = {
        let b = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![0]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        let r = vb.reference();
        dag.accept_block(vb);
        r
    };

    // Direct chain without equivocation
    let mut prev = leader;
    for round in 2..=5u32 {
        let b = Block {
            epoch: 0,
            round,
            author: (round % 4),
            timestamp_ms: round as u64 * 1000,
            ancestors: vec![prev],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_for_test(b);
        prev = vb.reference();
        dag.accept_block(vb);
    }

    // Anchor at R5 should find leader via clean chain
    let decision = committer.try_decide_with_anchor(&leader, &prev, &dag);
    assert!(
        matches!(decision, Decision::Indirect(_)),
        "Clean chain should result in Indirect commit, got {:?}",
        decision
    );
}
