// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/commit_test_fixture.rs (723 lines)
//
//! Integrated commit test fixture.
//!
//! Bundles `DagBuilder` + `DagState` + `BaseCommitter` + `UniversalCommitter`
//! into a single harness for testing commit rules end-to-end.

use super::dag_builder::DagBuilder;
use crate::narwhal_dag::dag_state::{DagState, DagStateConfig};
use crate::narwhal_ordering::base_committer::{BaseCommitter, Decision};
// Linearizer and UniversalCommitter used in extended fixture tests (Phase 2+)
#[allow(unused_imports)]
use crate::narwhal_ordering::linearizer::Linearizer;
#[allow(unused_imports)]
use crate::narwhal_ordering::universal_committer::UniversalCommitter;
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

/// Integrated commit test harness.
///
/// Combines DAG building with committer evaluation in a single API
/// so declarative tests can focus on topology, not plumbing.
pub struct CommitFixture {
    builder: DagBuilder,
    committee: Committee,
    leader_round_wave: u32,
}

impl CommitFixture {
    /// Create a fixture with uniform-stake committee of `n` authorities.
    #[must_use]
    pub fn new(n: usize) -> Self {
        let committee = Committee::new_for_test(n);
        Self {
            builder: DagBuilder::new(committee.clone()),
            committee,
            leader_round_wave: 1,
        }
    }

    /// Set the leader wave length (default 1 = every round has a leader).
    #[must_use]
    pub fn with_wave(mut self, wave: u32) -> Self {
        self.leader_round_wave = wave;
        self
    }

    /// Access the underlying builder (for `.layer(r).…` calls).
    pub fn dag(&mut self) -> &mut DagBuilder {
        &mut self.builder
    }

    /// Override leader for a round.
    pub fn set_leader(&mut self, round: Round, auth: AuthorityIndex) {
        self.builder.set_leader(round, auth);
    }

    // ── Direct commit test ──────────────────────────────────

    /// Test direct commit for a leader at `leader_round`.
    ///
    /// Returns the `Decision` from `BaseCommitter::try_direct_decide`.
    #[must_use]
    pub fn try_direct_decide(&self, leader_round: Round) -> Decision {
        let dag = self.builder.to_dag_state();
        let committer = BaseCommitter::new(self.committee.clone(), self.leader_round_wave);

        let leader = self.builder.leader_of(leader_round);
        let leader_ref = match self.builder.leader_block(leader_round) {
            Some(b) => b.reference(),
            None => return Decision::Skip,
        };

        let ledger = crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new();
        committer.try_direct_decide(&leader_ref, &dag, &ledger)
    }

    /// Test indirect/skip decision using an anchor.
    #[must_use]
    pub fn try_decide_with_anchor(&self, leader_round: Round, anchor_round: Round) -> Decision {
        let dag = self.builder.to_dag_state();
        let committer = BaseCommitter::new(self.committee.clone(), self.leader_round_wave);

        let leader_ref = match self.builder.leader_block(leader_round) {
            Some(b) => b.reference(),
            None => return Decision::Skip,
        };
        let anchor_ref = match self.builder.leader_block(anchor_round) {
            Some(b) => b.reference(),
            None => return Decision::Undecided,
        };

        committer.try_decide_with_anchor(&leader_ref, &anchor_ref, &dag)
    }

    // ── Assertions ──────────────────────────────────────────

    /// Assert that leader at `round` is directly committed.
    ///
    /// Panics with DAG dump if assertion fails.
    pub fn assert_direct_commit(&self, round: Round) {
        match self.try_direct_decide(round) {
            Decision::Direct(_) => {}
            other => panic!(
                "expected Direct commit at round {}, got {:?}\nDAG:\n{}",
                round,
                other,
                self.builder.dump()
            ),
        }
    }

    /// Assert that leader at `round` is undecided (directly).
    pub fn assert_direct_undecided(&self, round: Round) {
        match self.try_direct_decide(round) {
            Decision::Undecided => {}
            other => panic!(
                "expected Undecided at round {}, got {:?}\nDAG:\n{}",
                round,
                other,
                self.builder.dump()
            ),
        }
    }

    /// Assert indirect commit via anchor.
    pub fn assert_indirect_commit(&self, leader_round: Round, anchor_round: Round) {
        match self.try_decide_with_anchor(leader_round, anchor_round) {
            Decision::Indirect(_) => {}
            other => panic!(
                "expected Indirect commit for leader R{} via anchor R{}, got {:?}\nDAG:\n{}",
                leader_round,
                anchor_round,
                other,
                self.builder.dump()
            ),
        }
    }

    /// Assert skip via anchor.
    pub fn assert_skip_via_anchor(&self, leader_round: Round, anchor_round: Round) {
        match self.try_decide_with_anchor(leader_round, anchor_round) {
            Decision::Skip => {}
            other => panic!(
                "expected Skip for leader R{} via anchor R{}, got {:?}\nDAG:\n{}",
                leader_round,
                anchor_round,
                other,
                self.builder.dump()
            ),
        }
    }

    // ── Convenience builders ────────────────────────────────

    /// Build fully-connected layers from `start` to `end`.
    pub fn build_layers(&mut self, start: Round, end: Round) {
        self.builder.build_layers(start, end);
    }

    /// Committee reference.
    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_direct_commit() {
        let mut f = CommitFixture::new(4);
        f.set_leader(1, 0);
        f.build_layers(1, 2);
        f.assert_direct_commit(1);
    }

    #[test]
    fn fixture_undecided() {
        let mut f = CommitFixture::new(4);
        f.set_leader(1, 0);
        f.dag().layer(1).fully_connected().build();
        // Only 1 vote at R2
        f.dag().layer(2).authorities(&[1]).fully_connected().build();
        f.assert_direct_undecided(1);
    }

    #[test]
    fn fixture_indirect_commit() {
        let mut f = CommitFixture::new(4);
        f.set_leader(1, 0);
        f.set_leader(3, 1);
        f.dag().layer(1).fully_connected().build();
        // 2 voters (below quorum of 3)
        f.dag()
            .layer(2)
            .authorities(&[0, 1])
            .fully_connected()
            .build();
        // Anchor round with all authorities
        f.dag().layer(3).fully_connected().build();
        f.dag().layer(4).fully_connected().build();

        // Direct: undecided (only 2 votes)
        f.assert_direct_undecided(1);
        // Indirect via anchor at R3: voters at R2 link to leader at R1,
        // anchor at R3 links to voters at R2 → leader in anchor's causal history
        f.assert_indirect_commit(1, 3);
    }

    #[test]
    fn fixture_skip() {
        let mut f = CommitFixture::new(4);
        f.set_leader(1, 0);
        f.set_leader(3, 1);
        // R1: leader A missing
        f.dag()
            .layer(1)
            .authorities(&[1, 2, 3])
            .fully_connected()
            .build();
        f.dag().layer(2).fully_connected().build();
        // Anchor at R3
        f.dag().layer(3).fully_connected().build();
        f.dag().layer(4).fully_connected().build();

        // Skip: leader block doesn't exist → Skip
        match f.try_direct_decide(1) {
            Decision::Skip => {}
            other => panic!("expected Skip, got {:?}", other),
        }
    }
}
