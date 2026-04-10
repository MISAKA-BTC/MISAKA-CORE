// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Integration tests for Narwhal/Bullshark consensus.
//!
//! Simulates a multi-node consensus network in-process:
//! - N authorities running independent DagState + CoreEngine
//! - Blocks proposed and exchanged via in-memory channels
//! - All nodes must converge on the same committed sequence

use std::collections::HashMap;
use std::sync::Arc;

use misaka_dag::narwhal_dag::block_manager::*;
use misaka_dag::narwhal_dag::core_engine::{CoreEngine, ProposeContext};
use misaka_dag::narwhal_dag::dag_state::*;
use misaka_dag::narwhal_dag::leader_schedule::*;
use misaka_dag::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger;
use misaka_dag::narwhal_ordering::linearizer::*;
use misaka_dag::narwhal_ordering::universal_committer::*;
use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::commit::*;
use misaka_dag::narwhal_types::committee::*;

// ═══════════════════════════════════════════════════════════
//  Simulated node
// ═══════════════════════════════════════════════════════════

struct SimNode {
    authority: AuthorityIndex,
    core: CoreEngine,
    dag: DagState,
    block_manager: BlockManager,
    committer: UniversalCommitter,
    ledger: SlotEquivocationLedger,
    linearizer: Linearizer,
    finalizer: CommitFinalizer,
    clock: ThresholdClock,
    committed_txs: Vec<Vec<u8>>,
    committed_leaders: Vec<BlockRef>,
}

impl SimNode {
    fn new(authority: AuthorityIndex, committee: &Committee, vs: &TestValidatorSet) -> Self {
        let signer = vs.signer(authority as usize);
        let ls = LeaderSchedule::new(committee.clone(), 1);
        let chain_ctx = TestValidatorSet::chain_ctx();

        Self {
            authority,
            core: CoreEngine::new(
                authority,
                0,
                committee.clone(),
                signer,
                vs.verifier(0),
                chain_ctx,
            ),
            dag: DagState::new(committee.clone(), DagStateConfig::default()),
            block_manager: BlockManager::new(committee.clone()),
            committer: UniversalCommitter::new(committee.clone(), ls, 1, 2),
            ledger: SlotEquivocationLedger::new(),
            linearizer: Linearizer::new(),
            finalizer: CommitFinalizer::new(),
            clock: ThresholdClock::new(committee.clone()),
            committed_txs: Vec::new(),
            committed_leaders: Vec::new(),
        }
    }

    fn propose(&mut self, _round: Round, txs: Vec<Vec<u8>>) -> VerifiedBlock {
        self.core
            .propose_block(&mut self.dag, ProposeContext::normal(txs, [0u8; 32]))
    }

    fn receive_block(&mut self, block: VerifiedBlock) {
        let result = self
            .core
            .process_block(block, &mut self.block_manager, &mut self.dag);
        for b in &result.accepted {
            self.clock.observe(b.round(), b.author());
        }
    }

    fn try_commit(&mut self) {
        let commits = self.committer.try_commit(&self.dag, &self.ledger);
        for commit in &commits {
            self.dag.record_commit(commit.clone());
            self.committed_leaders.push(commit.leader);

            if let Some(output) = self.linearizer.linearize(commit, |r| {
                self.dag.get_block(r).map(|vb| vb.inner().clone())
            }) {
                for tx in &output.transactions {
                    self.committed_txs.push(tx.clone());
                }
                self.finalizer.submit(output);
            }
        }
        self.finalizer.finalize_all();
    }
}

// ═══════════════════════════════════════════════════════════
//  Test: 4-node consensus converges
// ═══════════════════════════════════════════════════════════

#[test]
fn test_4_node_consensus_convergence() {
    let vs = TestValidatorSet::new(4);
    let committee = vs.committee();
    let mut nodes: Vec<SimNode> = (0..4).map(|i| SimNode::new(i, &committee, &vs)).collect();

    // Simulate 6 rounds
    for round in 1..=6u32 {
        // Each node proposes a block
        let mut proposed_blocks = Vec::new();
        for i in 0..4 {
            let tx = vec![round as u8, i as u8]; // unique tx per node per round
            let block = nodes[i as usize].propose(round, vec![tx]);
            proposed_blocks.push(block);
        }

        // All nodes receive all blocks (fully connected network)
        for block in &proposed_blocks {
            for node in &mut nodes {
                if node.authority != block.author() {
                    node.receive_block(block.clone());
                }
            }
        }

        // All nodes try to commit
        for node in &mut nodes {
            node.try_commit();
        }
    }

    // All nodes must have committed the same leaders
    let leaders_0 = &nodes[0].committed_leaders;
    assert!(!leaders_0.is_empty(), "node 0 must have commits");

    for node in &nodes[1..] {
        assert_eq!(
            node.committed_leaders.len(),
            leaders_0.len(),
            "node {} has {} commits, expected {}",
            node.authority,
            node.committed_leaders.len(),
            leaders_0.len()
        );
        for (i, leader) in node.committed_leaders.iter().enumerate() {
            assert_eq!(
                *leader, leaders_0[i],
                "node {} commit {} leader mismatch: {:?} vs {:?}",
                node.authority, i, leader, leaders_0[i]
            );
        }
    }

    // All nodes must have committed the same transactions (same order)
    let txs_0 = &nodes[0].committed_txs;
    for node in &nodes[1..] {
        assert_eq!(
            node.committed_txs.len(),
            txs_0.len(),
            "node {} tx count mismatch",
            node.authority
        );
        assert_eq!(
            node.committed_txs, *txs_0,
            "node {} committed different txs",
            node.authority
        );
    }

    println!(
        "4-node consensus: {} commits, {} txs committed",
        leaders_0.len(),
        txs_0.len()
    );
}

// ═══════════════════════════════════════════════════════════
//  Test: 15-node SR committee converges
// ═══════════════════════════════════════════════════════════

#[test]
fn test_sr15_consensus_convergence() {
    let n = 15;
    let vs = TestValidatorSet::new(n);
    let committee = vs.committee();
    let mut nodes: Vec<SimNode> = (0..n as u32)
        .map(|i| SimNode::new(i, &committee, &vs))
        .collect();

    for round in 1..=6u32 {
        let mut proposed = Vec::new();
        for i in 0..n {
            let block = nodes[i].propose(round, vec![vec![round as u8, i as u8]]);
            proposed.push(block);
        }
        for block in &proposed {
            for node in &mut nodes {
                if node.authority != block.author() {
                    node.receive_block(block.clone());
                }
            }
        }
        for node in &mut nodes {
            node.try_commit();
        }
    }

    let leaders_0 = &nodes[0].committed_leaders;
    assert!(!leaders_0.is_empty(), "SR15 must produce commits");

    for node in &nodes[1..] {
        assert_eq!(
            node.committed_leaders, *leaders_0,
            "SR15 node {} diverged",
            node.authority
        );
    }

    println!("SR15 consensus: {} commits", leaders_0.len());
}

// ═══════════════════════════════════════════════════════════
//  Test: Byzantine fault tolerance (f nodes silent)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_bft_with_f_silent_nodes() {
    let n = 4;
    let f = 1; // max faults for n=4
    let vs = TestValidatorSet::new(n);
    let committee = vs.committee();
    let mut nodes: Vec<SimNode> = (0..n as u32)
        .map(|i| SimNode::new(i, &committee, &vs))
        .collect();

    for round in 1..=8u32 {
        // Only honest nodes (0..n-f) propose
        let mut proposed = Vec::new();
        for i in 0..(n - f) {
            let block = nodes[i].propose(round, vec![vec![round as u8]]);
            proposed.push(block);
        }

        // Honest nodes exchange blocks among themselves only
        for block in &proposed {
            for i in 0..(n - f) {
                if nodes[i].authority != block.author() {
                    nodes[i].receive_block(block.clone());
                }
            }
        }

        for i in 0..(n - f) {
            nodes[i].try_commit();
        }
    }

    // Honest nodes should still reach consensus
    let leaders_0 = &nodes[0].committed_leaders;
    assert!(
        !leaders_0.is_empty(),
        "honest nodes must commit even with {} silent faults",
        f
    );

    // All honest nodes agree
    for i in 1..(n - f) {
        assert_eq!(
            nodes[i].committed_leaders, *leaders_0,
            "honest node {} diverged",
            i
        );
    }

    println!(
        "BFT test (n={}, f={}): {} commits by honest nodes",
        n,
        f,
        leaders_0.len()
    );
}

// ═══════════════════════════════════════════════════════════
//  Test: Persistence round-trip
// ═══════════════════════════════════════════════════════════

#[cfg(feature = "json-store-dev")]
#[test]
fn test_persistence_round_trip() {
    use misaka_dag::narwhal_dag::store::*;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("consensus")).unwrap();

    let committee = Committee::new_for_test(4);
    let mut dag = DagState::new(committee.clone(), DagStateConfig::default());

    // Build 3 rounds of blocks
    for round in 1..=3u32 {
        for author in 0..4u32 {
            let block = Block {
                epoch: 0,
                round,
                author,
                timestamp_ms: round as u64 * 1000,
                ancestors: vec![],
                transactions: vec![vec![round as u8, author as u8]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![0xAA; 64],
            };
            dag.accept_block(VerifiedBlock::new_for_test(block));
        }
    }

    // Persist
    let batch = dag.take_write_batch();
    store.write_batch(&batch).unwrap();

    // Recover
    let recovered = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();

    assert_eq!(recovered.num_blocks(), 12); // 3 rounds * 4 authorities
    assert_eq!(recovered.highest_accepted_round(), 3);
}

// ═══════════════════════════════════════════════════════════
//  Test: Epoch transition
// ═══════════════════════════════════════════════════════════

#[test]
fn test_epoch_transition_sr15_to_sr21() {
    use misaka_dag::narwhal_dag::epoch::*;

    let sr15 = Committee::new_for_test(15);
    let mut mgr = EpochManager::new(0, sr15.clone());
    mgr.set_trigger(EpochChangeTrigger::CommitCount(5));

    // Simulate 5 commits
    for i in 0..5 {
        mgr.on_commit(i);
    }
    assert!(mgr.in_grace_period());

    // Transition to SR21
    let sr21 = Committee::new_for_test(21);
    mgr.prepare_epoch_change(sr21, 100);
    let new = mgr.apply_epoch_change().unwrap();

    assert_eq!(new.size(), 21);
    assert_eq!(new.quorum_threshold(), 15); // N - floor((N-1)/3) = 21 - 6 = 15
    assert_eq!(mgr.current_epoch(), 1);
}

// ═══════════════════════════════════════════════════════════
//  Test: Block verifier rejects invalid blocks
// ═══════════════════════════════════════════════════════════

#[test]
fn test_block_verifier_integration() {
    use misaka_dag::narwhal_dag::block_verifier::*;

    let vs = TestValidatorSet::new(4);
    let committee = vs.committee();
    let verifier = vs.verifier(0);

    // Valid block — must be properly signed with ML-DSA-65
    let mut valid = Block {
        epoch: 0,
        round: 1,
        author: 0,
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        ancestors: vec![],
        transactions: vec![vec![1, 2, 3]],
        commit_votes: vec![],
        tx_reject_votes: vec![],
        state_root: [0u8; 32],
        signature: vec![],
    };
    vs.sign_block(0, &mut valid);
    assert!(verifier.verify(&valid).is_ok());

    // Invalid: wrong epoch
    let wrong_epoch = Block {
        epoch: 99,
        ..valid.clone()
    };
    assert!(verifier.verify(&wrong_epoch).is_err());

    // Invalid: author out of range
    let bad_author = Block {
        author: 99,
        ..valid.clone()
    };
    assert!(verifier.verify(&bad_author).is_err());

    // Invalid: round 0
    let round_zero = Block {
        round: 0,
        ..valid.clone()
    };
    assert!(verifier.verify(&round_zero).is_err());

    // Invalid: empty signature
    let no_sig = Block {
        signature: vec![],
        ..valid.clone()
    };
    assert!(verifier.verify(&no_sig).is_err());
}

// ═══════════════════════════════════════════════════════════
//  Test: Pipelined committer (dual slot)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_pipelined_committer_dual_slot() {
    use misaka_dag::narwhal_ordering::pipeline::*;

    let committee = Committee::new_for_test(4);
    let ls = LeaderSchedule::new(committee.clone(), 2); // 2 slots
    let mut committer = PipelinedCommitter::new(committee.clone(), ls, 2, 2);
    let mut dag = DagState::new(committee, DagStateConfig::default());

    // Build 5 rounds fully connected
    let mut prev = Vec::new();
    for round in 1..=5u32 {
        let mut refs = Vec::new();
        for author in 0..4u32 {
            let block = Block {
                epoch: 0,
                round,
                author,
                timestamp_ms: round as u64 * 1000,
                ancestors: prev.clone(),
                transactions: vec![vec![round as u8, author as u8]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![0xAA; 64],
            };
            let vb = VerifiedBlock::new_for_test(block);
            refs.push(vb.reference());
            dag.accept_block(vb);
        }
        prev = refs;
    }

    let ledger = SlotEquivocationLedger::new();
    let commits = committer.try_commit(&dag, &ledger);
    assert!(
        !commits.is_empty(),
        "pipelined committer must produce commits"
    );

    // Commit indices must be sequential
    for (i, c) in commits.iter().enumerate() {
        assert_eq!(c.index, i as u64);
    }

    println!(
        "Pipelined (2 slots): {} commits from 5 rounds",
        commits.len()
    );
}

// ═══════════════════════════════════════════════════════════
//  Test: Commit observer reputation
// ═══════════════════════════════════════════════════════════

#[test]
fn test_commit_observer_updates_reputation() {
    use misaka_dag::narwhal_ordering::pipeline::CommitObserver;

    let mut observer = CommitObserver::new(100);
    let n = 4;

    // Authority 0 is always leader, authority 3 never has blocks
    for i in 0..10u64 {
        let sub_dag = CommittedSubDag {
            index: i,
            leader: BlockRef::new(2, 0, BlockDigest([i as u8; 32])),
            blocks: vec![
                BlockRef::new(1, 0, BlockDigest([0; 32])),
                BlockRef::new(1, 1, BlockDigest([1; 32])),
                BlockRef::new(1, 2, BlockDigest([2; 32])),
                // authority 3 missing
            ],
            timestamp_ms: 1000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        observer.observe(&sub_dag);
    }

    let scores = observer.build_reputation_scores(n);

    // Authority 0 should have highest score (leader + block)
    // Authority 3 should have lowest (only initial score)
    assert!(
        scores.scores[0] > scores.scores[3],
        "leader authority should have higher reputation: {} vs {}",
        scores.scores[0],
        scores.scores[3]
    );
}
