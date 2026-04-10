// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 0f58433, path: consensus/core/src/observer_service.rs
//
//! Observer Service — non-voting commit stream for external consumers.
//!
//! An observer node follows the consensus DAG without voting or proposing.
//! It receives committed sub-DAGs and packages them with ML-DSA-65 quorum
//! proofs for downstream verification.
//!
//! # Primary consumers
//!
//! - **Phase 4 Light Client**: verifies tx finality via quorum proof
//! - **Phase 7 Indexer**: reads commit stream for block/tx indexing
//! - **External auditors**: verify consensus integrity
//!
//! # Design
//!
//! ```text
//! Linearizer → CommitSubscriber → ObserverService
//!                                     │
//!                                     ├── (commit, quorum_proof) pairs
//!                                     │
//!                                     ├── Light Client (Phase 4)
//!                                     ├── Indexer (Phase 7)
//!                                     └── Audit tools
//! ```
//!
//! The observer does NOT:
//! - Propose blocks
//! - Vote on commits
//! - Participate in leader election
//! - Affect consensus progress

use std::fmt;

use crate::narwhal_dag::commit_consumer::CommitConsumer;
use crate::narwhal_ordering::linearizer::LinearizedOutput;
use crate::narwhal_types::block::{AuthorityIndex, BlockRef};
use crate::narwhal_types::commit::CommitDigest;

// ═══════════════════════════════════════════════════════════
//  Quorum Proof
// ═══════════════════════════════════════════════════════════

/// ML-DSA-65 quorum proof for a committed sub-DAG.
///
/// Contains the commit digest and the signatures from ≥ 2f+1 authorities
/// that endorsed this commit. The Light Client (Phase 4) verifies this
/// proof against the known validator set to confirm finality without
/// trusting any single full node.
#[derive(Clone, Debug)]
pub struct QuorumProof {
    /// Digest of the committed sub-DAG.
    pub commit_digest: CommitDigest,
    /// Commit index (sequential).
    pub commit_index: u64,
    /// Authorities that endorsed this commit (by index).
    /// In production, each entry would also carry the ML-DSA-65 signature.
    /// For now, we track authority indices; actual signature aggregation
    /// is deferred to Phase 4 when the Light Client needs it.
    pub endorsers: Vec<AuthorityIndex>,
    /// Total stake represented by endorsers.
    pub endorser_stake: u64,
    /// Whether the proof meets the quorum threshold (2f+1 stake).
    pub is_quorum: bool,
}

impl fmt::Display for QuorumProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QuorumProof(index={}, endorsers={}, stake={}, quorum={})",
            self.commit_index,
            self.endorsers.len(),
            self.endorser_stake,
            self.is_quorum
        )
    }
}

// ═══════════════════════════════════════════════════════════
//  Observed Commit (output type)
// ═══════════════════════════════════════════════════════════

/// A commit paired with its ML-DSA-65 quorum proof.
///
/// This is the primary output of the ObserverService, consumed by:
/// - Phase 4 Light Client (finality verification)
/// - Phase 7 Indexer (block/tx indexing)
#[derive(Clone, Debug)]
pub struct ObservedCommit {
    /// The linearized commit output (transactions, leader, etc.).
    pub output: LinearizedOutput,
    /// ML-DSA-65 quorum proof for this commit.
    pub quorum_proof: QuorumProof,
}

// ═══════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════

/// ObserverService metrics.
#[derive(Debug, Clone, Default)]
pub struct ObserverMetrics {
    /// Total commits observed.
    pub commits_observed: u64,
    /// Total commits with valid quorum proof.
    pub commits_with_quorum: u64,
    /// Total commits without quorum (should be 0 in normal operation).
    pub commits_without_quorum: u64,
    /// Total commits emitted to downstream consumers.
    pub commits_emitted: u64,
}

// ═══════════════════════════════════════════════════════════
//  ObserverService
// ═══════════════════════════════════════════════════════════

/// Non-voting commit stream service.
///
/// Implements [`CommitConsumer`] to receive ordered commits from the
/// consensus pipeline. Packages each commit with an ML-DSA-65 quorum
/// proof and emits (commit, proof) pairs for external consumers.
///
/// # Observer mode
///
/// When AuthorityNode starts in observer mode:
/// - CoreEngine processes blocks (verification only)
/// - Committer runs (to determine committed leaders)
/// - Linearizer orders transactions
/// - But NO blocks are proposed (observer is read-only)
/// - ObserverService receives the commit stream
pub struct ObserverService {
    /// Committee size for quorum calculation.
    committee_size: usize,
    /// Quorum stake threshold (2f+1).
    quorum_stake: u64,
    /// Recent observed commits (ring buffer for downstream polling).
    recent_commits: Vec<ObservedCommit>,
    /// Maximum number of recent commits to retain.
    max_recent: usize,
    /// Metrics.
    metrics: ObserverMetrics,
}

impl ObserverService {
    /// Create a new observer service.
    ///
    /// `committee_size`: number of validators
    /// `max_recent`: how many recent commits to buffer for polling
    pub fn new(committee_size: usize, max_recent: usize) -> Self {
        let f = (committee_size - 1) / 3;
        let quorum_stake = (committee_size - f) as u64;
        Self {
            committee_size,
            quorum_stake,
            recent_commits: Vec::with_capacity(max_recent.min(1024)),
            max_recent,
            metrics: ObserverMetrics::default(),
        }
    }

    /// Build a quorum proof for a commit.
    ///
    /// In the current implementation, we build a "structural" proof:
    /// the commit is produced by the BFT consensus pipeline which
    /// guarantees 2f+1 support by construction. The endorsers are
    /// the authorities whose blocks are referenced in the committed
    /// sub-DAG.
    ///
    /// Phase 4 (Light Client) will extend this with actual ML-DSA-65
    /// signature collection from the validator set.
    fn build_quorum_proof(&self, output: &LinearizedOutput) -> QuorumProof {
        // Collect unique block authors from the committed sub-DAG.
        // These are the authorities that contributed blocks to this commit.
        let mut endorsers: Vec<AuthorityIndex> = output
            .blocks
            .iter()
            .map(|br| br.author)
            .collect();
        endorsers.sort_unstable();
        endorsers.dedup();

        let endorser_stake = endorsers.len() as u64;
        let is_quorum = endorser_stake >= self.quorum_stake;

        QuorumProof {
            commit_digest: CommitDigest([0; 32]), // Placeholder — Phase 4 will compute real digest
            commit_index: output.commit_index,
            endorsers,
            endorser_stake,
            is_quorum,
        }
    }

    /// Get recent observed commits for downstream polling.
    pub fn recent_commits(&self) -> &[ObservedCommit] {
        &self.recent_commits
    }

    /// Get the latest observed commit (if any).
    pub fn latest_commit(&self) -> Option<&ObservedCommit> {
        self.recent_commits.last()
    }

    /// Number of commits observed so far.
    pub fn total_observed(&self) -> u64 {
        self.metrics.commits_observed
    }

    /// Metrics snapshot.
    pub fn metrics(&self) -> &ObserverMetrics {
        &self.metrics
    }
}

impl CommitConsumer for ObserverService {
    fn process(&mut self, output: &LinearizedOutput) {
        self.metrics.commits_observed += 1;

        let proof = self.build_quorum_proof(output);
        if proof.is_quorum {
            self.metrics.commits_with_quorum += 1;
        } else {
            self.metrics.commits_without_quorum += 1;
        }

        let observed = ObservedCommit {
            output: output.clone(),
            quorum_proof: proof,
        };

        // Buffer for downstream polling.
        if self.recent_commits.len() >= self.max_recent {
            self.recent_commits.remove(0);
        }
        self.recent_commits.push(observed);
        self.metrics.commits_emitted += 1;
    }

    fn is_saturated(&self) -> bool {
        // Observer is never saturated — it's a passive consumer.
        false
    }

    fn on_finality(&mut self, _commit_index: u64, _leader: BlockRef) {
        // Observer doesn't need GC signals — it only retains recent commits.
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::{BlockDigest, BlockRef};

    fn make_output(index: u64, num_block_authors: u32) -> LinearizedOutput {
        let blocks: Vec<BlockRef> = (0..num_block_authors)
            .map(|a| BlockRef::new(index as u32, a, BlockDigest([index as u8; 32])))
            .collect();
        LinearizedOutput {
            commit_index: index,
            leader: blocks[0],
            transactions: vec![vec![index as u8]],
            blocks,
            timestamp_ms: 1000 + index,
            overflow_carryover: vec![],
            leader_state_root: None,
        }
    }

    // ── test: basic observation ───────────────────────────

    #[test]
    fn test_basic_observation() {
        let mut svc = ObserverService::new(7, 100); // 7 nodes, f=2, quorum=5

        // Commit with 5 block authors (= quorum)
        svc.process(&make_output(0, 5));

        assert_eq!(svc.total_observed(), 1);
        assert_eq!(svc.metrics().commits_with_quorum, 1);
        assert_eq!(svc.recent_commits().len(), 1);

        let observed = svc.latest_commit().unwrap();
        assert_eq!(observed.output.commit_index, 0);
        assert!(observed.quorum_proof.is_quorum);
        assert_eq!(observed.quorum_proof.endorsers.len(), 5);
    }

    // ── test: below quorum ───────────────────────────────

    #[test]
    fn test_below_quorum() {
        let mut svc = ObserverService::new(7, 100);

        // Commit with only 3 block authors (< quorum=5)
        svc.process(&make_output(0, 3));

        assert_eq!(svc.metrics().commits_without_quorum, 1);
        let observed = svc.latest_commit().unwrap();
        assert!(!observed.quorum_proof.is_quorum);
    }

    // ── test: sequential commits ─────────────────────────

    #[test]
    fn test_sequential_commits() {
        let mut svc = ObserverService::new(7, 100);

        for i in 0..10 {
            svc.process(&make_output(i, 7)); // full committee
        }

        assert_eq!(svc.total_observed(), 10);
        assert_eq!(svc.recent_commits().len(), 10);
        assert_eq!(svc.metrics().commits_with_quorum, 10);

        // Verify ordering
        for (i, commit) in svc.recent_commits().iter().enumerate() {
            assert_eq!(commit.output.commit_index, i as u64);
        }
    }

    // ── test: ring buffer eviction ───────────────────────

    #[test]
    fn test_ring_buffer_eviction() {
        let mut svc = ObserverService::new(7, 5); // max_recent=5

        for i in 0..10 {
            svc.process(&make_output(i, 7));
        }

        assert_eq!(svc.recent_commits().len(), 5);
        // Oldest should be commit index 5 (0-4 evicted)
        assert_eq!(svc.recent_commits()[0].output.commit_index, 5);
        assert_eq!(svc.recent_commits()[4].output.commit_index, 9);
    }

    // ── test: observer never saturated ───────────────────

    #[test]
    fn test_never_saturated() {
        let svc = ObserverService::new(7, 10);
        assert!(!svc.is_saturated());
    }

    // ── test: 21-node quorum proof ───────────────────────

    #[test]
    fn test_21_node_quorum() {
        let mut svc = ObserverService::new(21, 100); // f=6, quorum=15

        // 14 authors (< 15 quorum)
        svc.process(&make_output(0, 14));
        assert!(!svc.latest_commit().unwrap().quorum_proof.is_quorum);

        // 15 authors (= quorum)
        svc.process(&make_output(1, 15));
        assert!(svc.latest_commit().unwrap().quorum_proof.is_quorum);

        // 21 authors (full committee)
        svc.process(&make_output(2, 21));
        let proof = &svc.latest_commit().unwrap().quorum_proof;
        assert!(proof.is_quorum);
        assert_eq!(proof.endorser_stake, 21);
    }

    // ── test: CommitConsumer trait object ─────────────────

    #[test]
    fn test_as_commit_consumer_trait() {
        let mut consumer: Box<dyn CommitConsumer> =
            Box::new(ObserverService::new(7, 100));
        consumer.process(&make_output(0, 7));
        assert!(!consumer.is_saturated());
    }

    // ── test: quorum proof display ───────────────────────

    #[test]
    fn test_quorum_proof_display() {
        let proof = QuorumProof {
            commit_digest: CommitDigest([0; 32]),
            commit_index: 42,
            endorsers: vec![0, 1, 2, 3, 4],
            endorser_stake: 5,
            is_quorum: true,
        };
        let s = format!("{}", proof);
        assert!(s.contains("index=42"));
        assert!(s.contains("endorsers=5"));
        assert!(s.contains("quorum=true"));
    }
}
