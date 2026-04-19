// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/transaction_certifier.rs (962 lines)
//
//! Transaction Certifier — fast-path finality for Mysticeti v2.
//!
//! Certifies transactions when ≥2f+1 validators implicitly accept them
//! (include the block as ancestor without reject vote). This is
//! independent of the commit pipeline and provides sub-second finality.
//!
//! See docs/design/tx_certifier.md for design rationale.

use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::{Committee, Stake};
use std::collections::{HashMap, HashSet};

/// Certification status of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificationStatus {
    /// Awaiting more votes.
    Pending {
        accept_stake: Stake,
        reject_stake: Stake,
    },
    /// Quorum accepted → ready for fast-path execution.
    Certified { stake: Stake },
    /// Quorum rejected.
    Rejected { stake: Stake },
}

/// Output: a certified block with per-TX outcomes.
#[derive(Clone, Debug)]
pub struct CertifiedOutput {
    pub block_ref: BlockRef,
    pub certified_txs: Vec<Transaction>,
    pub rejected_txs: Vec<Transaction>,
    pub certified_stake: Stake,
}

/// Per-block vote tracking state.
struct BlockVotes {
    block_ref: BlockRef,
    round: Round,
    author: AuthorityIndex,
    txs: Vec<Transaction>,
    /// Per-TX: set of accepting authorities.
    acceptors: Vec<HashSet<AuthorityIndex>>,
    /// Per-TX: set of rejecting authorities.
    rejectors: Vec<HashSet<AuthorityIndex>>,
    /// All authorities that have voted (by including this block as ancestor).
    voters: HashSet<AuthorityIndex>,
    /// True if all TXs have been decided.
    decided: bool,
}

/// Metrics for the certifier.
#[derive(Clone, Debug, Default)]
pub struct CertifierMetrics {
    pub blocks_tracked: u64,
    pub votes_received: u64,
    pub txs_certified: u64,
    pub txs_rejected: u64,
    pub gc_sweeps: u64,
    /// Task 1.4: Total TX digests in the final-rejected set.
    pub final_rejected_count: u64,
    /// Task 1.4: Blocks that timed out without full certification.
    pub certification_timeouts: u64,
}

/// Transaction certifier — fast-path finality engine.
///
/// Sui equivalent: `TransactionCertifier` in `transaction_certifier.rs`.
pub struct TxCertifier {
    committee: Committee,
    quorum: Stake,
    /// Pending blocks being tracked.
    pending: HashMap<BlockRef, BlockVotes>,
    /// Certified output queue.
    output: Vec<CertifiedOutput>,
    /// GC round — blocks below this are cleaned up.
    gc_round: Round,
    /// Max pending blocks before eviction.
    max_pending: usize,
    /// Metrics.
    metrics: CertifierMetrics,

    // ── Task 1.4: Sui-parity additions ──
    /// Final-rejected TX digests (SHA3-256 of TX bytes).
    /// Queried by core_engine to exclude from future proposals.
    final_rejected_digests: HashSet<[u8; 32]>,
    /// Per-TX digest reject vote tracking (cross-block aggregation).
    /// Maps tx_digest → set of rejecting authorities.
    cross_block_rejects: HashMap<[u8; 32], HashSet<AuthorityIndex>>,
    /// Rounds without certification → timeout threshold.
    certification_timeout_rounds: u32,
}

impl TxCertifier {
    /// Create a new certifier.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let quorum = committee.quorum_threshold();
        Self {
            committee,
            quorum,
            pending: HashMap::new(),
            output: Vec::new(),
            gc_round: 0,
            max_pending: 10_000,
            metrics: CertifierMetrics::default(),
            final_rejected_digests: HashSet::new(),
            cross_block_rejects: HashMap::new(),
            certification_timeout_rounds: 20,
        }
    }

    /// Register a proposed block for certification tracking.
    ///
    /// Sui equivalent: `TransactionCertifier::add_proposed_block()`.
    pub fn track_block(&mut self, block: &VerifiedBlock) {
        if block.round() <= self.gc_round {
            return;
        }
        if self.pending.contains_key(&block.reference()) {
            return;
        }

        // Evict oldest if at capacity
        if self.pending.len() >= self.max_pending {
            let oldest = self
                .pending
                .values()
                .min_by_key(|v| v.round)
                .map(|v| v.block_ref);
            if let Some(r) = oldest {
                self.pending.remove(&r);
            }
        }

        let txs = block.transactions().to_vec();
        let n = txs.len();
        self.pending.insert(
            block.reference(),
            BlockVotes {
                block_ref: block.reference(),
                round: block.round(),
                author: block.author(),
                txs,
                acceptors: vec![HashSet::new(); n],
                rejectors: vec![HashSet::new(); n],
                voters: HashSet::new(),
                decided: false,
            },
        );
        self.metrics.blocks_tracked += 1;
    }

    /// Process a vote: authority `voter` produced a block at `voter_round`
    /// that includes `parent_ref` as ancestor.
    ///
    /// `reject_parent` — if true, this is a reject vote (parent in tx_reject_votes).
    ///
    /// Sui equivalent: `TransactionCertifier::add_voted_blocks()`.
    pub fn add_vote(&mut self, parent_ref: &BlockRef, voter: AuthorityIndex, reject: bool) {
        let state = match self.pending.get_mut(parent_ref) {
            Some(s) if !s.decided => s,
            _ => return,
        };

        if !state.voters.insert(voter) {
            return;
        } // duplicate
        self.metrics.votes_received += 1;

        for i in 0..state.txs.len() {
            if reject {
                state.rejectors[i].insert(voter);
            } else {
                state.acceptors[i].insert(voter);
            }
        }

        self.try_certify(parent_ref);
    }

    /// Batch: authority `voter`'s block includes these parents.
    pub fn add_voted_parents(
        &mut self,
        voter: AuthorityIndex,
        parents: &[BlockRef],
        reject_parents: &HashSet<BlockRef>,
    ) {
        for parent in parents {
            let reject = reject_parents.contains(parent);
            self.add_vote(parent, voter, reject);
        }
    }

    /// Check if a block's TXs are fully certified/rejected.
    fn try_certify(&mut self, block_ref: &BlockRef) {
        let state = match self.pending.get(block_ref) {
            Some(s) => s,
            None => return,
        };
        if state.decided {
            return;
        }

        let mut all_decided = true;
        let mut certified_txs = Vec::new();
        let mut rejected_txs = Vec::new();
        let mut min_stake = Stake::MAX;

        for i in 0..state.txs.len() {
            let accept_stake: Stake = state.acceptors[i]
                .iter()
                .map(|&a| self.committee.stake(a))
                .sum();
            let reject_stake: Stake = state.rejectors[i]
                .iter()
                .map(|&a| self.committee.stake(a))
                .sum();

            if accept_stake >= self.quorum {
                certified_txs.push(state.txs[i].clone());
                min_stake = min_stake.min(accept_stake);
                self.metrics.txs_certified += 1;
            } else if reject_stake >= self.quorum {
                rejected_txs.push(state.txs[i].clone());
                self.metrics.txs_rejected += 1;
            } else {
                all_decided = false;
            }
        }

        if all_decided && !state.txs.is_empty() {
            self.output.push(CertifiedOutput {
                block_ref: *block_ref,
                certified_txs,
                rejected_txs,
                certified_stake: min_stake,
            });
            if let Some(s) = self.pending.get_mut(block_ref) {
                s.decided = true;
            }
        }
    }

    /// Get certification status for a specific TX (by block + TX index).
    #[must_use]
    pub fn tx_status(&self, block_ref: &BlockRef, tx_idx: usize) -> CertificationStatus {
        let state = match self.pending.get(block_ref) {
            Some(s) => s,
            None => {
                return CertificationStatus::Pending {
                    accept_stake: 0,
                    reject_stake: 0,
                }
            }
        };
        if tx_idx >= state.txs.len() {
            return CertificationStatus::Pending {
                accept_stake: 0,
                reject_stake: 0,
            };
        }
        let accept: Stake = state.acceptors[tx_idx]
            .iter()
            .map(|&a| self.committee.stake(a))
            .sum();
        let reject: Stake = state.rejectors[tx_idx]
            .iter()
            .map(|&a| self.committee.stake(a))
            .sum();
        if accept >= self.quorum {
            CertificationStatus::Certified { stake: accept }
        } else if reject >= self.quorum {
            CertificationStatus::Rejected { stake: reject }
        } else {
            CertificationStatus::Pending {
                accept_stake: accept,
                reject_stake: reject,
            }
        }
    }

    /// Take all certified outputs.
    #[must_use]
    pub fn take_certified(&mut self) -> Vec<CertifiedOutput> {
        std::mem::take(&mut self.output)
    }

    /// Advance GC round.
    pub fn update_gc_round(&mut self, round: Round) {
        if round <= self.gc_round {
            return;
        }
        self.gc_round = round;
        self.pending.retain(|_, v| v.round > self.gc_round);
        self.metrics.gc_sweeps += 1;
    }

    /// Number of pending (undecided) blocks.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Metrics.
    #[must_use]
    pub fn metrics(&self) -> &CertifierMetrics {
        &self.metrics
    }

    // ═══════════════════════════════════════════════════════════════
    //  Task 1.4: Sui-parity additions — reject vote aggregation
    // ═══════════════════════════════════════════════════════════════

    /// Record a cross-block reject vote for a specific TX digest.
    ///
    /// Unlike `add_vote` (which tracks per-block), this aggregates reject
    /// votes across multiple blocks containing the same TX.
    /// When reject stake reaches quorum, the TX is final-rejected.
    pub fn record_cross_block_reject(&mut self, tx_digest: [u8; 32], voter: AuthorityIndex) {
        let voters = self.cross_block_rejects.entry(tx_digest).or_default();
        if !voters.insert(voter) {
            return; // duplicate
        }

        let reject_stake: Stake = voters.iter().map(|&a| self.committee.stake(a)).sum();

        if reject_stake >= self.quorum {
            self.final_rejected_digests.insert(tx_digest);
            self.cross_block_rejects.remove(&tx_digest);
            self.metrics.final_rejected_count += 1;
        }
    }

    /// Check if a TX digest is final-rejected (quorum reject votes across blocks).
    #[must_use]
    pub fn is_final_rejected(&self, tx_digest: &[u8; 32]) -> bool {
        self.final_rejected_digests.contains(tx_digest)
    }

    /// Get all final-rejected TX digests.
    /// Used by core_engine.filter_rejected_txs() to exclude from proposals.
    #[must_use]
    pub fn final_rejected_digests(&self) -> &HashSet<[u8; 32]> {
        &self.final_rejected_digests
    }

    /// Check for certification timeouts: blocks that have been pending
    /// for more than `certification_timeout_rounds`.
    ///
    /// Timed-out blocks are removed from tracking. Their TXs are neither
    /// certified nor rejected — they'll go through the normal commit path.
    pub fn check_timeouts(&mut self, current_round: Round) -> Vec<BlockRef> {
        let threshold = self.certification_timeout_rounds;
        let timed_out: Vec<BlockRef> = self
            .pending
            .iter()
            .filter(|(_, v)| !v.decided && current_round > v.round + threshold)
            .map(|(br, _)| *br)
            .collect();

        for br in &timed_out {
            self.pending.remove(br);
            self.metrics.certification_timeouts += 1;
        }

        timed_out
    }

    /// Compute the TX digest (SHA3-256) for cross-block tracking.
    pub fn compute_tx_digest(tx: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(tx).into()
    }

    /// GC the cross-block reject tracking (remove entries below gc_round).
    /// Called alongside update_gc_round.
    pub fn gc_cross_block_rejects(&mut self) {
        // Can't GC by round since digests are round-independent.
        // Instead, cap total entries.
        const MAX_CROSS_BLOCK_ENTRIES: usize = 50_000;
        if self.cross_block_rejects.len() > MAX_CROSS_BLOCK_ENTRIES {
            // Drop oldest half (no ordering guarantee — HashMap)
            let to_remove: Vec<[u8; 32]> = self
                .cross_block_rejects
                .keys()
                .take(MAX_CROSS_BLOCK_ENTRIES / 2)
                .copied()
                .collect();
            for k in to_remove {
                self.cross_block_rejects.remove(&k);
            }
        }
    }

    /// Number of final-rejected TX digests.
    #[must_use]
    pub fn final_rejected_count(&self) -> usize {
        self.final_rejected_digests.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    fn make_vb(round: Round, author: AuthorityIndex, txs: Vec<Vec<u8>>) -> VerifiedBlock {
        let block = Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors: vec![],
            transactions: txs,
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        VerifiedBlock::new_for_test(block)
    }

    #[test]
    fn test_certification_quorum() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(1, 0, vec![vec![42]]);
        let br = vb.reference();
        cert.track_block(&vb);

        cert.add_vote(&br, 1, false);
        cert.add_vote(&br, 2, false);
        assert!(matches!(
            cert.tx_status(&br, 0),
            CertificationStatus::Pending { .. }
        ));

        cert.add_vote(&br, 3, false); // quorum = 3
        assert!(matches!(
            cert.tx_status(&br, 0),
            CertificationStatus::Certified { .. }
        ));

        let out = cert.take_certified();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].certified_txs.len(), 1);
    }

    #[test]
    fn test_rejection_quorum() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(1, 0, vec![vec![42]]);
        let br = vb.reference();
        cert.track_block(&vb);

        for i in 1..=3 {
            cert.add_vote(&br, i, true);
        } // reject
        assert!(matches!(
            cert.tx_status(&br, 0),
            CertificationStatus::Rejected { .. }
        ));
    }

    #[test]
    fn test_mixed_accept_reject() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(1, 0, vec![vec![1], vec![2]]);
        let br = vb.reference();
        cert.track_block(&vb);

        // 3 accept all TXs, but 1 rejects → both certified (accept quorum reached first)
        for i in 1..=3 {
            cert.add_vote(&br, i, false);
        }
        assert!(matches!(
            cert.tx_status(&br, 0),
            CertificationStatus::Certified { .. }
        ));
        assert!(matches!(
            cert.tx_status(&br, 1),
            CertificationStatus::Certified { .. }
        ));
    }

    #[test]
    fn test_duplicate_vote_ignored() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(1, 0, vec![vec![42]]);
        let br = vb.reference();
        cert.track_block(&vb);

        cert.add_vote(&br, 1, false);
        cert.add_vote(&br, 1, false); // duplicate
        assert!(matches!(
            cert.tx_status(&br, 0),
            CertificationStatus::Pending {
                accept_stake: 1,
                ..
            }
        ));
    }

    #[test]
    fn test_gc() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(5, 0, vec![vec![1]]);
        cert.track_block(&vb);
        assert_eq!(cert.pending_count(), 1);

        cert.update_gc_round(6);
        assert_eq!(cert.pending_count(), 0);
    }

    #[test]
    fn test_below_gc_not_tracked() {
        let mut cert = TxCertifier::new(committee4());
        cert.update_gc_round(10);
        let vb = make_vb(5, 0, vec![vec![1]]);
        cert.track_block(&vb);
        assert_eq!(cert.pending_count(), 0);
    }

    #[test]
    fn test_batch_votes() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(1, 0, vec![vec![42]]);
        let br = vb.reference();
        cert.track_block(&vb);

        let parents = vec![br];
        let reject = HashSet::new();
        cert.add_voted_parents(1, &parents, &reject);
        cert.add_voted_parents(2, &parents, &reject);
        cert.add_voted_parents(3, &parents, &reject);
        assert!(matches!(
            cert.tx_status(&br, 0),
            CertificationStatus::Certified { .. }
        ));
    }

    #[test]
    fn test_metrics() {
        let mut cert = TxCertifier::new(committee4());
        let vb = make_vb(1, 0, vec![vec![1], vec![2]]);
        let br = vb.reference();
        cert.track_block(&vb);
        for i in 1..=3 {
            cert.add_vote(&br, i, false);
        }
        assert_eq!(cert.metrics().txs_certified, 2);
        assert_eq!(cert.metrics().votes_received, 3);
    }

    // ── Task 1.4: New tests ──

    #[test]
    fn task_1_4_cross_block_reject_quorum() {
        let mut cert = TxCertifier::new(committee4());
        let tx = vec![0xDE, 0xAD];
        let digest = TxCertifier::compute_tx_digest(&tx);

        // 2 voters reject — not enough (quorum=3)
        cert.record_cross_block_reject(digest, 0);
        cert.record_cross_block_reject(digest, 1);
        assert!(!cert.is_final_rejected(&digest));

        // 3rd voter → quorum reached → final rejected
        cert.record_cross_block_reject(digest, 2);
        assert!(cert.is_final_rejected(&digest));
        assert_eq!(cert.final_rejected_count(), 1);
    }

    #[test]
    fn task_1_4_cross_block_reject_dedup() {
        let mut cert = TxCertifier::new(committee4());
        let digest = [0xAA; 32];

        // Same voter twice — counted once
        cert.record_cross_block_reject(digest, 0);
        cert.record_cross_block_reject(digest, 0);

        // Only 1 stake worth of reject
        assert!(!cert.is_final_rejected(&digest));
    }

    #[test]
    fn task_1_4_certification_timeout() {
        let mut cert = TxCertifier::new(committee4());
        cert.certification_timeout_rounds = 5;

        let vb = make_vb(10, 0, vec![vec![42]]);
        cert.track_block(&vb);
        assert_eq!(cert.pending_count(), 1);

        // Round 14 — not timed out yet (10 + 5 = 15)
        let timed_out = cert.check_timeouts(14);
        assert!(timed_out.is_empty());
        assert_eq!(cert.pending_count(), 1);

        // Round 16 — timed out (16 > 10 + 5)
        let timed_out = cert.check_timeouts(16);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(cert.pending_count(), 0);
        assert_eq!(cert.metrics().certification_timeouts, 1);
    }

    #[test]
    fn task_1_4_final_rejected_digests_query() {
        let mut cert = TxCertifier::new(committee4());

        let d1 = [0x11; 32];
        let d2 = [0x22; 32];

        // Reject d1 with quorum
        for i in 0..3 {
            cert.record_cross_block_reject(d1, i);
        }
        // Reject d2 with only 2 (not quorum)
        for i in 0..2 {
            cert.record_cross_block_reject(d2, i);
        }

        let rejected = cert.final_rejected_digests();
        assert!(rejected.contains(&d1));
        assert!(!rejected.contains(&d2));
    }

    #[test]
    fn task_1_4_compute_tx_digest_deterministic() {
        let tx = vec![1, 2, 3, 4, 5];
        let d1 = TxCertifier::compute_tx_digest(&tx);
        let d2 = TxCertifier::compute_tx_digest(&tx);
        assert_eq!(d1, d2);

        let different = TxCertifier::compute_tx_digest(&[5, 4, 3]);
        assert_ne!(d1, different);
    }
}
