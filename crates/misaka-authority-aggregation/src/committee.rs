// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `StakeCommittee` trait — generic authority set abstraction.
//!
//! Decouples quorum aggregation from the concrete Committee types in
//! misaka-dag and misaka-consensus. Both can implement this via a thin adapter.

/// Authority identifier within a committee (0-based index).
/// Mirrors `misaka_types::equivocation::AuthorityIndex`.
pub type AuthorityIndex = u32;

/// Stake weight type. Uses `u128` to accommodate both misaka-dag (`Stake = u64`)
/// and misaka-consensus `ValidatorSet` (`stake_weight: u128`).
pub type StakeWeight = u128;

/// Trait abstracting over authority sets with stake-weighted quorum.
///
/// Both `misaka_dag::Committee` (via adapter widening u64→u128) and
/// `misaka_consensus::ValidatorSet` can implement this.
pub trait StakeCommittee: Send + Sync {
    /// Number of authorities in the committee.
    fn size(&self) -> usize;

    /// Stake weight for authority at `index`. Returns 0 for out-of-range.
    fn stake(&self, index: AuthorityIndex) -> StakeWeight;

    /// Total stake across all authorities (saturating arithmetic).
    fn total_stake(&self) -> StakeWeight;

    /// Quorum threshold: the minimum stake for a quorum decision.
    /// BFT formula: `N - floor((N-1)/3)` (Sui-compatible).
    fn quorum_threshold(&self) -> StakeWeight;

    /// Fault tolerance: maximum Byzantine stake tolerated.
    /// Typically `floor((total_stake - 1) / 3)`.
    fn fault_tolerance(&self) -> StakeWeight;

    /// All authority indices `0..size()`.
    fn authority_indices(&self) -> Box<dyn Iterator<Item = AuthorityIndex> + '_> {
        Box::new(0..self.size() as AuthorityIndex)
    }
}

/// A simple `Vec<StakeWeight>` committee for testing.
///
/// Uses BFT formula: `f = (total-1)/3`, `Q = total - f`.
#[derive(Debug, Clone)]
pub struct SimpleStakeCommittee {
    stakes: Vec<StakeWeight>,
    total: StakeWeight,
    quorum: StakeWeight,
    fault_tol: StakeWeight,
}

impl SimpleStakeCommittee {
    /// Create from a list of stake weights.
    pub fn new(stakes: Vec<StakeWeight>) -> Self {
        let total: StakeWeight = stakes.iter().copied().sum();
        let fault_tol = if total == 0 { 0 } else { (total - 1) / 3 };
        let quorum = total.saturating_sub(fault_tol);
        Self {
            stakes,
            total,
            quorum,
            fault_tol,
        }
    }

    /// Create a uniform committee: `n` authorities each with `stake_per`.
    pub fn uniform(n: usize, stake_per: StakeWeight) -> Self {
        Self::new(vec![stake_per; n])
    }
}

impl StakeCommittee for SimpleStakeCommittee {
    fn size(&self) -> usize {
        self.stakes.len()
    }

    fn stake(&self, index: AuthorityIndex) -> StakeWeight {
        self.stakes.get(index as usize).copied().unwrap_or(0)
    }

    fn total_stake(&self) -> StakeWeight {
        self.total
    }

    fn quorum_threshold(&self) -> StakeWeight {
        self.quorum
    }

    fn fault_tolerance(&self) -> StakeWeight {
        self.fault_tol
    }
}
