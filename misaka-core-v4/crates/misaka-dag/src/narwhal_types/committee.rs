// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Committee types — authority set for Narwhal/Bullshark.
//!
//! Sui equivalent: consensus/types/committee.rs (~400 lines)

use super::block::AuthorityIndex;
use serde::{Deserialize, Serialize};

/// Stake weight.
pub type Stake = u64;

/// Authority information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    /// Human-readable hostname or address.
    pub hostname: String,
    /// Stake weight.
    pub stake: Stake,
    /// ML-DSA-65 public key (1952 bytes in production).
    pub public_key: Vec<u8>,
}

/// Committee — the set of authorities for an epoch.
///
/// Quorum = N - f where f = floor((N-1)/3).
/// Sui equivalent: `consensus/config/src/committee.rs:52`
///
/// This is strictly stronger than `ceil(2N/3)` when N is a multiple of 3,
/// ensuring `2Q - N > f` with margin (not just equality).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    /// Epoch number.
    pub epoch: u64,
    /// Ordered list of authorities (index = AuthorityIndex).
    pub authorities: Vec<Authority>,
}

impl Committee {
    /// Create a committee from a list of authorities.
    ///
    /// Task 0.1: Validates BFT invariants at construction time (release builds too).
    pub fn new(epoch: u64, authorities: Vec<Authority>) -> Self {
        assert!(
            !authorities.is_empty(),
            "committee must have at least one authority"
        );
        let c = Self { epoch, authorities };
        // Validate BFT invariant at construction — fail-fast if broken.
        let total = c.total_stake();
        assert!(total > 0, "committee total_stake must be > 0");
        let q = c.quorum_threshold(); // This assert!s internally
        let f = c.fault_tolerance();
        assert!(
            2u128 * q as u128 > total as u128 + f as u128,
            "BFT invariant violated at construction: 2*{q}={} <= {total}+{f}={}",
            2u128 * q as u128,
            total as u128 + f as u128
        );
        c
    }

    /// Create a committee with uniform stake (tests only).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(num_authorities: usize) -> Self {
        let authorities = (0..num_authorities)
            .map(|i| Authority {
                hostname: format!("validator-{}", i),
                stake: 1,
                public_key: vec![i as u8; 1952],
            })
            .collect();
        Self {
            epoch: 0,
            authorities,
        }
    }

    /// Create a committee with uniform stake for non-test code
    /// (e.g., during genesis when real keys are being loaded).
    ///
    /// SEC-FIX H-1: Routes through `new()` to enforce BFT invariants.
    pub fn new_uniform(epoch: u64, num_authorities: usize, public_keys: Vec<Vec<u8>>) -> Self {
        assert_eq!(
            public_keys.len(),
            num_authorities,
            "must provide exactly one public key per authority"
        );
        let authorities = public_keys
            .into_iter()
            .enumerate()
            .map(|(i, pk)| Authority {
                hostname: format!("validator-{}", i),
                stake: 1,
                public_key: pk,
            })
            .collect();
        Self::new(epoch, authorities)
    }

    /// Number of authorities.
    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Total stake (saturating to prevent overflow).
    pub fn total_stake(&self) -> Stake {
        self.authorities
            .iter()
            .fold(0u64, |acc, a| acc.saturating_add(a.stake))
    }

    /// Quorum threshold: `Q = N - f` where `f = floor((N-1)/3)`.
    ///
    /// Sui equivalent: `consensus/config/src/committee.rs:52`
    ///   `let fault_tolerance = (total_stake - 1) / 3;`
    ///   `let quorum_threshold = total_stake - fault_tolerance;`
    ///
    /// ## Why not `ceil(2N/3)`?
    ///
    /// `ceil(2N/3)` and `N - floor((N-1)/3)` differ when N is a multiple of 3:
    ///
    /// | N  | ceil(2N/3) | N-f (Sui) | f  | 2Q-N (overlap) | > f? |
    /// |----|------------|-----------|----|-----------------| -----|
    /// | 15 | 10         | **11**    | 4  | **1**→**7**     | ✓    |
    /// | 18 | 12         | **13**    | 5  | **1**→**8**     | ✓    |
    /// | 21 | 14         | **15**    | 6  | **7**→**9**     | ✓    |
    /// | 19 | 13         | 13        | 6  | 7               | ✓    |
    /// | 20 | 14         | 14        | 6  | 8               | ✓    |
    ///
    /// With `ceil(2N/3)`, N=21 gives Q=14, overlap=7 which exactly equals f+1.
    /// Under stake accounting rounding this margin evaporates.
    /// `N - f` gives Q=15, overlap=9, providing robust safety margin.
    ///
    /// ## Safety invariant
    ///
    /// `2 * quorum - total > fault_tolerance` (any two quorums share >f members)
    pub fn quorum_threshold(&self) -> Stake {
        let total = self.total_stake();
        // Defense-in-depth: empty committee must not panic.
        // Committee::new() already rejects empty input, but guard here too.
        if total == 0 {
            return 0;
        }
        // Sui formula: N - floor((N-1)/3)
        let f = self.fault_tolerance();
        let q = total - f;
        // Task 0.1: Safety invariant MUST hold in ALL builds (not just debug).
        // Two quorums must share > f members. This is the core BFT safety guarantee.
        // SEC-FIX H-1: Use u128 to prevent overflow when total_stake is large.
        assert!(
            2u128 * q as u128 > total as u128 + f as u128,
            "BFT safety invariant violated: 2*{q} = {} <= {total} + {f} = {}",
            2u128 * q as u128,
            total as u128 + f as u128
        );
        q
    }

    /// Maximum number of Byzantine faults tolerated (stake-weighted).
    ///
    /// `f = floor((total_stake - 1) / 3)`
    ///
    /// Sui equivalent: `(total_stake - 1) / 3`
    pub fn fault_tolerance(&self) -> Stake {
        let total = self.total_stake();
        if total == 0 {
            return 0;
        }
        (total - 1) / 3
    }

    /// Validity threshold (f+1): minimum votes to guarantee at least one honest.
    pub fn validity_threshold(&self) -> Stake {
        self.fault_tolerance() + 1
    }

    /// Maximum number of Byzantine faults tolerated (count, not stake-weighted).
    pub fn max_faults(&self) -> usize {
        (self.size() - 1) / 3
    }

    /// Check if a set of stakes reaches quorum.
    ///
    /// Phase 1 fix: empty committee (threshold=0) always returns false.
    /// Nothing can reach quorum in a committee with no members.
    pub fn reached_quorum(&self, stake: Stake) -> bool {
        let threshold = self.quorum_threshold();
        if threshold == 0 {
            return false;
        }
        stake >= threshold
    }

    /// Check if a set of stakes reaches validity threshold.
    pub fn reached_validity(&self, stake: Stake) -> bool {
        stake >= self.validity_threshold()
    }

    /// Get authority by index.
    pub fn authority(&self, index: AuthorityIndex) -> Option<&Authority> {
        self.authorities.get(index as usize)
    }

    /// Get stake for an authority.
    pub fn stake(&self, index: AuthorityIndex) -> Stake {
        self.authorities
            .get(index as usize)
            .map(|a| a.stake)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Quorum formula: Q = N - floor((N-1)/3), matching Sui ──
    //
    // N=15: f=4, Q=11  (old: 10)
    // N=18: f=5, Q=13  (old: 12)
    // N=21: f=6, Q=15  (old: 14)
    // N=19: f=6, Q=13  (same)
    // N=20: f=6, Q=14  (same)

    #[test]
    fn test_sr15_quorum() {
        let c = Committee::new_for_test(15);
        assert_eq!(c.fault_tolerance(), 4); // floor(14/3) = 4
        assert_eq!(c.quorum_threshold(), 11); // 15 - 4 = 11
        assert_eq!(c.validity_threshold(), 5); // f+1 = 5
        assert_eq!(c.max_faults(), 4);
    }

    #[test]
    fn test_sr18_quorum() {
        let c = Committee::new_for_test(18);
        assert_eq!(c.fault_tolerance(), 5); // floor(17/3) = 5
        assert_eq!(c.quorum_threshold(), 13); // 18 - 5 = 13
    }

    #[test]
    fn test_sr21_quorum() {
        let c = Committee::new_for_test(21);
        assert_eq!(c.fault_tolerance(), 6); // floor(20/3) = 6
        assert_eq!(c.quorum_threshold(), 15); // 21 - 6 = 15
    }

    #[test]
    fn test_n4_quorum() {
        // n=4: f=1, Q=3 (unchanged from old formula)
        let c = Committee::new_for_test(4);
        assert_eq!(c.fault_tolerance(), 1);
        assert_eq!(c.quorum_threshold(), 3);
    }

    #[test]
    fn test_n7_quorum() {
        // n=7: f=2, Q=5 (unchanged)
        let c = Committee::new_for_test(7);
        assert_eq!(c.fault_tolerance(), 2);
        assert_eq!(c.quorum_threshold(), 5);
    }

    #[test]
    fn test_n10_quorum() {
        // n=10: f=3, Q=7 (unchanged)
        let c = Committee::new_for_test(10);
        assert_eq!(c.fault_tolerance(), 3);
        assert_eq!(c.quorum_threshold(), 7);
    }

    #[test]
    fn test_n1_quorum() {
        // n=1: f=0, Q=1
        let c = Committee::new_for_test(1);
        assert_eq!(c.fault_tolerance(), 0);
        assert_eq!(c.quorum_threshold(), 1);
    }

    #[test]
    fn test_non_multiple_of_3() {
        // n=19: f=6, Q=13 (same as old ceil(2*19/3) = 13)
        let c = Committee::new_for_test(19);
        assert_eq!(c.fault_tolerance(), 6);
        assert_eq!(c.quorum_threshold(), 13);

        // n=20: f=6, Q=14 (same as old ceil(2*20/3) = 14)
        let c = Committee::new_for_test(20);
        assert_eq!(c.fault_tolerance(), 6);
        assert_eq!(c.quorum_threshold(), 14);
    }

    /// Verify the safety invariant for all committee sizes 1..100.
    #[test]
    fn test_safety_invariant_exhaustive() {
        for n in 1..=100usize {
            let c = Committee::new_for_test(n);
            let q = c.quorum_threshold();
            let f = c.fault_tolerance();
            let total = c.total_stake();
            // 2Q - N > f  (any two quorums share > f members)
            assert!(
                2u128 * q as u128 > total as u128 + f as u128,
                "safety invariant violated at N={n}: 2*{q}={} <= {total}+{f}={}",
                2u128 * q as u128,
                total as u128 + f as u128
            );
        }
    }

    #[test]
    fn test_reached_quorum() {
        let c = Committee::new_for_test(15);
        // Q=11 now (was 10)
        assert!(!c.reached_quorum(10));
        assert!(c.reached_quorum(11));
        assert!(c.reached_quorum(15));
    }

    #[test]
    fn test_committee_accessors() {
        let c = Committee::new_for_test(3);
        assert_eq!(c.size(), 3);
        assert_eq!(c.total_stake(), 3);
        assert_eq!(c.stake(0), 1);
        assert_eq!(c.stake(99), 0);
        assert!(c.authority(0).is_some());
        assert!(c.authority(3).is_none());
    }

    /// Task 0.1: Exhaustive BFT invariant verification for N=1..=100.
    /// Guarantees quorum_threshold satisfies 2Q > N + f for all committee sizes.
    #[test]
    fn quorum_invariant_holds_for_n_in_1_to_100() {
        for n in 1..=100usize {
            let c = Committee::new_for_test(n);
            let total = c.total_stake();
            let q = c.quorum_threshold();
            let f = c.fault_tolerance();

            assert_eq!(total, n as u64, "N={n}: total_stake mismatch");
            assert_eq!(f, (n as u64 - 1) / 3, "N={n}: fault_tolerance mismatch");
            assert_eq!(q, total - f, "N={n}: quorum = total - f");
            assert!(
                2u128 * q as u128 > total as u128 + f as u128,
                "N={n}: BFT safety invariant violated: 2*{q}={} <= {total}+{f}={}",
                2u128 * q as u128,
                total as u128 + f as u128
            );
            // Additionally verify validity threshold
            assert!(
                c.validity_threshold() == f + 1,
                "N={n}: validity_threshold should be f+1"
            );
        }
    }
}
