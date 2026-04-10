//! MEV Policy Enforcement — Transaction Ordering + Anti-Frontrunning.
//!
//! # Problem
//!
//! In a privacy-focused chain, MEV takes different forms than on Ethereum:
//! - Amounts are hidden (BDLOP commitments) → no sandwich attacks on amounts
//! - Sender/receiver are hidden (ML-DSA signatures) → no address-based frontrunning
//! - BUT: fee-based priority ordering can still be manipulated
//! - AND: spend-tag observation can leak timing information
//!
//! # MISAKA Anti-MEV Design
//!
//! 1. **Deterministic ordering**: TXs in a block are ordered by a canonical
//!    sort (fee desc → tx_hash asc), not by proposer-chosen order.
//!    This prevents proposers from reordering for personal gain.
//!
//! 2. **Fee cap enforcement**: TXs with fees > `MAX_FEE_MULTIPLIER × median_fee`
//!    are flagged as potential frontrunners. Proposers may include them but
//!    the anomaly is logged for monitoring.
//!
//! 3. **SpendTag timing protection**: The mempool does not reveal which
//!    spent_tags are pending to RPC queries. Only confirmed spent_tags
//!    (in finalized blocks) are visible.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Maximum fee multiplier over median before flagging.
/// A TX paying >10× the median fee is suspicious.
pub const MAX_FEE_MULTIPLIER: u64 = 10;

/// Minimum number of TXs needed to compute meaningful fee statistics.
pub const MIN_FEE_SAMPLE_SIZE: usize = 5;

// ═══════════════════════════════════════════════════════════════
//  MEV Score
// ═══════════════════════════════════════════════════════════════

/// MEV risk assessment for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevAssessment {
    pub tx_hash: [u8; 32],
    /// Fee anomaly score: 0.0 = normal, 1.0 = extreme outlier.
    pub fee_anomaly: f64,
    /// Whether this TX's fee exceeds the frontrun threshold.
    pub frontrun_flagged: bool,
    /// Canonical position in the block (lower = higher priority).
    pub canonical_position: usize,
}

/// Compute fee anomaly score using integer-safe comparison.
///
/// Returns a value in [0.0, 1.0]:
/// - 0.0: fee ≤ 2× median (normal)
/// - 0.5: fee = 5× median (elevated)
/// - 1.0: fee ≥ 10× median (extreme)
pub fn fee_anomaly_score(tx_fee: u64, median_fee: u64) -> f64 {
    // SEC-FIX NM-17: saturating_mul to prevent u64 overflow when median_fee is large
    if median_fee == 0 || tx_fee <= median_fee.saturating_mul(2) {
        return 0.0;
    }
    let ratio = tx_fee as f64 / median_fee as f64;
    let score = (ratio - 2.0) / (MAX_FEE_MULTIPLIER as f64 - 2.0);
    score.min(1.0).max(0.0)
}

/// Check if a TX fee exceeds the frontrun threshold.
pub fn is_frontrun_candidate(tx_fee: u64, median_fee: u64) -> bool {
    if median_fee == 0 {
        return false;
    }
    tx_fee > median_fee.saturating_mul(MAX_FEE_MULTIPLIER)
}

// ═══════════════════════════════════════════════════════════════
//  Canonical TX Ordering
// ═══════════════════════════════════════════════════════════════

/// Sort key for deterministic transaction ordering within a block.
///
/// Order: highest fee first, then by tx_hash ascending (deterministic tiebreak).
/// This ordering is consensus-critical — all validators MUST produce the
/// same block-level TX sequence for the same TX set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSortKey {
    /// Negated fee (for descending sort: higher fee = lower sort key).
    pub neg_fee: i64,
    /// TX hash (ascending tiebreak).
    pub tx_hash: [u8; 32],
}

impl Ord for TxSortKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.neg_fee
            .cmp(&other.neg_fee)
            .then_with(|| self.tx_hash.cmp(&other.tx_hash))
    }
}

impl PartialOrd for TxSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TxSortKey {
    pub fn new(fee: u64, tx_hash: [u8; 32]) -> Self {
        // SEC-FIX H-11: Saturating negate to prevent i64 overflow.
        // fee > i64::MAX would wrap to a positive neg_fee, reversing sort order.
        let clamped = fee.min(i64::MAX as u64);
        Self {
            neg_fee: -(clamped as i64),
            tx_hash,
        }
    }
}

/// Sort transactions in canonical block order.
///
/// This is a consensus-critical function: all validators MUST use this
/// exact ordering. Non-deterministic ordering = consensus failure.
pub fn canonical_tx_order(txs: &mut [(u64, [u8; 32])]) {
    txs.sort_by(|a, b| {
        let ka = TxSortKey::new(a.0, a.1);
        let kb = TxSortKey::new(b.0, b.1);
        ka.cmp(&kb)
    });
}

// ═══════════════════════════════════════════════════════════════
//  Block-Level MEV Analysis
// ═══════════════════════════════════════════════════════════════

/// Analyze all transactions in a candidate block for MEV anomalies.
///
/// Returns assessments for each TX plus the median fee.
pub fn analyze_block_mev(tx_fees_and_hashes: &[(u64, [u8; 32])]) -> (Vec<MevAssessment>, u64) {
    if tx_fees_and_hashes.is_empty() {
        return (vec![], 0);
    }

    // Compute median fee
    let mut fees: Vec<u64> = tx_fees_and_hashes.iter().map(|(f, _)| *f).collect();
    fees.sort();
    let median_fee = fees[fees.len() / 2];

    // Canonical sort order
    let mut sorted = tx_fees_and_hashes.to_vec();
    canonical_tx_order(&mut sorted);

    let assessments = sorted
        .iter()
        .enumerate()
        .map(|(pos, (fee, hash))| MevAssessment {
            tx_hash: *hash,
            fee_anomaly: fee_anomaly_score(*fee, median_fee),
            frontrun_flagged: is_frontrun_candidate(*fee, median_fee),
            canonical_position: pos,
        })
        .collect();

    (assessments, median_fee)
}

/// Compute deterministic block ordering hash for audit trail.
///
/// Validators can independently verify that a proposer used the
/// canonical ordering by checking this hash.
pub fn canonical_ordering_hash(tx_hashes_in_order: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:canonical_tx_order:v1:");
    h.update((tx_hashes_in_order.len() as u64).to_le_bytes());
    for hash in tx_hashes_in_order {
        h.update(hash);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_anomaly_normal() {
        assert_eq!(fee_anomaly_score(100, 100), 0.0);
        assert_eq!(fee_anomaly_score(200, 100), 0.0); // 2× is normal
    }

    #[test]
    fn test_fee_anomaly_elevated() {
        let score = fee_anomaly_score(500, 100); // 5×
        assert!(score > 0.3 && score < 0.5);
    }

    #[test]
    fn test_fee_anomaly_extreme() {
        let score = fee_anomaly_score(1000, 100); // 10×
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_fee_anomaly_zero_median() {
        assert_eq!(fee_anomaly_score(1000, 0), 0.0);
    }

    #[test]
    fn test_frontrun_detection() {
        assert!(!is_frontrun_candidate(100, 100));
        assert!(!is_frontrun_candidate(999, 100));
        assert!(is_frontrun_candidate(1001, 100));
    }

    #[test]
    fn test_canonical_ordering_deterministic() {
        let mut txs = vec![
            (100, [1u8; 32]),
            (500, [2u8; 32]),
            (100, [3u8; 32]),
            (200, [4u8; 32]),
        ];
        canonical_tx_order(&mut txs);

        // Highest fee first
        assert_eq!(txs[0].0, 500);
        assert_eq!(txs[1].0, 200);
        // Same fee → lower hash first
        assert_eq!(txs[2].0, 100);
        assert_eq!(txs[2].1, [1u8; 32]);
        assert_eq!(txs[3].1, [3u8; 32]);
    }

    #[test]
    fn test_canonical_ordering_hash() {
        let order1 = vec![[1u8; 32], [2u8; 32]];
        let order2 = vec![[2u8; 32], [1u8; 32]];

        let h1 = canonical_ordering_hash(&order1);
        let h2 = canonical_ordering_hash(&order2);

        assert_ne!(h1, h2); // Different orderings → different hashes
    }

    #[test]
    fn test_block_mev_analysis() {
        let txs = vec![
            (100, [1u8; 32]),
            (100, [2u8; 32]),
            (100, [3u8; 32]),
            (100, [4u8; 32]),
            (5000, [5u8; 32]), // Outlier: 50× median
        ];

        let (assessments, median) = analyze_block_mev(&txs);
        assert_eq!(median, 100);
        assert_eq!(assessments.len(), 5);

        // Outlier should be flagged
        let outlier = assessments.iter().find(|a| a.tx_hash == [5u8; 32]).unwrap();
        assert!(outlier.frontrun_flagged);
        assert_eq!(outlier.canonical_position, 0); // Highest fee → first position
    }
}
