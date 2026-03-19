//! Block Validation — DAG + Unified ZKP native.
//!
//! # Architecture
//!
//! Block validation is split into two phases:
//!
//! 1. **Header validation** (`misaka_dag::header_validation::validate_header_full`):
//!    The single source of truth for all header checks. This module provides
//!    a thin `validate_dag_header()` wrapper for the fast-path (pre-GhostDAG)
//!    that delegates to `DagBlockHeader::validate_structure()`.
//!
//! 2. **Transaction verification** (misaka_dag::qdag_verify): Unified ZKP,
//!    range proofs, balance proofs, nullifier binding.
//!
//! # Validation Path Unification (Task 3.2)
//!
//! Previously, `validate_dag_header()` duplicated checks from
//! `header_validation::validate_header_full()` (version, parents, timestamp,
//! duplicate parents). This was a maintenance hazard where the two paths
//! could diverge, leading to blocks accepted by one path but rejected by
//! the other.
//!
//! Now there is a single validation chain:
//! - **Fast path** (pre-GhostDAG): `validate_dag_header()` → `DagBlockHeader::validate_structure()`
//! - **Full path** (post-GhostDAG): `validate_header_full()` (includes sig, eligibility, root binding)
//!
//! Both paths produce the SAME result for the checks they share because
//! `validate_structure()` is the shared implementation used by both.

use misaka_pqc::unified_zkp::SCHEME_UNIFIED_ZKP;
use misaka_pqc::ring_scheme::MembershipSchemeVersion;
use misaka_pqc::error::CryptoError;

/// Minimum timestamp tolerance (seconds in the future).
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 60;

/// Validated block header (post-verification).
#[derive(Debug, Clone)]
pub struct ValidatedHeader {
    pub block_hash: [u8; 32],
    pub blue_score: u64,
    pub parent_count: usize,
    pub tx_count: usize,
    pub timestamp_ms: u64,
}

/// Validate a DAG block header (fast path, pre-GhostDAG).
///
/// Delegates to `DagBlockHeader::validate_structure()` which is the SINGLE
/// implementation of structural checks (version, parents, timestamp, duplicates).
///
/// For full validation including proposer signature and eligibility, use
/// `misaka_dag::header_validation::validate_header_full()` after GhostDAG
/// scoring is complete.
pub fn validate_dag_header(
    header: &misaka_dag::dag_block::DagBlockHeader,
    is_genesis: bool,
    now_ms: u64,
) -> Result<(), String> {
    // Delegate to the shared structural validation on DagBlockHeader.
    // This ensures fast-path and full-path never diverge on structural checks.
    header.validate_structure(now_ms)
        .map_err(|e| e.to_string())?;

    // Additional genesis-specific check: genesis is allowed to have no parents
    // even when validate_structure would reject it (blue_score > 0 with no parents).
    // For non-genesis blocks, validate_structure already rejects empty parents
    // when blue_score > 0.
    if !is_genesis && header.parents.is_empty() {
        return Err("non-genesis block must have at least one parent".into());
    }

    Ok(())
}

/// Check if a membership proof scheme version is accepted.
///
/// Only UnifiedZkpV1 is accepted for new blocks.
/// All legacy schemes are rejected.
pub fn is_scheme_accepted(scheme: u8, is_historical: bool) -> bool {
    match MembershipSchemeVersion::from_u8(scheme) {
        Some(v) => {
            if is_historical {
                v.is_accepted()
            } else {
                v.is_current() // Only UnifiedZkpV1
            }
        }
        None => false,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_dag::dag_block::{DagBlockHeader, DAG_VERSION, ZERO_HASH};

    fn make_header(parents: Vec<[u8; 32]>, ts: u64) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION, parents, timestamp_ms: ts,
            chain_id: 2, epoch: 0,
            tx_root: ZERO_HASH, proposer_id: [0; 32],
            proposer_randomness_commitment: [0; 32],
            protocol_version: 1,
            blue_score: 0,
        }
    }

    #[test]
    fn test_valid_header() {
        let h = make_header(vec![[0xAA; 32]], 1000);
        assert!(validate_dag_header(&h, false, 2000).is_ok());
    }

    #[test]
    fn test_genesis_no_parents_ok() {
        let h = make_header(vec![], 1000);
        assert!(validate_dag_header(&h, true, 2000).is_ok());
    }

    #[test]
    fn test_non_genesis_no_parents_rejected() {
        let h = make_header(vec![], 1000);
        assert!(validate_dag_header(&h, false, 2000).is_err());
    }

    #[test]
    fn test_duplicate_parent_rejected() {
        let h = make_header(vec![[0xAA; 32], [0xAA; 32]], 1000);
        assert!(validate_dag_header(&h, false, 2000).is_err());
    }

    #[test]
    fn test_future_timestamp_rejected() {
        let h = make_header(vec![[0xAA; 32]], 999_999_999);
        assert!(validate_dag_header(&h, false, 1000).is_err());
    }

    #[test]
    fn test_unified_zkp_accepted() {
        assert!(is_scheme_accepted(SCHEME_UNIFIED_ZKP, false));
        assert!(is_scheme_accepted(SCHEME_UNIFIED_ZKP, true));
    }

    #[test]
    fn test_removed_schemes_rejected() {
        assert!(!is_scheme_accepted(0x01, false)); // LRS
        assert!(!is_scheme_accepted(0x01, true));
        assert!(!is_scheme_accepted(0x02, false)); // Chipmunk
    }
}
