// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! CryptographicInvariantManager — cross-module invariant enforcement.
//!
//! QRL equivalent: ChainManager's unified state validation.
//!
//! Centralizes invariant checking across:
//! - UTXO key images
//! - Shielded spent_tags
//! - Bridge withdrawal IDs
//! - Capability delegation uniqueness
//! - Proof binding IDs
//! - Replay protection domains
//!
//! ## Design
//!
//! Instead of each module independently checking its own uniqueness,
//! this manager provides a single entry point for:
//! 1. Registering a spend tag
//! 2. Checking cross-domain uniqueness
//! 3. Auditing all cryptographic state
//! 4. Rollback support for chain reorgs

use crate::crypto_state::SpendUniquenessTag;
use std::collections::{HashMap, HashSet};

/// Invariant violation.
#[derive(Debug, Clone)]
pub struct InvariantViolation {
    pub tag: SpendUniquenessTag,
    pub violation_type: ViolationType,
    pub context: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationType {
    /// Same tag used twice within the same block.
    IntraBlockDuplicate,
    /// Tag already exists in confirmed state.
    AlreadyConfirmed,
    /// Cross-domain collision (same bytes, different domains).
    CrossDomainCollision,
    /// Rollback attempted on non-existent tag.
    RollbackMissing,
}

/// Cross-module cryptographic invariant manager.
///
/// Enforces uniqueness of spend tags across all subsystems.
pub struct CryptographicInvariantManager {
    /// All confirmed spend tags (persisted).
    confirmed: HashSet<SpendUniquenessTag>,
    /// Per-block pending tags (not yet committed).
    pending: Vec<SpendUniquenessTag>,
    /// Per-domain counters for monitoring.
    domain_counts: HashMap<String, u64>,
    /// Detected violations (for audit).
    violations: Vec<InvariantViolation>,
    /// Rollback journal: block_height → tags added in that block.
    rollback_journal: HashMap<u64, Vec<SpendUniquenessTag>>,
}

impl CryptographicInvariantManager {
    pub fn new() -> Self {
        Self {
            confirmed: HashSet::new(),
            pending: Vec::new(),
            domain_counts: HashMap::new(),
            violations: Vec::new(),
            rollback_journal: HashMap::new(),
        }
    }

    /// Check and register a spend uniqueness tag.
    ///
    /// Returns Ok(()) if the tag is unique, Err if it's a duplicate.
    /// The tag is added to pending (call `commit_block` to make permanent).
    pub fn check_and_register(
        &mut self,
        tag: SpendUniquenessTag,
    ) -> Result<(), InvariantViolation> {
        // Check against confirmed state
        if self.confirmed.contains(&tag) {
            let violation = InvariantViolation {
                tag: tag.clone(),
                violation_type: ViolationType::AlreadyConfirmed,
                context: format!("tag {} already confirmed", tag.domain()),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Check intra-block duplicates
        if self.pending.contains(&tag) {
            let violation = InvariantViolation {
                tag: tag.clone(),
                violation_type: ViolationType::IntraBlockDuplicate,
                context: format!("tag {} duplicate within block", tag.domain()),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Cross-domain collision check: same bytes, different domain type
        let bytes = *tag.as_bytes();
        let current_domain = tag.domain();
        for existing in self.confirmed.iter().chain(self.pending.iter()) {
            if existing.as_bytes() == &bytes && existing.domain() != current_domain {
                let violation = InvariantViolation {
                    tag: tag.clone(),
                    violation_type: ViolationType::CrossDomainCollision,
                    context: format!(
                        "cross-domain collision: {} tag matches {} tag",
                        current_domain,
                        existing.domain()
                    ),
                };
                self.violations.push(violation.clone());
                return Err(violation);
            }
        }

        *self
            .domain_counts
            .entry(tag.domain().to_string())
            .or_default() += 1;
        self.pending.push(tag);
        Ok(())
    }

    /// Commit the current block's pending tags.
    pub fn commit_block(&mut self, block_height: u64) {
        let tags = std::mem::take(&mut self.pending);
        for tag in &tags {
            self.confirmed.insert(tag.clone());
        }
        self.rollback_journal.insert(block_height, tags);
    }

    /// Rollback a block — remove tags added at that height.
    pub fn rollback_block(&mut self, block_height: u64) -> usize {
        if let Some(tags) = self.rollback_journal.remove(&block_height) {
            let count = tags.len();
            for tag in tags {
                self.confirmed.remove(&tag);
            }
            count
        } else {
            0
        }
    }

    /// Discard pending tags (block rejected).
    pub fn discard_pending(&mut self) {
        self.pending.clear();
    }

    /// Check if a tag exists (in confirmed or pending).
    pub fn contains(&self, tag: &SpendUniquenessTag) -> bool {
        self.confirmed.contains(tag) || self.pending.contains(tag)
    }

    /// Total confirmed tags.
    pub fn confirmed_count(&self) -> usize {
        self.confirmed.len()
    }

    /// Pending tags in current block.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Violations detected.
    pub fn violations(&self) -> &[InvariantViolation] {
        &self.violations
    }

    /// Per-domain statistics.
    pub fn domain_stats(&self) -> &HashMap<String, u64> {
        &self.domain_counts
    }

    /// Export audit summary.
    pub fn audit_summary(&self) -> AuditSummary {
        AuditSummary {
            total_confirmed: self.confirmed.len() as u64,
            total_pending: self.pending.len() as u64,
            total_violations: self.violations.len() as u64,
            domain_counts: self.domain_counts.clone(),
            rollback_heights: self.rollback_journal.keys().copied().collect(),
        }
    }
}

/// Audit summary for explorer / monitoring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditSummary {
    pub total_confirmed: u64,
    pub total_pending: u64,
    pub total_violations: u64,
    pub domain_counts: HashMap<String, u64>,
    pub rollback_heights: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_tag_accepted() {
        let mut mgr = CryptographicInvariantManager::new();
        let tag = SpendUniquenessTag::UtxoSpend([0x11; 32]);
        assert!(mgr.check_and_register(tag).is_ok());
        assert_eq!(mgr.pending_count(), 1);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut mgr = CryptographicInvariantManager::new();
        let tag = SpendUniquenessTag::UtxoSpend([0x11; 32]);
        mgr.check_and_register(tag.clone()).unwrap();
        mgr.commit_block(1);

        // Same tag again → rejected
        let result = mgr.check_and_register(tag);
        assert!(result.is_err());
        assert_eq!(mgr.violations().len(), 1);
    }

    #[test]
    #[allow(deprecated)]
    fn test_intra_block_duplicate() {
        let mut mgr = CryptographicInvariantManager::new();
        let tag = SpendUniquenessTag::ReservedV1([0x22; 32]);
        mgr.check_and_register(tag.clone()).unwrap();

        // Same tag within same block
        let result = mgr.check_and_register(tag);
        assert!(result.is_err());
        match result.unwrap_err().violation_type {
            ViolationType::IntraBlockDuplicate => {}
            other => panic!("expected IntraBlockDuplicate, got {:?}", other),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_cross_domain_collision() {
        let mut mgr = CryptographicInvariantManager::new();
        let bytes = [0x33; 32];
        // Same bytes, different domains
        let ki = SpendUniquenessTag::UtxoSpend(bytes);
        let null = SpendUniquenessTag::ReservedV1(bytes);

        mgr.check_and_register(ki).unwrap();
        let result = mgr.check_and_register(null);
        assert!(result.is_err());
        match result.unwrap_err().violation_type {
            ViolationType::CrossDomainCollision => {}
            other => panic!("expected CrossDomainCollision, got {:?}", other),
        }
    }

    #[test]
    fn test_commit_and_rollback() {
        let mut mgr = CryptographicInvariantManager::new();

        // Block 1: add 2 tags
        mgr.check_and_register(SpendUniquenessTag::UtxoSpend([0x01; 32]))
            .unwrap();
        mgr.check_and_register(SpendUniquenessTag::UtxoSpend([0x02; 32]))
            .unwrap();
        mgr.commit_block(1);
        assert_eq!(mgr.confirmed_count(), 2);

        // Block 2: add 1 tag
        mgr.check_and_register(SpendUniquenessTag::UtxoSpend([0x03; 32]))
            .unwrap();
        mgr.commit_block(2);
        assert_eq!(mgr.confirmed_count(), 3);

        // Rollback block 2
        let rolled_back = mgr.rollback_block(2);
        assert_eq!(rolled_back, 1);
        assert_eq!(mgr.confirmed_count(), 2);

        // Tag from block 2 should be re-usable
        assert!(mgr
            .check_and_register(SpendUniquenessTag::UtxoSpend([0x03; 32]))
            .is_ok());
    }

    #[test]
    fn test_discard_pending() {
        let mut mgr = CryptographicInvariantManager::new();
        mgr.check_and_register(SpendUniquenessTag::UtxoSpend([0x01; 32]))
            .unwrap();
        assert_eq!(mgr.pending_count(), 1);

        mgr.discard_pending();
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.confirmed_count(), 0);
    }

    #[test]
    fn test_audit_summary() {
        let mut mgr = CryptographicInvariantManager::new();
        mgr.check_and_register(SpendUniquenessTag::UtxoSpend([0x01; 32]))
            .unwrap();
        mgr.check_and_register(SpendUniquenessTag::BridgeWithdrawalId([0x02; 32]))
            .unwrap();
        mgr.commit_block(1);

        let summary = mgr.audit_summary();
        assert_eq!(summary.total_confirmed, 2);
        assert_eq!(summary.domain_counts["utxo_spend"], 1);
        assert_eq!(summary.domain_counts["bridge_withdrawal"], 1);
    }
}
