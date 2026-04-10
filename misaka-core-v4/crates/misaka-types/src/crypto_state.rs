// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! CryptoStateMetadata — per-address cryptographic operation tracking.
//!
//! QRL equivalent: OptimizedAddressState with OTS bitfield.
//! MISAKA equivalent: unified tracking of all cryptographic state operations.
//!
//! ## Why this matters
//!
//! QRL tracks OTS index usage per address because XMSS one-time signatures
//! are stateful — reuse breaks security.
//! MISAKA's ML-DSA-65 is stateless, but we still need to track:
//!
//! 1. **SpendTag/key image usage** — prevent double-spend
//! 2. **Delegated capability usage** — daily spend limits, cap count
//! 3. **Shielded note lifecycle** — scan cursors, encrypted note count
//! 4. **Proof binding** — prevent proof replay across tx types
//! 5. **Bridge request lifecycle** — withdrawal spent_tags
//!
//! This module provides the unified view that QRL's OptimizedAddressState
//! gives for OTS tracking, but generalized to all MISAKA crypto operations.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════
//  Per-address crypto state metadata
// ═══════════════════════════════════════════════════════════

/// Per-address cryptographic operation metadata.
///
/// Stored alongside balance/nonce state.
/// QRL equivalent: used_ots_key_count, ots_bitfield, paginated counters.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CryptoStateMetadata {
    /// Number of spent_tags / key images consumed by this address.
    pub consumed_spent_count: u64,
    /// Number of active delegated keys from this address.
    pub active_delegation_count: u32,
    /// Total delegated keys ever created (including revoked).
    pub total_delegation_count: u32,
    /// Number of encrypted notes received.
    pub encrypted_note_count: u64,
    /// Scan cursor — last scanned block height.
    pub scan_cursor_height: u64,
    /// Last seen commitment tree root (for incremental scan).
    pub last_seen_root: [u8; 32],
    /// Number of bridge withdrawal requests initiated.
    pub bridge_withdrawal_count: u64,
    /// Number of proof submissions (for rate limiting).
    pub proof_submission_count: u64,
    /// Daily spend amount (resets each epoch).
    pub daily_spend_epoch: u64,
    pub daily_spend_amount: u64,
    /// View tag page count (for wallet scanning optimization).
    pub view_tag_page_count: u32,
}

impl CryptoStateMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a spend tag consumption.
    pub fn record_spend_tag_consumed(&mut self) {
        self.consumed_spent_count += 1;
    }

    /// Record a new delegation.
    pub fn record_delegation_created(&mut self) {
        self.active_delegation_count += 1;
        self.total_delegation_count += 1;
    }

    /// Record a delegation revocation.
    pub fn record_delegation_revoked(&mut self) {
        self.active_delegation_count = self.active_delegation_count.saturating_sub(1);
    }

    /// Record an encrypted note received.
    pub fn record_note_received(&mut self) {
        self.encrypted_note_count += 1;
    }

    /// Update scan cursor.
    pub fn update_scan_cursor(&mut self, height: u64, root: [u8; 32]) {
        self.scan_cursor_height = height;
        self.last_seen_root = root;
    }

    /// Record a bridge withdrawal.
    pub fn record_bridge_withdrawal(&mut self) {
        self.bridge_withdrawal_count += 1;
    }

    /// Record daily spend. Returns Err if limit exceeded.
    pub fn record_daily_spend(
        &mut self,
        amount: u64,
        current_epoch: u64,
        daily_limit: u64,
    ) -> Result<(), String> {
        // Reset if epoch changed
        if current_epoch != self.daily_spend_epoch {
            self.daily_spend_epoch = current_epoch;
            self.daily_spend_amount = 0;
        }

        let new_total = self.daily_spend_amount.saturating_add(amount);
        if daily_limit > 0 && new_total > daily_limit {
            return Err(format!(
                "daily spend limit exceeded: {} + {} > {}",
                self.daily_spend_amount, amount, daily_limit
            ));
        }

        self.daily_spend_amount = new_total;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  Spend uniqueness tag
// ═══════════════════════════════════════════════════════════

/// Unified spend uniqueness tag -- abstracts over different anti-replay mechanisms.
///
/// QRL equivalent: OTS index uniqueness check.
/// MISAKA uses different mechanisms depending on the domain:
/// - UTXO transparent: spend identifier
/// - Bridge: withdrawal request ID
/// - Delegation: (master, delegated_pk) pair
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpendUniquenessTag {
    /// UTXO spend identifier (transparent ML-DSA-65).
    UtxoSpend([u8; 32]),
    /// Reserved: removed in v1.0.
    /// Variant retained for storage/wire format compatibility only -- no new writes.
    #[deprecated(note = "Removed in v1.0; variant kept for deserialization compat")]
    ReservedV1([u8; 32]),
    /// Bridge withdrawal ID.
    BridgeWithdrawalId([u8; 32]),
    /// Delegation uniqueness: SHA3(master_address || delegated_pk).
    DelegationId([u8; 32]),
    /// Proof binding ID (prevents proof replay).
    ProofBindingId([u8; 32]),
}

#[allow(deprecated)] // ReservedV1 variant retained for compat
impl SpendUniquenessTag {
    /// Get the raw 32-byte tag value.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Self::UtxoSpend(b) => b,
            Self::ReservedV1(b) => b,
            Self::BridgeWithdrawalId(b) => b,
            Self::DelegationId(b) => b,
            Self::ProofBindingId(b) => b,
        }
    }

    /// Domain tag for this uniqueness type.
    pub fn domain(&self) -> &'static str {
        match self {
            Self::UtxoSpend(_) => "utxo_spend",
            Self::ReservedV1(_) => "reserved_v1",
            Self::BridgeWithdrawalId(_) => "bridge_withdrawal",
            Self::DelegationId(_) => "delegation",
            Self::ProofBindingId(_) => "proof_binding",
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Replay protection domain
// ═══════════════════════════════════════════════════════════

/// Domain-separated replay protection tag.
///
/// Prevents cross-domain replay attacks where a valid spend tag
/// from one subsystem is replayed in another.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayProtectionId {
    /// Domain identifier.
    pub domain: ReplayDomain,
    /// The unique tag within this domain.
    pub tag: [u8; 32],
    /// Chain ID for cross-chain replay prevention.
    pub chain_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayDomain {
    UtxoSpend,
    BridgeWithdrawal,
    BridgeDeposit,
    CapabilityDelegation,
    ValidatorAttestation,
    GovernanceVote,
}

impl ReplayProtectionId {
    /// Compute the domain-separated ID.
    pub fn compute(domain: ReplayDomain, data: &[u8], chain_id: u32) -> Self {
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(b"MISAKA:replay:");
        h.update(&[domain.as_u8()]);
        h.update(&chain_id.to_le_bytes());
        h.update(data);
        let result = h.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        Self {
            domain,
            tag,
            chain_id,
        }
    }
}

impl ReplayDomain {
    fn as_u8(&self) -> u8 {
        match self {
            Self::UtxoSpend => 0,
            // 1 was ShieldedTransfer (removed)
            Self::BridgeWithdrawal => 2,
            Self::BridgeDeposit => 3,
            Self::CapabilityDelegation => 4,
            Self::ValidatorAttestation => 5,
            Self::GovernanceVote => 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_state_daily_limit() {
        let mut state = CryptoStateMetadata::new();
        // Epoch 0, limit 1000
        assert!(state.record_daily_spend(500, 0, 1000).is_ok());
        assert!(state.record_daily_spend(500, 0, 1000).is_ok());
        assert!(state.record_daily_spend(1, 0, 1000).is_err()); // exceeds

        // New epoch resets
        assert!(state.record_daily_spend(999, 1, 1000).is_ok());
    }

    #[test]
    fn test_crypto_state_counters() {
        let mut state = CryptoStateMetadata::new();
        state.record_spend_tag_consumed();
        state.record_spend_tag_consumed();
        state.record_delegation_created();
        state.record_delegation_created();
        state.record_delegation_revoked();
        state.record_note_received();

        assert_eq!(state.consumed_spent_count, 2);
        assert_eq!(state.active_delegation_count, 1);
        assert_eq!(state.total_delegation_count, 2);
        assert_eq!(state.encrypted_note_count, 1);
    }

    #[test]
    fn test_spend_uniqueness_domain_separation() {
        let ki = SpendUniquenessTag::UtxoSpend([0x11; 32]);
        #[allow(deprecated)]
        let null = SpendUniquenessTag::ReservedV1([0x11; 32]);
        // Same bytes, different domain
        assert_ne!(ki.domain(), null.domain());
        assert_eq!(ki.as_bytes(), null.as_bytes());
    }

    #[test]
    fn test_replay_protection_domain_separation() {
        let data = b"same_data";
        let r1 = ReplayProtectionId::compute(ReplayDomain::UtxoSpend, data, 1);
        let r2 = ReplayProtectionId::compute(ReplayDomain::BridgeWithdrawal, data, 1);
        let r3 = ReplayProtectionId::compute(ReplayDomain::UtxoSpend, data, 2); // different chain
                                                                                // Same data, different domain → different tag
        assert_ne!(r1.tag, r2.tag);
        // Same data, same domain, different chain → different tag
        assert_ne!(r1.tag, r3.tag);
    }
}
