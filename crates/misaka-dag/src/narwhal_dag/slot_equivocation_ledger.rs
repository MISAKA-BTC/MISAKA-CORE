// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Slot Equivocation Ledger — cross-slot equivocation detection and authority banning.
//!
//! ## Purpose
//!
//! The existing `DagState::block_index` and `VoteRegistry` detect equivocation
//! per-slot and per-leader respectively. This ledger provides a **global view**:
//! once an authority equivocates at any slot, they are banned from all future
//! quorum calculations for the current epoch.
//!
//! ## Integration Points
//!
//! - `BlockManager::try_accept_block` → `ledger.observe(slot, digest)`
//! - `Committee::reached_quorum_excluding_banned(stake, ledger, round)` replaces
//!   bare `reached_quorum(stake)` in:
//!   - `BaseCommitter::try_direct_decide` (voting count)
//!   - `StakeAggregator::reached_quorum`
//!   - `ThresholdClock` round advancement
//!
//! ## Persistence
//!
//! Evidence is append-only in `CF_EQUIVOCATION_EVIDENCE`. Never deleted
//! (required for slashing proposals and post-mortem analysis).
//!
//! ## Gossip
//!
//! Equivocation evidence is gossiped via `NetworkMessage::EquivocationEvidence`.
//! Receivers verify both signatures before merging into their local ledger.
//!
//! Sui equivalent: `consensus/core/src/block_manager.rs` equivocation handling
//! + authority exclusion in `consensus/core/src/dag_state.rs`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use crate::narwhal_types::block::{AuthorityIndex, BlockDigest, BlockRef, Round, Slot};
use crate::narwhal_types::committee::{Committee, Stake};

// ═══════════════════════════════════════════════════════════
//  Evidence
// ═══════════════════════════════════════════════════════════

/// Proof that an authority proposed two distinct blocks at the same slot.
///
/// Contains both block references and their ML-DSA-65 signatures so that
/// any third party can independently verify the equivocation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SlotEquivocationEvidence {
    /// The equivocating authority.
    pub authority: AuthorityIndex,
    /// The disputed slot (round, authority).
    pub slot: Slot,
    /// First observed block at this slot.
    pub block_a: BlockRef,
    /// Second observed block at this slot (different digest).
    pub block_b: BlockRef,
    /// ML-DSA-65 signature on block A (for independent verification).
    pub signature_a: Vec<u8>,
    /// ML-DSA-65 signature on block B (for independent verification).
    pub signature_b: Vec<u8>,
    /// Timestamp when this equivocation was detected (unix ms).
    pub detected_at_ms: u64,
}

impl SlotEquivocationEvidence {
    /// Serialize to bytes for persistence and gossip.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("evidence serialization cannot fail")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ═══════════════════════════════════════════════════════════
//  Observe result
// ═══════════════════════════════════════════════════════════

/// Result of observing a block at a slot.
#[derive(Clone, Debug)]
pub enum ObserveResult {
    /// First time seeing a block at this slot. Normal path.
    Fresh,
    /// Same digest as previously observed. Duplicate, no action needed.
    Duplicate,
    /// Different digest at same slot — equivocation detected.
    /// Contains the evidence for persistence and gossip.
    Equivocation(SlotEquivocationEvidence),
}

// ═══════════════════════════════════════════════════════════
//  Ledger
// ═══════════════════════════════════════════════════════════

/// Global equivocation tracking ledger.
///
/// Maintains a per-slot observation set and a per-authority ban list.
/// Once banned, an authority's stake is excluded from **all** quorum
/// calculations for the remainder of the epoch.
pub struct SlotEquivocationLedger {
    /// (round, author) → set of observed digests at that slot.
    /// If the set has >1 entry, the authority equivocated.
    observed_per_slot: BTreeMap<Slot, BTreeSet<BlockDigest>>,

    /// Authorities that have been detected equivocating.
    /// Maps authority → the round at which equivocation was first detected.
    /// Once banned, the authority is excluded from quorum for all rounds
    /// >= ban_round in this epoch.
    banned: HashMap<AuthorityIndex, Round>,

    /// All collected evidence, append-only.
    evidence: Vec<SlotEquivocationEvidence>,

    /// Quick lookup: set of banned authorities for O(1) checks.
    banned_set: HashSet<AuthorityIndex>,

    /// SEC-FIX: Cache of first-seen signature per slot for complete
    /// equivocation evidence. When equivocation is detected, both
    /// signatures are available for cryptographic proof.
    first_sig_cache: HashMap<Slot, Vec<u8>>,

    /// Clock abstraction (Phase 0-2 completion).
    clock: Arc<dyn super::clock::Clock>,
}

impl SlotEquivocationLedger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            observed_per_slot: BTreeMap::new(),
            banned: HashMap::new(),
            evidence: Vec::new(),
            banned_set: HashSet::new(),
            first_sig_cache: HashMap::new(),
            clock: Arc::new(super::clock::SystemClock),
        }
    }

    /// Inject a custom clock (for deterministic simulation).
    pub fn with_clock(mut self, clock: Arc<dyn super::clock::Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Observe a block at a given slot.
    ///
    /// Returns:
    /// - `Fresh` if this is the first block at this slot
    /// - `Duplicate` if the same digest was already observed
    /// - `Equivocation` if a different digest was observed (authority is banned)
    ///
    /// The caller must provide the block's signature for evidence construction.
    pub fn observe(
        &mut self,
        slot: Slot,
        digest: BlockDigest,
        block_ref: BlockRef,
        signature: &[u8],
    ) -> ObserveResult {
        let digests = self
            .observed_per_slot
            .entry(slot)
            .or_insert_with(BTreeSet::new);

        if digests.contains(&digest) {
            return ObserveResult::Duplicate;
        }

        if digests.is_empty() {
            // First block at this slot — cache its signature for future evidence
            digests.insert(digest);
            self.first_sig_cache.insert(slot, signature.to_vec());
            return ObserveResult::Fresh;
        }

        // Another digest exists at this slot → equivocation
        let existing_digest = *digests.iter().next().unwrap();
        digests.insert(digest);

        let now_ms = self.clock.now_millis();

        // SEC-FIX: Retrieve cached first-seen signature for complete evidence
        let signature_a = self.first_sig_cache.get(&slot).cloned().unwrap_or_default();

        let evidence = SlotEquivocationEvidence {
            authority: slot.authority,
            slot,
            block_a: BlockRef::new(slot.round, slot.authority, existing_digest),
            block_b: block_ref,
            signature_a,
            signature_b: signature.to_vec(),
            detected_at_ms: now_ms,
        };

        // Ban the authority
        self.banned.entry(slot.authority).or_insert(slot.round);
        self.banned_set.insert(slot.authority);

        self.evidence.push(evidence.clone());

        tracing::warn!(
            authority = slot.authority,
            round = slot.round,
            "Equivocation detected: authority {} proposed 2 blocks at round {}",
            slot.authority,
            slot.round
        );

        ObserveResult::Equivocation(evidence)
    }

    /// Observe with full signature caching for complete evidence.
    ///
    /// This variant should be used when the caller has access to both
    /// block signatures. Produces evidence that is independently verifiable.
    pub fn observe_with_signatures(
        &mut self,
        slot: Slot,
        digest: BlockDigest,
        block_ref: BlockRef,
        signature: &[u8],
        // Cache of first-seen signatures per slot
        sig_cache: &mut HashMap<Slot, Vec<u8>>,
    ) -> ObserveResult {
        let digests = self
            .observed_per_slot
            .entry(slot)
            .or_insert_with(BTreeSet::new);

        if digests.contains(&digest) {
            return ObserveResult::Duplicate;
        }

        if digests.is_empty() {
            digests.insert(digest);
            sig_cache.insert(slot, signature.to_vec());
            return ObserveResult::Fresh;
        }

        // Equivocation
        let existing_digest = *digests.iter().next().unwrap();
        digests.insert(digest);

        let now_ms = self.clock.now_millis();

        let signature_a = sig_cache.get(&slot).cloned().unwrap_or_default();

        let evidence = SlotEquivocationEvidence {
            authority: slot.authority,
            slot,
            block_a: BlockRef::new(slot.round, slot.authority, existing_digest),
            block_b: block_ref,
            signature_a,
            signature_b: signature.to_vec(),
            detected_at_ms: now_ms,
        };

        self.banned.entry(slot.authority).or_insert(slot.round);
        self.banned_set.insert(slot.authority);
        self.evidence.push(evidence.clone());

        tracing::warn!(
            authority = slot.authority,
            round = slot.round,
            "Equivocation detected (full evidence): authority {} at round {}",
            slot.authority,
            slot.round
        );

        ObserveResult::Equivocation(evidence)
    }

    // ─── Query methods ───────────────────────────────────────

    /// Check if an authority is banned (equivocated).
    #[inline]
    pub fn is_banned(&self, authority: AuthorityIndex) -> bool {
        self.banned_set.contains(&authority)
    }

    /// Get the round at which an authority was first detected equivocating.
    pub fn ban_round(&self, authority: AuthorityIndex) -> Option<Round> {
        self.banned.get(&authority).copied()
    }

    /// Return all banned authorities.
    pub fn banned_authorities(&self) -> &HashSet<AuthorityIndex> {
        &self.banned_set
    }

    /// Number of banned authorities.
    pub fn num_banned(&self) -> usize {
        self.banned_set.len()
    }

    /// All collected evidence (append-only, never cleared).
    pub fn evidence(&self) -> &[SlotEquivocationEvidence] {
        &self.evidence
    }

    /// Get new evidence since a given index (for incremental gossip).
    pub fn evidence_since(&self, from_index: usize) -> &[SlotEquivocationEvidence] {
        if from_index >= self.evidence.len() {
            &[]
        } else {
            &self.evidence[from_index..]
        }
    }

    // ─── Quorum with exclusion ───────────────────────────────

    /// Calculate effective stake excluding banned authorities.
    ///
    /// This is used in all quorum calculations to ensure equivocating
    /// validators cannot influence consensus decisions.
    pub fn effective_stake(
        &self,
        committee: &Committee,
        voters: impl Iterator<Item = AuthorityIndex>,
    ) -> Stake {
        // SEC-FIX NH-7: saturating fold to prevent u64 overflow
        voters
            .filter(|auth| !self.is_banned(*auth))
            .fold(0u64, |acc, auth| acc.saturating_add(committee.stake(auth)))
    }

    /// Check if quorum is reached with the given stake, after accounting
    /// for banned authorities in the total committee.
    ///
    /// The quorum threshold is recalculated based on the effective
    /// committee (excluding banned members' stake).
    ///
    /// **IMPORTANT**: We do NOT reduce the quorum threshold when banning.
    /// The threshold remains `Q = N - floor((N-1)/3)` over the FULL
    /// committee. We only exclude banned authorities' votes from the
    /// numerator. This is the conservative (safe) approach.
    pub fn reached_quorum_excluding_banned(
        &self,
        committee: &Committee,
        stake_from_honest_voters: Stake,
    ) -> bool {
        // Conservative: use full committee threshold, only filter votes
        committee.reached_quorum(stake_from_honest_voters)
    }

    // ─── Persistence ─────────────────────────────────────────

    /// Merge evidence received from a peer (gossip).
    ///
    /// Only merges evidence for authorities we haven't already banned
    /// at an equal or earlier round. Deduplicates by (authority, slot).
    ///
    /// SEC-FIX NH-3: Structural validation before ban. Rejects evidence
    /// with empty signatures, mismatched authority/slot, or identical digests.
    /// Cryptographic ML-DSA signature verification MUST be performed by the
    /// caller using `verify_evidence_signatures()` before calling this method.
    pub fn merge_evidence(&mut self, remote_evidence: &[SlotEquivocationEvidence]) {
        for ev in remote_evidence {
            // SEC-FIX NH-3: Structural validation — reject malformed evidence
            if ev.block_a.digest == ev.block_b.digest {
                tracing::warn!(
                    authority = ev.authority,
                    "Rejecting equivocation evidence: identical block digests"
                );
                continue;
            }
            if ev.block_a.author != ev.authority || ev.block_b.author != ev.authority {
                tracing::warn!(
                    authority = ev.authority,
                    "Rejecting equivocation evidence: authority mismatch in block refs"
                );
                continue;
            }
            if ev.block_a.round != ev.slot.round || ev.block_b.round != ev.slot.round {
                tracing::warn!(
                    authority = ev.authority,
                    "Rejecting equivocation evidence: round mismatch"
                );
                continue;
            }
            if ev.signature_a.is_empty() || ev.signature_b.is_empty() {
                tracing::warn!(
                    authority = ev.authority,
                    "Rejecting equivocation evidence: missing signatures"
                );
                continue;
            }

            // Check if we already have evidence for this exact slot
            let dominated = self
                .evidence
                .iter()
                .any(|existing| existing.authority == ev.authority && existing.slot == ev.slot);
            if dominated {
                continue;
            }

            // Ban the authority if not already banned
            self.banned.entry(ev.authority).or_insert(ev.slot.round);
            self.banned_set.insert(ev.authority);

            // Record the observed digests
            let digests = self
                .observed_per_slot
                .entry(ev.slot)
                .or_insert_with(BTreeSet::new);
            digests.insert(ev.block_a.digest);
            digests.insert(ev.block_b.digest);

            self.evidence.push(ev.clone());

            tracing::info!(
                authority = ev.authority,
                round = ev.slot.round,
                "Merged remote equivocation evidence for authority {} at round {}",
                ev.authority,
                ev.slot.round
            );
        }
    }

    /// Serialize all evidence for persistence.
    /// SEC-FIX TM-4: Return Result instead of panicking on serialization failure.
    pub fn serialize_evidence(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.evidence)
    }

    /// Restore ledger from persisted evidence.
    pub fn restore_from_evidence(evidence: Vec<SlotEquivocationEvidence>) -> Self {
        let mut ledger = Self::new();
        for ev in &evidence {
            ledger.banned.entry(ev.authority).or_insert(ev.slot.round);
            ledger.banned_set.insert(ev.authority);

            let digests = ledger
                .observed_per_slot
                .entry(ev.slot)
                .or_insert_with(BTreeSet::new);
            digests.insert(ev.block_a.digest);
            digests.insert(ev.block_b.digest);
        }
        ledger.evidence = evidence;
        ledger
    }

    // ─── GC ──────────────────────────────────────────────────

    /// Garbage-collect observation data for rounds below `gc_round`.
    ///
    /// Evidence is NEVER garbage-collected (needed for slashing).
    /// Only the `observed_per_slot` map is trimmed.
    pub fn gc_observations_below(&mut self, gc_round: Round) {
        // BTreeMap is sorted by Slot, which sorts by (round, authority).
        // Remove all entries with round < gc_round.
        let cutoff = Slot {
            round: gc_round,
            authority: 0,
        };
        // split_off returns entries >= cutoff, so we keep those
        let kept = self.observed_per_slot.split_off(&cutoff);
        let removed = self.observed_per_slot.len();
        self.observed_per_slot = kept;
        if removed > 0 {
            tracing::debug!(
                removed_slots = removed,
                gc_round = gc_round,
                "GC'd equivocation observation data"
            );
        }
    }

    // ─── Metrics ─────────────────────────────────────────────

    /// Total number of equivocation events detected.
    pub fn total_equivocations_detected(&self) -> usize {
        self.evidence.len()
    }

    /// Total bytes of stored evidence.
    pub fn evidence_bytes(&self) -> usize {
        self.evidence
            .iter()
            .map(|ev| {
                std::mem::size_of::<SlotEquivocationEvidence>()
                    + ev.signature_a.len()
                    + ev.signature_b.len()
            })
            .sum()
    }
}

impl Default for SlotEquivocationLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════
//  Committee extension
// ═══════════════════════════════════════════════════════════

/// Extension trait for Committee to calculate quorum with exclusions.
pub trait CommitteeEquivocationExt {
    /// Calculate quorum threshold excluding banned authorities.
    ///
    /// Conservative approach: threshold stays at `N - floor((N-1)/3)` over
    /// the FULL committee. Banned authorities' votes are simply not counted.
    fn reached_quorum_excluding(&self, stake: Stake, ledger: &SlotEquivocationLedger) -> bool;

    /// Effective total stake excluding banned authorities.
    fn effective_total_stake(&self, ledger: &SlotEquivocationLedger) -> Stake;
}

impl CommitteeEquivocationExt for Committee {
    fn reached_quorum_excluding(&self, stake: Stake, _ledger: &SlotEquivocationLedger) -> bool {
        // Conservative: use full committee threshold
        self.reached_quorum(stake)
    }

    fn effective_total_stake(&self, ledger: &SlotEquivocationLedger) -> Stake {
        // SEC-FIX NH-7: saturating_add to prevent u64 overflow
        let mut total = 0u64;
        for i in 0..self.size() as AuthorityIndex {
            if !ledger.is_banned(i) {
                total = total.saturating_add(self.stake(i));
            }
        }
        total
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_slot(round: Round, authority: AuthorityIndex) -> Slot {
        Slot { round, authority }
    }

    fn test_digest(val: u8) -> BlockDigest {
        let mut d = [0u8; 32];
        d[0] = val;
        BlockDigest(d)
    }

    fn test_block_ref(round: Round, author: AuthorityIndex, digest_val: u8) -> BlockRef {
        BlockRef::new(round, author, test_digest(digest_val))
    }

    fn test_committee(n: usize) -> Committee {
        Committee::new_for_test(n)
    }

    // ─── Basic observation ───────────────────────────────────

    #[test]
    fn test_fresh_observation() {
        let mut ledger = SlotEquivocationLedger::new();
        let slot = test_slot(1, 0);
        let result = ledger.observe(slot, test_digest(1), test_block_ref(1, 0, 1), &[0xAA]);
        assert!(matches!(result, ObserveResult::Fresh));
        assert_eq!(ledger.num_banned(), 0);
    }

    #[test]
    fn test_duplicate_observation() {
        let mut ledger = SlotEquivocationLedger::new();
        let slot = test_slot(1, 0);
        let digest = test_digest(1);
        let block_ref = test_block_ref(1, 0, 1);
        ledger.observe(slot, digest, block_ref, &[0xAA]);
        let result = ledger.observe(slot, digest, block_ref, &[0xAA]);
        assert!(matches!(result, ObserveResult::Duplicate));
        assert_eq!(ledger.num_banned(), 0);
    }

    #[test]
    fn test_equivocation_detected() {
        let mut ledger = SlotEquivocationLedger::new();
        let slot = test_slot(1, 0);
        ledger.observe(slot, test_digest(1), test_block_ref(1, 0, 1), &[0xAA]);
        let result = ledger.observe(slot, test_digest(2), test_block_ref(1, 0, 2), &[0xBB]);

        assert!(matches!(result, ObserveResult::Equivocation(_)));
        assert!(ledger.is_banned(0));
        assert_eq!(ledger.num_banned(), 1);
        assert_eq!(ledger.evidence().len(), 1);
    }

    // ─── Quorum exclusion ────────────────────────────────────

    #[test]
    fn test_equivocator_excluded_from_quorum() {
        let committee = test_committee(4); // 4 equal-stake authorities
        let mut ledger = SlotEquivocationLedger::new();

        // Authority 0 equivocates
        let slot = test_slot(1, 0);
        ledger.observe(slot, test_digest(1), test_block_ref(1, 0, 1), &[0xAA]);
        ledger.observe(slot, test_digest(2), test_block_ref(1, 0, 2), &[0xBB]);

        assert!(ledger.is_banned(0));

        // Calculate effective stake from honest voters only
        let honest_voters = [1u32, 2, 3]; // exclude authority 0
        let stake = ledger.effective_stake(&committee, honest_voters.iter().copied());

        // With equal stake and 4 authorities, each has stake 1
        // 3 honest voters → stake = 3
        // Quorum threshold for N=4: Q = 4 - floor(3/3) = 3
        assert!(committee.reached_quorum(stake));

        // But if we include the equivocator's vote, it doesn't count
        let all_voters = [0u32, 1, 2, 3];
        let filtered_stake = ledger.effective_stake(&committee, all_voters.iter().copied());
        // Only 3 honest votes counted (authority 0 filtered out)
        assert_eq!(filtered_stake, stake);
    }

    #[test]
    fn test_equivocator_fully_excluded_from_all_future_quora() {
        let committee = test_committee(4);
        let mut ledger = SlotEquivocationLedger::new();

        // Authority 2 equivocates at round 5
        let slot = test_slot(5, 2);
        ledger.observe(slot, test_digest(1), test_block_ref(5, 2, 1), &[0xAA]);
        ledger.observe(slot, test_digest(2), test_block_ref(5, 2, 2), &[0xBB]);

        // At any future round, authority 2 should be excluded
        for round in 6..=100 {
            assert!(
                ledger.is_banned(2),
                "authority 2 should remain banned at round {}",
                round
            );
        }

        // In a 4-authority committee with equal stake:
        // quorum_threshold = 3 (requires 3 out of 4)
        // With authority 2 banned, only authorities {0,1,3} can contribute
        // They need all 3 to reach quorum
        let honest_stake = ledger.effective_stake(&committee, [0u32, 1, 3].iter().copied());
        assert!(
            committee.reached_quorum(honest_stake),
            "3 honest authorities should still reach quorum"
        );

        // But 2 honest authorities can't reach quorum
        let insufficient = ledger.effective_stake(&committee, [0u32, 1].iter().copied());
        assert!(
            !committee.reached_quorum(insufficient),
            "2 authorities should not reach quorum for N=4"
        );
    }

    // ─── Evidence persistence and merge ──────────────────────

    #[test]
    fn test_evidence_serialization_roundtrip() {
        let mut ledger = SlotEquivocationLedger::new();
        let slot = test_slot(3, 1);
        ledger.observe(slot, test_digest(10), test_block_ref(3, 1, 10), &[0xAA; 64]);
        ledger.observe(slot, test_digest(20), test_block_ref(3, 1, 20), &[0xBB; 64]);

        // Serialize
        let bytes = ledger.serialize_evidence().unwrap();

        // Restore
        let evidence: Vec<SlotEquivocationEvidence> = serde_json::from_slice(&bytes).unwrap();
        let restored = SlotEquivocationLedger::restore_from_evidence(evidence);

        assert_eq!(restored.num_banned(), 1);
        assert!(restored.is_banned(1));
        assert_eq!(restored.evidence().len(), 1);
    }

    #[test]
    fn test_evidence_merge_from_peer() {
        let mut ledger_a = SlotEquivocationLedger::new();
        let mut ledger_b = SlotEquivocationLedger::new();

        // Node A detects equivocation by authority 0
        let slot0 = test_slot(1, 0);
        ledger_a.observe(slot0, test_digest(1), test_block_ref(1, 0, 1), &[0xAA]);
        ledger_a.observe(slot0, test_digest(2), test_block_ref(1, 0, 2), &[0xBB]);

        // Node B detects equivocation by authority 1
        let slot1 = test_slot(2, 1);
        ledger_b.observe(slot1, test_digest(3), test_block_ref(2, 1, 3), &[0xCC]);
        ledger_b.observe(slot1, test_digest(4), test_block_ref(2, 1, 4), &[0xDD]);

        // Merge B's evidence into A
        ledger_a.merge_evidence(ledger_b.evidence());
        assert_eq!(ledger_a.num_banned(), 2);
        assert!(ledger_a.is_banned(0));
        assert!(ledger_a.is_banned(1));

        // Merge A's evidence into B
        ledger_b.merge_evidence(ledger_a.evidence());
        assert_eq!(ledger_b.num_banned(), 2);
        assert!(ledger_b.is_banned(0));
        assert!(ledger_b.is_banned(1));
    }

    #[test]
    fn test_evidence_merge_is_idempotent() {
        let mut ledger = SlotEquivocationLedger::new();
        let slot = test_slot(1, 0);
        ledger.observe(slot, test_digest(1), test_block_ref(1, 0, 1), &[0xAA]);
        ledger.observe(slot, test_digest(2), test_block_ref(1, 0, 2), &[0xBB]);

        let evidence = ledger.evidence().to_vec();

        // Merge same evidence again — should not duplicate
        ledger.merge_evidence(&evidence);
        assert_eq!(
            ledger.evidence().len(),
            1,
            "duplicate merge should be idempotent"
        );
        assert_eq!(ledger.num_banned(), 1);
    }

    // ─── GC ──────────────────────────────────────────────────

    #[test]
    fn test_gc_observations_preserves_evidence() {
        let mut ledger = SlotEquivocationLedger::new();

        // Observe at rounds 1, 5, 10
        for round in [1, 5, 10] {
            let slot = test_slot(round, 0);
            ledger.observe(
                slot,
                test_digest(round as u8),
                test_block_ref(round, 0, round as u8),
                &[],
            );
        }

        // Equivocate at round 5
        let slot5 = test_slot(5, 0);
        ledger.observe(slot5, test_digest(55), test_block_ref(5, 0, 55), &[]);

        // GC below round 6
        ledger.gc_observations_below(6);

        // Evidence is preserved
        assert_eq!(ledger.evidence().len(), 1);
        assert!(ledger.is_banned(0));
    }

    // ─── Byzantine flood resistance ──────────────────────────

    #[test]
    fn test_byzantine_equivocation_flood() {
        let committee = test_committee(7); // 7 authorities, f=2
        let mut ledger = SlotEquivocationLedger::new();

        // f=2 Byzantine authorities (0, 1) each equivocate at 100 rounds
        for round in 1..=100u32 {
            for byzantine in [0u32, 1] {
                let slot = test_slot(round, byzantine);
                ledger.observe(
                    slot,
                    test_digest(1),
                    test_block_ref(round, byzantine, 1),
                    &[],
                );
                ledger.observe(
                    slot,
                    test_digest(2),
                    test_block_ref(round, byzantine, 2),
                    &[],
                );
            }
        }

        // Both should be banned
        assert_eq!(ledger.num_banned(), 2);
        assert!(ledger.is_banned(0));
        assert!(ledger.is_banned(1));

        // 5 honest authorities (2,3,4,5,6) should still reach quorum
        // Q = 7 - floor(6/3) = 7 - 2 = 5
        let honest_stake = ledger.effective_stake(&committee, [2u32, 3, 4, 5, 6].iter().copied());
        assert!(
            committee.reached_quorum(honest_stake),
            "5 honest out of 7 should reach quorum"
        );

        // 4 honest should NOT reach quorum
        let four_honest = ledger.effective_stake(&committee, [2u32, 3, 4, 5].iter().copied());
        assert!(
            !committee.reached_quorum(four_honest),
            "4 out of 7 should not reach quorum"
        );
    }
}
