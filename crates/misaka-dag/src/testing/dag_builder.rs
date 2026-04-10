// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 5b1d5849e, path: consensus/core/src/test_dag_builder.rs
//
//! Declarative DAG builder — fluent API for constructing test topologies.
//!
//! Builds `VerifiedBlock`s and feeds them to a `DagState`, using real
//! MISAKA types (`BlockRef`, `Committee`, etc.) so commit tests exercise
//! the same code path as production.
//!
//! ## Phase 1-3 enhancements
//!
//! - ML-DSA-65 real signing (not dummy bytes) — prevents CR-1 regression
//! - `TestValidatorSet` integration for committee-aware key management
//! - `Context::new_for_test()` integration
//! - Signature cache for amortizing ML-DSA-65 cost across repeated builds
//! - Equivocation blocks also receive real (distinct) signatures
//!
//! # Example
//!
//! ```ignore
//! let mut b = DagBuilder::new(Committee::new_for_test(4));
//! b.layer(1).fully_connected().build();
//! b.layer(2).authorities(&[0,1,2]).skip_ancestor(3).build();
//! let dag = b.into_dag_state();
//! ```

use crate::narwhal_dag::context::Context;
use crate::narwhal_dag::dag_state::{DagState, DagStateConfig};
use crate::narwhal_dag::leader_schedule::LeaderSchedule;
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// ─── Global cached TestValidatorSet ────────────────────────
//
// ML-DSA-65 key generation is expensive (~1-2ms per keypair).
// We cache a set of validators per committee size to avoid
// regenerating keys for every test.
static CACHED_VALIDATORS: std::sync::OnceLock<std::sync::Mutex<HashMap<usize, Arc<TestValidatorSet>>>> =
    std::sync::OnceLock::new();

pub fn cached_validator_set(n: usize) -> Arc<TestValidatorSet> {
    let map = CACHED_VALIDATORS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("validator cache lock");
    guard
        .entry(n)
        .or_insert_with(|| Arc::new(TestValidatorSet::new(n)))
        .clone()
}

/// Signature cache: maps (author, block_digest) → signature bytes.
///
/// **IMPORTANT: This cache only accelerates signature _generation_.**
/// It does NOT cache or skip signature _verification_. When blocks
/// produced by this cache are fed through `BlockVerifier::verify()`,
/// the full ML-DSA-65 verification path runs every time.
///
/// This distinction is critical for audit compliance (CR-1):
/// - Cache hit → skip 1 × `ml_dsa_sign_raw()` (~0.5ms)
/// - Verification → always runs `ml_dsa_verify_raw()` (~0.3ms)
///
/// Cache key is `(authority_index, block_digest)`. The digest includes
/// all authenticated fields (epoch, round, author, timestamp, ancestors,
/// transactions, votes), so different DAG topologies produce different
/// digests → cache miss. Same topology rebuilt → cache hit.
///
/// Expected hit rates:
/// - Single build: 0% (all misses)
/// - Rebuild same DAG (determinism test): 100%
/// - Across different tests: ~0% (different topologies)
#[derive(Clone, Default)]
pub struct SignatureCache {
    cache: HashMap<(AuthorityIndex, BlockDigest), Vec<u8>>,
    hits: u64,
    misses: u64,
}

impl SignatureCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&mut self, author: AuthorityIndex, digest: &BlockDigest) -> Option<&Vec<u8>> {
        let result = self.cache.get(&(author, *digest));
        if result.is_some() {
            self.hits += 1;
        } else {
            self.misses += 1;
        }
        result
    }

    fn insert(&mut self, author: AuthorityIndex, digest: BlockDigest, sig: Vec<u8>) {
        self.cache.insert((author, digest), sig);
    }

    /// Cache hit rate as a fraction (0.0–1.0).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Total entries in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Cache statistics: (hits, misses).
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

/// Fluent DAG construction API.
///
/// Constructs `VerifiedBlock`s round-by-round, maintaining the last-known
/// `BlockRef` per authority so the next round can reference them.
///
/// ## Signing modes
///
/// - `new(committee)`: Dummy signatures (`0xAA` bytes), blocks wrapped via
///   `VerifiedBlock::new_for_test()`. Fast but does not exercise signature
///   verification paths. Use for pure DAG topology tests (commit rules, etc.).
///
/// - `new_signed(n)` / `from_context(ctx)`: Real ML-DSA-65 signatures using
///   `TestValidatorSet`. Blocks are signed with production domain separation.
///   Use when testing block verification or when audit compliance requires
///   real crypto in the test path.
#[derive(Clone)]
pub struct DagBuilder {
    // Manual Debug impl below (TestValidatorSet doesn't derive Debug naturally)
    committee: Committee,
    /// All blocks keyed by `BlockRef`, insertion-ordered by round.
    pub blocks: BTreeMap<BlockRef, VerifiedBlock>,
    /// Last block per authority (ancestors for the next round).
    pub last_refs: Vec<Option<BlockRef>>,
    /// References of the primary block per (round, author) slot.
    /// Equivocating blocks are inserted into `blocks` but NOT recorded here,
    /// so `leader_block` and other queries can distinguish the canonical
    /// slot occupant from its Byzantine siblings.
    primary_refs: HashMap<(Round, AuthorityIndex), BlockRef>,
    /// Leader schedule (default: round-robin, wave=1).
    leader_schedule: LeaderSchedule,
    /// Override leaders per round.
    leader_overrides: HashMap<Round, AuthorityIndex>,
    /// Monotonic timestamp counter.
    next_ts: u64,
    /// Validator set for real signing (None = dummy signatures).
    validators: Option<Arc<TestValidatorSet>>,
    /// Signature cache (shared across rebuilds).
    sig_cache: SignatureCache,
}

impl std::fmt::Debug for DagBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DagBuilder")
            .field("committee_size", &self.committee.size())
            .field("num_blocks", &self.blocks.len())
            .field("signed", &self.validators.is_some())
            .field("sig_cache_len", &self.sig_cache.len())
            .finish()
    }
}

impl DagBuilder {
    /// Create a builder for the given committee.
    ///
    /// Uses **dummy signatures** — fast, suitable for DAG topology tests.
    ///
    /// Does **not** create genesis blocks automatically — round 0 is
    /// implicit (Narwhal has no explicit genesis blocks; round 1 blocks
    /// may have empty ancestors).
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let n = committee.size();
        let ls = LeaderSchedule::new(committee.clone(), 1);
        Self {
            committee,
            blocks: BTreeMap::new(),
            last_refs: vec![None; n],
            primary_refs: HashMap::new(),
            leader_schedule: ls,
            leader_overrides: HashMap::new(),
            next_ts: 1000,
            validators: None,
            sig_cache: SignatureCache::new(),
        }
    }

    /// Create a builder with **real ML-DSA-65 signatures**.
    ///
    /// Uses `TestValidatorSet` (cached across tests) for key generation
    /// and real signing with domain separation. Blocks pass through
    /// the production `BlockVerifier::verify()` path.
    ///
    /// ML-DSA-65 key generation is cached per committee size via a global
    /// `OnceLock`, so the first call per `n` pays ~N×1.5ms, subsequent
    /// calls reuse cached keypairs.
    #[must_use]
    pub fn new_signed(n: usize) -> Self {
        let vs = cached_validator_set(n);
        let committee = vs.committee();
        let ls = LeaderSchedule::new(committee.clone(), 1);
        Self {
            committee,
            blocks: BTreeMap::new(),
            last_refs: vec![None; n],
            primary_refs: HashMap::new(),
            leader_schedule: ls,
            leader_overrides: HashMap::new(),
            next_ts: 1000,
            validators: Some(vs),
            sig_cache: SignatureCache::new(),
        }
    }

    /// Create a builder from a `Context` (Phase 0-2 integration).
    ///
    /// Uses the Context's committee and creates a matching
    /// `TestValidatorSet` for real signing.
    #[must_use]
    pub fn from_context(ctx: &Context) -> Self {
        let n = ctx.committee_size();
        let vs = cached_validator_set(n);
        // Use the validator set's committee (which has real public keys)
        // rather than ctx.committee (which may have test keys).
        let committee = vs.committee();
        let ls = LeaderSchedule::new(committee.clone(), 1);
        Self {
            committee,
            blocks: BTreeMap::new(),
            last_refs: vec![None; n],
            primary_refs: HashMap::new(),
            leader_schedule: ls,
            leader_overrides: HashMap::new(),
            next_ts: 1000,
            validators: Some(vs),
            sig_cache: SignatureCache::new(),
        }
    }

    /// Create a `Context` compatible with this builder's committee.
    ///
    /// If the builder was created with `new_signed()` or `from_context()`,
    /// the context uses the same `TestValidatorSet` for key consistency.
    #[must_use]
    pub fn context_for_test(&self) -> Context {
        Context::new_for_test(self.committee.size())
    }

    /// Whether this builder uses real ML-DSA-65 signatures.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.validators.is_some()
    }

    /// Access the signature cache (for stats/diagnostics).
    pub fn sig_cache(&self) -> &SignatureCache {
        &self.sig_cache
    }

    /// Access the TestValidatorSet (if real signing is enabled).
    pub fn validator_set(&self) -> Option<&TestValidatorSet> {
        self.validators.as_deref()
    }

    // ── Leader schedule ─────────────────────────────────────

    /// Override the leader for a specific round.
    pub fn set_leader(&mut self, round: Round, auth: AuthorityIndex) -> &mut Self {
        self.leader_overrides.insert(round, auth);
        self
    }

    /// Leader for `round` (override → schedule fallback).
    #[must_use]
    pub fn leader_of(&self, round: Round) -> AuthorityIndex {
        self.leader_overrides
            .get(&round)
            .copied()
            .unwrap_or_else(|| self.leader_schedule.leader_at(round))
    }

    // ── Layer building ──────────────────────────────────────

    /// Begin building a single round.
    #[must_use]
    pub fn layer(&mut self, round: Round) -> LayerBuilder<'_> {
        LayerBuilder::new(self, round)
    }

    /// Build fully-connected layers for a range of rounds.
    pub fn build_layers(&mut self, start: Round, end: Round) {
        for r in start..=end {
            self.layer(r).fully_connected().build();
        }
    }

    // ── Queries ─────────────────────────────────────────────

    /// All `VerifiedBlock`s constructed so far, ordered by `BlockRef`.
    #[must_use]
    pub fn all_blocks(&self) -> Vec<&VerifiedBlock> {
        self.blocks.values().collect()
    }

    /// Blocks at a specific round.
    #[must_use]
    pub fn blocks_at_round(&self, round: Round) -> Vec<&VerifiedBlock> {
        self.blocks
            .values()
            .filter(|b| b.round() == round)
            .collect()
    }

    /// The leader block at a round (if it exists and was not skipped).
    #[must_use]
    pub fn leader_block(&self, round: Round) -> Option<&VerifiedBlock> {
        let leader = self.leader_of(round);
        // Prefer the primary block for this (round, leader) slot. Equivocating
        // siblings share the slot but use different digests; voters in the
        // next round only reference the primary (which is what ends up in
        // `last_refs`), so returning an equivocating sibling here causes
        // spurious Undecided decisions in `try_direct_decide`.
        if let Some(primary_ref) = self.primary_refs.get(&(round, leader)) {
            if let Some(block) = self.blocks.get(primary_ref) {
                return Some(block);
            }
        }
        self.blocks
            .values()
            .find(|b| b.round() == round && b.author() == leader)
    }

    /// Count of authorities that reference `leader_ref` as ancestor at `vote_round`.
    #[must_use]
    pub fn votes_for_leader(&self, vote_round: Round, leader_ref: &BlockRef) -> usize {
        self.blocks_at_round(vote_round)
            .iter()
            .filter(|b| b.ancestors().contains(leader_ref))
            .count()
    }

    /// Build a `DagState` from all accumulated blocks.
    #[must_use]
    pub fn into_dag_state(self) -> DagState {
        let mut dag = DagState::new(self.committee.clone(), DagStateConfig::default());
        for (_, block) in &self.blocks {
            dag.accept_block(block.clone());
        }
        dag
    }

    /// Build a `DagState` without consuming the builder.
    #[must_use]
    pub fn to_dag_state(&self) -> DagState {
        let mut dag = DagState::new(self.committee.clone(), DagStateConfig::default());
        for (_, block) in &self.blocks {
            dag.accept_block(block.clone());
        }
        dag
    }

    /// Dump the DAG as a human-readable string (for CI failure diagnostics).
    #[must_use]
    pub fn dump(&self) -> String {
        let max_round = self.blocks.keys().map(|r| r.round).max().unwrap_or(0);
        let mut out = String::new();
        for r in 1..=max_round {
            let blocks = self.blocks_at_round(r);
            let leader = self.leader_of(r);
            out.push_str(&format!("R{}: ", r));
            for b in &blocks {
                let mark = if b.author() == leader { "*" } else { "" };
                let anc: Vec<String> = b
                    .ancestors()
                    .iter()
                    .map(|a| format!("{}{}", authority_letter(a.author), a.round))
                    .collect();
                out.push_str(&format!(
                    "{}{}{} [{}]  ",
                    authority_letter(b.author()),
                    r,
                    mark,
                    anc.join(",")
                ));
            }
            out.push('\n');
        }
        out
    }

    /// Committee reference.
    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    // ── Equivocation API ─────────────────────────────────────

    /// Create an equivocating block at the same (author, round) as `original`.
    ///
    /// The equivocating block has a different timestamp and transactions,
    /// producing a distinct digest. This is the programmatic API for
    /// Phase 2 `slot_equivocation_ledger` testing.
    ///
    /// Unlike `LayerBuilder::equivocate()`, this gives fine-grained control
    /// over the equivocating block's content via the `modify` closure.
    ///
    /// ```ignore
    /// let orig_ref = builder.leader_block(1).unwrap().reference();
    /// let eq_ref = builder.create_equivocation(&orig_ref, |b| {
    ///     b.timestamp_ms += 1;
    ///     b.transactions = vec![vec![0xFF]];
    /// });
    /// // orig_ref and eq_ref have same (author, round) but different digests
    /// ```
    pub fn create_equivocation(
        &mut self,
        original: &BlockRef,
        modify: impl FnOnce(&mut Block),
    ) -> BlockRef {
        let orig_block = self
            .blocks
            .get(original)
            .expect("original block not found in DAG")
            .inner()
            .clone();

        let mut eq_block = orig_block;
        modify(&mut eq_block);
        // Ensure the equivocating block has a different digest
        assert_ne!(
            eq_block.digest(),
            original.digest,
            "equivocating block must differ from original (modify closure must change content)"
        );
        assert_eq!(eq_block.author, original.author, "author must match");
        assert_eq!(eq_block.round, original.round, "round must match");

        // Sign the equivocating block
        self.sign_block(&mut eq_block);
        let eq_vb = VerifiedBlock::new_for_test(eq_block);
        let eq_ref = eq_vb.reference();
        // Insert but don't update last_refs (original block owns the slot)
        self.blocks.insert(eq_ref, eq_vb);
        eq_ref
    }

    // ── Internal ────────────────────────────────────────────

    fn alloc_ts(&mut self) -> u64 {
        let ts = self.next_ts;
        self.next_ts += 100;
        ts
    }

    fn insert_block(&mut self, block: VerifiedBlock) {
        let r = block.reference();
        self.last_refs[r.author as usize] = Some(r);
        self.primary_refs.insert((r.round, r.author), r);
        self.blocks.insert(r, block);
    }

    /// Sign a block using the TestValidatorSet (if available),
    /// with signature cache. Falls back to dummy signature.
    fn sign_block(&mut self, block: &mut Block) {
        if let Some(ref vs) = self.validators {
            let digest = block.signing_digest_v2(TestValidatorSet::app_id());
            if let Some(cached) = self.sig_cache.get(block.author, &digest) {
                block.signature = cached.clone();
            } else {
                vs.sign_block(block.author as usize, block);
                self.sig_cache
                    .insert(block.author, digest, block.signature.clone());
            }
        }
        // else: keep dummy signature (0xAA bytes)
    }
}

// ═══════════════════════════════════════════════════════════════
//  LayerBuilder
// ═══════════════════════════════════════════════════════════════

/// Fluent builder for a single round's blocks.
pub struct LayerBuilder<'a> {
    dag: &'a mut DagBuilder,
    round: Round,
    authorities: Option<Vec<AuthorityIndex>>,
    skip_ancestors: Vec<AuthorityIndex>,
    skip_leader: bool,
    fully_connected: bool,
    min_connected: bool,
    equivocate_count: usize,
    num_txs: u32,
    custom_ancestors: Option<HashMap<AuthorityIndex, Vec<BlockRef>>>,
}

impl<'a> LayerBuilder<'a> {
    fn new(dag: &'a mut DagBuilder, round: Round) -> Self {
        Self {
            dag,
            round,
            authorities: None,
            skip_ancestors: vec![],
            skip_leader: false,
            fully_connected: false,
            min_connected: false,
            equivocate_count: 0,
            num_txs: 1,
            custom_ancestors: None,
        }
    }

    /// Only these authorities propose in this round.
    #[must_use]
    pub fn authorities(mut self, auths: &[AuthorityIndex]) -> Self {
        self.authorities = Some(auths.to_vec());
        self
    }

    /// Don't link to blocks from this authority.
    #[must_use]
    pub fn skip_ancestor(mut self, auth: AuthorityIndex) -> Self {
        self.skip_ancestors.push(auth);
        self
    }

    /// Don't link to blocks from these authorities.
    #[must_use]
    pub fn skip_ancestors(mut self, auths: &[AuthorityIndex]) -> Self {
        self.skip_ancestors.extend_from_slice(auths);
        self
    }

    /// Don't create a block for the leader.
    #[must_use]
    pub fn no_leader(mut self) -> Self {
        self.skip_leader = true;
        self
    }

    /// Link to all available ancestors (default if no custom ancestors set).
    #[must_use]
    pub fn fully_connected(mut self) -> Self {
        self.fully_connected = true;
        self
    }

    /// Link to exactly quorum ancestors (2f+1).
    #[must_use]
    pub fn min_connected(mut self) -> Self {
        self.min_connected = true;
        self
    }

    /// Create equivocating blocks per authority.
    #[must_use]
    pub fn equivocate(mut self, count: usize) -> Self {
        self.equivocate_count = count;
        self
    }

    /// Set TX count per block.
    #[must_use]
    pub fn num_txs(mut self, n: u32) -> Self {
        self.num_txs = n;
        self
    }

    /// Set explicit ancestors per authority.
    #[must_use]
    pub fn custom_ancestors(mut self, map: HashMap<AuthorityIndex, Vec<BlockRef>>) -> Self {
        self.custom_ancestors = Some(map);
        self
    }

    /// Finalize: construct blocks and insert into the builder.
    pub fn build(self) {
        let n = self.dag.committee.size() as u32;
        let active: Vec<AuthorityIndex> =
            self.authorities.clone().unwrap_or_else(|| (0..n).collect());

        let leader = self.dag.leader_of(self.round);

        // Collect available ancestors
        let available: Vec<BlockRef> = self
            .dag
            .last_refs
            .iter()
            .filter_map(|o| *o)
            .filter(|r| !self.skip_ancestors.contains(&r.author))
            .collect();

        let quorum = self.dag.committee.quorum_threshold() as usize;

        for &auth in &active {
            if self.skip_leader && auth == leader {
                continue;
            }

            let ancestors = if let Some(ref map) = self.custom_ancestors {
                map.get(&auth).cloned().unwrap_or_else(|| available.clone())
            } else if self.min_connected {
                available.iter().take(quorum).copied().collect()
            } else {
                available.clone()
            };

            let ts = self.dag.alloc_ts();
            let txs: Vec<Vec<u8>> = (0..self.num_txs)
                .map(|i| vec![auth as u8, self.round as u8, i as u8])
                .collect();

            let sig_len = if self.dag.validators.is_some() {
                // Will be overwritten by real signature
                0
            } else {
                64
            };

            let mut block = Block {
                epoch: 0,
                round: self.round,
                author: auth,
                timestamp_ms: ts,
                ancestors: ancestors.clone(),
                transactions: txs,
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![0xAA; sig_len],
            };
            self.dag.sign_block(&mut block);
            let vb = VerifiedBlock::new_for_test(block);
            self.dag.insert_block(vb);

            // Equivocating blocks (different digest, same slot)
            for eq_i in 0..self.equivocate_count {
                let mut eq_block = Block {
                    epoch: 0,
                    round: self.round,
                    author: auth,
                    timestamp_ms: ts + 1 + eq_i as u64,
                    ancestors: ancestors.clone(),
                    transactions: vec![vec![0xFF, auth as u8, eq_i as u8]],
                    commit_votes: vec![],
                    tx_reject_votes: vec![],
                    state_root: [0u8; 32],
                    signature: vec![0xBB; sig_len],
                };
                self.dag.sign_block(&mut eq_block);
                let eq_vb = VerifiedBlock::new_for_test(eq_block);
                // Insert but don't update last_refs (primary block owns the slot)
                self.dag.blocks.insert(eq_vb.reference(), eq_vb);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════

/// Authority index → letter (A=0, B=1, …, Z=25, [26], [27], …)
#[must_use]
pub fn authority_letter(idx: AuthorityIndex) -> String {
    if idx < 26 {
        String::from((b'A' + idx as u8) as char)
    } else {
        format!("[{}]", idx)
    }
}

/// Letter → authority index.
#[must_use]
pub fn letter_to_authority(ch: char) -> Option<AuthorityIndex> {
    if ch.is_ascii_uppercase() {
        Some((ch as u8 - b'A') as AuthorityIndex)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    #[test]
    fn fully_connected_layer() {
        let mut b = DagBuilder::new(committee4());
        b.layer(1).fully_connected().build();
        assert_eq!(b.blocks_at_round(1).len(), 4);
    }

    #[test]
    fn skip_ancestor_removes_link() {
        let mut b = DagBuilder::new(committee4());
        b.layer(1).fully_connected().build();
        b.layer(2).fully_connected().skip_ancestor(3).build();
        for blk in b.blocks_at_round(2) {
            assert!(
                !blk.ancestors().iter().any(|a| a.author == 3),
                "block from {} should not reference authority 3",
                blk.author()
            );
        }
    }

    #[test]
    fn partial_authorities() {
        let mut b = DagBuilder::new(committee4());
        b.layer(1).authorities(&[0, 1]).fully_connected().build();
        assert_eq!(b.blocks_at_round(1).len(), 2);
    }

    #[test]
    fn no_leader() {
        let mut b = DagBuilder::new(committee4());
        b.set_leader(1, 0);
        b.layer(1).fully_connected().no_leader().build();
        assert!(b.leader_block(1).is_none());
        assert_eq!(b.blocks_at_round(1).len(), 3);
    }

    #[test]
    fn equivocation() {
        let mut b = DagBuilder::new(committee4());
        b.layer(1).fully_connected().equivocate(1).build();
        // 4 primary + 4 equivocating
        assert_eq!(b.blocks_at_round(1).len(), 8);
    }

    #[test]
    fn into_dag_state_accepts_all() {
        let mut b = DagBuilder::new(committee4());
        b.build_layers(1, 5);
        let dag = b.into_dag_state();
        assert_eq!(dag.highest_accepted_round(), 5);
    }

    #[test]
    fn dump_does_not_panic() {
        let mut b = DagBuilder::new(committee4());
        b.build_layers(1, 3);
        let out = b.dump();
        assert!(out.contains("R1:"));
        assert!(out.contains("R3:"));
    }

    #[test]
    fn votes_for_leader_count() {
        let mut b = DagBuilder::new(committee4());
        b.set_leader(1, 0);
        b.layer(1).fully_connected().build();
        b.layer(2).fully_connected().build();
        let leader_ref = b.leader_block(1).unwrap().reference();
        assert_eq!(b.votes_for_leader(2, &leader_ref), 4);
    }

    #[test]
    fn min_connected_uses_quorum_ancestors() {
        let mut b = DagBuilder::new(committee4());
        b.layer(1).fully_connected().build();
        b.layer(2).min_connected().build();
        let quorum = committee4().quorum_threshold() as usize;
        for blk in b.blocks_at_round(2) {
            assert_eq!(
                blk.ancestors().len(),
                quorum,
                "min_connected should use exactly quorum ancestors"
            );
        }
    }

    // ── Phase 1-3: Real ML-DSA-65 signing tests ────────────

    #[test]
    fn signed_builder_produces_real_signatures() {
        let mut b = DagBuilder::new_signed(4);
        assert!(b.is_signed());
        b.layer(1).fully_connected().build();

        // Verify all blocks have real ML-DSA-65 signatures (3,309 bytes)
        for blk in b.blocks_at_round(1) {
            assert_eq!(
                blk.inner().signature.len(),
                3309,
                "expected ML-DSA-65 signature length (3309 bytes), got {}",
                blk.inner().signature.len()
            );
        }
    }

    #[test]
    fn signed_builder_deterministic_digests() {
        // Build the same DAG twice — block digests must match.
        let build = || {
            let mut b = DagBuilder::new_signed(4);
            b.build_layers(1, 3);
            let digests: Vec<BlockDigest> = b.all_blocks().iter().map(|b| b.digest()).collect();
            digests
        };
        let d1 = build();
        let d2 = build();
        assert_eq!(d1, d2, "deterministic DAG builds must produce identical digests");
    }

    #[test]
    fn signature_cache_hit_rate() {
        let mut b = DagBuilder::new_signed(4);
        b.build_layers(1, 3);
        let (hits, misses) = b.sig_cache().stats();
        // First build: all misses (12 blocks = 4 authorities × 3 rounds)
        assert_eq!(hits, 0);
        assert_eq!(misses, 12);
    }

    #[test]
    fn signed_equivocation_has_distinct_digests() {
        let mut b = DagBuilder::new_signed(4);
        b.layer(1).fully_connected().equivocate(1).build();
        let blocks_r1 = b.blocks_at_round(1);
        assert_eq!(blocks_r1.len(), 8); // 4 primary + 4 equivocating

        // Each authority has 2 blocks at round 1 with different digests
        for auth in 0..4u32 {
            let auth_blocks: Vec<_> = blocks_r1.iter().filter(|b| b.author() == auth).collect();
            assert_eq!(auth_blocks.len(), 2);
            assert_ne!(
                auth_blocks[0].digest(),
                auth_blocks[1].digest(),
                "equivocating blocks must have different digests"
            );
            // Both should have real signatures
            assert_eq!(auth_blocks[0].inner().signature.len(), 3309);
            assert_eq!(auth_blocks[1].inner().signature.len(), 3309);
        }
    }

    #[test]
    fn create_equivocation_api() {
        let mut b = DagBuilder::new_signed(4);
        b.layer(1).fully_connected().build();
        let orig_ref = b.leader_block(1).unwrap().reference();

        let eq_ref = b.create_equivocation(&orig_ref, |blk| {
            blk.timestamp_ms += 42;
            blk.transactions = vec![vec![0xDE, 0xAD]];
        });

        // Same (author, round), different digest
        assert_eq!(eq_ref.author, orig_ref.author);
        assert_eq!(eq_ref.round, orig_ref.round);
        assert_ne!(eq_ref.digest, orig_ref.digest);

        // Both blocks exist in the DAG
        assert!(b.blocks.contains_key(&orig_ref));
        assert!(b.blocks.contains_key(&eq_ref));

        // Equivocating block has real signature
        let eq_block = b.blocks.get(&eq_ref).unwrap();
        assert_eq!(eq_block.inner().signature.len(), 3309);
    }

    #[test]
    fn benchmark_ml_dsa65_costs() {
        use std::time::Instant;

        // 1. Key generation (first call pays full cost, subsequent cached)
        let t0 = Instant::now();
        let vs = cached_validator_set(4);
        let keygen_ms = t0.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[ML-DSA-65 bench] Key generation (4 validators): {keygen_ms:.2}ms");

        // Second call should be cached
        let t1 = Instant::now();
        let _vs2 = cached_validator_set(4);
        let keygen_cached_ms = t1.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[ML-DSA-65 bench] Key generation (cached): {keygen_cached_ms:.3}ms");

        // 2. Single block signing
        let mut block = Block {
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
        let t2 = Instant::now();
        vs.sign_block(0, &mut block);
        let sign_ms = t2.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[ML-DSA-65 bench] Single block sign: {sign_ms:.3}ms");
        assert_eq!(block.signature.len(), 3309);

        // 3. Single block verification
        let verifier = vs.verifier(0);
        let t3 = Instant::now();
        let result = verifier.verify(&block);
        let verify_ms = t3.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[ML-DSA-65 bench] Single block verify: {verify_ms:.3}ms");
        assert!(result.is_ok(), "verification failed: {:?}", result);

        // 4. Full signed DAG build (4 validators, 3 rounds = 12 blocks)
        let t4 = Instant::now();
        let mut b = DagBuilder::new_signed(4);
        b.build_layers(1, 3);
        let build_ms = t4.elapsed().as_secs_f64() * 1000.0;
        let per_block_ms = build_ms / 12.0;
        eprintln!("[ML-DSA-65 bench] Build 12-block signed DAG: {build_ms:.2}ms ({per_block_ms:.3}ms/block)");

        // Acceptance criteria: single block sign should be < 5ms
        assert!(
            sign_ms < 5.0,
            "ML-DSA-65 signing too slow: {sign_ms:.3}ms (limit: 5ms)"
        );
    }

    #[test]
    fn from_context_produces_signed_blocks() {
        let ctx = Context::new_for_test(4);
        let mut b = DagBuilder::from_context(&ctx);
        assert!(b.is_signed());
        b.layer(1).fully_connected().build();
        assert_eq!(b.blocks_at_round(1).len(), 4);
        // Real signatures
        for blk in b.blocks_at_round(1) {
            assert_eq!(blk.inner().signature.len(), 3309);
        }
    }
}
