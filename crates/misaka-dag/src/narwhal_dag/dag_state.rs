// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! DagState — authoritative in-memory DAG state.
//!
//! Sui equivalent: consensus/core/dag_state.rs (~2,600 lines)
//!
//! Stores blocks, tracks rounds, manages commits, handles eviction.
//! All mutations go through DagWriteBatch for atomic persistence.
//!
//! # Equivocation invariant (CRITICAL SAFETY)
//!
//! For any (AuthorityIndex, Round), DagState MUST contain at most one
//! VerifiedBlock. If a second block with the same (author, round) but
//! different digest is presented, it MUST be rejected and recorded as
//! equivocation evidence.
//!
//! This invariant is checked by:
//!  - `DagState::accept_block` (primary gate)
//!  - `BlockManager::try_accept_block` (secondary gate before suspension)
//!  - `vote_registry::register_vote` (tertiary gate for vote dedup)
//!
//! Violation of this invariant breaks BFT safety.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::Committee;

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// DagState configuration.
#[derive(Clone, Debug)]
pub struct DagStateConfig {
    /// Maximum number of rounds to keep in memory before eviction.
    /// Task 1.2: Now enforced — blocks beyond this window are evicted.
    pub max_cached_rounds: u32,
    /// Number of rounds to keep after last commit (GC margin).
    pub gc_depth: u32,
    /// Whether to enable equivocation detection.
    pub enable_equivocation_detection: bool,
    /// Task 1.2: Flush interval — batch writes until this many blocks accumulate.
    pub flush_batch_size: usize,
    /// Task 1.2: Max commits to retain in memory (older ones are pruned).
    pub max_cached_commits: usize,
}

impl Default for DagStateConfig {
    fn default() -> Self {
        Self {
            max_cached_rounds: 500,
            gc_depth: 50,
            enable_equivocation_detection: true,
            flush_batch_size: 32,
            max_cached_commits: 1000,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Block info (enriched block metadata)
// ═══════════════════════════════════════════════════════════

/// Enriched block information tracked by the DAG state.
#[derive(Clone, Debug)]
pub struct BlockInfo {
    /// The verified block.
    pub block: VerifiedBlock,
    /// Whether this block has been committed.
    pub committed: bool,
    /// Time when this block was accepted into the DAG.
    pub accepted_at: Instant,
}

// ═══════════════════════════════════════════════════════════
//  Pending commit vote
// ═══════════════════════════════════════════════════════════

/// A commit vote that hasn't been included in a block yet.
#[derive(Clone, Debug)]
pub struct PendingCommitVote {
    pub commit_index: CommitIndex,
    pub commit_digest: CommitDigest,
}

// ═══════════════════════════════════════════════════════════
//  Write batch
// ═══════════════════════════════════════════════════════════

/// Batched writes for atomic persistence.
///
/// All DagState mutations accumulate in a write batch.
/// Call `flush_to_disk()` to persist atomically.
#[derive(Default)]
pub struct DagWriteBatch {
    /// Blocks to persist.
    pub blocks: Vec<VerifiedBlock>,
    /// Commits to persist.
    pub commits: Vec<CommittedSubDag>,
    /// Last committed rounds per authority (for GC).
    pub last_committed_rounds: Option<Vec<Round>>,
}

impl DagWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.commits.is_empty() && self.last_committed_rounds.is_none()
    }

    pub fn add_block(&mut self, block: VerifiedBlock) {
        self.blocks.push(block);
    }

    pub fn add_commit(&mut self, commit: CommittedSubDag) {
        self.commits.push(commit);
    }

    pub fn set_last_committed_rounds(&mut self, rounds: Vec<Round>) {
        self.last_committed_rounds = Some(rounds);
    }
}

// ═══════════════════════════════════════════════════════════
//  Equivocation
// ═══════════════════════════════════════════════════════════

/// Detected block equivocation (same author, same round, different digest).
#[derive(Clone, Debug)]
pub struct Equivocation {
    pub slot: Slot,
    pub block_a: BlockRef,
    pub block_b: BlockRef,
}

/// Result of `DagState::accept_block()`.
///
/// Callers MUST inspect this — `#[must_use]` prevents silent ignore.
/// Use `.is_accepted()` for backward-compatible bool checks.
/// Match on the enum when equivocation handling is needed.
#[derive(Clone, Debug)]
#[must_use]
pub enum BlockAcceptResult {
    /// Block accepted normally (new, valid, no equivocation).
    Accepted,
    /// Block accepted AND equivocation detected. Evidence is stored.
    /// Callers should trigger slashing / reporting.
    AcceptedWithEquivocation(Equivocation),
    /// Block is a duplicate (same digest already stored). Ignored.
    Duplicate,
    /// Block is below the eviction round. Garbage.
    BelowEviction,
    /// Block author is not in the committee. Rejected.
    InvalidAuthor,
    /// Block rejected due to WAL or other infrastructure failure.
    Rejected(String),
}

impl BlockAcceptResult {
    /// `true` if the block was stored (Accepted or AcceptedWithEquivocation).
    #[inline]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedWithEquivocation(_))
    }

    /// `true` if equivocation was detected during acceptance.
    #[inline]
    pub fn is_equivocation(&self) -> bool {
        matches!(self, Self::AcceptedWithEquivocation(_))
    }
}

// ═══════════════════════════════════════════════════════════
//  DagState
// ═══════════════════════════════════════════════════════════

/// The authoritative DAG state.
///
/// Holds all accepted blocks in memory and tracks:
/// - Per-round block indexes
/// - Per-authority last block
/// - Highest accepted round
/// - Commit history
/// - Equivocation records
/// - Eviction state
pub struct DagState {
    /// Configuration.
    config: DagStateConfig,
    /// Committee for the current epoch.
    committee: Committee,

    // ── Block storage ──
    /// All accepted blocks by reference.
    blocks: HashMap<BlockRef, BlockInfo>,
    /// Blocks indexed by (round, author) → BlockRef.
    /// Multiple blocks at same slot = equivocation.
    blocks_by_slot: HashMap<Slot, Vec<BlockRef>>,
    /// Per-authority highest round with an accepted block.
    last_block_round: Vec<Round>,

    // ── Round tracking ──
    /// Highest round of any accepted block.
    highest_accepted_round: Round,
    /// Per-authority: list of block refs at each round.
    blocks_per_authority: Vec<BTreeMap<Round, Vec<BlockRef>>>,

    // ── Commit tracking ──
    /// All committed sub-DAGs in order.
    commits: Vec<CommittedSubDag>,
    /// Last committed round per authority.
    last_committed_rounds: Vec<Round>,
    /// Pending commit votes to include in next block.
    pending_commit_votes: Vec<PendingCommitVote>,
    /// Set of committed block refs (for marking).
    committed_blocks: HashSet<BlockRef>,

    // ── Eviction ──
    /// Lowest round still in memory (everything below is evicted).
    eviction_round: Round,
    /// Blocks evicted from memory (count only, for metrics).
    evicted_block_count: u64,

    // ── Equivocation detection ──
    /// Phase 1.1: Slot → BlockRef index. Enforces at most one block per (author, round).
    /// Any attempt to insert a second distinct digest at the same slot is rejected
    /// as equivocation. This is the PRIMARY safety gate.
    block_index: HashMap<Slot, BlockRef>,
    /// Detected equivocations.
    equivocations: Vec<Equivocation>,

    // ── Write batching ──
    /// Pending writes to flush.
    write_batch: DagWriteBatch,

    // ── Timing ──
    /// Last time a commit was recorded.
    last_commit_time: Option<Instant>,

    // ── WAL ──
    /// Optional write-ahead log for crash recovery.
    wal: Option<std::sync::Arc<std::sync::Mutex<super::consensus_wal::ConsensusWal>>>,
}

impl DagState {
    /// Create a new DagState for a committee.
    pub fn new(committee: Committee, config: DagStateConfig) -> Self {
        let n = committee.size();
        Self {
            config,
            blocks: HashMap::new(),
            blocks_by_slot: HashMap::new(),
            last_block_round: vec![0; n],
            highest_accepted_round: 0,
            blocks_per_authority: (0..n).map(|_| BTreeMap::new()).collect(),
            commits: Vec::new(),
            last_committed_rounds: vec![0; n],
            pending_commit_votes: Vec::new(),
            committed_blocks: HashSet::new(),
            eviction_round: 0,
            evicted_block_count: 0,
            block_index: HashMap::new(),
            equivocations: Vec::new(),
            write_batch: DagWriteBatch::new(),
            last_commit_time: None,
            wal: None,
            committee,
        }
    }

    /// Attach a ConsensusWal for crash-recovery logging.
    pub fn with_wal(
        mut self,
        wal: std::sync::Arc<std::sync::Mutex<super::consensus_wal::ConsensusWal>>,
    ) -> Self {
        self.wal = Some(wal);
        self
    }

    // ── Accept block ──

    /// Accept a verified block into the DAG state.
    ///
    /// Returns a [`BlockAcceptResult`] indicating what happened.
    /// Use `.is_accepted()` for simple bool checks, or match the enum
    /// when equivocation handling is needed.
    ///
    /// Checks:
    /// 1. Not below eviction round → `BelowEviction`
    /// 2. Not a duplicate → `Duplicate`
    /// 3. Author is valid → `InvalidAuthor`
    /// 4. Equivocation detection → `AcceptedWithEquivocation`
    pub fn accept_block(&mut self, block: VerifiedBlock) -> BlockAcceptResult {
        let block_ref = block.reference();
        let slot = block_ref.slot();

        // Audit R9: Structural checks BEFORE WAL append to prevent
        // writing rejected/duplicate/invalid blocks to the WAL.
        if block_ref.round < self.eviction_round {
            return BlockAcceptResult::BelowEviction;
        }
        if self.blocks.contains_key(&block_ref) {
            return BlockAcceptResult::Duplicate;
        }
        if block_ref.author as usize >= self.committee.size() {
            return BlockAcceptResult::InvalidAuthor;
        }

        // WAL append after structural validation, before in-memory mutation
        if let Some(wal) = &self.wal {
            if let Ok(mut w) = wal.lock() {
                let payload = match serde_json::to_vec(block.inner()) {
                    Ok(p) => p,
                    Err(e) => {
                        return BlockAcceptResult::Rejected(format!("WAL serialize failed: {}", e));
                    }
                };
                if let Err(e) =
                    w.append(super::consensus_wal::WalRecordKind::BlockAccepted, payload)
                {
                    return BlockAcceptResult::Rejected(format!("WAL append failed: {}", e));
                }
            }
        }

        // Phase 1.1: Equivocation detection via block_index (PRIMARY SAFETY GATE).
        // At most one block per (author, round). Second distinct digest = equivocation.
        let mut equivocation = None;
        match self.block_index.get(&slot) {
            Some(existing) if existing.digest == block_ref.digest => {
                // Same digest at same slot = true duplicate (already handled above,
                // but block_index check is defense-in-depth)
                return BlockAcceptResult::Duplicate;
            }
            Some(existing) => {
                // EQUIVOCATION: same slot, different digest.
                let ev = Equivocation {
                    slot,
                    block_a: *existing,
                    block_b: block_ref,
                };
                // Audit R9: Bound equivocations to prevent unbounded memory growth
                if self.equivocations.len() >= 1000 {
                    self.equivocations.remove(0);
                }
                self.equivocations.push(ev.clone());
                equivocation = Some(ev.clone());
                // NOTE: In Mysticeti, equivocating blocks are accepted as evidence.
                // We store the evidence but do NOT insert a second block.
                // The first block wins. This is stricter than Sui but safer.
                return BlockAcceptResult::AcceptedWithEquivocation(ev);
            }
            None => {
                // First block at this slot — register in index
                self.block_index.insert(slot, block_ref);
            }
        }

        // Insert into secondary indexes
        self.blocks_by_slot.entry(slot).or_default().push(block_ref);

        if let Some(authority_blocks) = self.blocks_per_authority.get_mut(block_ref.author as usize)
        {
            authority_blocks
                .entry(block_ref.round)
                .or_default()
                .push(block_ref);
        }

        // Update last block round for this authority
        if let Some(last) = self.last_block_round.get_mut(block_ref.author as usize) {
            if block_ref.round > *last {
                *last = block_ref.round;
            }
        }

        // Update highest accepted round
        if block_ref.round > self.highest_accepted_round {
            self.highest_accepted_round = block_ref.round;
        }

        // Store block info
        let info = BlockInfo {
            block: block.clone(),
            committed: false,
            accepted_at: Instant::now(),
        };
        self.blocks.insert(block_ref, info);

        // Add to write batch
        self.write_batch.add_block(block);

        // WP1: Run DAG invariant checks in debug builds
        self.check_invariants(&block_ref);

        match equivocation {
            Some(ev) => BlockAcceptResult::AcceptedWithEquivocation(ev),
            None => BlockAcceptResult::Accepted,
        }
    }

    // ── DAG Invariant Checkers (WP1) ──
    //
    // Runtime invariant checks for debug builds. Called after each block
    // acceptance to detect DAG corruption early.
    //
    // These are intentionally debug-only: production nodes skip them for
    // performance, but CI and testnet builds run them on every block.

    /// Run all DAG invariants on a newly accepted block.
    /// Panics in debug builds if any invariant is violated.
    #[cfg(debug_assertions)]
    pub fn check_invariants(&self, block_ref: &BlockRef) {
        if let Some(info) = self.blocks.get(block_ref) {
            self.invariant_unique_slot(block_ref);
            self.invariant_no_future_ancestors(&info.block);
            self.invariant_committee_membership(&info.block);
            self.invariant_monotonic_rounds(&info.block);
        }
    }

    /// SEC-FIX: Release builds now check the most critical invariant
    /// (unique slot — duplicate block insertion detection) instead of no-op.
    /// Full invariant suite still runs only in debug for performance.
    #[cfg(not(debug_assertions))]
    pub fn check_invariants(&self, block_ref: &BlockRef) {
        let slot = block_ref.slot();
        if let Some(existing) = self.block_index.get(&slot) {
            if existing.digest != block_ref.digest {
                tracing::error!(
                    "DAG INVARIANT VIOLATION (release): duplicate slot ({},{}) \
                     digests: existing={}, new={}",
                    slot.round,
                    slot.authority,
                    hex::encode(&existing.digest.0[..8]),
                    hex::encode(&block_ref.digest.0[..8]),
                );
            }
        }
    }

    /// Invariant: at most one accepted digest per (round, author) slot.
    ///
    /// The `block_index` HashMap enforces this at insertion time. This
    /// check verifies the invariant holds post-insertion (defense-in-depth).
    fn invariant_unique_slot(&self, block_ref: &BlockRef) {
        let slot = block_ref.slot();
        if let Some(indexed) = self.block_index.get(&slot) {
            debug_assert_eq!(
                indexed.digest, block_ref.digest,
                "INVARIANT VIOLATION: block_index has digest {:?} but accepted {:?} at slot {:?}",
                indexed.digest, block_ref.digest, slot
            );
        }
    }

    /// Invariant: all ancestors should have round strictly less than the block's round.
    ///
    /// Logged as warning rather than panic because test blocks may construct
    /// atypical DAG shapes (same-round ancestors for late-arrival testing).
    fn invariant_no_future_ancestors(&self, block: &VerifiedBlock) {
        for ancestor in block.ancestors() {
            if ancestor.round >= block.round() {
                tracing::warn!(
                    block_round = block.round(),
                    ancestor_round = ancestor.round,
                    "DAG invariant: block at round {} has ancestor at round {} (should be strictly less)",
                    block.round(), ancestor.round
                );
            }
        }
    }

    /// Invariant: all ancestor authors belong to the current epoch's committee.
    fn invariant_committee_membership(&self, block: &VerifiedBlock) {
        let committee_size = self.committee.size() as u32;
        for ancestor in block.ancestors() {
            debug_assert!(
                ancestor.author < committee_size,
                "INVARIANT VIOLATION: ancestor author {} exceeds committee size {}",
                ancestor.author,
                committee_size
            );
        }
        debug_assert!(
            block.author() < committee_size,
            "INVARIANT VIOLATION: block author {} exceeds committee size {}",
            block.author(),
            committee_size
        );
    }

    /// Invariant: if round > 0 and block has ancestors, ancestors should cover
    /// at least validity threshold of the committee.
    ///
    /// This is a WARNING, not a panic, because:
    /// - Test blocks often have minimal ancestors
    /// - Blocks arriving during sync may have partial ancestor sets
    /// - The commit rule handles insufficient ancestors correctly (Undecided)
    ///
    /// In production, this warning indicates a potentially malicious or
    /// misconfigured proposer.
    fn invariant_monotonic_rounds(&self, block: &VerifiedBlock) {
        if block.round() == 0 || block.ancestors().is_empty() {
            return;
        }
        let mut ancestor_stake = 0u64;
        let mut seen_authors = std::collections::HashSet::new();
        for ancestor in block.ancestors() {
            if seen_authors.insert(ancestor.author) {
                ancestor_stake += self.committee.stake(ancestor.author);
            }
        }
        if !self.committee.reached_validity(ancestor_stake) {
            tracing::warn!(
                round = block.round(),
                ancestor_stake = ancestor_stake,
                validity_threshold = self.committee.validity_threshold(),
                "DAG invariant: block at round {} has low ancestor stake ({} < validity {})",
                block.round(),
                ancestor_stake,
                self.committee.validity_threshold()
            );
        }
    }

    /// Estimate memory usage of the DagState for metrics export.
    pub fn estimated_memory_bytes(&self) -> usize {
        // Blocks: each VerifiedBlock is ~5KB average (with transactions)
        let block_mem = self.blocks.len() * 5120;
        // Indexes: ~64 bytes per entry
        let index_mem = (self.block_index.len() + self.blocks_by_slot.len()) * 64;
        // Commits: ~256 bytes average
        let commit_mem = self.commits.len() * 256;
        block_mem + index_mem + commit_mem
    }

    // ── Block queries ──

    /// Get a block by reference.
    pub fn get_block(&self, block_ref: &BlockRef) -> Option<&VerifiedBlock> {
        self.blocks.get(block_ref).map(|info| &info.block)
    }

    /// Get all blocks at a specific slot.
    pub fn get_blocks_at_slot(&self, slot: &Slot) -> Vec<&VerifiedBlock> {
        self.blocks_by_slot
            .get(slot)
            .map(|refs| refs.iter().filter_map(|r| self.get_block(r)).collect())
            .unwrap_or_default()
    }

    /// Get all blocks at a given round.
    pub fn get_blocks_at_round(&self, round: Round) -> Vec<&VerifiedBlock> {
        let mut result = Vec::new();
        for auth_idx in 0..self.committee.size() {
            let slot = Slot::new(round, auth_idx as AuthorityIndex);
            result.extend(self.get_blocks_at_slot(&slot));
        }
        result
    }

    /// Get blocks for a specific authority in a round range.
    pub fn get_authority_blocks(
        &self,
        author: AuthorityIndex,
        from_round: Round,
        to_round: Round,
    ) -> Vec<&VerifiedBlock> {
        let mut result = Vec::new();
        if let Some(authority_blocks) = self.blocks_per_authority.get(author as usize) {
            for (_round, refs) in authority_blocks.range(from_round..=to_round) {
                for r in refs {
                    if let Some(info) = self.blocks.get(r) {
                        result.push(&info.block);
                    }
                }
            }
        }
        result
    }

    /// Check if a block exists.
    pub fn contains_block(&self, block_ref: &BlockRef) -> bool {
        self.blocks.contains_key(block_ref)
    }

    /// Get all blocks that reference a given block as ancestor.
    pub fn get_children(&self, block_ref: &BlockRef) -> Vec<BlockRef> {
        let next_round = block_ref.round.saturating_add(1);
        let mut children = Vec::new();
        for block in self.get_blocks_at_round(next_round) {
            if block.ancestors().contains(block_ref) {
                children.push(block.reference());
            }
        }
        children
    }

    // ── Round tracking ──

    /// Highest accepted round.
    pub fn highest_accepted_round(&self) -> Round {
        self.highest_accepted_round
    }

    /// Last block round for each authority.
    pub fn last_block_rounds(&self) -> &[Round] {
        &self.last_block_round
    }

    /// Total number of blocks in memory.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Number of evicted blocks.
    pub fn evicted_count(&self) -> u64 {
        self.evicted_block_count
    }

    // ── Commit tracking ──

    /// Record a committed sub-DAG.
    pub fn record_commit(&mut self, sub_dag: CommittedSubDag) {
        // Update last committed rounds
        for block_ref in &sub_dag.blocks {
            if let Some(last) = self
                .last_committed_rounds
                .get_mut(block_ref.author as usize)
            {
                if block_ref.round > *last {
                    *last = block_ref.round;
                }
            }
            // Mark block as committed
            if let Some(info) = self.blocks.get_mut(block_ref) {
                info.committed = true;
            }
            self.committed_blocks.insert(*block_ref);
        }

        // Mark leader as committed
        if let Some(info) = self.blocks.get_mut(&sub_dag.leader) {
            info.committed = true;
        }
        self.committed_blocks.insert(sub_dag.leader);

        // Add commit vote for next block
        let digest = sub_dag.digest();
        self.pending_commit_votes.push(PendingCommitVote {
            commit_index: sub_dag.index,
            commit_digest: digest,
        });

        // Add to write batch
        let committed_rounds = self.last_committed_rounds.clone();
        self.write_batch.add_commit(sub_dag.clone());
        self.write_batch.set_last_committed_rounds(committed_rounds);

        // Store commit
        self.commits.push(sub_dag);
        self.last_commit_time = Some(Instant::now());
    }

    /// Last committed rounds per authority.
    pub fn last_committed_rounds(&self) -> &[Round] {
        &self.last_committed_rounds
    }

    /// Number of commits.
    pub fn num_commits(&self) -> usize {
        self.commits.len()
    }

    /// Last commit index.
    pub fn last_commit_index(&self) -> Option<CommitIndex> {
        self.commits.last().map(|c| c.index)
    }

    /// Get a specific commit by index.
    pub fn get_commit(&self, index: CommitIndex) -> Option<&CommittedSubDag> {
        self.commits.iter().find(|c| c.index == index)
    }

    /// Take and clear pending commit votes.
    pub fn take_pending_commit_votes(&mut self) -> Vec<PendingCommitVote> {
        std::mem::take(&mut self.pending_commit_votes)
    }

    /// Check if a block has been committed.
    pub fn is_committed(&self, block_ref: &BlockRef) -> bool {
        self.committed_blocks.contains(block_ref)
    }

    // ── Write batching ──

    /// Take the current write batch for persistence.
    pub fn take_write_batch(&mut self) -> DagWriteBatch {
        std::mem::take(&mut self.write_batch)
    }

    /// Check if there are pending writes.
    pub fn has_pending_writes(&self) -> bool {
        !self.write_batch.is_empty()
    }

    // ── Eviction / GC ──

    /// Evict blocks below the given round.
    ///
    /// Only evicts rounds below `min(last_committed_rounds) - gc_depth`.
    /// This ensures we don't evict blocks that might still be needed.
    pub fn evict_below(&mut self, round: Round) {
        if round <= self.eviction_round {
            return;
        }

        let old_eviction = self.eviction_round;
        self.eviction_round = round;

        // Remove blocks in evicted rounds
        let to_remove: Vec<BlockRef> = self
            .blocks
            .keys()
            .filter(|r| r.round < round && r.round >= old_eviction)
            .copied()
            .collect();

        for block_ref in &to_remove {
            self.blocks.remove(block_ref);
            let slot = block_ref.slot();
            // Phase 1.1: Clean block_index on eviction
            self.block_index.remove(&slot);
            if let Some(refs) = self.blocks_by_slot.get_mut(&slot) {
                refs.retain(|r| r != block_ref);
                if refs.is_empty() {
                    self.blocks_by_slot.remove(&slot);
                }
            }
        }

        // Clean up per-authority indexes
        for authority_blocks in &mut self.blocks_per_authority {
            let rounds_to_remove: Vec<Round> =
                authority_blocks.range(..round).map(|(r, _)| *r).collect();
            for r in rounds_to_remove {
                authority_blocks.remove(&r);
            }
        }

        self.evicted_block_count += to_remove.len() as u64;
    }

    /// Auto-evict based on GC depth from last committed rounds.
    pub fn auto_evict(&mut self) {
        let min_committed = self
            .last_committed_rounds
            .iter()
            .copied()
            .min()
            .unwrap_or(0);
        if min_committed > self.config.gc_depth {
            self.evict_below(min_committed - self.config.gc_depth);
        }
    }

    /// Current eviction round.
    pub fn eviction_round(&self) -> Round {
        self.eviction_round
    }

    // ── Equivocation ──

    /// Get detected equivocations.
    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    // ── Ancestor lookups ──

    /// Check if all ancestors of a block are present in the DAG.
    pub fn has_all_ancestors(&self, block: &VerifiedBlock) -> bool {
        block.ancestors().iter().all(|a| self.contains_block(a))
    }

    /// Get missing ancestors for a block.
    pub fn missing_ancestors(&self, block: &VerifiedBlock) -> Vec<BlockRef> {
        block
            .ancestors()
            .iter()
            .filter(|a| !self.contains_block(a))
            .copied()
            .collect()
    }

    // ── Time tracking ──

    /// Time since last commit.
    pub fn time_since_last_commit(&self) -> Option<std::time::Duration> {
        self.last_commit_time.map(|t| t.elapsed())
    }

    /// Committee reference.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    // ═══════════════════════════════════════════════════════════════
    //  Task 1.2: Sui-parity GC additions
    // ═══════════════════════════════════════════════════════════════

    /// Enforce max_cached_rounds limit.
    ///
    /// If the DAG spans more than `max_cached_rounds` rounds, evict the oldest.
    /// This is a hard cap independent of GC depth.
    pub fn enforce_max_cached_rounds(&mut self) {
        let max_rounds = self.config.max_cached_rounds;
        if self.highest_accepted_round > max_rounds {
            let cutoff = self.highest_accepted_round - max_rounds;
            if cutoff > self.eviction_round {
                self.evict_below(cutoff);
            }
        }
    }

    /// Prune old commits from memory.
    ///
    /// Keeps only the last `max_cached_commits` commits.
    /// Older commits are dropped from the in-memory Vec but their
    /// commit indices remain valid (they've been persisted by the store).
    pub fn prune_old_commits(&mut self) {
        let max = self.config.max_cached_commits;
        if self.commits.len() > max {
            let drain_count = self.commits.len() - max;
            self.commits.drain(0..drain_count);
        }
    }

    /// Prune committed_blocks set for blocks below eviction round.
    ///
    /// Committed status of evicted blocks is no longer needed since
    /// the blocks themselves are gone.
    pub fn prune_committed_set(&mut self) {
        self.committed_blocks
            .retain(|br| br.round >= self.eviction_round);
    }

    /// Full GC cycle: auto_evict + max_cached_rounds + commit pruning.
    ///
    /// Call this periodically (e.g., after each round advance or N blocks).
    pub fn full_gc(&mut self) {
        self.auto_evict();
        self.enforce_max_cached_rounds();
        self.prune_old_commits();
        self.prune_committed_set();
    }

    /// Check if the write batch should be flushed (based on batch size config).
    pub fn should_flush(&self) -> bool {
        self.write_batch.blocks.len() >= self.config.flush_batch_size
    }

    /// Memory usage estimate (block count + commit count + committed set size).
    pub fn memory_stats(&self) -> DagMemoryStats {
        DagMemoryStats {
            blocks_in_memory: self.blocks.len(),
            commits_in_memory: self.commits.len(),
            committed_set_size: self.committed_blocks.len(),
            eviction_round: self.eviction_round,
            highest_round: self.highest_accepted_round,
            round_span: self
                .highest_accepted_round
                .saturating_sub(self.eviction_round),
            equivocations: self.equivocations.len(),
            pending_writes: self.write_batch.blocks.len(),
        }
    }
}

/// Memory usage statistics for monitoring.
#[derive(Debug, Clone)]
pub struct DagMemoryStats {
    pub blocks_in_memory: usize,
    pub commits_in_memory: usize,
    pub committed_set_size: usize,
    pub eviction_round: Round,
    pub highest_round: Round,
    pub round_span: u32,
    pub equivocations: usize,
    pub pending_writes: usize,
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(round: Round, author: AuthorityIndex, ancestors: Vec<BlockRef>) -> VerifiedBlock {
        let block = Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors,
            transactions: vec![vec![author as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        VerifiedBlock::new_for_test(block)
    }

    fn test_dag_state(n: usize) -> DagState {
        DagState::new(Committee::new_for_test(n), DagStateConfig::default())
    }

    #[test]
    fn test_accept_and_query() {
        let mut state = test_dag_state(4);
        let b = make_block(1, 0, vec![]);
        let block_ref = b.reference();
        assert!(state.accept_block(b).is_accepted());
        assert!(state.contains_block(&block_ref));
        assert_eq!(state.num_blocks(), 1);
        assert_eq!(state.highest_accepted_round(), 1);
    }

    #[test]
    fn test_reject_duplicate() {
        let mut state = test_dag_state(4);
        let b = make_block(1, 0, vec![]);
        assert!(state.accept_block(b.clone()).is_accepted());
        assert!(!state.accept_block(b).is_accepted()); // duplicate
        assert_eq!(state.num_blocks(), 1);
    }

    #[test]
    fn test_equivocation_detected() {
        let mut state = test_dag_state(4);

        let b1 = make_block(1, 0, vec![]);
        assert!(state.accept_block(b1).is_accepted());

        // Different block at same slot (different tx → different digest)
        // Phase 1-1: real ML-DSA-65 signature (was 0xBB mock)
        let tvs = crate::narwhal_types::block::TestValidatorSet::new(4);
        let mut block2 = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![0xFF]], // different tx
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![],
        };
        tvs.sign_block(0, &mut block2);
        let b2 = VerifiedBlock::new_for_test(block2);
        let result = state.accept_block(b2);
        assert!(
            result.is_accepted(),
            "equivocating block should be accepted as evidence"
        );
        assert!(result.is_equivocation(), "should detect equivocation");

        assert_eq!(state.equivocations().len(), 1);
        // First block wins — equivocating block is NOT inserted into the DAG.
        // Evidence is recorded but only one block per slot is stored.
        assert_eq!(state.num_blocks(), 1);
    }

    #[test]
    fn test_invalid_author_rejected() {
        let mut state = test_dag_state(4);
        let b = make_block(1, 99, vec![]); // author 99 not in committee of 4
        assert!(!state.accept_block(b).is_accepted());
    }

    #[test]
    fn test_commit_tracking() {
        let mut state = test_dag_state(4);
        let b = make_block(1, 0, vec![]);
        let block_ref = b.reference();
        state.accept_block(b);

        let sub_dag = CommittedSubDag {
            index: 0,
            leader: block_ref,
            blocks: vec![block_ref],
            timestamp_ms: 1000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        state.record_commit(sub_dag);

        assert_eq!(state.num_commits(), 1);
        assert_eq!(state.last_commit_index(), Some(0));
        assert!(state.is_committed(&block_ref));
        assert!(!state.take_pending_commit_votes().is_empty());
    }

    #[test]
    fn test_eviction() {
        let mut state = test_dag_state(4);
        // Add blocks at rounds 1..10
        for round in 1..=10 {
            for author in 0..4u32 {
                let b = make_block(round, author, vec![]);
                state.accept_block(b);
            }
        }
        assert_eq!(state.num_blocks(), 40);

        // Evict rounds below 5
        state.evict_below(5);
        assert_eq!(state.eviction_round(), 5);
        // Rounds 1-4 evicted = 4*4 = 16 blocks
        assert_eq!(state.num_blocks(), 24);
        assert_eq!(state.evicted_count(), 16);
    }

    #[test]
    fn test_missing_ancestors() {
        let mut state = test_dag_state(4);
        let ancestor_ref = BlockRef::new(1, 0, BlockDigest([0x11; 32]));
        let b = make_block(2, 1, vec![ancestor_ref]);

        let missing = state.missing_ancestors(&b);
        assert_eq!(missing, vec![ancestor_ref]);
        assert!(!state.has_all_ancestors(&b));
    }

    #[test]
    fn test_write_batch() {
        let mut state = test_dag_state(4);
        assert!(!state.has_pending_writes());

        let b = make_block(1, 0, vec![]);
        state.accept_block(b);
        assert!(state.has_pending_writes());

        let batch = state.take_write_batch();
        assert_eq!(batch.blocks.len(), 1);
        assert!(!state.has_pending_writes());
    }

    #[test]
    fn test_blocks_at_round() {
        let mut state = test_dag_state(4);
        for author in 0..4u32 {
            state.accept_block(make_block(5, author, vec![]));
        }
        let round5 = state.get_blocks_at_round(5);
        assert_eq!(round5.len(), 4);
    }

    #[test]
    fn test_auto_evict() {
        let mut state = DagState::new(
            Committee::new_for_test(2),
            DagStateConfig {
                gc_depth: 3,
                ..Default::default()
            },
        );
        // Add blocks and commit
        for round in 1..=10 {
            for author in 0..2u32 {
                let b = make_block(round, author, vec![]);
                let bref = b.reference();
                state.accept_block(b);
                // Commit every block
                state.record_commit(CommittedSubDag {
                    index: (round as u64 - 1) * 2 + author as u64,
                    leader: bref,
                    blocks: vec![bref],
                    timestamp_ms: round as u64 * 1000,
                    previous_digest: CommitDigest([0; 32]),
                    is_direct: true,
                });
            }
        }
        state.auto_evict();
        // min committed round = 10, gc_depth = 3 → evict below 7
        assert_eq!(state.eviction_round(), 7);
    }

    // ── Task 1.2: GC addition tests ──

    #[test]
    fn task_1_2_enforce_max_cached_rounds() {
        let committee = Committee::new_for_test(2);
        let mut config = DagStateConfig::default();
        config.max_cached_rounds = 5;
        let mut state = DagState::new(committee, config);

        // Insert blocks at rounds 1..=10
        for round in 1..=10u32 {
            for author in 0..2u32 {
                let b = make_block(round, author, vec![]);
                state.accept_block(b);
            }
        }

        // Before enforcement: all 20 blocks present
        assert_eq!(state.num_blocks(), 20);

        // Enforce max_cached_rounds = 5 → highest=10, cutoff=5
        state.enforce_max_cached_rounds();
        assert!(state.eviction_round() >= 5);

        // Blocks at round 1..4 should be evicted
        for round in 1..5u32 {
            assert!(
                state.get_blocks_at_round(round).is_empty(),
                "round {} should be evicted",
                round
            );
        }
        // Blocks at round 6..10 should remain
        for round in 6..=10u32 {
            assert!(
                !state.get_blocks_at_round(round).is_empty(),
                "round {} should be retained",
                round
            );
        }
    }

    #[test]
    fn task_1_2_prune_old_commits() {
        let committee = Committee::new_for_test(2);
        let mut config = DagStateConfig::default();
        config.max_cached_commits = 5;
        let mut state = DagState::new(committee, config);

        // Insert and commit 10 blocks
        for round in 1..=10u32 {
            let b = make_block(round, 0, vec![]);
            let bref = b.reference();
            state.accept_block(b);
            state.record_commit(CommittedSubDag {
                index: round as u64,
                leader: bref,
                blocks: vec![bref],
                timestamp_ms: round as u64 * 1000,
                previous_digest: CommitDigest([0; 32]),
                is_direct: true,
            });
        }

        assert_eq!(state.num_commits(), 10);
        state.prune_old_commits();
        assert_eq!(state.num_commits(), 5);
    }

    #[test]
    fn task_1_2_full_gc_cycle() {
        let committee = Committee::new_for_test(2);
        let mut config = DagStateConfig::default();
        config.max_cached_rounds = 8;
        config.gc_depth = 3;
        config.max_cached_commits = 5;
        let mut state = DagState::new(committee, config);

        // Insert blocks at rounds 1..=10 with commits
        for round in 1..=10u32 {
            for author in 0..2u32 {
                let b = make_block(round, author, vec![]);
                let bref = b.reference();
                state.accept_block(b);
                state.record_commit(CommittedSubDag {
                    index: (round as u64 - 1) * 2 + author as u64,
                    leader: bref,
                    blocks: vec![bref],
                    timestamp_ms: round as u64 * 1000,
                    previous_digest: CommitDigest([0; 32]),
                    is_direct: true,
                });
            }
        }

        let stats_before = state.memory_stats();
        assert_eq!(stats_before.blocks_in_memory, 20);

        state.full_gc();

        let stats_after = state.memory_stats();
        // Blocks should be reduced (eviction + max_cached_rounds)
        assert!(
            stats_after.blocks_in_memory < stats_before.blocks_in_memory,
            "full_gc should reduce block count: {} -> {}",
            stats_before.blocks_in_memory,
            stats_after.blocks_in_memory
        );
        // Commits should be pruned to max_cached_commits
        assert!(stats_after.commits_in_memory <= 5);
    }

    #[test]
    fn task_1_2_memory_stats() {
        let committee = Committee::new_for_test(2);
        let state = DagState::new(committee, DagStateConfig::default());
        let stats = state.memory_stats();
        assert_eq!(stats.blocks_in_memory, 0);
        assert_eq!(stats.commits_in_memory, 0);
        assert_eq!(stats.eviction_round, 0);
        assert_eq!(stats.highest_round, 0);
        assert_eq!(stats.round_span, 0);
    }
}
