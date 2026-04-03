use misaka_dag_types::block::*;
use misaka_dag_types::committee::*;
use std::collections::{HashMap, BTreeMap, HashSet};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum DagError {
    #[error("equivocation detected at round {round} author {author}")]
    Equivocation { round: Round, author: AuthorityIndex },
    #[error("missing ancestor: {0:?}")]
    MissingAncestor(BlockRef),
    #[error("too many ancestors: {0} > {1}")]
    TooManyAncestors(usize, usize),
    #[error("invalid ancestor round: expected {expected}, got {got}")]
    InvalidAncestorRound { expected: Round, got: Round },
    #[error("invalid block signature: {0}")]
    InvalidSignature(String),
}

/// Persistent state snapshot (serializable subset of DagState).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DagSnapshot {
    pub blocks: Vec<Block>,
    pub last_committed_round: Round,
    pub highest_accepted_round: Round,
}

/// In-memory DAG state with proper indexing and GC.
pub struct DagState {
    /// Blocks indexed by BlockRef.
    blocks: HashMap<BlockRef, Block>,
    /// Index: (round, authority) -> BlockRef.
    slot_index: BTreeMap<(Round, AuthorityIndex), BlockRef>,
    /// Blocks per round (for quorum checking).
    round_blocks: BTreeMap<Round, Vec<BlockRef>>,
    /// Last block proposed by each authority.
    last_proposed: HashMap<AuthorityIndex, BlockRef>,
    /// Highest accepted round (quorum of blocks received).
    highest_accepted_round: Round,
    /// Last committed round.
    last_committed_round: Round,
    /// GC depth.
    gc_depth: Round,
    /// Committee for stake lookups.
    committee: Committee,
    /// P0-1: Detected equivocations.
    pub equivocations: Vec<EquivocationProof>,
    /// Cryptographic signature verifier (ML-DSA-65 in production).
    verifier: Arc<dyn SignatureVerifier>,
}

impl DagState {
    /// Create a new DagState with the given signature verifier.
    ///
    /// **Production:** pass `Arc::new(MlDsa65Verifier)` from `misaka-crypto`.
    /// **Tests:** pass `Arc::new(StructuralVerifier)`.
    pub fn new(committee: Committee, gc_depth: Round, verifier: Arc<dyn SignatureVerifier>) -> Self {
        // Insert genesis blocks
        let genesis = genesis_blocks(committee.size() as u32);
        let mut state = Self {
            blocks: HashMap::new(),
            slot_index: BTreeMap::new(),
            round_blocks: BTreeMap::new(),
            last_proposed: HashMap::new(),
            highest_accepted_round: 0,
            last_committed_round: 0,
            gc_depth,
            committee,
            equivocations: Vec::new(),
            verifier,
        };
        for g in genesis {
            // Genesis blocks are trusted; ignore Result
            let _ = state.accept_block(g);
        }
        state
    }

    /// Accept a verified block into the DAG.
    pub fn accept_block(&mut self, block: Block) -> Result<BlockRef, DagError> {
        let block_ref = block.reference();

        // P0-1: Equivocation detection
        if let Some(existing_ref) = self.slot_index.get(&(block.round, block.author)) {
            if existing_ref.digest != block_ref.digest {
                // EQUIVOCATION: same (round, author) but different block
                self.equivocations.push(EquivocationProof {
                    slot: Slot { round: block.round, authority: block.author },
                    block_a_ref: *existing_ref,
                    block_a_digest: existing_ref.digest,
                    block_b_ref: block_ref,
                    block_b_digest: block_ref.digest,
                });
                return Err(DagError::Equivocation {
                    round: block.round,
                    author: block.author,
                });
            }
            // Same digest = idempotent, already accepted
            return Ok(block_ref);
        }

        // P0-A: Block signature verification (ML-DSA-65 in production)
        // The signature covers the block digest (domain-separated hash of
        // epoch, round, author, timestamp, ancestors, transactions).
        if !block.signature.is_empty() {
            // Look up author's public key from committee
            if let Some(authority) = self.committee.authorities.get(block.author as usize) {
                // Verify that the block digest matches the computed digest
                let expected_digest = Block::compute_digest_for(&block);
                if expected_digest != block.digest() {
                    return Err(DagError::InvalidSignature(
                        format!("digest mismatch for round {} author {}", block.round, block.author)
                    ));
                }

                // Cryptographic signature verification via injected verifier.
                // In production: MlDsa65Verifier → dilithium3::verify_detached_signature
                // In tests: StructuralVerifier → length + non-zero check
                let digest_bytes = block.digest().0;
                self.verifier.verify(
                    &authority.public_key,
                    &digest_bytes,
                    &block.signature,
                ).map_err(|e| DagError::InvalidSignature(
                    format!("round {} author {}: {}", block.round, block.author, e)
                ))?;
            } else if block.round > 0 {
                // Unknown author (not in committee) — reject non-genesis blocks
                return Err(DagError::InvalidSignature(
                    format!("unknown author {} not in committee", block.author)
                ));
            }
        } else if block.round > 0 {
            // Non-genesis blocks MUST have a signature
            return Err(DagError::InvalidSignature(
                "missing signature for non-genesis block".to_string()
            ));
        }

        // P0-2: Ancestor validation
        let max_ancestors = self.committee.size();
        if block.ancestors.len() > max_ancestors {
            return Err(DagError::TooManyAncestors(block.ancestors.len(), max_ancestors));
        }

        // Validate ancestors are from round r-1 (except genesis round 0)
        if block.round > 1 {
            for ancestor in &block.ancestors {
                if ancestor.round != block.round - 1 && ancestor.round != 0 {
                    return Err(DagError::InvalidAncestorRound {
                        expected: block.round - 1,
                        got: ancestor.round,
                    });
                }
                // Verify ancestor exists in DAG
                if !self.blocks.contains_key(ancestor) {
                    return Err(DagError::MissingAncestor(*ancestor));
                }
            }
        }

        // Accept the block
        self.slot_index.insert((block.round, block.author), block_ref);
        self.round_blocks.entry(block.round).or_default().push(block_ref);
        self.last_proposed.insert(block.author, block_ref);
        self.blocks.insert(block_ref, block);
        self.update_highest_accepted_round();
        Ok(block_ref)
    }

    /// Check if we have a quorum of blocks at a round.
    fn update_highest_accepted_round(&mut self) {
        let mut r = self.highest_accepted_round;
        loop {
            let next = r + 1;
            let stake_at_next: Stake = self.round_blocks.get(&next)
                .map(|refs| refs.iter().map(|r| self.committee.stake(r.author)).sum())
                .unwrap_or(0);
            if stake_at_next >= self.committee.quorum_threshold() {
                r = next;
            } else {
                break;
            }
        }
        self.highest_accepted_round = r;
    }

    pub fn highest_accepted_round(&self) -> Round { self.highest_accepted_round }
    pub fn last_committed_round(&self) -> Round { self.last_committed_round }
    pub fn set_last_committed_round(&mut self, round: Round) { self.last_committed_round = round; }

    /// Get block by reference.
    pub fn get_block(&self, block_ref: &BlockRef) -> Option<&Block> {
        self.blocks.get(block_ref)
    }

    /// Get block at a specific slot.
    pub fn get_block_at_slot(&self, slot: &Slot) -> Option<&Block> {
        let block_ref = self.slot_index.get(&(slot.round, slot.authority))?;
        self.blocks.get(block_ref)
    }

    /// Get all blocks at a round.
    pub fn blocks_at_round(&self, round: Round) -> Vec<&Block> {
        self.round_blocks.get(&round)
            .map(|refs| refs.iter().filter_map(|r| self.blocks.get(r)).collect())
            .unwrap_or_default()
    }

    /// Get all uncommitted block refs at a slot.
    pub fn get_uncommitted_blocks_at_slot(&self, slot: &Slot) -> Vec<BlockRef> {
        self.slot_index.get(&(slot.round, slot.authority))
            .into_iter()
            .filter(|r| r.round > self.last_committed_round)
            .copied()
            .collect()
    }

    /// Check if a block is an ancestor of another (path exists in DAG).
    pub fn is_ancestor(&self, ancestor: &BlockRef, descendant: &BlockRef) -> bool {
        if ancestor.round >= descendant.round { return *ancestor == *descendant; }
        let mut stack = vec![*descendant];
        let mut visited = HashSet::new();
        while let Some(current_ref) = stack.pop() {
            if current_ref == *ancestor { return true; }
            if current_ref.round <= ancestor.round { continue; }
            if !visited.insert(current_ref) { continue; }
            if let Some(block) = self.blocks.get(&current_ref) {
                for a in &block.ancestors {
                    stack.push(*a);
                }
            }
        }
        false
    }

    /// Get ancestors of a block at a specific round.
    pub fn ancestors_at_round(&self, block_ref: &BlockRef, target_round: Round) -> Vec<BlockRef> {
        let mut result = Vec::new();
        let mut stack = vec![*block_ref];
        let mut visited = HashSet::new();
        while let Some(current) = stack.pop() {
            if !visited.insert(current) { continue; }
            if current.round == target_round {
                result.push(current);
                continue;
            }
            if current.round <= target_round { continue; }
            if let Some(block) = self.blocks.get(&current) {
                for a in &block.ancestors { stack.push(*a); }
            }
        }
        result
    }

    /// Garbage collect old rounds.
    pub fn gc(&mut self) {
        let cutoff = self.last_committed_round.saturating_sub(self.gc_depth);
        let old_rounds: Vec<Round> = self.round_blocks.keys()
            .copied().filter(|r| *r < cutoff).collect();
        for r in old_rounds {
            if let Some(refs) = self.round_blocks.remove(&r) {
                for block_ref in refs {
                    self.blocks.remove(&block_ref);
                    self.slot_index.remove(&(r, block_ref.author));
                }
            }
        }
    }

    pub fn committee(&self) -> &Committee { &self.committee }

    /// P0-3: Save current DAG state to disk.
    pub fn save_to_disk(&self, path: &std::path::Path) -> Result<(), String> {
        let snapshot = DagSnapshot {
            blocks: self.blocks.values().cloned().collect(),
            last_committed_round: self.last_committed_round,
            highest_accepted_round: self.highest_accepted_round,
        };
        let json = serde_json::to_string(&snapshot)
            .map_err(|e| format!("serialize: {}", e))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json).map_err(|e| format!("write: {}", e))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename: {}", e))?;
        Ok(())
    }

    /// P0-3: Load DAG state from disk.
    /// P0-E: Validates blocks on restore (digest integrity, equivocation detection).
    pub fn load_from_disk(&mut self, path: &std::path::Path) -> Result<usize, String> {
        if !path.exists() { return Ok(0); }
        let json = std::fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;
        let snapshot: DagSnapshot = serde_json::from_str(&json)
            .map_err(|e| format!("parse: {}", e))?;

        self.last_committed_round = snapshot.last_committed_round;

        // Sort blocks by round to ensure ancestors are loaded before children
        let mut sorted_blocks = snapshot.blocks;
        sorted_blocks.sort_by_key(|b| b.round);

        // P0-E: Validate blocks on restore
        let mut loaded = 0;
        let mut skipped = 0;
        for block in sorted_blocks {
            // Verify digest integrity
            let computed = Block::compute_digest_for(&block);
            if computed != block.digest() {
                tracing::warn!(
                    "Restore: block round={} author={} has corrupted digest — skipping",
                    block.round, block.author
                );
                skipped += 1;
                continue;
            }

            // For genesis blocks (round 0), skip signature check
            if block.round == 0 {
                let block_ref = block.reference();
                self.slot_index.insert((block.round, block.author), block_ref);
                self.round_blocks.entry(block.round).or_default().push(block_ref);
                self.last_proposed.insert(block.author, block_ref);
                self.blocks.insert(block_ref, block);
                loaded += 1;
                continue;
            }

            // For non-genesis: check equivocation (duplicate slot)
            let block_ref = block.reference();
            if let Some(existing) = self.slot_index.get(&(block.round, block.author)) {
                if existing.digest != block_ref.digest {
                    tracing::warn!(
                        "Restore: equivocation at round={} author={} — skipping",
                        block.round, block.author
                    );
                    skipped += 1;
                    continue;
                }
                // Same digest = already loaded
                continue;
            }

            // Accept the restored block
            self.slot_index.insert((block.round, block.author), block_ref);
            self.round_blocks.entry(block.round).or_default().push(block_ref);
            self.last_proposed.insert(block.author, block_ref);
            self.blocks.insert(block_ref, block);
            loaded += 1;
        }

        if skipped > 0 {
            tracing::warn!("Restore: {} blocks skipped due to corruption/equivocation", skipped);
        }

        self.update_highest_accepted_round();
        Ok(loaded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test committee with StructuralVerifier.
    fn test_committee(n: u32) -> (Committee, Arc<dyn SignatureVerifier>) {
        let auths = (0..n).map(|i| Authority {
            index: i, stake: 100, address: String::new(),
            public_key: vec![0xAA; 1952], // dummy ML-DSA-65 sized key
            reputation_score: 0, is_sr: false,
        }).collect();
        let c = Committee { epoch: 0, authorities: auths, total_stake: 100 * n as u64, leaders_per_round: 1, wave_length: 3 };
        (c, Arc::new(StructuralVerifier))
    }

    #[test]
    fn test_genesis_initialization() {
        let (c, v) = test_committee(4);
        let state = DagState::new(c, 50, v);
        assert_eq!(state.blocks_at_round(0).len(), 4); // 4 genesis blocks
    }

    #[test]
    fn test_equivocation_detected() {
        let (c, v) = test_committee(4);
        let mut state = DagState::new(c, 50, v);

        // Create two different blocks for same (round=1, author=0)
        let genesis_refs: Vec<_> = state.blocks_at_round(0).iter().map(|b| b.reference()).collect();
        let block_a = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
            ancestors: genesis_refs.clone(),
            transactions: vec![vec![1]], // different TX
            commit_votes: vec![], tx_reject_votes: vec![], signature: vec![0xAA; 64],
        };
        let block_b = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1001,
            ancestors: genesis_refs,
            transactions: vec![vec![2]], // different TX -> different digest
            commit_votes: vec![], tx_reject_votes: vec![], signature: vec![0xBB; 64],
        };

        assert!(state.accept_block(block_a).is_ok());
        assert!(state.accept_block(block_b).is_err()); // equivocation!
        assert_eq!(state.equivocations.len(), 1);
    }

    #[test]
    fn test_ancestor_validation() {
        let (c, v) = test_committee(4);
        let mut state = DagState::new(c, 50, v);

        // Block with non-existent ancestor
        let fake_ref = BlockRef { round: 1, author: 99, digest: BlockDigest([0xFF; 32]) };
        let bad_block = Block {
            epoch: 0, round: 2, author: 0, timestamp_ms: 2000,
            ancestors: vec![fake_ref],
            transactions: vec![], commit_votes: vec![], tx_reject_votes: vec![], signature: vec![0xAA; 64],
        };
        assert!(state.accept_block(bad_block).is_err());
    }

    #[test]
    fn test_missing_signature_rejected() {
        let (c, v) = test_committee(4);
        let mut state = DagState::new(c, 50, v);

        let genesis_refs: Vec<_> = state.blocks_at_round(0).iter().map(|b| b.reference()).collect();
        // Create block at round 1 with empty signature
        let block = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
            ancestors: genesis_refs,
            transactions: vec![vec![1]],
            commit_votes: vec![], tx_reject_votes: vec![],
            signature: vec![], // EMPTY — must be rejected
        };
        assert!(state.accept_block(block).is_err());
    }

    #[test]
    fn test_valid_signature_accepted() {
        let (c, v) = test_committee(4);
        let mut state = DagState::new(c, 50, v);

        let genesis_refs: Vec<_> = state.blocks_at_round(0).iter().map(|b| b.reference()).collect();
        let block = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
            ancestors: genesis_refs,
            transactions: vec![vec![1]],
            commit_votes: vec![], tx_reject_votes: vec![],
            signature: vec![0xAA; 64], // Non-empty, non-zero → passes StructuralVerifier
        };
        assert!(state.accept_block(block).is_ok());
    }

    #[test]
    fn test_short_signature_rejected() {
        let (c, v) = test_committee(4);
        let mut state = DagState::new(c, 50, v);

        let genesis_refs: Vec<_> = state.blocks_at_round(0).iter().map(|b| b.reference()).collect();
        let block = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
            ancestors: genesis_refs,
            transactions: vec![vec![1]],
            commit_votes: vec![], tx_reject_votes: vec![],
            signature: vec![0xAA; 16], // Too short — rejected by StructuralVerifier
        };
        assert!(state.accept_block(block).is_err());
    }

    #[test]
    fn test_allzero_signature_rejected() {
        let (c, v) = test_committee(4);
        let mut state = DagState::new(c, 50, v);

        let genesis_refs: Vec<_> = state.blocks_at_round(0).iter().map(|b| b.reference()).collect();
        let block = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
            ancestors: genesis_refs,
            transactions: vec![vec![1]],
            commit_votes: vec![], tx_reject_votes: vec![],
            signature: vec![0x00; 64], // All zeros — rejected
        };
        assert!(state.accept_block(block).is_err());
    }
}
