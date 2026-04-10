//! Pruning logic — removes old data to keep node storage manageable.
//!
//! MISAKA prunes:
//! - Block bodies older than the pruning depth
//! - UTXO diffs older than the finality window
//! - Headers are kept (compact, needed for proof-of-work chain)
//! - Pruning proofs enable new nodes to sync from pruning point

/// Pruning configuration.
#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// Pruning depth in blocks (measured in DAA score).
    pub pruning_depth: u64,
    /// Finality depth (blocks must be this deep before pruning).
    pub finality_depth: u64,
    /// Maximum data to prune per cycle (bytes).
    pub max_prune_per_cycle: u64,
    /// Pruning interval (seconds between prune cycles).
    pub prune_interval_secs: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            pruning_depth: 100_000,
            finality_depth: 86400,
            max_prune_per_cycle: 100 * 1024 * 1024, // 100 MB
            prune_interval_secs: 3600,
        }
    }
}

/// Pruning state.
pub struct PruningState {
    pub pruning_point: [u8; 32],
    pub pruning_point_daa_score: u64,
    pub last_prune_timestamp: u64,
    pub total_pruned_bytes: u64,
    pub total_pruned_blocks: u64,
}

/// Pruning candidate — a block that can be pruned.
pub struct PruningCandidate {
    pub hash: [u8; 32],
    pub daa_score: u64,
    pub body_size: u64,
    pub has_utxo_diff: bool,
}

/// Result of a pruning operation.
#[derive(Debug)]
pub struct PruneResult {
    pub blocks_pruned: usize,
    pub bytes_freed: u64,
    pub new_pruning_point: Option<[u8; 32]>,
    pub duration_ms: u64,
}

/// Determine which blocks can be pruned.
pub fn find_pruning_candidates(
    current_daa_score: u64,
    config: &PruningConfig,
    block_scores: &[(u8, u64, u64)], // (hash_byte, daa_score, body_size)
) -> Vec<usize> {
    let cutoff = current_daa_score.saturating_sub(config.pruning_depth);
    let finality_cutoff = current_daa_score.saturating_sub(config.finality_depth);

    block_scores
        .iter()
        .enumerate()
        .filter(|(_, (_, score, _))| *score < cutoff && *score < finality_cutoff)
        .map(|(i, _)| i)
        .collect()
}

/// Calculate the new pruning point after pruning.
pub fn calculate_new_pruning_point(
    current_pruning_point_score: u64,
    current_daa_score: u64,
    config: &PruningConfig,
) -> u64 {
    let target = current_daa_score.saturating_sub(config.pruning_depth);
    target.max(current_pruning_point_score)
}

/// Pruning proof — enables nodes to verify chain state from pruning point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PruningProof {
    pub pruning_point_hash: [u8; 32],
    pub pruning_point_daa_score: u64,
    pub header_chain: Vec<PruningProofHeader>,
    pub utxo_commitment: [u8; 32],
    pub blue_work: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PruningProofHeader {
    pub hash: [u8; 32],
    pub daa_score: u64,
    pub blue_score: u64,
    pub bits: u32,
    pub timestamp: u64,
}

/// Validate a pruning proof.
pub fn validate_pruning_proof(proof: &PruningProof) -> Result<(), PruningError> {
    if proof.header_chain.is_empty() {
        return Err(PruningError::EmptyHeaderChain);
    }

    // Verify header chain is in order
    for window in proof.header_chain.windows(2) {
        if window[1].daa_score <= window[0].daa_score {
            return Err(PruningError::HeadersOutOfOrder);
        }
    }

    // Verify pruning point is in the header chain
    if !proof
        .header_chain
        .iter()
        .any(|h| h.hash == proof.pruning_point_hash)
    {
        return Err(PruningError::PruningPointNotInChain);
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PruningError {
    #[error("empty header chain in pruning proof")]
    EmptyHeaderChain,
    #[error("headers out of order")]
    HeadersOutOfOrder,
    #[error("pruning point not found in header chain")]
    PruningPointNotInChain,
    #[error("invalid UTXO commitment")]
    InvalidUtxoCommitment,
    #[error("insufficient blue work")]
    InsufficientBlueWork,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_candidates() {
        let blocks = vec![
            (1, 100, 1000),
            (2, 500, 2000),
            (3, 999_900, 3000),
            (4, 999_999, 4000),
        ];
        let config = PruningConfig::default();
        let candidates = find_pruning_candidates(1_000_000, &config, &blocks);
        assert_eq!(candidates.len(), 2); // First two blocks are old enough
    }
}
