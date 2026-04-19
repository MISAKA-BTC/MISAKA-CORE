//! Narwhal block relay payloads carried over MISAKA's PQ-secure P2P transport.
//!
//! SEC-FIX [Audit H2]: Migrated from serde_json to borsh for wire serialization.
//! Borsh is deterministic and avoids JSON ambiguity on the P2P wire.

use borsh::{BorshDeserialize, BorshSerialize};
use misaka_dag::narwhal_types::block::{Block, BlockRef};
use serde::{Deserialize, Serialize};

use crate::payload_type::{MisakaMessage, MisakaPayloadType};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NarwhalBlockProposal {
    pub block: Block,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct NarwhalBlockRequest {
    pub refs: Vec<BlockRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NarwhalBlockResponse {
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct NarwhalCommitVote {
    pub vote: BlockRef,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum NarwhalRelayMessage {
    BlockProposal(NarwhalBlockProposal),
    BlockRequest(NarwhalBlockRequest),
    BlockResponse(NarwhalBlockResponse),
    CommitVote(NarwhalCommitVote),
}

#[derive(Debug, thiserror::Error)]
pub enum NarwhalRelayDecodeError {
    #[error("unexpected payload type for narwhal relay: {0:?}")]
    UnexpectedType(MisakaPayloadType),
    #[error("narwhal relay payload decode failed: {0}")]
    Borsh(String),
    #[error("invalid signature length: {0} (expected {ML_DSA_SIG_LEN})")]
    BadSignatureLength(usize),
    #[error("block too large: {0} bytes (max {MAX_BLOCK_SIZE_BYTES})")]
    BlockTooLarge(usize),
    #[error("CommitVote rate limited")]
    RateLimited,
}

/// ML-DSA-65 signature length (FIPS 204).
const ML_DSA_SIG_LEN: usize = 3309;

/// Maximum block size in bytes (must match block_verifier).
const MAX_BLOCK_SIZE_BYTES: usize = 16 * 1024 * 1024; // 16 MB

impl From<std::io::Error> for NarwhalRelayDecodeError {
    fn from(e: std::io::Error) -> Self {
        NarwhalRelayDecodeError::Borsh(e.to_string())
    }
}

/// Early-sanitize a decoded block before passing it to consensus.
///
/// SEC-FIX [C5]: Reject obviously malformed blocks at the P2P layer
/// before they reach the DAG or verifier, reducing attack surface.
fn sanitize_block(block: &Block) -> Result<(), NarwhalRelayDecodeError> {
    if block.signature.len() != ML_DSA_SIG_LEN {
        return Err(NarwhalRelayDecodeError::BadSignatureLength(
            block.signature.len(),
        ));
    }
    let size = block.size_bytes();
    if size > MAX_BLOCK_SIZE_BYTES {
        return Err(NarwhalRelayDecodeError::BlockTooLarge(size));
    }
    Ok(())
}

impl NarwhalRelayMessage {
    pub fn payload_type(&self) -> MisakaPayloadType {
        match self {
            Self::BlockProposal(_) => MisakaPayloadType::NarwhalBlockProposal,
            Self::BlockRequest(_) => MisakaPayloadType::NarwhalBlockRequest,
            Self::BlockResponse(_) => MisakaPayloadType::NarwhalBlockResponse,
            Self::CommitVote(_) => MisakaPayloadType::NarwhalCommitVote,
        }
    }

    pub fn to_message(&self) -> Result<MisakaMessage, std::io::Error> {
        Ok(MisakaMessage::new(
            self.payload_type(),
            borsh::to_vec(self)?,
        ))
    }

    pub fn from_message(message: &MisakaMessage) -> Result<Self, NarwhalRelayDecodeError> {
        let decoded: Self = match message.msg_type {
            MisakaPayloadType::NarwhalBlockProposal
            | MisakaPayloadType::NarwhalBlockRequest
            | MisakaPayloadType::NarwhalBlockResponse
            | MisakaPayloadType::NarwhalCommitVote => borsh::from_slice(&message.payload)?,
            other => return Err(NarwhalRelayDecodeError::UnexpectedType(other)),
        };

        // SEC-FIX [C5]: Early sanitize — reject malformed blocks at the P2P
        // boundary before they reach consensus / verification.
        match &decoded {
            Self::BlockProposal(proposal) => sanitize_block(&proposal.block)?,
            Self::BlockResponse(response) => {
                for block in &response.blocks {
                    sanitize_block(block)?;
                }
            }
            _ => {}
        }

        Ok(decoded)
    }

    /// SEC-FIX M-16: Rate-limited message decoding for CommitVote.
    /// Returns `Err` if the peer has exceeded their vote budget.
    /// Non-CommitVote messages pass through without rate checks.
    pub fn from_message_rate_limited(
        message: &MisakaMessage,
        rate_limiter: &mut VoteRateLimiter,
        peer_id: &[u8],
        current_epoch: u64,
    ) -> Result<Self, NarwhalRelayDecodeError> {
        let decoded = Self::from_message(message)?;
        if let Self::CommitVote(_) = &decoded {
            if !rate_limiter.check(peer_id, current_epoch) {
                return Err(NarwhalRelayDecodeError::RateLimited);
            }
        }
        Ok(decoded)
    }
}

// ═══════════════════════════════════════════════════════════════
//  SEC-FIX: CommitVote Flood Protection
// ═══════════════════════════════════════════════════════════════

/// Per-peer vote rate limiter to prevent CommitVote flooding.
///
/// Exported via `misaka_p2p::VoteRateLimiter`. Use
/// `NarwhalRelayMessage::from_message_rate_limited()` to apply
/// rate limiting during message decoding.
pub struct VoteRateLimiter {
    /// (epoch, count) per peer
    counts: std::collections::HashMap<Vec<u8>, (u64, u32)>,
    max_per_epoch: u32,
}

impl VoteRateLimiter {
    pub fn new(max_per_epoch: u32) -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            max_per_epoch,
        }
    }

    /// Check if a peer is within their vote budget for the given epoch.
    /// Returns true if allowed, false if the peer exceeded their limit.
    pub fn check(&mut self, peer_id: &[u8], epoch: u64) -> bool {
        let entry = self.counts.entry(peer_id.to_vec()).or_insert((epoch, 0));
        if entry.0 != epoch {
            *entry = (epoch, 0); // Reset on new epoch
        }
        entry.1 += 1;
        if entry.1 > self.max_per_epoch {
            tracing::warn!(
                "CommitVote flood: peer {} exceeded {} votes in epoch {}",
                hex::encode(&peer_id[..8.min(peer_id.len())]),
                self.max_per_epoch,
                epoch
            );
            return false;
        }
        true
    }

    /// Purge state for peers not seen in the current epoch.
    pub fn gc(&mut self, current_epoch: u64) {
        self.counts.retain(|_, (epoch, _)| *epoch == current_epoch);
    }
}

/// Recommended maximum votes per peer per epoch.
/// Each validator sends ~1 vote per round, and there are limited rounds per epoch.
pub const MAX_VOTES_PER_PEER_PER_EPOCH: u32 = 1000;

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_dag::narwhal_types::block::{BlockDigest, BlockRef};

    fn sample_block() -> Block {
        Block {
            epoch: 7,
            round: 3,
            author: 1,
            timestamp_ms: 42,
            ancestors: vec![BlockRef::new(2, 0, BlockDigest([0x11; 32]))],
            transactions: vec![vec![1, 2, 3]],
            commit_votes: vec![BlockRef::new(2, 2, BlockDigest([0x22; 32]))],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 3309],
        }
    }

    #[test]
    fn narwhal_block_proposal_roundtrips_via_misaka_message() {
        let relay = NarwhalRelayMessage::BlockProposal(NarwhalBlockProposal {
            block: sample_block(),
        });

        let message = relay.to_message().expect("encode");
        let decoded = NarwhalRelayMessage::from_message(&message).expect("decode");

        assert_eq!(message.msg_type, MisakaPayloadType::NarwhalBlockProposal);
        match decoded {
            NarwhalRelayMessage::BlockProposal(decoded) => {
                assert_eq!(decoded.block.digest(), sample_block().digest());
                assert_eq!(decoded.block.commit_votes.len(), 1);
            }
            other => panic!("unexpected decoded payload: {other:?}"),
        }
    }

    #[test]
    fn narwhal_block_request_roundtrips_refs() {
        let relay = NarwhalRelayMessage::BlockRequest(NarwhalBlockRequest {
            refs: vec![
                BlockRef::new(5, 0, BlockDigest([0x55; 32])),
                BlockRef::new(5, 1, BlockDigest([0x66; 32])),
            ],
        });

        let message = relay.to_message().expect("encode");
        let decoded = NarwhalRelayMessage::from_message(&message).expect("decode");

        match decoded {
            NarwhalRelayMessage::BlockRequest(decoded) => {
                assert_eq!(decoded.refs.len(), 2);
                assert_eq!(decoded.refs[0].digest, BlockDigest([0x55; 32]));
            }
            other => panic!("unexpected decoded payload: {other:?}"),
        }
    }
}
