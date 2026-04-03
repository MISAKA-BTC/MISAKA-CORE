//! Block is the fundamental DAG vertex.
//! Unlike Narwhal, there are NO separate Vote or Certificate types.
//! Voting is implicit: including a block as ancestor = voting for it.

pub type Round = u64;
pub type Epoch = u64;
pub type AuthorityIndex = u32;
pub type BlockTimestampMs = u64;
pub type TransactionIndex = u16;

/// Unique reference to a block in the DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlockRef {
    pub round: Round,
    pub author: AuthorityIndex,
    pub digest: BlockDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlockDigest(pub [u8; 32]);

/// A position in the DAG (round, authority).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Slot {
    pub round: Round,
    pub authority: AuthorityIndex,
}

/// Transaction = opaque bytes.
pub type Transaction = Vec<u8>;

/// Vote to commit a specific leader.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitVote {
    pub round: Round,
    pub leader: AuthorityIndex,
    pub commit_digest: [u8; 32],
}

/// Vote to reject specific transactions within a block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionRejectVote {
    pub block_ref: BlockRef,
    pub rejected_indices: Vec<TransactionIndex>,
}

/// The fundamental DAG vertex.
/// In Mysticeti, blocks serve triple duty: data, voting, and certification.
/// Including a block as ancestor = voting for that block and its sub-DAG.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub epoch: Epoch,
    pub round: Round,
    pub author: AuthorityIndex,
    pub timestamp_ms: BlockTimestampMs,
    /// References to ancestor blocks (parents from prior rounds).
    /// Including a block here = implicit vote for it.
    pub ancestors: Vec<BlockRef>,
    /// Transactions included in this block.
    pub transactions: Vec<Transaction>,
    /// Votes on previous commits (protocol-level acks).
    pub commit_votes: Vec<CommitVote>,
    /// Per-block transaction rejection votes.
    pub tx_reject_votes: Vec<TransactionRejectVote>,
    /// Signature (ML-DSA-65).
    pub signature: Vec<u8>,
}

impl Block {
    pub fn digest(&self) -> BlockDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"MISAKA:block:v2:");
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.round.to_le_bytes());
        h.update(&self.author.to_le_bytes());
        h.update(&self.timestamp_ms.to_le_bytes());
        for a in &self.ancestors {
            h.update(&a.round.to_le_bytes());
            h.update(&a.author.to_le_bytes());
            h.update(&a.digest.0);
        }
        for tx in &self.transactions {
            h.update(&(tx.len() as u32).to_le_bytes());
            h.update(tx);
        }
        BlockDigest(*h.finalize().as_bytes())
    }

    pub fn reference(&self) -> BlockRef {
        BlockRef {
            round: self.round,
            author: self.author,
            digest: self.digest(),
        }
    }

    /// Compute digest from block fields (for verification).
    pub fn compute_digest_for(block: &Block) -> BlockDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"MISAKA:block:v2:");
        h.update(&block.epoch.to_le_bytes());
        h.update(&block.round.to_le_bytes());
        h.update(&block.author.to_le_bytes());
        h.update(&block.timestamp_ms.to_le_bytes());
        for a in &block.ancestors {
            h.update(&a.round.to_le_bytes());
            h.update(&a.author.to_le_bytes());
            h.update(&a.digest.0);
        }
        for tx in &block.transactions {
            h.update(&(tx.len() as u32).to_le_bytes());
            h.update(tx);
        }
        BlockDigest(*h.finalize().as_bytes())
    }

    /// Total size in bytes (approximate).
    pub fn size(&self) -> usize {
        self.transactions.iter().map(|t| t.len()).sum::<usize>()
            + self.ancestors.len() * 40
            + self.signature.len()
            + 64 // fixed fields
    }
}

/// Genesis block (round 0, used as initial ancestor for all authorities).
pub fn genesis_blocks(committee_size: u32) -> Vec<Block> {
    (0..committee_size).map(|i| Block {
        epoch: 0,
        round: 0,
        author: i,
        timestamp_ms: 0,
        ancestors: vec![],
        transactions: vec![],
        commit_votes: vec![],
        tx_reject_votes: vec![],
        signature: vec![],
    }).collect()
}

// ---------------------------------------------------------------------------
// Signature verification trait — dependency-injection point for ML-DSA-65.
// Production: MlDsa65Verifier (misaka-crypto)
// Tests: StructuralVerifier (below)
// ---------------------------------------------------------------------------

/// Cryptographic signature verifier.
///
/// All consensus-critical signature checks (block, vote, checkpoint) go through
/// this trait so that production code uses real ML-DSA-65 while unit tests can
/// use a lightweight structural verifier.
pub trait SignatureVerifier: Send + Sync {
    /// Verify that `signature` is a valid signature over `message` by the
    /// holder of `public_key`.
    ///
    /// * `public_key` — ML-DSA-65 public key (1952 bytes in production)
    /// * `message`    — domain-separated digest (e.g. block digest, checkpoint digest)
    /// * `signature`  — ML-DSA-65 signature (3293 bytes in production)
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String>;
}

/// Structural-only verifier — rejects trivially invalid signatures (too short,
/// all-zero) but performs **no cryptographic verification**.
///
/// # Safety
/// This MUST NOT be used in production. It exists solely so that unit tests
/// can construct DAG / BFT state without generating real ML-DSA-65 key pairs.
pub struct StructuralVerifier;

impl SignatureVerifier for StructuralVerifier {
    fn verify(&self, _public_key: &[u8], _message: &[u8], signature: &[u8]) -> Result<(), String> {
        if signature.len() < 32 {
            return Err(format!("signature too short: {} bytes (min 32)", signature.len()));
        }
        if signature.iter().all(|&b| b == 0) {
            return Err("signature is all zeros".to_string());
        }
        Ok(())
    }
}

/// Block signer — produces ML-DSA-65 signatures for proposed blocks.
///
/// Production: `MlDsa65Signer` in `misaka-crypto` (uses real dilithium3::detached_sign).
/// Tests: `DummySigner` (produces deterministic dummy signatures).
pub trait BlockSigner: Send + Sync {
    /// Sign the block digest with the authority's secret key.
    ///
    /// * `block_digest` — domain-separated hash of block contents
    ///
    /// Returns the ML-DSA-65 signature bytes (3309 bytes in production).
    fn sign_block(&self, block_digest: &[u8]) -> Result<Vec<u8>, String>;
}

/// Dummy signer for tests — produces structurally valid but cryptographically
/// meaningless signatures. Passes `StructuralVerifier` but not `MlDsa65Verifier`.
pub struct DummySigner;

impl BlockSigner for DummySigner {
    fn sign_block(&self, block_digest: &[u8]) -> Result<Vec<u8>, String> {
        // Produce a non-zero 64-byte signature that passes StructuralVerifier
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&block_digest[..std::cmp::min(32, block_digest.len())]);
        sig.resize(64, 0xAA);
        Ok(sig)
    }
}

/// Proof that an authority produced two different blocks for the same slot.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EquivocationProof {
    pub slot: Slot,
    pub block_a_ref: BlockRef,
    pub block_a_digest: BlockDigest,
    pub block_b_ref: BlockRef,
    pub block_b_digest: BlockDigest,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_block_digest_deterministic() {
        let b = Block {
            epoch: 0, round: 1, author: 0, timestamp_ms: 1000,
            ancestors: vec![], transactions: vec![vec![1,2,3]],
            commit_votes: vec![], tx_reject_votes: vec![], signature: vec![],
        };
        assert_eq!(b.digest(), b.digest());
    }
    #[test]
    fn test_genesis_blocks() {
        let gen = genesis_blocks(21);
        assert_eq!(gen.len(), 21);
        assert_eq!(gen[0].round, 0);
        assert_eq!(gen[20].author, 20);
    }
}
