// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal block types — Sui-aligned.
//!
//! Sui equivalent: consensus/types/block.rs (~1,800 lines)
//!
//! MISAKA blocks carry UTXO transactions (not Move objects).
//! ML-DSA-65 signatures replace Ed25519.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════
//  Primitives
// ═══════════════════════════════════════════════════════════

/// Authority index within the committee (0..committee_size).
pub type AuthorityIndex = u32;

/// Block round number.
pub type Round = u32;

/// Millisecond timestamp.
pub type BlockTimestampMs = u64;

/// Transaction payload — raw bytes (UTXO serialized).
pub type Transaction = Vec<u8>;

/// Slot = (round, authority).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Slot {
    pub round: Round,
    pub authority: AuthorityIndex,
}

impl Slot {
    pub fn new(round: Round, authority: AuthorityIndex) -> Self {
        Self { round, authority }
    }
}

// ═══════════════════════════════════════════════════════════
//  Block digest
// ═══════════════════════════════════════════════════════════

/// 32-byte block digest (BLAKE3).
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct BlockDigest(pub [u8; 32]);

impl fmt::Debug for BlockDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockDigest({})", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for BlockDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

// ═══════════════════════════════════════════════════════════
//  Block reference
// ═══════════════════════════════════════════════════════════

/// Lightweight reference to a block: (round, author, digest).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct BlockRef {
    pub round: Round,
    pub author: AuthorityIndex,
    pub digest: BlockDigest,
}

impl BlockRef {
    pub fn new(round: Round, author: AuthorityIndex, digest: BlockDigest) -> Self {
        Self {
            round,
            author,
            digest,
        }
    }

    pub fn slot(&self) -> Slot {
        Slot {
            round: self.round,
            authority: self.author,
        }
    }
}

impl fmt::Display for BlockRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B(r={},a={},{})", self.round, self.author, self.digest)
    }
}

impl PartialOrd for BlockRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.round
            .cmp(&other.round)
            .then(self.author.cmp(&other.author))
            .then(self.digest.0.cmp(&other.digest.0))
    }
}

// ═══════════════════════════════════════════════════════════
//  Block
// ═══════════════════════════════════════════════════════════

/// A Narwhal DAG block.
///
/// Each block is produced by one authority per round and references
/// blocks from the previous round (ancestors).
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Block {
    /// Epoch this block belongs to.
    pub epoch: u64,
    /// Round number.
    pub round: Round,
    /// Author authority index.
    pub author: AuthorityIndex,
    /// Creation timestamp (ms since epoch).
    pub timestamp_ms: BlockTimestampMs,
    /// References to ancestor blocks (must include ≥2f+1 from round-1).
    pub ancestors: Vec<BlockRef>,
    /// Transaction payloads.
    pub transactions: Vec<Transaction>,
    /// Commit votes (piggy-backed on blocks).
    pub commit_votes: Vec<BlockRef>,
    /// Transaction reject votes (Sui extension).
    pub tx_reject_votes: Vec<BlockRef>,
    /// Phase 3 C7: Post-execution state root (MuHash of UTXO set).
    /// Commits the executor's state at the time of block proposal.
    pub state_root: [u8; 32],
    /// v1.0 hard-fork parallel SMT state root
    /// (see `misaka_storage::UtxoSet::compute_state_root_v4`).
    ///
    /// Carried on the block only in memory; the wire format
    /// (both borsh and serde) SKIPS this field during the
    /// parallel phase, keeping v0.9 ↔ v1.0 wire compatibility.
    /// Consensus does not read this value pre-activation.
    ///
    /// At the v1.0 activation epoch, Step 7 of the migration
    /// removes the skip attributes, promoting the field to
    /// wire-visible and digest-bound. See
    /// `docs/design/v100_smt_migration.md`.
    #[borsh(skip)]
    #[serde(default, skip)]
    pub state_root_smt: [u8; 32],
    /// ML-DSA-65 signature over block content.
    pub signature: Vec<u8>,
}

impl Block {
    /// Compute the BLAKE3 digest of this block (intra-chain identity).
    ///
    /// Includes all authenticated fields: epoch, round, author, timestamp,
    /// ancestors, transactions, commit_votes, tx_reject_votes.
    /// Signature is excluded (sign-then-hash pattern).
    ///
    /// NOTE: This is the intra-chain block identity used for DAG references.
    /// For signing/verification, use `signing_digest()` which includes chain context.
    pub fn digest(&self) -> BlockDigest {
        self.digest_inner(None)
    }

    /// Compute the chain-context-bound digest for signing and verification.
    ///
    /// Phase 30 (CR-2): Includes chain_id + genesis_hash to prevent
    /// cross-network replay. A block signed for testnet will have a
    /// different signing_digest than the same block on mainnet.
    pub fn signing_digest(
        &self,
        chain_ctx: &misaka_types::chain_context::ChainContext,
    ) -> BlockDigest {
        self.digest_inner(Some(chain_ctx))
    }

    fn digest_inner(
        &self,
        chain_ctx: Option<&misaka_types::chain_context::ChainContext>,
    ) -> BlockDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"MISAKA:narwhal:block:v2:");
        // CR-2: chain context binding (cross-network replay prevention)
        if let Some(ctx) = chain_ctx {
            h.update(&ctx.digest());
        }
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.round.to_le_bytes());
        h.update(&self.author.to_le_bytes());
        h.update(&self.timestamp_ms.to_le_bytes());
        for a in &self.ancestors {
            h.update(&a.digest.0);
        }
        for tx in &self.transactions {
            h.update(&(tx.len() as u32).to_le_bytes());
            h.update(tx);
        }
        h.update(&(self.commit_votes.len() as u32).to_le_bytes());
        for cv in &self.commit_votes {
            h.update(&cv.round.to_le_bytes());
            h.update(&cv.author.to_le_bytes());
            h.update(&cv.digest.0);
        }
        h.update(&(self.tx_reject_votes.len() as u32).to_le_bytes());
        for rv in &self.tx_reject_votes {
            h.update(&rv.round.to_le_bytes());
            h.update(&rv.author.to_le_bytes());
            h.update(&rv.digest.0);
        }
        // Phase 3 C7: Include state_root in block digest (HARD FORK).
        h.update(&self.state_root);
        BlockDigest(*h.finalize().as_bytes())
    }

    /// Phase 2b: Compute the IntentMessage-based signing digest.
    ///
    /// Uses NarwhalBlockPayload wrapped in IntentMessage for
    /// domain separation and cross-chain replay protection.
    /// The content_digest is the existing BLAKE3 block digest.
    pub fn signing_digest_v2(&self, app_id: misaka_types::intent::AppId) -> BlockDigest {
        use misaka_types::intent::{IntentMessage, IntentScope};
        use misaka_types::intent_payloads::NarwhalBlockPayload;

        let payload = NarwhalBlockPayload {
            round: self.round,
            author: self.author as u32,
            epoch: self.epoch,
            timestamp_ms: self.timestamp_ms,
            content_digest: self.digest().0,
            state_root: self.state_root,
        };
        let intent = IntentMessage::wrap(IntentScope::NarwhalBlock, app_id, &payload);
        BlockDigest(intent.signing_digest())
    }

    /// Get a BlockRef for this block.
    pub fn reference(&self) -> BlockRef {
        BlockRef {
            round: self.round,
            author: self.author,
            digest: self.digest(),
        }
    }

    /// Slot = (round, author).
    pub fn slot(&self) -> Slot {
        Slot {
            round: self.round,
            authority: self.author,
        }
    }

    /// Total serialized size estimate (for memory tracking).
    pub fn size_bytes(&self) -> usize {
        64 + self.ancestors.len() * 40
            + self.transactions.iter().map(|t| t.len() + 4).sum::<usize>()
            + self.commit_votes.len() * 40
            + self.tx_reject_votes.len() * 40
            + self.signature.len()
    }
}

// ═══════════════════════════════════════════════════════════
//  Verified block (signed + checked)
// ═══════════════════════════════════════════════════════════

/// A block whose signature has been verified.
///
/// Sui equivalent: VerifiedBlock — wraps Block in Arc for cheap cloning.
#[derive(Clone, Debug)]
pub struct VerifiedBlock {
    inner: Arc<Block>,
    block_ref: BlockRef,
}

impl VerifiedBlock {
    /// Wrap a block that has already been signature-verified.
    ///
    /// SEC-FIX: `pub(crate)` — only callable within misaka-dag.
    /// External code (network handlers, bridges) MUST use `new_for_test`
    /// (test only) or pass blocks through `BlockVerifier::verify()` which
    /// returns `VerifiedBlock` directly. This prevents unverified blocks
    /// from being laundered into the "verified" type.
    pub(crate) fn new_verified(block: Block) -> Self {
        let block_ref = block.reference();
        Self {
            inner: Arc::new(block),
            block_ref,
        }
    }

    /// Wrap a network-received block for forwarding to the consensus runtime.
    ///
    /// **WARNING**: This does NOT verify the block's signature. The caller
    /// MUST ensure the block is passed to `CoreEngine::process_block` which
    /// performs full verification at step 1 before any state mutation.
    ///
    /// This constructor exists because the consensus message channel requires
    /// `VerifiedBlock` type, but actual verification happens inside the runtime.
    /// It is intentionally NOT named `new_verified` to avoid implying the block
    /// has been checked.
    ///
    /// SEC-FIX: Replaces direct `new_verified` calls from network handlers.
    /// Do NOT call `subscriptions.publish()` or increment `blocks_accepted`
    /// on blocks created with this constructor.
    pub fn new_pending_verification(block: Block) -> Self {
        let block_ref = block.reference();
        Self {
            inner: Arc::new(block),
            block_ref,
        }
    }

    /// For tests: skip signature verification.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(block: Block) -> Self {
        Self::new_verified(block)
    }

    pub fn reference(&self) -> BlockRef {
        self.block_ref
    }
    pub fn round(&self) -> Round {
        self.block_ref.round
    }
    pub fn author(&self) -> AuthorityIndex {
        self.block_ref.author
    }
    pub fn digest(&self) -> BlockDigest {
        self.block_ref.digest
    }
    pub fn timestamp_ms(&self) -> BlockTimestampMs {
        self.inner.timestamp_ms
    }
    pub fn ancestors(&self) -> &[BlockRef] {
        &self.inner.ancestors
    }
    pub fn transactions(&self) -> &[Transaction] {
        &self.inner.transactions
    }
    pub fn commit_votes(&self) -> &[BlockRef] {
        &self.inner.commit_votes
    }
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }
    pub fn inner(&self) -> &Block {
        &self.inner
    }
    pub fn into_block(self) -> Arc<Block> {
        self.inner
    }
    pub fn size_bytes(&self) -> usize {
        self.inner.size_bytes()
    }
}

// ═══════════════════════════════════════════════════════════
//  Compact block metadata (memory-efficient)
// ═══════════════════════════════════════════════════════════

/// Compact block metadata — keeps only what's needed for DAG traversal.
///
/// Full block data is stored on disk; this stays in memory.
/// Sui stores ~40 bytes per block in memory for 16GB SR budget.
#[derive(Clone, Debug)]
pub struct CompactBlockMeta {
    pub block_ref: BlockRef,
    pub epoch: u64,
    pub timestamp_ms: BlockTimestampMs,
    pub ancestors: Vec<BlockRef>,
    pub committed: bool,
    pub tx_count: u32,
}

impl CompactBlockMeta {
    pub fn from_verified(vb: &VerifiedBlock) -> Self {
        Self {
            block_ref: vb.reference(),
            epoch: vb.epoch(),
            timestamp_ms: vb.timestamp_ms(),
            ancestors: vb.ancestors().to_vec(),
            committed: false,
            tx_count: vb.transactions().len() as u32,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Signature verification trait
// ═══════════════════════════════════════════════════════════

/// Trait for cryptographic signature verification.
///
/// Production: MlDsa65Verifier (FIPS 204 / Dilithium3)
/// Tests: MlDsa65TestSigner + TestValidatorSet (real ML-DSA-65 keys)
pub trait SignatureVerifier: Send + Sync + fmt::Debug {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String>;
}

/// Production ML-DSA-65 verifier — delegates to misaka_crypto.
///
/// SECURITY: This is the ONLY verifier for production use.
/// Routes: misaka_crypto → misaka_pqc → pqcrypto_mldsa::mldsa65.
/// NO feature gate — always compiled, always available.
#[derive(Debug)]
pub struct MlDsa65Verifier;

impl SignatureVerifier for MlDsa65Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
        misaka_crypto::signature::MlDsa65BlockVerifier
            .verify_block_signature(public_key, message, signature)
    }
}

/// Test-only verifier that accepts any non-empty signature.
///
/// SECURITY: This must NEVER be used in production code.
/// Restricted to `#[cfg(test)]` only — not available via `test-utils` feature
/// to prevent accidental use in non-test binaries (e.g. misaka-test-cluster).
#[cfg(test)]
#[derive(Debug)]
pub struct PermissiveVerifier;

#[cfg(test)]
impl SignatureVerifier for PermissiveVerifier {
    fn verify(&self, _public_key: &[u8], _message: &[u8], signature: &[u8]) -> Result<(), String> {
        if signature.is_empty() {
            Err("empty signature".to_string())
        } else {
            Ok(())
        }
    }
}

/// Trait for block signing.
///
/// Production: MlDsa65Signer
/// Tests: MlDsa65TestSigner (Phase 29 CR-1 fix)
pub trait BlockSigner: Send + Sync + fmt::Debug {
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> Vec<u8>;
}

// ── Phase 29 (CR-1): StructuralVerifier and DummySigner DELETED ──
// These were fail-open: StructuralVerifier accepted ANY non-empty signature,
// DummySigner produced fake signatures that StructuralVerifier would accept.
// Tests now use MlDsa65Verifier (production) + MlDsa65TestSigner (real keys).

/// Test signer — signs with a REAL ML-DSA-65 keypair.
///
/// CR-1 fix: Test builds run the same signature verification path as production.
/// No fake signatures, no structural-only checks.
#[cfg(any(test, feature = "test-utils"))]
pub struct MlDsa65TestSigner {
    keypair: misaka_pqc::MlDsaKeypair,
}

#[cfg(any(test, feature = "test-utils"))]
impl std::fmt::Debug for MlDsa65TestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65TestSigner")
            .field("pk_len", &self.keypair.public_key.as_bytes().len())
            .finish()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl MlDsa65TestSigner {
    pub fn generate() -> Self {
        Self {
            keypair: misaka_pqc::MlDsaKeypair::generate(),
        }
    }

    pub fn from_keypair(kp: misaka_pqc::MlDsaKeypair) -> Self {
        Self { keypair: kp }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl BlockSigner for MlDsa65TestSigner {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        misaka_pqc::pq_sign::ml_dsa_sign_raw(&self.keypair.secret_key, message)
            .expect("test ML-DSA-65 signing must succeed")
            .as_bytes()
            .to_vec()
    }
    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key.as_bytes().to_vec()
    }
}

/// Test validator set — generates N real ML-DSA-65 keypairs.
///
/// All tests MUST use this to construct `BlockVerifier` and sign blocks.
/// The verifier uses `MlDsa65Verifier` (production path), not a structural stub.
#[cfg(any(test, feature = "test-utils"))]
pub struct TestValidatorSet {
    pub signers: Vec<std::sync::Arc<MlDsa65TestSigner>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl TestValidatorSet {
    pub fn new(num: usize) -> Self {
        let signers = (0..num)
            .map(|_| std::sync::Arc::new(MlDsa65TestSigner::generate()))
            .collect();
        Self { signers }
    }

    /// Build a Committee with real public keys.
    pub fn committee(&self) -> crate::narwhal_types::committee::Committee {
        let pks: Vec<Vec<u8>> = self
            .signers
            .iter()
            .map(|s| s.keypair.public_key.as_bytes().to_vec())
            .collect();
        crate::narwhal_types::committee::Committee::new_uniform(0, self.signers.len(), pks)
    }

    /// Get a signer for `authority` as Arc<dyn BlockSigner>.
    pub fn signer(&self, authority: usize) -> std::sync::Arc<dyn BlockSigner> {
        self.signers[authority].clone()
    }

    /// Test chain context (chain_id=99, genesis_hash=zeroed).
    pub fn chain_ctx() -> misaka_types::chain_context::ChainContext {
        misaka_types::chain_context::ChainContext::new(99, [0u8; 32])
    }

    /// Build a BlockVerifier with MlDsa65Verifier (production verifier).
    pub fn verifier(&self, epoch: u64) -> crate::narwhal_dag::block_verifier::BlockVerifier {
        crate::narwhal_dag::block_verifier::BlockVerifier::new(
            self.committee(),
            epoch,
            std::sync::Arc::new(MlDsa65Verifier),
            Self::chain_ctx(),
        )
    }

    /// Test AppId (chain_id=99, genesis_hash=zeroed).
    pub fn app_id() -> misaka_types::intent::AppId {
        misaka_types::intent::AppId::new(99, [0u8; 32])
    }

    /// Sign a block as `author` using real ML-DSA-65 with IntentMessage.
    pub fn sign_block(&self, author: usize, block: &mut Block) {
        let digest = block.signing_digest_v2(Self::app_id());
        block.signature = self.signers[author].sign(&digest.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_digest_deterministic() {
        let block = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![1, 2, 3]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let d1 = block.digest();
        let d2 = block.digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_block_digest_includes_commit_votes() {
        let block1 = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![],
        };
        let block2 = Block {
            commit_votes: vec![BlockRef::new(0, 0, BlockDigest([0xFF; 32]))],
            ..block1.clone()
        };
        // Different commit_votes → different digest
        assert_ne!(block1.digest(), block2.digest());
    }

    #[test]
    fn test_block_ref_ordering() {
        let a = BlockRef::new(1, 0, BlockDigest([0; 32]));
        let b = BlockRef::new(2, 0, BlockDigest([0; 32]));
        let c = BlockRef::new(1, 1, BlockDigest([0; 32]));
        assert!(a < b); // lower round
        assert!(a < c); // same round, lower author
    }

    #[test]
    fn test_verified_block_accessors() {
        let block = Block {
            epoch: 5,
            round: 10,
            author: 3,
            timestamp_ms: 5000,
            ancestors: vec![],
            transactions: vec![vec![0xDE, 0xAD]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xBB; 64],
        };
        let vb = VerifiedBlock::new_for_test(block);
        assert_eq!(vb.round(), 10);
        assert_eq!(vb.author(), 3);
        assert_eq!(vb.epoch(), 5);
        assert_eq!(vb.transactions().len(), 1);
    }

    #[test]
    fn test_ml_dsa65_verifier_rejects_invalid() {
        let v = MlDsa65Verifier;
        // Real ML-DSA-65 verifier rejects invalid signatures
        assert!(v.verify(&[1; 32], b"msg", &[0xAA; 64]).is_err());
        assert!(v.verify(&[], b"msg", &[0xAA; 64]).is_err());
        assert!(v.verify(&[1; 32], b"msg", &[]).is_err());
    }

    #[test]
    fn test_compact_block_meta() {
        let block = Block {
            epoch: 0,
            round: 5,
            author: 2,
            timestamp_ms: 3000,
            ancestors: vec![BlockRef::new(4, 0, BlockDigest([0x11; 32]))],
            transactions: vec![vec![1], vec![2], vec![3]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xCC; 64],
        };
        let vb = VerifiedBlock::new_for_test(block);
        let meta = CompactBlockMeta::from_verified(&vb);
        assert_eq!(meta.tx_count, 3);
        assert!(!meta.committed);
        assert_eq!(meta.ancestors.len(), 1);
    }
}
