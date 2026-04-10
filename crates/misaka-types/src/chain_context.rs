//! Chain context for cross-network replay prevention (CR-2).
//!
//! Every signed message (block, vote, tx) is bound to a specific chain
//! via ChainContext. This prevents:
//! - Testnet block replayed on mainnet (chain_id mismatch)
//! - Fork block replayed on main chain (genesis_hash mismatch)
//!
//! # Fields
//! - `chain_id`: numeric identifier (mainnet=1, testnet=2, devnet=3)
//! - `genesis_hash`: hash of the genesis block (fork discrimination)

use sha3::{Digest, Sha3_256};

/// Chain context — bound to all signed consensus messages.
///
/// Constructed once at node startup from CLI args + genesis manifest.
/// Passed to BlockVerifier, CoreEngine, and all signing paths.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainContext {
    /// Numeric chain identifier. mainnet=1, testnet=2, devnet=3.
    pub chain_id: u32,
    /// Hash of the genesis block. Discriminates forks with same chain_id.
    pub genesis_hash: [u8; 32],
}

impl ChainContext {
    pub const MAINNET_CHAIN_ID: u32 = 1;
    pub const TESTNET_CHAIN_ID: u32 = 2;
    pub const DEVNET_CHAIN_ID: u32 = 3;

    pub fn new(chain_id: u32, genesis_hash: [u8; 32]) -> Self {
        Self {
            chain_id,
            genesis_hash,
        }
    }

    /// 32-byte digest for compact inclusion in hash computations.
    ///
    /// `SHA3-256("MISAKA-CHAIN-CTX:v1:" || chain_id || genesis_hash)`
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"MISAKA-CHAIN-CTX:v1:");
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.genesis_hash);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_chain_ids_produce_different_digests() {
        let a = ChainContext::new(1, [0u8; 32]);
        let b = ChainContext::new(2, [0u8; 32]);
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn different_genesis_hashes_produce_different_digests() {
        let a = ChainContext::new(1, [0u8; 32]);
        let b = ChainContext::new(1, [1u8; 32]);
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn same_context_produces_same_digest() {
        let a = ChainContext::new(1, [0xAA; 32]);
        let b = ChainContext::new(1, [0xAA; 32]);
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn digest_is_32_bytes() {
        let ctx = ChainContext::new(1, [0u8; 32]);
        assert_eq!(ctx.digest().len(), 32);
    }
}
