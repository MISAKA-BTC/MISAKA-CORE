//! # PeerId — Public-Key-Derived Peer Identity
//!
//! # Design
//!
//! PeerId is the canonical identifier for every node in the MISAKA network.
//! It is derived from the node's transport public key (ML-DSA-65) via a
//! domain-separated hash, making it:
//!
//! - **Stable**: Same key → same PeerId across restarts
//! - **Deterministic**: No randomness involved
//! - **IP-independent**: Nodes can change IP without changing identity
//! - **Network-scoped**: Different chain_id → different PeerId (prevents cross-network confusion)
//!
//! ```text
//! PeerId = SHA3-256("MISAKA_PEER_ID_V1:" || chain_id_le_bytes || transport_pubkey_bytes)
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

const PEER_ID_DST: &[u8] = b"MISAKA_PEER_ID_V1:";

/// Canonical peer identity — 32-byte hash of the node's transport public key.
///
/// # Invariants
///
/// - PeerId is always derived from a real public key (never random)
/// - PeerId is domain-separated by chain_id
/// - PeerId is used as the primary key for ban/reputation/allowlist/registry
/// - PeerId is NOT an IP address and is NOT tied to any network location
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Derive a PeerId from a transport public key and chain_id.
    ///
    /// The chain_id binding prevents a node's identity from being valid
    /// on a different network (e.g., testnet PeerId ≠ mainnet PeerId).
    pub fn from_pubkey(transport_pubkey: &[u8], chain_id: u32) -> Self {
        let mut h = Sha3_256::new();
        h.update(PEER_ID_DST);
        h.update(chain_id.to_le_bytes());
        h.update(transport_pubkey);
        Self(h.finalize().into())
    }

    /// Zero PeerId (used as sentinel value, never matches a real peer).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Check if this is the zero/sentinel PeerId.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short hex representation for logging (first 8 hex chars).
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for PeerId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_deterministic() {
        let pk = [0xAA; 1952]; // ML-DSA-65 public key size
        let id1 = PeerId::from_pubkey(&pk, 1);
        let id2 = PeerId::from_pubkey(&pk, 1);
        assert_eq!(id1, id2, "same key + chain_id must produce same PeerId");
    }

    #[test]
    fn test_peer_id_chain_id_separation() {
        let pk = [0xBB; 1952];
        let id_mainnet = PeerId::from_pubkey(&pk, 1);
        let id_testnet = PeerId::from_pubkey(&pk, 2);
        assert_ne!(
            id_mainnet, id_testnet,
            "different chain_id must produce different PeerId"
        );
    }

    #[test]
    fn test_peer_id_key_separation() {
        let pk1 = [0xCC; 1952];
        let pk2 = [0xDD; 1952];
        let id1 = PeerId::from_pubkey(&pk1, 1);
        let id2 = PeerId::from_pubkey(&pk2, 1);
        assert_ne!(id1, id2, "different keys must produce different PeerId");
    }

    #[test]
    fn test_peer_id_zero_sentinel() {
        assert!(PeerId::ZERO.is_zero());
        let pk = [0xEE; 100];
        assert!(!PeerId::from_pubkey(&pk, 1).is_zero());
    }

    #[test]
    fn test_peer_id_display() {
        let id = PeerId([
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(format!("{}", id), "123456789abcdef0");
    }

    #[test]
    fn test_peer_id_hashmap_key() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let id = PeerId::from_pubkey(&[1; 32], 1);
        map.insert(id, "test");
        assert_eq!(map.get(&id), Some(&"test"));
    }
}
