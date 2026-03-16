//! Bridge request and receipt types.

use sha3::{Sha3_256, Digest};
use serde::{Serialize, Deserialize};

/// Bridge transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeDirection {
    SolanaToMisaka,
    MisakaToSolana,
}

/// Bridge request status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeStatus {
    Pending,
    Approved,
    Executed,
    Rejected,
}

/// A bridge transfer request (either direction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRequest {
    /// Unique request identifier (hash of source tx + params).
    pub request_id: [u8; 32],
    /// Source chain ID.
    pub source_chain: u32,
    /// Destination chain ID.
    pub dest_chain: u32,
    /// Asset identifier (e.g. "SOL", "USDC", "MSK").
    pub asset_id: String,
    /// Amount in base units.
    pub amount: u64,
    /// Sender address/identifier on source chain.
    pub sender: String,
    /// Recipient address/identifier on destination chain.
    pub recipient: String,
    /// Monotonic nonce for replay protection.
    pub nonce: u64,
}

impl BridgeRequest {
    /// Compute the authorization hash (public input to the verifier).
    ///
    /// Binds: domain_tag || request_id || source || dest || asset || amount || recipient || nonce
    pub fn authorization_hash(&self, domain_tag: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(domain_tag);
        h.update(self.request_id);
        h.update(self.source_chain.to_le_bytes());
        h.update(self.dest_chain.to_le_bytes());
        h.update(self.asset_id.as_bytes());
        h.update(self.amount.to_le_bytes());
        h.update(self.recipient.as_bytes());
        h.update(self.nonce.to_le_bytes());
        h.finalize().into()
    }
}

/// A processed bridge receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeReceipt {
    pub request_id: [u8; 32],
    pub direction: BridgeDirection,
    pub status: BridgeStatus,
    pub amount: u64,
    pub recipient: String,
    pub asset_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_hash_deterministic() {
        let req = BridgeRequest {
            request_id: [0xAA; 32], source_chain: 1, dest_chain: 2,
            asset_id: "SOL".into(), amount: 1000,
            sender: "s".into(), recipient: "r".into(), nonce: 42,
        };
        let h1 = req.authorization_hash(b"TEST:");
        let h2 = req.authorization_hash(b"TEST:");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_domains_different_hashes() {
        let req = BridgeRequest {
            request_id: [0xBB; 32], source_chain: 1, dest_chain: 2,
            asset_id: "SOL".into(), amount: 1000,
            sender: "s".into(), recipient: "r".into(), nonce: 1,
        };
        let h1 = req.authorization_hash(b"MINT:");
        let h2 = req.authorization_hash(b"BURN:");
        assert_ne!(h1, h2);
    }
}
