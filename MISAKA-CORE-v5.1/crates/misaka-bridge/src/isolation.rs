//! Bridge Token Isolation — PQ/Non-PQ separation.
//!
//! # Design Principle
//!
//! MISAKA Network is fully post-quantum. External chains (Solana, Ethereum)
//! are NOT post-quantum. Bridge tokens must be clearly separated:
//!
//! ```text
//! native MISAKA  = PQ-secured (ML-DSA-65, lattice ring sig, STARK proofs)
//! wrapped MISAKA = non-PQ origin (bridged from Solana/Ethereum)
//! ```
//!
//! Wrapped tokens carry a `BridgeOrigin` tag that:
//! - Prevents mixing PQ and non-PQ security guarantees
//! - Enables different fee structures for bridged assets
//! - Allows future migration paths when external chains adopt PQ
//!
//! # Security Invariant
//!
//! A wrapped token can NEVER be treated as a native PQ-secured token.
//! Unwrapping (bridge out) is the only way to convert wrapped → native
//! on the origin chain.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// External chain identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ExternalChain {
    /// Solana (non-PQ: Ed25519).
    Solana = 1,
    /// Ethereum (non-PQ: secp256k1/ECDSA).
    Ethereum = 2,
    /// Bitcoin (non-PQ: secp256k1/Schnorr).
    Bitcoin = 3,
    /// Reserved for future PQ-enabled external chains.
    PqExternal = 100,
}

impl ExternalChain {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Solana),
            2 => Some(Self::Ethereum),
            3 => Some(Self::Bitcoin),
            100 => Some(Self::PqExternal),
            _ => None,
        }
    }

    /// Whether this external chain uses post-quantum cryptography.
    pub fn is_pq_secured(&self) -> bool {
        matches!(self, Self::PqExternal)
    }

    /// Human-readable chain name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Solana => "Solana",
            Self::Ethereum => "Ethereum",
            Self::Bitcoin => "Bitcoin",
            Self::PqExternal => "PQ-External",
        }
    }
}

/// Bridge origin tag attached to wrapped tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeOrigin {
    /// Source chain.
    pub chain: ExternalChain,
    /// Lock transaction hash on the source chain.
    pub lock_tx_hash: Vec<u8>,
    /// Original token mint/contract address on the source chain.
    pub source_token: Vec<u8>,
    /// Timestamp of the bridge lock event.
    pub lock_timestamp: u64,
    /// Whether this token retains PQ security guarantees.
    /// Always `false` for non-PQ chains, `true` only for PqExternal.
    pub pq_secured: bool,
}

/// Error type for bridge isolation operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IsolationError {
    #[error("PQ/non-PQ chain mismatch: {0}")]
    ChainTypeMismatch(String),
}

impl BridgeOrigin {
    /// Create a new bridge origin for a non-PQ chain.
    ///
    /// Returns `Err` if the chain is PQ-secured (use `new_pq()` instead).
    pub fn new_non_pq(
        chain: ExternalChain,
        lock_tx_hash: Vec<u8>,
        source_token: Vec<u8>,
        lock_timestamp: u64,
    ) -> Result<Self, IsolationError> {
        if chain.is_pq_secured() {
            return Err(IsolationError::ChainTypeMismatch(format!(
                "use new_pq() for PQ-secured chain {:?}",
                chain
            )));
        }
        Ok(Self {
            chain,
            lock_tx_hash,
            source_token,
            lock_timestamp,
            pq_secured: false,
        })
    }

    /// Create a bridge origin for a PQ-secured external chain.
    ///
    /// Returns `Err` if the chain is NOT PQ-secured (use `new_non_pq()` instead).
    pub fn new_pq(
        chain: ExternalChain,
        lock_tx_hash: Vec<u8>,
        source_token: Vec<u8>,
        lock_timestamp: u64,
    ) -> Result<Self, IsolationError> {
        if !chain.is_pq_secured() {
            return Err(IsolationError::ChainTypeMismatch(format!(
                "use new_non_pq() for non-PQ chain {:?}",
                chain
            )));
        }
        Ok(Self {
            chain,
            lock_tx_hash,
            source_token,
            lock_timestamp,
            pq_secured: true,
        })
    }

    /// Compute a unique identifier for this bridge origin.
    pub fn origin_id(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_BRIDGE_ORIGIN:v1:");
        h.update(&(self.chain as u32).to_le_bytes());
        h.update(&self.lock_tx_hash);
        h.update(&self.source_token);
        h.update(&self.lock_timestamp.to_le_bytes());
        h.finalize().into()
    }
}

/// Token type classification on MISAKA Network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// Native MISAKA token — fully PQ-secured.
    Native,
    /// Wrapped token from an external chain — security depends on origin.
    Wrapped(BridgeOrigin),
}

impl TokenType {
    /// Whether this token has full PQ security guarantees.
    pub fn is_pq_secured(&self) -> bool {
        match self {
            Self::Native => true,
            Self::Wrapped(origin) => origin.pq_secured,
        }
    }

    /// Security level description.
    pub fn security_label(&self) -> &'static str {
        match self {
            Self::Native => "PQ-secured (native MISAKA)",
            Self::Wrapped(origin) if origin.pq_secured => "PQ-secured (bridged from PQ chain)",
            Self::Wrapped(_) => "non-PQ (bridged from classical chain)",
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_is_pq() {
        assert!(TokenType::Native.is_pq_secured());
    }

    #[test]
    fn test_wrapped_solana_not_pq() {
        let origin = BridgeOrigin::new_non_pq(
            ExternalChain::Solana,
            vec![0xAA; 64],
            vec![0xBB; 32],
            1700000000,
        )
        .unwrap();
        let token = TokenType::Wrapped(origin);
        assert!(!token.is_pq_secured());
    }

    #[test]
    fn test_wrapped_ethereum_not_pq() {
        let origin = BridgeOrigin::new_non_pq(
            ExternalChain::Ethereum,
            vec![0xCC; 32],
            vec![0xDD; 20],
            1700000000,
        )
        .unwrap();
        assert!(!origin.pq_secured);
    }

    #[test]
    fn test_origin_id_deterministic() {
        let origin = BridgeOrigin::new_non_pq(
            ExternalChain::Solana,
            vec![0xAA; 64],
            vec![0xBB; 32],
            1700000000,
        )
        .unwrap();
        assert_eq!(origin.origin_id(), origin.origin_id());
    }

    #[test]
    fn test_origin_id_unique() {
        let o1 = BridgeOrigin::new_non_pq(
            ExternalChain::Solana,
            vec![0xAA; 64],
            vec![0xBB; 32],
            1700000000,
        )
        .unwrap();
        let o2 = BridgeOrigin::new_non_pq(
            ExternalChain::Ethereum,
            vec![0xAA; 64],
            vec![0xBB; 32],
            1700000000,
        )
        .unwrap();
        assert_ne!(o1.origin_id(), o2.origin_id());
    }

    #[test]
    fn test_external_chain_names() {
        assert_eq!(ExternalChain::Solana.name(), "Solana");
        assert_eq!(ExternalChain::Ethereum.name(), "Ethereum");
        assert_eq!(ExternalChain::Bitcoin.name(), "Bitcoin");
    }

    #[test]
    fn test_security_labels() {
        assert_eq!(
            TokenType::Native.security_label(),
            "PQ-secured (native MISAKA)"
        );
        let wrapped = TokenType::Wrapped(
            BridgeOrigin::new_non_pq(ExternalChain::Solana, vec![], vec![], 0).unwrap(),
        );
        assert_eq!(
            wrapped.security_label(),
            "non-PQ (bridged from classical chain)"
        );
    }

    #[test]
    fn test_external_chain_from_u32() {
        assert_eq!(ExternalChain::from_u32(1), Some(ExternalChain::Solana));
        assert_eq!(ExternalChain::from_u32(99), None);
    }

    #[test]
    fn test_new_pq_errors_on_non_pq_chain() {
        assert!(BridgeOrigin::new_pq(ExternalChain::Solana, vec![], vec![], 0).is_err());
    }

    #[test]
    fn test_new_non_pq_errors_on_pq_chain() {
        assert!(BridgeOrigin::new_non_pq(ExternalChain::PqExternal, vec![], vec![], 0).is_err());
    }
}
