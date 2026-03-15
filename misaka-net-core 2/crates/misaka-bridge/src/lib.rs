//! Cross-chain Bridge — ZK-ACE authorization abstraction.
//!
//! Misaka side manages:
//! - Bridge request / receipt lifecycle
//! - ZK-ACE authorization (identity commitment + replay protection)
//! - Asset registry (which Solana SPL tokens are bridged)
//! - Wrapped asset mint/burn accounting
//!
//! The verifier trait is abstract: initial devnet uses MockVerifier,
//! future mainnet plugs in real ZK proof verification.

pub mod verifier;
pub mod request;
pub mod registry;
pub mod replay;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

pub use verifier::{BridgeVerifier, CommitteeVerifier, AuthorizationProof, validate_verifier_for_production};
#[cfg(feature = "dev-bridge-mock")]
pub use verifier::MockVerifier;
pub use request::{BridgeRequest, BridgeReceipt, BridgeDirection, BridgeStatus};
pub use registry::{AssetRegistry, BridgedAsset};
pub use replay::ReplayProtection;

pub const CHAIN_ID_SOLANA: u32 = 1;
pub const CHAIN_ID_MISAKA: u32 = 2;

// ── Domain Separation ──
pub const DST_BRIDGE_MINT:    &[u8] = b"MISAKA_BRIDGE_MINT:v1:";
pub const DST_BRIDGE_RELEASE: &[u8] = b"MISAKA_BRIDGE_RELEASE:v1:";
pub const DST_BRIDGE_BURN:    &[u8] = b"MISAKA_BRIDGE_BURN:v1:";
pub const DST_BRIDGE_ADMIN:   &[u8] = b"MISAKA_BRIDGE_ADMIN:v1:";

/// Bridge module orchestrator.
pub struct BridgeModule {
    pub verifier: Box<dyn BridgeVerifier>,
    pub registry: AssetRegistry,
    pub replay: ReplayProtection,
    pub pending_mints: HashMap<[u8; 32], BridgeRequest>,
    pub pending_burns: HashMap<[u8; 32], BridgeRequest>,
}

impl BridgeModule {
    pub fn new(verifier: Box<dyn BridgeVerifier>) -> Self {
        Self {
            verifier,
            registry: AssetRegistry::new(),
            replay: ReplayProtection::new(),
            pending_mints: HashMap::new(),
            pending_burns: HashMap::new(),
        }
    }

    /// Process a lock event from Solana → mint on Misaka.
    pub fn process_lock_event(
        &mut self,
        request: BridgeRequest,
        proof: AuthorizationProof,
    ) -> Result<BridgeReceipt, BridgeError> {
        // 1. Replay check
        if self.replay.is_used(&request.request_id) {
            return Err(BridgeError::ReplayDetected(hex::encode(request.request_id)));
        }

        // 2. Asset must be registered
        if !self.registry.is_registered(&request.asset_id) {
            return Err(BridgeError::UnknownAsset(request.asset_id.clone()));
        }

        // 3. Verify authorization proof
        let public_input = request.authorization_hash(DST_BRIDGE_MINT);
        self.verifier.verify(&proof, &public_input)
            .map_err(|e| BridgeError::AuthorizationFailed(e))?;

        // 4. Mark replay
        self.replay.mark_used(request.request_id);

        // 5. Create receipt
        let receipt = BridgeReceipt {
            request_id: request.request_id,
            direction: BridgeDirection::SolanaToMisaka,
            status: BridgeStatus::Approved,
            amount: request.amount,
            recipient: request.recipient.clone(),
            asset_id: request.asset_id.clone(),
        };

        Ok(receipt)
    }

    /// Process a burn on Misaka → unlock on Solana.
    pub fn process_burn_request(
        &mut self,
        request: BridgeRequest,
        proof: AuthorizationProof,
    ) -> Result<BridgeReceipt, BridgeError> {
        if self.replay.is_used(&request.request_id) {
            return Err(BridgeError::ReplayDetected(hex::encode(request.request_id)));
        }

        if !self.registry.is_registered(&request.asset_id) {
            return Err(BridgeError::UnknownAsset(request.asset_id.clone()));
        }

        let public_input = request.authorization_hash(DST_BRIDGE_BURN);
        self.verifier.verify(&proof, &public_input)
            .map_err(|e| BridgeError::AuthorizationFailed(e))?;

        self.replay.mark_used(request.request_id);

        let receipt = BridgeReceipt {
            request_id: request.request_id,
            direction: BridgeDirection::MisakaToSolana,
            status: BridgeStatus::Approved,
            amount: request.amount,
            recipient: request.recipient.clone(),
            asset_id: request.asset_id.clone(),
        };

        Ok(receipt)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("replay detected: {0}")]
    ReplayDetected(String),
    #[error("unknown asset: {0}")]
    UnknownAsset(String),
    #[error("authorization failed: {0}")]
    AuthorizationFailed(String),
    #[error("bridge paused")]
    Paused,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_bridge_lock_and_mint() {
        let mut bridge = BridgeModule::new(Box::new(MockVerifier));
        bridge.registry.register("SOL".into(), CHAIN_ID_SOLANA, "So1...".into());

        let req = BridgeRequest {
            request_id: [0xAA; 32],
            source_chain: CHAIN_ID_SOLANA,
            dest_chain: CHAIN_ID_MISAKA,
            asset_id: "SOL".into(),
            amount: 1_000_000,
            sender: "sender_solana".into(),
            recipient: "recipient_misaka".into(),
            nonce: 1,
        };

        let receipt = bridge.process_lock_event(req, AuthorizationProof::mock()).unwrap();
        assert_eq!(receipt.status, BridgeStatus::Approved);
        assert_eq!(receipt.amount, 1_000_000);
    }

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_bridge_replay_rejected() {
        let mut bridge = BridgeModule::new(Box::new(MockVerifier));
        bridge.registry.register("SOL".into(), CHAIN_ID_SOLANA, "So1...".into());

        let req = BridgeRequest {
            request_id: [0xBB; 32],
            source_chain: CHAIN_ID_SOLANA,
            dest_chain: CHAIN_ID_MISAKA,
            asset_id: "SOL".into(),
            amount: 500,
            sender: "s".into(),
            recipient: "r".into(),
            nonce: 1,
        };

        bridge.process_lock_event(req.clone(), AuthorizationProof::mock()).unwrap();
        assert!(bridge.process_lock_event(req, AuthorizationProof::mock()).is_err());
    }

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_bridge_unknown_asset() {
        let mut bridge = BridgeModule::new(Box::new(MockVerifier));
        let req = BridgeRequest {
            request_id: [0xCC; 32],
            source_chain: CHAIN_ID_SOLANA,
            dest_chain: CHAIN_ID_MISAKA,
            asset_id: "UNKNOWN".into(),
            amount: 100,
            sender: "s".into(),
            recipient: "r".into(),
            nonce: 1,
        };
        assert!(bridge.process_lock_event(req, AuthorizationProof::mock()).is_err());
    }

    /// Production-path test: CommitteeVerifier with real M-of-N check.
    #[test]
    fn test_bridge_with_committee_verifier() {
        let member1 = [0xAA; 32];
        let member2 = [0xBB; 32];
        let v = CommitteeVerifier::new(1, vec![member1, member2]).unwrap();
        let mut bridge = BridgeModule::new(Box::new(v));
        bridge.registry.register("SOL".into(), CHAIN_ID_SOLANA, "So1...".into());

        let req = BridgeRequest {
            request_id: [0xDD; 32],
            source_chain: CHAIN_ID_SOLANA,
            dest_chain: CHAIN_ID_MISAKA,
            asset_id: "SOL".into(),
            amount: 5000,
            sender: "s".into(),
            recipient: "r".into(),
            nonce: 1,
        };

        // Build committee proof: 1 member signature
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&member1);
        proof_data.extend_from_slice(&[0u8; 64]);

        let proof = AuthorizationProof {
            scheme: "committee-v1".into(),
            proof_data,
            identity_commitment: [0; 32],
            nonce: 1,
        };

        let receipt = bridge.process_lock_event(req, proof).unwrap();
        assert_eq!(receipt.status, BridgeStatus::Approved);
    }
}
