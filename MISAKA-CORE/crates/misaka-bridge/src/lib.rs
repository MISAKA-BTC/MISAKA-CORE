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

pub mod circuit_breaker;
pub mod isolation;
pub mod persistence;
pub mod registry;
pub mod replay;
pub mod request;
pub mod threshold;
pub mod verifier;

use std::collections::HashMap;

pub use circuit_breaker::{BridgeStateManager, CheckResult, CircuitBreaker};
pub use isolation::{BridgeOrigin, ExternalChain, IsolationError, TokenType};
pub use registry::{AssetRegistry, BridgedAsset};
pub use replay::ReplayProtection;
pub use request::{BridgeDirection, BridgeReceipt, BridgeRequest, BridgeStatus};
#[cfg(feature = "dev-bridge-mock")]
pub use verifier::MockVerifier;
pub use verifier::{
    validate_verifier_for_production, AuthorizationProof, BridgeVerifier, CommitteeMember,
    CommitteeVerifier,
};

pub const CHAIN_ID_SOLANA: u32 = 1;
pub const CHAIN_ID_MISAKA: u32 = 2;

// ── Domain Separation ──
pub const DST_BRIDGE_MINT: &[u8] = b"MISAKA_BRIDGE_MINT:v1:";
pub const DST_BRIDGE_RELEASE: &[u8] = b"MISAKA_BRIDGE_RELEASE:v1:";
pub const DST_BRIDGE_BURN: &[u8] = b"MISAKA_BRIDGE_BURN:v1:";
pub const DST_BRIDGE_ADMIN: &[u8] = b"MISAKA_BRIDGE_ADMIN:v1:";

/// Bridge module orchestrator.
///
/// # No-Rollback Architecture
///
/// The bridge has a `safety` state manager that can pause/resume the bridge.
/// Bridge incidents are resolved by pausing, NOT by L1 chain rollback.
pub struct BridgeModule {
    pub verifier: Box<dyn BridgeVerifier>,
    pub registry: AssetRegistry,
    pub replay: ReplayProtection,
    pub pending_mints: HashMap<[u8; 32], BridgeRequest>,
    pub pending_burns: HashMap<[u8; 32], BridgeRequest>,
    /// Bridge safety state (pause/resume, circuit breaker).
    pub safety: BridgeStateManager,
}

impl BridgeModule {
    /// Create a bridge module with durable replay protection.
    ///
    /// `replay_data_path` is the file path for persistent nullifier storage.
    /// This ensures replay protection survives restarts.
    pub fn new(
        verifier: Box<dyn BridgeVerifier>,
        replay_data_path: &std::path::Path,
    ) -> Result<Self, BridgeError> {
        let replay = ReplayProtection::durable(replay_data_path)
            .map_err(|e| BridgeError::Internal(format!("replay protection init failed: {}", e)))?;
        Ok(Self {
            verifier,
            registry: AssetRegistry::new(),
            replay,
            pending_mints: HashMap::new(),
            pending_burns: HashMap::new(),
            safety: BridgeStateManager::new(),
        })
    }

    /// Create a bridge module with volatile replay protection.
    /// **TEST ONLY** — all state is lost on restart.
    #[cfg(test)]
    pub fn new_for_test(verifier: Box<dyn BridgeVerifier>) -> Self {
        Self {
            verifier,
            registry: AssetRegistry::new(),
            replay: ReplayProtection::new_volatile_for_test(),
            pending_mints: HashMap::new(),
            pending_burns: HashMap::new(),
            safety: BridgeStateManager::new(),
        }
    }

    /// Check that the bridge is active. Returns Err(Paused) if not.
    fn require_active(&self) -> Result<(), BridgeError> {
        if !self.safety.is_active() {
            return Err(BridgeError::Paused);
        }
        Ok(())
    }

    /// Process a lock event from Solana → mint on Misaka.
    pub fn process_lock_event(
        &mut self,
        request: BridgeRequest,
        proof: AuthorizationProof,
    ) -> Result<BridgeReceipt, BridgeError> {
        // 0. Pause guard — bridge must be active
        self.require_active()?;

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
        self.verifier
            .verify(&proof, &public_input)
            .map_err(|e| BridgeError::AuthorizationFailed(e))?;

        // 4. Mark replay
        self.replay.mark_used(request.request_id).map_err(|e| {
            BridgeError::AuthorizationFailed(format!("replay persist failed: {}", e))
        })?;

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
        // 0. Pause guard — bridge must be active
        self.require_active()?;

        if self.replay.is_used(&request.request_id) {
            return Err(BridgeError::ReplayDetected(hex::encode(request.request_id)));
        }

        if !self.registry.is_registered(&request.asset_id) {
            return Err(BridgeError::UnknownAsset(request.asset_id.clone()));
        }

        let public_input = request.authorization_hash(DST_BRIDGE_BURN);
        self.verifier
            .verify(&proof, &public_input)
            .map_err(|e| BridgeError::AuthorizationFailed(e))?;

        self.replay.mark_used(request.request_id).map_err(|e| {
            BridgeError::AuthorizationFailed(format!("replay persist failed: {}", e))
        })?;

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
    #[error("isolation error: {0}")]
    Isolation(#[from] IsolationError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_bridge_lock_and_mint() {
        let mut bridge = BridgeModule::new_for_test(Box::new(MockVerifier));
        bridge
            .registry
            .register("SOL".into(), CHAIN_ID_SOLANA, "So1...".into());

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

        let receipt = bridge
            .process_lock_event(req, AuthorizationProof::mock())
            .unwrap();
        assert_eq!(receipt.status, BridgeStatus::Approved);
        assert_eq!(receipt.amount, 1_000_000);
    }

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_bridge_replay_rejected() {
        let mut bridge = BridgeModule::new_for_test(Box::new(MockVerifier));
        bridge
            .registry
            .register("SOL".into(), CHAIN_ID_SOLANA, "So1...".into());

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

        bridge
            .process_lock_event(req.clone(), AuthorizationProof::mock())
            .unwrap();
        assert!(bridge
            .process_lock_event(req, AuthorizationProof::mock())
            .is_err());
    }

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_bridge_unknown_asset() {
        let mut bridge = BridgeModule::new_for_test(Box::new(MockVerifier));
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
        assert!(bridge
            .process_lock_event(req, AuthorizationProof::mock())
            .is_err());
    }

    /// Production-path test: CommitteeVerifier with real ML-DSA-65 verification.
    #[test]
    fn test_bridge_with_committee_verifier() {
        use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair};

        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();

        let m1 = CommitteeMember {
            pk_hash: {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(kp1.public_key.as_bytes());
                h.finalize().into()
            },
            public_key: kp1.public_key.as_bytes().to_vec(),
        };
        let m2 = CommitteeMember {
            pk_hash: {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(kp2.public_key.as_bytes());
                h.finalize().into()
            },
            public_key: kp2.public_key.as_bytes().to_vec(),
        };

        let v = CommitteeVerifier::new(1, vec![m1.clone(), m2], 2).unwrap();

        let mut bridge = BridgeModule::new_for_test(Box::new(v));
        bridge
            .registry
            .register("SOL".into(), CHAIN_ID_SOLANA, "So1...".into());

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

        // Build committee proof: real ML-DSA-65 signature
        // Build signing message the same way the verifier does
        let signing_msg = {
            use sha3::{Digest, Sha3_256};
            let domain_tag = b"MISAKA_BRIDGE_AUTH:v2:";
            let public_input = req.authorization_hash(DST_BRIDGE_MINT);
            let mut msg = Vec::new();
            msg.extend_from_slice(domain_tag);
            msg.extend_from_slice(&2u32.to_le_bytes()); // chain_id
            msg.extend_from_slice(&public_input);
            msg.extend_from_slice(&1u64.to_le_bytes()); // nonce
            let mut h = Sha3_256::new();
            h.update(&msg);
            h.finalize().to_vec()
        };

        let sig = ml_dsa_sign_raw(&kp1.secret_key, &signing_msg).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&m1.pk_hash);
        proof_data.extend_from_slice(sig.as_bytes());

        let proof = AuthorizationProof {
            scheme: "committee-v2-ml-dsa".into(),
            proof_data,
            identity_commitment: [0; 32],
            nonce: 1,
        };

        let receipt = bridge.process_lock_event(req, proof).unwrap();
        assert_eq!(receipt.status, BridgeStatus::Approved);
    }
}
