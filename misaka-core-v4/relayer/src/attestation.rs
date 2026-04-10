//! Multi-signer attestation for bridge operations.
//!
//! Requires N-of-M relayer signatures before a mint is authorized.
//!
//! Each relayer independently verifies the burn on Solana, then signs
//! an attestation message. Only when N attestations are collected from
//! M authorized relayers is the mint authorized.

use crate::message::VerifiedBurn;
use misaka_types::intent::{AppId, IntentMessage, IntentScope};
use misaka_types::intent_payloads::BridgeAttestationPayload;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fmt;

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Configuration for the N-of-M attestation scheme.
pub struct AttestationConfig {
    /// Minimum signatures required (N).
    pub required_signatures: usize,
    /// Total authorized relayers (M).
    pub total_relayers: usize,
    /// Authorized relayer public keys (ML-DSA-65, 1952 bytes each).
    pub authorized_relayers: Vec<Vec<u8>>,
    /// Our relayer index.
    pub own_index: usize,
    /// Phase 2b: AppId for IntentMessage-based signing.
    pub app_id: AppId,
}

// ═══════════════════════════════════════════════════════════════
//  Attestation Types
// ═══════════════════════════════════════════════════════════════

/// A single relayer's attestation for a burn event.
pub struct BurnAttestation {
    pub burn_id: String,
    pub solana_tx_signature: String,
    pub burn_amount_raw: u64,
    pub wallet_address: String,
    pub misaka_receive_address: String,
    pub relayer_index: usize,
    /// ML-DSA-65 signature over the attestation message.
    pub signature: Vec<u8>,
    /// Solana slot at which the burn occurred (monotonic nonce for replay protection).
    pub burn_slot: u64,
}

/// Errors that can occur during attestation collection.
#[derive(Debug)]
pub enum AttestationError {
    /// Relayer index not in the authorized set.
    UnauthorizedRelayer,
    /// Signature does not verify against the relayer's public key.
    InvalidSignature,
    /// This relayer already attested for this burn.
    DuplicateAttestation,
    /// Burn ID not found in pending attestations.
    BurnNotFound,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnauthorizedRelayer => write!(f, "relayer not in authorized set"),
            Self::InvalidSignature => write!(f, "attestation signature invalid"),
            Self::DuplicateAttestation => write!(f, "duplicate attestation from same relayer"),
            Self::BurnNotFound => write!(f, "burn ID not found in pending attestations"),
        }
    }
}

impl std::error::Error for AttestationError {}

// ═══════════════════════════════════════════════════════════════
//  Attestation Collector
// ═══════════════════════════════════════════════════════════════

/// Collects attestations from multiple relayers and checks quorum.
pub struct AttestationCollector {
    config: AttestationConfig,
    /// burn_id -> collected attestations
    pending: HashMap<String, Vec<BurnAttestation>>,
}

impl AttestationCollector {
    /// Create a new attestation collector.
    ///
    /// # Panics
    ///
    /// Panics if `required_signatures < 2` in non-dev builds (Phase 1 C5 fix).
    /// N=1 is a single point of trust — one lying relayer could forge mints.
    /// See docs/architecture.md §7.2.
    pub fn new(config: AttestationConfig) -> Self {
        // Phase 1 (C5): reject N=1 in non-dev builds
        #[cfg(not(any(feature = "dev", test)))]
        if config.required_signatures < 2 {
            panic!(
                "FATAL: required_signatures must be >= 2 in production builds. \
                 N={} is a single point of trust; use 'dev' feature flag \
                 for local testing only. See docs/architecture.md §7.2.",
                config.required_signatures,
            );
        }
        if config.required_signatures > config.total_relayers {
            panic!(
                "FATAL: required_signatures ({}) > total_relayers ({})",
                config.required_signatures, config.total_relayers,
            );
        }
        Self {
            config,
            pending: HashMap::new(),
        }
    }

    /// Submit our own attestation for a verified burn.
    ///
    /// The `signer` closure takes a message byte slice and returns a signature.
    /// In single-relayer mode (N=1, M=1), this is the only attestation needed.
    pub fn attest(
        &mut self,
        burn: &VerifiedBurn,
        burn_id: &str,
        solana_tx_sig: &str,
        misaka_receive_address: &str,
        signer: &dyn Fn(&[u8]) -> Vec<u8>,
    ) -> BurnAttestation {
        // Phase 2b: sign the IntentMessage digest
        let digest = self.attestation_digest(
            burn_id,
            solana_tx_sig,
            burn.amount,
            &burn.wallet,
            misaka_receive_address,
            burn.slot,
        );

        let signature = signer(&digest);

        let attestation = BurnAttestation {
            burn_id: burn_id.to_string(),
            solana_tx_signature: solana_tx_sig.to_string(),
            burn_amount_raw: burn.amount,
            wallet_address: burn.wallet.clone(),
            misaka_receive_address: misaka_receive_address.to_string(),
            relayer_index: self.config.own_index,
            signature,
            burn_slot: burn.slot,
        };

        // Auto-insert our own attestation into pending
        self.pending
            .entry(burn_id.to_string())
            .or_insert_with(Vec::new)
            .push(BurnAttestation {
                burn_id: attestation.burn_id.clone(),
                solana_tx_signature: attestation.solana_tx_signature.clone(),
                burn_amount_raw: attestation.burn_amount_raw,
                wallet_address: attestation.wallet_address.clone(),
                misaka_receive_address: attestation.misaka_receive_address.clone(),
                relayer_index: attestation.relayer_index,
                signature: attestation.signature.clone(),
                burn_slot: attestation.burn_slot,
            });

        attestation
    }

    /// Receive an attestation from another relayer.
    /// Returns `Ok(true)` if the N-of-M threshold is now met.
    pub fn receive_attestation(
        &mut self,
        attestation: BurnAttestation,
    ) -> Result<bool, AttestationError> {
        // Check relayer is authorized
        if attestation.relayer_index >= self.config.total_relayers {
            return Err(AttestationError::UnauthorizedRelayer);
        }

        // Verify the relayer has a known public key
        if attestation.relayer_index >= self.config.authorized_relayers.len() {
            return Err(AttestationError::UnauthorizedRelayer);
        }

        // Phase 2b: Verify signature against IntentMessage digest
        let expected_digest = self.attestation_digest(
            &attestation.burn_id,
            &attestation.solana_tx_signature,
            attestation.burn_amount_raw,
            &attestation.wallet_address,
            &attestation.misaka_receive_address,
            attestation.burn_slot,
        );

        let pubkey = &self.config.authorized_relayers[attestation.relayer_index];
        if !Self::verify_signature_v2(pubkey, &expected_digest, &attestation.signature) {
            return Err(AttestationError::InvalidSignature);
        }

        // Check for duplicate attestation from the same relayer
        let attestations = self
            .pending
            .entry(attestation.burn_id.clone())
            .or_insert_with(Vec::new);

        if attestations
            .iter()
            .any(|a| a.relayer_index == attestation.relayer_index)
        {
            return Err(AttestationError::DuplicateAttestation);
        }

        attestations.push(attestation);

        // Check if quorum is now met
        Ok(attestations.len() >= self.config.required_signatures)
    }

    /// Check if a burn has enough consistent attestations to proceed with mint.
    ///
    /// SEC-FIX: Now verifies that all attestations agree on burn_amount_raw,
    /// wallet_address, and misaka_receive_address. Previously only checked count.
    pub fn is_authorized(&self, burn_id: &str) -> bool {
        let attestations = match self.pending.get(burn_id) {
            Some(a) if a.len() >= self.config.required_signatures => a,
            _ => return false,
        };

        // Defense-in-depth: verify all attestations agree on critical fields.
        // Individual signature verification already covers this (the signed digest
        // includes these fields), but this is an explicit consistency check.
        let first = &attestations[0];
        for att in &attestations[1..] {
            if att.burn_amount_raw != first.burn_amount_raw
                || att.wallet_address != first.wallet_address
                || att.misaka_receive_address != first.misaka_receive_address
            {
                tracing::warn!(
                    "Attestation inconsistency for burn {}: amount/wallet/addr mismatch between relayers {} and {}",
                    burn_id, first.relayer_index, att.relayer_index
                );
                return false;
            }
        }

        true
    }

    /// Get all attestations for a burn (for on-chain submission).
    pub fn get_attestations(&self, burn_id: &str) -> Option<&[BurnAttestation]> {
        self.pending.get(burn_id).map(|v| v.as_slice())
    }

    /// Phase 2b: Compute the IntentMessage-based signing digest for a burn attestation.
    ///
    /// All relayers must sign the same digest for a given burn event.
    /// The digest is: SHA3-256("MISAKA-INTENT:v1:" || borsh(IntentMessage {
    ///     scope: BridgeAttestation, app_id, payload: borsh(BridgeAttestationPayload) }))
    fn attestation_digest(
        &self,
        burn_id: &str,
        tx_sig: &str,
        amount: u64,
        wallet: &str,
        recipient: &str,
        burn_slot: u64,
    ) -> [u8; 32] {
        // Compute burn_id hash from burn_id string AND tx_sig for cryptographic binding.
        // Including tx_sig ensures the digest is bound to the specific Solana transaction,
        // preventing attestation reuse across different transactions.
        let burn_id_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(burn_id.as_bytes());
            h.update(tx_sig.as_bytes());
            h.update(wallet.as_bytes());
            let r = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        };
        // Audit #12 fix: recipient address is hex-decoded (not raw UTF-8 bytes)
        // to produce a deterministic 32-byte address regardless of encoding.
        let receive_addr: [u8; 32] = {
            let mut addr = [0u8; 32];
            if let Ok(bytes) = hex::decode(recipient) {
                let copy_len = bytes.len().min(32);
                addr[..copy_len].copy_from_slice(&bytes[..copy_len]);
            } else {
                // Fallback: SHA3-256 hash of the recipient string for deterministic 32 bytes
                let h = Sha3_256::digest(recipient.as_bytes());
                addr.copy_from_slice(&h);
            }
            addr
        };

        let payload = BridgeAttestationPayload {
            burn_id: burn_id_hash,
            burn_amount: amount,
            // Audit #12 fix: burn_slot from VerifiedBurn, used as monotonic nonce.
            // burn_slot is the Solana slot at which the burn occurred — naturally
            // monotonic and unique per burn event, preventing committee signature replay.
            burn_slot,
            misaka_receive_address: receive_addr,
            nonce: burn_slot, // Use burn_slot as monotonic nonce (unique per burn event)
        };
        let intent = IntentMessage::wrap(
            IntentScope::BridgeAttestation,
            self.config.app_id.clone(),
            &payload,
        );
        intent.signing_digest()
    }

    /// Phase 2b: Verify ML-DSA-65 signature over IntentMessage digest.
    fn verify_signature_v2(pubkey: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
        use misaka_pqc::pq_sign::{MlDsaPublicKey, MlDsaSignature, ml_dsa_verify_raw};

        if pubkey.len() != 1952 || signature.len() != 3309 {
            return false;
        }
        let pk = match MlDsaPublicKey::from_bytes(pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match MlDsaSignature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        // Verify over the IntentMessage digest (raw, no domain prefix).
        // IntentMessage already provides domain separation via scope + app_id.
        ml_dsa_verify_raw(&pk, digest, &sig).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::VerifiedBurn;

    /// Phase 1 (C4): Generate a real ML-DSA-65 keypair for testing.
    fn make_test_keypair() -> (Vec<u8>, misaka_pqc::pq_sign::MlDsaKeypair) {
        let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
        let pk_bytes = kp.public_key.as_bytes().to_vec();
        (pk_bytes, kp)
    }

    /// Phase 2b: Create an ML-DSA-65 signer closure that signs digest.
    /// IntentMessage already provides domain separation, so we use empty domain prefix.
    fn make_test_signer(kp: &misaka_pqc::pq_sign::MlDsaKeypair) -> impl Fn(&[u8]) -> Vec<u8> + '_ {
        move |digest: &[u8]| {
            use misaka_pqc::pq_sign::ml_dsa_sign_raw;
            let sig = ml_dsa_sign_raw(&kp.secret_key, digest)
                .expect("ML-DSA-65 sign must not fail in test");
            sig.as_bytes().to_vec()
        }
    }

    fn test_app_id() -> AppId {
        AppId::new(2, [0u8; 32])
    }

    fn make_verified_burn() -> VerifiedBurn {
        VerifiedBurn {
            amount: 1_000_000_000,
            wallet: "SoLwALLET1111111111111111111111111111111111".to_string(),
            mint: "MISAKAmint111111111111111111111111111111111".to_string(),
            slot: 12345,
            block_time: 1700000000,
            burn_index: 0,
        }
    }

    #[test]
    fn test_single_relayer_mode() {
        // N=1, M=1 — now using real ML-DSA-65 keys
        let (pk0, kp0) = make_test_keypair();
        let config = AttestationConfig {
            required_signatures: 1,
            total_relayers: 1,
            authorized_relayers: vec![pk0],
            own_index: 0,
            app_id: test_app_id(),
        };

        let mut collector = AttestationCollector::new(config);
        let burn = make_verified_burn();
        let signer = make_test_signer(&kp0);

        let _attestation = collector.attest(
            &burn,
            "burn-001",
            "txsig111111111111111111111111111111111111111111",
            "msk1recipient1111111111111111111",
            &signer,
        );

        // With N=1, our own attestation is enough
        assert!(
            collector.is_authorized("burn-001"),
            "single relayer should be authorized after own attestation"
        );

        let attestations = collector.get_attestations("burn-001").unwrap();
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].relayer_index, 0);
    }

    #[test]
    fn test_3_of_5_quorum() {
        // N=3, M=5 — multi-relayer quorum with real ML-DSA-65 keys
        let keypairs: Vec<_> = (0..5).map(|_| make_test_keypair()).collect();
        let pubkeys: Vec<Vec<u8>> = keypairs.iter().map(|(pk, _)| pk.clone()).collect();
        // Keep keypairs alive for signing
        let kps: Vec<&misaka_pqc::pq_sign::MlDsaKeypair> = keypairs.iter().map(|(_, kp)| kp).collect();

        let config = AttestationConfig {
            required_signatures: 3,
            total_relayers: 5,
            authorized_relayers: pubkeys.clone(),
            own_index: 0,
            app_id: test_app_id(),
        };

        let mut collector = AttestationCollector::new(config);
        let burn = make_verified_burn();
        let burn_id = "burn-002";
        let tx_sig = "txsig222222222222222222222222222222222222222222";
        let recipient = "msk1recipient2222222222222222222";

        // Relayer 0 (us) attests
        let signer0 = make_test_signer(kps[0]);
        collector.attest(&burn, burn_id, tx_sig, recipient, &signer0);
        assert!(
            !collector.is_authorized(burn_id),
            "should need more attestations (1/3)"
        );

        // Relayer 1 attests
        let digest = collector.attestation_digest(
            burn_id,
            tx_sig,
            burn.amount,
            &burn.wallet,
            recipient,
            burn.slot,
        );
        let signer1 = make_test_signer(kps[1]);
        let sig1 = signer1(&digest);
        let att1 = BurnAttestation {
            burn_id: burn_id.to_string(),
            solana_tx_signature: tx_sig.to_string(),
            burn_amount_raw: burn.amount,
            wallet_address: burn.wallet.clone(),
            misaka_receive_address: recipient.to_string(),
            relayer_index: 1,
            signature: sig1,
            burn_slot: burn.slot,
        };
        let met = collector.receive_attestation(att1).unwrap();
        assert!(!met, "should need more attestations (2/3)");
        assert!(!collector.is_authorized(burn_id));

        // Relayer 2 attests — this should reach quorum
        let signer2 = make_test_signer(kps[2]);
        let sig2 = signer2(&digest);
        let att2 = BurnAttestation {
            burn_id: burn_id.to_string(),
            solana_tx_signature: tx_sig.to_string(),
            burn_amount_raw: burn.amount,
            wallet_address: burn.wallet.clone(),
            misaka_receive_address: recipient.to_string(),
            relayer_index: 2,
            signature: sig2,
            burn_slot: burn.slot,
        };
        let met = collector.receive_attestation(att2).unwrap();
        assert!(met, "quorum should be met at 3/3");
        assert!(collector.is_authorized(burn_id));

        let attestations = collector.get_attestations(burn_id).unwrap();
        assert_eq!(attestations.len(), 3);
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let keypairs: Vec<_> = (0..3).map(|_| make_test_keypair()).collect();
        let pubkeys: Vec<Vec<u8>> = keypairs.iter().map(|(pk, _)| pk.clone()).collect();
        let kps: Vec<&misaka_pqc::pq_sign::MlDsaKeypair> = keypairs.iter().map(|(_, kp)| kp).collect();

        let config = AttestationConfig {
            required_signatures: 2,
            total_relayers: 3,
            authorized_relayers: pubkeys.clone(),
            own_index: 0,
            app_id: test_app_id(),
        };

        let mut collector = AttestationCollector::new(config);
        let burn = make_verified_burn();
        let burn_id = "burn-003";
        let tx_sig = "txsig333333333333333333333333333333333333333333";
        let recipient = "msk1recipient3333333333333333333";

        // Relayer 0 attests
        let signer0 = make_test_signer(kps[0]);
        collector.attest(&burn, burn_id, tx_sig, recipient, &signer0);

        // Relayer 1 attests
        let digest = collector.attestation_digest(
            burn_id,
            tx_sig,
            burn.amount,
            &burn.wallet,
            recipient,
            burn.slot,
        );
        let signer1 = make_test_signer(kps[1]);
        let sig1 = signer1(&digest);
        let att1 = BurnAttestation {
            burn_id: burn_id.to_string(),
            solana_tx_signature: tx_sig.to_string(),
            burn_amount_raw: burn.amount,
            wallet_address: burn.wallet.clone(),
            misaka_receive_address: recipient.to_string(),
            relayer_index: 1,
            signature: sig1.clone(),
            burn_slot: burn.slot,
        };
        collector.receive_attestation(att1).unwrap();

        // Relayer 1 tries again — should be rejected
        let att1_dup = BurnAttestation {
            burn_id: burn_id.to_string(),
            solana_tx_signature: tx_sig.to_string(),
            burn_amount_raw: burn.amount,
            wallet_address: burn.wallet.clone(),
            misaka_receive_address: recipient.to_string(),
            relayer_index: 1,
            signature: sig1,
            burn_slot: burn.slot,
        };
        let result = collector.receive_attestation(att1_dup);
        assert!(result.is_err());
        match result.unwrap_err() {
            AttestationError::DuplicateAttestation => {} // expected
            other => panic!("expected DuplicateAttestation, got: {}", other),
        }
    }

    #[test]
    fn test_unauthorized_relayer_rejected() {
        let keypairs: Vec<_> = (0..2).map(|_| make_test_keypair()).collect();
        let pubkeys: Vec<Vec<u8>> = keypairs.iter().map(|(pk, _)| pk.clone()).collect();

        let config = AttestationConfig {
            required_signatures: 2,
            total_relayers: 2,
            authorized_relayers: pubkeys.clone(),
            own_index: 0,
            app_id: test_app_id(),
        };

        let mut collector = AttestationCollector::new(config);

        // Relayer index 5 is not authorized (only 0 and 1 are)
        let att = BurnAttestation {
            burn_id: "burn-004".to_string(),
            solana_tx_signature: "txsig444444444444444444444444444444444444444444".to_string(),
            burn_amount_raw: 1_000_000,
            wallet_address: "SoLwALLET1111111111111111111111111111111111".to_string(),
            misaka_receive_address: "msk1recipient4444444444444444444".to_string(),
            relayer_index: 5,
            signature: vec![0; 32],
            burn_slot: 12345,
        };

        let result = collector.receive_attestation(att);
        assert!(result.is_err());
        match result.unwrap_err() {
            AttestationError::UnauthorizedRelayer => {} // expected
            other => panic!("expected UnauthorizedRelayer, got: {}", other),
        }
    }

    #[test]
    fn test_attestation_digest_deterministic() {
        let (pk0, _kp0) = make_test_keypair();
        let config = AttestationConfig {
            required_signatures: 1,
            total_relayers: 1,
            authorized_relayers: vec![pk0],
            own_index: 0,
            app_id: test_app_id(),
        };
        let collector = AttestationCollector::new(config);

        let d1 = collector.attestation_digest("burn-x", "txsig-x", 1000, "wallet-x", "recipient-x", 100);
        let d2 = collector.attestation_digest("burn-x", "txsig-x", 1000, "wallet-x", "recipient-x", 100);
        assert_eq!(d1, d2, "same inputs must produce same digest");

        let d3 = collector.attestation_digest("burn-y", "txsig-x", 1000, "wallet-x", "recipient-x", 100);
        assert_ne!(d1, d3, "different burn_id must produce different digest");

        // Audit #12: different burn_slot must produce different digest (nonce monotonicity)
        let d4 = collector.attestation_digest("burn-x", "txsig-x", 1000, "wallet-x", "recipient-x", 200);
        assert_ne!(d1, d4, "different burn_slot must produce different digest");
    }
}
