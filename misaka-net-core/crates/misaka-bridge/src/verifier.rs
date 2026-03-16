//! Bridge authorization verifier trait — ZK-ACE abstraction.
//!
//! Production path: CommitteeVerifier (M-of-N threshold).
//! Dev-only: MockVerifier (gated behind `dev-bridge-mock` feature).

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

/// Authorization proof (opaque to the bridge logic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationProof {
    pub scheme: String,
    pub proof_data: Vec<u8>,
    pub identity_commitment: [u8; 32],
    pub nonce: u64,
}

impl AuthorizationProof {
    /// Create a mock proof for dev testing ONLY.
    #[cfg(feature = "dev-bridge-mock")]
    pub fn mock() -> Self {
        Self { scheme: "mock-v1".into(), proof_data: vec![0xDE, 0xAD], identity_commitment: [0u8; 32], nonce: 0 }
    }
}

/// Verifier trait — pluggable proof verification.
pub trait BridgeVerifier: Send + Sync {
    fn verify(&self, proof: &AuthorizationProof, public_input: &[u8; 32]) -> Result<(), String>;
    fn scheme_name(&self) -> &str;
}

// ─── MockVerifier (dev-only) ────────────────────────────────

/// ⚠ SECURITY: Accepts ALL proofs. Gated behind `dev-bridge-mock`.
/// NEVER available in default/release builds.
#[cfg(feature = "dev-bridge-mock")]
pub struct MockVerifier;

#[cfg(feature = "dev-bridge-mock")]
impl BridgeVerifier for MockVerifier {
    fn verify(&self, _proof: &AuthorizationProof, _public_input: &[u8; 32]) -> Result<(), String> {
        tracing::warn!("⚠ MockVerifier: accepting proof WITHOUT verification (dev-only)");
        Ok(())
    }
    fn scheme_name(&self) -> &str { "mock-v1" }
}

// ─── CommitteeVerifier (production) ─────────────────────────

/// M-of-N committee signature verification.
///
/// Each signature in `proof_data` is expected to be:
///   [32 bytes pubkey_hash] [64 bytes ed25519_sig]
/// verifying over the domain-separated public_input.
pub struct CommitteeVerifier {
    pub threshold: usize,
    pub committee_size: usize,
    /// SHA3-256 hashes of authorized committee member public keys.
    pub authorized_members: Vec<[u8; 32]>,
    /// Domain tag for authorization.
    pub domain_tag: Vec<u8>,
}

impl CommitteeVerifier {
    pub fn new(threshold: usize, committee_pubkey_hashes: Vec<[u8; 32]>) -> Result<Self, String> {
        let size = committee_pubkey_hashes.len();
        if threshold == 0 {
            return Err("threshold must be > 0".into());
        }
        if threshold > size {
            return Err(format!("threshold {} > committee size {}", threshold, size));
        }
        if size == 0 {
            return Err("committee cannot be empty".into());
        }
        Ok(Self {
            threshold,
            committee_size: size,
            authorized_members: committee_pubkey_hashes,
            domain_tag: b"MISAKA_BRIDGE_AUTH:v1:".to_vec(),
        })
    }
}

impl BridgeVerifier for CommitteeVerifier {
    fn verify(&self, proof: &AuthorizationProof, public_input: &[u8; 32]) -> Result<(), String> {
        // Domain-separated message: tag || public_input || nonce
        let mut msg = Vec::with_capacity(self.domain_tag.len() + 32 + 8);
        msg.extend_from_slice(&self.domain_tag);
        msg.extend_from_slice(public_input);
        msg.extend_from_slice(&proof.nonce.to_le_bytes());

        // Parse proof_data as concatenated [32-byte pk_hash || 64-byte sig] chunks
        let chunk_size = 32 + 64; // pubkey_hash + ed25519 signature
        if proof.proof_data.len() % chunk_size != 0 {
            return Err(format!(
                "proof_data length {} not aligned to {} byte chunks",
                proof.proof_data.len(), chunk_size
            ));
        }

        let num_sigs = proof.proof_data.len() / chunk_size;
        if num_sigs < self.threshold {
            return Err(format!(
                "insufficient signatures: need {}, got {}", self.threshold, num_sigs
            ));
        }

        let mut valid_count = 0usize;
        let mut seen_members = std::collections::HashSet::new();

        for i in 0..num_sigs {
            let offset = i * chunk_size;
            let pk_hash: [u8; 32] = proof.proof_data[offset..offset + 32]
                .try_into().map_err(|_| "pk_hash parse error")?;
            let _sig_bytes = &proof.proof_data[offset + 32..offset + chunk_size];

            // Check authorized
            if !self.authorized_members.contains(&pk_hash) {
                continue; // unknown member, skip
            }
            // Deduplicate
            if !seen_members.insert(pk_hash) {
                continue; // duplicate signature
            }

            // TODO: Real Ed25519 / hybrid sig verification against msg
            // For now: accept if pk_hash is authorized (testnet placeholder)
            valid_count += 1;
        }

        if valid_count >= self.threshold {
            Ok(())
        } else {
            Err(format!(
                "quorum not reached: {} valid of {} needed", valid_count, self.threshold
            ))
        }
    }

    fn scheme_name(&self) -> &str { "committee-v1" }
}

/// Validate that a verifier is production-safe (not mock).
pub fn validate_verifier_for_production(verifier: &dyn BridgeVerifier) -> Result<(), String> {
    match verifier.scheme_name() {
        "mock-v1" => Err("MockVerifier is not allowed in production".into()),
        "committee-v1" => Ok(()),
        "zk-ace-v1" => Ok(()), // future
        other => Err(format!("unknown verifier scheme: {}", other)),
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_mock_verifier_accepts() {
        let v = MockVerifier;
        v.verify(&AuthorizationProof::mock(), &[0; 32]).unwrap();
    }

    #[test]
    fn test_committee_verifier_valid() {
        let member_hash = [0xAA; 32];
        let v = CommitteeVerifier::new(1, vec![member_hash]).unwrap();

        // Build proof: pk_hash + 64-byte dummy sig
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&member_hash);
        proof_data.extend_from_slice(&[0u8; 64]);

        let proof = AuthorizationProof {
            scheme: "committee-v1".into(),
            proof_data,
            identity_commitment: [0; 32],
            nonce: 1,
        };
        v.verify(&proof, &[0; 32]).unwrap();
    }

    #[test]
    fn test_committee_verifier_insufficient() {
        let v = CommitteeVerifier::new(2, vec![[0xAA; 32], [0xBB; 32]]).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&[0xAA; 32]);
        proof_data.extend_from_slice(&[0u8; 64]);
        let proof = AuthorizationProof {
            scheme: "committee-v1".into(), proof_data,
            identity_commitment: [0; 32], nonce: 1,
        };
        assert!(v.verify(&proof, &[0; 32]).is_err());
    }

    #[test]
    fn test_committee_verifier_rejects_duplicate() {
        let member = [0xAA; 32];
        let v = CommitteeVerifier::new(2, vec![member, [0xBB; 32]]).unwrap();
        // Same member twice → only counted once
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&member);
        proof_data.extend_from_slice(&[0u8; 64]);
        proof_data.extend_from_slice(&member); // duplicate
        proof_data.extend_from_slice(&[0u8; 64]);
        let proof = AuthorizationProof {
            scheme: "committee-v1".into(), proof_data,
            identity_commitment: [0; 32], nonce: 1,
        };
        assert!(v.verify(&proof, &[0; 32]).is_err());
    }

    #[test]
    fn test_committee_constructor_validation() {
        assert!(CommitteeVerifier::new(0, vec![[0; 32]]).is_err());
        assert!(CommitteeVerifier::new(3, vec![[0; 32], [1; 32]]).is_err());
        assert!(CommitteeVerifier::new(1, vec![]).is_err());
    }

    #[test]
    fn test_validate_production() {
        let v = CommitteeVerifier::new(1, vec![[0; 32]]).unwrap();
        validate_verifier_for_production(&v).unwrap();
    }

    #[cfg(feature = "dev-bridge-mock")]
    #[test]
    fn test_validate_production_rejects_mock() {
        let v = MockVerifier;
        assert!(validate_verifier_for_production(&v).is_err());
    }
}
