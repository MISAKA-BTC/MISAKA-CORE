//! Validator set — PQ-only ML-DSA-65 signature verification.
//!
//! ECC (Ed25519) is COMPLETELY EXCLUDED.
//! All validator signatures verified via ML-DSA-65 only.
//!
//! Consensus participation is restricted to validators with
//! status == Active (registered via misakastake.com, meets minimum stake).

use misaka_types::validator::{ValidatorId, ValidatorIdentity, ValidatorSignature, ValidatorStatus};
use misaka_types::error::MisakaError;
use misaka_crypto::validator_sig::{ValidatorPqPublicKey, ValidatorPqSignature, validator_verify};
use misaka_crypto::sha3_256;

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorIdentity>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<ValidatorIdentity>) -> Self { Self { validators } }

    /// Total stake of Active validators only.
    pub fn total_stake(&self) -> u128 {
        self.validators.iter()
            .filter(|v| v.is_active())
            .map(|v| v.stake_weight)
            .sum()
    }

    /// BFT quorum threshold: >2/3 of total Active stake.
    pub fn quorum_threshold(&self) -> u128 {
        self.total_stake() * 2 / 3 + 1
    }

    /// Get an Active validator by ID.
    /// Returns None if the validator is not Active (jailed, unbonding, etc).
    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorIdentity> {
        self.validators.iter().find(|v| v.validator_id == *id && v.is_active())
    }

    /// Get any validator by ID regardless of status (for diagnostics).
    pub fn get_any(&self, id: &ValidatorId) -> Option<&ValidatorIdentity> {
        self.validators.iter().find(|v| v.validator_id == *id)
    }

    /// Number of Active validators.
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.is_active()).count()
    }

    /// Verify a validator's PQ-only ML-DSA-65 signature.
    /// Only Active validators can have their signatures verified for consensus.
    pub fn verify_validator_sig(
        &self, validator_id: &ValidatorId, message: &[u8], sig: &ValidatorSignature,
    ) -> Result<(), MisakaError> {
        let vi = self.get(validator_id)
            .ok_or_else(|| {
                // Provide detailed rejection reason
                match self.get_any(validator_id) {
                    Some(v) => MisakaError::SignatureVerificationFailed(
                        format!("validator {} has status {:?}, not Active",
                            hex::encode(validator_id), v.status)),
                    None => MisakaError::SignatureVerificationFailed(
                        format!("unknown validator: {}", hex::encode(validator_id))),
                }
            })?;

        let pk = ValidatorPqPublicKey::from_bytes(&vi.public_key.bytes)
            .map_err(|e| MisakaError::SignatureVerificationFailed(e.to_string()))?;
        let pq_sig = ValidatorPqSignature::from_bytes(&sig.bytes)
            .map_err(|e| MisakaError::SignatureVerificationFailed(e.to_string()))?;

        validator_verify(message, &pq_sig, &pk)
            .map_err(|e| MisakaError::SignatureVerificationFailed(e.to_string()))
    }

    /// Deterministic hash of the validator set (for epoch snapshots).
    pub fn set_hash(&self) -> [u8; 32] {
        let mut sorted = self.validators.clone();
        sorted.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        let mut buf = Vec::new();
        for v in &sorted {
            buf.extend_from_slice(&v.validator_id);
            buf.extend_from_slice(&v.stake_weight.to_le_bytes());
            buf.extend_from_slice(&v.public_key.bytes);
            buf.push(v.is_active() as u8);
        }
        sha3_256(&buf)
    }

    /// Check if a validator is eligible for consensus participation.
    /// This is the SINGLE authority for eligibility — used at startup,
    /// connection, proposal, vote, and sync time.
    pub fn is_eligible(&self, id: &ValidatorId) -> bool {
        self.get(id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::*;
    use misaka_crypto::validator_sig::{generate_validator_keypair, validator_sign, ValidatorKeypair};

    fn make_validator(id_byte: u8, stake: u128) -> (ValidatorIdentity, ValidatorKeypair) {
        let kp = generate_validator_keypair();
        let mut vid = [0u8; 20]; vid[0] = id_byte;
        (ValidatorIdentity::new_active(
            vid, stake, ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
        ), kp)
    }

    fn make_jailed_validator(id_byte: u8, stake: u128) -> (ValidatorIdentity, ValidatorKeypair) {
        let kp = generate_validator_keypair();
        let mut vid = [0u8; 20]; vid[0] = id_byte;
        let mut vi = ValidatorIdentity::new_active(
            vid, stake, ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
        );
        vi.status = ValidatorStatus::Jailed;
        vi.jailed_at_epoch = 1;
        (vi, kp)
    }

    #[test]
    fn test_quorum() {
        let (v1, _) = make_validator(1, 100);
        let (v2, _) = make_validator(2, 100);
        let (v3, _) = make_validator(3, 100);
        let vs = ValidatorSet::new(vec![v1, v2, v3]);
        assert_eq!(vs.total_stake(), 300);
        assert_eq!(vs.quorum_threshold(), 201);
    }

    #[test]
    fn test_jailed_excluded_from_stake() {
        let (v1, _) = make_validator(1, 100);
        let (v2, _) = make_jailed_validator(2, 100);
        let vs = ValidatorSet::new(vec![v1, v2]);
        assert_eq!(vs.total_stake(), 100);
        assert_eq!(vs.active_count(), 1);
    }

    #[test]
    fn test_verify_pq_sig() {
        let (vi, kp) = make_validator(1, 100);
        let vs = ValidatorSet::new(vec![vi.clone()]);
        let msg = b"test";
        let sig = validator_sign(msg, &kp.secret_key).unwrap();
        vs.verify_validator_sig(&vi.validator_id, msg,
            &ValidatorSignature { bytes: sig.to_bytes() }).unwrap();
    }

    #[test]
    fn test_jailed_validator_sig_rejected() {
        let (vi, kp) = make_jailed_validator(1, 100);
        let vs = ValidatorSet::new(vec![vi.clone()]);
        let msg = b"test";
        let sig = validator_sign(msg, &kp.secret_key).unwrap();
        let result = vs.verify_validator_sig(&vi.validator_id, msg,
            &ValidatorSignature { bytes: sig.to_bytes() });
        assert!(result.is_err(), "jailed validator signatures must be rejected");
    }

    #[test]
    fn test_set_hash_changes_with_status() {
        let (v1, _) = make_validator(1, 100);
        let vs1 = ValidatorSet::new(vec![v1.clone()]);
        let h1 = vs1.set_hash();

        let mut v2 = v1.clone();
        v2.status = ValidatorStatus::Jailed;
        let vs2 = ValidatorSet::new(vec![v2]);
        assert_ne!(h1, vs2.set_hash());
    }

    #[test]
    fn test_unknown_validator_not_eligible() {
        let (v1, _) = make_validator(1, 100);
        let vs = ValidatorSet::new(vec![v1]);
        let unknown_id = [0xFFu8; 20];
        assert!(!vs.is_eligible(&unknown_id));
    }

    #[test]
    fn test_pending_validator_not_eligible() {
        let kp = generate_validator_keypair();
        let mut vid = [0u8; 20]; vid[0] = 1;
        let vi = ValidatorIdentity::new_pending(
            vid, 100, ValidatorPublicKey { bytes: kp.public_key.to_bytes() }, 0,
        );
        let vs = ValidatorSet::new(vec![vi]);
        assert!(!vs.is_eligible(&vid), "pending validators must not be consensus eligible");
    }

    #[test]
    fn test_stake_below_minimum() {
        let kp = generate_validator_keypair();
        let mut vid = [0u8; 20]; vid[0] = 1;
        let vi = ValidatorIdentity::new_active(
            vid, 50, // below MINIMUM_SELF_STAKE
            ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
        );
        assert!(!vi.meets_minimum_stake());
    }
}
