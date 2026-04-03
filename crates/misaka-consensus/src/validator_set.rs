//! Validator set — PQ-only ML-DSA-65 signature verification.
//!
//! ECC (Ed25519) is COMPLETELY EXCLUDED.
//! All validator signatures verified via ML-DSA-65 only.

use misaka_crypto::sha3_256;
use misaka_crypto::validator_sig::{validator_verify, ValidatorPqPublicKey, ValidatorPqSignature};
use misaka_types::error::MisakaError;
use misaka_types::validator::{ValidatorId, ValidatorIdentity, ValidatorSignature};

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorIdentity>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<ValidatorIdentity>) -> Self {
        Self { validators }
    }

    pub fn total_stake(&self) -> u128 {
        self.validators
            .iter()
            .filter(|v| v.is_active)
            .map(|v| v.stake_weight)
            .sum()
    }

    /// BFT quorum threshold: `⌈total_stake × 2/3⌉ + 1`.
    ///
    /// Uses `QUORUM_THRESHOLD_BPS` (6667 = 66.67%) from `misaka_types::constants`
    /// as the single source of truth.
    ///
    /// # Safety
    ///
    /// With `n` equal-weight validators:
    /// - n=4: quorum=3, tolerates 1 Byzantine
    /// - n=100: quorum=67, tolerates 33 Byzantine
    pub fn quorum_threshold(&self) -> u128 {
        let bps = misaka_types::constants::QUORUM_THRESHOLD_BPS as u128;
        // BPS = basis points (10000 = 100%). 6667 = 66.67%.
        // quorum = ceil(total_stake * bps / 10000) + 1
        //        = (total_stake * bps + 9999) / 10000
        let total = self.total_stake();
        (total * bps + 9999) / 10000
    }

    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorIdentity> {
        self.validators
            .iter()
            .find(|v| v.validator_id == *id && v.is_active)
    }

    /// Verify a validator's PQ-only ML-DSA-65 signature.
    pub fn verify_validator_sig(
        &self,
        validator_id: &ValidatorId,
        message: &[u8],
        sig: &ValidatorSignature,
    ) -> Result<(), MisakaError> {
        let vi = self.get(validator_id).ok_or_else(|| {
            MisakaError::SignatureVerificationFailed(format!(
                "unknown validator: {}",
                hex::encode(validator_id)
            ))
        })?;

        let pk = ValidatorPqPublicKey::from_bytes(&vi.public_key.bytes)
            .map_err(|e| MisakaError::SignatureVerificationFailed(e.to_string()))?;
        let pq_sig = ValidatorPqSignature::from_bytes(&sig.bytes)
            .map_err(|e| MisakaError::SignatureVerificationFailed(e.to_string()))?;

        validator_verify(message, &pq_sig, &pk)
            .map_err(|e| MisakaError::SignatureVerificationFailed(e.to_string()))
    }

    pub fn set_hash(&self) -> [u8; 32] {
        let mut sorted = self.validators.clone();
        sorted.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        let mut buf = Vec::new();
        for v in &sorted {
            buf.extend_from_slice(&v.validator_id);
            buf.extend_from_slice(&v.stake_weight.to_le_bytes());
            buf.extend_from_slice(&v.public_key.bytes);
            buf.push(v.is_active as u8);
        }
        sha3_256(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::{
        generate_validator_keypair, validator_sign, ValidatorKeypair,
    };
    use misaka_types::validator::*;

    fn make_validator(id_byte: u8, stake: u128) -> (ValidatorIdentity, ValidatorKeypair) {
        let kp = generate_validator_keypair();
        let mut vid = [0u8; 32];
        vid[0] = id_byte;
        (
            ValidatorIdentity {
                validator_id: vid,
                stake_weight: stake,
                public_key: ValidatorPublicKey {
                    bytes: kp.public_key.to_bytes(),
                },
                is_active: true,
            },
            kp,
        )
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
    fn test_verify_pq_sig() {
        let (vi, kp) = make_validator(1, 100);
        let vs = ValidatorSet::new(vec![vi.clone()]);
        let msg = b"test";
        let sig = validator_sign(msg, &kp.secret_key).unwrap();
        vs.verify_validator_sig(
            &vi.validator_id,
            msg,
            &ValidatorSignature {
                bytes: sig.to_bytes(),
            },
        )
        .unwrap();
    }

    #[test]
    fn test_set_hash_includes_pk_and_active() {
        let (v1, _) = make_validator(1, 100);
        let vs = ValidatorSet::new(vec![v1.clone()]);
        let h1 = vs.set_hash();
        let mut v2 = v1.clone();
        v2.is_active = false;
        let vs2 = ValidatorSet::new(vec![v2]);
        assert_ne!(h1, vs2.set_hash());
    }
}
