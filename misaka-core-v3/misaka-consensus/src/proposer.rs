//! Proposer selection — Active validators only.
//!
//! Block proposal rights are determined by the staking registry.
//! Only Active validators (registered via misakastake.com, minimum stake met)
//! can propose blocks. Round-robin weighted by stake.

use misaka_types::validator::{ValidatorId, Proposal};
use misaka_types::error::MisakaError;
use super::validator_set::ValidatorSet;

/// Select the proposer for a given slot.
/// Only Active validators are eligible.
pub fn proposer_for_slot(vs: &ValidatorSet, slot: u64) -> Option<ValidatorId> {
    let active: Vec<&ValidatorId> = vs.validators.iter()
        .filter(|v| v.is_active()).map(|v| &v.validator_id).collect();
    if active.is_empty() { return None; }
    Some(*active[(slot as usize) % active.len()])
}

/// Verify a block proposal: correct proposer + valid signature.
pub fn verify_proposal(vs: &ValidatorSet, proposal: &Proposal) -> Result<(), MisakaError> {
    let expected = proposer_for_slot(vs, proposal.slot)
        .ok_or_else(|| MisakaError::SignatureVerificationFailed("no active validators".into()))?;
    if proposal.proposer != expected {
        return Err(MisakaError::SignatureVerificationFailed(
            format!("wrong proposer for slot {}: expected {}, got {}",
                proposal.slot, hex::encode(expected), hex::encode(proposal.proposer))));
    }
    vs.verify_validator_sig(&proposal.proposer, &proposal.signing_bytes(), &proposal.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::*;
    use misaka_crypto::validator_sig::{generate_validator_keypair, validator_sign, ValidatorKeypair};

    fn setup() -> (ValidatorSet, Vec<ValidatorKeypair>, Vec<ValidatorId>) {
        let mut vs = Vec::new(); let mut kps = Vec::new(); let mut ids = Vec::new();
        for i in 0..4u8 {
            let kp = generate_validator_keypair();
            let mut vid = [0u8; 20]; vid[0] = i;
            vs.push(ValidatorIdentity::new_active(
                vid, 100, ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
            ));
            ids.push(vid); kps.push(kp);
        }
        (ValidatorSet::new(vs), kps, ids)
    }

    #[test]
    fn test_valid_proposal() {
        let (vs, kps, ids) = setup();
        let p = Proposal { slot: 0, proposer: ids[0], block_hash: [0xAA; 32],
            signature: ValidatorSignature { bytes: vec![] } };
        let sig = validator_sign(&p.signing_bytes(), &kps[0].secret_key).unwrap();
        let p = Proposal { signature: ValidatorSignature { bytes: sig.to_bytes() }, ..p };
        verify_proposal(&vs, &p).unwrap();
    }

    #[test]
    fn test_wrong_proposer() {
        let (vs, _, ids) = setup();
        let p = Proposal { slot: 0, proposer: ids[1], block_hash: [0xAA; 32],
            signature: ValidatorSignature { bytes: vec![0; 3309] } };
        assert!(verify_proposal(&vs, &p).is_err());
    }

    #[test]
    fn test_jailed_validator_cannot_propose() {
        let kp = generate_validator_keypair();
        let mut vid = [0u8; 20]; vid[0] = 1;
        let mut vi = ValidatorIdentity::new_active(
            vid, 100, ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
        );
        vi.status = ValidatorStatus::Jailed;
        let vs = ValidatorSet::new(vec![vi]);
        assert!(proposer_for_slot(&vs, 0).is_none(),
            "jailed validator must not be eligible as proposer");
    }
}
