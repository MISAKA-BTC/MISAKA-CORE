use misaka_types::validator::{ValidatorId, Proposal};
use misaka_types::error::MisakaError;
use super::validator_set::ValidatorSet;

pub fn proposer_for_slot(vs: &ValidatorSet, slot: u64) -> Option<ValidatorId> {
    let active: Vec<&ValidatorId> = vs.validators.iter()
        .filter(|v| v.is_active).map(|v| &v.validator_id).collect();
    if active.is_empty() { return None; }
    Some(*active[(slot as usize) % active.len()])
}

pub fn verify_proposal(vs: &ValidatorSet, proposal: &Proposal) -> Result<(), MisakaError> {
    let expected = proposer_for_slot(vs, proposal.slot)
        .ok_or_else(|| MisakaError::SignatureVerificationFailed("no active validators".into()))?;
    if proposal.proposer != expected {
        return Err(MisakaError::SignatureVerificationFailed(
            format!("wrong proposer for slot {}", proposal.slot)));
    }
    vs.verify_validator_sig(&proposal.proposer, &proposal.signing_bytes(), &proposal.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::*;
    use misaka_crypto::hybrid::{generate_hybrid_keypair, hybrid_sign};

    fn setup() -> (ValidatorSet, Vec<misaka_crypto::HybridKeypair>, Vec<ValidatorId>) {
        let mut vs = Vec::new(); let mut kps = Vec::new(); let mut ids = Vec::new();
        for i in 0..4u8 {
            let kp = generate_hybrid_keypair();
            let mut vid = [0u8; 20]; vid[0] = i;
            vs.push(ValidatorIdentity {
                validator_id: vid, stake_weight: 100,
                public_key: ValidatorPublicKey { bytes: kp.public_key.to_bytes() },
                is_active: true,
            });
            ids.push(vid); kps.push(kp);
        }
        (ValidatorSet::new(vs), kps, ids)
    }

    #[test]
    fn test_valid_proposal() {
        let (vs, kps, ids) = setup();
        let p = Proposal { slot: 0, proposer: ids[0], block_hash: [0xAA; 32],
            signature: ValidatorSignature { bytes: vec![] } };
        let sig = hybrid_sign(&p.signing_bytes(), &kps[0].secret_key).unwrap();
        let p = Proposal { signature: ValidatorSignature { bytes: sig.to_bytes() }, ..p };
        verify_proposal(&vs, &p).unwrap();
    }

    #[test]
    fn test_wrong_proposer() {
        let (vs, _, ids) = setup();
        let p = Proposal { slot: 0, proposer: ids[1], block_hash: [0xAA; 32],
            signature: ValidatorSignature { bytes: vec![0; 3373] } };
        assert!(verify_proposal(&vs, &p).is_err());
    }
}
