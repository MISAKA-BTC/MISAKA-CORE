use misaka_types::validator::FinalityProof;
use misaka_types::error::MisakaError;
use super::validator_set::ValidatorSet;
use super::committee::verify_committee_votes;

pub fn verify_finality(vs: &ValidatorSet, proof: &FinalityProof) -> Result<(), MisakaError> {
    let quorum = vs.quorum_threshold();
    let weight = verify_committee_votes(vs, &proof.commits, proof.slot, &proof.block_hash)?;
    if weight < quorum { return Err(MisakaError::QuorumNotReached { got: weight as u64, need: quorum as u64 }); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::*;
    use misaka_crypto::validator_sig::{generate_validator_keypair, validator_sign, ValidatorKeypair};

    fn setup() -> (ValidatorSet, Vec<ValidatorKeypair>, Vec<[u8; 20]>) {
        let mut vs = Vec::new(); let mut kps = Vec::new(); let mut ids = Vec::new();
        for i in 0..4u8 {
            let kp = generate_validator_keypair();
            let mut vid = [0u8; 20]; vid[0] = i;
            vs.push(ValidatorIdentity { validator_id: vid, stake_weight: 100,
                public_key: ValidatorPublicKey { bytes: kp.public_key.to_bytes() }, is_active: true });
            ids.push(vid); kps.push(kp);
        }
        (ValidatorSet::new(vs), kps, ids)
    }

    fn mk(kp: &ValidatorKeypair, vid: [u8; 20], s: u64, bh: [u8; 32]) -> CommitteeVote {
        let stub = CommitteeVote { slot: s, voter: vid, block_hash: bh, signature: ValidatorSignature { bytes: vec![] } };
        let sig = validator_sign(&stub.signing_bytes(), &kp.secret_key).unwrap();
        CommitteeVote { signature: ValidatorSignature { bytes: sig.to_bytes() }, ..stub }
    }

    #[test]
    fn test_ok() { let (vs, kps, ids) = setup(); let bh = [0xBB; 32];
        verify_finality(&vs, &FinalityProof { slot: 1, block_hash: bh, commits: vec![mk(&kps[0], ids[0], 1, bh), mk(&kps[1], ids[1], 1, bh), mk(&kps[2], ids[2], 1, bh)] }).unwrap(); }
    #[test]
    fn test_insufficient() { let (vs, kps, ids) = setup(); let bh = [0xBB; 32];
        assert!(verify_finality(&vs, &FinalityProof { slot: 1, block_hash: bh, commits: vec![mk(&kps[0], ids[0], 1, bh)] }).is_err()); }
}
