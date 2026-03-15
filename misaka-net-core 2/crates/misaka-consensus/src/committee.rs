use std::collections::HashSet;
use misaka_types::validator::CommitteeVote;
use misaka_types::error::MisakaError;
use super::validator_set::ValidatorSet;

pub fn verify_vote(vs: &ValidatorSet, vote: &CommitteeVote) -> Result<u128, MisakaError> {
    let vi = vs.get(&vote.voter)
        .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown voter".into()))?;
    vs.verify_validator_sig(&vote.voter, &vote.signing_bytes(), &vote.signature)?;
    Ok(vi.stake_weight)
}

pub fn verify_committee_votes(
    vs: &ValidatorSet, votes: &[CommitteeVote], expected_slot: u64, expected_bh: &[u8; 32],
) -> Result<u128, MisakaError> {
    let mut seen = HashSet::new();
    let mut total: u128 = 0;
    for v in votes {
        if v.slot != expected_slot { return Err(MisakaError::SignatureVerificationFailed("slot mismatch".into())); }
        if v.block_hash != *expected_bh { return Err(MisakaError::SignatureVerificationFailed("hash mismatch".into())); }
        if !seen.insert(v.voter) { return Err(MisakaError::SignatureVerificationFailed("duplicate vote".into())); }
        total += verify_vote(vs, v)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::*;
    use misaka_crypto::hybrid::{generate_hybrid_keypair, hybrid_sign};

    fn make_vote(kp: &misaka_crypto::HybridKeypair, vid: [u8; 20], slot: u64, bh: [u8; 32]) -> CommitteeVote {
        let stub = CommitteeVote { slot, voter: vid, block_hash: bh,
            signature: ValidatorSignature { bytes: vec![] } };
        let sig = hybrid_sign(&stub.signing_bytes(), &kp.secret_key).unwrap();
        CommitteeVote { signature: ValidatorSignature { bytes: sig.to_bytes() }, ..stub }
    }

    fn setup() -> (ValidatorSet, Vec<misaka_crypto::HybridKeypair>, Vec<[u8; 20]>) {
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
    fn test_valid_vote() { let (vs, kps, ids) = setup(); verify_vote(&vs, &make_vote(&kps[0], ids[0], 1, [0xAA; 32])).unwrap(); }
    #[test]
    fn test_duplicate() {
        let (vs, kps, ids) = setup(); let bh = [0xAA; 32];
        assert!(verify_committee_votes(&vs, &[make_vote(&kps[0], ids[0], 1, bh), make_vote(&kps[0], ids[0], 1, bh)], 1, &bh).is_err());
    }
    #[test]
    fn test_accumulates() {
        let (vs, kps, ids) = setup(); let bh = [0xAA; 32];
        assert_eq!(verify_committee_votes(&vs, &[make_vote(&kps[0], ids[0], 1, bh), make_vote(&kps[1], ids[1], 1, bh), make_vote(&kps[2], ids[2], 1, bh)], 1, &bh).unwrap(), 300);
    }
}
