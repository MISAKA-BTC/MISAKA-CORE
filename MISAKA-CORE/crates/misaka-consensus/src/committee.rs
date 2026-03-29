use super::validator_set::ValidatorSet;
use misaka_types::error::MisakaError;
use misaka_types::validator::{CommitteeVote, DagCheckpointTarget, DagCheckpointVote};
use std::collections::HashSet;

pub fn verify_vote(vs: &ValidatorSet, vote: &CommitteeVote) -> Result<u128, MisakaError> {
    let vi = vs
        .get(&vote.voter)
        .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown voter".into()))?;
    vs.verify_validator_sig(&vote.voter, &vote.signing_bytes(), &vote.signature)?;
    Ok(vi.stake_weight)
}

pub fn verify_committee_votes(
    vs: &ValidatorSet,
    votes: &[CommitteeVote],
    expected_slot: u64,
    expected_bh: &[u8; 32],
) -> Result<u128, MisakaError> {
    let mut seen = HashSet::new();
    let mut total: u128 = 0;
    for v in votes {
        if v.slot != expected_slot {
            return Err(MisakaError::SignatureVerificationFailed(
                "slot mismatch".into(),
            ));
        }
        if v.block_hash != *expected_bh {
            return Err(MisakaError::SignatureVerificationFailed(
                "hash mismatch".into(),
            ));
        }
        if !seen.insert(v.voter) {
            return Err(MisakaError::SignatureVerificationFailed(
                "duplicate vote".into(),
            ));
        }
        total += verify_vote(vs, v)?;
    }
    Ok(total)
}

pub fn verify_dag_checkpoint_vote(
    vs: &ValidatorSet,
    vote: &DagCheckpointVote,
) -> Result<u128, MisakaError> {
    let vi = vs
        .get(&vote.voter)
        .ok_or_else(|| MisakaError::SignatureVerificationFailed("unknown voter".into()))?;
    vs.verify_validator_sig(&vote.voter, &vote.signing_bytes(), &vote.signature)?;
    Ok(vi.stake_weight)
}

pub fn verify_dag_checkpoint_votes(
    vs: &ValidatorSet,
    votes: &[DagCheckpointVote],
    expected_target: &DagCheckpointTarget,
) -> Result<u128, MisakaError> {
    let mut seen = HashSet::new();
    let mut total: u128 = 0;
    for v in votes {
        if v.target != *expected_target {
            return Err(MisakaError::SignatureVerificationFailed(
                "dag checkpoint target mismatch".into(),
            ));
        }
        if !seen.insert(v.voter) {
            return Err(MisakaError::SignatureVerificationFailed(
                "duplicate dag checkpoint vote".into(),
            ));
        }
        total += verify_dag_checkpoint_vote(vs, v)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::{
        generate_validator_keypair, validator_sign, ValidatorKeypair,
    };
    use misaka_types::validator::*;

    fn make_vote(kp: &ValidatorKeypair, vid: [u8; 32], slot: u64, bh: [u8; 32]) -> CommitteeVote {
        let stub = CommitteeVote {
            slot,
            voter: vid,
            block_hash: bh,
            signature: ValidatorSignature { bytes: vec![] },
        };
        let sig = validator_sign(&stub.signing_bytes(), &kp.secret_key).unwrap();
        CommitteeVote {
            signature: ValidatorSignature {
                bytes: sig.to_bytes(),
            },
            ..stub
        }
    }

    fn setup() -> (ValidatorSet, Vec<ValidatorKeypair>, Vec<[u8; 32]>) {
        let mut vs = Vec::new();
        let mut kps = Vec::new();
        let mut ids = Vec::new();
        for i in 0..4u8 {
            let kp = generate_validator_keypair();
            let mut vid = [0u8; 32];
            vid[0] = i;
            vs.push(ValidatorIdentity {
                validator_id: vid,
                stake_weight: 100,
                public_key: ValidatorPublicKey {
                    bytes: kp.public_key.to_bytes(),
                },
                is_active: true,
            });
            ids.push(vid);
            kps.push(kp);
        }
        (ValidatorSet::new(vs), kps, ids)
    }

    #[test]
    fn test_valid_vote() {
        let (vs, kps, ids) = setup();
        verify_vote(&vs, &make_vote(&kps[0], ids[0], 1, [0xAA; 32])).unwrap();
    }
    #[test]
    fn test_duplicate() {
        let (vs, kps, ids) = setup();
        let bh = [0xAA; 32];
        assert!(verify_committee_votes(
            &vs,
            &[
                make_vote(&kps[0], ids[0], 1, bh),
                make_vote(&kps[0], ids[0], 1, bh)
            ],
            1,
            &bh
        )
        .is_err());
    }
    #[test]
    fn test_accumulates() {
        let (vs, kps, ids) = setup();
        let bh = [0xAA; 32];
        assert_eq!(
            verify_committee_votes(
                &vs,
                &[
                    make_vote(&kps[0], ids[0], 1, bh),
                    make_vote(&kps[1], ids[1], 1, bh),
                    make_vote(&kps[2], ids[2], 1, bh)
                ],
                1,
                &bh
            )
            .unwrap(),
            300
        );
    }

    fn make_dag_vote(
        kp: &ValidatorKeypair,
        vid: [u8; 32],
        target: DagCheckpointTarget,
    ) -> DagCheckpointVote {
        let stub = DagCheckpointVote {
            voter: vid,
            target,
            signature: ValidatorSignature { bytes: vec![] },
        };
        let sig = validator_sign(&stub.signing_bytes(), &kp.secret_key).unwrap();
        DagCheckpointVote {
            signature: ValidatorSignature {
                bytes: sig.to_bytes(),
            },
            ..stub
        }
    }

    fn sample_target() -> DagCheckpointTarget {
        DagCheckpointTarget {
            block_hash: [0xDD; 32],
            blue_score: 42,
            utxo_root: [0xEE; 32],
            total_key_images: 7,
            total_applied_txs: 12,
        }
    }

    #[test]
    fn test_verify_dag_checkpoint_votes_ok() {
        let (vs, kps, ids) = setup();
        let target = sample_target();
        let votes = vec![
            make_dag_vote(&kps[0], ids[0], target.clone()),
            make_dag_vote(&kps[1], ids[1], target.clone()),
            make_dag_vote(&kps[2], ids[2], target.clone()),
        ];
        assert_eq!(
            verify_dag_checkpoint_votes(&vs, &votes, &target).unwrap(),
            300
        );
    }

    #[test]
    fn test_verify_dag_checkpoint_votes_target_mismatch() {
        let (vs, kps, ids) = setup();
        let target = sample_target();
        let mut wrong_target = sample_target();
        wrong_target.utxo_root[0] ^= 0x01;
        let votes = vec![
            make_dag_vote(&kps[0], ids[0], target.clone()),
            make_dag_vote(&kps[1], ids[1], wrong_target),
        ];
        assert!(verify_dag_checkpoint_votes(&vs, &votes, &target).is_err());
    }
}
