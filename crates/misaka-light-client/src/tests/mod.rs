// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Light client tests — fixture-based with real ML-DSA-65 keypairs.
//!
//! NO stub verifiers. Every signature is real ML-DSA-65.

mod byzantine;
mod determinism;
mod epoch_transition;
mod happy_path;
mod security;

use misaka_crypto::validator_sig::{validator_sign, ValidatorPqPublicKey, ValidatorPqSecretKey};
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_protocol_config::ProtocolVersion;
use misaka_types::dag_types::{BlockDigest, BlockRef, CommitDigest};
use misaka_types::validator::{
    CommitteeVote, EpochTransitionProof, EpochTransitionVote, ValidatorIdentity,
    ValidatorPublicKey, ValidatorSignature,
};

use crate::client::LightClient;
use crate::storage::MemoryStorage;
use crate::stream::UnverifiedCommit;
use crate::trust_root::TrustRoot;
use crate::verification;

/// Test fixture with real ML-DSA-65 keypairs.
pub struct TestFixture {
    pub keypairs: Vec<MlDsaKeypair>,
    pub committee: Vec<ValidatorIdentity>,
    pub chain_id: u32,
    pub stake_per: u128,
}

impl TestFixture {
    /// Create N validators with real ML-DSA-65 keys.
    pub fn new(n: usize, stake_per: u128) -> Self {
        let mut keypairs = Vec::with_capacity(n);
        let mut committee = Vec::with_capacity(n);

        for _i in 0..n {
            let kp = MlDsaKeypair::generate();
            let pk_bytes = kp.public_key.to_bytes();
            let pq_pk =
                ValidatorPqPublicKey::from_bytes(&pk_bytes).expect("generated key should be valid");
            let validator_id = pq_pk.to_canonical_id();

            committee.push(ValidatorIdentity {
                validator_id,
                stake_weight: stake_per,
                public_key: ValidatorPublicKey { bytes: pk_bytes },
                is_active: true,
            });
            keypairs.push(kp);
        }

        Self {
            keypairs,
            committee,
            chain_id: 2, // testnet
            stake_per,
        }
    }

    /// Create a LightClient initialized from this fixture's genesis.
    pub fn make_client(&self) -> LightClient<MemoryStorage> {
        let trust_root = TrustRoot {
            chain_id: self.chain_id,
            genesis_hash: [0x42; 32],
            protocol_version: ProtocolVersion::V1,
            initial_epoch: 0,
            initial_committee: self.committee.clone(),
        };
        LightClient::new(trust_root, MemoryStorage::new()).expect("client init should succeed")
    }

    /// Sign a message with validator at index, returning raw signature bytes.
    ///
    /// Uses `validator_sign()` which applies domain separation
    /// (SHA3-256("MISAKA-PQ-SIG:v2:" || message)).
    fn sign_with_validator(&self, idx: usize, message: &[u8]) -> Vec<u8> {
        let sk_bytes = self.keypairs[idx].secret_key.with_bytes(|b| b.to_vec());
        let sk = ValidatorPqSecretKey::from_bytes(&sk_bytes).expect("sk valid");
        let sig = validator_sign(message, &sk).expect("signing should succeed");
        sig.to_bytes()
    }

    /// Create an UnverifiedCommit signed by the specified validators.
    pub fn make_commit(&self, commit_index: u64, slot: u64, signers: &[usize]) -> UnverifiedCommit {
        self.make_commit_with_hash(commit_index, slot, signers, [0xAA; 32])
    }

    /// Create an UnverifiedCommit with a specific block hash.
    pub fn make_commit_with_hash(
        &self,
        commit_index: u64,
        slot: u64,
        signers: &[usize],
        block_hash: [u8; 32],
    ) -> UnverifiedCommit {
        let epoch = 0u64;
        let votes: Vec<CommitteeVote> = signers
            .iter()
            .map(|&idx| {
                let vote = CommitteeVote {
                    slot,
                    voter: self.committee[idx].validator_id,
                    block_hash,
                    signature: ValidatorSignature {
                        bytes: vec![0; 3309], // placeholder, will be replaced
                    },
                    epoch,
                    chain_id: self.chain_id,
                };
                // Sign with the real ML-DSA-65 key
                let signing_bytes = vote.signing_bytes();
                let sig_bytes = self.sign_with_validator(idx, &signing_bytes);
                CommitteeVote {
                    signature: ValidatorSignature { bytes: sig_bytes },
                    ..vote
                }
            })
            .collect();

        UnverifiedCommit {
            epoch,
            commit_index,
            commit_digest: CommitDigest([commit_index as u8; 32]),
            leader: BlockRef {
                round: slot as u32,
                author: 0,
                digest: BlockDigest(block_hash),
            },
            block_refs: vec![],
            timestamp_ms: 1_700_000_000_000 + commit_index * 1000,
            chain_id: self.chain_id,
            slot,
            block_hash,
            votes,
        }
    }

    /// Create an epoch transition proof signed by specified validators.
    pub fn make_epoch_transition(
        &self,
        old_epoch: u64,
        new_epoch: u64,
        new_committee: &[ValidatorIdentity],
        signers: &[usize],
    ) -> EpochTransitionProof {
        let new_committee_hash = verification::committee_hash(new_committee);
        let signing_bytes =
            EpochTransitionProof::signing_bytes(old_epoch, new_epoch, &new_committee_hash);

        let transition_votes: Vec<EpochTransitionVote> = signers
            .iter()
            .map(|&idx| {
                let sig_bytes = self.sign_with_validator(idx, &signing_bytes);
                EpochTransitionVote {
                    voter: self.committee[idx].validator_id,
                    signature: ValidatorSignature { bytes: sig_bytes },
                }
            })
            .collect();

        EpochTransitionProof {
            old_epoch,
            new_epoch,
            new_committee_hash,
            new_committee: new_committee.to_vec(),
            transition_votes,
        }
    }
}
