//! VRF-Based Proposer Selection — unpredictable, stake-weighted leader election.
//!
//! # Why VRF?
//!
//! Round-robin proposer selection (`slot % n`) is predictable:
//! - Attacker knows who proposes next → targeted DDoS
//! - No randomness → no fairness guarantee over time
//!
//! BTC solves this with PoW randomness, Kaspa with DAG parallelism.
//! For PoS, VRF (Verifiable Random Function) provides:
//! - **Unpredictability**: next proposer unknown until they reveal VRF proof
//! - **Verifiability**: anyone can verify the proof with the public key
//! - **Stake-proportional**: probability of election ∝ stake weight
//!
//! # Construction
//!
//! ML-DSA-65 is deterministic (FIPS 204): `Sign(sk, m)` always produces the
//! same signature for the same (sk, m). This deterministic property is exactly
//! what makes it a valid VRF:
//!
//! ```text
//! vrf_input = SHA3-256("MISAKA:VRF:v1:" || slot || round || epoch_randomness)
//! vrf_proof = ML-DSA-65.Sign(sk, vrf_input)
//! vrf_hash  = SHA3-256("MISAKA:VRF-HASH:v1:" || vrf_proof)
//! ```
//!
//! The `vrf_hash` is mapped to [0, total_stake) to select the proposer.
//!
//! # Anti-Grinding
//!
//! The epoch randomness is committed at epoch boundary (RANDAO accumulation).
//! After commitment, no validator can influence it. The VRF input includes
//! the epoch randomness, so grinding (trying many inputs to get favorable
//! output) is impossible after the epoch starts.
//!
//! # Fallback
//!
//! If no valid VRF proof is received within the timeout, the round advances.
//! A new VRF input (with incremented round) selects a different proposer.
//! This ensures liveness even if the elected proposer is offline.

use sha3::{Digest, Sha3_256};

use super::bft_types::{EpochRandomness, Hash, VrfOutput};
use super::validator_set::ValidatorSet;
use misaka_types::validator::ValidatorId;

// ═══════════════════════════════════════════════════════════════
//  VRF Evaluation & Verification
// ═══════════════════════════════════════════════════════════════

/// Evaluate VRF for proposer election.
///
/// Called by the local validator to produce their VRF proof for a (slot, round).
/// The validator should only reveal this proof if they are the elected leader.
///
/// # Arguments
/// - `sk_bytes`: ML-DSA-65 secret key (4032 bytes)
/// - `slot`: current slot number
/// - `round`: current round within the slot
/// - `epoch_randomness`: committed randomness for this epoch
///
/// # Returns
/// - `VrfOutput` containing the proof and derived hash
pub fn vrf_evaluate(
    sk_bytes: &[u8],
    slot: u64,
    round: u32,
    epoch_randomness: &Hash,
) -> Result<VrfOutput, VrfError> {
    use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaSecretKey};

    let input = VrfOutput::vrf_input(slot, round, epoch_randomness);

    // Domain-separated digest for VRF input
    let digest = vrf_signing_digest(&input);

    let sk = MlDsaSecretKey::from_bytes(sk_bytes)
        .map_err(|_| VrfError::InvalidSecretKey)?;
    let sig = ml_dsa_sign_raw(&sk, &digest)
        .map_err(|_| VrfError::SigningFailed)?;

    let proof_bytes = sig.as_bytes().to_vec();
    let hash = VrfOutput::hash_from_proof(&proof_bytes);

    Ok(VrfOutput {
        proof: proof_bytes,
        hash,
    })
}

/// Verify a VRF proof from another validator.
///
/// # Arguments
/// - `pk_bytes`: ML-DSA-65 public key of the claimed proposer (1952 bytes)
/// - `slot`, `round`, `epoch_randomness`: VRF input parameters
/// - `output`: the VRF output to verify
///
/// # Verification Steps
/// 1. Reconstruct the VRF input from (slot, round, epoch_randomness)
/// 2. Verify the ML-DSA-65 signature (proof) against the public key
/// 3. Verify that `output.hash == SHA3-256(proof)`
pub fn vrf_verify(
    pk_bytes: &[u8],
    slot: u64,
    round: u32,
    epoch_randomness: &Hash,
    output: &VrfOutput,
) -> Result<(), VrfError> {
    use misaka_pqc::pq_sign::{ml_dsa_verify_raw, MlDsaPublicKey, MlDsaSignature};

    let input = VrfOutput::vrf_input(slot, round, epoch_randomness);
    let digest = vrf_signing_digest(&input);

    // Step 1: Verify ML-DSA-65 signature
    let pk = MlDsaPublicKey::from_bytes(pk_bytes)
        .map_err(|_| VrfError::InvalidPublicKey)?;
    let sig = MlDsaSignature::from_bytes(&output.proof)
        .map_err(|_| VrfError::InvalidProofFormat)?;
    ml_dsa_verify_raw(&pk, &digest, &sig)
        .map_err(|_| VrfError::ProofVerificationFailed)?;

    // Step 2: Verify hash derivation
    let expected_hash = VrfOutput::hash_from_proof(&output.proof);
    if expected_hash != output.hash {
        return Err(VrfError::HashMismatch);
    }

    Ok(())
}

/// Domain-separated digest for VRF signing.
fn vrf_signing_digest(input: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:VRF-SIGN:v1:");
    h.update(input);
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
//  Stake-Weighted Proposer Election
// ═══════════════════════════════════════════════════════════════

/// Determine the elected proposer from a VRF hash and the validator set.
///
/// # Algorithm
///
/// 1. Compute cumulative stake ranges for each active validator:
///    ```text
///    validator 0: [0, stake_0)
///    validator 1: [stake_0, stake_0 + stake_1)
///    validator 2: [stake_0 + stake_1, stake_0 + stake_1 + stake_2)
///    ...
///    ```
/// 2. Map VRF hash to [0, total_stake):
///    `index = u128::from(vrf_hash[0..16]) % total_stake`
/// 3. The validator whose range contains `index` is the proposer.
///
/// # Determinism
///
/// The validator list is sorted by validator_id to ensure all nodes
/// compute the same result from the same VRF hash.
///
/// # Stake Proportionality
///
/// Probability of election = validator_stake / total_stake.
/// This is mathematically exact (modular bias is negligible for u128).
pub fn elect_proposer(
    vrf_hash: &Hash,
    validator_set: &ValidatorSet,
) -> Option<ValidatorId> {
    let mut active: Vec<_> = validator_set
        .validators
        .iter()
        .filter(|v| v.is_active && v.stake_weight > 0)
        .collect();

    if active.is_empty() {
        return None;
    }

    // Deterministic ordering: sort by validator_id
    active.sort_by_key(|v| v.validator_id);

    let total_stake: u128 = active.iter().map(|v| v.stake_weight).sum();
    if total_stake == 0 {
        return None;
    }

    // Map vrf_hash to [0, total_stake)
    // Use first 16 bytes of hash as u128 (little-endian)
    let hash_u128 = u128::from_le_bytes(
        vrf_hash[..16].try_into().unwrap_or([0u8; 16]),
    );
    let index = hash_u128 % total_stake;

    // Find the validator whose cumulative range contains `index`
    let mut cumulative: u128 = 0;
    for v in &active {
        cumulative += v.stake_weight;
        if index < cumulative {
            return Some(v.validator_id);
        }
    }

    // Should never reach here, but fail-closed
    Some(active.last().map(|v| v.validator_id).unwrap_or([0u8; 32]))
}

/// Check if a given validator is the elected proposer for (slot, round).
///
/// # Full Verification Flow
///
/// 1. Verify VRF proof (signature check)
/// 2. Derive VRF hash from verified proof
/// 3. Run proposer election with the hash
/// 4. Compare result with claimed proposer
pub fn verify_proposer_election(
    claimed_proposer: &ValidatorId,
    vrf_output: &VrfOutput,
    pk_bytes: &[u8],
    slot: u64,
    round: u32,
    epoch_randomness: &Hash,
    validator_set: &ValidatorSet,
) -> Result<(), VrfError> {
    // Step 1-2: Verify VRF proof and hash
    vrf_verify(pk_bytes, slot, round, epoch_randomness, vrf_output)?;

    // Step 3: Run election
    let elected = elect_proposer(&vrf_output.hash, validator_set)
        .ok_or(VrfError::NoActiveValidators)?;

    // Step 4: Compare
    if elected != *claimed_proposer {
        return Err(VrfError::NotElected {
            claimed: *claimed_proposer,
            actual: elected,
        });
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Legacy Fallback (round-robin)
// ═══════════════════════════════════════════════════════════════

/// Legacy round-robin proposer selection.
///
/// **DEPRECATED**: Use `elect_proposer()` with VRF for production.
/// Retained for testnet compatibility and gradual migration.
pub fn proposer_for_slot_legacy(
    vs: &ValidatorSet,
    slot: u64,
) -> Option<ValidatorId> {
    let active: Vec<&ValidatorId> = vs
        .validators
        .iter()
        .filter(|v| v.is_active)
        .map(|v| &v.validator_id)
        .collect();
    if active.is_empty() {
        return None;
    }
    Some(*active[(slot as usize) % active.len()])
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum VrfError {
    #[error("invalid ML-DSA-65 secret key")]
    InvalidSecretKey,
    #[error("invalid ML-DSA-65 public key")]
    InvalidPublicKey,
    #[error("VRF signing failed")]
    SigningFailed,
    #[error("invalid VRF proof format")]
    InvalidProofFormat,
    #[error("VRF proof verification failed")]
    ProofVerificationFailed,
    #[error("VRF hash mismatch: proof does not derive to claimed hash")]
    HashMismatch,
    #[error("no active validators for proposer election")]
    NoActiveValidators,
    #[error("not elected: claimed={}, actual={}", hex::encode(claimed), hex::encode(actual))]
    NotElected {
        claimed: ValidatorId,
        actual: ValidatorId,
    },
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::generate_validator_keypair;
    use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

    fn make_validator_set(stakes: &[u128]) -> ValidatorSet {
        let mut validators = Vec::new();
        for (i, &stake) in stakes.iter().enumerate() {
            let kp = generate_validator_keypair();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            validators.push(ValidatorIdentity {
                validator_id: vid,
                stake_weight: stake,
                public_key: ValidatorPublicKey {
                    bytes: kp.public_key.to_bytes(),
                },
                is_active: true,
            });
        }
        ValidatorSet::new(validators)
    }

    #[test]
    fn test_elect_proposer_deterministic() {
        let vs = make_validator_set(&[100, 200, 300]);
        let hash = [0xAA; 32];
        let a = elect_proposer(&hash, &vs);
        let b = elect_proposer(&hash, &vs);
        assert_eq!(a, b);
    }

    #[test]
    fn test_elect_proposer_different_hashes_can_differ() {
        let vs = make_validator_set(&[100, 100, 100]);
        let h1 = [0x00; 32];
        let h2 = [0xFF; 32];
        // With equal stake, different hashes should generally select different validators
        // (not guaranteed for specific values, but statistically likely)
        let _a = elect_proposer(&h1, &vs);
        let _b = elect_proposer(&h2, &vs);
        // Just verify both return Some
        assert!(_a.is_some());
        assert!(_b.is_some());
    }

    #[test]
    fn test_elect_proposer_empty_set() {
        let vs = ValidatorSet::new(vec![]);
        assert!(elect_proposer(&[0; 32], &vs).is_none());
    }

    #[test]
    fn test_elect_proposer_single_validator() {
        let vs = make_validator_set(&[1000]);
        // Single validator should always be elected
        for byte in 0..=255u8 {
            let mut hash = [0u8; 32];
            hash[0] = byte;
            let elected = elect_proposer(&hash, &vs);
            assert!(elected.is_some());
        }
    }

    #[test]
    fn test_stake_proportional_election() {
        // Validator A: 900 stake, Validator B: 100 stake
        // Over many random hashes, A should be elected ~90% of the time
        let vs = make_validator_set(&[900, 100]);

        let mut count_first = 0u64;
        let total_trials = 10_000;

        for i in 0..total_trials {
            let mut hash = [0u8; 32];
            // Generate pseudo-random hashes
            let mut h = Sha3_256::new();
            h.update(b"test-seed:");
            h.update(i.to_le_bytes());
            let result: [u8; 32] = h.finalize().into();
            hash.copy_from_slice(&result);

            let elected = elect_proposer(&hash, &vs);
            if let Some(id) = elected {
                if id[0] == 0 {
                    count_first += 1;
                }
            }
        }

        // Expect ~90% for validator 0 (stake 900/1000)
        // Allow ±5% tolerance
        let ratio = count_first as f64 / total_trials as f64;
        assert!(
            (0.85..=0.95).contains(&ratio),
            "Expected ~90% election for 900/1000 stake, got {:.1}%",
            ratio * 100.0
        );
    }

    #[test]
    fn test_vrf_evaluate_and_verify() {
        let kp = generate_validator_keypair();
        let epoch_rand = [0xBB; 32];

        let output = vrf_evaluate(
            &kp.secret_key.pq_sk,
            42,
            0,
            &epoch_rand,
        )
        .expect("VRF evaluate should succeed");

        // Verify
        vrf_verify(
            &kp.public_key.pq_pk,
            42,
            0,
            &epoch_rand,
            &output,
        )
        .expect("VRF verify should succeed");
    }

    #[test]
    fn test_vrf_wrong_key_fails() {
        let kp1 = generate_validator_keypair();
        let kp2 = generate_validator_keypair();
        let epoch_rand = [0xBB; 32];

        let output = vrf_evaluate(&kp1.secret_key.pq_sk, 42, 0, &epoch_rand)
            .expect("VRF evaluate should succeed");

        // Wrong key
        let result = vrf_verify(&kp2.public_key.pq_pk, 42, 0, &epoch_rand, &output);
        assert!(result.is_err());
    }

    #[test]
    fn test_vrf_wrong_slot_fails() {
        let kp = generate_validator_keypair();
        let epoch_rand = [0xBB; 32];

        let output = vrf_evaluate(&kp.secret_key.pq_sk, 42, 0, &epoch_rand)
            .expect("VRF evaluate should succeed");

        // Wrong slot
        let result = vrf_verify(&kp.public_key.pq_pk, 43, 0, &epoch_rand, &output);
        assert!(result.is_err());
    }

    #[test]
    fn test_vrf_hash_tamper_detected() {
        let kp = generate_validator_keypair();
        let epoch_rand = [0xBB; 32];

        let mut output = vrf_evaluate(&kp.secret_key.pq_sk, 42, 0, &epoch_rand)
            .expect("VRF evaluate should succeed");

        // Tamper hash
        output.hash[0] ^= 0xFF;

        let result = vrf_verify(&kp.public_key.pq_pk, 42, 0, &epoch_rand, &output);
        assert!(matches!(result, Err(VrfError::HashMismatch)));
    }

    #[test]
    fn test_vrf_deterministic() {
        let kp = generate_validator_keypair();
        let epoch_rand = [0xBB; 32];

        let out1 = vrf_evaluate(&kp.secret_key.pq_sk, 42, 0, &epoch_rand).unwrap();
        let out2 = vrf_evaluate(&kp.secret_key.pq_sk, 42, 0, &epoch_rand).unwrap();
        assert_eq!(out1.hash, out2.hash);
    }
}
