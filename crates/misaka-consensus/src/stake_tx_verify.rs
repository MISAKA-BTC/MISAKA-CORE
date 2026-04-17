//! Stake transaction signature verification (γ-2)
//!
//! Verifies the ML-DSA-65 signature on a `ValidatorStakeTx` against either
//! the consensus pubkey embedded in the Register envelope (for `Register`)
//! or the pubkey already on file in [`StakingRegistry`] (for `StakeMore` /
//! `BeginExit`). Also enforces the `validator_id ⇔ pubkey` binding (for
//! Register) and the state machine constraint that `BeginExit` is only
//! valid for `Active` validators.
//!
//! This module is called from:
//! - `block_validation::validate_and_apply_block_inner` (legacy path,
//!   with an optional `&StakingRegistry` — γ-2)
//! - `utxo_executor` (DAG / finality path, γ-3 — pending)
//!
//! It does NOT mutate registry state. State changes (e.g.
//! `l1_stake_verified = true`, `activate`, `begin_exit`) are performed by
//! the executor in γ-3 AFTER this verification succeeds.

use misaka_crypto::validator_sig::ValidatorPqPublicKey;
use misaka_pqc::pq_sign::{ml_dsa_verify_raw, MlDsaPublicKey, MlDsaSignature};
use misaka_types::validator_stake_tx::{StakeTxKind, StakeTxParams, ValidatorStakeTx};

use crate::staking::{StakingRegistry, ValidatorState};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StakeVerifyError {
    #[error("stake envelope decode failed: {0}")]
    DecodeFailed(String),

    #[error("ML-DSA-65 signature verification failed")]
    SignatureInvalid,

    #[error(
        "validator_id mismatch: expected {} got {}",
        hex::encode(expected),
        hex::encode(actual)
    )]
    ValidatorIdMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("unknown validator: {}", hex::encode(.0))]
    UnknownValidator([u8; 32]),

    #[error("BeginExit requires Active state, got {state}")]
    InvalidStateForBeginExit { state: String },

    #[error("consensus_pubkey parse failed: {0}")]
    PubkeyParseFailed(String),

    #[error("structural validation failed: {0}")]
    StructuralValidation(String),
}

// ─── Verifier ────────────────────────────────────────────────────────────────

/// Verify a `ValidatorStakeTx` against the registry.
///
/// Processing order:
/// 1. `stake_tx.validate_structure()` (defense-in-depth, already called by
///    `UtxoTransaction::validate_structure` in γ-1 but re-run here so the
///    executor path (γ-3) can call this directly).
/// 2. Resolve the verifying pubkey:
///    - `Register` → `params.consensus_pubkey`, plus `validator_id` must
///      equal `ValidatorPqPublicKey::to_canonical_id(pubkey)`.
///    - `StakeMore` / `BeginExit` → `registry.get(validator_id).pubkey`.
/// 3. ML-DSA-65 verify of `stake_tx.signing_payload()`.
/// 4. For `BeginExit`: require `state == Active`.
///
/// The verifier is stateless: it does NOT update `l1_stake_verified` or the
/// validator state. That is the executor's job in γ-3.
///
/// # Register + already-registered
///
/// If `registry.get(stake_tx.validator_id)` is `Some` at call time, this
/// function does NOT reject — γ-6 will add a merge/idempotency layer. For
/// now, re-Register of an existing validator is allowed by the verifier
/// and the executor decides what to do with the delta.
pub fn verify_stake_tx_signature(
    stake_tx: &ValidatorStakeTx,
    registry: &StakingRegistry,
) -> Result<(), StakeVerifyError> {
    // 1. defense-in-depth structural re-check
    stake_tx
        .validate_structure()
        .map_err(|e| StakeVerifyError::StructuralValidation(e.to_string()))?;

    // 2. resolve pubkey + kind-specific preconditions
    let pubkey_bytes: Vec<u8> = match &stake_tx.params {
        StakeTxParams::Register(params) => {
            // validator_id ⇔ pubkey binding
            let pq_pk = ValidatorPqPublicKey::from_bytes(&params.consensus_pubkey)
                .map_err(|e| StakeVerifyError::PubkeyParseFailed(e.to_string()))?;
            let derived_id = pq_pk.to_canonical_id();
            if derived_id != stake_tx.validator_id {
                return Err(StakeVerifyError::ValidatorIdMismatch {
                    expected: derived_id,
                    actual: stake_tx.validator_id,
                });
            }
            // Note: registry.get(&validator_id) may be Some here (re-Register).
            // γ-2 does not reject — γ-6 will add merge/idempotency semantics.
            params.consensus_pubkey.clone()
        }
        StakeTxParams::StakeMore(_) | StakeTxParams::BeginExit => {
            let account = registry
                .get(&stake_tx.validator_id)
                .ok_or(StakeVerifyError::UnknownValidator(stake_tx.validator_id))?;
            account.pubkey.clone()
        }
    };

    // 3. ML-DSA-65 verify
    let pk = MlDsaPublicKey::from_bytes(&pubkey_bytes)
        .map_err(|e| StakeVerifyError::PubkeyParseFailed(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(&stake_tx.signature)
        .map_err(|_| StakeVerifyError::SignatureInvalid)?;
    let payload = stake_tx.signing_payload();
    ml_dsa_verify_raw(&pk, &payload, &sig).map_err(|_| StakeVerifyError::SignatureInvalid)?;

    // 4. BeginExit state precondition (after signature verify so we never
    //    leak registry state to an unauthenticated request)
    if stake_tx.kind == StakeTxKind::BeginExit {
        let account = registry
            .get(&stake_tx.validator_id)
            .ok_or(StakeVerifyError::UnknownValidator(stake_tx.validator_id))?;
        if account.state != ValidatorState::Active {
            return Err(StakeVerifyError::InvalidStateForBeginExit {
                state: account.state.label().to_string(),
            });
        }
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, deprecated)]
mod tests {
    use super::*;
    use crate::staking::StakingConfig;
    use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair};
    use misaka_types::validator_stake_tx::{
        RegisterParams, StakeInput, StakeMoreParams, StakeTxParams, ValidatorStakeTx,
    };

    fn make_config() -> StakingConfig {
        // Testnet defaults but with a tiny min_validator_stake so the
        // compact fixtures (stake_amount = 10_000) pass the bound checks.
        StakingConfig {
            min_validator_stake: 1_000,
            min_uptime_bps: 0,
            min_score: 0,
            ..StakingConfig::testnet()
        }
    }

    fn sign_and_wrap(mut tx: ValidatorStakeTx, kp: &MlDsaKeypair) -> ValidatorStakeTx {
        tx.signature = vec![]; // placeholder so signing_payload is stable
        let payload = tx.signing_payload();
        let sig = ml_dsa_sign_raw(&kp.secret_key, &payload).expect("sign");
        tx.signature = sig.as_bytes().to_vec();
        tx
    }

    fn make_register_tx(kp: &MlDsaKeypair, validator_id: [u8; 32]) -> ValidatorStakeTx {
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xABu8; 32],
                output_index: 0,
                amount: 10_000,
            }],
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: kp.public_key.as_bytes().to_vec(),
                reward_address: [2u8; 32],
                commission_bps: 500,
                p2p_endpoint: None,
                moniker: None,
            }),
            signature: vec![],
        };
        sign_and_wrap(tx, kp)
    }

    fn make_stake_more_tx(
        kp: &MlDsaKeypair,
        validator_id: [u8; 32],
        additional: u64,
    ) -> ValidatorStakeTx {
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::StakeMore,
            validator_id,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xCDu8; 32],
                output_index: 0,
                amount: additional + 1_000,
            }],
            fee: 1_000,
            nonce: 1,
            memo: None,
            params: StakeTxParams::StakeMore(StakeMoreParams {
                additional_amount: additional,
            }),
            signature: vec![],
        };
        sign_and_wrap(tx, kp)
    }

    fn make_begin_exit_tx(kp: &MlDsaKeypair, validator_id: [u8; 32]) -> ValidatorStakeTx {
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::BeginExit,
            validator_id,
            stake_inputs: vec![],
            fee: 1_000,
            nonce: 2,
            memo: None,
            params: StakeTxParams::BeginExit,
            signature: vec![],
        };
        sign_and_wrap(tx, kp)
    }

    fn preregister(registry: &mut StakingRegistry, kp: &MlDsaKeypair, validator_id: [u8; 32]) {
        registry
            .register(
                validator_id,
                kp.public_key.as_bytes().to_vec(),
                10_000, // stake_amount (≥ min 1_000)
                500,    // commission_bps
                [9u8; 32],
                0, // current_epoch
                [0xEEu8; 32],
                0,
                true, // solana_stake_verified — activate() gates on this
                None,
                true, // l1_stake_verified — γ-3 writes true after stake deposit
            )
            .expect("register");
    }

    #[test]
    fn test_register_valid_signature_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let tx = make_register_tx(&kp, vid);
        let registry = StakingRegistry::new(make_config());
        verify_stake_tx_signature(&tx, &registry).expect("valid register");
    }

    #[test]
    fn test_register_invalid_signature() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut tx = make_register_tx(&kp, vid);
        tx.signature[0] ^= 0xFF; // corrupt one byte
        let registry = StakingRegistry::new(make_config());
        match verify_stake_tx_signature(&tx, &registry) {
            Err(StakeVerifyError::SignatureInvalid) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn test_register_validator_id_mismatch() {
        let kp = MlDsaKeypair::generate();
        let wrong_id = [0xFFu8; 32];
        let tx = make_register_tx(&kp, wrong_id);
        let registry = StakingRegistry::new(make_config());
        match verify_stake_tx_signature(&tx, &registry) {
            Err(StakeVerifyError::ValidatorIdMismatch { .. }) => {}
            other => panic!("expected ValidatorIdMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_register_bad_consensus_pubkey() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut tx = make_register_tx(&kp, vid);
        if let StakeTxParams::Register(ref mut params) = tx.params {
            params.consensus_pubkey = vec![0u8; 100]; // wrong length
        }
        let registry = StakingRegistry::new(make_config());
        // validate_structure catches wrong pubkey length before pubkey parse
        match verify_stake_tx_signature(&tx, &registry) {
            Err(StakeVerifyError::StructuralValidation(_)) => {}
            other => panic!("expected StructuralValidation, got {:?}", other),
        }
    }

    #[test]
    fn test_stake_more_unknown_validator() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let tx = make_stake_more_tx(&kp, vid, 5_000);
        let registry = StakingRegistry::new(make_config());
        match verify_stake_tx_signature(&tx, &registry) {
            Err(StakeVerifyError::UnknownValidator(_)) => {}
            other => panic!("expected UnknownValidator, got {:?}", other),
        }
    }

    #[test]
    fn test_stake_more_known_validator_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut registry = StakingRegistry::new(make_config());
        preregister(&mut registry, &kp, vid);
        let tx = make_stake_more_tx(&kp, vid, 5_000);
        verify_stake_tx_signature(&tx, &registry).expect("valid stake_more");
    }

    #[test]
    fn test_begin_exit_active_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut registry = StakingRegistry::new(make_config());
        preregister(&mut registry, &kp, vid);
        // LOCKED → ACTIVE (both verified-flags already true via preregister)
        registry.activate(&vid, 1).expect("activate");
        let tx = make_begin_exit_tx(&kp, vid);
        verify_stake_tx_signature(&tx, &registry).expect("valid begin_exit from Active");
    }

    #[test]
    fn test_begin_exit_locked_rejected() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut registry = StakingRegistry::new(make_config());
        preregister(&mut registry, &kp, vid);
        // state is LOCKED here (no activate)
        let tx = make_begin_exit_tx(&kp, vid);
        match verify_stake_tx_signature(&tx, &registry) {
            Err(StakeVerifyError::InvalidStateForBeginExit { state }) => {
                assert_eq!(state, "LOCKED");
            }
            other => panic!("expected InvalidStateForBeginExit(LOCKED), got {:?}", other),
        }
    }

    /// γ-3: verify path must work for a validator registered through the
    /// L1 native flow (`solana_stake_verified=false, l1_stake_verified=true`).
    /// Mirrors the `stake_more` / `begin_exit` use case from `utxo_executor`
    /// where the registry's pubkey was populated by `register_l1_native`.
    fn preregister_l1_for_stake_more(
        registry: &mut StakingRegistry,
        kp: &MlDsaKeypair,
        validator_id: [u8; 32],
    ) {
        registry
            .register(
                validator_id,
                kp.public_key.as_bytes().to_vec(),
                10_000,
                500,
                [9u8; 32],
                0,
                [0xEEu8; 32],
                0,
                false, // solana_stake_verified
                None,
                true, // l1_stake_verified
            )
            .expect("register (l1-only)");
    }

    #[test]
    fn test_stake_more_l1_only_registry_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut registry = StakingRegistry::new(make_config());
        preregister_l1_for_stake_more(&mut registry, &kp, vid);
        // verify path for StakeMore does not care about the attestation
        // source — pubkey match + ML-DSA-65 are the only checks.
        let tx = make_stake_more_tx(&kp, vid, 5_000);
        verify_stake_tx_signature(&tx, &registry).expect("stake_more against l1-only registry");
    }

    #[test]
    fn test_begin_exit_exiting_rejected() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut registry = StakingRegistry::new(make_config());
        preregister(&mut registry, &kp, vid);
        registry.activate(&vid, 1).expect("activate");
        // `exit()` = ACTIVE → EXITING (staking API name; envelope kind is BeginExit)
        registry.exit(&vid, 2).expect("exit");
        let tx = make_begin_exit_tx(&kp, vid);
        match verify_stake_tx_signature(&tx, &registry) {
            Err(StakeVerifyError::InvalidStateForBeginExit { state }) => {
                assert_eq!(state, "EXITING");
            }
            other => panic!(
                "expected InvalidStateForBeginExit(EXITING), got {:?}",
                other
            ),
        }
    }
}
