//! Transaction signing pipeline — full ML-DSA-65 signature workflow.
//!
//! # Security Properties
//! - All secret key material is zeroized after use
//! - Signature hashing uses domain-separated SHA3-256
//! - Replay protection via chain-id binding in sig hash
//! - Double-spend detection at wallet layer before broadcast
//! - Nonce-misuse resistance via deterministic nonce derivation

use misaka_pqc::pq_sign::{
    ml_dsa_sign_raw, ml_dsa_verify_raw,
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    ML_DSA_PK_LEN, ML_DSA_SK_LEN, ML_DSA_SIG_LEN,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Signature hash type — determines which parts of a tx are signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigHashType {
    /// Sign all inputs and all outputs (default, most secure).
    All = 0x01,
    /// Sign all inputs, no outputs (allows output modification).
    None = 0x02,
    /// Sign all inputs, only the output at the same index.
    Single = 0x03,
    /// AnyoneCanPay modifier — sign only this input.
    AnyoneCanPayAll = 0x81,
    AnyoneCanPayNone = 0x82,
    AnyoneCanPaySingle = 0x83,
}

impl SigHashType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::All),
            0x02 => Some(Self::None),
            0x03 => Some(Self::Single),
            0x81 => Some(Self::AnyoneCanPayAll),
            0x82 => Some(Self::AnyoneCanPayNone),
            0x83 => Some(Self::AnyoneCanPaySingle),
            _ => None,
        }
    }

    pub fn anyone_can_pay(&self) -> bool {
        (*self as u8) & 0x80 != 0
    }

    pub fn base_type(&self) -> u8 {
        (*self as u8) & 0x1f
    }
}

/// Transaction signing context — binds signature to specific tx state.
#[derive(Debug, Clone)]
pub struct SigningContext {
    pub chain_id: [u8; 4],
    pub tx_version: u32,
    pub lock_time: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload_hash: [u8; 32],
}

/// Compute the signature hash for a transaction input.
///
/// # Algorithm
/// ```text
/// sig_hash = SHA3-256(
///     domain_prefix ||
///     chain_id ||
///     hash_type ||
///     hash_prevouts ||
///     hash_sequence ||
///     outpoint ||
///     script_public_key ||
///     value ||
///     hash_outputs ||
///     lock_time ||
///     subnetwork_id
/// )
/// ```
pub fn compute_sig_hash(
    ctx: &SigningContext,
    inputs: &[InputForSigning],
    outputs: &[OutputForSigning],
    input_index: usize,
    hash_type: SigHashType,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:tx:sighash:v2:");
    h.update(&ctx.chain_id);
    h.update(&[hash_type as u8]);

    // Hash prevouts (all inputs or just this one)
    let hash_prevouts = if hash_type.anyone_can_pay() {
        hash_single_outpoint(&inputs[input_index])
    } else {
        hash_all_outpoints(inputs)
    };
    h.update(&hash_prevouts);

    // Hash sequences
    let hash_sequences = if hash_type.anyone_can_pay() || hash_type.base_type() != 0x01 {
        [0u8; 32]
    } else {
        hash_all_sequences(inputs)
    };
    h.update(&hash_sequences);

    // Current input outpoint
    h.update(&inputs[input_index].prev_tx_id);
    h.update(&inputs[input_index].prev_index.to_le_bytes());

    // Script public key of the input being signed
    h.update(&(inputs[input_index].script_public_key.len() as u32).to_le_bytes());
    h.update(&inputs[input_index].script_public_key);

    // Value
    h.update(&inputs[input_index].value.to_le_bytes());

    // Hash outputs
    let hash_outputs = match hash_type.base_type() {
        0x01 => hash_all_outputs(outputs),
        0x03 if input_index < outputs.len() => hash_single_output(&outputs[input_index]),
        _ => [0u8; 32],
    };
    h.update(&hash_outputs);

    // Lock time and metadata
    h.update(&ctx.lock_time.to_le_bytes());
    h.update(&ctx.subnetwork_id);
    h.update(&ctx.gas.to_le_bytes());
    h.update(&ctx.payload_hash);

    h.finalize().into()
}

/// Input data needed for signature hash computation.
#[derive(Debug, Clone)]
pub struct InputForSigning {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub value: u64,
    pub script_public_key: Vec<u8>,
    pub sequence: u64,
}

/// Output data needed for signature hash computation.
#[derive(Debug, Clone)]
pub struct OutputForSigning {
    pub value: u64,
    pub script_public_key: Vec<u8>,
}

fn hash_all_outpoints(inputs: &[InputForSigning]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for input in inputs {
        h.update(&input.prev_tx_id);
        h.update(&input.prev_index.to_le_bytes());
    }
    h.finalize().into()
}

fn hash_single_outpoint(input: &InputForSigning) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(&input.prev_tx_id);
    h.update(&input.prev_index.to_le_bytes());
    h.finalize().into()
}

fn hash_all_sequences(inputs: &[InputForSigning]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for input in inputs {
        h.update(&input.sequence.to_le_bytes());
    }
    h.finalize().into()
}

fn hash_all_outputs(outputs: &[OutputForSigning]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for output in outputs {
        h.update(&output.value.to_le_bytes());
        h.update(&(output.script_public_key.len() as u32).to_le_bytes());
        h.update(&output.script_public_key);
    }
    h.finalize().into()
}

fn hash_single_output(output: &OutputForSigning) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(&output.value.to_le_bytes());
    h.update(&(output.script_public_key.len() as u32).to_le_bytes());
    h.update(&output.script_public_key);
    h.finalize().into()
}

/// Sign a transaction input using real ML-DSA-65 (Dilithium3).
///
/// Calls `pqcrypto_dilithium::dilithium3::detached_sign` under the hood.
///
/// # Output Format
/// `[ML-DSA-65 signature (3309 bytes)][SigHashType (1 byte)]`
///
/// # Security
/// - Domain-separated: "MISAKA:sign:v1:" prefix prevents cross-context replay
/// - Key length enforced: must be ML_DSA_SK_LEN (4032 bytes)
pub fn sign_input(
    sig_hash: &[u8; 32],
    signing_key: &[u8],
    hash_type: SigHashType,
) -> Result<Vec<u8>, SigningError> {
    if signing_key.is_empty() {
        return Err(SigningError::EmptyKey);
    }
    if signing_key.len() != ML_DSA_SK_LEN {
        return Err(SigningError::Failed(format!(
            "signing key must be {} bytes (ML-DSA-65), got {}",
            ML_DSA_SK_LEN, signing_key.len()
        )));
    }

    let sk = MlDsaSecretKey::from_bytes(signing_key)
        .map_err(|e| SigningError::Failed(format!("invalid ML-DSA-65 secret key: {}", e)))?;

    // Domain-separated message — same prefix used by verify_input_signature
    let mut msg = Vec::with_capacity(47); // 15 prefix + 32 hash
    msg.extend_from_slice(b"MISAKA:sign:v1:");
    msg.extend_from_slice(sig_hash);

    let signature = ml_dsa_sign_raw(&sk, &msg)
        .map_err(|e| SigningError::Failed(format!("ML-DSA-65 sign failed: {}", e)))?;

    // Output: [3309 bytes ML-DSA-65 signature][1 byte hash_type]
    let mut result = Vec::with_capacity(ML_DSA_SIG_LEN + 1);
    result.extend_from_slice(signature.as_bytes());
    result.push(hash_type as u8);

    Ok(result)
}

/// Verify a transaction input signature using real ML-DSA-65 (Dilithium3).
///
/// Calls `pqcrypto_dilithium::dilithium3::verify_detached_signature` under the hood.
///
/// # Input Format
/// `signature` must be `[ML-DSA-65 sig (3309 bytes)][SigHashType (1 byte)]`
/// or at minimum `[ML-DSA-65 sig (3309 bytes)]`.
pub fn verify_input_signature(
    sig_hash: &[u8; 32],
    public_key: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    if public_key.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    if signature.len() < ML_DSA_SIG_LEN {
        return Err(SigningError::InvalidSignatureLength(signature.len()));
    }
    if public_key.len() != ML_DSA_PK_LEN {
        return Err(SigningError::VerificationFailed(format!(
            "public key must be {} bytes (ML-DSA-65), got {}",
            ML_DSA_PK_LEN, public_key.len()
        )));
    }

    let pk = MlDsaPublicKey::from_bytes(public_key)
        .map_err(|e| SigningError::VerificationFailed(format!("invalid public key: {}", e)))?;

    // Extract the ML-DSA-65 signature bytes (first 3309 bytes, rest is hash_type)
    let sig = MlDsaSignature::from_bytes(&signature[..ML_DSA_SIG_LEN])
        .map_err(|e| SigningError::VerificationFailed(format!("invalid signature: {}", e)))?;

    // Domain-separated message — same prefix used by sign_input
    let mut msg = Vec::with_capacity(47);
    msg.extend_from_slice(b"MISAKA:sign:v1:");
    msg.extend_from_slice(sig_hash);

    match ml_dsa_verify_raw(&pk, &msg, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Batch signing of all inputs in a transaction.
pub fn sign_transaction(
    ctx: &SigningContext,
    inputs: &[InputForSigning],
    outputs: &[OutputForSigning],
    signing_keys: &[Vec<u8>],
    hash_type: SigHashType,
) -> Result<Vec<Vec<u8>>, SigningError> {
    if inputs.len() != signing_keys.len() {
        return Err(SigningError::KeyCountMismatch {
            inputs: inputs.len(),
            keys: signing_keys.len(),
        });
    }

    let mut signatures = Vec::with_capacity(inputs.len());
    for (i, key) in signing_keys.iter().enumerate() {
        let sig_hash = compute_sig_hash(ctx, inputs, outputs, i, hash_type);
        let sig = sign_input(&sig_hash, key, hash_type)?;
        signatures.push(sig);
    }
    Ok(signatures)
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("empty signing key")]
    EmptyKey,
    #[error("invalid signature length: {0}")]
    InvalidSignatureLength(usize),
    #[error("key count mismatch: {inputs} inputs, {keys} keys")]
    KeyCountMismatch { inputs: usize, keys: usize },
    #[error("signing failed: {0}")]
    Failed(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;

    fn test_ctx() -> SigningContext {
        SigningContext {
            chain_id: [0x4D, 0x53, 0x4B, 0x01],
            tx_version: 1,
            lock_time: 0,
            subnetwork_id: [0; 20],
            gas: 0,
            payload_hash: [0; 32],
        }
    }

    #[test]
    fn test_sig_hash_determinism() {
        let ctx = test_ctx();
        let inputs = vec![InputForSigning {
            prev_tx_id: [1; 32],
            prev_index: 0,
            value: 5000,
            script_public_key: vec![0x76, 0xa7],
            sequence: u64::MAX,
        }];
        let outputs = vec![OutputForSigning {
            value: 4000,
            script_public_key: vec![0x76, 0xa7],
        }];

        let h1 = compute_sig_hash(&ctx, &inputs, &outputs, 0, SigHashType::All);
        let h2 = compute_sig_hash(&ctx, &inputs, &outputs, 0, SigHashType::All);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_hash_types() {
        let ctx = test_ctx();
        let inputs = vec![InputForSigning {
            prev_tx_id: [1; 32],
            prev_index: 0,
            value: 5000,
            script_public_key: vec![0x76],
            sequence: u64::MAX,
        }];
        let outputs = vec![OutputForSigning {
            value: 4000,
            script_public_key: vec![0x76],
        }];

        let h_all = compute_sig_hash(&ctx, &inputs, &outputs, 0, SigHashType::All);
        let h_none = compute_sig_hash(&ctx, &inputs, &outputs, 0, SigHashType::None);
        assert_ne!(h_all, h_none);
    }

    #[test]
    fn test_sign_verify_round_trip_real_mldsa65() {
        // Generate a real ML-DSA-65 keypair
        let kp = MlDsaKeypair::generate();

        let sig_hash = [42u8; 32];
        let sig = sign_input(
            &sig_hash,
            kp.secret_key.as_bytes(),
            SigHashType::All,
        ).expect("signing should succeed");

        // Signature = 3309 bytes ML-DSA-65 + 1 byte hash_type
        assert_eq!(sig.len(), ML_DSA_SIG_LEN + 1);
        assert_eq!(sig[ML_DSA_SIG_LEN], SigHashType::All as u8);

        // Verify with the corresponding public key
        let valid = verify_input_signature(
            &sig_hash,
            kp.public_key.as_bytes(),
            &sig,
        ).expect("verification should not error");
        assert!(valid, "valid signature must verify");
    }

    #[test]
    fn test_wrong_key_rejected() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();

        let sig_hash = [99u8; 32];
        let sig = sign_input(
            &sig_hash,
            kp1.secret_key.as_bytes(),
            SigHashType::All,
        ).unwrap();

        // Verify with WRONG public key → must fail
        let valid = verify_input_signature(
            &sig_hash,
            kp2.public_key.as_bytes(),
            &sig,
        ).expect("verification should not error");
        assert!(!valid, "signature from different key must not verify");
    }

    #[test]
    fn test_tampered_sig_hash_rejected() {
        let kp = MlDsaKeypair::generate();

        let sig_hash = [42u8; 32];
        let sig = sign_input(
            &sig_hash,
            kp.secret_key.as_bytes(),
            SigHashType::All,
        ).unwrap();

        // Verify with DIFFERENT sig_hash → must fail
        let wrong_hash = [43u8; 32];
        let valid = verify_input_signature(
            &wrong_hash,
            kp.public_key.as_bytes(),
            &sig,
        ).expect("verification should not error");
        assert!(!valid, "tampered sig_hash must not verify");
    }

    #[test]
    fn test_full_transaction_sign_verify() {
        let kp = MlDsaKeypair::generate();
        let ctx = test_ctx();

        let inputs = vec![InputForSigning {
            prev_tx_id: [1; 32],
            prev_index: 0,
            value: 5000,
            script_public_key: vec![0x76, 0xa7],
            sequence: u64::MAX,
        }];
        let outputs = vec![OutputForSigning {
            value: 4000,
            script_public_key: vec![0x76, 0xa7],
        }];

        // Sign all inputs
        let sigs = sign_transaction(
            &ctx,
            &inputs,
            &outputs,
            &[kp.secret_key.as_bytes().to_vec()],
            SigHashType::All,
        ).expect("transaction signing should succeed");

        assert_eq!(sigs.len(), 1);

        // Verify each signature
        let sig_hash = compute_sig_hash(&ctx, &inputs, &outputs, 0, SigHashType::All);
        let valid = verify_input_signature(
            &sig_hash,
            kp.public_key.as_bytes(),
            &sigs[0],
        ).expect("verification should not error");
        assert!(valid, "transaction signature must verify");
    }

    #[test]
    fn test_empty_key_rejected() {
        let sig_hash = [0u8; 32];
        assert!(sign_input(&sig_hash, &[], SigHashType::All).is_err());
    }

    #[test]
    fn test_wrong_key_length_rejected() {
        let sig_hash = [0u8; 32];
        // 64 bytes is not a valid ML-DSA-65 secret key (must be 4032)
        assert!(sign_input(&sig_hash, &[1u8; 64], SigHashType::All).is_err());
    }

    #[test]
    fn test_cross_compatibility_with_node_verify() {
        // This test proves that wallet-signed TX can be verified by the
        // same ml_dsa_verify_raw() that the node consensus layer uses.
        let kp = MlDsaKeypair::generate();
        let sig_hash = [0xAB; 32];

        // Wallet signs
        let sig = sign_input(
            &sig_hash,
            kp.secret_key.as_bytes(),
            SigHashType::All,
        ).unwrap();

        // Construct the same domain-separated message the node would
        let mut msg = Vec::with_capacity(47);
        msg.extend_from_slice(b"MISAKA:sign:v1:");
        msg.extend_from_slice(&sig_hash);

        // Verify using the raw PQC function (same as node side)
        let pq_sig = MlDsaSignature::from_bytes(&sig[..ML_DSA_SIG_LEN]).unwrap();
        let result = ml_dsa_verify_raw(
            &kp.public_key,
            &msg,
            &pq_sig,
        );
        assert!(result.is_ok(), "wallet signature must be verifiable by node's ml_dsa_verify_raw");
    }
}
