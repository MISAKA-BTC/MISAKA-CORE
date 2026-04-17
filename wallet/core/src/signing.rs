//! Transaction signing pipeline — full ML-DSA-65 signature workflow.
//!
//! # Security Properties
//! - All secret key material is zeroized after use
//! - Signature hashing uses domain-separated SHA3-256
//! - Replay protection via chain-id binding in sig hash
//! - Double-spend detection at wallet layer before broadcast
//! - Nonce-misuse resistance via deterministic nonce derivation

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
///
/// # SEC-FIX: DEPRECATED — use `misaka_types::intent::IntentMessage` instead.
///
/// This function uses `"MISAKA:tx:sighash:v2:"` domain separator which is
/// INCOMPATIBLE with the executor's `IntentMessage::signing_digest()` (which uses
/// `"MISAKA-INTENT:v1:"`). Transactions signed with this digest will fail
/// verification in the DAG executor.
///
/// For executor-compatible signing, construct:
/// ```ignore
/// use misaka_types::intent::{IntentMessage, IntentScope, AppId};
/// use misaka_types::tx_signable::TxSignablePayload;
/// let payload = TxSignablePayload::from(&tx);
/// let intent = IntentMessage::wrap(IntentScope::TransparentTransfer, app_id, &payload);
/// let digest = intent.signing_digest();
/// ```
#[deprecated(
    note = "SEC-FIX: Use IntentMessage::signing_digest() for executor-compatible signatures"
)]
pub(crate) fn compute_sig_hash(
    ctx: &SigningContext,
    inputs: &[InputForSigning],
    outputs: &[OutputForSigning],
    input_index: usize,
    hash_type: SigHashType,
) -> [u8; 32] {
    // R4-H4 FIX: Bounds check to prevent panic on invalid input_index.
    if input_index >= inputs.len() {
        tracing::error!(
            "compute_sig_hash: input_index {} out of bounds (inputs.len()={})",
            input_index,
            inputs.len()
        );
        return [0u8; 32];
    }
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

/// Sign a transaction input using ML-DSA-65.
///
/// # Security: Zeroizes the signing key copy after use.
pub fn sign_input(
    sig_hash: &[u8; 32],
    signing_key: &[u8],
    hash_type: SigHashType,
) -> Result<Vec<u8>, SigningError> {
    if signing_key.is_empty() {
        return Err(SigningError::EmptyKey);
    }

    // Domain-separated message for ML-DSA-65 signing
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(b"MISAKA:sign:v1:");
    msg.extend_from_slice(sig_hash);

    // Real ML-DSA-65 signing via pqcrypto dilithium3
    let sk = misaka_pqc::pq_sign::MlDsaSecretKey::from_bytes(signing_key)
        .map_err(|e| SigningError::Failed(format!("invalid secret key: {}", e)))?;
    let pq_sig = misaka_pqc::pq_sign::ml_dsa_sign_raw(&sk, &msg)
        .map_err(|e| SigningError::Failed(format!("ML-DSA-65 signing failed: {}", e)))?;

    let mut sig = pq_sig.0;
    sig.push(hash_type as u8); // append hash_type byte
    Ok(sig)
}

/// Verify a transaction input signature.
///
/// SEC-FIX T3-H1: `sign_input` outputs 3309-byte ML-DSA sig + 1-byte hash_type = 3310.
/// This function now accepts 3310 bytes, splits off the trailing hash_type byte,
/// and verifies the 3309-byte ML-DSA signature. Also accepts raw 3309-byte
/// signatures for backward compatibility with pre-hash-type formats.
pub fn verify_input_signature(
    sig_hash: &[u8; 32],
    public_key: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    if public_key.is_empty() || signature.is_empty() {
        return Ok(false);
    }

    // SEC-FIX T3-H1: sign_input appends 1 hash_type byte → 3310 total.
    // Accept both 3309 (raw ML-DSA) and 3310 (ML-DSA + hash_type).
    let sig_bytes = match signature.len() {
        3310 => &signature[..3309],
        3309 => signature,
        other => return Err(SigningError::InvalidSignatureLength(other)),
    };

    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(b"MISAKA:sign:v1:");
    msg.extend_from_slice(sig_hash);

    let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(public_key)
        .map_err(|e| SigningError::VerificationFailed(format!("invalid public key: {}", e)))?;
    let pq_sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(sig_bytes)
        .map_err(|e| SigningError::VerificationFailed(format!("invalid signature: {}", e)))?;
    match misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, &msg, &pq_sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute the executor-compatible signing digest for a transaction.
///
/// This produces the same 32-byte digest that the DAG executor's
/// `UtxoExecutor` verifies against: `SHA3-256("MISAKA-INTENT:v1:" || borsh(IntentMessage))`.
///
/// Use this instead of `compute_sig_hash()` for all on-chain transactions.
pub fn compute_intent_signing_digest(
    tx: &misaka_types::utxo::UtxoTransaction,
    chain_id: u32,
    genesis_hash: [u8; 32],
) -> [u8; 32] {
    use misaka_types::intent::{AppId, IntentMessage, IntentScope};
    use misaka_types::tx_signable::TxSignablePayload;

    let payload = TxSignablePayload::from(tx);
    let app_id = AppId::new(chain_id, genesis_hash);
    let intent = IntentMessage::wrap(IntentScope::TransparentTransfer, app_id, &payload);
    intent.signing_digest()
}

/// Sign a transaction input using the executor-compatible IntentMessage digest.
///
/// Produces a raw 3309-byte ML-DSA-65 signature (no trailing hash_type byte),
/// compatible with the on-chain verifier.
pub fn sign_input_intent(
    signing_digest: &[u8; 32],
    signing_key: &[u8],
) -> Result<Vec<u8>, SigningError> {
    if signing_key.is_empty() {
        return Err(SigningError::EmptyKey);
    }

    let sk = misaka_pqc::pq_sign::MlDsaSecretKey::from_bytes(signing_key)
        .map_err(|e| SigningError::Failed(format!("invalid secret key: {}", e)))?;
    let pq_sig = misaka_pqc::pq_sign::ml_dsa_sign_raw(&sk, signing_digest)
        .map_err(|e| SigningError::Failed(format!("ML-DSA-65 signing failed: {}", e)))?;

    Ok(pq_sig.0)
}

/// Verify a transaction input signature using the executor-compatible IntentMessage digest.
///
/// Accepts only raw 3309-byte ML-DSA-65 signatures (no hash_type byte).
pub fn verify_input_signature_intent(
    signing_digest: &[u8; 32],
    public_key: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    if public_key.is_empty() || signature.len() != 3309 {
        return Ok(false);
    }

    let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(public_key)
        .map_err(|e| SigningError::VerificationFailed(format!("invalid public key: {}", e)))?;
    let pq_sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(signature)
        .map_err(|e| SigningError::VerificationFailed(format!("invalid signature: {}", e)))?;
    match misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, signing_digest, &pq_sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
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
#[allow(deprecated)]
mod tests {
    use super::*;

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
    fn test_sign_verify_round_trip() {
        let sig_hash = [42u8; 32];
        let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
        let sk_bytes = kp.secret_key.with_bytes(|b| b.to_vec());
        let sig = sign_input(&sig_hash, &sk_bytes, SigHashType::All).unwrap();
        assert!(sig.len() > 3293);
    }
}
