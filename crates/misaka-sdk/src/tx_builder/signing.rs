//! ML-DSA-65 signing helpers.

use crate::error::SdkError;
use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair, MlDsaSecretKey};
use misaka_types::eutxo::tx_v2::UtxoTransactionV2;

/// Compute the signing digest for a v2 tx input.
/// Must match E4 phase1 digest for verification to succeed.
pub fn compute_signing_digest(tx: &UtxoTransactionV2, input_index: u32) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:eutxo:input_sign:v1:");
    h.update([tx.version]);
    h.update([tx.network_id]);
    h.update(input_index.to_le_bytes());
    let body_bytes = borsh::to_vec(tx).unwrap_or_default();
    let mut bh = Sha3_256::new();
    bh.update(&body_bytes);
    let body_hash: [u8; 32] = bh.finalize().into();
    h.update(body_hash);
    h.finalize().to_vec()
}

/// Sign a tx input with an ML-DSA-65 secret key.
pub fn sign_input(
    tx: &UtxoTransactionV2,
    input_index: u32,
    sk: &MlDsaSecretKey,
) -> Result<Vec<u8>, SdkError> {
    let digest = compute_signing_digest(tx, input_index);
    let sig = ml_dsa_sign_raw(sk, &digest)
        .map_err(|e| SdkError::SigningFailed(format!("{}", e)))?;
    Ok(sig.as_bytes().to_vec())
}

/// Generate a fresh ML-DSA-65 keypair.
pub fn generate_keypair() -> MlDsaKeypair {
    MlDsaKeypair::generate()
}
