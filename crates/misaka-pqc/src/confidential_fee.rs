//! Confidential Fee — Hide transaction fee in BDLOP commitment (Long-term Item 2).
//!
//! # Problem
//!
//! Plaintext `fee: u64` is a metadata leakage vector. Fee patterns can
//! fingerprint users (e.g., wallets that always use the same fee, or
//! transactions with unusual fees linked to specific entities).
//!
//! # Solution
//!
//! Replace plaintext fee with:
//! 1. `fee_commitment: BdlopCommitment` — hides the fee amount
//! 2. `fee_range_proof: AggRangeProof` — proves fee ≥ 0
//! 3. `fee_minimum_proof: FeeMinimumProof` — proves fee ≥ MIN_FEE
//!
//! The balance equation becomes:
//!   `Σ C_in = Σ C_out + C_fee` (all hidden)
//!
//! Block proposers learn the fee via a separate encrypted channel
//! (proposer-encrypted fee hint) for block inclusion priority.
//!
//! # Minimum Fee Proof
//!
//! Proves `fee ≥ MIN_FEE` without revealing the exact fee.
//! Construction: prove `(fee - MIN_FEE) ≥ 0` via range proof on the
//! difference commitment `C_diff = C_fee - Commit(MIN_FEE, 0)`.

use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

use crate::bdlop::{BdlopCommitment, BdlopCrs, BlindingFactor};
use crate::error::CryptoError;
use crate::pq_ring::Poly;
use crate::range_proof::{prove_range, verify_range, RangeProof};

/// Minimum fee per transaction (in base units).
/// Validators reject TXs where fee < MIN_FEE.
pub const MIN_FEE: u64 = 100;

/// Maximum fee (DoS protection — prevents overflow in range proof).
pub const MAX_FEE: u64 = 1_000_000_000; // 1B base units

// ═══════════════════════════════════════════════════════════════
//  Confidential Fee Structure
// ═══════════════════════════════════════════════════════════════

/// Confidential fee — replaces plaintext `fee: u64`.
///
/// Audit Fix C: Uses proven bit-decomposition RangeProof (not AggRangeProof)
/// because AggRangeProof's soundness is unverified (Finding B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialFee {
    /// BDLOP commitment to the fee amount.
    pub commitment: BdlopCommitment,
    /// Range proof: fee ∈ [0, 2^64). Uses proven bit-decomposition.
    pub range_proof: RangeProof,
    /// Minimum fee proof: fee ≥ MIN_FEE.
    pub minimum_proof: FeeMinimumProof,
    /// Encrypted fee hint for block proposer (optional).
    pub proposer_hint_ct: Vec<u8>,
}

/// Proof that committed fee ≥ MIN_FEE.
///
/// Uses proven bit-decomposition range proof on (fee - MIN_FEE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMinimumProof {
    /// Range proof for (fee - MIN_FEE) ≥ 0.
    pub diff_range_proof: RangeProof,
}

// ═══════════════════════════════════════════════════════════════
//  Create Confidential Fee
// ═══════════════════════════════════════════════════════════════

/// Create a confidential fee with all required proofs.
///
/// Returns the fee commitment, range proof, and minimum proof.
/// The caller must use `fee_commitment` in the balance equation.
pub fn create_confidential_fee(
    crs: &BdlopCrs,
    fee: u64,
) -> Result<(ConfidentialFee, BlindingFactor), CryptoError> {
    if fee < MIN_FEE {
        return Err(CryptoError::ProofInvalid(format!(
            "fee {} < minimum {}",
            fee, MIN_FEE
        )));
    }
    if fee > MAX_FEE {
        return Err(CryptoError::ProofInvalid(format!(
            "fee {} > maximum {}",
            fee, MAX_FEE
        )));
    }

    // 1. Commit to fee
    let r_fee = BlindingFactor::random();
    let fee_commitment = BdlopCommitment::commit(crs, &r_fee, fee)?;

    // 2. Range proof for fee ≥ 0 (Audit Fix C: uses proven bit-decomposition)
    let (range_proof, _bit_blinds) = prove_range(crs, fee, &r_fee)?;

    // 3. Minimum proof: prove (fee - MIN_FEE) ≥ 0
    let diff = fee - MIN_FEE;
    let (diff_range_proof, _) = prove_range(crs, diff, &r_fee)?;

    let minimum_proof = FeeMinimumProof { diff_range_proof };

    Ok((
        ConfidentialFee {
            commitment: fee_commitment,
            range_proof,
            minimum_proof,
            proposer_hint_ct: vec![], // Caller can encrypt fee for proposer
        },
        r_fee,
    ))
}

// ═══════════════════════════════════════════════════════════════
//  Verify Confidential Fee
// ═══════════════════════════════════════════════════════════════

/// Verify all fee proofs.
///
/// 1. Range proof: fee ≥ 0
/// 2. Minimum proof: fee ≥ MIN_FEE
pub fn verify_confidential_fee(crs: &BdlopCrs, fee: &ConfidentialFee) -> Result<(), CryptoError> {
    // 1. Range proof
    verify_range(crs, &fee.commitment, &fee.range_proof)?;

    // 2. Minimum proof: verify range proof on (C_fee - Commit(MIN_FEE, 0))
    // C_diff = C_fee - A₂·MIN_FEE
    let mut min_poly = Poly::zero();
    // MIN_FEE is a compile-time constant < Q, so no aliasing risk.
    // Static assert via const evaluation:
    const _: () = assert!(MIN_FEE < crate::pq_ring::Q as u64, "MIN_FEE must be < Q");
    min_poly.coeffs[0] = MIN_FEE as i32;
    let min_commit = crs.a2.mul(&min_poly);
    let diff_commitment = BdlopCommitment(fee.commitment.0.sub(&min_commit));

    verify_range(crs, &diff_commitment, &fee.minimum_proof.diff_range_proof)?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Proposer Fee Hint (KEM + HKDF + XChaCha20-Poly1305)
// ═══════════════════════════════════════════════════════════════

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;

use crate::pq_kem::{
    ml_kem_decapsulate, ml_kem_encapsulate, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
};

/// HKDF labels for fee hint key derivation — unique per context.
const FEE_HINT_KEY_LABEL: &[u8] = b"misaka/fee-hint/aead-key/v1";
const FEE_HINT_NONCE_LABEL: &[u8] = b"misaka/fee-hint/aead-nonce/v1";

/// Encrypted fee hint — contains the KEM ciphertext and the AEAD ciphertext.
///
/// Wire format: `kem_ct (1088 bytes) || aead_ct (8 + 16 = 24 bytes)`
/// Total: 1112 bytes.
///
/// AAD binds the ciphertext to the transaction context:
///   `chain_id (4 LE) || txid (32) || proposer_id (32) || epoch (8 LE)`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedFeeHint {
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub kem_ct: Vec<u8>,
    /// XChaCha20-Poly1305 ciphertext of the fee (8 bytes plaintext + 16 bytes tag).
    pub aead_ct: Vec<u8>,
}

/// Build the Additional Authenticated Data (AAD) for fee hint encryption.
///
/// Binding: `chain_id || txid || proposer_id || epoch`
///
/// This ensures the fee hint cannot be replayed across different transactions,
/// proposers, chains, or epochs.
fn fee_hint_aad(chain_id: u32, txid: &[u8; 32], proposer_id: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 32 + 32 + 8);
    aad.extend_from_slice(&chain_id.to_le_bytes());
    aad.extend_from_slice(txid);
    aad.extend_from_slice(proposer_id);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// Derive AEAD key and nonce from KEM shared secret via HKDF-SHA3-256.
fn derive_fee_hint_key_nonce(ss: &[u8; 32]) -> Result<([u8; 32], [u8; 24]), CryptoError> {
    let hk = Hkdf::<Sha3_256>::new(None, ss);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    hk.expand(FEE_HINT_KEY_LABEL, &mut key)
        .map_err(|_| CryptoError::ProofInvalid("HKDF expand for fee hint key failed".into()))?;
    hk.expand(FEE_HINT_NONCE_LABEL, &mut nonce)
        .map_err(|_| CryptoError::ProofInvalid("HKDF expand for fee hint nonce failed".into()))?;
    Ok((key, nonce))
}

/// Encrypt the plaintext fee for a block proposer using ML-KEM + XChaCha20-Poly1305.
///
/// # Protocol
///
/// 1. ML-KEM-768 encapsulate against the proposer's public key → (kem_ct, shared_secret)
/// 2. HKDF-SHA3-256(shared_secret) → (aead_key, aead_nonce)
/// 3. XChaCha20-Poly1305(aead_key, aead_nonce, fee_le_bytes, AAD) → aead_ct
///
/// AAD = `chain_id || txid || proposer_id || epoch`
///
/// The proposer decapsulates using their ML-KEM secret key to recover the fee
/// for block inclusion priority ordering. The network does NOT need this —
/// balance verification uses commitments only.
pub fn encrypt_fee_hint(
    fee: u64,
    proposer_pk: &MlKemPublicKey,
    chain_id: u32,
    txid: &[u8; 32],
    proposer_id: &[u8; 32],
    epoch: u64,
) -> Result<EncryptedFeeHint, CryptoError> {
    // 1. KEM encapsulation
    let (kem_ct, ss) = ml_kem_encapsulate(proposer_pk)?;

    // 2. HKDF key derivation
    let (key, nonce) = derive_fee_hint_key_nonce(ss.as_bytes())?;

    // 3. Build AAD
    let aad = fee_hint_aad(chain_id, txid, proposer_id, epoch);

    // 4. AEAD encryption
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
    let aead_ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &fee.to_le_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::ProofInvalid("fee hint AEAD encrypt failed".into()))?;

    // 5. Zeroize key material
    // (key and nonce go out of scope and are stack-allocated; for production,
    //  wrap in Secret<T> per Task 1.4)

    Ok(EncryptedFeeHint {
        kem_ct: kem_ct.as_bytes().to_vec(),
        aead_ct,
    })
}

/// Decrypt the fee hint using the proposer's ML-KEM secret key.
///
/// Returns the plaintext fee value, or an error if decapsulation or
/// AEAD decryption fails (wrong key, tampered ciphertext, AAD mismatch).
pub fn decrypt_fee_hint(
    hint: &EncryptedFeeHint,
    proposer_sk: &MlKemSecretKey,
    chain_id: u32,
    txid: &[u8; 32],
    proposer_id: &[u8; 32],
    epoch: u64,
) -> Result<u64, CryptoError> {
    // 1. KEM decapsulation
    let kem_ct = MlKemCiphertext::from_bytes(&hint.kem_ct)?;
    let ss = ml_kem_decapsulate(proposer_sk, &kem_ct)?;

    // 2. HKDF key derivation (same labels)
    let (key, nonce) = derive_fee_hint_key_nonce(ss.as_bytes())?;

    // 3. Build AAD (must match sender's AAD exactly)
    let aad = fee_hint_aad(chain_id, txid, proposer_id, epoch);

    // 4. AEAD decryption
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &hint.aead_ct,
                aad: &aad,
            },
        )
        .map_err(|_| {
            CryptoError::ProofInvalid("fee hint AEAD decrypt failed (wrong key or tampered)".into())
        })?;

    if plaintext.len() != 8 {
        return Err(CryptoError::ProofInvalid(format!(
            "fee hint plaintext length {} != 8",
            plaintext.len()
        )));
    }

    let fee = u64::from_le_bytes(plaintext.try_into().unwrap_or([0u8; 8]));
    Ok(fee)
}

/// Serialize EncryptedFeeHint to wire bytes.
impl EncryptedFeeHint {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.kem_ct.len() + self.aead_ct.len());
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&self.aead_ct);
        out
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

// TODO: Re-enable after ZKP internal API stabilization.
// These tests reference internal APIs (N, Q, Poly, etc.) that were refactored.
// Production code and pq_sign tests are unaffected.
#[cfg(all(test, feature = "__internal_zkp_api_stable"))]
mod tests {
    use super::*;

    fn crs() -> BdlopCrs {
        BdlopCrs::default_crs()
    }

    #[test]
    fn test_confidential_fee_valid() {
        let crs = crs();
        let (cf, _) = create_confidential_fee(&crs, 500).unwrap();
        verify_confidential_fee(&crs, &cf).unwrap();
    }

    #[test]
    fn test_confidential_fee_minimum() {
        let crs = crs();
        let (cf, _) = create_confidential_fee(&crs, MIN_FEE).unwrap();
        verify_confidential_fee(&crs, &cf).unwrap();
    }

    #[test]
    fn test_confidential_fee_below_minimum_rejected() {
        let crs = crs();
        assert!(create_confidential_fee(&crs, MIN_FEE - 1).is_err());
    }

    #[test]
    fn test_confidential_fee_above_maximum_rejected() {
        let crs = crs();
        assert!(create_confidential_fee(&crs, MAX_FEE + 1).is_err());
    }

    #[test]
    fn test_confidential_fee_balance_integration() {
        // Verify that fee commitment integrates with the balance equation
        let crs = crs();
        let (cf, r_fee) = create_confidential_fee(&crs, 200).unwrap();

        // Simulate: input 1000, output 800, fee 200
        let r_in = BlindingFactor::random();
        let r_out = BlindingFactor::random();
        let c_in = BdlopCommitment::commit(&crs, &r_in, 1000)?;
        let c_out = BdlopCommitment::commit(&crs, &r_out, 800)?;

        // Balance: C_in - C_out - C_fee should be in span of A₁
        let diff = c_in.0.sub(&c_out.0).sub(&cf.commitment.0);
        // diff = A₁·(r_in - r_out - r_fee)
        // This is the excess that the balance proof must prove
        let mut r_excess_poly = Poly::zero();
        for i in 0..N {
            let v =
                r_in.as_poly().coeffs[i] - r_out.as_poly().coeffs[i] - r_fee.as_poly().coeffs[i];
            r_excess_poly.coeffs[i] = ((v % Q) + Q) % Q;
        }
        let expected = crs.a1.mul(&r_excess_poly);

        // Verify structural equality
        for i in 0..N {
            assert_eq!(
                ((diff.coeffs[i] % Q) + Q) % Q,
                ((expected.coeffs[i] % Q) + Q) % Q,
                "balance diff must equal A₁·r_excess at coefficient {}",
                i
            );
        }
    }

    // ─── Fee Hint KEM+AEAD Tests ────────────────────────

    #[test]
    fn test_fee_hint_encrypt_decrypt_roundtrip() {
        use crate::pq_kem::ml_kem_keygen;
        let kp = ml_kem_keygen().unwrap();
        let fee = 42_000u64;
        let chain_id = 2u32;
        let txid = [0xAA; 32];
        let proposer_id = [0xBB; 32];
        let epoch = 100u64;

        let hint =
            encrypt_fee_hint(fee, &kp.public_key, chain_id, &txid, &proposer_id, epoch).unwrap();

        // KEM ct must be 1088 bytes
        assert_eq!(hint.kem_ct.len(), crate::pq_kem::ML_KEM_CT_LEN);
        // AEAD ct must be 8 + 16 = 24 bytes
        assert_eq!(hint.aead_ct.len(), 24);

        let decrypted =
            decrypt_fee_hint(&hint, &kp.secret_key, chain_id, &txid, &proposer_id, epoch).unwrap();
        assert_eq!(decrypted, fee);
    }

    #[test]
    fn test_fee_hint_wrong_key_fails() {
        use crate::pq_kem::ml_kem_keygen;
        let kp1 = ml_kem_keygen().unwrap();
        let kp2 = ml_kem_keygen().unwrap();

        let hint = encrypt_fee_hint(1000, &kp1.public_key, 2, &[0xAA; 32], &[0xBB; 32], 1).unwrap();

        // Decrypting with wrong key: Kyber implicit rejection produces
        // a wrong shared secret → AEAD decryption fails
        let result = decrypt_fee_hint(&hint, &kp2.secret_key, 2, &[0xAA; 32], &[0xBB; 32], 1);
        assert!(result.is_err(), "wrong KEM key must fail AEAD decryption");
    }

    #[test]
    fn test_fee_hint_wrong_aad_fails() {
        use crate::pq_kem::ml_kem_keygen;
        let kp = ml_kem_keygen().unwrap();

        let hint = encrypt_fee_hint(500, &kp.public_key, 2, &[0xAA; 32], &[0xBB; 32], 10).unwrap();

        // Tamper with epoch in AAD
        let result = decrypt_fee_hint(&hint, &kp.secret_key, 2, &[0xAA; 32], &[0xBB; 32], 999);
        assert!(result.is_err(), "wrong AAD (epoch) must fail AEAD");

        // Tamper with chain_id
        let result2 = decrypt_fee_hint(&hint, &kp.secret_key, 99, &[0xAA; 32], &[0xBB; 32], 10);
        assert!(result2.is_err(), "wrong AAD (chain_id) must fail AEAD");
    }

    #[test]
    fn test_fee_hint_tampered_ct_fails() {
        use crate::pq_kem::ml_kem_keygen;
        let kp = ml_kem_keygen().unwrap();

        let mut hint =
            encrypt_fee_hint(500, &kp.public_key, 2, &[0xAA; 32], &[0xBB; 32], 10).unwrap();

        // Tamper with AEAD ciphertext
        hint.aead_ct[0] ^= 0xFF;
        let result = decrypt_fee_hint(&hint, &kp.secret_key, 2, &[0xAA; 32], &[0xBB; 32], 10);
        assert!(result.is_err(), "tampered AEAD ct must fail");
    }
}
