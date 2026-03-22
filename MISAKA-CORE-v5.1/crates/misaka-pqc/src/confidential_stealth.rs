//! Confidential Stealth — Extended ML-KEM stealth for Q-DAG-CT outputs.
//!
//! Extends the base stealth system (pq_stealth.rs) with blinding factor encryption.
//! In Q-DAG-CT, recipients need both the amount AND the blinding factor to:
//! 1. Verify the commitment opening: C = A₁·r + A₂·v
//! 2. Create spending proofs for the received UTXO
//!
//! # Protocol Extension
//!
//! ```text
//! Sender:
//!   1. ML-KEM-768 encapsulate → (ct, ss)
//!   2. HKDF derive: k_addr, k_amt, k_blind, k_payload, scan_tag, nonce_amt, nonce_blind
//!   3. Encrypt amount via XChaCha20-Poly1305(k_amt, nonce_amt, amount, AAD)
//!   4. Encrypt blinding factor via XChaCha20-Poly1305(k_blind, nonce_blind, blind_bytes, AAD)
//!
//! Recipient:
//!   1. ML-KEM-768 decapsulate → ss
//!   2. Re-derive all sub-keys
//!   3. Check scan_tag
//!   4. Decrypt amount + blinding factor
//!   5. Verify: C == Commit(crs, blind, amount)
//! ```
//!
//! # Security
//!
//! - Each sub-key has its own HKDF label (no nonce reuse across contexts)
//! - Blinding factor is zeroized after use
//! - AAD binds all ciphertext to the one-time address and tx context

use hkdf::Hkdf;
use zeroize::Zeroize;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key as AeadKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use sha3::{Digest as Sha3Digest, Sha3_256};

use crate::error::CryptoError;
use crate::secret::ct_eq;
use crate::pq_kem::{
    ml_kem_encapsulate, ml_kem_decapsulate,
    MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret,
    ML_KEM_CT_LEN,
};
use crate::pq_ring::{Poly, N};
use crate::bdlop::{BdlopCrs, BdlopCommitment, BlindingFactor};
use crate::qdag_tx::ConfidentialStealthData;

// ═══════════════════════════════════════════════════════════════
//  HKDF Labels — each AEAD context gets unique key + nonce
// ═══════════════════════════════════════════════════════════════

const LABEL_ADDR: &[u8]       = b"misaka/ct-stealth/address/v1";
const LABEL_AMT_KEY: &[u8]    = b"misaka/ct-stealth/amt-key/v1";
const LABEL_AMT_NONCE: &[u8]  = b"misaka/ct-stealth/amt-nonce/v1";
const LABEL_BLIND_KEY: &[u8]  = b"misaka/ct-stealth/blind-key/v1";
const LABEL_BLIND_NONCE: &[u8]= b"misaka/ct-stealth/blind-nonce/v1";
const LABEL_SCAN_TAG: &[u8]   = b"misaka/ct-stealth/scan-tag/v1";

/// Version byte for confidential stealth data.
pub const CT_STEALTH_VERSION: u8 = 0x02;

// ═══════════════════════════════════════════════════════════════
//  Derived Materials (all zeroized on drop)
// ═══════════════════════════════════════════════════════════════

struct CtDerivedMaterials {
    k_addr: [u8; 32],
    k_amt: [u8; 32],
    nonce_amt: [u8; 24],
    k_blind: [u8; 32],
    nonce_blind: [u8; 24],
    scan_tag: [u8; 16],
}

impl Drop for CtDerivedMaterials {
    fn drop(&mut self) {
        self.k_addr.zeroize();
        self.k_amt.zeroize();
        self.nonce_amt.zeroize();
        self.k_blind.zeroize();
        self.nonce_blind.zeroize();
        self.scan_tag.zeroize();
    }
}

fn derive_ct_materials(ss: &MlKemSharedSecret) -> Result<CtDerivedMaterials, CryptoError> {
    let hk = Hkdf::<Sha3_256>::new(None, ss.as_bytes());

    let mut m = CtDerivedMaterials {
        k_addr: [0; 32], k_amt: [0; 32], nonce_amt: [0; 24],
        k_blind: [0; 32], nonce_blind: [0; 24], scan_tag: [0; 16],
    };

    hk.expand(LABEL_ADDR, &mut m.k_addr)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    hk.expand(LABEL_AMT_KEY, &mut m.k_amt)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    hk.expand(LABEL_AMT_NONCE, &mut m.nonce_amt)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    hk.expand(LABEL_BLIND_KEY, &mut m.k_blind)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    hk.expand(LABEL_BLIND_NONCE, &mut m.nonce_blind)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    hk.expand(LABEL_SCAN_TAG, &mut m.scan_tag)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    Ok(m)
}

fn derive_one_time_address(k_addr: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_CT_ADDR_V2:");
    h.update(k_addr);
    h.finalize().into()
}

fn build_aad(one_time_address: &[u8; 32], chain_id: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + 4);
    aad.push(CT_STEALTH_VERSION);
    aad.extend_from_slice(one_time_address);
    aad.extend_from_slice(&chain_id.to_le_bytes());
    aad
}

// ═══════════════════════════════════════════════════════════════
//  AEAD helpers
// ═══════════════════════════════════════════════════════════════

fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 24], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher.encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| CryptoError::StealthPayloadTooShort { min: 0, got: pt.len() })
}

fn aead_decrypt(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::StealthHmacMismatch)
}

// ═══════════════════════════════════════════════════════════════
//  Sender: Create confidential stealth output
// ═══════════════════════════════════════════════════════════════

/// Result of creating a confidential stealth output.
pub struct CtStealthOutput {
    pub one_time_address: [u8; 32],
    pub stealth_data: ConfidentialStealthData,
}

/// Create a confidential stealth output with encrypted amount AND blinding factor.
///
/// The recipient uses their ML-KEM secret key to decrypt both values,
/// enabling them to reconstruct the commitment opening and spend the output.
pub fn create_confidential_stealth(
    recipient_view_pk: &MlKemPublicKey,
    amount: u64,
    blind: &BlindingFactor,
    chain_id: u32,
) -> Result<CtStealthOutput, CryptoError> {
    // 1. KEM encapsulation
    let (ct, ss) = ml_kem_encapsulate(recipient_view_pk)?;

    // 2. Derive all sub-keys
    let mat = derive_ct_materials(&ss)?;

    // 3. One-time address
    let one_time_address = derive_one_time_address(&mat.k_addr);

    // 4. AAD
    let aad = build_aad(&one_time_address, chain_id);

    // 5. Encrypt amount (8 bytes → 8 + 16 tag = 24 bytes)
    let amount_ct = aead_encrypt(&mat.k_amt, &mat.nonce_amt, &amount.to_le_bytes(), &aad)?;

    // 6. Encrypt blinding factor polynomial (N*2 = 512 bytes → 512 + 16 tag = 528 bytes)
    let blind_bytes = blind.as_poly().to_bytes();
    let blind_ct = aead_encrypt(&mat.k_blind, &mat.nonce_blind, &blind_bytes, &aad)?;

    Ok(CtStealthOutput {
        one_time_address,
        stealth_data: ConfidentialStealthData {
            kem_ct: ct.as_bytes().to_vec(),
            scan_tag: mat.scan_tag,
            amount_ct,
            blind_ct,
            one_time_address,
        },
    })
}

// ═══════════════════════════════════════════════════════════════
//  Recipient: Scan + Recover
// ═══════════════════════════════════════════════════════════════

/// Verified confidential output — commitment integrity confirmed.
///
/// Audit Fix G: This struct is ONLY returned after commitment verification passes.
/// Raw decrypted data is never exposed without verification.
pub struct VerifiedCtOutput {
    pub one_time_address: [u8; 32],
    pub amount: u64,
    pub blinding_factor: BlindingFactor,
    /// The on-chain commitment that was verified against.
    pub verified_commitment: BdlopCommitment,
}

/// Recipient scanner for confidential stealth outputs.
pub struct CtStealthScanner {
    view_sk: MlKemSecretKey,
}

impl CtStealthScanner {
    pub fn new(view_sk: MlKemSecretKey) -> Self {
        Self { view_sk }
    }

    /// Recover a confidential stealth output with MANDATORY commitment verification.
    ///
    /// # Audit Fix G (CRITICAL)
    ///
    /// The previous API had separate `try_recover()` and `verify_commitment()` calls.
    /// A caller could forget to verify, accepting decrypted data without checking
    /// that the amount+blind match the on-chain commitment.
    ///
    /// This function is now atomic: decryption AND commitment verification happen
    /// together. Unverified raw data is NEVER returned.
    ///
    /// Returns `Ok(Some(verified))` if output belongs to this wallet AND commitment matches.
    /// Returns `Ok(None)` if scan_tag mismatch (not ours).
    /// Returns `Err` if decryption succeeds but commitment doesn't match (malicious sender).
    pub fn try_recover_verified(
        &self,
        stealth_data: &ConfidentialStealthData,
        on_chain_commitment: &BdlopCommitment,
        crs: &BdlopCrs,
        chain_id: u32,
    ) -> Result<Option<VerifiedCtOutput>, CryptoError> {
        // 1. KEM ct length check
        if stealth_data.kem_ct.len() != ML_KEM_CT_LEN {
            return Err(CryptoError::MlKemInvalidCtLen(stealth_data.kem_ct.len()));
        }

        // 2. Decapsulate
        let ct = MlKemCiphertext::from_bytes(&stealth_data.kem_ct)?;
        let ss = ml_kem_decapsulate(&self.view_sk, &ct)?;

        // 3. Derive materials
        let mat = derive_ct_materials(&ss)?;

        // 4. Scan tag check (constant-time)
        if !ct_eq(&mat.scan_tag, &stealth_data.scan_tag) {
            return Ok(None);
        }

        // 5. Derive one-time address and build AAD
        let one_time_address = derive_one_time_address(&mat.k_addr);
        let aad = build_aad(&one_time_address, chain_id);

        // 6. Decrypt amount
        let amount_plain = match aead_decrypt(&mat.k_amt, &mat.nonce_amt, &stealth_data.amount_ct, &aad) {
            Ok(pt) => pt,
            Err(_) => return Ok(None),
        };
        if amount_plain.len() != 8 {
            return Err(CryptoError::StealthPayloadTooShort { min: 8, got: amount_plain.len() });
        }
        let amount = u64::from_le_bytes(amount_plain.try_into().unwrap_or([0u8; 8]));

        // 7. Decrypt blinding factor
        let blind_plain = match aead_decrypt(&mat.k_blind, &mat.nonce_blind, &stealth_data.blind_ct, &aad) {
            Ok(pt) => pt,
            Err(_) => return Ok(None),
        };
        if blind_plain.len() != N * 2 {
            return Err(CryptoError::StealthPayloadTooShort { min: N * 2, got: blind_plain.len() });
        }
        let blind_poly = Poly::from_bytes(&blind_plain)?;
        let blinding_factor = BlindingFactor(blind_poly);

        // ── 8. MANDATORY commitment verification (Audit Fix G) ──
        //
        // Recompute commitment from decrypted (amount, blind) and check
        // it matches the on-chain commitment. If it doesn't, the sender
        // encrypted wrong values — this MUST be an error, not silent acceptance.
        let recomputed = BdlopCommitment::commit(crs, &blinding_factor, amount)?;
        if recomputed != *on_chain_commitment {
            return Err(CryptoError::StealthHmacMismatch);
            // Use StealthHmacMismatch as the closest existing error variant.
            // A dedicated CommitmentMismatch variant should be added.
        }

        Ok(Some(VerifiedCtOutput {
            one_time_address,
            amount,
            blinding_factor,
            verified_commitment: on_chain_commitment.clone(),
        }))
    }
}

fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 { diff |= a[i] ^ b[i]; }
    diff == 0
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_kem::ml_kem_keygen;
    use crate::bdlop::BdlopCrs;

    #[test]
    fn test_confidential_stealth_roundtrip() {
        let kp = ml_kem_keygen().unwrap();
        let crs = BdlopCrs::default_crs();
        let amount = 1_000_000u64;
        let blind = BlindingFactor::random();
        let commitment = BdlopCommitment::commit(&crs, &blind, amount)?;

        let output = create_confidential_stealth(
            &kp.public_key, amount, &blind, 2,
        ).unwrap();

        let scanner = CtStealthScanner::new(kp.secret_key);
        // Audit Fix G: atomic recover + verify
        let recovered = scanner.try_recover_verified(
            &output.stealth_data, &commitment, &crs, 2,
        ).unwrap().expect("should recover output for correct key");

        assert_eq!(recovered.amount, amount);
        assert_eq!(recovered.one_time_address, output.one_time_address);
        assert_eq!(recovered.verified_commitment, commitment);
    }

    #[test]
    fn test_wrong_view_key_no_match() {
        let sender_kp = ml_kem_keygen().unwrap();
        let wrong_kp = ml_kem_keygen().unwrap();
        let crs = BdlopCrs::default_crs();
        let blind = BlindingFactor::random();
        let commitment = BdlopCommitment::commit(&crs, &blind, 500)?;

        let output = create_confidential_stealth(
            &sender_kp.public_key, 500, &blind, 2,
        ).unwrap();

        let scanner = CtStealthScanner::new(wrong_kp.secret_key);
        let result = scanner.try_recover_verified(
            &output.stealth_data, &commitment, &crs, 2,
        ).unwrap();
        assert!(result.is_none(), "wrong key must not recover");
    }

    #[test]
    fn test_wrong_chain_id_fails() {
        let kp = ml_kem_keygen().unwrap();
        let crs = BdlopCrs::default_crs();
        let blind = BlindingFactor::random();
        let commitment = BdlopCommitment::commit(&crs, &blind, 100)?;

        let output = create_confidential_stealth(
            &kp.public_key, 100, &blind, 2,
        ).unwrap();

        let scanner = CtStealthScanner::new(kp.secret_key);
        let result = scanner.try_recover_verified(
            &output.stealth_data, &commitment, &crs, 3,
        ).unwrap();
        assert!(result.is_none(), "wrong chain_id must fail AEAD");
    }

    #[test]
    fn test_commitment_mismatch_is_error() {
        // Audit Fix G: tampered commitment must be a hard ERROR, not silent acceptance
        let kp = ml_kem_keygen().unwrap();
        let crs = BdlopCrs::default_crs();
        let blind = BlindingFactor::random();
        let real_commitment = BdlopCommitment::commit(&crs, &blind, 100)?;

        let output = create_confidential_stealth(
            &kp.public_key, 100, &blind, 2,
        ).unwrap();

        // Use a WRONG commitment
        let wrong_blind = BlindingFactor::random();
        let wrong_commitment = BdlopCommitment::commit(&crs, &wrong_blind, 999)?;

        let scanner = CtStealthScanner::new(kp.secret_key);
        let result = scanner.try_recover_verified(
            &output.stealth_data, &wrong_commitment, &crs, 2,
        );
        assert!(result.is_err(),
            "AUDIT FIX G: commitment mismatch must be a hard error, not silent acceptance");
    }

    #[test]
    fn test_tampered_blind_ct_fails() {
        let kp = ml_kem_keygen().unwrap();
        let crs = BdlopCrs::default_crs();
        let blind = BlindingFactor::random();
        let commitment = BdlopCommitment::commit(&crs, &blind, 100)?;

        let mut output = create_confidential_stealth(
            &kp.public_key, 100, &blind, 2,
        ).unwrap();
        output.stealth_data.blind_ct[0] ^= 0xFF;

        let scanner = CtStealthScanner::new(kp.secret_key);
        let result = scanner.try_recover_verified(
            &output.stealth_data, &commitment, &crs, 2,
        ).unwrap();
        assert!(result.is_none(), "tampered blind_ct must fail AEAD");
    }
}
