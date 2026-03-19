//! Stealth Address Protocol v2 — Enhanced ML-KEM-768 with domain separation.
//!
//! Changes from v1:
//! - Domain separation tags versioned to MISAKA_STEALTH_V2
//! - Structured stealth payload (separate scan_tag / addr_commit / amount_ct / memo_ct)
//! - Optimized scan: 16-byte scan_tag check before any AEAD
//! - Optional encrypted memo field
//! - Better zeroize hygiene
//! - Designed for future confidential transaction extension
//!
//! Backwards compatible: v1 outputs remain scannable via StealthScanner v1.

use hkdf::Hkdf;
use sha3::{Sha3_256, Digest as Sha3Digest};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key as AeadKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

use crate::error::CryptoError;
use crate::pq_kem::{
    ml_kem_encapsulate, ml_kem_decapsulate,
    MlKemPublicKey, MlKemSecretKey, ML_KEM_CT_LEN,
};
use serde::{Serialize, Deserialize};

// ─── Domain Separation Labels (v2) ─────────────────────────

const DST_V2_ROOT:     &[u8] = b"MISAKA_STEALTH_V2:root";
const DST_V2_ADDRESS:  &[u8] = b"MISAKA_STEALTH_V2:address";
const DST_V2_SCAN:     &[u8] = b"MISAKA_STEALTH_V2:scan";
const DST_V2_AMOUNT:   &[u8] = b"MISAKA_STEALTH_V2:amount";
const DST_V2_MEMO:     &[u8] = b"MISAKA_STEALTH_V2:memo";
const DST_V2_NONCE:    &[u8] = b"MISAKA_STEALTH_V2:nonce";
const DST_V2_ADDR_CMT: &[u8] = b"MISAKA_STEALTH_V2:addr_commit";

pub const STEALTH_V2_TAG: u8 = 0x02;

// ─── Stealth Payload v2 ─────────────────────────────────────

/// On-chain stealth extension data v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthPayloadV2 {
    /// Version tag (0x02).
    pub version: u8,
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub kem_ct: Vec<u8>,
    /// Fast-rejection scan tag (16 bytes).
    pub scan_tag: [u8; 16],
    /// Address commitment (20 bytes, for one-time address derivation).
    pub addr_commit: [u8; 20],
    /// AEAD-encrypted amount (8-byte u64 LE + 16-byte tag = 24 bytes).
    pub amount_ct: Vec<u8>,
    /// Optional AEAD-encrypted memo (variable + 16-byte tag).
    pub memo_ct: Option<Vec<u8>>,
}

impl StealthPayloadV2 {
    /// Wire size in bytes.
    pub fn wire_size(&self) -> usize {
        1 + self.kem_ct.len() + 16 + 20 + self.amount_ct.len()
        + self.memo_ct.as_ref().map(|m| m.len()).unwrap_or(0)
        + 4 // length prefixes
    }
}

/// Recovered stealth output (after successful scan + decrypt).
#[derive(Debug, Clone)]
pub struct RecoveredOutputV2 {
    pub amount: u64,
    pub one_time_address: [u8; 20],
    pub memo: Option<Vec<u8>>,
}

// ─── Key Derivation ─────────────────────────────────────────

struct DerivedKeysV2 {
    k_addr: [u8; 32],
    scan_tag: [u8; 16],
    k_amount: [u8; 32],
    k_memo: [u8; 32],
    nonce_bytes: [u8; 24],
    addr_commit: [u8; 20],
}

impl Drop for DerivedKeysV2 {
    fn drop(&mut self) {
        for b in self.k_addr.iter_mut() { unsafe { std::ptr::write_volatile(b, 0u8); } }
        for b in self.k_amount.iter_mut() { unsafe { std::ptr::write_volatile(b, 0u8); } }
        for b in self.k_memo.iter_mut() { unsafe { std::ptr::write_volatile(b, 0u8); } }
        for b in self.scan_tag.iter_mut() { unsafe { std::ptr::write_volatile(b, 0u8); } }
        for b in self.nonce_bytes.iter_mut() { unsafe { std::ptr::write_volatile(b, 0u8); } }
        for b in self.addr_commit.iter_mut() { unsafe { std::ptr::write_volatile(b, 0u8); } }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn derive_keys_v2(shared_secret: &[u8; 32], tx_context: &[u8]) -> Result<DerivedKeysV2, CryptoError> {
    let hk = Hkdf::<Sha3_256>::new(Some(tx_context), shared_secret);

    let mut k_addr = [0u8; 32];
    hk.expand(DST_V2_ADDRESS, &mut k_addr)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    let mut scan_buf = [0u8; 16];
    hk.expand(DST_V2_SCAN, &mut scan_buf)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    let mut k_amount = [0u8; 32];
    hk.expand(DST_V2_AMOUNT, &mut k_amount)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    let mut k_memo = [0u8; 32];
    hk.expand(DST_V2_MEMO, &mut k_memo)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    let mut nonce_bytes = [0u8; 24];
    hk.expand(DST_V2_NONCE, &mut nonce_bytes)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    // Address commitment: SHA3-256(DST || k_addr)[..20]
    let addr_full: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(DST_V2_ADDR_CMT);
        h.update(&k_addr);
        h.finalize().into()
    };
    let mut addr_commit = [0u8; 20];
    addr_commit.copy_from_slice(&addr_full[..20]);

    Ok(DerivedKeysV2 { k_addr, scan_tag: scan_buf, k_amount, k_memo, nonce_bytes, addr_commit })
}

fn build_tx_context(tx_id: &[u8], output_index: u32) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(tx_id.len() + 4 + DST_V2_ROOT.len());
    ctx.extend_from_slice(DST_V2_ROOT);
    ctx.extend_from_slice(tx_id);
    ctx.extend_from_slice(&output_index.to_le_bytes());
    ctx
}

fn encrypt_aead(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    cipher.encrypt(xnonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::StealthDomainMismatch)
}

fn decrypt_aead(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    cipher.decrypt(xnonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::StealthHmacMismatch)
}

// ─── Sender Side ────────────────────────────────────────────

/// Create a stealth output v2.
///
/// Returns (one_time_address, stealth_payload).
pub fn create_stealth_v2(
    recipient_view_pk: &MlKemPublicKey,
    amount: u64,
    memo: Option<&[u8]>,
    tx_id: &[u8],
    output_index: u32,
) -> Result<(/* one_time_address */ [u8; 20], StealthPayloadV2), CryptoError> {
    // 1. KEM encapsulate
    let (ct, ss) = ml_kem_encapsulate(recipient_view_pk)?;

    // 2. Derive all sub-keys
    let tx_ctx = build_tx_context(tx_id, output_index);
    let keys = derive_keys_v2(ss.as_bytes(), &tx_ctx)?;

    // 3. AAD binds tx context
    let aad = {
        let mut a = Vec::new();
        a.push(STEALTH_V2_TAG);
        a.extend_from_slice(tx_id);
        a.extend_from_slice(&output_index.to_le_bytes());
        a.extend_from_slice(&keys.addr_commit);
        a
    };

    // 4. Encrypt amount
    let amount_ct = encrypt_aead(&keys.k_amount, &keys.nonce_bytes, &amount.to_le_bytes(), &aad)?;

    // 5. Optionally encrypt memo
    let memo_ct = if let Some(m) = memo {
        Some(encrypt_aead(&keys.k_memo, &keys.nonce_bytes, m, &aad)?)
    } else {
        None
    };

    let payload = StealthPayloadV2 {
        version: STEALTH_V2_TAG,
        kem_ct: ct.as_bytes().to_vec(),
        scan_tag: keys.scan_tag,
        addr_commit: keys.addr_commit,
        amount_ct,
        memo_ct,
    };

    Ok((keys.addr_commit, payload))
}

// ─── Receiver Side ──────────────────────────────────────────

/// Scanner for stealth v2 outputs.
pub struct StealthScannerV2 {
    secret_key: MlKemSecretKey,
}

impl StealthScannerV2 {
    pub fn new(sk: MlKemSecretKey) -> Self {
        Self { secret_key: sk }
    }

    /// Quick scan: check scan_tag only (no AEAD decrypt).
    /// Returns true if this output *might* be for us.
    pub fn quick_scan(
        &self,
        payload: &StealthPayloadV2,
        tx_id: &[u8],
        output_index: u32,
    ) -> Result<bool, CryptoError> {
        if payload.version != STEALTH_V2_TAG {
            return Ok(false);
        }

        let ct = crate::pq_kem::MlKemCiphertext::from_bytes(&payload.kem_ct)?;
        let ss = ml_kem_decapsulate(&self.secret_key, &ct)?;

        let tx_ctx = build_tx_context(tx_id, output_index);
        let keys = derive_keys_v2(ss.as_bytes(), &tx_ctx)?;

        // Constant-time scan tag comparison
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= keys.scan_tag[i] ^ payload.scan_tag[i];
        }

        Ok(diff == 0)
    }

    /// Full recovery: decrypt amount and memo.
    pub fn recover(
        &self,
        payload: &StealthPayloadV2,
        tx_id: &[u8],
        output_index: u32,
    ) -> Result<Option<RecoveredOutputV2>, CryptoError> {
        if payload.version != STEALTH_V2_TAG {
            return Ok(None);
        }

        let ct = crate::pq_kem::MlKemCiphertext::from_bytes(&payload.kem_ct)?;
        let ss = ml_kem_decapsulate(&self.secret_key, &ct)?;

        let tx_ctx = build_tx_context(tx_id, output_index);
        let keys = derive_keys_v2(ss.as_bytes(), &tx_ctx)?;

        // Check scan_tag
        let mut diff = 0u8;
        for i in 0..16 { diff |= keys.scan_tag[i] ^ payload.scan_tag[i]; }
        if diff != 0 { return Ok(None); }

        // Check addr_commit
        if keys.addr_commit != payload.addr_commit { return Ok(None); }

        // AAD
        let aad = {
            let mut a = Vec::new();
            a.push(STEALTH_V2_TAG);
            a.extend_from_slice(tx_id);
            a.extend_from_slice(&output_index.to_le_bytes());
            a.extend_from_slice(&keys.addr_commit);
            a
        };

        // Decrypt amount
        let amount_bytes = decrypt_aead(&keys.k_amount, &keys.nonce_bytes, &payload.amount_ct, &aad)?;
        if amount_bytes.len() != 8 {
            return Err(CryptoError::StealthPayloadTooShort { min: 8, got: amount_bytes.len() });
        }
        let amount = u64::from_le_bytes(amount_bytes.try_into().unwrap_or([0u8; 8]));

        // Decrypt memo if present
        let memo = if let Some(ref memo_ct) = payload.memo_ct {
            Some(decrypt_aead(&keys.k_memo, &keys.nonce_bytes, memo_ct, &aad)?)
        } else {
            None
        };

        Ok(Some(RecoveredOutputV2 {
            amount,
            one_time_address: keys.addr_commit,
            memo,
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_kem::ml_kem_keygen;
    use std::collections::HashSet;

    #[test]
    fn test_stealth_v2_roundtrip() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x42u8; 32];
        let amount = 1_000_000u64;

        let (ota, payload) = create_stealth_v2(
            &kp.public_key, amount, Some(b"hello bob"), &tx_id, 0,
        ).unwrap();

        assert_eq!(payload.version, STEALTH_V2_TAG);
        assert_eq!(payload.kem_ct.len(), ML_KEM_CT_LEN);
        assert_eq!(payload.addr_commit, ota);

        let scanner = StealthScannerV2::new(kp.secret_key);
        let recovered = scanner.recover(&payload, &tx_id, 0).unwrap().unwrap();
        assert_eq!(recovered.amount, amount);
        assert_eq!(recovered.one_time_address, ota);
        assert_eq!(recovered.memo.as_deref(), Some(b"hello bob".as_slice()));
    }

    #[test]
    fn test_stealth_v2_quick_scan_positive() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0xAA; 32];
        let (_, payload) = create_stealth_v2(&kp.public_key, 5000, None, &tx_id, 0).unwrap();
        let scanner = StealthScannerV2::new(kp.secret_key);
        assert!(scanner.quick_scan(&payload, &tx_id, 0).unwrap());
    }

    #[test]
    fn test_stealth_v2_wrong_recipient() {
        let kp1 = ml_kem_keygen().unwrap();
        let kp2 = ml_kem_keygen().unwrap();
        let tx_id = [0xBB; 32];
        let (_, payload) = create_stealth_v2(&kp1.public_key, 1000, None, &tx_id, 0).unwrap();
        let scanner = StealthScannerV2::new(kp2.secret_key);
        // quick_scan will either return false or decrypt will fail
        let result = scanner.recover(&payload, &tx_id, 0);
        match result {
            Ok(None) => {} // scan_tag mismatch
            Ok(Some(_)) => panic!("should not recover with wrong key"),
            Err(_) => {} // KEM decap fail or AEAD fail
        }
    }

    #[test]
    fn test_stealth_v2_no_memo() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0xCC; 32];
        let (_, payload) = create_stealth_v2(&kp.public_key, 9999, None, &tx_id, 0).unwrap();
        assert!(payload.memo_ct.is_none());
        let scanner = StealthScannerV2::new(kp.secret_key);
        let recovered = scanner.recover(&payload, &tx_id, 0).unwrap().unwrap();
        assert_eq!(recovered.amount, 9999);
        assert!(recovered.memo.is_none());
    }

    #[test]
    fn test_stealth_v2_different_outputs() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0xDD; 32];
        let (ota0, _) = create_stealth_v2(&kp.public_key, 100, None, &tx_id, 0).unwrap();
        let (ota1, _) = create_stealth_v2(&kp.public_key, 200, None, &tx_id, 1).unwrap();
        // Different output indices produce different addresses
        assert_ne!(ota0, ota1);
    }

    #[test]
    fn test_stealth_v2_wire_size() {
        let kp = ml_kem_keygen().unwrap();
        let (_, payload) = create_stealth_v2(&kp.public_key, 1000, Some(b"test"), &[0; 32], 0).unwrap();
        assert!(payload.wire_size() > 0);
        assert_eq!(payload.kem_ct.len(), 1088);
        assert_eq!(payload.amount_ct.len(), 24); // 8 + 16 tag
    }

    // ─── Negative / edge-case tests ─────────────────────────

    #[test]
    fn test_stealth_v2_wrong_tx_id_fails() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x11; 32];
        let (_, payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        let scanner = StealthScannerV2::new(kp.secret_key);
        // Wrong tx_id → scan_tag mismatch or AEAD failure
        let wrong_tx = [0x22; 32];
        let result = scanner.recover(&payload, &wrong_tx, 0);
        match result {
            Ok(None) => {}       // scan_tag mismatch → correct rejection
            Err(_) => {}         // AEAD failure → correct rejection
            Ok(Some(_)) => panic!("should not recover with wrong tx_id"),
        }
    }

    #[test]
    fn test_stealth_v2_wrong_output_index_fails() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x33; 32];
        let (_, payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        let scanner = StealthScannerV2::new(kp.secret_key);
        let result = scanner.recover(&payload, &tx_id, 99);
        match result {
            Ok(None) => {}
            Err(_) => {}
            Ok(Some(_)) => panic!("should not recover with wrong output index"),
        }
    }

    #[test]
    fn test_stealth_v2_tampered_scan_tag() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x44; 32];
        let (_, mut payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        payload.scan_tag[0] ^= 0xFF; // tamper
        let scanner = StealthScannerV2::new(kp.secret_key);
        // quick_scan should return false
        assert!(!scanner.quick_scan(&payload, &tx_id, 0).unwrap());
        // full recover should return None
        assert!(scanner.recover(&payload, &tx_id, 0).unwrap().is_none());
    }

    #[test]
    fn test_stealth_v2_tampered_amount_ct() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x55; 32];
        let (_, mut payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        payload.amount_ct[0] ^= 0xFF; // tamper AEAD ciphertext
        let scanner = StealthScannerV2::new(kp.secret_key);
        // scan_tag matches but AEAD decrypt fails
        let result = scanner.recover(&payload, &tx_id, 0);
        assert!(result.is_err(), "tampered amount_ct must fail AEAD");
    }

    #[test]
    fn test_stealth_v2_tampered_memo_ct() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x66; 32];
        let (_, mut payload) = create_stealth_v2(&kp.public_key, 1000, Some(b"secret memo"), &tx_id, 0).unwrap();
        if let Some(ref mut memo) = payload.memo_ct {
            memo[0] ^= 0xFF; // tamper
        }
        let scanner = StealthScannerV2::new(kp.secret_key);
        let result = scanner.recover(&payload, &tx_id, 0);
        assert!(result.is_err(), "tampered memo_ct must fail AEAD");
    }

    #[test]
    fn test_stealth_v2_tampered_addr_commit() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x77; 32];
        let (_, mut payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        payload.addr_commit[0] ^= 0xFF; // tamper
        let scanner = StealthScannerV2::new(kp.secret_key);
        // addr_commit check fails in recover
        let result = scanner.recover(&payload, &tx_id, 0).unwrap();
        assert!(result.is_none(), "tampered addr_commit must be rejected");
    }

    #[test]
    fn test_stealth_v2_malformed_kem_ct() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x88; 32];
        let (_, mut payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        payload.kem_ct = vec![0u8; 100]; // wrong length
        let scanner = StealthScannerV2::new(kp.secret_key);
        assert!(scanner.quick_scan(&payload, &tx_id, 0).is_err());
    }

    #[test]
    fn test_stealth_v2_wrong_version_tag() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0x99; 32];
        let (_, mut payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
        payload.version = 0xFF; // wrong version
        let scanner = StealthScannerV2::new(kp.secret_key);
        assert!(!scanner.quick_scan(&payload, &tx_id, 0).unwrap());
        assert!(scanner.recover(&payload, &tx_id, 0).unwrap().is_none());
    }

    /// Verify that quick_scan is an optimization ONLY.
    /// A positive quick_scan must ALWAYS be followed by full recover for definitive answer.
    #[test]
    fn test_quick_scan_is_optimization_only() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = [0xAB; 32];
        let (_, payload) = create_stealth_v2(&kp.public_key, 5000, Some(b"test"), &tx_id, 0).unwrap();
        let scanner = StealthScannerV2::new(kp.secret_key);

        // quick_scan = true → must call recover for final answer
        let quick = scanner.quick_scan(&payload, &tx_id, 0).unwrap();
        assert!(quick, "quick_scan should be true for correct recipient");

        let full = scanner.recover(&payload, &tx_id, 0).unwrap();
        assert!(full.is_some(), "recover must succeed after positive quick_scan");
        assert_eq!(full.unwrap().amount, 5000);
    }

    /// Tag collision resistance: 10 different recipients, same tx_id/index.
    /// All scan_tags must be unique (statistical property).
    #[test]
    fn test_stealth_v2_scan_tag_collision_resistance() {
        let tx_id = [0xEE; 32];
        let mut tags = Vec::new();
        for _ in 0..10 {
            let kp = ml_kem_keygen().unwrap();
            let (_, payload) = create_stealth_v2(&kp.public_key, 1000, None, &tx_id, 0).unwrap();
            tags.push(payload.scan_tag);
        }
        // All 10 tags should be unique (probability of collision ≈ 2^-128 per pair)
        let unique: HashSet<[u8; 16]> = tags.iter().cloned().collect();
        assert_eq!(unique.len(), 10, "scan_tag collision detected among 10 outputs");
    }
}
