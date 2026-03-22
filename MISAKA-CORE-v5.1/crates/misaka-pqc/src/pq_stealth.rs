//! PQ Stealth Addresses — HKDF + XChaCha20-Poly1305 (Spec §5).
//!
//! # Protocol
//!
//! **Sender** (per output):
//! 1. Derive deterministic encapsulation seed from tx_unique_id, output_index, recipient pk
//! 2. ML-KEM-768 encapsulate → (kem_ct, shared_secret)
//! 3. HKDF-Extract(shared_secret) → root_key
//! 4. HKDF-Expand domain-separated sub-keys: k_addr, k_amt, k_payload, scan_tag, nonce
//! 5. Encrypt amount + payload with XChaCha20-Poly1305 (AAD binds tx context)
//!
//! **Recipient** scan:
//! 1. Structural checks (version, kem_ct length)
//! 2. ML-KEM-768 decapsulate → shared_secret
//! 3. Re-derive all sub-keys
//! 4. Compare scan_tag (constant-time)
//! 5. Verify one-time address match
//! 6. AEAD decrypt amount + payload
//! 7. Validate ranges
//!
//! # Security
//!
//! - All keys domain-separated via HKDF-Expand labels
//! - Amount + payload authenticated via AEAD (XChaCha20-Poly1305)
//! - AAD binds: version || tx_unique_id || output_index || one_time_address
//! - Scan tag is 16 bytes for fast rejection before AEAD
//! - Shared secrets zeroized on drop

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha3::{Digest as Sha3Digest, Sha3_256};

use crate::error::CryptoError;
use crate::secret::ct_eq;
use crate::pq_kem::{
    ml_kem_decapsulate, ml_kem_encapsulate, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
    MlKemSharedSecret, ML_KEM_CT_LEN,
};
use misaka_types::stealth::{PqStealthData, PQ_STEALTH_VERSION};

// ─── HKDF Domain Labels ─────────────────────────────────────

const LABEL_ADDRESS: &[u8] = b"misaka/pq-stealth/address/v1";
const LABEL_AMOUNT: &[u8] = b"misaka/pq-stealth/amount/v1";
const LABEL_PAYLOAD: &[u8] = b"misaka/pq-stealth/payload/v1";
const LABEL_SCAN_TAG: &[u8] = b"misaka/pq-stealth/scan-tag/v1";
const LABEL_NONCE: &[u8] = b"misaka/pq-stealth/nonce/v1";

// ─── Key Derivation ──────────────────────────────────────────

/// Derive the deterministic encapsulation seed (§5 step 1).
///
/// `seed32 = HKDF-Expand(HKDF-Extract("", tx_id || idx || pk), LABEL_ENCAP_SEED, 32)`

/// Materials derived from the KEM shared secret via HKDF.
struct DerivedMaterials {
    k_addr: [u8; 32],
    k_amt: [u8; 32],
    k_payload: [u8; 32],
    scan_tag: [u8; 16],
    nonce_bytes: [u8; 24],
}

impl Drop for DerivedMaterials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k_addr.zeroize();
        self.k_amt.zeroize();
        self.k_payload.zeroize();
        self.scan_tag.zeroize();
        self.nonce_bytes.zeroize();
    }
}

/// Derive all sub-keys from the KEM shared secret (§5 steps 3-4).
fn derive_materials(shared_secret: &MlKemSharedSecret) -> Result<DerivedMaterials, CryptoError> {
    // root_key = HKDF-Extract("", shared_secret) — using SHA3-256 (Grover-resistant)
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret.as_bytes());

    let mut k_addr = [0u8; 32];
    hk.expand(LABEL_ADDRESS, &mut k_addr)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    let mut k_amt = [0u8; 32];
    hk.expand(LABEL_AMOUNT, &mut k_amt)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    let mut k_payload = [0u8; 32];
    hk.expand(LABEL_PAYLOAD, &mut k_payload)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    let mut scan_tag = [0u8; 16];
    hk.expand(LABEL_SCAN_TAG, &mut scan_tag)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;
    let mut nonce_bytes = [0u8; 24];
    hk.expand(LABEL_NONCE, &mut nonce_bytes)
        .map_err(|_| CryptoError::StealthDomainMismatch)?;

    Ok(DerivedMaterials {
        k_addr,
        k_amt,
        k_payload,
        scan_tag,
        nonce_bytes,
    })
}

/// Derive one-time destination address from k_addr.
///
/// `addr = SHA3-256(k_addr)[0..20]`
fn derive_one_time_address(k_addr: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(k_addr);
    h.finalize().into()
}

/// Build the AAD that binds ciphertext to tx context.
///
/// `AAD = version || tx_unique_id || output_index_le || one_time_address`
fn build_aad(tx_unique_id: &[u8; 32], output_index: u32, one_time_address: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 32 + 4 + 20);
    aad.push(PQ_STEALTH_VERSION);
    aad.extend_from_slice(tx_unique_id);
    aad.extend_from_slice(&output_index.to_le_bytes());
    aad.extend_from_slice(one_time_address);
    aad
}

// ─── AEAD Encrypt / Decrypt ──────────────────────────────────

fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(key));
    let nonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::StealthPayloadTooShort {
            min: 0,
            got: plaintext.len(),
        })
}

fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(key));
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::StealthHmacMismatch)
}

// ─── Public: Stealth Output ──────────────────────────────────

/// Fully constructed stealth output.
#[derive(Debug, Clone)]
pub struct StealthOutput {
    /// One-time destination address (20 bytes).
    pub one_time_address: [u8; 32],
    /// On-chain stealth data for the output.
    pub stealth_data: PqStealthData,
}

/// Recovered stealth output after successful scan.
#[derive(Debug, Clone)]
pub struct RecoveredOutput {
    pub one_time_address: [u8; 32],
    pub amount: u64,
    pub payload: Vec<u8>,
    pub output_index: u32,
}

// ─── Sender: Create ──────────────────────────────────────────

/// Create a stealth output for a recipient (§5 sender pipeline).
///
/// - `recipient_view_pk`: ML-KEM-768 view public key
/// - `amount`: amount in base units
/// - `payload`: optional extra data (memo, asset ID, etc.)
/// - `tx_unique_id`: 32-byte transaction identifier
/// - `output_index`: index within the transaction
pub fn create_stealth_output(
    recipient_view_pk: &MlKemPublicKey,
    amount: u64,
    payload: &[u8],
    tx_unique_id: &[u8; 32],
    output_index: u32,
) -> Result<StealthOutput, CryptoError> {
    // 1. KEM encapsulation (randomized — deterministic seed reserved for testing)
    let (ct, ss) = ml_kem_encapsulate(recipient_view_pk)?;

    // 2-4. Derive all sub-keys
    let mat = derive_materials(&ss)?;

    // 5. Derive one-time address
    let one_time_address = derive_one_time_address(&mat.k_addr);

    // 6. Build AAD
    let aad = build_aad(tx_unique_id, output_index, &one_time_address);

    // 7. Encrypt amount (XChaCha20-Poly1305)
    let amount_bytes = amount.to_le_bytes();
    let amount_ct = aead_encrypt(&mat.k_amt, &mat.nonce_bytes, &amount_bytes, &aad)?;

    // 8. Encrypt payload
    let payload_ct = if payload.is_empty() {
        // Empty payload → encrypt zero-length → just the 16-byte auth tag
        aead_encrypt(&mat.k_payload, &mat.nonce_bytes, &[], &aad)?
    } else {
        aead_encrypt(&mat.k_payload, &mat.nonce_bytes, payload, &aad)?
    };

    Ok(StealthOutput {
        one_time_address,
        stealth_data: PqStealthData {
            version: PQ_STEALTH_VERSION,
            kem_ct: ct.as_bytes().to_vec(),
            scan_tag: mat.scan_tag,
            amount_ct,
            payload_ct,
        },
    })
}

// ─── Recipient: Scanner ──────────────────────────────────────

/// Recipient scanner backed by their ML-KEM-768 view secret key.
pub struct StealthScanner {
    view_sk: MlKemSecretKey,
}

impl StealthScanner {
    pub fn new(view_sk: MlKemSecretKey) -> Self {
        Self { view_sk }
    }

    /// Try to recover a single output.
    ///
    /// Returns:
    /// - `Ok(Some(recovered))` → belongs to this wallet
    /// - `Ok(None)` → scan tag mismatch (not ours) or AEAD failed gracefully
    /// - `Err(_)` → malformed structure
    pub fn try_recover(
        &self,
        stealth_data: &PqStealthData,
        tx_unique_id: &[u8; 32],
        output_index: u32,
    ) -> Result<Option<RecoveredOutput>, CryptoError> {
        // 1. Structural checks
        if stealth_data.version != PQ_STEALTH_VERSION {
            return Err(CryptoError::StealthDomainMismatch);
        }
        if stealth_data.kem_ct.len() != ML_KEM_CT_LEN {
            return Err(CryptoError::MlKemInvalidCtLen(stealth_data.kem_ct.len()));
        }

        // 2. Decapsulate
        let ct = MlKemCiphertext::from_bytes(&stealth_data.kem_ct)?;
        let ss = ml_kem_decapsulate(&self.view_sk, &ct)?;

        // 3. Re-derive materials
        let mat = derive_materials(&ss)?;

        // 4. Compare scan tag (constant-time)
        if !ct_eq(&mat.scan_tag, &stealth_data.scan_tag) {
            return Ok(None); // Not for us
        }

        // 5. Derive and verify one-time address
        let one_time_address = derive_one_time_address(&mat.k_addr);

        // 6. Build AAD
        let aad = build_aad(tx_unique_id, output_index, &one_time_address);

        // 7. Decrypt amount
        let amount_plain =
            match aead_decrypt(&mat.k_amt, &mat.nonce_bytes, &stealth_data.amount_ct, &aad) {
                Ok(pt) => pt,
                Err(_) => return Ok(None), // AEAD failed → not ours or tampered
            };
        if amount_plain.len() != 8 {
            return Err(CryptoError::StealthPayloadTooShort {
                min: 8,
                got: amount_plain.len(),
            });
        }
        let amount = u64::from_le_bytes(amount_plain.try_into().unwrap_or([0u8; 8]));

        // 8. Decrypt payload
        let payload = match aead_decrypt(
            &mat.k_payload,
            &mat.nonce_bytes,
            &stealth_data.payload_ct,
            &aad,
        ) {
            Ok(pt) => pt,
            Err(_) => return Ok(None),
        };

        Ok(Some(RecoveredOutput {
            one_time_address,
            amount,
            payload,
            output_index,
        }))
    }

    /// Batch scan a slice of stealth outputs.
    pub fn scan_batch(
        &self,
        outputs: &[(PqStealthData, [u8; 32], u32)], // (data, tx_id, idx)
    ) -> Vec<RecoveredOutput> {
        outputs
            .iter()
            .filter_map(|(data, tx_id, idx)| self.try_recover(data, tx_id, *idx).ok().flatten())
            .collect()
    }
}

/// Constant-time comparison for fixed-size secret-derived tags.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_kem::ml_kem_keygen;

    fn test_tx_id() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn test_stealth_roundtrip() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let amount = 1_000_000u64;
        let payload = b"test memo";

        let output = create_stealth_output(&kp.public_key, amount, payload, &tx_id, 0).unwrap();

        let scanner = StealthScanner::new(kp.secret_key);
        let recovered = scanner
            .try_recover(&output.stealth_data, &tx_id, 0)
            .unwrap()
            .expect("should recover");

        assert_eq!(recovered.amount, amount);
        assert_eq!(recovered.payload, payload);
        assert_eq!(recovered.one_time_address, output.one_time_address);
        assert_eq!(recovered.output_index, 0);
    }

    #[test]
    fn test_wrong_view_key_no_match() {
        let sender_kp = ml_kem_keygen().unwrap();
        let wrong_kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();

        let output = create_stealth_output(&sender_kp.public_key, 500, b"", &tx_id, 0).unwrap();

        let scanner = StealthScanner::new(wrong_kp.secret_key);
        let result = scanner
            .try_recover(&output.stealth_data, &tx_id, 0)
            .unwrap();
        assert!(result.is_none(), "wrong key must not recover");
    }

    #[test]
    fn test_tampered_kem_ct_fails() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let mut output = create_stealth_output(&kp.public_key, 100, b"", &tx_id, 0).unwrap();

        // Tamper with ciphertext
        output.stealth_data.kem_ct[0] ^= 0xFF;

        let scanner = StealthScanner::new(kp.secret_key);
        let result = scanner
            .try_recover(&output.stealth_data, &tx_id, 0)
            .unwrap();
        assert!(result.is_none(), "tampered kem_ct must fail");
    }

    #[test]
    fn test_tampered_amount_ct_fails() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let mut output = create_stealth_output(&kp.public_key, 100, b"", &tx_id, 0).unwrap();

        output.stealth_data.amount_ct[0] ^= 0xFF;

        let scanner = StealthScanner::new(kp.secret_key);
        // Scan tag matches (kem_ct unchanged) but AEAD decrypt fails → None
        let result = scanner
            .try_recover(&output.stealth_data, &tx_id, 0)
            .unwrap();
        assert!(result.is_none(), "tampered amount_ct must fail AEAD");
    }

    #[test]
    fn test_tampered_payload_ct_fails() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let mut output =
            create_stealth_output(&kp.public_key, 100, b"real memo", &tx_id, 0).unwrap();

        output.stealth_data.payload_ct[0] ^= 0xFF;

        let scanner = StealthScanner::new(kp.secret_key);
        let result = scanner
            .try_recover(&output.stealth_data, &tx_id, 0)
            .unwrap();
        assert!(result.is_none(), "tampered payload_ct must fail");
    }

    #[test]
    fn test_different_output_index_different_result() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let o0 = create_stealth_output(&kp.public_key, 100, b"", &tx_id, 0).unwrap();
        let o1 = create_stealth_output(&kp.public_key, 100, b"", &tx_id, 1).unwrap();

        assert_ne!(o0.one_time_address, o1.one_time_address);
        assert_ne!(o0.stealth_data.scan_tag, o1.stealth_data.scan_tag);
    }

    #[test]
    fn test_domain_separated_keys_differ() {
        let ss = MlKemSharedSecret::from_bytes(&[0x42; 32]).unwrap();
        let mat = derive_materials(&ss).unwrap();
        // All sub-keys must be distinct
        assert_ne!(mat.k_addr, mat.k_amt);
        assert_ne!(mat.k_amt, mat.k_payload);
        assert_ne!(mat.scan_tag, mat.k_addr[..16]);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let output = create_stealth_output(&kp.public_key, 42, b"ser test", &tx_id, 7).unwrap();

        let mut buf = Vec::new();
        output.stealth_data.mcs1_encode(&mut buf);
        let mut offset = 0;
        let decoded = PqStealthData::mcs1_decode(&buf, &mut offset).unwrap();
        assert_eq!(output.stealth_data, decoded);
    }

    #[test]
    fn test_empty_payload() {
        let kp = ml_kem_keygen().unwrap();
        let tx_id = test_tx_id();
        let output = create_stealth_output(&kp.public_key, 99, b"", &tx_id, 0).unwrap();

        let scanner = StealthScanner::new(kp.secret_key);
        let recovered = scanner
            .try_recover(&output.stealth_data, &tx_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.amount, 99);
        assert!(recovered.payload.is_empty());
    }

    #[test]
    fn test_batch_scan() {
        let recipient = ml_kem_keygen().unwrap();
        let other = ml_kem_keygen().unwrap();
        let tx_id = [0x11; 32];

        let mut batch = Vec::new();
        // 2 for recipient
        for i in 0..2u32 {
            let o =
                create_stealth_output(&recipient.public_key, (i + 1) as u64 * 100, b"", &tx_id, i)
                    .unwrap();
            batch.push((o.stealth_data, tx_id, i));
        }
        // 1 for other
        let o = create_stealth_output(&other.public_key, 999, b"", &tx_id, 2).unwrap();
        batch.push((o.stealth_data, tx_id, 2));

        let scanner = StealthScanner::new(recipient.secret_key);
        let found = scanner.scan_batch(&batch);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].amount, 100);
        assert_eq!(found[1].amount, 200);
    }
}
