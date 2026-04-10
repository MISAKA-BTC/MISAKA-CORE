//! # MISAKA Address — Unified `misaka1` Prefix with Chain-Bound Checksum
//!
//! # Address Format
//!
//! ```text
//! misaka1<40 hex chars (20 bytes)><4 hex checksum>
//! ```
//!
//! Total length: 7 ("misaka1") + 40 (address body) + 4 (checksum) = **51 chars**.
//!
//! # Design
//!
//! - **Single prefix `misaka1`** for all networks (mainnet, testnet, devnet).
//! - **Chain-bound checksum**: The 4-char checksum includes the `chain_id` in
//!   its hash preimage. An address generated on testnet (chain_id=2) will have
//!   a different checksum than the same raw bytes on mainnet (chain_id=1).
//!   Submitting a testnet address to a mainnet node fails checksum validation.
//! - **Typo detection**: The checksum catches single-character typos when
//!   users manually enter addresses.
//! - **Legacy support**: Old formats (`msk1<40hex>`, `misaka1<40hex>`) are
//!   accepted without checksum verification for backward compatibility.
//!
//! # Checksum Algorithm
//!
//! ```text
//! checksum = hex(SHA3-256("MISAKA:addr:checksum:v2:" || chain_id_le(4) || hex_body)[0..2])
//! ```
//!
//! The `chain_id` is encoded as 4-byte little-endian so that `misaka1<same hex>` on
//! mainnet and testnet produce different checksums → cross-network sends are rejected.
//!
//! # Single Source of Truth
//!
//! All RPC, API, CLI, and wallet code MUST use `encode_address()` /
//! `decode_address()` / `validate_address()` from this module.
//! No ad-hoc prefix checks (`starts_with("msk1")`) elsewhere.

use sha3::{Digest, Sha3_256};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Universal address prefix (all networks).
pub const PREFIX: &str = "misaka1";

/// Legacy testnet prefix (accepted on decode for backward compat).
pub const LEGACY_PREFIX: &str = "msk1";

/// Raw address bytes.
pub const ADDR_BYTES: usize = 32;
/// Hex chars for the address body.
pub const ADDR_HEX_LEN: usize = ADDR_BYTES * 2; // 64
/// Checksum length (hex chars).
pub const CHECKSUM_HEX_LEN: usize = 4;
/// Full address length: prefix(7) + hex(40) + checksum(4) = 51.
pub const FULL_ADDR_LEN: usize = PREFIX.len() + ADDR_HEX_LEN + CHECKSUM_HEX_LEN; // 75

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

/// Address parsing errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AddressError {
    #[error("unknown prefix (expected '{PREFIX}'): '{found}'")]
    UnknownPrefix { found: String },

    #[error("invalid length: expected {FULL_ADDR_LEN} chars, got {got}")]
    InvalidLength { got: usize },

    #[error("invalid hex in address body: {0}")]
    InvalidHex(String),

    #[error("checksum mismatch (wrong network or typo): expected {expected}, got {got}")]
    ChecksumMismatch { expected: String, got: String },
}

// ═══════════════════════════════════════════════════════════════
//  Encode
// ═══════════════════════════════════════════════════════════════

/// Encode a 20-byte address to display format.
///
/// ```text
/// misaka1<40 hex><4 checksum>  (51 chars, all networks)
/// ```
///
/// The checksum is bound to `chain_id`, so the same raw address
/// produces different display strings on different networks.
pub fn encode_address(addr: &[u8; ADDR_BYTES], chain_id: u32) -> String {
    let hex_part = hex::encode(addr);
    let checksum = compute_checksum(chain_id, &hex_part);
    format!("{}{}{}", PREFIX, hex_part, checksum)
}

// ═══════════════════════════════════════════════════════════════
//  Decode
// ═══════════════════════════════════════════════════════════════

/// Decode a display address back to 20 raw bytes.
///
/// # Arguments
///
/// - `s`: The display address string.
/// - `chain_id`: The chain_id of the current node. Used to verify the
///   chain-bound checksum. If the address was encoded on a different
///   chain_id, the checksum will not match → rejected.
///
/// # Legacy Compatibility
///
/// Accepts the following legacy formats without checksum verification:
/// - `misaka1<40 hex>` (47 chars) — old format without checksum
/// - `msk1<40 hex>` (44 chars) — old testnet format
///
/// These are silently accepted but should be migrated to the
/// checksummed format (`misaka1<40 hex><4 checksum>`, 51 chars).
pub fn decode_address(s: &str, chain_id: u32) -> Result<[u8; ADDR_BYTES], AddressError> {
    let hex_part: &str;
    let provided_checksum: Option<&str>;

    if let Some(rest) = s.strip_prefix(PREFIX) {
        match rest.len() {
            n if n == ADDR_HEX_LEN + CHECKSUM_HEX_LEN => {
                // Current format: 40 hex + 4 checksum
                hex_part = &rest[..ADDR_HEX_LEN];
                provided_checksum = Some(&rest[ADDR_HEX_LEN..]);
            }
            n if n == ADDR_HEX_LEN => {
                // Legacy: 40 hex, no checksum
                hex_part = rest;
                provided_checksum = None;
            }
            _ => {
                return Err(AddressError::InvalidLength { got: s.len() });
            }
        }
    } else if let Some(rest) = s.strip_prefix(LEGACY_PREFIX) {
        // "msk1..." — old testnet format, no checksum
        if rest.len() != ADDR_HEX_LEN {
            return Err(AddressError::InvalidLength { got: s.len() });
        }
        hex_part = rest;
        provided_checksum = None;
    } else {
        let end = s.len().min(10);
        return Err(AddressError::UnknownPrefix {
            found: s[..end].to_string(),
        });
    };

    // ── Hex decode ──
    let bytes = hex::decode(hex_part).map_err(|e| AddressError::InvalidHex(format!("{}", e)))?;
    if bytes.len() != ADDR_BYTES {
        return Err(AddressError::InvalidHex(format!(
            "expected {} bytes, got {}",
            ADDR_BYTES,
            bytes.len()
        )));
    }

    // ── Checksum verification (chain_id bound) ──
    if let Some(provided) = provided_checksum {
        let computed = compute_checksum(chain_id, hex_part);
        if computed != provided {
            return Err(AddressError::ChecksumMismatch {
                expected: computed,
                got: provided.to_string(),
            });
        }
    }

    let mut addr = [0u8; ADDR_BYTES];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Quick validation: is this string a well-formed MISAKA address
/// on the given chain?
pub fn is_valid_address(s: &str, chain_id: u32) -> bool {
    decode_address(s, chain_id).is_ok()
}

/// Validate an address string for use in RPC/API handlers.
///
/// Returns the decoded 20-byte address on success.
/// This is the **recommended entry point** for all endpoint handlers.
///
/// ```ignore
/// let addr_bytes = misaka_types::address::validate_address(&req.address, chain_id)
///     .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))))?;
/// ```
pub fn validate_address(s: &str, chain_id: u32) -> Result<[u8; ADDR_BYTES], AddressError> {
    decode_address(s, chain_id)
}

/// Format-only validation: checks prefix, hex validity, and length.
///
/// Does NOT verify the chain-bound checksum. Use this in the API proxy
/// layer where `chain_id` is not known. The upstream node will perform
/// full chain-aware validation via `validate_address()`.
///
/// Returns the decoded 20-byte address on success.
pub fn validate_format(s: &str) -> Result<[u8; ADDR_BYTES], AddressError> {
    let hex_part: &str;

    if let Some(rest) = s.strip_prefix(PREFIX) {
        match rest.len() {
            n if n == ADDR_HEX_LEN + CHECKSUM_HEX_LEN => {
                hex_part = &rest[..ADDR_HEX_LEN];
            }
            n if n == ADDR_HEX_LEN => {
                hex_part = rest;
            }
            _ => {
                return Err(AddressError::InvalidLength { got: s.len() });
            }
        }
    } else if let Some(rest) = s.strip_prefix(LEGACY_PREFIX) {
        if rest.len() != ADDR_HEX_LEN {
            return Err(AddressError::InvalidLength { got: s.len() });
        }
        hex_part = rest;
    } else {
        let end = s.len().min(10);
        return Err(AddressError::UnknownPrefix {
            found: s[..end].to_string(),
        });
    };

    let bytes = hex::decode(hex_part).map_err(|e| AddressError::InvalidHex(format!("{}", e)))?;
    if bytes.len() != ADDR_BYTES {
        return Err(AddressError::InvalidHex(format!(
            "expected {} bytes, got {}",
            ADDR_BYTES,
            bytes.len()
        )));
    }

    let mut addr = [0u8; ADDR_BYTES];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

// ═══════════════════════════════════════════════════════════════
//  Checksum (chain_id bound)
// ═══════════════════════════════════════════════════════════════

/// Compute a 4-char hex checksum bound to the chain_id.
///
/// Including `chain_id` means the same raw address bytes produce
/// a different checksum on mainnet vs testnet. This prevents
/// cross-network address reuse from going undetected.
fn compute_checksum(chain_id: u32, hex_part: &str) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:addr:checksum:v2:");
    h.update(chain_id.to_le_bytes());
    h.update(hex_part.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(&hash[..2]) // 2 bytes = 4 hex chars
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};

    fn sample_addr() -> [u8; 32] {
        [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ]
    }

    // ── Encode: always misaka1 ──

    #[test]
    fn test_encode_always_misaka1() {
        let mainnet = encode_address(&sample_addr(), MAINNET_CHAIN_ID);
        let testnet = encode_address(&sample_addr(), TESTNET_CHAIN_ID);
        let devnet = encode_address(&sample_addr(), 99);

        assert!(mainnet.starts_with("misaka1"));
        assert!(testnet.starts_with("misaka1"));
        assert!(devnet.starts_with("misaka1"));

        assert_eq!(mainnet.len(), FULL_ADDR_LEN);
        assert_eq!(testnet.len(), FULL_ADDR_LEN);
        assert_eq!(devnet.len(), FULL_ADDR_LEN);
    }

    #[test]
    fn test_same_body_different_checksum_across_chains() {
        let mainnet = encode_address(&sample_addr(), MAINNET_CHAIN_ID);
        let testnet = encode_address(&sample_addr(), TESTNET_CHAIN_ID);
        // Body (chars 7..47) is the same hex
        assert_eq!(&mainnet[7..47], &testnet[7..47]);
        // Checksum (chars 47..51) differs due to chain_id
        assert_ne!(&mainnet[47..], &testnet[47..]);
    }

    // ── Decode roundtrip ──

    #[test]
    fn test_roundtrip_mainnet() {
        let addr = sample_addr();
        let encoded = encode_address(&addr, MAINNET_CHAIN_ID);
        let decoded = decode_address(&encoded, MAINNET_CHAIN_ID).expect("valid");
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_roundtrip_testnet() {
        let addr = sample_addr();
        let encoded = encode_address(&addr, TESTNET_CHAIN_ID);
        let decoded = decode_address(&encoded, TESTNET_CHAIN_ID).expect("valid");
        assert_eq!(decoded, addr);
    }

    // ── Cross-network rejection ──

    #[test]
    fn test_mainnet_addr_rejected_on_testnet() {
        let encoded = encode_address(&sample_addr(), MAINNET_CHAIN_ID);
        let result = decode_address(&encoded, TESTNET_CHAIN_ID);
        assert!(
            matches!(result, Err(AddressError::ChecksumMismatch { .. })),
            "mainnet addr on testnet must fail: {:?}",
            result
        );
    }

    #[test]
    fn test_testnet_addr_rejected_on_mainnet() {
        let encoded = encode_address(&sample_addr(), TESTNET_CHAIN_ID);
        let result = decode_address(&encoded, MAINNET_CHAIN_ID);
        assert!(
            matches!(result, Err(AddressError::ChecksumMismatch { .. })),
            "testnet addr on mainnet must fail: {:?}",
            result
        );
    }

    // ── Legacy ──

    #[test]
    fn test_legacy_misaka1_no_checksum() {
        let hex_part = hex::encode(sample_addr());
        let legacy = format!("misaka1{}", hex_part); // 47 chars, no checksum
        let decoded = decode_address(&legacy, MAINNET_CHAIN_ID).expect("legacy accepted");
        assert_eq!(decoded, sample_addr());
    }

    #[test]
    fn test_legacy_msk1() {
        let hex_part = hex::encode(sample_addr());
        let legacy = format!("msk1{}", hex_part); // 44 chars
        let decoded = decode_address(&legacy, TESTNET_CHAIN_ID).expect("legacy msk1 accepted");
        assert_eq!(decoded, sample_addr());
    }

    // ── Checksum tamper ──

    #[test]
    fn test_checksum_tamper_detected() {
        let mut encoded = encode_address(&sample_addr(), MAINNET_CHAIN_ID);
        let last = encoded.pop().unwrap();
        encoded.push(if last == '0' { '1' } else { '0' });
        assert!(matches!(
            decode_address(&encoded, MAINNET_CHAIN_ID),
            Err(AddressError::ChecksumMismatch { .. })
        ));
    }

    // ── Invalid ──

    #[test]
    fn test_unknown_prefix() {
        assert!(matches!(
            decode_address("btc1abc", MAINNET_CHAIN_ID),
            Err(AddressError::UnknownPrefix { .. })
        ));
    }

    #[test]
    fn test_invalid_hex() {
        // 64 hex chars body + 4 checksum = 68 chars after prefix
        // 'g' is not a valid hex char, so this should fail with InvalidHex
        let bad = format!("misaka1{}{}", "g".repeat(64), "0000");
        assert!(matches!(
            decode_address(&bad, MAINNET_CHAIN_ID),
            Err(AddressError::InvalidHex(_))
        ));
    }

    #[test]
    fn test_too_short() {
        assert!(matches!(
            decode_address("misaka1abc", MAINNET_CHAIN_ID),
            Err(AddressError::InvalidLength { .. })
        ));
    }

    // ── Convenience ──

    #[test]
    fn test_is_valid() {
        let addr = encode_address(&sample_addr(), TESTNET_CHAIN_ID);
        assert!(is_valid_address(&addr, TESTNET_CHAIN_ID));
        assert!(!is_valid_address(&addr, MAINNET_CHAIN_ID)); // wrong chain
        assert!(!is_valid_address("invalid", MAINNET_CHAIN_ID));
    }

    #[test]
    fn test_deterministic() {
        let a = encode_address(&sample_addr(), MAINNET_CHAIN_ID);
        let b = encode_address(&sample_addr(), MAINNET_CHAIN_ID);
        assert_eq!(a, b);
    }
}
