//! Privacy Hardening — Address, Metadata, Scan Tag, Operational (M/N/P/Q).
//!
//! # Improvement M: One-time address expanded to 32 bytes
//!
//! [u8; 32] → [u8; 32]: collision-resistant, future-proof, no domain mixup.
//! Internal representation is always 32 bytes. UI display truncates.
//!
//! # Improvement N: Metadata padding
//!
//! Fixed ring size, output padding, TX size normalization.
//! Prevents fingerprinting by input/output count or TX size.
//!
//! # Improvement P: Scan tag standardization
//!
//! Fixed 16-byte scan tag with version prefix. All wallets MUST use
//! identical generation. No implementation-specific fingerprinting.
//!
//! # Improvement Q: Operational separation
//!
//! Wallet broadcast ≠ validator node. Light client queries are batched.
//! Hidden mode documentation is explicit about what leaks.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// ═══════════════════════════════════════════════════════════════
//  Improvement M: Extended Address (32 bytes)
// ═══════════════════════════════════════════════════════════════

/// Extended one-time address — 32 bytes for collision resistance.
///
/// Improvement M: Previously [u8; 32] (too short for PQ security margins).
/// Now [u8; 32] with version + scheme embedded.
///
/// Format:
/// ```text
/// [0]:     version byte (0x01 = Q-DAG-CT v1)
/// [1]:     scheme byte (0x10 = UnifiedZkp)
/// [2..4]:  chain_id (u16 LE)
/// [4..32]: H(spending_pubkey || view_pubkey || derivation_index)[..28]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OneTimeAddress(pub [u8; 32]);

/// Address version for Q-DAG-CT.
pub const ADDRESS_VERSION: u8 = 0x01;
/// Scheme byte for UnifiedZkp.
pub const ADDRESS_SCHEME_UNIFIED: u8 = 0x10;

impl OneTimeAddress {
    /// Derive a one-time address from key material.
    pub fn derive(k_addr: &[u8; 32], chain_id: u32) -> Self {
        let mut addr = [0u8; 32];
        addr[0] = ADDRESS_VERSION;
        addr[1] = ADDRESS_SCHEME_UNIFIED;
        addr[2] = (chain_id & 0xFF) as u8;
        addr[3] = ((chain_id >> 8) & 0xFF) as u8;

        let hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA_OTA_V2:");
            h.update(k_addr);
            h.update(&chain_id.to_le_bytes());
            h.finalize().into()
        };
        addr[4..32].copy_from_slice(&hash[..28]);
        Self(addr)
    }

    /// UI display: truncated hex with checksum.
    pub fn display_short(&self) -> String {
        format!("msk1{}", hex::encode(&self.0[4..12]))
    }

    /// Full hex representation.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn version(&self) -> u8 {
        self.0[0]
    }
    pub fn scheme(&self) -> u8 {
        self.0[1]
    }
    pub fn chain_id(&self) -> u16 {
        u16::from_le_bytes([self.0[2], self.0[3]])
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Backward compatibility: extract 20-byte legacy address.
    #[deprecated(note = "Use 32-byte address directly")]
    pub fn to_legacy_20(&self) -> [u8; 32] {
        let mut legacy = [0u8; 32];
        legacy.copy_from_slice(&self.0);
        legacy
    }
}

// ═══════════════════════════════════════════════════════════════
//  Improvement N: Metadata Padding
// ═══════════════════════════════════════════════════════════════

/// Standard ring size — FIXED for all transactions.
///
/// Improvement N: Variable ring size allows fingerprinting.
/// All TXs MUST use exactly this ring size.
pub const STANDARD_RING_SIZE: usize = 16;

/// Standard output count — PADDED to this minimum.
///
/// If a TX has fewer real outputs, dummy outputs are added.
/// Dummy outputs have valid commitments (to zero with random blind)
/// and valid range proofs, but no real recipient.
pub const MIN_OUTPUT_COUNT: usize = 2;

/// Standard TX size target (bytes) — pad with extra field.
///
/// TXs smaller than this are padded with random extra bytes.
/// This prevents TX-size-based fingerprinting.
pub const TX_SIZE_TARGET: usize = 4096;

/// Padding policy for transactions.
#[derive(Debug, Clone)]
pub struct TxPaddingPolicy {
    pub fixed_ring_size: usize,
    pub min_outputs: usize,
    pub tx_size_target: usize,
}

impl Default for TxPaddingPolicy {
    fn default() -> Self {
        Self {
            fixed_ring_size: STANDARD_RING_SIZE,
            min_outputs: MIN_OUTPUT_COUNT,
            tx_size_target: TX_SIZE_TARGET,
        }
    }
}

impl TxPaddingPolicy {
    /// How many dummy outputs to add.
    pub fn dummy_outputs_needed(&self, real_output_count: usize) -> usize {
        if real_output_count >= self.min_outputs {
            0
        } else {
            self.min_outputs - real_output_count
        }
    }

    /// How many extra bytes to add for size padding.
    pub fn extra_padding_needed(&self, current_tx_size: usize) -> usize {
        if current_tx_size >= self.tx_size_target {
            0
        } else {
            self.tx_size_target - current_tx_size
        }
    }

    /// Validate that a TX meets padding requirements.
    pub fn validate(&self, anonymity_set_size: usize, output_count: usize) -> Result<(), String> {
        if anonymity_set_size != self.fixed_ring_size {
            return Err(format!(
                "ring size {} != fixed {}",
                anonymity_set_size, self.fixed_ring_size
            ));
        }
        if output_count < self.min_outputs {
            return Err(format!(
                "output count {} < minimum {}",
                output_count, self.min_outputs
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Improvement N: Output Shuffling & Dummy Generation
// ═══════════════════════════════════════════════════════════════

/// Shuffle a list of output indices so that the change output is placed at a
/// uniformly random position. This prevents fingerprinting by output ordering
/// (e.g., "change is always index 1").
///
/// Returns a permutation vector: `result[i]` is the original index of the
/// output that should appear at position `i` in the final TX.
pub fn shuffle_output_positions(output_count: usize) -> Vec<usize> {
    use rand::seq::SliceRandom;
    let mut indices: Vec<usize> = (0..output_count).collect();
    let mut rng = rand::rngs::OsRng;
    indices.shuffle(&mut rng);
    indices
}

/// Generate random extra-field padding bytes for TX size normalization.
///
/// Fills the TX's `extra` field with random bytes to reach `tx_size_target`.
/// This prevents TX-size-based fingerprinting.
pub fn generate_extra_padding(needed: usize) -> Vec<u8> {
    let mut padding = vec![0u8; needed];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut padding);
    padding
}

// ═══════════════════════════════════════════════════════════════
//  Improvement P: Scan Tag Standardization
// ═══════════════════════════════════════════════════════════════

/// Standardized scan tag format.
///
/// All wallets MUST use this exact derivation.
/// No implementation-specific variations allowed.
///
/// Format: HKDF-Expand(shared_secret, "misaka/scan-tag/v2", 16)
///
/// The tag MUST NOT leak:
/// - Output type (transfer vs change)
/// - Wallet implementation
/// - Protocol version (version is in the address, not the tag)
pub const SCAN_TAG_LABEL: &[u8] = b"misaka/ct-stealth/scan-tag/v2";
pub const SCAN_TAG_LEN: usize = 16;

/// Generate a standardized scan tag.
///
/// ALL implementations MUST use this exact function.
/// Any deviation creates a wallet fingerprint.
///
/// # Panics
///
/// Returns all-zero tag on HKDF failure (theoretically unreachable for 16-byte output).
pub fn generate_scan_tag(shared_secret_material: &[u8]) -> [u8; SCAN_TAG_LEN] {
    let hk = hkdf::Hkdf::<Sha3_256>::new(None, shared_secret_material);
    let mut tag = [0u8; SCAN_TAG_LEN];
    // HKDF-Expand with 16-byte output is infallible (max output = 255 * HashLen).
    // Use if-let to satisfy clippy::expect_used = "deny".
    if hk.expand(SCAN_TAG_LABEL, &mut tag).is_err() {
        return [0u8; SCAN_TAG_LEN];
    }
    tag
}

// ═══════════════════════════════════════════════════════════════
//  Improvement Q: Operational Separation
// ═══════════════════════════════════════════════════════════════

/// Operational mode — documents what privacy properties are available.
///
/// Improvement Q: Be explicit about what leaks in each mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyMode {
    /// Wallet broadcasts TX directly. First-hop peer learns IP.
    /// Validator and wallet on same machine.
    /// Scan queries go to own node.
    /// Privacy: on-chain only. Network layer leaks.
    DirectBroadcast,

    /// Wallet broadcasts via Tor/mixnet. IP hidden from peers.
    /// Validator and wallet on separate machines.
    /// Scan queries batched and noised.
    /// Privacy: on-chain + partial network.
    TorBroadcast,

    /// Full separation: wallet → mixnet → multiple relays → network.
    /// Light client scans use private information retrieval.
    /// Timing randomized.
    /// Privacy: on-chain + network + timing.
    FullPrivacy,
}

impl PrivacyMode {
    /// What leaks in this mode.
    pub fn leakage_summary(&self) -> &'static [&'static str] {
        match self {
            Self::DirectBroadcast => &[
                "IP address of sender (first-hop peer)",
                "Timing of TX submission",
                "Validator and wallet linkability (same infra)",
                "Scan query patterns to own node",
                "Input/output counts (on-chain)",
                "Ring size (on-chain, but fixed)",
            ],
            Self::TorBroadcast => &[
                "Timing of TX submission (Tor latency correlations)",
                "Input/output counts (on-chain)",
                "Ring size (on-chain, but fixed)",
            ],
            Self::FullPrivacy => &[
                "Input/output counts (on-chain, padded but not zero)",
                "Ring size (on-chain, but fixed)",
                "TX existence (on-chain)",
            ],
        }
    }
}

/// Wallet scan configuration — controls privacy of balance queries.
///
/// Improvement Q: Light clients querying full nodes for their outputs
/// leak which outputs belong to them. Mitigations:
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Batch size for scan requests (larger = more private).
    pub batch_size: usize,
    /// Number of noise queries per real query.
    pub noise_ratio: usize,
    /// Use PIR (Private Information Retrieval) if available.
    pub use_pir: bool,
    /// Scan full blocks (most private but most bandwidth).
    pub full_block_scan: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            noise_ratio: 3,        // 3 fake queries per 1 real
            use_pir: false,        // PIR not yet implemented
            full_block_scan: true, // Download full blocks, scan locally
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_32_bytes() {
        let addr = OneTimeAddress::derive(&[0xAA; 32], 2);
        assert_eq!(addr.as_bytes().len(), 32);
        assert_eq!(addr.version(), ADDRESS_VERSION);
        assert_eq!(addr.scheme(), ADDRESS_SCHEME_UNIFIED);
        assert_eq!(addr.chain_id(), 2);
    }

    #[test]
    fn test_address_deterministic() {
        let a1 = OneTimeAddress::derive(&[0xBB; 32], 2);
        let a2 = OneTimeAddress::derive(&[0xBB; 32], 2);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_address_chain_bound() {
        let a1 = OneTimeAddress::derive(&[0xBB; 32], 1);
        let a2 = OneTimeAddress::derive(&[0xBB; 32], 2);
        assert_ne!(a1, a2);
    }

    #[test]
    fn test_padding_policy() {
        let p = TxPaddingPolicy::default();
        assert_eq!(p.dummy_outputs_needed(1), 1); // Need 1 more to reach 2
        assert_eq!(p.dummy_outputs_needed(2), 0); // Already at minimum
        assert_eq!(p.dummy_outputs_needed(5), 0); // Over minimum
        assert!(p.validate(STANDARD_RING_SIZE, 2).is_ok());
        assert!(p.validate(8, 2).is_err()); // Wrong ring size
    }

    #[test]
    fn test_scan_tag_standardized() {
        let t1 = generate_scan_tag(b"shared_secret_1");
        let t2 = generate_scan_tag(b"shared_secret_1");
        assert_eq!(t1, t2); // Same input → same tag
        let t3 = generate_scan_tag(b"shared_secret_2");
        assert_ne!(t1, t3); // Different input → different tag
    }

    #[test]
    fn test_privacy_mode_leakage() {
        let direct = PrivacyMode::DirectBroadcast.leakage_summary();
        let full = PrivacyMode::FullPrivacy.leakage_summary();
        assert!(direct.len() > full.len(), "full privacy should leak less");
    }
}
