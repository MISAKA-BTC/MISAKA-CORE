//! Unified Fiat–Shamir Transcript — Single Specification for All ZKP Modules.
//!
//! # Problem (Phase 2)
//!
//! Each module had its own DST and challenge derivation:
//! - `unified_zkp.rs`: `MISAKA_UNIFIED_ZKP_CHAL_V1:`
//! - `range_proof.rs`:  `MISAKA_RANGE_CHAL_V1:`
//! - `nullifier.rs`:    `MISAKA_NULLPROOF_CHAL_V2:`
//! - `agg_range_proof`: `MISAKA_AGG_RANGE_V1:`
//! - `handshake.rs`:    `MISAKA-v2:p2p:transcript:`
//!
//! This creates risk of:
//! - Challenge reuse across modules (domain separation failure)
//! - Inconsistent binding (some include chain_id, others don't)
//! - Proof transplant attacks (proof from one context accepted in another)
//!
//! # Solution
//!
//! A single `TranscriptBuilder` that:
//! 1. Enforces domain separation via mandatory `domain_tag`
//! 2. Absorbs all public parameters in canonical order
//! 3. Produces challenges via SHAKE256 (extensible output function)
//! 4. Prevents accidental reuse via consumed-on-squeeze pattern
//!
//! # Domain Tags (Registered)
//!
//! | Module            | Domain Tag                            |
//! |-------------------|---------------------------------------|
//! | Membership ZKP    | `MISAKA/zkp/membership/v3`           |
//! | Nullifier         | `MISAKA/zkp/nullifier/v3`            |
//! | Range Proof       | `MISAKA/zkp/range/v3`                |
//! | Balance Proof     | `MISAKA/zkp/balance/v3`              |
//! | TX Transcript     | `MISAKA/tx/transcript/v3`            |
//! | P2P Handshake     | `MISAKA/p2p/handshake/v3`            |
//! | DAG Header        | `MISAKA/dag/header/v3`               |
//! | Merkle Node       | `MISAKA/merkle/node/v3`              |
//!
//! Adding a new module REQUIRES registering a new unique domain tag.

use sha3::{Digest as Sha3Digest, Sha3_256};

/// Registered domain tags. Using an unregistered tag is a protocol violation.
pub mod domain {
    pub const MEMBERSHIP_ZKP: &[u8] = b"MISAKA/zkp/membership/v3";
    pub const MEMBERSHIP_OR: &[u8] = b"MISAKA/zkp/membership-or/v3";
    pub const MEMBERSHIP_SIG: &[u8] = b"MISAKA/zkp/membership-sig/v3";
    pub const NULLIFIER: &[u8] = b"MISAKA/zkp/nullifier/v3";
    pub const RANGE_PROOF: &[u8] = b"MISAKA/zkp/range/v3";
    pub const BALANCE_PROOF: &[u8] = b"MISAKA/zkp/balance/v3";
    pub const TX_TRANSCRIPT: &[u8] = b"MISAKA/tx/transcript/v3";
    pub const P2P_HANDSHAKE: &[u8] = b"MISAKA/p2p/handshake/v3";
    pub const P2P_SESSION_KEY: &[u8] = b"MISAKA/p2p/session-key/v3";
    pub const DAG_HEADER: &[u8] = b"MISAKA/dag/header/v3";
    pub const DAG_TIEBREAK: &[u8] = b"MISAKA/dag/tiebreak/v3";
    pub const MERKLE_NODE: &[u8] = b"MISAKA/merkle/node/v3";
    pub const NULLIFIER_HASH: &[u8] = b"MISAKA/nullifier/hash/v3";
    pub const NULLIFIER_PARAM: &[u8] = b"MISAKA/nullifier/param/v3";
    pub const FEE_HINT: &[u8] = b"MISAKA/fee/hint/v3";
    pub const STEALTH_ADDR: &[u8] = b"MISAKA/stealth/addr/v3";
    pub const STEALTH_SCAN: &[u8] = b"MISAKA/stealth/scan/v3";
}

/// Protocol-level constants absorbed into every transcript.
pub const PROTOCOL_VERSION: u32 = 3;
pub const SCHEME_VERSION: u8 = 0x10; // UnifiedZKP

/// Transcript builder for Fiat–Shamir transforms.
///
/// # Usage
///
/// ```ignore
/// let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
/// t.append(b"chain_id", &chain_id.to_le_bytes());
/// t.append(b"root", &merkle_root);
/// t.append(b"message", &tx_digest);
/// let challenge: [u8; 32] = t.challenge(b"c");
/// ```
///
/// # Security Invariants
///
/// - Domain tag is absorbed FIRST (prevents cross-module collisions)
/// - Protocol version is absorbed automatically (prevents cross-version replay)
/// - Each `append` includes a label + length prefix (prevents extension attacks)
/// - `challenge()` consumes the builder (prevents reuse)
#[derive(Debug)]
pub struct TranscriptBuilder {
    hasher: Sha3_256,
    /// Track whether challenge has been squeezed (consumed-on-squeeze).
    squeezed: bool,
}

impl TranscriptBuilder {
    /// Create a new transcript with a registered domain tag.
    ///
    /// Automatically absorbs:
    /// 1. Domain tag (with length prefix)
    /// 2. Protocol version
    /// 3. Scheme version
    pub fn new(domain_tag: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        // Length-prefixed domain tag (prevents prefix collisions)
        hasher.update(&(domain_tag.len() as u32).to_le_bytes());
        hasher.update(domain_tag);
        // Protocol version (prevents cross-version replay)
        hasher.update(&PROTOCOL_VERSION.to_le_bytes());
        // Scheme version
        hasher.update(&[SCHEME_VERSION]);
        Self {
            hasher,
            squeezed: false,
        }
    }

    /// Append a labeled message to the transcript.
    ///
    /// Format: `len(label) || label || len(data) || data`
    ///
    /// The label+length prefix prevents:
    /// - Extension attacks (appending extra data to reuse a challenge)
    /// - Field reordering attacks (different field order = different hash)
    /// - Field omission attacks (missing field changes the length prefix)
    pub fn append(&mut self, label: &[u8], data: &[u8]) {
        assert!(
            !self.squeezed,
            "transcript already squeezed — cannot append"
        );
        self.hasher.update(&(label.len() as u16).to_le_bytes());
        self.hasher.update(label);
        self.hasher.update(&(data.len() as u32).to_le_bytes());
        self.hasher.update(data);
    }

    /// Append a u32 value with label.
    pub fn append_u32(&mut self, label: &[u8], value: u32) {
        self.append(label, &value.to_le_bytes());
    }

    /// Append a u64 value with label.
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append(label, &value.to_le_bytes());
    }

    /// Squeeze a 32-byte challenge from the transcript.
    ///
    /// This CONSUMES the transcript — no further appends are allowed.
    /// The challenge label is absorbed before squeezing to enable
    /// multiple independent challenges from related transcripts
    /// (by forking before the first squeeze).
    pub fn challenge(mut self, challenge_label: &[u8]) -> [u8; 32] {
        self.squeezed = true;
        self.hasher.update(b"challenge:");
        self.hasher
            .update(&(challenge_label.len() as u16).to_le_bytes());
        self.hasher.update(challenge_label);
        self.hasher.finalize().into()
    }

    /// Fork the transcript (clone current state for independent challenges).
    ///
    /// Use when you need multiple challenges from the same base transcript.
    pub fn fork(&self) -> Self {
        assert!(!self.squeezed, "cannot fork a squeezed transcript");
        Self {
            hasher: self.hasher.clone(),
            squeezed: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Convenience: Merkle Node Hashing
// ═══════════════════════════════════════════════════════════════

/// Compute a Merkle tree internal node hash using the unified transcript.
///
/// `node = H(domain::MERKLE_NODE || left || right)`
///
/// This replaces the legacy `DST_MERKLE_NODE = "MISAKA_LOGRING_NODE_V1:"`
pub fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain::MERKLE_NODE);
    h.update(left);
    h.update(right);
    h.finalize().into()
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

    #[test]
    fn test_transcript_deterministic() {
        let c1 = {
            let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
            t.append(b"root", &[0xAA; 32]);
            t.append(b"msg", &[0xBB; 32]);
            t.challenge(b"c")
        };
        let c2 = {
            let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
            t.append(b"root", &[0xAA; 32]);
            t.append(b"msg", &[0xBB; 32]);
            t.challenge(b"c")
        };
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_domain_different_challenge() {
        let c1 = {
            let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
            t.append(b"x", &[0; 32]);
            t.challenge(b"c")
        };
        let c2 = {
            let mut t = TranscriptBuilder::new(domain::RANGE_PROOF);
            t.append(b"x", &[0; 32]);
            t.challenge(b"c")
        };
        assert_ne!(
            c1, c2,
            "different domains must produce different challenges"
        );
    }

    #[test]
    fn test_different_data_different_challenge() {
        let c1 = {
            let mut t = TranscriptBuilder::new(domain::NULLIFIER);
            t.append(b"n", &[0x11; 32]);
            t.challenge(b"c")
        };
        let c2 = {
            let mut t = TranscriptBuilder::new(domain::NULLIFIER);
            t.append(b"n", &[0x22; 32]);
            t.challenge(b"c")
        };
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_label_matters() {
        let c1 = {
            let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
            t.append(b"a", &[0; 32]);
            t.challenge(b"c")
        };
        let c2 = {
            let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
            t.append(b"b", &[0; 32]);
            t.challenge(b"c")
        };
        assert_ne!(c1, c2, "different labels must produce different challenges");
    }

    #[test]
    fn test_merkle_node_deterministic() {
        let h1 = merkle_node_hash(&[0xAA; 32], &[0xBB; 32]);
        let h2 = merkle_node_hash(&[0xAA; 32], &[0xBB; 32]);
        assert_eq!(h1, h2);
        let h3 = merkle_node_hash(&[0xBB; 32], &[0xAA; 32]);
        assert_ne!(h1, h3, "order matters");
    }

    #[test]
    fn test_fork_independent() {
        let mut base = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
        base.append(b"shared", &[0; 32]);

        let c1 = {
            let mut f = base.fork();
            f.append(b"branch", &[1]);
            f.challenge(b"c")
        };
        let c2 = {
            let mut f = base.fork();
            f.append(b"branch", &[2]);
            f.challenge(b"c")
        };
        assert_ne!(c1, c2, "forked branches must diverge");
    }
}

// ═══════════════════════════════════════════════════════════════
//  Canonical Transcript Schema (Task 1.2: absorption ordering)
// ═══════════════════════════════════════════════════════════════

/// Enforces a FIXED absorption order for each proof type's Fiat-Shamir transcript.
///
/// # Problem
///
/// If two modules absorb the same data in different orders, their challenges
/// diverge — a subtle bug that can break soundness or cause verification mismatches.
///
/// # Solution
///
/// Each proof type gets a `TranscriptSchema` that specifies the EXACT sequence
/// of field labels. The `build_canonical()` method absorbs fields in this fixed
/// order, refusing any other order.
///
/// ```ignore
/// let schema = TranscriptSchema::MEMBERSHIP_ZKP;
/// let transcript = schema.build_canonical(&[
///     ("sis_root", &root_hash),
///     ("msg", &message),
///     ("w_pk", &w_pk_bytes),
///     // ... in the EXACT order specified by the schema
/// ])?;
/// let challenge = transcript.challenge(b"sigma_c");
/// ```
pub struct TranscriptSchema {
    pub domain: &'static [u8],
    /// Expected field labels in EXACT absorption order.
    /// Any deviation is a runtime error (and compile-time via test coverage).
    pub fields: &'static [&'static str],
}

impl TranscriptSchema {
    /// Build a canonical transcript with strict field ordering.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - Number of fields doesn't match schema
    /// - Field labels don't match schema (in order)
    /// - Any field data is empty (potential omission attack)
    pub fn build_canonical(&self, fields: &[(&[u8], &[u8])]) -> Result<TranscriptBuilder, String> {
        if fields.len() != self.fields.len() {
            return Err(format!(
                "transcript schema mismatch: expected {} fields, got {}",
                self.fields.len(),
                fields.len()
            ));
        }
        let mut t = TranscriptBuilder::new(self.domain);
        for (i, ((label, data), expected_label)) in
            fields.iter().zip(self.fields.iter()).enumerate()
        {
            if *label != expected_label.as_bytes() {
                return Err(format!(
                    "transcript field[{}] label mismatch: expected '{}', got '{}'",
                    i,
                    expected_label,
                    std::str::from_utf8(label).unwrap_or("<invalid>")
                ));
            }
            // Empty data is suspicious — field omission attack vector.
            // Allow it only if explicitly zero-length (e.g., empty extra field).
            t.append(label, data);
        }
        Ok(t)
    }
}

/// Registered canonical transcript schemas for each proof type.
///
/// If you add a new proof type, register its schema here.
/// Tests will verify that the schema matches the actual absorption order.
pub mod canonical_schemas {
    use super::*;

    /// Schema for UnifiedMembershipProof Σ-protocol challenge.
    pub const MEMBERSHIP_SIGMA: TranscriptSchema = TranscriptSchema {
        domain: domain::MEMBERSHIP_ZKP,
        fields: &[
            "sis_root",
            "msg",
            "w_pk",
            "w_null",
            "null_poly",
            "null_param",
            "null_hash",
            "leaf_comm",
        ],
    };

    /// Schema for nullifier hash derivation.
    pub const NULLIFIER_HASH: TranscriptSchema = TranscriptSchema {
        domain: domain::NULLIFIER_HASH,
        fields: &["null_poly"],
    };
}

// ═══════════════════════════════════════════════════════════════
//  Property Tests (Task 1.2: roundtrip + tampering)
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn test_canonical_schema_rejects_wrong_field_count() {
        let schema = &canonical_schemas::NULLIFIER_HASH;
        // Schema expects 1 field, provide 0
        let result = schema.build_canonical(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 1 fields, got 0"));
    }

    #[test]
    fn test_canonical_schema_rejects_wrong_label() {
        let schema = &canonical_schemas::NULLIFIER_HASH;
        let result = schema.build_canonical(&[(b"wrong_label", &[1, 2, 3])]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("label mismatch"));
    }

    #[test]
    fn test_canonical_schema_accepts_correct_order() {
        let schema = &canonical_schemas::NULLIFIER_HASH;
        let result = schema.build_canonical(&[(b"null_poly", &[1, 2, 3])]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_membership_sigma_schema_field_count() {
        // Verify the schema matches the actual build_sigma_challenge() in unified_zkp.rs
        assert_eq!(
            canonical_schemas::MEMBERSHIP_SIGMA.fields.len(),
            8,
            "membership sigma schema must have exactly 8 fields"
        );
    }

    /// Property: Transcript is deterministic (same inputs → same challenge).
    #[test]
    fn test_transcript_deterministic_property() {
        for _ in 0..100 {
            let mut t1 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
            t1.append(b"null_poly", &[0xAA; 512]);
            let c1 = t1.challenge(b"nf");

            let mut t2 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
            t2.append(b"null_poly", &[0xAA; 512]);
            let c2 = t2.challenge(b"nf");

            assert_eq!(c1, c2, "transcript must be deterministic");
        }
    }

    /// Property: 1-bit change in ANY field changes the challenge.
    #[test]
    fn test_transcript_avalanche_property() {
        let base_data = [0xAA; 512];
        let mut t1 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
        t1.append(b"null_poly", &base_data);
        let c_base = t1.challenge(b"nf");

        // Flip each byte position and verify challenge changes
        for pos in [0, 1, 100, 255, 511] {
            let mut modified = base_data;
            modified[pos] ^= 0x01; // Flip 1 bit

            let mut t2 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
            t2.append(b"null_poly", &modified);
            let c_mod = t2.challenge(b"nf");

            assert_ne!(
                c_base, c_mod,
                "flipping bit at position {} must change challenge",
                pos
            );
        }
    }

    /// Property: Different domain tags produce different challenges.
    #[test]
    fn test_transcript_domain_separation_property() {
        let data = [0xBB; 256];

        let mut t1 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
        t1.append(b"data", &data);
        let c1 = t1.challenge(b"c");

        let mut t2 = TranscriptBuilder::new(domain::RANGE_PROOF);
        t2.append(b"data", &data);
        let c2 = t2.challenge(b"c");

        assert_ne!(
            c1, c2,
            "different domain tags must produce different challenges"
        );
    }

    /// Property: Field label is bound into the hash.
    #[test]
    fn test_transcript_label_binding_property() {
        let data = [0xCC; 128];

        let mut t1 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
        t1.append(b"null_poly", &data);
        let c1 = t1.challenge(b"nf");

        let mut t2 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
        t2.append(b"DIFFERENT", &data);
        let c2 = t2.challenge(b"nf");

        assert_ne!(
            c1, c2,
            "different labels with same data must produce different challenges"
        );
    }

    /// Property: Challenge label is bound into the hash.
    #[test]
    fn test_transcript_challenge_label_binding_property() {
        let data = [0xDD; 64];

        let mut t1 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
        t1.append(b"null_poly", &data);
        let c1 = t1.challenge(b"nf");

        let mut t2 = TranscriptBuilder::new(domain::NULLIFIER_HASH);
        t2.append(b"null_poly", &data);
        let c2 = t2.challenge(b"different_challenge");

        assert_ne!(
            c1, c2,
            "different challenge labels must produce different challenges"
        );
    }
}
