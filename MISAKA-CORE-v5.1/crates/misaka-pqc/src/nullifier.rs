//! Global Nullifier — Algebraically-Verifiable Construction (Audit Fix A).
//!
//! # Problem (Audit Finding A, CRITICAL)
//!
//! The previous NullifierProof only proved `pk = a·s` via Σ-protocol and
//! included the nullifier in the Fiat-Shamir hash. This is a COMMITMENT,
//! not a PROOF of correct derivation. A malicious prover could:
//!   1. Know `s` for `pk`
//!   2. Compute nullifier from a DIFFERENT output_id
//!   3. Pass verification because the Σ-protocol is valid for (a, pk, s)
//!
//! # Solution: Algebraic Nullifier
//!
//! Replace the hash-based nullifier with an algebraic construction
//! that is verifiable within the same Σ-protocol:
//!
//! ```text
//! a_null = DerivePublicParam(H("MISAKA_NULL_PARAM:" || output_id || chain_id))
//! nullifier_poly = a_null · s   (mod q)
//! nullifier = SHA3-256(nullifier_poly.to_bytes())
//! ```
//!
//! The proof now demonstrates TWO relations simultaneously:
//!   1. `pk = a · s`        (ring membership)
//!   2. `t_null = a_null · s` (nullifier correctness)
//!
//! Both use the SAME masking `y` and SAME secret `s`, bound by a single
//! Fiat-Shamir challenge. The verifier checks BOTH reconstructions.
//!
//! # Security Properties
//!
//! - **Soundness**: Forging requires knowing `s` — extractable from the proof
//! - **Ring-independent**: `a_null` depends on output_id, not ring_root
//! - **Output-bound**: Different output_id → different `a_null` → different nullifier
//! - **Chain-bound**: chain_id is mixed into `a_null` derivation

use sha3::{Sha3_256, Digest};
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

use crate::pq_ring::{Poly, Q, N, BETA, MAX_SIGN_ATTEMPTS,
    sample_masking_poly, hash_to_challenge, derive_public_param};
use crate::transcript::{TranscriptBuilder, domain, PROTOCOL_VERSION};
use crate::error::CryptoError;
use crate::secret::ct_eq_32;

const NULLIFIER_PARAM_DST: &[u8] = b"MISAKA_NULL_PARAM_V3:";
const NULLIFIER_CHAL_DST: &[u8] = b"MISAKA_NULLPROOF_CHAL_V3:";

// ═══════════════════════════════════════════════════════════════
//  NullifierContext — Full Context Binding (Task 2.1)
// ═══════════════════════════════════════════════════════════════

/// Domain separator for transaction types used in NullifierContext.
///
/// Each transaction domain produces a distinct nullifier parameter,
/// preventing cross-domain replay: a Transfer nullifier cannot be
/// replayed as a Governance nullifier even on the same chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxDomain {
    /// Standard value transfer
    Transfer = 0x01,
    /// Governance vote
    Governance = 0x02,
    /// Staking deposit/withdrawal
    Staking = 0x03,
    /// Bridge lock/unlock
    Bridge = 0x04,
}

impl TxDomain {
    pub fn to_byte(self) -> u8 { self as u8 }

    pub fn from_byte(b: u8) -> Result<Self, CryptoError> {
        match b {
            0x01 => Ok(Self::Transfer),
            0x02 => Ok(Self::Governance),
            0x03 => Ok(Self::Staking),
            0x04 => Ok(Self::Bridge),
            _ => Err(CryptoError::RingSignatureInvalid(
                format!("unknown TxDomain: 0x{:02X}", b))),
        }
    }
}

/// Nullifier Context — binds the nullifier derivation to the full
/// transaction environment, preventing all known replay vectors.
///
/// # Security Properties (Task 2.1)
///
/// | Field                | Prevents                                          |
/// |----------------------|---------------------------------------------------|
/// | `chain_id`           | Cross-chain replay (fork reuse)                   |
/// | `tx_domain`          | Cross-domain replay (Transfer ↔ Governance)       |
/// | `spent_output_id`    | Output rebinding (claiming wrong UTXO)            |
/// | `protocol_version`   | Version downgrade attacks                         |
/// | `anonymity_root_epoch` | Stale anonymity set replay                      |
///
/// # Integration with Fiat-Shamir
///
/// The hash of this context is absorbed into BOTH:
/// 1. The nullifier parameter derivation (`a_null = DeriveParam(H(ctx))`)
/// 2. The UnifiedMembershipProof Σ-protocol transcript
///
/// This creates a cryptographic binding between the nullifier and
/// the specific transaction context. Changing ANY field changes the
/// nullifier AND invalidates the proof.
///
/// # Why Replay Attacks Become Impossible
///
/// ## Cross-Chain Replay
/// Attacker observes TX on chain A (chain_id=1) and resubmits on chain B (chain_id=2).
/// → `NullifierContext.chain_id` differs → `a_null` differs → `null_poly = a_null·s` differs
/// → Nullifier hash differs → Fiat-Shamir challenge differs → Proof is invalid on chain B.
///
/// ## Cross-Domain Replay
/// Attacker takes a Transfer TX nullifier and tries to use it in Governance.
/// → `NullifierContext.tx_domain` differs → same chain of invalidation as above.
///
/// ## Stale Anonymity Set Replay
/// Attacker replays a TX from epoch 5 in epoch 10 (where the UTXO set has changed).
/// → `NullifierContext.anonymity_root_epoch` differs → proof invalid.
/// This prevents an attacker from mining proofs against old, smaller anonymity sets
/// and submitting them in the current epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierContext {
    /// Chain identifier (mainnet=1, testnet=2, etc.)
    pub chain_id: u32,
    /// Transaction domain (Transfer, Governance, Staking, Bridge)
    pub tx_domain: TxDomain,
    /// The output being spent
    pub spent_output_id: OutputId,
    /// Protocol version at time of proof generation
    pub protocol_version: u32,
    /// Epoch of the anonymity root used in the membership proof.
    /// This is the block height or epoch number at which the SIS
    /// Merkle root was computed.
    pub anonymity_root_epoch: u64,
}

impl NullifierContext {
    /// Fixed-size canonical serialization (53 bytes).
    ///
    /// ```text
    /// chain_id (4) + tx_domain (1) + spent_output_id (36)
    /// + protocol_version (4) + anonymity_root_epoch (8) = 53 bytes
    /// ```
    pub const WIRE_SIZE: usize = 4 + 1 + 36 + 4 + 8;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        let mut off = 0;
        buf[off..off+4].copy_from_slice(&self.chain_id.to_le_bytes()); off += 4;
        buf[off] = self.tx_domain.to_byte(); off += 1;
        buf[off..off+36].copy_from_slice(&self.spent_output_id.to_bytes()); off += 36;
        buf[off..off+4].copy_from_slice(&self.protocol_version.to_le_bytes()); off += 4;
        buf[off..off+8].copy_from_slice(&self.anonymity_root_epoch.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != Self::WIRE_SIZE {
            return Err(CryptoError::RingSignatureInvalid(
                format!("NullifierContext: expected {} bytes, got {}", Self::WIRE_SIZE, data.len())));
        }
        let mut off = 0;
        let chain_id = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]); off += 4;
        let tx_domain = TxDomain::from_byte(data[off])?; off += 1;
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&data[off..off+32]); off += 32;
        let output_index = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]); off += 4;
        let protocol_version = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]); off += 4;
        let anonymity_root_epoch = u64::from_le_bytes([
            data[off], data[off+1], data[off+2], data[off+3],
            data[off+4], data[off+5], data[off+6], data[off+7],
        ]);
        Ok(Self {
            chain_id,
            tx_domain,
            spent_output_id: OutputId { tx_hash, output_index },
            protocol_version,
            anonymity_root_epoch,
        })
    }

    /// Compute the context hash for use in nullifier parameter derivation
    /// and Fiat-Shamir transcript absorption.
    ///
    /// `H_ctx = SHA3-256(NULLIFIER_PARAM_DST || context_bytes)`
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(NULLIFIER_PARAM_DST);
        h.update(&self.to_bytes());
        h.finalize().into()
    }
}

/// Canonical nullifier hash: `H_transcript(null_poly) -> [u8; 32]`.
///
/// **CRITICAL**: This is the SINGLE source of truth for converting a nullifier
/// polynomial into a 32-byte nullifier hash. Both `NullifierProof` and
/// `UnifiedMembershipProof` MUST use this function.
///
/// Domain: `MISAKA/nullifier/hash/v3` (registered in transcript::domain).
///
/// # Why not raw SHA3?
///
/// Using `TranscriptBuilder` with a registered domain tag prevents:
/// - Cross-protocol hash collisions (e.g., a range proof hash accidentally
///   matching a nullifier hash)
/// - Domain confusion between nullifier hash and nullifier parameter derivation
pub fn canonical_nullifier_hash(null_poly: &Poly) -> [u8; 32] {
    let mut t = TranscriptBuilder::new(domain::NULLIFIER_HASH);
    t.append(b"null_poly", &null_poly.to_bytes());
    t.challenge(b"nf")
}

/// Output identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputId {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
}

impl OutputId {
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(&self.tx_hash);
        buf[32..].copy_from_slice(&self.output_index.to_le_bytes());
        buf
    }
}

/// Derive the nullifier public parameter `a_null` from output_id and chain_id.
///
/// **DEPRECATED**: Use `derive_nullifier_param_ctx` with full `NullifierContext`.
/// Retained for migration and test compatibility only.
pub fn derive_nullifier_param(output_id: &OutputId, chain_id: u32) -> Poly {
    let mut seed = [0u8; 32];
    let h = {
        let mut h = Sha3_256::new();
        h.update(NULLIFIER_PARAM_DST);
        h.update(&output_id.to_bytes());
        h.update(&chain_id.to_le_bytes());
        h.finalize()
    };
    seed.copy_from_slice(&h);
    derive_public_param(&seed)
}

/// Derive the nullifier public parameter `a_null` from full `NullifierContext`.
///
/// `a_null = DerivePublicParam(H(DST || NullifierContext.to_bytes()))`
///
/// # Why Full Context Binding (Task 2.1)
///
/// The old `derive_nullifier_param(output_id, chain_id)` only bound the nullifier
/// to the output and chain. The new version additionally binds:
/// - `tx_domain`: prevents cross-domain replay (Transfer ↔ Governance)
/// - `protocol_version`: prevents version downgrade exploitation
/// - `anonymity_root_epoch`: prevents stale anonymity set replay
///
/// All these fields flow into the seed hash, so changing ANY field
/// produces a completely different `a_null`, which means a completely
/// different nullifier polynomial `t_null = a_null · s`.
pub fn derive_nullifier_param_ctx(ctx: &NullifierContext) -> Poly {
    let seed = ctx.hash();
    derive_public_param(&seed)
}

/// Compute the algebraic nullifier using full context binding.
///
/// `nullifier = canonical_nullifier_hash(a_null · s)`
/// where `a_null = DerivePublicParam(NullifierContext.hash())`
///
/// Returns `(nullifier_hash, nullifier_poly, a_null)`.
pub fn compute_nullifier_ctx(
    secret: &Poly,
    ctx: &NullifierContext,
) -> ([u8; 32], Poly, Poly) {
    let a_null = derive_nullifier_param_ctx(ctx);
    let null_poly = a_null.mul(secret);
    let null_hash = canonical_nullifier_hash(&null_poly);
    (null_hash, null_poly, a_null)
}

/// Compute the algebraic nullifier.
///
/// `nullifier = canonical_nullifier_hash(a_null · s)`
///
/// where `a_null = DerivePublicParam(output_id, chain_id)`
///
/// This is algebraically verifiable: the verifier can check
/// `a_null · z - c · nullifier_poly` against the commitment.
///
/// # Output-bound Nullifier Property (Phase 2 Fix)
///
/// The nullifier depends ONLY on:
/// - `secret` (the spending key polynomial `s`)
/// - `output_id` (tx_hash + output_index — identifies the UTXO)
/// - `chain_id` (prevents cross-chain replay)
///
/// It does NOT depend on ring_root, ring composition, or anonymity set.
/// This means: same UTXO + same key = same nullifier, regardless of
/// which anonymity set the prover uses. Double-spend is always detected.
pub fn compute_nullifier(
    secret: &Poly,
    output_id: &OutputId,
    chain_id: u32,
) -> ([u8; 32], Poly) {
    let a_null = derive_nullifier_param(output_id, chain_id);
    let null_poly = a_null.mul(secret); // t_null = a_null · s
    let null_hash = canonical_nullifier_hash(&null_poly);
    (null_hash, null_poly)
}

/// Verify a claimed nullifier matches derivation (requires secret — testing only).
pub fn verify_nullifier(
    secret: &Poly, output_id: &OutputId, chain_id: u32,
    claimed: &[u8; 32],
) -> bool {
    let (expected, _) = compute_nullifier(secret, output_id, chain_id);
    ct_eq_32(&expected, claimed)
}

// Removed: local constant_time_eq — use crate::secret::ct_eq_32 instead.

// ═══════════════════════════════════════════════════════════════
//  NullifierProof — Dual-Relation Σ-Protocol (Audit Fix A)
// ═══════════════════════════════════════════════════════════════

/// Algebraically-bound nullifier proof.
///
/// Proves knowledge of `s` such that BOTH:
///   1. `pk = a · s`
///   2. `nullifier_poly = a_null · s`
///
/// Using the SAME `s` and SAME masking polynomial `y`.
///
/// Wire format:
///   output_id (36) + chain_id (4) + challenge (32) + response (512)
///   + nullifier_poly (512)
///   Total: 1096 bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierProof {
    pub(crate) output_id: OutputId,
    pub(crate) chain_id: u32,
    pub(crate) challenge: [u8; 32],
    pub(crate) response: Poly,
    /// The algebraic nullifier polynomial: t_null = a_null · s.
    /// This is public and verifiable.
    pub(crate) nullifier_poly: Poly,
}

impl NullifierProof {
    /// Generate a nullifier proof with dual-relation binding.
    pub fn prove(
        a: &Poly,
        secret: &Poly,
        pubkey: &Poly,
        output_id: &OutputId,
        chain_id: u32,
        nullifier: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let a_null = derive_nullifier_param(output_id, chain_id);
        let null_poly = a_null.mul(secret);

        // Verify claimed nullifier matches using canonical hash
        let expected_hash = canonical_nullifier_hash(&null_poly);
        if expected_hash != *nullifier {
            return Err(CryptoError::RingSignatureInvalid(
                "nullifier proof: claimed nullifier does not match secret derivation".into()));
        }

        for _ in 0..MAX_SIGN_ATTEMPTS {
            let y = sample_masking_poly();

            // Dual commitments from the SAME y:
            let w_pk = a.mul(&y);         // for relation 1: pk = a·s
            let w_null = a_null.mul(&y);   // for relation 2: t_null = a_null·s

            // Challenge binds BOTH relations
            let challenge: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(NULLIFIER_CHAL_DST);
                h.update(&a.to_bytes());
                h.update(&pubkey.to_bytes());
                h.update(&a_null.to_bytes());
                h.update(&null_poly.to_bytes());
                h.update(nullifier);
                h.update(&output_id.to_bytes());
                h.update(&chain_id.to_le_bytes());
                h.update(&w_pk.to_bytes());
                h.update(&w_null.to_bytes());
                h.finalize().into()
            };

            let c_poly = hash_to_challenge(&challenge);
            let cs = c_poly.mul(secret);
            let mut z = Poly::zero();
            for i in 0..N {
                let y_c = if y.coeffs[i] > Q/2 { y.coeffs[i]-Q } else { y.coeffs[i] };
                let cs_c = if cs.coeffs[i] > Q/2 { cs.coeffs[i]-Q } else { cs.coeffs[i] };
                z.coeffs[i] = ((y_c + cs_c) % Q + Q) % Q;
            }

            if z.norm_inf() >= BETA {
                zeroize_poly(&mut z);
                continue;
            }

            return Ok(Self { output_id: *output_id, chain_id, challenge, response: z, nullifier_poly: null_poly });
        }
        Err(CryptoError::RingSignatureInvalid("nullifier proof: max attempts".into()))
    }

    /// Verify the dual-relation nullifier proof (Audit Fix A).
    ///
    /// Checks BOTH:
    ///   1. `w_pk' = a·z - c·pk` reconstructs correctly (proves pk = a·s)
    ///   2. `w_null' = a_null·z - c·null_poly` reconstructs correctly (proves null_poly = a_null·s)
    ///   3. `H(null_poly) == nullifier` (binds polynomial to hash)
    ///
    /// If ANY check fails, the proof is rejected (fail-closed).
    pub fn verify(
        &self,
        a: &Poly,
        pubkey: &Poly,
        nullifier: &[u8; 32],
    ) -> Result<(), CryptoError> {
        // ── 0. Norm bound ──
        if self.response.norm_inf() >= BETA {
            return Err(CryptoError::RingSignatureInvalid("nullifier proof: norm".into()));
        }

        // ── 1. Verify nullifier hash matches polynomial ──
        let expected_hash = canonical_nullifier_hash(&self.nullifier_poly);
        if !ct_eq_32(&expected_hash, nullifier) {
            return Err(CryptoError::RingSignatureInvalid(
                "nullifier proof: H(null_poly) != claimed nullifier".into()));
        }

        // ── 2. Recompute a_null from public data ──
        let a_null = derive_nullifier_param(&self.output_id, self.chain_id);

        // ── 3. Reconstruct BOTH commitments ──
        let c_poly = hash_to_challenge(&self.challenge);

        // Relation 1: w_pk' = a·z - c·pk
        let w_pk_prime = a.mul(&self.response).sub(&c_poly.mul(pubkey));

        // Relation 2: w_null' = a_null·z - c·null_poly
        let w_null_prime = a_null.mul(&self.response).sub(&c_poly.mul(&self.nullifier_poly));

        // ── 4. Recompute challenge from BOTH reconstructed commitments ──
        let expected_challenge: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(NULLIFIER_CHAL_DST);
            h.update(&a.to_bytes());
            h.update(&pubkey.to_bytes());
            h.update(&a_null.to_bytes());
            h.update(&self.nullifier_poly.to_bytes());
            h.update(nullifier);
            h.update(&self.output_id.to_bytes());
            h.update(&self.chain_id.to_le_bytes());
            h.update(&w_pk_prime.to_bytes());
            h.update(&w_null_prime.to_bytes());
            h.finalize().into()
        };

        if !ct_eq_32(&expected_challenge, &self.challenge) {
            return Err(CryptoError::RingSignatureInvalid(
                "nullifier proof: challenge mismatch (dual-relation)".into()));
        }

        Ok(())
    }

    pub fn output_id(&self) -> &OutputId { &self.output_id }
    pub fn chain_id(&self) -> u32 { self.chain_id }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36 + 4 + 32 + N*2 + N*2);
        buf.extend_from_slice(&self.output_id.to_bytes());
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.nullifier_poly.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        let expected = 36 + 4 + 32 + N*2 + N*2;
        if data.len() != expected {
            return Err(CryptoError::RingSignatureInvalid(
                format!("nullifier proof: expected {} bytes, got {}", expected, data.len())));
        }
        let mut off = 0;
        let mut tx_hash = [0u8;32]; tx_hash.copy_from_slice(&data[off..off+32]); off+=32;
        let output_index = u32::from_le_bytes([data[off],data[off+1],data[off+2],data[off+3]]); off+=4;
        let chain_id = u32::from_le_bytes([data[off],data[off+1],data[off+2],data[off+3]]); off+=4;
        let mut challenge = [0u8;32]; challenge.copy_from_slice(&data[off..off+32]); off+=32;
        let response = Poly::from_bytes(&data[off..off+N*2])?; off+=N*2;
        let nullifier_poly = Poly::from_bytes(&data[off..off+N*2])?;
        Ok(Self {
            output_id: OutputId { tx_hash, output_index },
            chain_id, challenge, response, nullifier_poly,
        })
    }
}

/// Zeroize a polynomial (uses centralized secret::zeroize_i32s).
fn zeroize_poly(p: &mut Poly) {
    p.coeffs.zeroize();
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::{derive_secret_poly, compute_pubkey, derive_public_param, DEFAULT_A_SEED};

    fn setup() -> (Poly, Poly, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(&a, &s);
        (a, s, pk)
    }

    fn test_output() -> OutputId {
        OutputId { tx_hash: [0xAA; 32], output_index: 0 }
    }

    #[test]
    fn test_nullifier_deterministic() {
        let (_, s, _) = setup();
        let (n1, _) = compute_nullifier(&s, &test_output(), 2);
        let (n2, _) = compute_nullifier(&s, &test_output(), 2);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nullifier_ring_independent() {
        let (_, s, _) = setup();
        let out = test_output();
        let (n1, _) = compute_nullifier(&s, &out, 2);
        let (n2, _) = compute_nullifier(&s, &out, 2);
        assert_eq!(n1, n2, "same output must always produce same nullifier");
    }

    #[test]
    fn test_nullifier_output_bound() {
        let (_, s, _) = setup();
        let o1 = OutputId { tx_hash: [0xAA;32], output_index: 0 };
        let o2 = OutputId { tx_hash: [0xAA;32], output_index: 1 };
        let (n1, _) = compute_nullifier(&s, &o1, 2);
        let (n2, _) = compute_nullifier(&s, &o2, 2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_chain_bound() {
        let (_, s, _) = setup();
        let (n1, _) = compute_nullifier(&s, &test_output(), 1);
        let (n2, _) = compute_nullifier(&s, &test_output(), 2);
        assert_ne!(n1, n2);
    }

    // ─── Audit Fix A: Dual-relation proof ───────────────

    #[test]
    fn test_proof_valid() {
        let (a, s, pk) = setup();
        let out = test_output();
        let (null, _) = compute_nullifier(&s, &out, 2);
        let proof = NullifierProof::prove(&a, &s, &pk, &out, 2, &null).unwrap();
        proof.verify(&a, &pk, &null).unwrap();
    }

    #[test]
    fn test_proof_wrong_nullifier_rejected() {
        let (a, s, pk) = setup();
        let out = test_output();
        let (null, _) = compute_nullifier(&s, &out, 2);
        let proof = NullifierProof::prove(&a, &s, &pk, &out, 2, &null).unwrap();
        // Verify with wrong nullifier — MUST fail (Audit Fix A)
        assert!(proof.verify(&a, &pk, &[0xFF; 32]).is_err(),
            "AUDIT FIX A: wrong nullifier must be rejected by dual-relation check");
    }

    #[test]
    fn test_proof_wrong_pk_rejected() {
        let (a, s, pk) = setup();
        let (_, _, pk2) = setup();
        let out = test_output();
        let (null, _) = compute_nullifier(&s, &out, 2);
        let proof = NullifierProof::prove(&a, &s, &pk, &out, 2, &null).unwrap();
        assert!(proof.verify(&a, &pk2, &null).is_err(),
            "AUDIT FIX A: wrong pk must be rejected");
    }

    #[test]
    fn test_proof_cross_output_rejected() {
        // CRITICAL TEST: Prover uses s to compute nullifier for output A,
        // but tries to bind it to output B. This MUST fail.
        let (a, s, pk) = setup();
        let out_a = OutputId { tx_hash: [0xAA;32], output_index: 0 };
        let out_b = OutputId { tx_hash: [0xBB;32], output_index: 0 };
        let (null_a, _) = compute_nullifier(&s, &out_a, 2);

        // Prove for output A
        let proof = NullifierProof::prove(&a, &s, &pk, &out_a, 2, &null_a).unwrap();

        // Try to verify as if it were for output B — MUST fail
        // because a_null is derived from output_id, so the reconstruction
        // with output_b's a_null will produce wrong w_null'
        assert!(proof.verify(&a, &pk, &null_a).is_ok(), "correct proof must pass");
        // The proof carries output_id internally, so verifier sees out_a.
        // If attacker modifies the proof's output_id:
        let mut tampered = proof.to_bytes();
        tampered[0..32].copy_from_slice(&[0xBB; 32]); // change tx_hash
        let tampered_proof = NullifierProof::from_bytes(&tampered).unwrap();
        assert!(tampered_proof.verify(&a, &pk, &null_a).is_err(),
            "AUDIT FIX A: tampered output_id must break dual-relation");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (a, s, pk) = setup();
        let out = test_output();
        let (null, _) = compute_nullifier(&s, &out, 2);
        let proof = NullifierProof::prove(&a, &s, &pk, &out, 2, &null).unwrap();
        let bytes = proof.to_bytes();
        let proof2 = NullifierProof::from_bytes(&bytes).unwrap();
        proof2.verify(&a, &pk, &null).unwrap();
    }
}
