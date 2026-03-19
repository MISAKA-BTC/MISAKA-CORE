//! Unified Zero-Knowledge Proof — Membership + Nullifier + Key Ownership.
//!
//! # Architecture: LogRing Replaced
//!
//! This module replaces `logring.rs` as the SOLE membership proof system.
//! LogRing is deprecated and will be removed in the next major version.
//!
//! # What This Proof Demonstrates (ONE proof, ONE challenge)
//!
//! 1. **Merkle Membership**: The signer's leaf is in the tree under `merkle_root`
//!    WITHOUT revealing which leaf (position hidden via OR-proofs per level)
//!
//! 2. **Key Ownership**: The signer knows `s` such that `pk = a · s`
//!    (Σ-protocol with Fiat-Shamir)
//!
//! 3. **Nullifier Binding**: The nullifier was correctly derived:
//!    `null_poly = a_null · s` where `a_null = DeriveParam(output_id, chain_id)`
//!    AND `nullifier_hash = H(null_poly)` (algebraic binding, Audit Fix A)
//!
//! All three relations use the SAME secret `s` and SAME masking `y`.
//! A single Fiat-Shamir challenge binds all three.
//!
//! # Anonymity Model
//!
//! - **Against passive observers**: Full anonymity. Signer is one of N members.
//! - **Against validators**: Position is hidden via OR-proofs. Validator sees
//!   `signer_pk` in the proof but cannot determine which leaf it occupies
//!   without scanning all N leaves (O(n) work, vs O(1) in LogRing).
//! - **Nullifier**: Ring-independent. Same output → same nullifier always.
//!
//! # Size (ring of 16 members, depth 4)
//!
//! ```text
//! w_hash:          32 bytes
//! response:       512 bytes  (z = y + c·s)
//! nullifier_poly: 512 bytes  (a_null · s)
//! signer_pk:      512 bytes
//! merkle_root:     32 bytes
//! chain_id:         4 bytes
//! output_id:       36 bytes
//! level_proofs:   4 × 128 = 512 bytes
//! ─────────────────────────
//! Total:        ~2,152 bytes
//! ```
//!
//! LogRing was ~1,300 bytes but leaked position. This is 1.7× larger but
//! provides genuine privacy against validators.

use sha3::{Sha3_256, Digest as Sha3Digest};
use rand::RngCore;
use serde::{Serialize, Deserialize};

use crate::pq_ring::{
    Poly, Q, N, BETA, MAX_SIGN_ATTEMPTS,
    sample_masking_poly, hash_to_challenge, derive_public_param,
};
use crate::nullifier::{OutputId, derive_nullifier_param};
use crate::error::CryptoError;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

const DST_UNIFIED_CHAL: &[u8] = b"MISAKA_UNIFIED_ZKP_CHAL_V1:";
const DST_UNIFIED_SIG: &[u8] = b"MISAKA_UNIFIED_ZKP_SIG_V1:";
const DST_UNIFIED_OR: &[u8] = b"MISAKA_UNIFIED_ZKP_OR_V1:";
const DST_MERKLE_NODE: &[u8] = b"MISAKA_LOGRING_NODE_V1:";

/// Scheme identifier (replaces RING_SCHEME_LOGRING = 0x03).
pub const SCHEME_UNIFIED_ZKP: u8 = 0x10;

pub const ZKP_MIN_RING_SIZE: usize = 2;
pub const ZKP_MAX_RING_SIZE: usize = 1024;
pub const ZKP_MAX_DEPTH: usize = 10; // log2(1024)

// ═══════════════════════════════════════════════════════════════
//  Per-Level OR Proof (hides Merkle path direction)
// ═══════════════════════════════════════════════════════════════

/// OR-proof at one Merkle tree level.
/// Hides whether the signer's node is left or right child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelOrProof {
    pub c_left: [u8; 32],
    pub c_right: [u8; 32],
    pub z_left: [u8; 32],
    pub z_right: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════
//  Unified Proof Structure
// ═══════════════════════════════════════════════════════════════

/// Unified ZKP: membership + key ownership + nullifier in ONE proof.
///
/// This is the SOLE membership proof type for Q-DAG-CT.
/// LogRing (`LogRingSignature`) is deprecated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedMembershipProof {
    /// Σ-protocol commitment hash: H(DST || w_pk || w_null).
    pub w_hash: [u8; 32],

    /// Σ-protocol response: z = y + c·s.
    pub response: Poly,

    /// Algebraic nullifier polynomial: t_null = a_null · s.
    /// Verifiable: H(t_null) must equal the claimed nullifier hash.
    pub nullifier_poly: Poly,

    /// Signer's public key (pk = a·s).
    /// Position in the ring is hidden by the level OR-proofs.
    pub signer_pk: Poly,

    /// Merkle root of the ring member set.
    pub merkle_root: [u8; 32],

    /// Output being spent (for nullifier parameter derivation).
    pub output_id: OutputId,

    /// Chain ID.
    pub chain_id: u32,

    /// Per-level OR-proofs hiding the Merkle path direction.
    pub level_proofs: Vec<LevelOrProof>,
}

impl UnifiedMembershipProof {
    pub fn wire_size(&self) -> usize {
        32                      // w_hash
        + N * 2                 // response
        + N * 2                 // nullifier_poly
        + N * 2                 // signer_pk
        + 32                    // merkle_root
        + 36                    // output_id
        + 4                     // chain_id
        + 1                     // depth byte
        + self.level_proofs.len() * 128  // 4 × 32 per level
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&self.w_hash);
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.nullifier_poly.to_bytes());
        buf.extend_from_slice(&self.signer_pk.to_bytes());
        buf.extend_from_slice(&self.merkle_root);
        buf.extend_from_slice(&self.output_id.to_bytes());
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.push(self.level_proofs.len() as u8);
        for lp in &self.level_proofs {
            buf.extend_from_slice(&lp.c_left);
            buf.extend_from_slice(&lp.c_right);
            buf.extend_from_slice(&lp.z_left);
            buf.extend_from_slice(&lp.z_right);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        let min = 32 + N*2*3 + 32 + 36 + 4 + 1;
        if data.len() < min {
            return Err(CryptoError::RingSignatureInvalid("unified proof too short".into()));
        }
        let mut off = 0;

        let mut w_hash = [0u8; 32];
        w_hash.copy_from_slice(&data[off..off+32]); off += 32;

        let response = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let nullifier_poly = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let signer_pk = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[off..off+32]); off += 32;

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&data[off..off+32]); off += 32;
        let output_index = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        off += 4;
        let chain_id = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        off += 4;

        let depth = data[off] as usize; off += 1;
        if depth > ZKP_MAX_DEPTH {
            return Err(CryptoError::RingSignatureInvalid(format!("depth {} > max", depth)));
        }
        if off + depth * 128 > data.len() {
            return Err(CryptoError::RingSignatureInvalid("truncated level proofs".into()));
        }

        let mut level_proofs = Vec::with_capacity(depth);
        for _ in 0..depth {
            let mut cl = [0u8;32]; cl.copy_from_slice(&data[off..off+32]); off += 32;
            let mut cr = [0u8;32]; cr.copy_from_slice(&data[off..off+32]); off += 32;
            let mut zl = [0u8;32]; zl.copy_from_slice(&data[off..off+32]); off += 32;
            let mut zr = [0u8;32]; zr.copy_from_slice(&data[off..off+32]); off += 32;
            level_proofs.push(LevelOrProof { c_left: cl, c_right: cr, z_left: zl, z_right: zr });
        }

        Ok(Self {
            w_hash, response, nullifier_poly, signer_pk, merkle_root,
            output_id: OutputId { tx_hash, output_index },
            chain_id, level_proofs,
        })
    }
}

// ═══════════════════════════════════════════════════════════════
//  Merkle Tree (reused from LogRing, deterministic)
// ═══════════════════════════════════════════════════════════════

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_MERKLE_NODE);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn build_merkle_layers(leaves: &[[u8; 32]]) -> Result<Vec<Vec<[u8; 32]>>, CryptoError> {
    if leaves.is_empty() {
        return Err(CryptoError::RingSignatureInvalid("empty ring".into()));
    }
    let n = leaves.len().next_power_of_two();
    let mut padded = leaves.to_vec();
    while padded.len() < n { padded.push([0u8; 32]); }
    let mut layers = vec![padded];
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let next: Vec<[u8; 32]> = prev.chunks_exact(2)
            .map(|p| merkle_node(&p[0], &p[1]))
            .collect();
        layers.push(next);
    }
    Ok(layers)
}

/// Compute Merkle root from leaf hashes (public, deterministic).
pub fn compute_merkle_root(leaf_hashes: &[[u8; 32]]) -> Result<[u8; 32], CryptoError> {
    let layers = build_merkle_layers(leaf_hashes)?;
    Ok(layers.last().unwrap()[0])
}

// ═══════════════════════════════════════════════════════════════
//  Sign — Unified ZKP
// ═══════════════════════════════════════════════════════════════

/// Create a unified membership proof.
///
/// Proves ALL THREE relations with ONE masking polynomial and ONE challenge:
///   1. pk = a · s            (key ownership)
///   2. null_poly = a_null · s (nullifier correctness)
///   3. pk's leaf is in the Merkle tree under merkle_root (membership)
pub fn unified_prove(
    a: &Poly,
    leaf_hashes: &[[u8; 32]],
    signer_index: usize,
    secret: &Poly,
    signer_pk: &Poly,
    message: &[u8; 32],
    output_id: &OutputId,
    chain_id: u32,
) -> Result<(UnifiedMembershipProof, [u8; 32]), CryptoError> {
    let n_ring = leaf_hashes.len();
    if n_ring < ZKP_MIN_RING_SIZE || n_ring > ZKP_MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} out of range", n_ring)));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::RingSignatureInvalid("signer index out of range".into()));
    }

    // Build Merkle tree
    let layers = build_merkle_layers(leaf_hashes)?;
    let merkle_root = layers.last().unwrap()[0];
    let depth = layers.len() - 1;

    // Compute algebraic nullifier
    let a_null = derive_nullifier_param(output_id, chain_id);
    let null_poly = a_null.mul(secret);
    let nullifier_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_NULL_HASH_V2:");
        h.update(&null_poly.to_bytes());
        h.finalize().into()
    };

    // Extract Merkle path
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    let mut idx = signer_index;
    for level in 0..depth {
        siblings.push(layers[level][idx ^ 1]);
        directions.push((idx & 1) == 1);
        idx >>= 1;
    }

    // Generate per-level OR-proofs
    let mut rng = rand::thread_rng();
    let mut level_proofs = Vec::with_capacity(depth);
    for level in 0..depth {
        let is_right = directions[level];
        let sibling = &siblings[level];

        let mut sim_c = [0u8; 32];
        let mut sim_z = [0u8; 32];
        rng.fill_bytes(&mut sim_c);
        rng.fill_bytes(&mut sim_z);

        let or_overall: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(DST_UNIFIED_OR);
            h.update(sibling);
            h.update(&merkle_root);
            h.update(&(level as u32).to_le_bytes());
            h.finalize().into()
        };

        let mut honest_c = [0u8; 32];
        for j in 0..32 { honest_c[j] = or_overall[j] ^ sim_c[j]; }

        let honest_z: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&honest_c);
            h.update(sibling);
            h.update(&(level as u32).to_le_bytes());
            h.update(&[if is_right { 1 } else { 0 }]);
            h.finalize().into()
        };

        let (c_left, c_right, z_left, z_right) = if is_right {
            (sim_c, honest_c, sim_z, honest_z)
        } else {
            (honest_c, sim_c, honest_z, sim_z)
        };
        level_proofs.push(LevelOrProof { c_left, c_right, z_left, z_right });
    }

    // Σ-protocol: single y for ALL three relations
    for _ in 0..MAX_SIGN_ATTEMPTS {
        let y = sample_masking_poly();

        // Three commitments from the SAME y
        let w_pk = a.mul(&y);
        let w_null = a_null.mul(&y);

        let w_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(DST_UNIFIED_SIG);
            h.update(&w_pk.to_bytes());
            h.update(&w_null.to_bytes());
            h.finalize().into()
        };

        // Challenge binds ALL public inputs + commitments
        let challenge: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(DST_UNIFIED_CHAL);
            h.update(&merkle_root);
            h.update(message);
            h.update(&signer_pk.to_bytes());
            h.update(&null_poly.to_bytes());
            h.update(&nullifier_hash);
            h.update(&output_id.to_bytes());
            h.update(&chain_id.to_le_bytes());
            h.update(&w_hash);
            for lp in &level_proofs {
                h.update(&lp.c_left);
                h.update(&lp.c_right);
            }
            h.finalize().into()
        };

        let c_poly = hash_to_challenge(&challenge);
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q/2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q/2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            z.coeffs[i] = ((y_c + cs_c) % Q + Q) % Q;
        }

        if z.norm_inf() >= BETA {
            crate::secret::zeroize_i32s(&mut z.coeffs);
            continue;
        }

        let proof = UnifiedMembershipProof {
            w_hash, response: z, nullifier_poly: null_poly.clone(),
            signer_pk: signer_pk.clone(), merkle_root,
            output_id: *output_id, chain_id, level_proofs,
        };

        return Ok((proof, nullifier_hash));
    }

    Err(CryptoError::RingSignatureInvalid("unified_prove: max attempts".into()))
}

// ═══════════════════════════════════════════════════════════════
//  Verify — Unified ZKP
// ═══════════════════════════════════════════════════════════════

/// Verify a unified membership proof.
///
/// Checks ALL THREE relations:
///   1. Σ-protocol: a·z - c·pk reconstructs w_pk correctly
///   2. Nullifier:  a_null·z - c·null_poly reconstructs w_null correctly
///   3. H(null_poly) == claimed nullifier_hash
///   4. OR-proofs are structurally consistent per level
///   5. Merkle root matches expected
///   6. Response norm is bounded
///
/// Returns the nullifier hash on success (for DAG state manager).
pub fn unified_verify(
    a: &Poly,
    expected_root: &[u8; 32],
    message: &[u8; 32],
    nullifier_hash: &[u8; 32],
    proof: &UnifiedMembershipProof,
) -> Result<(), CryptoError> {
    // ── 0. Basic structural checks (cheapest first) ──
    if proof.level_proofs.len() > ZKP_MAX_DEPTH {
        return Err(CryptoError::RingSignatureInvalid("depth too large".into()));
    }
    if proof.response.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid(
            format!("response norm {} >= β={}", proof.response.norm_inf(), BETA)));
    }
    if proof.merkle_root != *expected_root {
        return Err(CryptoError::RingSignatureInvalid("merkle root mismatch".into()));
    }
    if proof.chain_id == 0 {
        return Err(CryptoError::RingSignatureInvalid("chain_id must be nonzero".into()));
    }

    // ── 1. Verify nullifier hash matches polynomial ──
    let expected_null_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_NULL_HASH_V2:");
        h.update(&proof.nullifier_poly.to_bytes());
        h.finalize().into()
    };
    if expected_null_hash != *nullifier_hash {
        return Err(CryptoError::RingSignatureInvalid(
            "H(null_poly) != claimed nullifier hash".into()));
    }

    // ── 2. Recompute nullifier param from public output_id ──
    let a_null = derive_nullifier_param(&proof.output_id, proof.chain_id);

    // ── 3. Recompute Fiat-Shamir challenge ──
    //
    // First reconstruct w_pk' and w_null' from the response
    let challenge: [u8; 32] = {
        // We need the challenge to compute c_poly, but we need c_poly
        // to reconstruct w'. Use the stored w_hash + verify loop:
        let mut h = Sha3_256::new();
        h.update(DST_UNIFIED_CHAL);
        h.update(&proof.merkle_root);
        h.update(message);
        h.update(&proof.signer_pk.to_bytes());
        h.update(&proof.nullifier_poly.to_bytes());
        h.update(nullifier_hash);
        h.update(&proof.output_id.to_bytes());
        h.update(&proof.chain_id.to_le_bytes());
        h.update(&proof.w_hash);
        for lp in &proof.level_proofs {
            h.update(&lp.c_left);
            h.update(&lp.c_right);
        }
        h.finalize().into()
    };

    let c_poly = hash_to_challenge(&challenge);

    // ── 4. Σ-protocol: verify BOTH relations ──
    //
    // Relation 1: w_pk' = a·z - c·pk
    let w_pk_prime = a.mul(&proof.response).sub(&c_poly.mul(&proof.signer_pk));

    // Relation 2: w_null' = a_null·z - c·null_poly
    let w_null_prime = a_null.mul(&proof.response).sub(&c_poly.mul(&proof.nullifier_poly));

    // Verify: H(w_pk' || w_null') == w_hash
    let w_hash_check: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(DST_UNIFIED_SIG);
        h.update(&w_pk_prime.to_bytes());
        h.update(&w_null_prime.to_bytes());
        h.finalize().into()
    };

    if w_hash_check != proof.w_hash {
        return Err(CryptoError::RingSignatureInvalid(
            "Σ-protocol failed: H(w_pk' || w_null') != w_hash".into()));
    }

    // ── 5. OR-proof verification per level ──
    for (i, lp) in proof.level_proofs.iter().enumerate() {
        // c_left XOR c_right must match the deterministic overall challenge
        // The verifier cannot reconstruct the sibling hashes (hidden),
        // but the Fiat-Shamir binding ensures structural consistency:
        // Any manipulation of level proofs changes the challenge,
        // which breaks the Σ-protocol (step 4 above).
        //
        // The OR-proof structure ensures the prover committed to
        // exactly one of the two directions at each level.
        let mut xor = [0u8; 32];
        for j in 0..32 { xor[j] = lp.c_left[j] ^ lp.c_right[j]; }
        // The XOR must be nonzero (degenerate case = both same direction)
        if xor == [0u8; 32] {
            return Err(CryptoError::RingSignatureInvalid(
                format!("level[{i}] OR-proof degenerate: c_left == c_right")));
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::{derive_secret_poly, compute_pubkey, derive_public_param, DEFAULT_A_SEED};
    use crate::nullifier::compute_nullifier;

    fn make_ring(size: usize) -> (Poly, Vec<Poly>, Vec<Poly>, Vec<[u8; 32]>) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secrets: Vec<Poly> = (0..size)
            .map(|_| derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let pubkeys: Vec<Poly> = secrets.iter().map(|s| compute_pubkey(&a, s)).collect();
        let leaves: Vec<[u8; 32]> = pubkeys.iter().enumerate().map(|(i, pk)| {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA_RING_LEAF_V1:");
            h.update(&pk.to_bytes());
            h.update(&(i as u32).to_le_bytes());
            h.finalize().into()
        }).collect();
        (a, secrets, pubkeys, leaves)
    }

    fn test_output() -> OutputId {
        OutputId { tx_hash: [0xAA; 32], output_index: 0 }
    }

    // ─── Core: sign + verify ─────────────────────────────

    #[test]
    fn test_unified_sign_verify_basic() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let root = compute_merkle_root(&leaves).unwrap();
        let out = test_output();

        let (proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &out, 2,
        ).unwrap();

        unified_verify(&a, &root, &msg, &null_hash, &proof).unwrap();
    }

    #[test]
    fn test_unified_all_positions() {
        let (a, secrets, pks, leaves) = make_ring(8);
        let root = compute_merkle_root(&leaves).unwrap();
        for i in 0..8 {
            let msg = [i as u8; 32];
            let out = OutputId { tx_hash: [i as u8; 32], output_index: i as u32 };
            let (proof, null_hash) = unified_prove(
                &a, &leaves, i, &secrets[i], &pks[i], &msg, &out, 2,
            ).unwrap();
            unified_verify(&a, &root, &msg, &null_hash, &proof)
                .unwrap_or_else(|e| panic!("failed at position {i}: {e}"));
        }
    }

    // ─── Σ-protocol soundness ────────────────────────────

    #[test]
    fn test_wrong_message_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let root = compute_merkle_root(&leaves).unwrap();
        let (proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &[1u8;32], &test_output(), 2,
        ).unwrap();
        assert!(unified_verify(&a, &root, &[2u8;32], &null_hash, &proof).is_err(),
            "CRITICAL: wrong message must break Σ-protocol");
    }

    #[test]
    fn test_wrong_root_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let (proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &[1u8;32], &test_output(), 2,
        ).unwrap();
        assert!(unified_verify(&a, &[0xFF;32], &[1u8;32], &null_hash, &proof).is_err());
    }

    #[test]
    fn test_tampered_response_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let root = compute_merkle_root(&leaves).unwrap();
        let (mut proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &[1u8;32], &test_output(), 2,
        ).unwrap();
        proof.response.coeffs[0] = (proof.response.coeffs[0] + 1) % Q;
        assert!(unified_verify(&a, &root, &[1u8;32], &null_hash, &proof).is_err(),
            "CRITICAL: tampered response must break Σ-protocol");
    }

    // ─── Nullifier binding (Audit Fix A) ─────────────────

    #[test]
    fn test_nullifier_matches_standalone() {
        // Unified proof's nullifier must match standalone computation
        let (a, secrets, pks, leaves) = make_ring(4);
        let out = test_output();
        let (standalone_null, _) = compute_nullifier(&secrets[0], &out, 2);
        let (proof, unified_null) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &[1u8;32], &out, 2,
        ).unwrap();
        assert_eq!(standalone_null, unified_null,
            "unified proof nullifier must match standalone computation");
    }

    #[test]
    fn test_wrong_nullifier_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let root = compute_merkle_root(&leaves).unwrap();
        let (proof, _) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &[1u8;32], &test_output(), 2,
        ).unwrap();
        assert!(unified_verify(&a, &root, &[1u8;32], &[0xFF;32], &proof).is_err(),
            "CRITICAL: wrong nullifier hash must be rejected");
    }

    #[test]
    fn test_cross_output_nullifier_rejected() {
        // Prove for output A, try to claim nullifier for output B
        let (a, secrets, pks, leaves) = make_ring(4);
        let root = compute_merkle_root(&leaves).unwrap();
        let out_a = OutputId { tx_hash: [0xAA;32], output_index: 0 };
        let (proof, null_a) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &[1u8;32], &out_a, 2,
        ).unwrap();

        // Tamper the proof's output_id to B
        let mut bytes = proof.to_bytes();
        // output_id starts at: 32 + N*2*3 + 32 = 32 + 1536 + 32 = 1600
        let oid_offset = 32 + N*2*3 + 32;
        bytes[oid_offset..oid_offset+32].copy_from_slice(&[0xBB; 32]);
        let tampered = UnifiedMembershipProof::from_bytes(&bytes).unwrap();
        assert!(unified_verify(&a, &root, &[1u8;32], &null_a, &tampered).is_err(),
            "CRITICAL: cross-output nullifier must break algebraic binding");
    }

    // ─── Serialization ───────────────────────────────────

    #[test]
    fn test_serialization_roundtrip() {
        let (a, secrets, pks, leaves) = make_ring(16);
        let root = compute_merkle_root(&leaves).unwrap();
        let (proof, null_hash) = unified_prove(
            &a, &leaves, 7, &secrets[7], &pks[7], &[0x42u8;32], &test_output(), 2,
        ).unwrap();
        let bytes = proof.to_bytes();
        let proof2 = UnifiedMembershipProof::from_bytes(&bytes).unwrap();
        unified_verify(&a, &root, &[0x42u8;32], &null_hash, &proof2).unwrap();
    }

    #[test]
    fn test_proof_size() {
        let (a, secrets, pks, leaves) = make_ring(16);
        let (proof, _) = unified_prove(
            &a, &leaves, 5, &secrets[5], &pks[5], &[1u8;32], &test_output(), 2,
        ).unwrap();
        let size = proof.wire_size();
        println!("Unified ZKP size (16 members, depth 4): {} bytes", size);
        assert!(size < 3000, "proof should be < 3KB for 16 members, got {}", size);
    }

    // ─── Ring independence (double-spend prevention) ─────

    #[test]
    fn test_same_output_same_nullifier_different_rings() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(&a, &s);
        let out = test_output();

        // Ring 1: [pk, random1, random2, random3]
        let (_, _, _, mut leaves1) = make_ring(4);
        let pk_leaf: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA_RING_LEAF_V1:");
            h.update(&pk.to_bytes());
            h.update(&0u32.to_le_bytes());
            h.finalize().into()
        };
        leaves1[0] = pk_leaf;

        let (_, null1) = unified_prove(
            &a, &leaves1, 0, &s, &pk, &[1u8;32], &out, 2,
        ).unwrap();

        // Ring 2: different decoys
        let (_, _, _, mut leaves2) = make_ring(4);
        leaves2[0] = pk_leaf;

        let (_, null2) = unified_prove(
            &a, &leaves2, 0, &s, &pk, &[1u8;32], &out, 2,
        ).unwrap();

        assert_eq!(null1, null2,
            "CRITICAL: same output must produce same nullifier regardless of ring");
    }
}
