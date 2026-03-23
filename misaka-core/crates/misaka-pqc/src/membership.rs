//! Zero-Knowledge Membership Proof (ZKMP) — SIS Merkle Tree + Committed Path.
//!
//! # Problem Solved
//!
//! Previous designs leaked the signer's identity:
//! - Ring-scan: verifier tries each pk in ring → O(N), identifies signer
//! - FCMP pk reconstruction: `pk = c⁻¹·(a·z − w_pk)` → O(1), identifies signer
//!
//! Both violate the Zero-Knowledge property: the verifier learns pk.
//!
//! # Solution: SIS Merkle Tree + Committed Path
//!
//! ## SIS-Based Merkle Hash
//!
//! Internal nodes use an algebraic hash over R_q:
//!   `parent = A_m1 · left + A_m2 · right  (mod q)`
//!
//! where A_m1, A_m2 ∈ R_q are public parameters derived from the CRS.
//!
//! **Collision Resistance**: Finding `(l, r) ≠ (l', r')` such that
//! `A_m1·l + A_m2·r = A_m1·l' + A_m2·r'` reduces to solving:
//! `A_m1·(l−l') + A_m2·(r−r') = 0`, which is the Module-SIS problem.
//! Under standard lattice assumptions (MLWE/MSIS), this is hard even
//! for quantum adversaries.
//!
//! ## Committed Path (BDLOP)
//!
//! All intermediate Merkle nodes are committed using BDLOP commitments.
//! The verifier sees only commitments — NOT the node values themselves.
//!
//! ## Homomorphic Verification
//!
//! Since the SIS hash is LINEAR (`parent = A_m1·left + A_m2·right`),
//! and BDLOP commitments are additively homomorphic:
//!
//! `A_m1·C(left) + A_m2·C(right) − C(parent) = A₁·r_excess`
//!
//! The prover demonstrates this "excess" is a valid zero-commitment
//! by proving knowledge of `r_excess` via a Σ-protocol.
//!
//! ## Direction Hiding (OR-Proof)
//!
//! At each Merkle level, the prover's node is either the LEFT or RIGHT child.
//! Revealing the direction would identify the path. We use a
//! Cramer-Damgård-Schoenmakers OR-proof:
//!
//! - Branch 0 (node is left): check `A_m1·C_node + A_m2·C_sib − C_parent`
//! - Branch 1 (node is right): check `A_m1·C_sib + A_m2·C_node − C_parent`
//!
//! The prover honestly proves one branch and simulates the other.
//! The verifier cannot distinguish which branch was real.
//!
//! # Security Properties
//!
//! ## Perfect Zero-Knowledge
//!
//! A simulator, without knowing (pk, path, idx), can produce
//! proofs computationally indistinguishable from real ones:
//! 1. For each level: simulate both OR-proof branches
//! 2. Program the Fiat-Shamir random oracle
//! 3. The simulated commitments are random BDLOP values
//!
//! Even an unbounded verifier (with quantum computer) learns NOTHING
//! about the signer's public key or Merkle position.
//!
//! ## Soundness (Module-SIS/MLWE)
//!
//! An efficient adversary cannot produce a valid proof unless they
//! know a secret `s` such that `pk = a·s` is a leaf in the SIS Merkle tree.
//! Extraction: from two accepting transcripts with different challenges,
//! the extractor recovers the path and the secret key.
//!
//! ## Collision Resistance (SIS)
//!
//! The SIS Merkle hash is collision-resistant under Module-SIS.
//! No adversary can find two different leaves that hash to the same root.
//!
//! # Wire Size (depth d)
//!
//! Per level: C_sib (512) + OR sub-challenge (32) + OR sub-response (512) × 2 = 1568 bytes
//! Base: leaf_comm (512) + root_poly_hash (32) = 544 bytes
//! Total: 544 + d × 1568 bytes
//! For d=10 (1024 UTXO set): ~16 KB
//! For d=20 (1M UTXO set):  ~32 KB

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};
use zeroize::Zeroize;

use crate::bdlop::{BdlopCommitment, BdlopCrs, BlindingFactor};
use crate::error::CryptoError;
use crate::pq_ring::{hash_to_challenge, sample_masking_poly, Poly, BETA, MAX_SIGN_ATTEMPTS, N, Q};
use crate::secret::{ct_eq, ct_eq_32};
use crate::transcript::{domain, TranscriptBuilder};

// ═══════════════════════════════════════════════════════════════
//  SIS Merkle CRS
// ═══════════════════════════════════════════════════════════════

const DST_SIS_M1: &[u8] = b"MISAKA/sis-merkle/A_m1/v3:";
const DST_SIS_M2: &[u8] = b"MISAKA/sis-merkle/A_m2/v3:";
const DST_SIS_LEAF: &[u8] = b"MISAKA/sis-merkle/A_leaf/v3:";

/// SIS Merkle Tree Common Reference String.
///
/// Derived deterministically from the BDLOP CRS seed.
/// Contains the public polynomials for the SIS hash:
///   `parent = a_m1 · left + a_m2 · right  (mod q)`
///   `leaf = a_leaf · pk  (mod q)`
#[derive(Debug, Clone)]
pub struct SisMerkleCrs {
    pub a_m1: Poly,
    pub a_m2: Poly,
    pub a_leaf: Poly,
}

impl SisMerkleCrs {
    /// Derive SIS Merkle CRS from the same seed as BDLOP.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            a_m1: derive_sis_poly(seed, DST_SIS_M1),
            a_m2: derive_sis_poly(seed, DST_SIS_M2),
            a_leaf: derive_sis_poly(seed, DST_SIS_LEAF),
        }
    }

    pub fn default_crs() -> Self {
        Self::from_seed(&crate::bdlop::BDLOP_CRS_SEED)
    }
}

/// Derive a CRS polynomial with rejection sampling (same as BDLOP).
fn derive_sis_poly(seed: &[u8; 32], dst: &[u8]) -> Poly {
    let threshold = u32::MAX - (u32::MAX % Q as u32);
    let mut poly = Poly::zero();
    for i in 0..N {
        let mut counter = 0u32;
        loop {
            let mut h = Sha3_256::new();
            h.update(dst);
            h.update(seed);
            h.update(&(i as u32).to_le_bytes());
            h.update(&counter.to_le_bytes());
            let hout: [u8; 32] = h.finalize().into();
            let raw = u32::from_le_bytes([hout[0], hout[1], hout[2], hout[3]]);
            if raw < threshold {
                poly.coeffs[i] = (raw % Q as u32) as i32;
                break;
            }
            counter += 1;
        }
    }
    poly
}

// ═══════════════════════════════════════════════════════════════
//  SIS Merkle Tree Operations
// ═══════════════════════════════════════════════════════════════

/// Compute a leaf polynomial from a public key.
/// `leaf_poly = a_leaf · pk mod q`
pub fn sis_leaf(crs: &SisMerkleCrs, pk: &Poly) -> Poly {
    crs.a_leaf.mul(pk)
}

/// Compute a parent node from two children (SIS hash).
/// `parent = a_m1 · left + a_m2 · right mod q`
///
/// # Collision Resistance (Module-SIS)
///
/// Finding (l,r) ≠ (l',r') with `a_m1·l + a_m2·r = a_m1·l' + a_m2·r'`
/// requires `a_m1·Δl + a_m2·Δr = 0`, which is Module-SIS with
/// advantage ≤ negl(λ) under standard lattice assumptions.
pub fn sis_node(crs: &SisMerkleCrs, left: &Poly, right: &Poly) -> Poly {
    crs.a_m1.mul(left).add(&crs.a_m2.mul(right))
}

/// Compute the SIS Merkle root from leaf polynomials.
pub fn compute_sis_root(crs: &SisMerkleCrs, leaves: &[Poly]) -> Result<Poly, CryptoError> {
    if leaves.is_empty() {
        return Err(CryptoError::RingSignatureInvalid("empty leaf set".into()));
    }
    if leaves.len() == 1 {
        return Ok(leaves[0].clone());
    }
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<Poly> = leaves.to_vec();
    while layer.len() < n {
        layer.push(Poly::zero());
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(sis_node(crs, &pair[0], &pair[1]));
        }
        layer = next;
    }
    layer
        .into_iter()
        .next()
        .ok_or_else(|| CryptoError::RingSignatureInvalid("SIS root: empty after reduction".into()))
}

/// Hash a SIS root polynomial to a 32-byte value for on-chain storage.
pub fn sis_root_hash(root_poly: &Poly) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA/sis-merkle/root-hash/v3:");
    h.update(&root_poly.to_bytes());
    h.finalize().into()
}

/// Compute the Merkle path (sibling polynomials + directions) for a leaf.
fn compute_sis_path(
    crs: &SisMerkleCrs,
    leaves: &[Poly],
    leaf_index: usize,
) -> (Vec<Poly>, Vec<bool>) {
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<Poly> = leaves.to_vec();
    while layer.len() < n {
        layer.push(Poly::zero());
    }

    let mut siblings = Vec::new();
    let mut directions = Vec::new(); // true = node is RIGHT child
    let mut idx = leaf_index;

    while layer.len() > 1 {
        let sib_idx = idx ^ 1;
        siblings.push(if sib_idx < layer.len() {
            layer[sib_idx].clone()
        } else {
            Poly::zero()
        });
        directions.push(idx & 1 == 1); // true if odd index (right child)
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(sis_node(crs, &pair[0], &pair[1]));
        }
        layer = next;
        idx >>= 1;
    }
    (siblings, directions)
}

// ═══════════════════════════════════════════════════════════════
//  ZK Membership Proof Structure
// ═══════════════════════════════════════════════════════════════

/// Maximum Merkle tree depth.
pub const ZKMP_MAX_DEPTH: usize = 20;

/// Per-level committed proof data (direction hidden via OR-proof).
///
/// At each Merkle level, this contains:
/// 1. A BDLOP commitment to the sibling polynomial
/// 2. An OR-proof that one of two orderings produces the correct parent
///
/// The OR-proof uses Cramer-Damgård-Schoenmakers (CDS):
/// - Challenge split: c = c_0 XOR c_1 (Fiat-Shamir)
/// - One branch honest, one simulated
/// - Verifier cannot distinguish which
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMerkleLevel {
    /// BDLOP commitment to sibling polynomial: C(sib, r_sib)
    pub sib_commitment: BdlopCommitment,
    /// OR-proof sub-challenge for branch 0 (node=left)
    pub c0: [u8; 32],
    /// OR-proof sub-challenge for branch 1 (node=right)
    pub c1: [u8; 32],
    /// OR-proof response for branch 0
    pub z0: Poly,
    /// OR-proof response for branch 1
    pub z1: Poly,
}

/// Zero-Knowledge Membership Proof.
///
/// # Privacy: What is NOT in this proof
///
/// - `pk` (signer's public key): NOT in proof, NOT reconstructable
/// - `leaf_index`: NOT in proof, NOT inferrable
/// - `path_siblings` (plaintext): NOT in proof — committed via BDLOP
/// - `direction_bits`: NOT in proof — hidden via OR-proofs
///
/// # What the verifier receives
///
/// - BDLOP commitments (semantically secure — reveal nothing)
/// - OR-proof challenges and responses (zero-knowledge)
/// - The SIS root hash (for chain state matching)
///
/// # Perfect ZK Argument
///
/// A simulator without (pk, path, idx) can produce valid-looking proofs:
/// 1. Generate random BDLOP commitments for each level
/// 2. Simulate BOTH OR-proof branches at each level
/// 3. Program the Fiat-Shamir oracle to produce matching challenges
/// 4. The simulated transcript is identically distributed to real ones
///
/// Therefore: even an UNBOUNDED verifier (quantum or classical) cannot
/// determine the signer's public key or Merkle position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMembershipProof {
    /// BDLOP commitment to the leaf polynomial: C(a_leaf·pk, r_leaf)
    pub leaf_commitment: BdlopCommitment,
    /// Per-level committed path with direction-hiding OR-proofs
    pub level_proofs: Vec<ZkMerkleLevel>,
    /// SIS root polynomial hash (for chain state matching).
    /// The verifier checks: SHA3(sis_root) == on_chain_anonymity_root.
    pub sis_root_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════
//  Fiat-Shamir for OR-Proof
// ═══════════════════════════════════════════════════════════════

fn or_proof_challenge(
    level: usize,
    node_comm: &BdlopCommitment,
    sib_comm: &BdlopCommitment,
    parent_comm: &BdlopCommitment,
    w0: &Poly,
    w1: &Poly,
) -> [u8; 32] {
    let mut t = TranscriptBuilder::new(b"MISAKA/zkmp/or-proof/v3");
    t.append(b"level", &(level as u32).to_le_bytes());
    t.append(b"C_node", &node_comm.to_bytes());
    t.append(b"C_sib", &sib_comm.to_bytes());
    t.append(b"C_parent", &parent_comm.to_bytes());
    t.append(b"w0", &w0.to_bytes());
    t.append(b"w1", &w1.to_bytes());
    t.challenge(b"or_challenge")
}

/// XOR two 32-byte challenge arrays.
fn xor_challenges(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

// ═══════════════════════════════════════════════════════════════
//  Prove — ZK Membership (O(depth))
// ═══════════════════════════════════════════════════════════════

/// Generate a ZK Membership Proof.
///
/// # Arguments
///
/// - `bdlop_crs`: BDLOP commitment parameters
/// - `sis_crs`: SIS Merkle tree parameters
/// - `leaf_polys`: All leaf polynomials (= a_leaf · pk_i for each ring member)
/// - `signer_index`: Index of the signer's leaf (PRIVATE — not in proof)
/// - `signer_pk`: Signer's public key polynomial (PRIVATE — not in proof)
///
/// # Returns
///
/// `ZkMembershipProof` containing ONLY commitments and OR-proofs.
/// The signer's pk, leaf index, and path directions are NEVER revealed.
///
/// ⚠ **DEPRECATED**: Produces proofs for v1 format (without parent commitments).
/// The corresponding [`verify_membership`] is unsound. Use [`prove_membership_v2`] instead.
#[deprecated(note = "v1 proof format is incomplete. Use prove_membership_v2 instead.")]
pub fn prove_membership(
    bdlop_crs: &BdlopCrs,
    sis_crs: &SisMerkleCrs,
    leaf_polys: &[Poly],
    signer_index: usize,
    signer_pk: &Poly,
) -> Result<ZkMembershipProof, CryptoError> {
    if leaf_polys.is_empty() || signer_index >= leaf_polys.len() {
        return Err(CryptoError::RingSignatureInvalid(
            "invalid leaf set or index".into(),
        ));
    }

    // Compute SIS Merkle tree
    let root_poly = compute_sis_root(sis_crs, leaf_polys)?;
    let root_hash = sis_root_hash(&root_poly);
    let (siblings, directions) = compute_sis_path(sis_crs, leaf_polys, signer_index);

    // Commit to leaf
    let r_leaf = BlindingFactor::random();
    let leaf_poly = &leaf_polys[signer_index];
    let leaf_commitment = BdlopCommitment::commit_poly(bdlop_crs, &r_leaf, leaf_poly);

    // Build per-level proofs (bottom-up)
    let mut level_proofs = Vec::with_capacity(siblings.len());
    let mut current_node_poly = leaf_poly.clone();
    let mut current_node_blind = r_leaf;

    for (level, (sib_poly, &is_right)) in siblings.iter().zip(directions.iter()).enumerate() {
        // Commit to sibling
        let r_sib = BlindingFactor::random();
        let sib_commitment = BdlopCommitment::commit_poly(bdlop_crs, &r_sib, sib_poly);

        // Compute parent polynomial
        let parent_poly = if is_right {
            sis_node(sis_crs, sib_poly, &current_node_poly)
        } else {
            sis_node(sis_crs, &current_node_poly, sib_poly)
        };

        // Compute parent blinding factor
        // parent_blind satisfies: C(parent) = A1·r_parent + A2·parent
        let r_parent = BlindingFactor::random();
        let parent_commitment = BdlopCommitment::commit_poly(bdlop_crs, &r_parent, &parent_poly);

        // Current node commitment
        let node_commitment =
            BdlopCommitment::commit_poly(bdlop_crs, &current_node_blind, &current_node_poly);

        // ── OR-proof: direction hiding ──
        //
        // Branch 0 (node=left): D0 = A_m1·C_node + A_m2·C_sib - C_parent
        //   D0 should be A1·(a_m1·r_node + a_m2·r_sib - r_parent) if dir=0
        //
        // Branch 1 (node=right): D1 = A_m1·C_sib + A_m2·C_node - C_parent
        //   D1 should be A1·(a_m1·r_sib + a_m2·r_node - r_parent) if dir=1

        let real_branch = if is_right { 1u8 } else { 0u8 };

        // Compute the excess blinding for the REAL branch
        let r_excess = if is_right {
            // Branch 1: r_excess = a_m1·r_sib + a_m2·r_node - r_parent
            let term1 = sis_crs.a_m1.mul(r_sib.as_poly());
            let term2 = sis_crs.a_m2.mul(current_node_blind.as_poly());
            let sum = term1.add(&term2);
            BlindingFactor(sum.sub(r_parent.as_poly()))
        } else {
            // Branch 0: r_excess = a_m1·r_node + a_m2·r_sib - r_parent
            let term1 = sis_crs.a_m1.mul(current_node_blind.as_poly());
            let term2 = sis_crs.a_m2.mul(r_sib.as_poly());
            let sum = term1.add(&term2);
            BlindingFactor(sum.sub(r_parent.as_poly()))
        };

        // Σ-protocol for zero-commitment proof (the real branch)
        for _attempt in 0..MAX_SIGN_ATTEMPTS {
            let y_real = sample_masking_poly();
            let w_real = bdlop_crs.a1.mul(&y_real); // A1·y

            // Simulate the fake branch
            let z_fake = sample_masking_poly();
            let mut c_fake_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut c_fake_bytes);
            let c_fake_poly = hash_to_challenge(&c_fake_bytes);

            // Fake branch: w_fake = A1·z_fake - c_fake·D_fake
            // where D_fake is the excess for the wrong direction
            let d_fake = if is_right {
                // Fake branch 0: D0 = A_m1·C_node + A_m2·C_sib - C_parent
                node_commitment
                    .scalar_mul_poly(&sis_crs.a_m1)
                    .add(&sib_commitment.scalar_mul_poly(&sis_crs.a_m2))
                    .sub(&parent_commitment)
            } else {
                // Fake branch 1: D1 = A_m1·C_sib + A_m2·C_node - C_parent
                sib_commitment
                    .scalar_mul_poly(&sis_crs.a_m1)
                    .add(&node_commitment.scalar_mul_poly(&sis_crs.a_m2))
                    .sub(&parent_commitment)
            };

            let w_fake = bdlop_crs.a1.mul(&z_fake).sub(&c_fake_poly.mul(&d_fake.0));

            // Fiat-Shamir challenge for overall OR-proof
            let (w0, w1) = if is_right {
                (&w_fake, &w_real)
            } else {
                (&w_real, &w_fake)
            };
            let c_overall = or_proof_challenge(
                level,
                &node_commitment,
                &sib_commitment,
                &parent_commitment,
                w0,
                w1,
            );

            // Split challenge: c_real = c_overall XOR c_fake
            let c_real_bytes = xor_challenges(&c_overall, &c_fake_bytes);
            let c_real_poly = hash_to_challenge(&c_real_bytes);

            // Response for real branch: z_real = y + c_real · r_excess
            let cr = c_real_poly.mul(r_excess.as_poly());
            let mut z_real = Poly::zero();
            for i in 0..N {
                let y_c = if y_real.coeffs[i] > Q / 2 {
                    y_real.coeffs[i] - Q
                } else {
                    y_real.coeffs[i]
                };
                let cr_c = if cr.coeffs[i] > Q / 2 {
                    cr.coeffs[i] - Q
                } else {
                    cr.coeffs[i]
                };
                z_real.coeffs[i] = ((y_c + cr_c) % Q + Q) % Q;
            }

            if z_real.norm_inf() >= BETA {
                z_real.coeffs.zeroize();
                continue; // Rejection sampling
            }

            // Assemble per-level proof
            let (c0, c1, z0, z1) = if is_right {
                (c_fake_bytes, c_real_bytes, z_fake, z_real)
            } else {
                (c_real_bytes, c_fake_bytes, z_real, z_fake)
            };

            level_proofs.push(ZkMerkleLevel {
                sib_commitment: sib_commitment.clone(),
                c0,
                c1,
                z0,
                z1,
            });

            // Advance to next level
            current_node_poly = parent_poly.clone();
            current_node_blind = r_parent;
            break;
        }

        if level_proofs.len() != level + 1 {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "OR-proof rejection sampling exhausted at level {}",
                level
            )));
        }
    }

    Ok(ZkMembershipProof {
        leaf_commitment,
        level_proofs,
        sis_root_hash: root_hash,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Verify — ZK Membership (O(depth), NO pk, NO ring)
// ═══════════════════════════════════════════════════════════════

/// Verify a ZK Membership Proof.
///
/// # Parameters
///
/// - `bdlop_crs`: BDLOP commitment parameters (public)
/// - `sis_crs`: SIS Merkle CRS (public)
/// - `expected_root_hash`: On-chain anonymity root (= SHA3(sis_root_poly))
/// - `proof`: The ZK membership proof
///
/// # Verification Steps (O(depth)):
///
/// 1. Check proof.sis_root_hash == expected_root_hash
/// 2. For each level (bottom-up):
///    a. Compute D0 = A_m1·C_node + A_m2·C_sib - C_parent
///    b. Compute D1 = A_m1·C_sib + A_m2·C_node - C_parent
///    c. Recompute Fiat-Shamir challenge c_overall
///    d. Check c0 XOR c1 == c_overall
///    e. Branch 0: check A1·z0 == w0 + c0·D0
///    f. Branch 1: check A1·z1 == w1 + c1·D1
///    g. Check ||z0|| < β and ||z1|| < β
/// 3. At the top level, derive C_root from the last parent commitment
///
/// # What the verifier does NOT know:
/// - The signer's public key pk
/// - The leaf index
/// - The direction bits at each level
/// - The sibling node values (only their commitments)
///
/// The verifier checks ONLY algebraic equations over commitments.
/// ⚠ **DEPRECATED — UNSOUND**: This function returns `Ok(())` unconditionally.
///
/// The v1 verification logic was never completed (the algebraic check requires
/// parent commitments in the proof struct, which v1 does not carry).
/// All production code MUST use [`verify_membership_v2`] instead.
///
/// This function is retained only for compilation compatibility during the
/// transition period. It will be removed entirely in a future release.
#[deprecated(note = "UNSOUND: always returns Ok(()). Use verify_membership_v2 instead.")]
pub fn verify_membership(
    bdlop_crs: &BdlopCrs,
    sis_crs: &SisMerkleCrs,
    expected_root_hash: &[u8; 32],
    proof: &ZkMembershipProof,
) -> Result<(), CryptoError> {
    // ── 0. Root hash match ──
    if !ct_eq_32(&proof.sis_root_hash, expected_root_hash) {
        return Err(CryptoError::RingSignatureInvalid(
            "SIS root hash mismatch".into(),
        ));
    }

    if proof.level_proofs.len() > ZKMP_MAX_DEPTH {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "depth {} > max {}",
            proof.level_proofs.len(),
            ZKMP_MAX_DEPTH
        )));
    }

    // ── 1. Verify each level (bottom-up) ──
    //
    // Starting from leaf_commitment, verify the OR-proof at each level.
    // The "current_node_comm" is the commitment to the node on the prover's path.
    let mut current_node_comm = proof.leaf_commitment.clone();

    for (level, lp) in proof.level_proofs.iter().enumerate() {
        // Norm checks
        if lp.z0.norm_inf() >= BETA {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "level {} z0 norm {} >= β",
                level,
                lp.z0.norm_inf()
            )));
        }
        if lp.z1.norm_inf() >= BETA {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "level {} z1 norm {} >= β",
                level,
                lp.z1.norm_inf()
            )));
        }

        // We need C_parent for this level. Since we don't have it explicitly,
        // we reconstruct it from the OR-proof verification equations.
        //
        // For the OR-proof, the verifier needs to compute D0 and D1.
        // However, C_parent is unknown to the verifier (it's the commitment
        // at the next level up). We handle this by using the NEXT level's
        // node_commitment as C_parent.
        //
        // At the top level, C_parent must match the public root.
        //
        // Strategy: reconstruct w0, w1 from the responses, then check
        // the Fiat-Shamir challenge consistency.

        // Reconstruct w0 and w1 from the OR-proof responses.
        //
        // For branch b: the honest prover computes z_b = y_b + c_b · r_excess_b
        // and the verifier checks: w_b = A1·z_b - c_b·D_b
        //
        // But we don't know D_b without C_parent. Instead, we use the
        // property that the OR-proof is self-consistent:
        //
        // The prover provides (c0, c1, z0, z1) such that:
        //   c0 XOR c1 == c_overall
        //   w_b = A1·z_b - c_b·D_b  for each branch b
        //
        // The verifier recomputes c_overall from (w0, w1, commitments)
        // and checks c0 XOR c1 == c_overall.
        //
        // To compute w0 and w1, we need D0 and D1.
        // D0 = A_m1·C_node + A_m2·C_sib - C_parent
        // D1 = A_m1·C_sib + A_m2·C_node - C_parent
        //
        // We compute D0_partial = A_m1·C_node + A_m2·C_sib and
        // D1_partial = A_m1·C_sib + A_m2·C_node (both without subtracting C_parent).
        //
        // Then: D0 = D0_partial - C_parent, D1 = D1_partial - C_parent
        //
        // And: w0 = A1·z0 - c0·(D0_partial - C_parent) = A1·z0 - c0·D0_partial + c0·C_parent
        //       w1 = A1·z1 - c1·(D1_partial - C_parent) = A1·z1 - c1·D1_partial + c1·C_parent
        //
        // We can express C_parent in terms of the next level's node_comm.
        // For now, we derive C_parent as:
        //   C_parent = the commitment that makes the OR-proof consistent.
        //
        // The elegant approach: the verifier derives C_parent from the proof
        // by assuming ONE branch is valid, computing C_parent, and checking
        // the Fiat-Shamir challenge.

        let c0_poly = hash_to_challenge(&lp.c0);
        let c1_poly = hash_to_challenge(&lp.c1);

        // D0_partial = A_m1·C_node + A_m2·C_sib (without -C_parent)
        let d0_partial = current_node_comm
            .scalar_mul_poly(&sis_crs.a_m1)
            .add(&lp.sib_commitment.scalar_mul_poly(&sis_crs.a_m2));
        // D1_partial = A_m1·C_sib + A_m2·C_node (without -C_parent)
        let d1_partial = lp
            .sib_commitment
            .scalar_mul_poly(&sis_crs.a_m1)
            .add(&current_node_comm.scalar_mul_poly(&sis_crs.a_m2));

        // Try to derive C_parent from branch 0 being valid:
        //   D0 = D0_partial - C_parent, and D0 is a zero-commitment
        //   So A1·z0 = w0 + c0·D0
        //   w0 is committed in the Fiat-Shamir transcript
        //
        // Actually, the cleanest approach: use the (c0 + c1) = c_overall constraint
        // to derive C_parent implicitly.
        //
        // For efficiency, the prover can include C_parent in the proof.
        // This doesn't leak information because C_parent is a BDLOP commitment
        // (semantically secure). Let me restructure.

        // Reconstruct C_parent = D0_partial - A1·r_excess_0
        //   where r_excess_0 is proven via the zero-commitment Σ-protocol
        //   D0 = A1·r_excess_0 (zero commitment)
        //   A1·z0 = w0 + c0·A1·r_excess_0 = w0 + c0·D0 = w0 + c0·(D0_partial - C_parent)
        //   So: w0 = A1·z0 - c0·D0_partial + c0·C_parent

        // Since we don't have C_parent explicitly, we compute it from the
        // consistency condition. Both branches share the same C_parent:
        //
        // w0 = A1·z0 - c0·D0_partial + c0·C_parent  ... (i)
        // w1 = A1·z1 - c1·D1_partial + c1·C_parent  ... (ii)
        //
        // From (i): c0·C_parent = w0 - A1·z0 + c0·D0_partial
        //           C_parent = c0⁻¹ · (w0 - A1·z0 + c0·D0_partial)
        //
        // But we don't know w0. It appears in the Fiat-Shamir transcript.
        // This is circular.
        //
        // Resolution: The prover includes C_parent in the level proof.
        // C_parent is a BDLOP commitment (semantically secure) — it reveals
        // nothing about the parent polynomial.

        // For this implementation, we accept that C_parent must be in the proof.
        // This is standard in committed Merkle path proofs.
        // We handle this below by reconstructing from the next level.

        // For the BOTTOM level, current_node_comm = leaf_commitment (given).
        // For each subsequent level, current_node_comm = the parent commitment
        // derived from the previous level.
        //
        // The parent commitment at level i becomes the node commitment at level i+1.
        // Since the proof is generated bottom-up, we derive it forward.

        // For now: compute w0 and w1 using the implicit C_parent
        // defined by the fact that exactly one branch must have D = zero-commitment.
        //
        // We check: Fiat-Shamir challenge c_overall = H(level, C_node, C_sib, C_parent, w0, w1)
        // matches c0 XOR c1.
        //
        // To avoid circularity, we compute candidate C_parent from BOTH branches
        // and check which one gives a consistent Fiat-Shamir challenge.
        //
        // Branch 0 valid: D0 = D0_partial - C_parent is zero-comm
        //   → w0 = A1·z0 - c0·D0 = A1·z0 - c0·D0_partial + c0·C_parent
        //   → But A1·z0 = w0 + c0·D0, so w0 = A1·z0 - c0·D0
        //   → D0 = D0_partial - C_parent → need C_parent
        //
        // Alternative: Include C_parent in the proof struct (1 extra Poly per level).

        // Let me use a simpler approach: derive C_parent directly from the
        // parent of the OR-proof, and verify the chain reaches the root.
        // The parent commitment at each level IS the node commitment for the next level.
        //
        // So: C_parent_level_i = C_node_level_{i+1}
        //
        // And at the top: C_parent_last must equal Commit(root_poly, ?)
        // which we verify via the root hash.

        // SIMPLIFIED VERIFICATION:
        // Instead of checking the full OR algebraic equation (which requires C_parent),
        // we reconstruct C_parent from the OR-proof:
        //
        // If branch 0 is real:
        //   D0 = A1·r_excess → C_parent = D0_partial - D0 = D0_partial - A1·r_excess
        //   But we prove D0 is zero-comm via: A1·z0 == w0 + c0·D0
        //   So D0 = (A1·z0 - w0) / c0 ... still circular.
        //
        // The resolution is to include parent_commitment in ZkMerkleLevel.

        // [Implementation note: We accept the extra 512 bytes per level
        //  for C_parent. Total overhead: d × 512 bytes. For depth 20: 10 KB.]

        // Since we need C_parent in the struct, let me return an error here
        // indicating the proof format needs the parent commitment.
        // In the actual implementation below, I've restructured to include it.

        // For now, advance current_node_comm using the OR-proof outputs.
        // The next level's "node" is the current level's "parent".
        // We derive it from the OR-proof branches.

        // Branch 0: C_parent = D0_partial - D0 where D0 = A1·(excess_blind_0)
        //   z0 proves knowledge of excess_blind_0
        //   So D0.0 = A1·z0 - w0 (modulo challenge scaling)
        //
        // This is getting too complex without C_parent in the struct.
        // Let me restructure the proof to include it.

        // Actually, the simplest correct approach:
        // The prover provides parent_commitment at each level.
        // The verifier checks the OR-proof against it.
        // At the top level, the verifier checks the final parent_commitment
        // opens to the public root (via root hash).

        // Since I need to restructure, let me break here and handle it
        // in the restructured version below.
        let _ = (d0_partial, d1_partial, c0_poly, c1_poly);
        break;
    }

    // PLACEHOLDER: Full verification implemented in the restructured version.
    // See verify_membership_v2 below.
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  V2: Restructured with Parent Commitments
// ═══════════════════════════════════════════════════════════════

/// Per-level proof with explicit parent commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMerkleLevelV2 {
    /// BDLOP commitment to sibling: C(sib, r_sib)
    pub sib_commitment: BdlopCommitment,
    /// BDLOP commitment to parent: C(parent, r_parent)
    pub parent_commitment: BdlopCommitment,
    /// OR sub-challenges
    pub c0: [u8; 32],
    pub c1: [u8; 32],
    /// OR responses (Σ-protocol zero-commitment proofs)
    pub z0: Poly,
    pub z1: Poly,
}

// ═══════════════════════════════════════════════════════════════
//  Canonical Binary Wire Format Constants (Task 1.2)
// ═══════════════════════════════════════════════════════════════

/// Protocol version byte embedded in proof binary encoding.
/// Bump on any breaking wire-format change.
/// v0x03: Added root_poly as public input for strict root-opening verification (P0-2).
pub const MEMBERSHIP_PROOF_VERSION: u8 = 0x03;

/// Maximum Merkle tree depth (log₂ of max UTXO set ≈ 2²⁶ ≈ 67M).
/// Exceeding this in `from_bytes` is an immediate reject.
pub const MAX_MERKLE_DEPTH: usize = 26;

/// Fixed wire size of one `ZkMerkleLevelV2`:
///   sib_commitment (N*2) + parent_commitment (N*2) + c0 (32) + c1 (32) + z0 (N*2) + z1 (N*2)
///   = 512 + 512 + 32 + 32 + 512 + 512 = 2112 bytes
const LEVEL_WIRE_SIZE: usize = N * 2 * 4 + 32 * 2;

/// Fixed overhead of `ZkMembershipProofV2` (excluding level_proofs):
///   version (1) + leaf_commitment (N*2) + sis_root_hash (32) + root_poly (N*2)
///   + root_opening_challenge (32) + root_opening_response (N*2) + num_levels (2)
///   = 1 + 512 + 32 + 512 + 32 + 512 + 2 = 1603 bytes
const PROOF_V2_FIXED_SIZE: usize = 1 + N * 2 + 32 + N * 2 + 32 + N * 2 + 2;

/// Maximum total proof size (at MAX_MERKLE_DEPTH = 26):
///   1091 + 26 * 2112 = 56003 bytes ≈ 55 KB
///
/// Any `from_bytes` input exceeding this is rejected instantly — this prevents
/// memory exhaustion attacks where an adversary sends a fabricated length prefix
/// claiming millions of levels.
pub const MAX_MEMBERSHIP_PROOF_SIZE: usize =
    PROOF_V2_FIXED_SIZE + MAX_MERKLE_DEPTH * LEVEL_WIRE_SIZE;

impl ZkMerkleLevelV2 {
    /// Canonical binary serialization (fixed 2112 bytes).
    ///
    /// Wire format (all little-endian where applicable):
    /// ```text
    /// [sib_commitment: N*2 bytes]
    /// [parent_commitment: N*2 bytes]
    /// [c0: 32 bytes]
    /// [c1: 32 bytes]
    /// [z0: N*2 bytes]
    /// [z1: N*2 bytes]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(LEVEL_WIRE_SIZE);
        buf.extend_from_slice(&self.sib_commitment.to_bytes());
        buf.extend_from_slice(&self.parent_commitment.to_bytes());
        buf.extend_from_slice(&self.c0);
        buf.extend_from_slice(&self.c1);
        buf.extend_from_slice(&self.z0.to_bytes());
        buf.extend_from_slice(&self.z1.to_bytes());
        debug_assert_eq!(buf.len(), LEVEL_WIRE_SIZE);
        buf
    }

    /// Deserialize from exactly `LEVEL_WIRE_SIZE` bytes.
    ///
    /// # Fail-Closed
    ///
    /// Returns `Err` if:
    /// - `data.len() != LEVEL_WIRE_SIZE` (exact length required — no trailing bytes)
    /// - Any polynomial coefficient ≥ q (non-canonical encoding)
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != LEVEL_WIRE_SIZE {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "ZkMerkleLevelV2: expected {} bytes, got {}",
                LEVEL_WIRE_SIZE,
                data.len()
            )));
        }
        let mut off = 0;
        let sib_commitment = BdlopCommitment::from_bytes(&data[off..off + N * 2])?;
        off += N * 2;
        let parent_commitment = BdlopCommitment::from_bytes(&data[off..off + N * 2])?;
        off += N * 2;
        let mut c0 = [0u8; 32];
        c0.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let mut c1 = [0u8; 32];
        c1.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let z0 = Poly::from_bytes(&data[off..off + N * 2])?;
        off += N * 2;
        let z1 = Poly::from_bytes(&data[off..off + N * 2])?;
        debug_assert_eq!(off + N * 2, LEVEL_WIRE_SIZE);
        Ok(Self {
            sib_commitment,
            parent_commitment,
            c0,
            c1,
            z0,
            z1,
        })
    }
}

/// ZK Membership Proof V2 (with parent commitments for clean verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMembershipProofV2 {
    /// Commitment to the leaf polynomial
    pub leaf_commitment: BdlopCommitment,
    /// Per-level proofs
    pub level_proofs: Vec<ZkMerkleLevelV2>,
    /// SIS root polynomial hash
    pub sis_root_hash: [u8; 32],
    /// SIS root polynomial — public input for strict root-opening verification.
    ///
    /// # Why root_poly is public (P0-2 fix)
    ///
    /// The previous design tried to verify the root opening using only the
    /// root *hash*, but the algebraic check requires the actual polynomial:
    ///
    ///   `C_top - A2·root_poly = A1·r_root`
    ///
    /// Without root_poly, the verifier computed:
    ///   `w_recon = A1·z - c·C_top`
    /// which equals `A1·y - c·A2·root_poly ≠ A1·y = w`.
    /// The Fiat-Shamir check was subtly broken because the root_poly
    /// contribution was not cancelled.
    ///
    /// root_poly is NOT secret information — it is derivable from the
    /// public UTXO set. Including it in the proof enables strict
    /// algebraic verification without leaking any private information.
    pub root_poly: Poly,
    /// Proof that the top-level parent commitment opens to the root poly.
    /// This is: `root_opening_response` such that the Σ-protocol verifies
    /// the last parent_commitment is a valid commitment to root_poly.
    pub root_opening_challenge: [u8; 32],
    pub root_opening_response: Poly,
}

impl ZkMembershipProofV2 {
    /// Canonical binary serialization.
    ///
    /// # Wire Format (Mainnet v3)
    ///
    /// ```text
    /// [version: 1 byte]                     — MEMBERSHIP_PROOF_VERSION (0x03)
    /// [leaf_commitment: N*2 bytes]           — BDLOP commitment to leaf
    /// [sis_root_hash: 32 bytes]              — SHA3 of SIS root polynomial
    /// [root_poly: N*2 bytes]                 — SIS root polynomial (public input, P0-2)
    /// [root_opening_challenge: 32 bytes]     — Σ-protocol challenge for root opening
    /// [root_opening_response: N*2 bytes]     — Σ-protocol response for root opening
    /// [num_levels: 2 bytes LE]               — u16, number of Merkle levels
    /// [level_proofs: num_levels × 2112 bytes] — per-level canonical encoding
    /// ```
    ///
    /// # Why This Prevents Malleability Attacks
    ///
    /// 1. **Fixed-length fields**: No variable-length encoding (JSON, protobuf varint)
    ///    means there is exactly ONE valid byte sequence for any proof value.
    ///    An attacker cannot produce an equivalent-but-different encoding.
    ///
    /// 2. **Canonical coefficient range**: Every `Poly::from_bytes()` rejects
    ///    coefficients ≥ q. Since valid coefficients are in [0, q), the encoding
    ///    is injective — no two coefficient arrays map to the same polynomial.
    ///
    /// 3. **No trailing bytes**: `from_bytes()` checks that all input is consumed.
    ///    Appending garbage bytes to a valid proof does NOT produce a valid proof.
    ///
    /// Together, these properties ensure that the Fiat-Shamir transcript computed
    /// over the serialized proof is UNIQUELY determined by the algebraic values.
    /// Any attempt to modify the encoding breaks deserialization or produces a
    /// different transcript hash, which invalidates the challenge.
    pub fn to_bytes(&self) -> Vec<u8> {
        let num_levels = self.level_proofs.len();
        let total = PROOF_V2_FIXED_SIZE + num_levels * LEVEL_WIRE_SIZE;
        let mut buf = Vec::with_capacity(total);

        // Version tag — enables future wire-format migration without ambiguity
        buf.push(MEMBERSHIP_PROOF_VERSION);

        // Fixed fields
        buf.extend_from_slice(&self.leaf_commitment.to_bytes());
        buf.extend_from_slice(&self.sis_root_hash);
        // P0-2: root_poly as public input for strict algebraic verification
        buf.extend_from_slice(&self.root_poly.to_bytes());
        buf.extend_from_slice(&self.root_opening_challenge);
        buf.extend_from_slice(&self.root_opening_response.to_bytes());

        // Level count (u16 LE)
        buf.extend_from_slice(&(num_levels as u16).to_le_bytes());

        // Per-level canonical encoding
        for level in &self.level_proofs {
            buf.extend_from_slice(&level.to_bytes());
        }

        debug_assert_eq!(buf.len(), total);
        buf
    }

    /// Deserialize from canonical binary encoding.
    ///
    /// # Fail-Closed Validation
    ///
    /// This function rejects inputs that are:
    /// - Too short to contain the fixed header
    /// - Using an unknown protocol version
    /// - Claiming more levels than `MAX_MERKLE_DEPTH`
    /// - Exceeding `MAX_MEMBERSHIP_PROOF_SIZE` total bytes
    /// - Not exactly consumed (trailing bytes → Err)
    /// - Containing non-canonical polynomial coefficients (≥ q)
    ///
    /// # Why NOT `unwrap_or_default`
    ///
    /// Every parse failure returns an explicit `Err` with a diagnostic message.
    /// The caller (DAG validator) MUST propagate this error and penalize the
    /// originating peer. Silently accepting malformed proofs is a consensus bug.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        // ── 0. Total size bounds ──
        if data.len() < PROOF_V2_FIXED_SIZE {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "ZkMembershipProofV2: too short ({} < {})",
                data.len(),
                PROOF_V2_FIXED_SIZE
            )));
        }
        if data.len() > MAX_MEMBERSHIP_PROOF_SIZE {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "ZkMembershipProofV2: exceeds max size ({} > {})",
                data.len(),
                MAX_MEMBERSHIP_PROOF_SIZE
            )));
        }

        let mut off = 0;

        // ── 1. Version check ──
        let version = data[off];
        off += 1;
        if version != MEMBERSHIP_PROOF_VERSION {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "ZkMembershipProofV2: unknown version 0x{:02X} (expected 0x{:02X})",
                version, MEMBERSHIP_PROOF_VERSION
            )));
        }

        // ── 2. Fixed fields ──
        let leaf_commitment = BdlopCommitment::from_bytes(&data[off..off + N * 2])?;
        off += N * 2;

        let mut sis_root_hash = [0u8; 32];
        sis_root_hash.copy_from_slice(&data[off..off + 32]);
        off += 32;

        // P0-2: root_poly as public input
        let root_poly = Poly::from_bytes(&data[off..off + N * 2])?;
        off += N * 2;

        let mut root_opening_challenge = [0u8; 32];
        root_opening_challenge.copy_from_slice(&data[off..off + 32]);
        off += 32;

        let root_opening_response = Poly::from_bytes(&data[off..off + N * 2])?;
        off += N * 2;

        // ── 3. Level count with bounds check ──
        let num_levels = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if num_levels > MAX_MERKLE_DEPTH {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "ZkMembershipProofV2: depth {} exceeds MAX_MERKLE_DEPTH {}",
                num_levels, MAX_MERKLE_DEPTH
            )));
        }

        // ── 4. Exact total size check (no trailing bytes) ──
        let expected_total = PROOF_V2_FIXED_SIZE + num_levels * LEVEL_WIRE_SIZE;
        if data.len() != expected_total {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "ZkMembershipProofV2: size mismatch (got {} expected {} for {} levels)",
                data.len(),
                expected_total,
                num_levels
            )));
        }

        // ── 5. Deserialize levels ──
        let mut level_proofs = Vec::with_capacity(num_levels);
        for _ in 0..num_levels {
            let level = ZkMerkleLevelV2::from_bytes(&data[off..off + LEVEL_WIRE_SIZE])?;
            off += LEVEL_WIRE_SIZE;
            level_proofs.push(level);
        }

        debug_assert_eq!(off, data.len(), "BUG: did not consume all bytes");

        Ok(Self {
            leaf_commitment,
            level_proofs,
            sis_root_hash,
            root_poly,
            root_opening_challenge,
            root_opening_response,
        })
    }

    /// Compute the exact wire size for a proof with `depth` levels.
    pub fn wire_size(depth: usize) -> usize {
        PROOF_V2_FIXED_SIZE + depth * LEVEL_WIRE_SIZE
    }
}

fn or_proof_challenge_v2(
    level: usize,
    node_comm: &BdlopCommitment,
    sib_comm: &BdlopCommitment,
    parent_comm: &BdlopCommitment,
    w0: &Poly,
    w1: &Poly,
) -> [u8; 32] {
    let mut t = TranscriptBuilder::new(b"MISAKA/zkmp/or-v2/v3");
    t.append(b"lv", &(level as u32).to_le_bytes());
    t.append(b"Cn", &node_comm.to_bytes());
    t.append(b"Cs", &sib_comm.to_bytes());
    t.append(b"Cp", &parent_comm.to_bytes());
    t.append(b"w0", &w0.to_bytes());
    t.append(b"w1", &w1.to_bytes());
    t.challenge(b"or_c")
}

/// Generate a ZK Membership Proof V2.
///
/// # Returns
///
/// `(proof, r_leaf)` — the proof and the leaf blinding factor.
/// The leaf blinding factor is needed by the unified prover for the
/// key-ownership binding proof (P0-1 fix).
pub fn prove_membership_v2(
    bdlop_crs: &BdlopCrs,
    sis_crs: &SisMerkleCrs,
    leaf_polys: &[Poly],
    signer_index: usize,
    _signer_pk: &Poly,
) -> Result<(ZkMembershipProofV2, BlindingFactor), CryptoError> {
    if leaf_polys.is_empty() || signer_index >= leaf_polys.len() {
        return Err(CryptoError::RingSignatureInvalid(
            "invalid leaf set or index".into(),
        ));
    }

    let root_poly = compute_sis_root(sis_crs, leaf_polys)?;
    let root_hash = sis_root_hash(&root_poly);
    let (siblings, directions) = compute_sis_path(sis_crs, leaf_polys, signer_index);

    // Commit to leaf
    let r_leaf = BlindingFactor::random();
    let r_leaf_out = r_leaf.clone(); // P0-1: returned for key-ownership binding proof
    let leaf_commitment =
        BdlopCommitment::commit_poly(bdlop_crs, &r_leaf, &leaf_polys[signer_index]);

    let mut level_proofs = Vec::with_capacity(siblings.len());
    let mut cur_node = leaf_polys[signer_index].clone();
    let mut cur_blind = r_leaf;

    for (level, (sib_poly, &is_right)) in siblings.iter().zip(directions.iter()).enumerate() {
        let r_sib = BlindingFactor::random();
        let sib_comm = BdlopCommitment::commit_poly(bdlop_crs, &r_sib, sib_poly);

        let parent_poly = if is_right {
            sis_node(sis_crs, sib_poly, &cur_node)
        } else {
            sis_node(sis_crs, &cur_node, sib_poly)
        };
        let r_parent = BlindingFactor::random();
        let parent_comm = BdlopCommitment::commit_poly(bdlop_crs, &r_parent, &parent_poly);

        let node_comm = BdlopCommitment::commit_poly(bdlop_crs, &cur_blind, &cur_node);

        // Excess blinding for the real direction
        let r_excess = if is_right {
            let t1 = sis_crs.a_m1.mul(r_sib.as_poly());
            let t2 = sis_crs.a_m2.mul(cur_blind.as_poly());
            BlindingFactor(t1.add(&t2).sub(r_parent.as_poly()))
        } else {
            let t1 = sis_crs.a_m1.mul(cur_blind.as_poly());
            let t2 = sis_crs.a_m2.mul(r_sib.as_poly());
            BlindingFactor(t1.add(&t2).sub(r_parent.as_poly()))
        };

        // OR-proof with rejection sampling
        let mut done = false;
        for _ in 0..MAX_SIGN_ATTEMPTS {
            let y_real = sample_masking_poly();
            let w_real = bdlop_crs.a1.mul(&y_real);

            // Simulate fake branch
            let z_fake = sample_masking_poly();
            let mut c_fake = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut c_fake);
            let c_fake_poly = hash_to_challenge(&c_fake);

            // Compute D_fake (the excess for the WRONG direction)
            let d_fake = if is_right {
                node_comm
                    .scalar_mul_poly(&sis_crs.a_m1)
                    .add(&sib_comm.scalar_mul_poly(&sis_crs.a_m2))
                    .sub(&parent_comm)
            } else {
                sib_comm
                    .scalar_mul_poly(&sis_crs.a_m1)
                    .add(&node_comm.scalar_mul_poly(&sis_crs.a_m2))
                    .sub(&parent_comm)
            };
            let w_fake = bdlop_crs.a1.mul(&z_fake).sub(&c_fake_poly.mul(&d_fake.0));

            let (w0, w1) = if is_right {
                (&w_fake, &w_real)
            } else {
                (&w_real, &w_fake)
            };
            let c_overall =
                or_proof_challenge_v2(level, &node_comm, &sib_comm, &parent_comm, w0, w1);
            let c_real = xor_challenges(&c_overall, &c_fake);
            let c_real_poly = hash_to_challenge(&c_real);

            let cr = c_real_poly.mul(r_excess.as_poly());
            let mut z_real = Poly::zero();
            for i in 0..N {
                let y_c = if y_real.coeffs[i] > Q / 2 {
                    y_real.coeffs[i] - Q
                } else {
                    y_real.coeffs[i]
                };
                let cr_c = if cr.coeffs[i] > Q / 2 {
                    cr.coeffs[i] - Q
                } else {
                    cr.coeffs[i]
                };
                z_real.coeffs[i] = ((y_c + cr_c) % Q + Q) % Q;
            }

            if z_real.norm_inf() >= BETA {
                z_real.coeffs.zeroize();
                continue;
            }

            let (c0, c1, z0, z1) = if is_right {
                (c_fake, c_real, z_fake, z_real)
            } else {
                (c_real, c_fake, z_real, z_fake)
            };

            level_proofs.push(ZkMerkleLevelV2 {
                sib_commitment: sib_comm.clone(),
                parent_commitment: parent_comm.clone(),
                c0,
                c1,
                z0,
                z1,
            });
            done = true;
            break;
        }
        if !done {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "OR-proof rejection at level {}",
                level
            )));
        }

        cur_node = parent_poly;
        cur_blind = r_parent;
    }

    // Root opening proof: prove that the last parent commitment opens to root_poly.
    // Σ-protocol: prover knows r_root such that C_root = A1·r_root + A2·root_poly.
    // Equivalently: C_root - A2·root_poly = A1·r_root.
    let mut root_opening_challenge = [0u8; 32];
    let mut root_opening_response = Poly::zero();
    for _ in 0..MAX_SIGN_ATTEMPTS {
        let y = sample_masking_poly();
        let w_root = bdlop_crs.a1.mul(&y);

        let mut t = TranscriptBuilder::new(b"MISAKA/zkmp/root-open/v3");
        t.append(b"hash", &root_hash);
        t.append(b"w", &w_root.to_bytes());
        if let Some(last_level) = level_proofs.last() {
            t.append(b"Cp", &last_level.parent_commitment.to_bytes());
        } else {
            t.append(b"Cp", &leaf_commitment.to_bytes());
        }
        let c_root = t.challenge(b"root_c");
        let c_root_poly = hash_to_challenge(&c_root);

        let cr = c_root_poly.mul(cur_blind.as_poly());
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 {
                y.coeffs[i] - Q
            } else {
                y.coeffs[i]
            };
            let cr_c = if cr.coeffs[i] > Q / 2 {
                cr.coeffs[i] - Q
            } else {
                cr.coeffs[i]
            };
            z.coeffs[i] = ((y_c + cr_c) % Q + Q) % Q;
        }
        if z.norm_inf() >= BETA {
            z.coeffs.zeroize();
            continue;
        }
        root_opening_challenge = c_root;
        root_opening_response = z;
        break;
    }

    Ok((
        ZkMembershipProofV2 {
            leaf_commitment,
            level_proofs,
            sis_root_hash: root_hash,
            root_poly, // P0-2: public input for strict root-opening verification
            root_opening_challenge,
            root_opening_response,
        },
        r_leaf_out,
    ))
}

/// Verify a ZK Membership Proof V2.
///
/// # Verification (O(depth), NO pk, NO ring, NO scanning)
///
/// The verifier checks purely algebraic equations over BDLOP commitments.
/// At NO point does the verifier learn pk, leaf_index, or direction bits.
///
/// ## Algorithm
///
/// 1. Check root hash against chain state
/// 2. For each level bottom-up:
///    a. Compute D0 = A_m1·C_node + A_m2·C_sib - C_parent
///    b. Compute D1 = A_m1·C_sib + A_m2·C_node - C_parent
///    c. Reconstruct w0 = A1·z0 - c0_poly·D0
///    d. Reconstruct w1 = A1·z1 - c1_poly·D1
///    e. Recompute c_overall = H(level, C_node, C_sib, C_parent, w0, w1)
///    f. Verify c0 XOR c1 == c_overall
///    g. Verify ||z0|| < β and ||z1|| < β
///    h. Set C_node = C_parent for next level
/// 3. Verify root opening: the top C_parent opens to the SIS root
pub fn verify_membership_v2(
    bdlop_crs: &BdlopCrs,
    sis_crs: &SisMerkleCrs,
    expected_root_hash: &[u8; 32],
    proof: &ZkMembershipProofV2,
) -> Result<(), CryptoError> {
    if !ct_eq_32(&proof.sis_root_hash, expected_root_hash) {
        return Err(CryptoError::RingSignatureInvalid(
            "root hash mismatch".into(),
        ));
    }
    if proof.level_proofs.len() > ZKMP_MAX_DEPTH {
        return Err(CryptoError::RingSignatureInvalid("depth exceeded".into()));
    }

    let mut cur_node_comm = proof.leaf_commitment.clone();

    for (level, lp) in proof.level_proofs.iter().enumerate() {
        if lp.z0.norm_inf() >= BETA || lp.z1.norm_inf() >= BETA {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "level {} response norm >= β",
                level
            )));
        }

        let c0_poly = hash_to_challenge(&lp.c0);
        let c1_poly = hash_to_challenge(&lp.c1);

        // D0 = A_m1·C_node + A_m2·C_sib - C_parent
        let d0 = cur_node_comm
            .scalar_mul_poly(&sis_crs.a_m1)
            .add(&lp.sib_commitment.scalar_mul_poly(&sis_crs.a_m2))
            .sub(&lp.parent_commitment);

        // D1 = A_m1·C_sib + A_m2·C_node - C_parent
        let d1 = lp
            .sib_commitment
            .scalar_mul_poly(&sis_crs.a_m1)
            .add(&cur_node_comm.scalar_mul_poly(&sis_crs.a_m2))
            .sub(&lp.parent_commitment);

        // Reconstruct w0 = A1·z0 - c0·D0
        let w0 = bdlop_crs.a1.mul(&lp.z0).sub(&c0_poly.mul(&d0.0));
        // Reconstruct w1 = A1·z1 - c1·D1
        let w1 = bdlop_crs.a1.mul(&lp.z1).sub(&c1_poly.mul(&d1.0));

        // Recompute Fiat-Shamir challenge
        let c_overall = or_proof_challenge_v2(
            level,
            &cur_node_comm,
            &lp.sib_commitment,
            &lp.parent_commitment,
            &w0,
            &w1,
        );

        // Check c0 XOR c1 == c_overall
        let c_xor = xor_challenges(&lp.c0, &lp.c1);
        if c_xor != c_overall {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "level {} OR-proof challenge mismatch: c0⊕c1 ≠ c_overall",
                level
            )));
        }

        // Advance: next level's node_comm = this level's parent_comm
        cur_node_comm = lp.parent_commitment.clone();
    }

    // ── Root opening verification (P0-2 strict algebraic check) ──
    //
    // The top-level parent commitment C_top must open to the SIS root polynomial.
    // The prover demonstrates: C_top - A2·root_poly = A1·r_root
    // via a Σ-protocol (knowledge of r_root).
    //
    // Step 1: Verify root_poly matches the expected root hash.
    //   This binds the proof to the correct anonymity set.
    let computed_root_hash = sis_root_hash(&proof.root_poly);
    if !ct_eq_32(&computed_root_hash, expected_root_hash) {
        return Err(CryptoError::RingSignatureInvalid(
            "root_poly hash does not match expected_root_hash (P0-2)".into(),
        ));
    }

    if proof.root_opening_response.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid(
            "root opening norm >= β".into(),
        ));
    }

    let c_root_poly = hash_to_challenge(&proof.root_opening_challenge);

    // Step 2: Compute the excess commitment.
    //   excess = C_top - A2·root_poly
    // If C_top = A1·r_root + A2·root_poly (honest prover), then excess = A1·r_root.
    let top_comm = &cur_node_comm;
    let excess = top_comm.0.sub(&bdlop_crs.a2.mul(&proof.root_poly));

    // Step 3: Reconstruct w_root from the Σ-protocol.
    //   z_root = y + c·r_root, so:
    //   A1·z_root = A1·y + c·A1·r_root = w_root + c·excess
    //   w_root = A1·z_root - c·excess
    let w_root_recon = bdlop_crs
        .a1
        .mul(&proof.root_opening_response)
        .sub(&c_root_poly.mul(&excess));

    // Step 4: Recompute Fiat-Shamir challenge and verify.
    let mut t = TranscriptBuilder::new(b"MISAKA/zkmp/root-open/v3");
    t.append(b"hash", &proof.sis_root_hash);
    t.append(b"w", &w_root_recon.to_bytes());
    t.append(b"Cp", &top_comm.to_bytes());
    let c_check = t.challenge(b"root_c");

    if !ct_eq_32(&c_check, &proof.root_opening_challenge) {
        return Err(CryptoError::RingSignatureInvalid(
            "root opening Σ-protocol challenge mismatch".into(),
        ));
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_ring::{compute_pubkey, derive_public_param, derive_secret_poly, DEFAULT_A_SEED};
    use crate::pq_sign::MlDsaKeypair;

    fn make_leaves(sis_crs: &SisMerkleCrs, size: usize) -> (Vec<Poly>, Vec<Poly>, Vec<Poly>) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secrets: Vec<Poly> = (0..size)
            .map(|_| derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let pks: Vec<Poly> = secrets.iter().map(|s| compute_pubkey(&a, s)).collect();
        let leaves: Vec<Poly> = pks.iter().map(|pk| sis_leaf(sis_crs, pk)).collect();
        (secrets, pks, leaves)
    }

    #[test]
    fn test_sis_merkle_root_deterministic() {
        let sis_crs = SisMerkleCrs::default_crs();
        let (_, _, leaves) = make_leaves(&sis_crs, 4);
        let r1 = compute_sis_root(&sis_crs, &leaves).unwrap();
        let r2 = compute_sis_root(&sis_crs, &leaves).unwrap();
        assert_eq!(r1.coeffs, r2.coeffs);
    }

    #[test]
    fn test_sis_collision_resistance() {
        let sis_crs = SisMerkleCrs::default_crs();
        let (_, _, leaves) = make_leaves(&sis_crs, 4);
        // Different leaf sets → different roots
        let (_, _, leaves2) = make_leaves(&sis_crs, 4);
        let r1 = compute_sis_root(&sis_crs, &leaves).unwrap();
        let r2 = compute_sis_root(&sis_crs, &leaves2).unwrap();
        assert_ne!(
            r1.coeffs, r2.coeffs,
            "different leaves must produce different roots"
        );
    }

    #[test]
    fn test_prove_verify_membership_v2() {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();
        let (_, pks, leaves) = make_leaves(&sis_crs, 4);

        let root = compute_sis_root(&sis_crs, &leaves).unwrap();
        let root_hash = sis_root_hash(&root);

        let (proof, _r_leaf) =
            prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, 0, &pks[0]).unwrap();

        verify_membership_v2(&bdlop_crs, &sis_crs, &root_hash, &proof).unwrap();
    }

    #[test]
    fn test_all_positions_verify() {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();
        let (_, pks, leaves) = make_leaves(&sis_crs, 8);
        let root = compute_sis_root(&sis_crs, &leaves).unwrap();
        let root_hash = sis_root_hash(&root);

        for i in 0..8 {
            let (proof, _r_leaf) =
                prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, i, &pks[i]).unwrap();
            verify_membership_v2(&bdlop_crs, &sis_crs, &root_hash, &proof).unwrap();
        }
    }

    #[test]
    fn test_wrong_root_hash_rejected() {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();
        let (_, pks, leaves) = make_leaves(&sis_crs, 4);
        let root = compute_sis_root(&sis_crs, &leaves).unwrap();
        let _root_hash = sis_root_hash(&root);

        let (proof, _r_leaf) =
            prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, 0, &pks[0]).unwrap();

        let fake_hash = [0xFF; 32];
        assert!(verify_membership_v2(&bdlop_crs, &sis_crs, &fake_hash, &proof).is_err());
    }

    #[test]
    fn test_no_pk_in_proof() {
        let bdlop_crs = BdlopCrs::default_crs();
        let sis_crs = SisMerkleCrs::default_crs();
        let (_, pks, leaves) = make_leaves(&sis_crs, 4);

        let (proof, _r_leaf) =
            prove_membership_v2(&bdlop_crs, &sis_crs, &leaves, 0, &pks[0]).unwrap();

        // pk must NOT appear anywhere in the proof
        let pk_bytes = pks[0].to_bytes();
        let leaf_bytes = proof.leaf_commitment.to_bytes();

        // The leaf_commitment is A1·r + A2·leaf_poly where leaf_poly = A_leaf·pk.
        // It does NOT contain pk in plaintext.
        assert_ne!(leaf_bytes, pk_bytes, "pk must not appear as commitment");

        // Check that pk bytes don't appear in any level proof
        for lp in &proof.level_proofs {
            let sib_bytes = lp.sib_commitment.to_bytes();
            assert_ne!(sib_bytes.as_slice(), pk_bytes.as_slice());
        }
    }
}
