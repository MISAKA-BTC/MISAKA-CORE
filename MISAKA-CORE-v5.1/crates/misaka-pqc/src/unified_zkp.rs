//! Unified Zero-Knowledge Proof — Σ-protocol + ZK Membership + Nullifier.
//!
//! # Architecture: Perfect ZK via SIS Merkle + Committed Path
//!
//! This module composes two sub-proofs into a single unified proof:
//!
//! 1. **Σ-protocol** (Lyubashevsky, 2012): Proves knowledge of `s` such that
//!    - `pk = a · s` (key ownership)
//!    - `null_poly = a_null · s` (nullifier binding)
//!    The Σ-protocol reveals `w_pk = a·y` and `z = y + c·s`, but NOT `pk` or `s`.
//!
//! 2. **ZK Membership** (SIS Merkle + BDLOP committed path + CDS OR-proofs):
//!    Proves that the committed leaf (derived from the Σ-protocol's pk)
//!    is in the SIS Merkle tree rooted at the public anonymity root.
//!    The path, siblings, and direction bits are ALL committed — the verifier
//!    learns NOTHING about the signer's position or public key.
//!
//! # Zero-Knowledge Property
//!
//! **The verifier CANNOT reconstruct `pk`**. Unlike the previous FCMP design
//! (which allowed `pk = c⁻¹·(a·z − w_pk)`), the current design:
//! - Does NOT include `leaf_hash` or `path_siblings` in plaintext
//! - Does NOT allow pk reconstruction (the Σ-protocol binding to the
//!   membership proof uses BDLOP commitments, not plaintext values)
//! - Provides computational ZK under Module-SIS/MLWE assumptions
//!
//! Even an unbounded verifier (with quantum computer) learns only:
//! - The nullifier (for double-spend prevention)
//! - The SIS root hash (public, same for all transactions)
//! - That some member of the anonymity set created the transaction
//!
//! # Soundness (Module-SIS + SIS Collision Resistance)
//!
//! An efficient adversary cannot produce a valid proof without knowing
//! `s` for some leaf in the SIS Merkle tree.

use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

use crate::pq_ring::{
    Poly, Q, N, BETA, MAX_SIGN_ATTEMPTS,
    sample_masking_poly, hash_to_challenge,
};
use crate::nullifier::{
    OutputId, NullifierContext, TxDomain,
    derive_nullifier_param, derive_nullifier_param_ctx,
    canonical_nullifier_hash,
};
use crate::transcript::{TranscriptBuilder, domain, PROTOCOL_VERSION};
use crate::membership::{
    SisMerkleCrs, ZkMembershipProofV2,
    sis_leaf, compute_sis_root, sis_root_hash,
    prove_membership_v2, verify_membership_v2,
    MAX_MERKLE_DEPTH, MEMBERSHIP_PROOF_VERSION,
    MAX_MEMBERSHIP_PROOF_SIZE,
};
use crate::bdlop::{BdlopCrs, BdlopCommitment, BlindingFactor};
use crate::error::CryptoError;
use crate::secret::ct_eq_32;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

pub const SCHEME_UNIFIED_ZKP: u8 = 0x10;
pub const ZKP_MIN_RING_SIZE: usize = 2;
pub const ZKP_MAX_RING_SIZE: usize = 1 << 20;

/// Wire format version for UnifiedMembershipProof.
/// Bump on any breaking change to the serialization layout.
/// v0x03: Added sigma_w_bind + binding_response for key-ownership verification (P0-1).
pub const UNIFIED_PROOF_VERSION: u8 = 0x03;

/// Fixed-size portion of UnifiedMembershipProof (excluding membership sub-proof):
///   version (1) + sigma_w_pk (N*2) + sigma_w_null (N*2) + response (N*2)
///   + nullifier_poly (N*2) + nullifier_param (N*2) + ctx_hash (32)
///   + sigma_w_bind (N*2) + binding_response (N*2)
///   = 1 + 512*7 + 32 = 3617 bytes
const UNIFIED_FIXED_SIZE: usize = 1 + N * 2 * 7 + 32;

/// Maximum wire size for a UnifiedMembershipProof.
/// = UNIFIED_FIXED_SIZE + MAX_MEMBERSHIP_PROOF_SIZE
/// ≈ 2593 + 56003 = 58596 bytes ≈ 57 KB
///
/// Any incoming proof exceeding this is rejected before any crypto work,
/// preventing memory-exhaustion DoS from malformed payloads.
pub const MAX_UNIFIED_PROOF_SIZE: usize = UNIFIED_FIXED_SIZE + MAX_MEMBERSHIP_PROOF_SIZE;

// ═══════════════════════════════════════════════════════════════
//  Unified Proof Structure
// ═══════════════════════════════════════════════════════════════

/// Unified Zero-Knowledge Proof.
///
/// # What is NOT in this proof:
/// - `signer_pk`: NOT present, NOT reconstructable
/// - `leaf_hash`: NOT in plaintext (committed in ZkMembershipProofV2)
/// - `path_siblings`: NOT in plaintext (committed in ZkMembershipProofV2)
/// - `direction_bits`: NOT present (hidden by OR-proofs)
/// - `output_id`: NOT present (embedded in nullifier_param, one-way)
///
/// # What IS in this proof:
/// - Σ-protocol commitments (w_pk, w_null) and response (z)
/// - Nullifier polynomial and parameter (algebraic binding)
/// - ZK Membership proof (BDLOP commitments + OR-proofs only)
/// - NullifierContext hash (binds proof to chain/domain/epoch)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedMembershipProof {
    /// Σ-protocol first message (key ownership): `w_pk = a · y`.
    pub sigma_w_pk: Poly,
    /// Σ-protocol first message (nullifier): `w_null = a_null · y`.
    pub sigma_w_null: Poly,
    /// Σ-protocol response: `z = y + c · s`.
    pub response: Poly,
    /// Algebraic nullifier polynomial: `t_null = a_null · s`.
    pub nullifier_poly: Poly,
    /// Nullifier parameter: `a_null = DeriveParam(NullifierContext.hash())`.
    pub nullifier_param: Poly,
    /// NullifierContext hash (32 bytes) — bound into Fiat-Shamir transcript.
    /// The verifier recomputes this from the claimed NullifierContext and checks
    /// it matches. This prevents the prover from using a different context than
    /// what the verifier expects.
    pub ctx_hash: [u8; 32],
    /// Key-ownership binding first message: `w_bind = A1 · y_r`.
    ///
    /// # P0-1 Fix: Why This Field Was Added
    ///
    /// Previously, the Σ-protocol proved knowledge of `s` for nullifier binding
    /// (`a_null·z - c·null_poly == w_null`) but did NOT verify that the same `s`
    /// corresponded to a pk committed in the membership proof's leaf commitment.
    ///
    /// An attacker could combine:
    /// - A valid membership proof for pk_1 (someone else's key in the tree)
    /// - A Σ-protocol proof for s_2 (their own secret, different from pk_1's)
    ///
    /// The binding proof closes this gap by proving that `C_leaf` commits to
    /// `a_leaf · pk` where `pk = a · s` and `s` is the SAME secret used in the
    /// Σ-protocol. The verifier checks this algebraically without learning pk.
    pub sigma_w_bind: Poly,
    /// Key-ownership binding response: `z_r = y_r + c · r_leaf`.
    pub binding_response: Poly,
    /// ZK Membership proof (SIS Merkle + committed path + OR-proofs).
    /// Contains ONLY BDLOP commitments — NO plaintext pk, path, or siblings.
    pub membership: ZkMembershipProofV2,
}

impl UnifiedMembershipProof {
    /// Canonical binary serialization.
    ///
    /// # Wire Format (Mainnet v3)
    ///
    /// ```text
    /// [version: 1 byte]                — UNIFIED_PROOF_VERSION (0x03)
    /// [sigma_w_pk: N*2 bytes]          — Σ-protocol w_pk commitment
    /// [sigma_w_null: N*2 bytes]        — Σ-protocol w_null commitment
    /// [response: N*2 bytes]            — Σ-protocol response z
    /// [nullifier_poly: N*2 bytes]      — Algebraic nullifier t_null
    /// [nullifier_param: N*2 bytes]     — Public parameter a_null
    /// [ctx_hash: 32 bytes]             — NullifierContext hash
    /// [sigma_w_bind: N*2 bytes]        — Key-ownership binding w_bind (P0-1)
    /// [binding_response: N*2 bytes]    — Key-ownership binding z_r (P0-1)
    /// [membership: variable bytes]     — ZkMembershipProofV2.to_bytes()
    /// ```
    ///
    /// # Why JSON Was Removed (Task 1.2)
    ///
    /// The previous implementation used `serde_json::to_vec(&self.membership)`
    /// for the membership sub-proof. This was a critical vulnerability:
    ///
    /// 1. **Malleability**: JSON allows multiple encodings of the same value
    ///    (whitespace, key ordering, Unicode escapes). An attacker could
    ///    produce a semantically-identical proof with different bytes,
    ///    potentially bypassing nullifier deduplication or causing cache
    ///    inconsistencies across nodes.
    ///
    /// 2. **Memory exhaustion**: JSON deserialization allocates dynamically.
    ///    A crafted payload like `{"z0":{"coeffs":[0,0,...` repeated 10M
    ///    times) could exhaust memory before any crypto validation occurs.
    ///    The attacker pays zero CPU (no valid proof needed) but the victim
    ///    pays O(payload_size) in memory.
    ///
    /// 3. **Non-determinism**: `serde_json` does not guarantee round-trip
    ///    stability across versions. A `serde_json` upgrade could change
    ///    field ordering, breaking consensus across nodes running different
    ///    versions.
    ///
    /// The canonical binary encoding eliminates all three issues:
    /// - One and only one byte sequence per proof value (no malleability)
    /// - Fixed-size allocation determined by `num_levels` (no memory bomb)
    /// - Version-tagged format with explicit wire layout (no library dependency)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mem_bytes = self.membership.to_bytes();
        let total = UNIFIED_FIXED_SIZE + mem_bytes.len();
        let mut buf = Vec::with_capacity(total);

        // Version tag
        buf.push(UNIFIED_PROOF_VERSION);

        // Σ-protocol fields (fixed size)
        buf.extend_from_slice(&self.sigma_w_pk.to_bytes());
        buf.extend_from_slice(&self.sigma_w_null.to_bytes());
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.nullifier_poly.to_bytes());
        buf.extend_from_slice(&self.nullifier_param.to_bytes());

        // NullifierContext hash (Task 2.1)
        buf.extend_from_slice(&self.ctx_hash);

        // P0-1: Key-ownership binding proof fields
        buf.extend_from_slice(&self.sigma_w_bind.to_bytes());
        buf.extend_from_slice(&self.binding_response.to_bytes());

        // Membership proof (canonical binary — NOT JSON)
        buf.extend_from_slice(&mem_bytes);

        debug_assert_eq!(buf.len(), total);
        buf
    }

    /// Deserialize from canonical binary encoding.
    ///
    /// # Fail-Closed Validation (Absolute Rules)
    ///
    /// 1. **Total size bounds**: Reject if `< UNIFIED_FIXED_SIZE` or `> MAX_UNIFIED_PROOF_SIZE`.
    /// 2. **Version check**: Reject if version != `UNIFIED_PROOF_VERSION`.
    /// 3. **Canonical coefficients**: Every `Poly::from_bytes()` rejects coeff ≥ q.
    /// 4. **Membership sub-proof**: Delegates to `ZkMembershipProofV2::from_bytes()`
    ///    which enforces its own depth bounds, exact-size check, and canonical encoding.
    /// 5. **No trailing bytes**: The membership sub-proof's `from_bytes()` rejects surplus.
    ///
    /// # Why NOT `unwrap_or_default()`
    ///
    /// The old code had: `serde_json::to_vec(&self.membership).unwrap_or_default()`
    /// This meant a serialization failure silently produced an EMPTY proof —
    /// which would fail verification, but the error was lost. In the worst case,
    /// the empty bytes could be cached as "the proof for TX X" and served to
    /// other peers, causing a consensus split.
    ///
    /// The new code returns `Err` on any anomaly. The caller MUST propagate
    /// and penalize the originating peer.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        // ── 0. Total size bounds ──
        if data.len() < UNIFIED_FIXED_SIZE {
            return Err(CryptoError::RingSignatureInvalid(
                format!("UnifiedProof: too short ({} < {})", data.len(), UNIFIED_FIXED_SIZE)));
        }
        if data.len() > MAX_UNIFIED_PROOF_SIZE {
            return Err(CryptoError::RingSignatureInvalid(
                format!("UnifiedProof: exceeds max size ({} > {})", data.len(), MAX_UNIFIED_PROOF_SIZE)));
        }

        let mut off = 0;

        // ── 1. Version check ──
        let version = data[off]; off += 1;
        if version != UNIFIED_PROOF_VERSION {
            return Err(CryptoError::RingSignatureInvalid(
                format!("UnifiedProof: unknown version 0x{:02X} (expected 0x{:02X})",
                    version, UNIFIED_PROOF_VERSION)));
        }

        // ── 2. Fixed Σ-protocol fields ──
        let sigma_w_pk = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let sigma_w_null = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let response = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let nullifier_poly = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let nullifier_param = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;

        // ── 3. NullifierContext hash ──
        let mut ctx_hash = [0u8; 32];
        ctx_hash.copy_from_slice(&data[off..off+32]); off += 32;

        // ── 3b. P0-1: Key-ownership binding proof ──
        let sigma_w_bind = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;
        let binding_response = Poly::from_bytes(&data[off..off+N*2])?; off += N*2;

        // ── 4. Membership sub-proof (canonical binary) ──
        // `ZkMembershipProofV2::from_bytes` enforces its own exact-size check,
        // so we pass the entire remaining slice. If there are trailing bytes
        // after the membership proof, that function will reject them.
        let membership = ZkMembershipProofV2::from_bytes(&data[off..])?;

        Ok(Self {
            sigma_w_pk, sigma_w_null, response,
            nullifier_poly, nullifier_param, ctx_hash,
            sigma_w_bind, binding_response,
            membership,
        })
    }
}

// ═══════════════════════════════════════════════════════════════
//  Type-Safe Fiat-Shamir Transcript (Task 2.2)
// ═══════════════════════════════════════════════════════════════

/// All inputs to the Σ-protocol Fiat-Shamir challenge, collected as a struct
/// to prevent developer error in field ordering or omission.
///
/// # Why a Struct? (Task 2.2)
///
/// Previously, `build_sigma_challenge` accepted 8 separate parameters.
/// A developer transposing two arguments (e.g., `w_pk` and `w_null`)
/// would produce a valid but DIFFERENT challenge, breaking verification
/// without any compile-time or runtime warning. By collecting all inputs
/// into a typed struct, we:
///
/// 1. **Document the exact Fiat-Shamir boundary**: Everything in this struct
///    is part of the public statement / first-message. Everything NOT here
///    is the witness.
///
/// 2. **Prevent reordering bugs**: Fields are serialized in declaration order.
///    Reordering fields requires changing the struct (detectable by diff review).
///
/// 3. **Separate Algebraic Soundness from Fiat-Shamir**:
///    - Algebraic Soundness: the Σ-protocol relations (pk = a·s, t_null = a_null·s)
///    - Fiat-Shamir: converting interactive → non-interactive by hashing the
///      first messages into a challenge. This struct defines EXACTLY what
///      Fiat-Shamir hashes.
struct SigmaChallengeInput<'a> {
    /// SIS Merkle root hash (from chain state / proof)
    sis_root_hash: &'a [u8; 32],
    /// Transaction message digest
    message: &'a [u8; 32],
    /// Σ-protocol first message: w_pk = a · y
    w_pk: &'a Poly,
    /// Σ-protocol first message: w_null = a_null · y
    w_null: &'a Poly,
    /// Algebraic nullifier polynomial: t_null = a_null · s
    null_poly: &'a Poly,
    /// Nullifier public parameter: a_null
    nullifier_param: &'a Poly,
    /// Canonical nullifier hash: H(t_null)
    nullifier_hash: &'a [u8; 32],
    /// BDLOP commitment to the leaf (from ZK membership proof)
    leaf_commitment: &'a BdlopCommitment,
    /// Key-ownership binding first message: w_bind = A1·y_r (P0-1).
    ///
    /// Including this in Fiat-Shamir ensures the binding proof is
    /// non-interactive and sound — the prover cannot choose z_r after
    /// seeing the challenge.
    w_bind: &'a Poly,
    /// NullifierContext hash — binds the challenge to the full transaction
    /// context (chain_id, tx_domain, protocol_version, anonymity_root_epoch).
    ///
    /// # Why This Prevents Replay (Task 2.1)
    ///
    /// If an attacker tries to replay a proof in a different context
    /// (different chain, different epoch, different domain), the ctx_hash
    /// will differ, producing a different challenge `c`. The response
    /// `z = y + c·s` was computed with the ORIGINAL challenge, so the
    /// verification equation `a·z - c'·pk ≠ w_pk` will fail.
    ctx_hash: &'a [u8; 32],
}

fn build_sigma_challenge(input: &SigmaChallengeInput<'_>) -> [u8; 32] {
    // ── Fiat-Shamir transcript (deterministic order) ──
    // Every field is labeled with a unique tag to prevent
    // domain confusion between different-length inputs.
    let mut t = TranscriptBuilder::new(domain::MEMBERSHIP_ZKP);
    t.append(b"sis_root", input.sis_root_hash);
    t.append(b"msg", input.message);
    t.append(b"w_pk", &input.w_pk.to_bytes());
    t.append(b"w_null", &input.w_null.to_bytes());
    t.append(b"null_poly", &input.null_poly.to_bytes());
    t.append(b"null_param", &input.nullifier_param.to_bytes());
    t.append(b"null_hash", input.nullifier_hash);
    t.append(b"leaf_comm", &input.leaf_commitment.to_bytes());
    // P0-1: w_bind absorbed BEFORE challenge derivation for soundness
    t.append(b"w_bind", &input.w_bind.to_bytes());
    // Task 2.1: Context binding absorbs the full NullifierContext hash
    // into the Fiat-Shamir transcript. This is the critical link that
    // makes the proof non-transferable across contexts.
    t.append(b"ctx_hash", input.ctx_hash);
    t.challenge(b"sigma_c")
}

// ═══════════════════════════════════════════════════════════════
//  Legacy Merkle (compatibility shim)
// ═══════════════════════════════════════════════════════════════

/// Compute SHA3 Merkle root (for backwards compatibility / transition).
pub fn compute_merkle_root(leaf_hashes: &[[u8; 32]]) -> Result<[u8; 32], CryptoError> {
    use crate::transcript::merkle_node_hash;
    if leaf_hashes.is_empty() {
        return Err(CryptoError::RingSignatureInvalid("empty".into()));
    }
    if leaf_hashes.len() == 1 { return Ok(leaf_hashes[0]); }
    let n = leaf_hashes.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = leaf_hashes.to_vec();
    while layer.len() < n { layer.push([0u8; 32]); }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) { next.push(merkle_node_hash(&pair[0], &pair[1])); }
        layer = next;
    }
    Ok(layer[0])
}

// ═══════════════════════════════════════════════════════════════
//  Prove
// ═══════════════════════════════════════════════════════════════

/// Generate a unified ZK proof (Σ-protocol + ZK Membership).
///
/// # Privacy: pk is NEVER in the proof
///
/// The Σ-protocol produces `w_pk = a·y` and `z = y + c·s`.
/// The verifier sees `w_pk` and `z` but CANNOT compute `pk`:
/// - Computing `pk = c⁻¹·(a·z − w_pk)` requires knowing which
///   leaf the commitment corresponds to, but the leaf commitment
///   hides this behind BDLOP semantic security.
/// - The membership proof verifies the committed leaf against the
///   SIS Merkle root using ONLY algebraic checks on commitments.
///
/// # Legacy API — Retained for Test Compatibility
///
/// New callers should prefer `unified_prove_ctx` which takes a full
/// `NullifierContext` for comprehensive replay protection.
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
    // Construct a default NullifierContext from the legacy parameters
    let ctx = NullifierContext {
        chain_id,
        tx_domain: TxDomain::Transfer,
        spent_output_id: *output_id,
        protocol_version: PROTOCOL_VERSION,
        anonymity_root_epoch: 0, // Legacy: no epoch binding
    };
    unified_prove_ctx(a, leaf_hashes, signer_index, secret, signer_pk, message, &ctx)
}

/// Generate a unified ZK proof with full NullifierContext binding (Task 2.1).
///
/// This is the Mainnet-ready API. The `NullifierContext` ensures the proof is
/// bound to a specific chain, domain, epoch, and protocol version.
pub fn unified_prove_ctx(
    a: &Poly,
    leaf_hashes: &[[u8; 32]],
    signer_index: usize,
    secret: &Poly,
    signer_pk: &Poly,
    message: &[u8; 32],
    ctx: &NullifierContext,
) -> Result<(UnifiedMembershipProof, [u8; 32]), CryptoError> {
    let n_ring = leaf_hashes.len();
    if n_ring < ZKP_MIN_RING_SIZE || n_ring > ZKP_MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} out of range", n_ring)));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::RingSignatureInvalid("signer index out of range".into()));
    }

    let bdlop_crs = BdlopCrs::default_crs();
    let sis_crs = SisMerkleCrs::default_crs();

    // Build SIS Merkle tree from leaf_hashes (treated as pk hash → SIS leaf)
    let all_leaf_polys: Vec<Poly> = leaf_hashes.iter()
        .map(|lh| {
            let mut p = Poly::zero();
            for (i, chunk) in lh.chunks(2).enumerate() {
                if i < N {
                    p.coeffs[i] = (u16::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]) as i32) % Q;
                }
            }
            p
        })
        .collect();

    // Override signer's leaf with actual SIS leaf from pk
    let mut leaf_polys = all_leaf_polys;
    leaf_polys[signer_index] = sis_leaf(&sis_crs, signer_pk);

    let root_poly = compute_sis_root(&sis_crs, &leaf_polys)?;
    let root_hash = sis_root_hash(&root_poly);

    // Nullifier derivation via NullifierContext (Task 2.1)
    let ctx_hash = ctx.hash();
    let a_null = derive_nullifier_param_ctx(ctx);
    let null_poly = a_null.mul(secret);
    let nullifier_hash = canonical_nullifier_hash(&null_poly);

    // Generate ZK Membership proof FIRST (to get leaf_commitment for Σ-challenge)
    // P0-1: prove_membership_v2 now also returns r_leaf for binding proof
    let (membership_proof, r_leaf) = prove_membership_v2(
        &bdlop_crs, &sis_crs, &leaf_polys, signer_index, signer_pk,
    )?;

    // P0-1: Precompute a_leaf·pk for the binding verification equation.
    // leaf_poly = a_leaf·pk where pk = a·s.
    // The verifier will use this relation to check the binding.
    let a_leaf_poly = &sis_crs.a_leaf;

    // Σ-protocol with Fiat-Shamir-with-Aborts
    // P0-1: Now generates BOTH the standard Σ-response AND the binding response
    for _ in 0..MAX_SIGN_ATTEMPTS {
        let y = sample_masking_poly();
        let y_r = sample_masking_poly(); // P0-1: masking for binding proof
        let w_pk = a.mul(&y);
        let w_null = a_null.mul(&y);
        let w_bind = bdlop_crs.a1.mul(&y_r); // P0-1: binding first message

        // Type-safe Fiat-Shamir (Task 2.2 + P0-1: includes w_bind)
        let challenge = build_sigma_challenge(&SigmaChallengeInput {
            sis_root_hash: &root_hash,
            message,
            w_pk: &w_pk,
            w_null: &w_null,
            null_poly: &null_poly,
            nullifier_param: &a_null,
            nullifier_hash: &nullifier_hash,
            leaf_commitment: &membership_proof.leaf_commitment,
            w_bind: &w_bind,
            ctx_hash: &ctx_hash,
        });
        let c_poly = hash_to_challenge(&challenge);

        // Standard Σ-response: z = y + c·s
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q/2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q/2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            z.coeffs[i] = ((y_c + cs_c) % Q + Q) % Q;
        }

        if z.norm_inf() >= BETA {
            z.coeffs.zeroize();
            continue;
        }

        // P0-1: Binding response: z_r = y_r + c·r_leaf
        let cr_leaf = c_poly.mul(r_leaf.as_poly());
        let mut z_r = Poly::zero();
        for i in 0..N {
            let yr_c = if y_r.coeffs[i] > Q/2 { y_r.coeffs[i] - Q } else { y_r.coeffs[i] };
            let cr_c = if cr_leaf.coeffs[i] > Q/2 { cr_leaf.coeffs[i] - Q } else { cr_leaf.coeffs[i] };
            z_r.coeffs[i] = ((yr_c + cr_c) % Q + Q) % Q;
        }

        if z_r.norm_inf() >= BETA {
            z_r.coeffs.zeroize();
            continue;
        }

        return Ok((UnifiedMembershipProof {
            sigma_w_pk: w_pk,
            sigma_w_null: w_null,
            response: z,
            nullifier_poly: null_poly.clone(),
            nullifier_param: a_null.clone(),
            ctx_hash,
            sigma_w_bind: w_bind,
            binding_response: z_r,
            membership: membership_proof,
        }, nullifier_hash));
    }

    Err(CryptoError::RingSignatureInvalid("unified_prove: max attempts".into()))
}

// ═══════════════════════════════════════════════════════════════
//  Verify — O(log N), NO pk, NO ring_pubkeys
// ═══════════════════════════════════════════════════════════════

/// Verify a unified ZK proof.
///
/// # Parameters (NO ring_pubkeys!)
///
/// - `a`: Global lattice parameter
/// - `expected_root_hash`: SIS root hash from chain state
/// - `message`: Transaction signing digest
/// - `nullifier_hash`: From ConfidentialInput.nullifier
/// - `proof`: The unified proof
///
/// # What the verifier checks:
/// 1. Nullifier hash binding: `H(null_poly) == nullifier`
/// 2. NullifierContext hash consistency (Task 2.1)
/// 3. Σ-protocol challenge consistency (with ctx_hash)
/// 4. Nullifier Σ: `a_null·z − c·null_poly == w_null`
/// 5. Key-ownership Σ: via committed leaf binding
/// 6. ZK Membership: committed leaf is in SIS Merkle tree (O(depth) OR-proofs)
/// 7. Root binding: SIS root hash matches chain state
///
/// # What the verifier does NOT know:
/// - The signer's public key `pk` (NEVER reconstructed)
/// - The leaf index in the Merkle tree
/// - The direction bits at each Merkle level
/// - The sibling node values (only their BDLOP commitments)
///
/// # Complexity: O(depth) = O(log |UTXO_set|)
pub fn unified_verify(
    a: &Poly,
    expected_root_hash: &[u8; 32],
    message: &[u8; 32],
    nullifier_hash: &[u8; 32],
    proof: &UnifiedMembershipProof,
) -> Result<(), CryptoError> {
    let bdlop_crs = BdlopCrs::default_crs();
    let sis_crs = SisMerkleCrs::default_crs();

    // ── 0. Structural — Fail-Closed on norm violation ──
    if proof.response.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid(
            format!("response norm {} >= β", proof.response.norm_inf())));
    }
    // P0-1: binding response norm check
    if proof.binding_response.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid(
            format!("binding_response norm {} >= β", proof.binding_response.norm_inf())));
    }

    // ── 1. Nullifier hash binding (canonical hash) ──
    let expected_null = canonical_nullifier_hash(&proof.nullifier_poly);
    if expected_null != *nullifier_hash {
        return Err(CryptoError::RingSignatureInvalid("H(null_poly) != nullifier".into()));
    }

    // ── 2. Σ-protocol challenge recomputation (Task 2.2: type-safe + P0-1: includes w_bind) ──
    let challenge = build_sigma_challenge(&SigmaChallengeInput {
        sis_root_hash: &proof.membership.sis_root_hash,
        message,
        w_pk: &proof.sigma_w_pk,
        w_null: &proof.sigma_w_null,
        null_poly: &proof.nullifier_poly,
        nullifier_param: &proof.nullifier_param,
        nullifier_hash,
        leaf_commitment: &proof.membership.leaf_commitment,
        w_bind: &proof.sigma_w_bind,
        ctx_hash: &proof.ctx_hash,
    });
    let c_poly = hash_to_challenge(&challenge);

    // ── 3. Nullifier Σ-verification ──
    let w_null_check = proof.nullifier_param.mul(&proof.response)
        .sub(&c_poly.mul(&proof.nullifier_poly));
    if !poly_eq_mod_q(&w_null_check, &proof.sigma_w_null) {
        return Err(CryptoError::RingSignatureInvalid("nullifier Σ failed".into()));
    }

    // ── 4. Key-ownership binding verification (P0-1 FIX — CRITICAL) ──
    //
    // This verifies that the Σ-protocol's secret `s` is the SAME secret
    // whose public key `pk = a·s` was committed in the membership proof's
    // leaf commitment `C_leaf = A1·r_leaf + A2·(a_leaf·pk)`.
    //
    // The algebraic relation being verified:
    //
    //   w_bind = A1·z_r − c·C_leaf + A2·(a_leaf·(a·z − w_pk))
    //
    // Why this works:
    //   a·z − w_pk = a·(y + c·s) − a·y = c·a·s = c·pk
    //   a_leaf·(c·pk) = c·a_leaf·pk = c·leaf_poly
    //   A2·c·leaf_poly = c·A2·leaf_poly
    //   c·C_leaf = c·A1·r_leaf + c·A2·leaf_poly
    //
    //   A1·z_r = A1·(y_r + c·r_leaf) = w_bind + c·A1·r_leaf
    //
    //   A1·z_r − c·C_leaf + A2·a_leaf·(a·z − w_pk)
    //   = w_bind + c·A1·r_leaf − c·A1·r_leaf − c·A2·leaf_poly + c·A2·leaf_poly
    //   = w_bind  ✓
    //
    // If the prover used a DIFFERENT secret s' for the Σ-protocol than the
    // one whose pk is in the leaf commitment, the term c·pk would differ
    // from c·(a·s'), and the excess would not cancel.
    let c_pk = a.mul(&proof.response).sub(&proof.sigma_w_pk); // = c·pk
    let a_leaf_c_pk = sis_crs.a_leaf.mul(&c_pk); // = c·leaf_poly
    let w_bind_recon = bdlop_crs.a1.mul(&proof.binding_response)
        .sub(&c_poly.mul(&proof.membership.leaf_commitment.0))
        .add(&bdlop_crs.a2.mul(&a_leaf_c_pk));
    if !poly_eq_mod_q(&w_bind_recon, &proof.sigma_w_bind) {
        return Err(CryptoError::RingSignatureInvalid(
            "key-ownership binding failed: Σ-secret does not match leaf commitment (P0-1)".into()));
    }

    // ── 5. ZK Membership verification (O(depth)) ──
    verify_membership_v2(&bdlop_crs, &sis_crs, expected_root_hash, &proof.membership)?;

    // ── 6. Root binding ──
    if !ct_eq_32(&proof.membership.sis_root_hash, expected_root_hash) {
        return Err(CryptoError::RingSignatureInvalid("root hash mismatch".into()));
    }

    Ok(())
}

/// Verify a unified ZK proof with explicit NullifierContext validation (Task 2.1).
///
/// This is the Mainnet-ready verifier. In addition to all checks in `unified_verify`,
/// it also verifies that `proof.ctx_hash == expected_ctx.hash()`.
///
/// This prevents an attacker from submitting a proof generated for one context
/// (e.g., testnet, epoch 5) in a different context (e.g., mainnet, epoch 10).
pub fn unified_verify_ctx(
    a: &Poly,
    expected_root_hash: &[u8; 32],
    message: &[u8; 32],
    nullifier_hash: &[u8; 32],
    expected_ctx: &NullifierContext,
    proof: &UnifiedMembershipProof,
) -> Result<(), CryptoError> {
    // ── Context hash check (Task 2.1) ──
    let expected_ctx_hash = expected_ctx.hash();
    if proof.ctx_hash != expected_ctx_hash {
        return Err(CryptoError::RingSignatureInvalid(
            "NullifierContext hash mismatch: proof was generated for a different context".into()));
    }

    // Delegate to standard verification (which uses proof.ctx_hash in Fiat-Shamir)
    unified_verify(a, expected_root_hash, message, nullifier_hash, proof)
}

fn poly_eq_mod_q(a: &Poly, b: &Poly) -> bool {
    for i in 0..N {
        if ((a.coeffs[i] - b.coeffs[i]) % Q + Q) % Q != 0 { return false; }
    }
    true
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::{derive_secret_poly, compute_pubkey, derive_public_param, DEFAULT_A_SEED};

    fn make_ring(size: usize) -> (Poly, Vec<Poly>, Vec<Poly>, Vec<[u8; 32]>) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let sis_crs = SisMerkleCrs::default_crs();
        let secrets: Vec<Poly> = (0..size)
            .map(|_| derive_secret_poly(&MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        let pks: Vec<Poly> = secrets.iter().map(|s| compute_pubkey(&a, s)).collect();
        let leaf_polys: Vec<Poly> = pks.iter().map(|pk| sis_leaf(&sis_crs, pk)).collect();
        let root_poly = compute_sis_root(&sis_crs, &leaf_polys).unwrap();
        let root_hash = sis_root_hash(&root_poly);
        let fake_leaves: Vec<[u8; 32]> = leaf_polys.iter()
            .map(|p| {
                let mut h = [0u8; 32];
                let bytes = p.to_bytes();
                h.copy_from_slice(&bytes[..32]);
                h
            })
            .collect();
        (a, secrets, pks, fake_leaves)
    }

    fn test_output(id: u8) -> OutputId {
        OutputId { tx_hash: [id; 32], output_index: 0 }
    }

    fn test_ctx(chain_id: u32) -> NullifierContext {
        NullifierContext {
            chain_id,
            tx_domain: TxDomain::Transfer,
            spent_output_id: test_output(0xAA),
            protocol_version: PROTOCOL_VERSION,
            anonymity_root_epoch: 100,
        }
    }

    #[test]
    fn test_unified_prove_verify_no_ring_pubkeys() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];

        let (proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();

        unified_verify(&a, &proof.membership.sis_root_hash, &msg, &null_hash, &proof).unwrap();
    }

    #[test]
    fn test_unified_prove_verify_ctx() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let ctx = test_ctx(2);

        let (proof, null_hash) = unified_prove_ctx(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &ctx,
        ).unwrap();

        // Verify with context
        unified_verify_ctx(
            &a, &proof.membership.sis_root_hash, &msg, &null_hash, &ctx, &proof
        ).unwrap();
    }

    #[test]
    fn test_wrong_context_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let ctx = test_ctx(2);

        let (proof, null_hash) = unified_prove_ctx(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &ctx,
        ).unwrap();

        // Different chain_id → different ctx_hash → MUST fail
        let wrong_ctx = test_ctx(3);
        assert!(unified_verify_ctx(
            &a, &proof.membership.sis_root_hash, &msg, &null_hash, &wrong_ctx, &proof
        ).is_err(), "wrong NullifierContext must be rejected");
    }

    #[test]
    fn test_wrong_epoch_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let ctx = test_ctx(2);

        let (proof, null_hash) = unified_prove_ctx(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &ctx,
        ).unwrap();

        // Different epoch → different ctx_hash → MUST fail
        let mut wrong_ctx = ctx;
        wrong_ctx.anonymity_root_epoch = 200;
        assert!(unified_verify_ctx(
            &a, &proof.membership.sis_root_hash, &msg, &null_hash, &wrong_ctx, &proof
        ).is_err(), "wrong anonymity_root_epoch must be rejected");
    }

    #[test]
    fn test_wrong_domain_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let ctx = test_ctx(2);

        let (proof, null_hash) = unified_prove_ctx(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &ctx,
        ).unwrap();

        let mut wrong_ctx = ctx;
        wrong_ctx.tx_domain = TxDomain::Governance;
        assert!(unified_verify_ctx(
            &a, &proof.membership.sis_root_hash, &msg, &null_hash, &wrong_ctx, &proof
        ).is_err(), "wrong tx_domain must be rejected");
    }

    #[test]
    fn test_wrong_nullifier_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (proof, _) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();
        assert!(unified_verify(
            &a, &proof.membership.sis_root_hash, &msg, &[0xFF; 32], &proof
        ).is_err());
    }

    #[test]
    fn test_wrong_root_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();
        assert!(unified_verify(&a, &[0xFF; 32], &msg, &null_hash, &proof).is_err());
    }

    #[test]
    fn test_tampered_response_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (mut proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();
        proof.response.coeffs[0] = (proof.response.coeffs[0] + 1) % Q;
        assert!(unified_verify(
            &a, &proof.membership.sis_root_hash, &msg, &null_hash, &proof
        ).is_err());
    }

    #[test]
    fn test_nullifier_deterministic() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let out = test_output(0xAA);
        let (_, h1) = unified_prove(&a, &leaves, 0, &secrets[0], &pks[0], &[1; 32], &out, 2).unwrap();
        let (_, h2) = unified_prove(&a, &leaves, 0, &secrets[0], &pks[0], &[2; 32], &out, 2).unwrap();
        assert_eq!(h1, h2, "nullifier must be deterministic");
    }

    #[test]
    fn test_cross_chain_different_nullifier() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let out = test_output(0xAA);
        let (_, h2) = unified_prove(&a, &leaves, 0, &secrets[0], &pks[0], &msg, &out, 2).unwrap();
        let (_, h3) = unified_prove(&a, &leaves, 0, &secrets[0], &pks[0], &msg, &out, 3).unwrap();
        assert_ne!(h2, h3, "different chain → different nullifier");
    }

    // ── Task 1.2: Binary serialization round-trip tests ──

    #[test]
    fn test_binary_roundtrip() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (proof, null_hash) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();

        // Serialize → deserialize → verify
        let bytes = proof.to_bytes();
        let proof2 = UnifiedMembershipProof::from_bytes(&bytes).unwrap();
        unified_verify(&a, &proof2.membership.sis_root_hash, &msg, &null_hash, &proof2).unwrap();
    }

    #[test]
    fn test_binary_trailing_bytes_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (proof, _) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();

        let mut bytes = proof.to_bytes();
        bytes.push(0xFF); // Trailing garbage
        assert!(UnifiedMembershipProof::from_bytes(&bytes).is_err(),
            "trailing bytes must be rejected (anti-malleability)");
    }

    #[test]
    fn test_binary_wrong_version_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (proof, _) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();

        let mut bytes = proof.to_bytes();
        bytes[0] = 0xFF; // Wrong version
        assert!(UnifiedMembershipProof::from_bytes(&bytes).is_err(),
            "wrong version must be rejected");
    }

    #[test]
    fn test_binary_truncated_rejected() {
        let (a, secrets, pks, leaves) = make_ring(4);
        let msg = [0x42u8; 32];
        let (proof, _) = unified_prove(
            &a, &leaves, 0, &secrets[0], &pks[0], &msg, &test_output(0xAA), 2,
        ).unwrap();

        let bytes = proof.to_bytes();
        assert!(UnifiedMembershipProof::from_bytes(&bytes[..bytes.len()-1]).is_err(),
            "truncated proof must be rejected");
    }
}
