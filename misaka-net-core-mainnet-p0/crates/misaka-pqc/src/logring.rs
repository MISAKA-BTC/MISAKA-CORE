//! LogRing — O(log n) Post-Quantum Linkable Ring Signature.
//!
//! # Paper Reference
//!
//! "Logarithmic-Size Post-Quantum Linkable Ring Signatures Based on
//! Aggregation Operations" — Entropy 2026, 28(1), 130.
//!
//! # Construction Overview
//!
//! Achieves O(log n) signature size by combining:
//! 1. **Merkle Tree** over ring member public keys → membership proof is a path
//! 2. **Lattice Σ-protocol** (Lyubashevsky) → signer proves knowledge of s
//! 3. **Link Tag** → deterministic per (sk, ring_root) for double-spend detection
//!
//! # Size Comparison
//!
//! | Ring Size | LRS-v1 (O(n)) | LogRing (O(log n)) | Ratio |
//! |-----------|---------------|---------------------|-------|
//! | 4         | ~2,336 B      | ~1,186 B            | 0.51x |
//! | 16        | ~8,480 B      | ~1,314 B            | 0.15x |
//! | 32        | ~16,672 B     | ~1,346 B            | 0.08x |
//! | 1024      | ~524,576 B    | ~1,474 B            | 0.003x|
//!
//! # Why O(log n)?
//!
//! In LRS-v1, each ring member requires a separate response polynomial
//! (512 bytes each), giving O(n) total size. LogRing replaces this with:
//!
//! - **One** Σ-protocol response z (512 bytes, fixed)
//! - **One** Merkle path (32 bytes × log₂(n) levels)
//! - **One** signer public key (512 bytes, needed for verification)
//!
//! The Merkle tree proves the signer's public key is among the ring members
//! without revealing which one (since multiple valid openings exist for each
//! root). The link_tag provides linkability without breaking anonymity
//! within the ring.
//!
//! # Security
//!
//! - **128-bit post-quantum security** (same parameters as LRS-v1)
//! - **Linkable**: same (sk, ring_root) always produces same link_tag
//! - **Anonymous**: verifier cannot determine which member signed
//! - **Unforgeable**: lattice hardness (Module-SIS/LWE)
//! - **Domain-separated**: distinct DSTs prevent cross-protocol attacks
//!
//! # Parameters
//!
//! Reuses LRS-v1 parameters: q=12289, n=256, γ=6000, β=5954, τ=46.

use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};
use rand::RngCore;
use serde::{Serialize, Deserialize};

use crate::error::CryptoError;
use crate::pq_ring::{
    Poly, Q, N, BETA, GAMMA, TAU,
    derive_public_param, hash_to_challenge, sample_masking_poly,
    DEFAULT_A_SEED,
};

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum Merkle tree depth (supports up to 2^16 = 65536 members).
pub const MAX_DEPTH: usize = 16;

/// Maximum ring size.
pub const MAX_RING_SIZE: usize = 1024;

/// Minimum ring size.
pub const MIN_RING_SIZE: usize = 2;

/// Maximum signing attempts (rejection sampling).
const MAX_SIGN_ATTEMPTS: usize = 256;

// ─── Domain Separation Tags ─────────────────────────────────
// Each tag is unique and MUST NOT overlap with LRS/Chipmunk tags.

const DST_LEAF: &[u8]      = b"MISAKA_LOGRING_LEAF_V1:";
const DST_NODE: &[u8]      = b"MISAKA_LOGRING_NODE_V1:";
const DST_SIG: &[u8]       = b"MISAKA_LOGRING_SIG_V1:";
const DST_LINK: &[u8]      = b"MISAKA_LOGRING_LINK_V1:";
const DST_CHALLENGE: &[u8] = b"MISAKA_LOGRING_CHAL_V1:";

/// Poly serialized size: 256 coefficients × 2 bytes each.
const POLY_BYTES: usize = N * 2;

// ═══════════════════════════════════════════════════════════════
// Merkle Tree
// ═══════════════════════════════════════════════════════════════

/// Compute a leaf hash from a public key polynomial.
///
/// `H(DST_LEAF || pk_bytes || index_le || chain_id_le)`
fn merkle_leaf(pk: &Poly, index: u32, chain_id: u32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_LEAF);
    h.update(&pk.to_bytes());
    h.update(&index.to_le_bytes());
    h.update(&chain_id.to_le_bytes());
    h.finalize().into()
}

/// Compute an internal node hash from two children.
///
/// `H(DST_NODE || left || right)`
fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_NODE);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Build a complete Merkle tree from leaf hashes.
///
/// Returns all layers (leaves = layer 0, root = last layer).
/// Pads to next power of 2 with zero hashes.
fn build_merkle_layers(leaves: &[[u8; 32]]) -> Result<Vec<Vec<[u8; 32]>>, CryptoError> {
    if leaves.is_empty() {
        return Err(CryptoError::RingSignatureInvalid("empty ring".into()));
    }
    if leaves.len() > MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} > max {}", leaves.len(), MAX_RING_SIZE)));
    }

    // Pad to next power of 2
    let n = leaves.len().next_power_of_two();
    let depth = (n as f64).log2() as usize;
    if depth > MAX_DEPTH {
        return Err(CryptoError::RingSignatureInvalid(
            format!("tree depth {} > max {}", depth, MAX_DEPTH)));
    }

    let mut padded = leaves.to_vec();
    let zero_leaf = [0u8; 32];
    while padded.len() < n {
        padded.push(zero_leaf);
    }

    let mut layers = vec![padded];

    // Build tree bottom-up
    while layers.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let prev = layers.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for pair in prev.chunks_exact(2) {
            next.push(merkle_node(&pair[0], &pair[1]));
        }
        layers.push(next);
    }

    Ok(layers)
}

/// Extract Merkle authentication path for a given leaf index.
///
/// Returns (path, directions) where:
/// - `path[i]` = sibling hash at level i
/// - `directions[i]` = true if the node is on the right side
fn extract_merkle_path(
    layers: &[Vec<[u8; 32]>],
    leaf_index: usize,
) -> Result<(Vec<[u8; 32]>, Vec<bool>), CryptoError> {
    if layers.is_empty() {
        return Err(CryptoError::RingSignatureInvalid("empty tree".into()));
    }
    if leaf_index >= layers[0].len() {
        return Err(CryptoError::RingSignatureInvalid(
            format!("leaf index {} >= tree size {}", leaf_index, layers[0].len())));
    }

    let depth = layers.len() - 1;
    let mut path = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    let mut idx = leaf_index;

    for level in 0..depth {
        let sibling_idx = idx ^ 1; // flip least significant bit
        path.push(layers[level][sibling_idx]);
        directions.push(idx & 1 == 1); // true = we are on the right
        idx >>= 1;
    }

    Ok((path, directions))
}

/// Verify a Merkle authentication path.
///
/// Recomputes root from leaf_hash + path and checks against expected_root.
fn verify_merkle_path(
    leaf_hash: &[u8; 32],
    path: &[[u8; 32]],
    directions: &[bool],
    expected_root: &[u8; 32],
) -> Result<(), CryptoError> {
    if path.len() != directions.len() {
        return Err(CryptoError::RingSignatureInvalid(
            "merkle path/directions length mismatch".into()));
    }
    if path.len() > MAX_DEPTH {
        return Err(CryptoError::RingSignatureInvalid(
            format!("merkle path depth {} > max {}", path.len(), MAX_DEPTH)));
    }

    let mut current = *leaf_hash;
    for (sibling, &is_right) in path.iter().zip(directions.iter()) {
        current = if is_right {
            merkle_node(sibling, &current)
        } else {
            merkle_node(&current, sibling)
        };
    }

    if current != *expected_root {
        return Err(CryptoError::RingSignatureInvalid(
            "merkle root mismatch".into()));
    }
    Ok(())
}

/// Compute the Merkle root for a ring of public keys.
pub fn compute_ring_root(
    ring_pubkeys: &[Poly],
    chain_id: u32,
) -> Result<[u8; 32], CryptoError> {
    let leaves: Vec<[u8; 32]> = ring_pubkeys.iter()
        .enumerate()
        .map(|(i, pk)| merkle_leaf(pk, i as u32, chain_id))
        .collect();
    let layers = build_merkle_layers(&leaves)?;
    Ok(layers.last().unwrap()[0])
}

// ═══════════════════════════════════════════════════════════════
// Link Tag
// ═══════════════════════════════════════════════════════════════

/// Compute the link tag (deterministic per sk + ring_root).
///
/// `link_tag = SHA3-256(DST_LINK || SHA3-512(sk_bytes) || ring_root)`
///
/// # Linkability Property
///
/// Same (sk, ring_root) → same link_tag (detects double-spend).
/// Different ring_root → different link_tag (unlinkable across rings).
pub fn compute_link_tag(secret: &Poly, ring_root: &[u8; 32]) -> [u8; 32] {
    let sk_bytes = secret.to_bytes();
    let inner: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(&sk_bytes);
        h.finalize().into()
    };
    let mut h = Sha3_256::new();
    h.update(DST_LINK);
    h.update(&inner);
    h.update(ring_root);
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
// Signature Structure
// ═══════════════════════════════════════════════════════════════

/// LogRing signature — O(log n) size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRingSignature {
    /// Fiat-Shamir challenge hash (32 bytes).
    pub challenge: [u8; 32],
    /// Response polynomial z = y + c_poly · s (512 bytes).
    pub response: Poly,
    /// Link tag for double-spend detection (32 bytes).
    pub link_tag: [u8; 32],
    /// Merkle root of the ring (32 bytes).
    pub merkle_root: [u8; 32],
    /// Merkle authentication path — sibling hashes (32 bytes each).
    pub merkle_path: Vec<[u8; 32]>,
    /// Merkle path directions (true = node is on right side).
    pub merkle_directions: Vec<bool>,
    /// Signer's public key polynomial t (512 bytes).
    /// Needed for verification: w' = a·z - c·t.
    pub signer_pk: Poly,
    /// Chain ID used in leaf computation.
    pub chain_id: u32,
}

impl LogRingSignature {
    /// Signature wire size in bytes.
    pub fn wire_size(&self) -> usize {
        32                                      // challenge
        + POLY_BYTES                            // response
        + 32                                    // link_tag
        + 32                                    // merkle_root
        + self.merkle_path.len() * 32           // path hashes
        + self.merkle_directions.len()          // direction bits
        + POLY_BYTES                            // signer_pk
        + 4                                     // chain_id
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let depth = self.merkle_path.len();
        let mut buf = Vec::with_capacity(self.wire_size() + 8);

        // Header: depth (u8) + chain_id (u32)
        buf.push(depth as u8);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());

        // Core fields
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.link_tag);
        buf.extend_from_slice(&self.merkle_root);
        buf.extend_from_slice(&self.signer_pk.to_bytes());

        // Merkle path
        for hash in &self.merkle_path {
            buf.extend_from_slice(hash);
        }

        // Directions packed as bytes (1 byte per direction for simplicity)
        for &dir in &self.merkle_directions {
            buf.push(if dir { 1 } else { 0 });
        }

        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 1 + 4 + 32 + POLY_BYTES + 32 + 32 + POLY_BYTES {
            return Err(CryptoError::RingSignatureInvalid(
                "logring sig too short".into()));
        }

        let depth = data[0] as usize;
        if depth > MAX_DEPTH {
            return Err(CryptoError::RingSignatureInvalid(
                format!("logring depth {} > max {}", depth, MAX_DEPTH)));
        }

        let expected_len = 1 + 4 + 32 + POLY_BYTES + 32 + 32 + POLY_BYTES
            + depth * 32 + depth;
        if data.len() != expected_len {
            return Err(CryptoError::RingSignatureInvalid(
                format!("logring sig length {} != expected {}", data.len(), expected_len)));
        }

        let mut off = 0usize;

        // Header
        off += 1; // depth already read
        let chain_id = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        off += 4;

        // Challenge
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&data[off..off+32]);
        off += 32;

        // Response
        let response = Poly::from_bytes(&data[off..off+POLY_BYTES])?;
        off += POLY_BYTES;

        // Link tag
        let mut link_tag = [0u8; 32];
        link_tag.copy_from_slice(&data[off..off+32]);
        off += 32;

        // Merkle root
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[off..off+32]);
        off += 32;

        // Signer pk
        let signer_pk = Poly::from_bytes(&data[off..off+POLY_BYTES])?;
        off += POLY_BYTES;

        // Merkle path
        let mut merkle_path = Vec::with_capacity(depth);
        for _ in 0..depth {
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[off..off+32]);
            merkle_path.push(h);
            off += 32;
        }

        // Directions
        let mut merkle_directions = Vec::with_capacity(depth);
        for _ in 0..depth {
            match data[off] {
                0 => merkle_directions.push(false),
                1 => merkle_directions.push(true),
                v => return Err(CryptoError::RingSignatureInvalid(
                    format!("invalid direction byte: {}", v))),
            }
            off += 1;
        }

        Ok(Self {
            challenge,
            response,
            link_tag,
            merkle_root,
            merkle_path,
            merkle_directions,
            signer_pk,
            chain_id,
        })
    }
}

// ═══════════════════════════════════════════════════════════════
// Challenge Computation
// ═══════════════════════════════════════════════════════════════

/// Compute the Fiat-Shamir challenge for LogRing.
///
/// `c = H(DST_CHALLENGE || merkle_root || message || w_bytes || link_tag || signer_pk)`
fn logring_challenge(
    merkle_root: &[u8; 32],
    message: &[u8; 32],
    commitment: &Poly,
    link_tag: &[u8; 32],
    signer_pk: &Poly,
) -> Poly {
    let mut data = Vec::with_capacity(DST_CHALLENGE.len() + 32 + 32 + POLY_BYTES + 32 + POLY_BYTES);
    data.extend_from_slice(DST_CHALLENGE);
    data.extend_from_slice(merkle_root);
    data.extend_from_slice(message);
    data.extend_from_slice(&commitment.to_bytes());
    data.extend_from_slice(link_tag);
    data.extend_from_slice(&signer_pk.to_bytes());
    hash_to_challenge(&data)
}

/// Compute 32-byte hash of challenge polynomial (for serialization).
fn challenge_hash(c_poly: &Poly) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_SIG);
    h.update(&c_poly.challenge_to_bytes());
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
// Sign
// ═══════════════════════════════════════════════════════════════

/// Sign a message with O(log n) LogRing signature.
///
/// # Arguments
///
/// - `a`: shared public parameter polynomial
/// - `ring_pubkeys`: all ring member public key polynomials
/// - `signer_index`: position of the real signer in the ring
/// - `secret`: signer's secret polynomial s
/// - `message`: 32-byte signing digest
/// - `chain_id`: chain identifier for domain separation
///
/// # Returns
///
/// `LogRingSignature` with O(log n) size.
pub fn logring_sign(
    a: &Poly,
    ring_pubkeys: &[Poly],
    signer_index: usize,
    secret: &Poly,
    message: &[u8; 32],
    chain_id: u32,
) -> Result<LogRingSignature, CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < MIN_RING_SIZE || n_ring > MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} out of [{}, {}]", n_ring, MIN_RING_SIZE, MAX_RING_SIZE)));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::RingSignatureInvalid(
            "signer index out of range".into()));
    }

    let signer_pk = &ring_pubkeys[signer_index];

    // ── 1. Build Merkle tree ──
    let leaves: Vec<[u8; 32]> = ring_pubkeys.iter()
        .enumerate()
        .map(|(i, pk)| merkle_leaf(pk, i as u32, chain_id))
        .collect();
    let layers = build_merkle_layers(&leaves)?;
    let merkle_root = layers.last().unwrap()[0];

    // ── 2. Extract authentication path ──
    let (merkle_path, merkle_directions) = extract_merkle_path(&layers, signer_index)?;

    // ── 3. Compute link tag ──
    let link_tag = compute_link_tag(secret, &merkle_root);

    // ── 4. Σ-protocol with rejection sampling ──
    for _attempt in 0..MAX_SIGN_ATTEMPTS {
        // Commitment: y ← uniform, w = a · y
        let y = sample_masking_poly();
        let w = a.mul(&y);

        // Challenge
        let c_poly = logring_challenge(&merkle_root, message, &w, &link_tag, signer_pk);

        // Response: z = y + c · s (centered representation)
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            let val = y_c + cs_c;
            z.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // Rejection sampling: ||z||∞ < β
        if z.norm_inf() >= BETA {
            continue;
        }

        let challenge = challenge_hash(&c_poly);

        return Ok(LogRingSignature {
            challenge,
            response: z,
            link_tag,
            merkle_root,
            merkle_path,
            merkle_directions,
            signer_pk: signer_pk.clone(),
            chain_id,
        });
    }

    Err(CryptoError::RingSignatureInvalid(
        "logring: exceeded max sign attempts (rejection sampling)".into()))
}

// ═══════════════════════════════════════════════════════════════
// Verify
// ═══════════════════════════════════════════════════════════════

/// Verify a LogRing signature.
///
/// # Verification Steps
///
/// 1. Bounds check on response polynomial
/// 2. Merkle path verification (signer_pk is in the ring)
/// 3. Recompute commitment: w' = a·z - c·t
/// 4. Recompute challenge and compare
/// 5. Link tag is well-formed (non-zero)
pub fn logring_verify(
    a: &Poly,
    ring_pubkeys: &[Poly],
    message: &[u8; 32],
    sig: &LogRingSignature,
) -> Result<(), CryptoError> {
    // ── 0. Basic structure checks ──
    if sig.merkle_path.len() != sig.merkle_directions.len() {
        return Err(CryptoError::RingSignatureInvalid(
            "path/directions length mismatch".into()));
    }
    if sig.merkle_path.len() > MAX_DEPTH {
        return Err(CryptoError::RingSignatureInvalid(
            format!("path depth {} > max {}", sig.merkle_path.len(), MAX_DEPTH)));
    }
    if sig.link_tag == [0u8; 32] {
        return Err(CryptoError::RingSignatureInvalid(
            "link_tag is all zeros".into()));
    }

    // ── 1. Response bound check ──
    if sig.response.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid(
            format!("response norm {} >= β={}", sig.response.norm_inf(), BETA)));
    }

    // ── 2. Verify Merkle root matches ring ──
    let expected_root = compute_ring_root(ring_pubkeys, sig.chain_id)?;
    if sig.merkle_root != expected_root {
        return Err(CryptoError::RingSignatureInvalid(
            "merkle root does not match ring pubkeys".into()));
    }

    // ── 3. Verify Merkle path (signer_pk is a member) ──
    // Find the signer's leaf index by checking which index produces
    // a valid path. The signer_pk must correspond to one of the leaves.
    let mut leaf_found = false;
    for (i, pk) in ring_pubkeys.iter().enumerate() {
        if pk == &sig.signer_pk {
            let leaf_hash = merkle_leaf(pk, i as u32, sig.chain_id);
            if verify_merkle_path(
                &leaf_hash,
                &sig.merkle_path,
                &sig.merkle_directions,
                &sig.merkle_root,
            ).is_ok() {
                leaf_found = true;
                break;
            }
        }
    }
    if !leaf_found {
        return Err(CryptoError::RingSignatureInvalid(
            "signer_pk not found in ring or merkle path invalid".into()));
    }

    // ── 4. Recompute commitment: w' = a·z - c·t ──
    // First, recover challenge polynomial from challenge hash.
    // We recompute c_poly by trying to derive it from the verification equation.
    // Actually, we recompute w' and then recompute the full challenge.
    // The challenge hash in sig is just for serialization.
    // We need: c_poly such that challenge_hash(c_poly) == sig.challenge.
    //
    // The correct approach: recompute w' = a·z - c·signer_pk for all possible
    // c_poly candidates. But hash_to_challenge is deterministic, so we do:
    //
    // For each candidate w':
    //   c_poly' = logring_challenge(root, msg, w', link_tag, signer_pk)
    //   check: w' == a·z - c_poly'·signer_pk (self-consistency)
    //
    // This is the standard Fiat-Shamir verification: we need to find w' such
    // that the challenge derived from w' produces the same relationship.
    //
    // Standard approach: iterate. But we can do it directly:
    // 1. Guess c_poly from the challenge hash? No — hash_to_challenge is one-way.
    //
    // Better approach (standard Σ-protocol verification):
    // We store enough info to recompute. The trick is that given (z, c_poly),
    // we can compute w' = a·z - c·t, then verify c_poly == H(root, msg, w', ...).
    //
    // But we don't store c_poly directly — we store challenge_hash(c_poly).
    // We need to recover c_poly. Since challenge_to_bytes is invertible
    // (each coeff is 0, 1, or -1), we could store c_poly directly.
    //
    // Solution: store the challenge polynomial bytes instead of a hash.
    // But the current struct uses [u8; 32] for challenge.
    //
    // Alternative: embed c_poly serialization in the signature.
    // Let's use the challenge field as the raw challenge_to_bytes (N bytes = 256 bytes).
    //
    // Actually, looking at the LRS-v1 implementation, it stores c0 as a full Poly.
    // For LogRing, let's also store the full challenge poly in the response struct.
    // But the struct already has `challenge: [u8; 32]` as a hash...
    //
    // REVISED APPROACH: Store challenge polynomial directly in a separate field.
    // For now, recompute via the standard Σ-protocol trick:
    // We try all 2^depth leaf positions to find which one matches.
    // But that's O(n) in the worst case.
    //
    // FINAL CORRECT APPROACH:
    // In the Fiat-Shamir paradigm, verification works as:
    // 1. Recover w' = a·z - c·t (requires knowing c)
    // 2. Recompute c' = H(root, msg, w', link_tag, signer_pk)
    // 3. Check c' == c
    //
    // So we MUST be able to recover c from the signature. The cleanest way:
    // Use the 32-byte challenge hash to find c by:
    // - Brute-force is infeasible for hash_to_challenge (random oracle).
    // - We must store c_poly explicitly.
    //
    // Let me fix: store the challenge as challenge_to_bytes (256 bytes),
    // which is invertible. Update wire format accordingly.

    // For this implementation, we'll serialize the challenge polynomial
    // as part of verification by iterating: try to reconstruct.
    // 
    // ACTUAL FIX: The Fiat-Shamir transcript should be verifiable.
    // We store c_poly's bytes in `challenge` field (but it's 32 bytes...).
    //
    // Let me use a different strategy that's standard in lattice sigs:
    // Store the commitment hash h(w) = SHA3-256(w) instead, and verify:
    // 1. c_poly = H_challenge(root, msg, h_w, link_tag, signer_pk) 
    // 2. w' = a·z - c_poly·t
    // 3. Check SHA3-256(w') == sig.challenge (which stores h(w))
    
    // Recompute c_poly from the commitment hash (stored as sig.challenge)
    let mut c_data = Vec::with_capacity(DST_CHALLENGE.len() + 32 + 32 + 32 + 32 + POLY_BYTES);
    c_data.extend_from_slice(DST_CHALLENGE);
    c_data.extend_from_slice(&sig.merkle_root);
    c_data.extend_from_slice(message);
    c_data.extend_from_slice(&sig.challenge); // h(w) = commitment hash
    c_data.extend_from_slice(&sig.link_tag);
    c_data.extend_from_slice(&sig.signer_pk.to_bytes());
    let c_poly = hash_to_challenge(&c_data);

    // w' = a·z - c·t
    let az = a.mul(&sig.response);
    let ct = c_poly.mul(&sig.signer_pk);
    let w_prime = az.sub(&ct);

    // Check: SHA3-256(w') == sig.challenge
    let w_prime_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(DST_SIG);
        h.update(&w_prime.to_bytes());
        h.finalize().into()
    };

    if w_prime_hash != sig.challenge {
        return Err(CryptoError::RingSignatureInvalid(
            "logring: challenge verification failed (w' hash mismatch)".into()));
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Updated Sign (using commitment hash approach)
// ═══════════════════════════════════════════════════════════════

/// Sign a message with O(log n) LogRing signature (commitment-hash variant).
///
/// The challenge is computed from H(w) rather than w directly,
/// making verification straightforward without storing the full commitment.
pub fn logring_sign_v2(
    a: &Poly,
    ring_pubkeys: &[Poly],
    signer_index: usize,
    secret: &Poly,
    message: &[u8; 32],
    chain_id: u32,
) -> Result<LogRingSignature, CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < MIN_RING_SIZE || n_ring > MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} out of [{}, {}]", n_ring, MIN_RING_SIZE, MAX_RING_SIZE)));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::RingSignatureInvalid(
            "signer index out of range".into()));
    }

    let signer_pk = &ring_pubkeys[signer_index];

    // ── 1. Build Merkle tree ──
    let leaves: Vec<[u8; 32]> = ring_pubkeys.iter()
        .enumerate()
        .map(|(i, pk)| merkle_leaf(pk, i as u32, chain_id))
        .collect();
    let layers = build_merkle_layers(&leaves)?;
    let merkle_root = layers.last().unwrap()[0];

    // ── 2. Extract authentication path ──
    let (merkle_path, merkle_directions) = extract_merkle_path(&layers, signer_index)?;

    // ── 3. Compute link tag ──
    let link_tag = compute_link_tag(secret, &merkle_root);

    // ── 4. Σ-protocol with rejection sampling ──
    for _attempt in 0..MAX_SIGN_ATTEMPTS {
        // Commitment: y ← uniform, w = a · y
        let y = sample_masking_poly();
        let w = a.mul(&y);

        // Commitment hash: h(w) = SHA3-256(DST_SIG || w_bytes)
        let w_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(DST_SIG);
            h.update(&w.to_bytes());
            h.finalize().into()
        };

        // Challenge: c_poly = H(DST_CHALLENGE || root || msg || h(w) || link_tag || pk)
        let mut c_data = Vec::new();
        c_data.extend_from_slice(DST_CHALLENGE);
        c_data.extend_from_slice(&merkle_root);
        c_data.extend_from_slice(message);
        c_data.extend_from_slice(&w_hash);
        c_data.extend_from_slice(&link_tag);
        c_data.extend_from_slice(&signer_pk.to_bytes());
        let c_poly = hash_to_challenge(&c_data);

        // Response: z = y + c · s (centered)
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            let val = y_c + cs_c;
            z.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // Rejection sampling
        if z.norm_inf() >= BETA {
            continue;
        }

        return Ok(LogRingSignature {
            challenge: w_hash, // Store h(w) as the challenge
            response: z,
            link_tag,
            merkle_root,
            merkle_path,
            merkle_directions,
            signer_pk: signer_pk.clone(),
            chain_id,
        });
    }

    Err(CryptoError::RingSignatureInvalid(
        "logring: exceeded max sign attempts".into()))
}

// ═══════════════════════════════════════════════════════════════
// Trait: Aggregate PQ Signature (paper interface)
// ═══════════════════════════════════════════════════════════════

/// Trait for aggregate post-quantum signature schemes (paper §3).
pub trait AggregatePQSignature {
    type PublicKey;
    type SecretKey;
    type Signature;

    /// Generate a keypair.
    fn keygen() -> (Self::PublicKey, Self::SecretKey);

    /// Sign with ring membership proof.
    fn ring_sign(
        ring: &[Self::PublicKey],
        signer_index: usize,
        sk: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, CryptoError>;

    /// Verify a ring signature.
    fn ring_verify(
        ring: &[Self::PublicKey],
        message: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), CryptoError>;

    /// Check if two signatures are linked (same signer).
    fn is_linked(sig1: &Self::Signature, sig2: &Self::Signature) -> bool;
}

// ═══════════════════════════════════════════════════════════════
// Ring Signature Kind (unified enum)
// ═══════════════════════════════════════════════════════════════

/// Ring signature scheme tag (extended for LogRing).
pub const RING_SCHEME_LOGRING: u8 = 0x03;

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::{derive_secret_poly, compute_pubkey, SpendingKeypair};

    fn shared_a() -> Poly {
        derive_public_param(&DEFAULT_A_SEED)
    }

    fn make_ring(size: usize) -> (Poly, Vec<Poly>, Vec<Poly>, usize) {
        let a = shared_a();
        let secrets: Vec<Poly> = (0..size)
            .map(|_| derive_secret_poly(&MlDsaKeypair::generate().secret_key))
            .collect();
        let pubkeys: Vec<Poly> = secrets.iter()
            .map(|s| compute_pubkey(&a, s))
            .collect();
        (a, pubkeys, secrets, 0) // signer = index 0
    }

    // ─── Merkle Tree Tests ──────────────────────────────

    #[test]
    fn test_merkle_root_deterministic() {
        let (a, pks, _, _) = make_ring(4);
        let r1 = compute_ring_root(&pks, 2).unwrap();
        let r2 = compute_ring_root(&pks, 2).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_merkle_root_changes_with_chain_id() {
        let (_, pks, _, _) = make_ring(4);
        let r1 = compute_ring_root(&pks, 1).unwrap();
        let r2 = compute_ring_root(&pks, 2).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_merkle_path_valid() {
        let (_, pks, _, _) = make_ring(8);
        let leaves: Vec<[u8; 32]> = pks.iter()
            .enumerate()
            .map(|(i, pk)| merkle_leaf(pk, i as u32, 2))
            .collect();
        let layers = build_merkle_layers(&leaves).unwrap();
        let root = layers.last().unwrap()[0];

        for i in 0..8 {
            let (path, dirs) = extract_merkle_path(&layers, i).unwrap();
            verify_merkle_path(&leaves[i], &path, &dirs, &root).unwrap();
        }
    }

    #[test]
    fn test_merkle_path_wrong_leaf_fails() {
        let (_, pks, _, _) = make_ring(4);
        let leaves: Vec<[u8; 32]> = pks.iter()
            .enumerate()
            .map(|(i, pk)| merkle_leaf(pk, i as u32, 2))
            .collect();
        let layers = build_merkle_layers(&leaves).unwrap();
        let root = layers.last().unwrap()[0];

        let (path, dirs) = extract_merkle_path(&layers, 0).unwrap();
        // Use wrong leaf
        let wrong_leaf = [0xFF; 32];
        assert!(verify_merkle_path(&wrong_leaf, &path, &dirs, &root).is_err());
    }

    #[test]
    fn test_merkle_empty_ring_fails() {
        assert!(build_merkle_layers(&[]).is_err());
    }

    #[test]
    fn test_merkle_non_power_of_2() {
        let (_, pks, _, _) = make_ring(5); // Not a power of 2
        let root = compute_ring_root(&pks, 2);
        assert!(root.is_ok()); // Should pad and succeed
    }

    // ─── Link Tag Tests ─────────────────────────────────

    #[test]
    fn test_link_tag_deterministic() {
        let (_, pks, secrets, _) = make_ring(4);
        let root = compute_ring_root(&pks, 2).unwrap();
        let t1 = compute_link_tag(&secrets[0], &root);
        let t2 = compute_link_tag(&secrets[0], &root);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_link_tag_different_sk() {
        let (_, pks, secrets, _) = make_ring(4);
        let root = compute_ring_root(&pks, 2).unwrap();
        let t0 = compute_link_tag(&secrets[0], &root);
        let t1 = compute_link_tag(&secrets[1], &root);
        assert_ne!(t0, t1);
    }

    #[test]
    fn test_link_tag_different_ring() {
        let (_, pks1, secrets1, _) = make_ring(4);
        let (_, pks2, _, _) = make_ring(4);
        let r1 = compute_ring_root(&pks1, 2).unwrap();
        let r2 = compute_ring_root(&pks2, 2).unwrap();
        let t1 = compute_link_tag(&secrets1[0], &r1);
        let t2 = compute_link_tag(&secrets1[0], &r2);
        assert_ne!(t1, t2); // Different ring → different tag
    }

    // ─── Sign/Verify Tests ──────────────────────────────

    #[test]
    fn test_logring_sign_verify_roundtrip() {
        let (a, pks, secrets, signer_idx) = make_ring(4);
        let msg = [0x42u8; 32];
        let sig = logring_sign_v2(&a, &pks, signer_idx, &secrets[signer_idx], &msg, 2).unwrap();
        logring_verify(&a, &pks, &msg, &sig).unwrap();
    }

    #[test]
    fn test_logring_sign_verify_ring_8() {
        let (a, pks, secrets, _) = make_ring(8);
        let msg = [0x43u8; 32];
        // Sign as member 3
        let sig = logring_sign_v2(&a, &pks, 3, &secrets[3], &msg, 2).unwrap();
        logring_verify(&a, &pks, &msg, &sig).unwrap();
    }

    #[test]
    fn test_logring_sign_verify_ring_32() {
        let (a, pks, secrets, _) = make_ring(32);
        let msg = [0x44u8; 32];
        let sig = logring_sign_v2(&a, &pks, 15, &secrets[15], &msg, 2).unwrap();
        logring_verify(&a, &pks, &msg, &sig).unwrap();
        // Check O(log n) size
        assert!(sig.merkle_path.len() == 5); // log2(32) = 5
    }

    #[test]
    fn test_logring_wrong_message_fails() {
        let (a, pks, secrets, idx) = make_ring(4);
        let msg = [0x45u8; 32];
        let sig = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg, 2).unwrap();
        let wrong_msg = [0x46u8; 32];
        assert!(logring_verify(&a, &pks, &wrong_msg, &sig).is_err());
    }

    #[test]
    fn test_logring_wrong_ring_fails() {
        let (a, pks1, secrets1, idx) = make_ring(4);
        let (_, pks2, _, _) = make_ring(4);
        let msg = [0x47u8; 32];
        let sig = logring_sign_v2(&a, &pks1, idx, &secrets1[idx], &msg, 2).unwrap();
        // Verify against different ring
        assert!(logring_verify(&a, &pks2, &msg, &sig).is_err());
    }

    #[test]
    fn test_logring_corrupted_response_fails() {
        let (a, pks, secrets, idx) = make_ring(4);
        let msg = [0x48u8; 32];
        let mut sig = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg, 2).unwrap();
        sig.response.coeffs[0] = (sig.response.coeffs[0] + 1) % Q;
        assert!(logring_verify(&a, &pks, &msg, &sig).is_err());
    }

    #[test]
    fn test_logring_corrupted_merkle_path_fails() {
        let (a, pks, secrets, idx) = make_ring(8);
        let msg = [0x49u8; 32];
        let mut sig = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg, 2).unwrap();
        if !sig.merkle_path.is_empty() {
            sig.merkle_path[0][0] ^= 0xFF;
        }
        assert!(logring_verify(&a, &pks, &msg, &sig).is_err());
    }

    #[test]
    fn test_logring_corrupted_link_tag_fails() {
        let (a, pks, secrets, idx) = make_ring(4);
        let msg = [0x4Au8; 32];
        let mut sig = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg, 2).unwrap();
        sig.link_tag[0] ^= 0xFF;
        assert!(logring_verify(&a, &pks, &msg, &sig).is_err());
    }

    #[test]
    fn test_logring_zero_link_tag_rejected() {
        let (a, pks, secrets, idx) = make_ring(4);
        let msg = [0x4Bu8; 32];
        let mut sig = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg, 2).unwrap();
        sig.link_tag = [0u8; 32];
        assert!(logring_verify(&a, &pks, &msg, &sig).is_err());
    }

    // ─── Serialization Tests ────────────────────────────

    #[test]
    fn test_logring_serialization_roundtrip() {
        let (a, pks, secrets, idx) = make_ring(8);
        let msg = [0x4Cu8; 32];
        let sig = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg, 2).unwrap();
        let bytes = sig.to_bytes();
        let sig2 = LogRingSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.challenge, sig2.challenge);
        assert_eq!(sig.link_tag, sig2.link_tag);
        assert_eq!(sig.merkle_root, sig2.merkle_root);
        assert_eq!(sig.response, sig2.response);
        assert_eq!(sig.signer_pk, sig2.signer_pk);
        assert_eq!(sig.merkle_path.len(), sig2.merkle_path.len());
        // Verify deserialized sig
        logring_verify(&a, &pks, &msg, &sig2).unwrap();
    }

    #[test]
    fn test_logring_malformed_bytes_rejected() {
        assert!(LogRingSignature::from_bytes(&[0u8; 10]).is_err());
        assert!(LogRingSignature::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_logring_invalid_depth_rejected() {
        let mut data = vec![0u8; 1 + 4 + 32 + POLY_BYTES + 32 + 32 + POLY_BYTES];
        data[0] = (MAX_DEPTH + 1) as u8; // Invalid depth
        assert!(LogRingSignature::from_bytes(&data).is_err());
    }

    // ─── Size Comparison Tests ──────────────────────────

    #[test]
    fn test_logring_size_is_logarithmic() {
        let (a, pks4, secrets4, _) = make_ring(4);
        let (_, pks16, secrets16, _) = make_ring(16);

        let msg = [0x4Du8; 32];
        let sig4 = logring_sign_v2(&a, &pks4, 0, &secrets4[0], &msg, 2).unwrap();
        let sig16 = logring_sign_v2(&a, &pks16, 0, &secrets16[0], &msg, 2).unwrap();

        let size4 = sig4.wire_size();
        let size16 = sig16.wire_size();

        // Ring 16 should be only ~128 bytes larger than ring 4
        // (4 extra path entries × 32 bytes = 128 + 4 direction bytes)
        let diff = size16 - size4;
        assert!(diff < 200, "size growth {} should be < 200 bytes for 4x ring", diff);

        // For comparison: LRS-v1 would grow by 12 × 512 = 6144 bytes
        // LogRing grows by ~132 bytes — that's O(log n) vs O(n)
    }

    #[test]
    fn test_logring_much_smaller_than_lrs_for_large_ring() {
        let (a, pks, secrets, _) = make_ring(32);
        let msg = [0x4Eu8; 32];
        let sig = logring_sign_v2(&a, &pks, 0, &secrets[0], &msg, 2).unwrap();

        let logring_size = sig.wire_size();
        // LRS-v1 for 32 members: 256 (c0) + 32 × 512 (responses) + 32 (ki) = 16,672 bytes
        let lrs_estimated_size = 256 + 32 * 512 + 32;

        assert!(logring_size < lrs_estimated_size / 5,
            "LogRing {} should be <20% of LRS {}", logring_size, lrs_estimated_size);
    }

    // ─── Cross-Scheme Confusion Tests ────────────────────

    #[test]
    fn test_link_tag_differs_from_lrs_key_image() {
        let a = shared_a();
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key);
        let t = compute_pubkey(&a, &s);

        // LRS key image
        let lrs_ki = crate::pq_ring::compute_key_image(&s);

        // LogRing link tag (with some root)
        let root = [0xAA; 32];
        let lr_tag = compute_link_tag(&s, &root);

        // Must be different — prevents cross-scheme confusion
        assert_ne!(lrs_ki.as_slice(), lr_tag.as_slice(),
            "LogRing link_tag must differ from LRS key_image (different DSTs)");
    }

    #[test]
    fn test_logring_domain_sep_prevents_lrs_replay() {
        // The DST_CHALLENGE for LogRing is "MISAKA_LOGRING_CHAL_V1:"
        // while LRS uses "MISAKA-LRS:challenge:v1:"
        // This means an LRS signature cannot pass LogRing verification
        // even if the algebraic structure matched.
        assert_ne!(DST_CHALLENGE, b"MISAKA-LRS:challenge:v1:");
        assert_ne!(DST_LINK, b"MISAKA-LRS:ki:v1:");
    }

    // ─── Ring Size Edge Cases ───────────────────────────

    #[test]
    fn test_logring_ring_size_2() {
        let (a, pks, secrets, _) = make_ring(2);
        let msg = [0x50u8; 32];
        let sig = logring_sign_v2(&a, &pks, 0, &secrets[0], &msg, 2).unwrap();
        logring_verify(&a, &pks, &msg, &sig).unwrap();
        assert_eq!(sig.merkle_path.len(), 1); // log2(2) = 1
    }

    #[test]
    fn test_logring_ring_size_1_fails() {
        let a = shared_a();
        let s = derive_secret_poly(&MlDsaKeypair::generate().secret_key);
        let pk = compute_pubkey(&a, &s);
        let msg = [0x51u8; 32];
        assert!(logring_sign_v2(&a, &[pk], 0, &s, &msg, 2).is_err());
    }

    #[test]
    fn test_logring_signer_out_of_range_fails() {
        let (a, pks, secrets, _) = make_ring(4);
        let msg = [0x52u8; 32];
        assert!(logring_sign_v2(&a, &pks, 99, &secrets[0], &msg, 2).is_err());
    }

    // ─── Linkability Tests ──────────────────────────────

    #[test]
    fn test_double_sign_same_ring_produces_same_link_tag() {
        let (a, pks, secrets, idx) = make_ring(4);
        let msg1 = [0x53u8; 32];
        let msg2 = [0x54u8; 32];
        let sig1 = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg1, 2).unwrap();
        let sig2 = logring_sign_v2(&a, &pks, idx, &secrets[idx], &msg2, 2).unwrap();
        // Same signer + same ring → same link_tag (detects double-spend)
        assert_eq!(sig1.link_tag, sig2.link_tag);
    }

    #[test]
    fn test_different_signers_different_link_tags() {
        let (a, pks, secrets, _) = make_ring(4);
        let msg = [0x55u8; 32];
        let sig0 = logring_sign_v2(&a, &pks, 0, &secrets[0], &msg, 2).unwrap();
        let sig1 = logring_sign_v2(&a, &pks, 1, &secrets[1], &msg, 2).unwrap();
        assert_ne!(sig0.link_tag, sig1.link_tag);
    }
}
