//! Transaction Resolution — Q-DAG-CT Ring Leaf Resolution Engine.
//!
//! # Architecture (v3 hardened)
//!
//! Each `ConfidentialInput` declares:
//! - `anonymity_root`: the Merkle root of its ring member set
//! - `ring_member_refs`: explicit OutputId references for each ring member
//!
//! The resolution pipeline:
//! 1. For each `ring_member_ref`, look up the UTXO in the UTXO set
//! 2. Build a `RingMemberLeaf` from (spending_pubkey, commitment, output_id, chain_id)
//! 3. Compute the Merkle root of the resolved leaves
//! 4. Verify it matches the declared `anonymity_root` — reject if mismatch
//! 5. Return resolved leaves to `qdag_verify` for ZKP verification
//!
//! # Decoy Selection (sender-side)
//!
//! The sender selects decoy outputs from the UTXO set to form the ring.
//! Selection criteria:
//! - Output must be unspent and sufficiently deep (MIN_DECOY_DEPTH blocks)
//! - Output must have a registered spending pubkey
//! - Output must be on the same chain_id
//! - Decoys are sampled uniformly from eligible outputs (no age/amount bias)

use sha3::{Sha3_256, Digest as Sha3Digest};

use misaka_pqc::qdag_tx::{RingMemberLeaf, ConfidentialInput};
use misaka_pqc::nullifier::OutputId;
use misaka_pqc::unified_zkp::{compute_merkle_root, SCHEME_UNIFIED_ZKP};
use misaka_pqc::bdlop::BdlopCommitment;
use misaka_pqc::pq_ring::Poly;
use misaka_pqc::privacy::STANDARD_RING_SIZE;

// ═══════════════════════════════════════════════════════════════
//  UTXO Accessor Trait
// ═══════════════════════════════════════════════════════════════

/// Trait for read-only UTXO set access during ring resolution.
///
/// Implemented by `UtxoSet` (in-memory) and `RocksBlockStore` (persistent).
/// The consensus layer uses this trait to avoid depending on storage internals.
pub trait UtxoAccessor {
    /// Look up an unspent output by reference.
    /// Returns (amount, spending_pubkey_bytes) or None if not found/spent.
    fn get_utxo_for_ring(
        &self, outref: &OutputId,
    ) -> Option<UtxoRingData>;

    /// Get the current committed height (for decoy depth checks).
    fn current_height(&self) -> u64;

    /// Collect eligible decoy candidates from the UTXO set.
    ///
    /// Returns OutputIds of unspent outputs that:
    /// - Have registered spending pubkeys
    /// - Are at least `min_depth` blocks deep
    /// - Are on the specified chain_id
    /// - Exclude the real input's OutputId
    fn eligible_decoys(
        &self,
        chain_id: u32,
        min_depth: u64,
        exclude: &OutputId,
        max_count: usize,
    ) -> Vec<OutputId>;
}

/// Data needed from a UTXO entry to construct a RingMemberLeaf.
#[derive(Debug, Clone)]
pub struct UtxoRingData {
    /// Serialized spending public key polynomial (512 bytes).
    pub spending_pubkey: Vec<u8>,
    /// BDLOP commitment to the output amount.
    pub commitment: BdlopCommitment,
    /// Block height at which this output was created.
    pub created_height: u64,
}

/// Minimum depth (in blocks) for a UTXO to be eligible as a decoy.
/// Prevents fingerprinting by selecting only very recent outputs.
pub const MIN_DECOY_DEPTH: u64 = 100;

// ═══════════════════════════════════════════════════════════════
//  Ring Leaf Resolution (Verifier-side)
// ═══════════════════════════════════════════════════════════════

/// Resolve ring member leaves for a confidential input from the UTXO set.
///
/// This is the PRODUCTION implementation that replaces the former placeholder.
///
/// # Fail-Closed Behavior
///
/// - If ANY ring member ref cannot be found in the UTXO set → Err
/// - If ANY ring member lacks a spending pubkey → Err
/// - If the resolved Merkle root doesn't match `input.anonymity_root` → Err
/// - If the ring size doesn't match `STANDARD_RING_SIZE` → Err
pub fn resolve_ring_leaves<A: UtxoAccessor>(
    input: &ConfidentialInput,
    chain_id: u32,
    utxo_set: &A,
) -> Result<Vec<RingMemberLeaf>, String> {
    // 1. Validate ring size
    if input.ring_member_refs.len() != STANDARD_RING_SIZE {
        return Err(format!(
            "ring size {} != required {} (STANDARD_RING_SIZE)",
            input.ring_member_refs.len(), STANDARD_RING_SIZE
        ));
    }

    // 2. Check for duplicate ring members (prevents trivial deanonymization)
    {
        let mut seen = std::collections::HashSet::new();
        for r in &input.ring_member_refs {
            if !seen.insert(r.to_bytes()) {
                return Err(format!(
                    "duplicate ring member: {}:{}",
                    hex::encode(&r.tx_hash[..8]), r.output_index
                ));
            }
        }
    }

    // 3. Resolve each ring member from UTXO set
    let mut leaves = Vec::with_capacity(STANDARD_RING_SIZE);
    for (i, outid) in input.ring_member_refs.iter().enumerate() {
        let utxo_data = utxo_set.get_utxo_for_ring(outid)
            .ok_or_else(|| format!(
                "ring member [{}] not found in UTXO set: {}:{}",
                i, hex::encode(&outid.tx_hash[..8]), outid.output_index
            ))?;

        if utxo_data.spending_pubkey.is_empty() {
            return Err(format!(
                "ring member [{}] has no spending pubkey: {}:{}",
                i, hex::encode(&outid.tx_hash[..8]), outid.output_index
            ));
        }

        leaves.push(RingMemberLeaf {
            spending_pubkey: utxo_data.spending_pubkey,
            commitment: utxo_data.commitment,
            output_id: outid.clone(),
            chain_id,
        });
    }

    // 4. Compute Merkle root from resolved leaves and verify root binding
    let leaf_hashes: Vec<[u8; 32]> = leaves.iter()
        .map(|l| l.leaf_hash())
        .collect();

    let computed_root = compute_merkle_root(&leaf_hashes)
        .map_err(|e| format!("merkle root computation failed: {}", e))?;

    if computed_root != input.anonymity_root {
        return Err(format!(
            "root binding failed: declared={} computed={}",
            hex::encode(&input.anonymity_root[..8]),
            hex::encode(&computed_root[..8])
        ));
    }

    Ok(leaves)
}

// ═══════════════════════════════════════════════════════════════
//  Decoy Selection (Sender-side)
// ═══════════════════════════════════════════════════════════════

/// Select decoys and build a full ring for a transaction input.
///
/// The real input is placed at a random position within the ring.
/// Returns (ring_member_refs, signer_index).
pub fn select_ring_with_decoys<A: UtxoAccessor>(
    real_output_id: &OutputId,
    chain_id: u32,
    utxo_set: &A,
) -> Result<(Vec<OutputId>, usize), String> {
    use rand::seq::SliceRandom;
    use rand::Rng;

    let decoys_needed = STANDARD_RING_SIZE - 1;

    let candidates = utxo_set.eligible_decoys(
        chain_id, MIN_DECOY_DEPTH, real_output_id, decoys_needed * 4,
    );

    if candidates.len() < decoys_needed {
        return Err(format!(
            "insufficient decoy candidates: {} available, {} needed",
            candidates.len(), decoys_needed
        ));
    }

    // Sample decoys uniformly (no amount/age bias)
    let mut rng = rand::thread_rng();
    let mut selected: Vec<OutputId> = candidates
        .choose_multiple(&mut rng, decoys_needed)
        .cloned()
        .collect();

    // Insert real input at random position
    let signer_index = rng.gen_range(0..STANDARD_RING_SIZE);
    selected.insert(signer_index, real_output_id.clone());

    Ok((selected, signer_index))
}

// ═══════════════════════════════════════════════════════════════
//  Proof Scheme Check
// ═══════════════════════════════════════════════════════════════

/// Check that a transaction uses only accepted proof schemes.
pub fn check_proof_scheme(scheme_byte: u8) -> Result<(), String> {
    if scheme_byte != SCHEME_UNIFIED_ZKP {
        return Err(format!(
            "unsupported membership scheme: 0x{:02x} (expected UnifiedZkp 0x{:02x})",
            scheme_byte, SCHEME_UNIFIED_ZKP
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

    // ─── Mock UTXO Accessor ─────────────────────────────

    struct MockUtxoSet {
        entries: std::collections::HashMap<Vec<u8>, UtxoRingData>,
        height: u64,
    }

    impl MockUtxoSet {
        fn new(height: u64) -> Self {
            Self { entries: std::collections::HashMap::new(), height }
        }

        fn insert(&mut self, outid: &OutputId, data: UtxoRingData) {
            self.entries.insert(outid.to_bytes().to_vec(), data);
        }
    }

    impl UtxoAccessor for MockUtxoSet {
        fn get_utxo_for_ring(&self, outref: &OutputId) -> Option<UtxoRingData> {
            self.entries.get(&outref.to_bytes().to_vec()).cloned()
        }

        fn current_height(&self) -> u64 { self.height }

        fn eligible_decoys(
            &self, _chain_id: u32, _min_depth: u64, exclude: &OutputId, max_count: usize,
        ) -> Vec<OutputId> {
            let exclude_bytes = exclude.to_bytes();
            self.entries.keys()
                .filter(|k| k.as_slice() != exclude_bytes.as_slice())
                .take(max_count)
                .map(|k| {
                    let mut tx_hash = [0u8; 32];
                    tx_hash.copy_from_slice(&k[..32]);
                    let output_index = u32::from_le_bytes(k[32..36].try_into().unwrap());
                    OutputId { tx_hash, output_index }
                })
                .collect()
        }
    }

    fn make_utxo_data(pk_byte: u8) -> UtxoRingData {
        UtxoRingData {
            spending_pubkey: vec![pk_byte; 512],
            commitment: BdlopCommitment(Poly::zero()),
            created_height: 1,
        }
    }

    fn make_outid(id: u8, idx: u32) -> OutputId {
        OutputId { tx_hash: [id; 32], output_index: idx }
    }

    // ─── Resolution Tests ───────────────────────────────

    #[test]
    fn test_resolve_valid_ring() {
        let mut utxo = MockUtxoSet::new(200);
        let chain_id = 2u32;

        // Insert STANDARD_RING_SIZE outputs
        let refs: Vec<OutputId> = (0..STANDARD_RING_SIZE as u8)
            .map(|i| {
                let outid = make_outid(i + 1, 0);
                utxo.insert(&outid, make_utxo_data(i + 0x10));
                outid
            })
            .collect();

        // Build a ConfidentialInput with correct root
        let leaves: Vec<RingMemberLeaf> = refs.iter().enumerate().map(|(i, outid)| {
            RingMemberLeaf {
                spending_pubkey: vec![(i as u8) + 0x10; 512],
                commitment: BdlopCommitment(Poly::zero()),
                output_id: outid.clone(),
                chain_id,
            }
        }).collect();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.leaf_hash()).collect();
        let root = compute_merkle_root(&leaf_hashes).unwrap();

        let input = ConfidentialInput {
            anonymity_root: root,
            nullifier: [0x11; 32],
            membership_proof: vec![0; 100],
            spent_output_id: make_outid(1, 0),
            input_commitment: BdlopCommitment(Poly::zero()),
            ring_member_refs: refs,
        };

        let resolved = resolve_ring_leaves(&input, chain_id, &utxo);
        assert!(resolved.is_ok(), "valid ring should resolve: {:?}", resolved.err());
        assert_eq!(resolved.unwrap().len(), STANDARD_RING_SIZE);
    }

    #[test]
    fn test_resolve_wrong_ring_size_rejected() {
        let utxo = MockUtxoSet::new(200);
        let input = ConfidentialInput {
            anonymity_root: [0; 32],
            nullifier: [0x11; 32],
            membership_proof: vec![],
            spent_output_id: make_outid(1, 0),
            input_commitment: BdlopCommitment(Poly::zero()),
            ring_member_refs: vec![make_outid(1, 0)], // only 1, not STANDARD_RING_SIZE
        };
        assert!(resolve_ring_leaves(&input, 2, &utxo).is_err());
    }

    #[test]
    fn test_resolve_missing_utxo_rejected() {
        let utxo = MockUtxoSet::new(200); // empty
        let refs: Vec<OutputId> = (0..STANDARD_RING_SIZE as u8)
            .map(|i| make_outid(i + 1, 0))
            .collect();
        let input = ConfidentialInput {
            anonymity_root: [0; 32],
            nullifier: [0x11; 32],
            membership_proof: vec![],
            spent_output_id: make_outid(1, 0),
            input_commitment: BdlopCommitment(Poly::zero()),
            ring_member_refs: refs,
        };
        assert!(resolve_ring_leaves(&input, 2, &utxo).is_err());
    }

    #[test]
    fn test_resolve_root_mismatch_rejected() {
        let mut utxo = MockUtxoSet::new(200);
        let refs: Vec<OutputId> = (0..STANDARD_RING_SIZE as u8)
            .map(|i| {
                let outid = make_outid(i + 1, 0);
                utxo.insert(&outid, make_utxo_data(i + 0x10));
                outid
            })
            .collect();

        let input = ConfidentialInput {
            anonymity_root: [0xFF; 32], // WRONG root
            nullifier: [0x11; 32],
            membership_proof: vec![],
            spent_output_id: make_outid(1, 0),
            input_commitment: BdlopCommitment(Poly::zero()),
            ring_member_refs: refs,
        };
        let result = resolve_ring_leaves(&input, 2, &utxo);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("root binding failed"));
    }

    #[test]
    fn test_resolve_duplicate_ring_member_rejected() {
        let mut utxo = MockUtxoSet::new(200);
        let outid = make_outid(1, 0);
        utxo.insert(&outid, make_utxo_data(0x10));

        let refs: Vec<OutputId> = std::iter::repeat(outid)
            .take(STANDARD_RING_SIZE)
            .collect();

        let input = ConfidentialInput {
            anonymity_root: [0; 32],
            nullifier: [0x11; 32],
            membership_proof: vec![],
            spent_output_id: make_outid(1, 0),
            input_commitment: BdlopCommitment(Poly::zero()),
            ring_member_refs: refs,
        };
        let result = resolve_ring_leaves(&input, 2, &utxo);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate ring member"));
    }

    // ─── Proof Scheme Tests ─────────────────────────────

    #[test]
    fn test_unified_zkp_accepted() {
        assert!(check_proof_scheme(SCHEME_UNIFIED_ZKP).is_ok());
    }

    #[test]
    fn test_legacy_scheme_rejected() {
        assert!(check_proof_scheme(0x03).is_err());
    }

    #[test]
    fn test_unknown_scheme_rejected() {
        assert!(check_proof_scheme(0xFF).is_err());
    }
}
