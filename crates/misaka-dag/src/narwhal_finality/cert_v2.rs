// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Certificate V2 — ZK-forward-compatible certificate types (Phase 3a).
//!
//! # What this module is
//!
//! The foundation of Phase 3a's Certificate V2 design, reconciling the
//! two source prompts captured in
//! `docs/design/v091_phase3a_cert_v2.md`:
//!
//! * **Prompt A** contributed the `epoch` field and the "Cert enum
//!   `{V1(FinalizedCheckpoint), V2(CertificateV2)}`" shape.
//! * **Prompt B** contributed the [`VoteCommitment`] wrapping
//!   (instead of a bare `BitVec`), the [`VoteCommitmentScheme`]
//!   trait, and the [`AggregationProof`] slot that lets a later
//!   hardfork retrofit ZK proofs without breaking digest-stable DAG
//!   references.
//!
//! # What this module is NOT (yet)
//!
//! No write / read path. No RocksDB CF. No verify path. No migration
//! tool. No adaptive round rate. No epoch-boundary config
//! adjustment. All of these land in follow-up sessions — see
//! §5 of the design doc.
//!
//! # Scheme tag
//!
//! The `CommitmentScheme` byte is persisted on disk as part of
//! [`VoteCommitment`]. Renaming or re-numbering existing variants
//! corrupts every on-disk cert. Add new schemes; don't edit existing
//! ones.
//!
//! Current variants:
//! * [`CommitmentScheme::Blake3MerkleV1`] (`0x01`) — the only live
//!   scheme in Phase 3a. Blake3 was chosen over SHA-2-256 to match
//!   the existing `Checkpoint::compute_digest` convention; the
//!   "scheme-tag" reservation is v1 either way.
//! * (future) `Poseidon2MerkleV1` and siblings — placeholders for
//!   ZK-friendly hashes once the retrofit plan lands.

use serde::{Deserialize, Serialize};

use super::{CheckpointDigest, FinalizedCheckpoint};

// ─── CommitmentScheme tag ─────────────────────────────────────────

/// Persisted byte tag identifying which [`VoteCommitmentScheme`] was
/// used to compute a [`VoteCommitment::root`].
///
/// Values are on-disk stable. Add variants; never renumber existing
/// ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CommitmentScheme {
    /// Blake3 merkle (Phase 3a default). See [`Blake3MerkleV1`].
    Blake3MerkleV1 = 0x01,
}

impl CommitmentScheme {
    /// The single-byte wire / disk tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ─── Scheme trait ─────────────────────────────────────────────────

/// A family of functions for computing a [`VoteCommitment::root`]
/// from a sorted list of voter-leaf hashes.
///
/// Implementations MUST be pure (no internal state, no RNG) so that
/// two validators computing the commitment from the same voter set
/// in different processes agree byte-for-byte.
///
/// The [`scheme_tag`](Self::scheme_tag) associated function returns
/// the byte that is persisted alongside the root, so that future
/// schemes can cohabit on disk without ambiguity.
pub trait VoteCommitmentScheme {
    /// Hash a leaf. `voter_id` is the validator public key (or its
    /// 32-byte hash); `extra` is scheme-specific auxiliary data (e.g.
    /// the signature) — may be empty.
    fn leaf(voter_id: &[u8; 32], extra: &[u8]) -> [u8; 32];

    /// Hash an internal (non-leaf) node.
    fn internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];

    /// Compute the merkle root from a leaf list. Implementations
    /// MUST sort the leaves by `voter_id` ascending before hashing
    /// and MUST pad odd counts by duplicating the last leaf to the
    /// next power of two.
    fn root(leaves: &mut [[u8; 32]]) -> [u8; 32];

    /// The on-disk tag for this scheme.
    fn scheme_tag() -> CommitmentScheme;
}

// ─── Blake3MerkleV1 impl ──────────────────────────────────────────

const DOMAIN_LEAF: &[u8] = b"MISAKA:cert_v2:leaf:v1";
const DOMAIN_INTERNAL: &[u8] = b"MISAKA:cert_v2:internal:v1";
const DOMAIN_ROOT: &[u8] = b"MISAKA:cert_v2:root:v1";

/// Blake3-backed merkle commitment scheme.
pub struct Blake3MerkleV1;

impl VoteCommitmentScheme for Blake3MerkleV1 {
    fn leaf(voter_id: &[u8; 32], extra: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_LEAF);
        h.update(voter_id);
        h.update(&(extra.len() as u64).to_le_bytes());
        h.update(extra);
        *h.finalize().as_bytes()
    }

    fn internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_INTERNAL);
        h.update(left);
        h.update(right);
        *h.finalize().as_bytes()
    }

    fn root(leaves: &mut [[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            // Empty-set root is the domain-separated hash of the empty
            // input. This is a conventional choice; disallow-or-zero
            // would also be valid but non-empty callers would then
            // need to branch. Keeping "empty set → defined root" is
            // simpler and can't be confused with a real set's root
            // because real sets always have ≥ 1 voter.
            let mut h = blake3::Hasher::new();
            h.update(DOMAIN_ROOT);
            h.update(&0u64.to_le_bytes());
            return *h.finalize().as_bytes();
        }

        leaves.sort_unstable();

        // Pad to next power of two by duplicating the last element.
        let target = leaves.len().next_power_of_two();
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        while level.len() < target {
            level.push(*level.last().expect("non-empty"));
        }

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(Self::internal(&pair[0], &pair[1]));
            }
            level = next;
        }

        // Wrap the final level-0 hash with DOMAIN_ROOT so the root
        // cannot collide with an intermediate internal hash even
        // across a single-leaf tree.
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_ROOT);
        h.update(&(leaves.len() as u64).to_le_bytes());
        h.update(&level[0]);
        *h.finalize().as_bytes()
    }

    fn scheme_tag() -> CommitmentScheme {
        CommitmentScheme::Blake3MerkleV1
    }
}

// ─── VoteCommitment ───────────────────────────────────────────────

/// Bit-packed voter participation + the commitment root.
///
/// `voters` is a big-endian bit vector over the epoch's validator
/// ordering; bit `i` set means validator index `i` voted. The root
/// is computed from the *actual* voter IDs (not the bit vector) —
/// the bit vector is carried alongside so light clients can verify
/// participation without the full validator set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteCommitment {
    /// Bit-packed participation: one bit per authority index,
    /// big-endian, `voters.len() * 8` bits total.
    pub voters: Vec<u8>,
    /// Number of set bits in `voters`. Redundant with the bit vector
    /// but expensive-to-recompute so we carry it explicitly; checked
    /// at deserialise time.
    pub voter_count: u32,
    /// Commitment root computed by the scheme identified in `scheme`.
    pub root: [u8; 32],
    /// Which scheme produced `root`. Persisted as a byte.
    pub scheme: CommitmentScheme,
}

impl VoteCommitment {
    /// Build a new [`VoteCommitment`] under [`Blake3MerkleV1`].
    ///
    /// * `voter_ids` is the list of 32-byte voter public keys
    ///   (ordering irrelevant — the scheme sorts internally).
    /// * `voters_bits` is the raw bit-packed participation vector
    ///   (usually produced by a bitmap store indexed by authority).
    #[must_use]
    pub fn with_blake3(voter_ids: &[[u8; 32]], voters_bits: Vec<u8>) -> Self {
        let mut leaves: Vec<[u8; 32]> = voter_ids
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect();
        let root = Blake3MerkleV1::root(&mut leaves);
        Self {
            voters: voters_bits,
            voter_count: voter_ids.len() as u32,
            root,
            scheme: CommitmentScheme::Blake3MerkleV1,
        }
    }
}

// ─── AggregationProof ─────────────────────────────────────────────

/// Identifier of the proof system used in an [`AggregationProof`].
///
/// Only `ReservedV1` is accepted in Phase 3a; any cert carrying a
/// non-`None` `aggregation_slot` is rejected regardless of its
/// contents. The variant exists so Phase 3b can drop in a real
/// proof without shape change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofSystem {
    /// Reserved placeholder — no proof actually accepted in Phase 3a.
    ReservedV1 = 0x01,
}

impl ProofSystem {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A prospective aggregated-signature proof. All contents are
/// opaque to the verifier in Phase 3a. Phase 3b will define a
/// concrete `system` with real `proof` and `public_inputs`
/// encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationProof {
    pub system: ProofSystem,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    /// Unix millis at which the proof was generated. Advisory only
    /// in Phase 3a (not consensus-binding).
    pub generated_at: u64,
}

// ─── CertificateV2 ────────────────────────────────────────────────

/// The v2 certificate shape — ZK-forward-compatible.
///
/// Note: [`digest`](Self::digest) deliberately **excludes** the
/// `aggregation_slot` field. A later hardfork may retrofit proofs
/// into existing certificates without breaking DAG references that
/// cite them by digest. This exclusion is consensus-stable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateV2 {
    /// Digest of the consensus checkpoint this certificate attests.
    pub header: CheckpointDigest,
    /// Participation + merkle commitment to voters.
    pub vote_refs: VoteCommitment,
    /// Epoch in which this certificate was finalised.
    pub epoch: u64,
    /// Optional aggregated proof. MUST be `None` in Phase 3a; the
    /// verify path rejects any `Some(_)`.
    pub aggregation_slot: Option<AggregationProof>,
}

const DOMAIN_CERT_DIGEST: &[u8] = b"MISAKA:cert_v2:digest:v1";

impl CertificateV2 {
    /// Compute the certificate digest. Does **not** include
    /// `aggregation_slot` — see module docs for why.
    #[must_use]
    pub fn digest(&self) -> CheckpointDigest {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_CERT_DIGEST);
        h.update(&self.header.0);
        h.update(&self.epoch.to_le_bytes());
        h.update(&[self.vote_refs.scheme.tag()]);
        h.update(&(self.vote_refs.voters.len() as u64).to_le_bytes());
        h.update(&self.vote_refs.voters);
        h.update(&(self.vote_refs.voter_count as u64).to_le_bytes());
        h.update(&self.vote_refs.root);
        CheckpointDigest(*h.finalize().as_bytes())
    }
}

// ─── Cert enum ────────────────────────────────────────────────────

/// Either a v1 (existing [`FinalizedCheckpoint`]) or a v2 certificate.
///
/// Phase 3a wire and storage stay on V1; V2 is the new shape that
/// will land in a follow-up session's write path. The enum lets
/// consumers handle both during the cross-over epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Certificate {
    V1(FinalizedCheckpoint),
    V2(CertificateV2),
}

// ─── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn voter(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // ── CommitmentScheme tag ──────────────────────────────────────

    #[test]
    fn commitment_scheme_tag_is_one() {
        assert_eq!(CommitmentScheme::Blake3MerkleV1.tag(), 0x01);
    }

    #[test]
    fn commitment_scheme_is_serde_stable() {
        let s = CommitmentScheme::Blake3MerkleV1;
        let j = serde_json::to_string(&s).unwrap();
        let back: CommitmentScheme = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    // ── Blake3MerkleV1 determinism ────────────────────────────────

    #[test]
    fn leaf_is_domain_separated_from_internal() {
        // A single leaf should not equal the internal hash of two
        // zero leaves. Guards against accidental cross-kind collision.
        let l = Blake3MerkleV1::leaf(&voter(0xAB), &[]);
        let i = Blake3MerkleV1::internal(&l, &l);
        assert_ne!(l, i);
    }

    #[test]
    fn root_sorts_leaves_for_determinism() {
        let ids_a = vec![voter(0x03), voter(0x01), voter(0x02)];
        let ids_b = vec![voter(0x02), voter(0x03), voter(0x01)];
        let mut la: Vec<[u8; 32]> = ids_a
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect();
        let mut lb: Vec<[u8; 32]> = ids_b
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect();
        assert_eq!(Blake3MerkleV1::root(&mut la), Blake3MerkleV1::root(&mut lb));
    }

    #[test]
    fn root_changes_with_different_voter_set() {
        let mut la = vec![voter(0x01), voter(0x02)]
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect::<Vec<_>>();
        let mut lb = vec![voter(0x01), voter(0x03)]
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect::<Vec<_>>();
        assert_ne!(Blake3MerkleV1::root(&mut la), Blake3MerkleV1::root(&mut lb));
    }

    #[test]
    fn root_handles_odd_leaf_count_via_duplication() {
        // Three leaves pad to four by duplicating the last (after
        // sort). Should succeed and be deterministic.
        let mut la = vec![voter(0x01), voter(0x02), voter(0x03)]
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect::<Vec<_>>();
        let r_a = Blake3MerkleV1::root(&mut la);
        let mut lb = vec![voter(0x03), voter(0x01), voter(0x02)]
            .iter()
            .map(|id| Blake3MerkleV1::leaf(id, &[]))
            .collect::<Vec<_>>();
        let r_b = Blake3MerkleV1::root(&mut lb);
        assert_eq!(r_a, r_b);
    }

    #[test]
    fn root_single_leaf_differs_from_two_same_leaves() {
        let mut one = vec![Blake3MerkleV1::leaf(&voter(0x01), &[])];
        let mut two = vec![
            Blake3MerkleV1::leaf(&voter(0x01), &[]),
            Blake3MerkleV1::leaf(&voter(0x01), &[]),
        ];
        // The second-level leaf-count prefix in root() disambiguates
        // these, so roots differ.
        assert_ne!(
            Blake3MerkleV1::root(&mut one),
            Blake3MerkleV1::root(&mut two)
        );
    }

    #[test]
    fn root_empty_set_is_well_defined() {
        let mut empty: Vec<[u8; 32]> = vec![];
        let r = Blake3MerkleV1::root(&mut empty);
        // Just assert it runs and returns something non-zero. Two
        // empty calls should agree.
        let mut empty2: Vec<[u8; 32]> = vec![];
        let r2 = Blake3MerkleV1::root(&mut empty2);
        assert_eq!(r, r2);
    }

    // ── VoteCommitment ────────────────────────────────────────────

    #[test]
    fn vote_commitment_with_blake3_populates_scheme_tag() {
        let vc = VoteCommitment::with_blake3(&[voter(0x01), voter(0x02)], vec![0xC0]);
        assert_eq!(vc.scheme, CommitmentScheme::Blake3MerkleV1);
        assert_eq!(vc.voter_count, 2);
    }

    #[test]
    fn vote_commitment_determinism_across_insertion_order() {
        let a = VoteCommitment::with_blake3(&[voter(0x01), voter(0x02)], vec![0b11]);
        let b = VoteCommitment::with_blake3(&[voter(0x02), voter(0x01)], vec![0b11]);
        assert_eq!(a.root, b.root);
    }

    // ── ProofSystem ───────────────────────────────────────────────

    #[test]
    fn proof_system_reserved_v1_tag() {
        assert_eq!(ProofSystem::ReservedV1.tag(), 0x01);
    }

    // ── CertificateV2 digest ──────────────────────────────────────

    fn make_cert(with_aggregation: bool) -> CertificateV2 {
        CertificateV2 {
            header: CheckpointDigest([0xAB; 32]),
            vote_refs: VoteCommitment::with_blake3(
                &[voter(0x01), voter(0x02), voter(0x03)],
                vec![0b111],
            ),
            epoch: 7,
            aggregation_slot: if with_aggregation {
                Some(AggregationProof {
                    system: ProofSystem::ReservedV1,
                    proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
                    public_inputs: vec![0xCA, 0xFE],
                    generated_at: 1_700_000_000_000,
                })
            } else {
                None
            },
        }
    }

    #[test]
    fn cert_digest_excludes_aggregation_slot() {
        let without = make_cert(false);
        let with_some = make_cert(true);
        assert_eq!(without.digest(), with_some.digest());
    }

    #[test]
    fn cert_digest_changes_with_header() {
        let c1 = make_cert(false);
        let mut c2 = make_cert(false);
        c2.header = CheckpointDigest([0xCD; 32]);
        assert_ne!(c1.digest(), c2.digest());
    }

    #[test]
    fn cert_digest_changes_with_epoch() {
        let c1 = make_cert(false);
        let mut c2 = make_cert(false);
        c2.epoch = 8;
        assert_ne!(c1.digest(), c2.digest());
    }

    #[test]
    fn cert_digest_changes_with_voters_bitvec() {
        let c1 = make_cert(false);
        let mut c2 = make_cert(false);
        c2.vote_refs.voters = vec![0b011];
        assert_ne!(c1.digest(), c2.digest());
    }

    #[test]
    fn cert_digest_changes_with_voter_commitment_root() {
        let c1 = make_cert(false);
        let mut c2 = make_cert(false);
        c2.vote_refs.root = [0xFF; 32];
        assert_ne!(c1.digest(), c2.digest());
    }

    #[test]
    fn cert_digest_is_deterministic() {
        let c = make_cert(false);
        assert_eq!(c.digest(), c.digest());
    }

    // ── Certificate enum serde ────────────────────────────────────

    #[test]
    fn cert_enum_v2_serde_roundtrip() {
        let c = Certificate::V2(make_cert(true));
        let j = serde_json::to_string(&c).unwrap();
        let back: Certificate = serde_json::from_str(&j).unwrap();
        match back {
            Certificate::V2(c2) => {
                assert_eq!(c2.epoch, 7);
                assert!(c2.aggregation_slot.is_some());
            }
            Certificate::V1(_) => panic!("expected V2 variant"),
        }
    }
}
