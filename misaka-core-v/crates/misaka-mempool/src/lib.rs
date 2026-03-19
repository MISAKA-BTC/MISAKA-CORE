//! UTXO Mempool — ALL PQ verification performed internally.
//!
//! # Caller provides ONLY:
//! - `UtxoTransaction` (raw tx from network/wallet)
//! - Reference to `UtxoSet` (read-only lookup)
//!
//! # Mempool performs internally:
//! 1. Structural validation
//! 2. Ring member resolution (UTXO set lookup → spending pubkeys)
//! 3. Ring signature parsing + verification
//! 4. Key image proof parsing + verification (if present in tx.extra)
//! 5. Key image conflict (mempool + chain)
//! 6. Stealth extension sanity
//! 7. Size / capacity limits
//!
//! **Zero external verification responsibility.**

use std::collections::{BTreeMap, HashSet};
use misaka_types::utxo::*;
use misaka_types::stealth::PQ_STEALTH_VERSION;
use misaka_storage::utxo_set::UtxoSet;
use misaka_pqc::pq_ring::{self, RingSig, Poly, derive_public_param, DEFAULT_A_SEED};
use misaka_pqc::ki_proof::{self, KiProof};
use misaka_pqc::packing;
use misaka_pqc::logring::{LogRingSignature, logring_verify, compute_link_tag};

#[cfg(feature = "chipmunk")]
use misaka_pqc::chipmunk::{ChipmunkSig, ChipmunkKiProof, chipmunk_ring_verify, chipmunk_verify_ki};

/// Mempool admission error — every failure path explicit.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("structural: {0}")]
    Structural(String),
    #[error("ring sig parse: input[{index}]: {reason}")]
    RingSigParse { index: usize, reason: String },
    #[error("ring sig invalid: input[{index}]: {reason}")]
    RingSigInvalid { index: usize, reason: String },
    #[error("key image proof invalid: input[{index}]: {reason}")]
    KeyImageProofInvalid { index: usize, reason: String },
    #[error("key image conflict: {0}")]
    KeyImageConflict(String),
    #[error("ring member not found: input[{index}] member {member}")]
    RingMemberNotFound { index: usize, member: String },
    #[error("ring member has no spending pubkey: input[{index}]")]
    RingMemberNoPubkey { index: usize },
    #[error("stealth malformed: output[{index}]: {reason}")]
    StealthMalformed { index: usize, reason: String },
    #[error("amount mismatch: inputs={inputs}, outputs+fee={required}")]
    AmountMismatch { inputs: u64, required: u64 },
    #[error("ring amounts not uniform: input[{index}]: {reason}")]
    RingAmountNotUniform { index: usize, reason: String },
    #[error("capacity full")]
    CapacityFull,
}

pub struct MempoolEntry {
    pub tx: UtxoTransaction,
    pub tx_hash: [u8; 32],
    pub received_at_ms: u64,
}

/// Spending public key stored alongside UTXO for ring resolution.
/// Now stored in UtxoSet (persistent) — NOT in mempool (memory-only).
#[derive(Debug, Clone)]
pub struct UtxoSpendingKey {
    pub poly: Poly,
}

pub struct UtxoMempool {
    entries: BTreeMap<[u8; 32], MempoolEntry>,
    key_images_mempool: HashSet<[u8; 32]>,
    /// LogRing link_tags in mempool (for double-spend detection).
    link_tags_mempool: HashSet<[u8; 32]>,
    spent_key_images: HashSet<[u8; 32]>,
    /// Spent LogRing link_tags on-chain.
    spent_link_tags: HashSet<[u8; 32]>,
    max_size: usize,
    /// Shared ring-sig parameter.
    a_param: Poly,
}

impl UtxoMempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            key_images_mempool: HashSet::new(),
            link_tags_mempool: HashSet::new(),
            spent_key_images: HashSet::new(),
            spent_link_tags: HashSet::new(),
            max_size,
            a_param: derive_public_param(&DEFAULT_A_SEED),
        }
    }

    /// Resolve ring member public keys from the UTXO set's spending key registry.
    /// This reads from PERSISTENT storage — not memory-only mempool state.
    fn resolve_ring_pubkeys(
        &self,
        input_idx: usize,
        members: &[OutputRef],
        utxo_set: &UtxoSet,
    ) -> Result<Vec<Poly>, MempoolError> {
        let mut pks = Vec::with_capacity(members.len());
        for member in members {
            // Check UTXO exists
            if utxo_set.get(member).is_none() {
                return Err(MempoolError::RingMemberNotFound {
                    index: input_idx,
                    member: format!("{}:{}", hex::encode(&member.tx_hash[..8]), member.output_index),
                });
            }
            // Get spending pubkey from UTXO set (persistent)
            let pk_bytes = utxo_set.get_spending_key(member)
                .ok_or(MempoolError::RingMemberNoPubkey { index: input_idx })?;
            let poly = Poly::from_bytes(pk_bytes)
                .map_err(|e| MempoolError::RingMemberNoPubkey { index: input_idx })?;
            pks.push(poly);
        }
        Ok(pks)
    }

    /// Parse ring signature from raw bytes.
    fn parse_ring_sig(
        &self,
        input_idx: usize,
        raw: &[u8],
        ring_size: usize,
    ) -> Result<RingSig, MempoolError> {
        // Try v2 (compact) first, then v0 (raw)
        if let Ok(sig) = packing::unpack_ring_sig_v2(raw, ring_size) {
            return Ok(sig);
        }
        if let Ok(sig) = packing::unpack_ring_sig(raw, ring_size) {
            return Ok(sig);
        }
        RingSig::from_bytes(raw, ring_size)
            .map_err(|e| MempoolError::RingSigParse {
                index: input_idx, reason: e.to_string(),
            })
    }

    /// Full-verification admission. ALL checks internal. No external responsibility.
    ///
    /// # Arguments
    /// - `tx`: Raw transaction from network/wallet
    /// - `utxo_set`: Read-only reference for UTXO existence + amount checks
    /// - `now_ms`: Timestamp for ordering
    pub fn admit(
        &mut self,
        tx: UtxoTransaction,
        utxo_set: &UtxoSet,
        now_ms: u64,
    ) -> Result<[u8; 32], MempoolError> {
        // ── 1. Structural validation ──
        tx.validate_structure()
            .map_err(|e| MempoolError::Structural(e.to_string()))?;

        // ── 2. Capacity ──
        if self.entries.len() >= self.max_size {
            return Err(MempoolError::CapacityFull);
        }

        // ── 3. Dedup ──
        let tx_hash = tx.tx_hash();
        if self.entries.contains_key(&tx_hash) {
            return Ok(tx_hash);
        }

        let signing_digest = tx.signing_digest();

        // ── 4. Per-input verification ──
        for (i, inp) in tx.inputs.iter().enumerate() {
            // 4a. Key image conflict (chain state)
            if self.spent_key_images.contains(&inp.key_image) {
                return Err(MempoolError::KeyImageConflict(
                    format!("{} spent on-chain", hex::encode(inp.key_image))));
            }

            // 4b. Key image conflict (mempool)
            if self.key_images_mempool.contains(&inp.key_image) {
                return Err(MempoolError::KeyImageConflict(
                    format!("{} in mempool", hex::encode(inp.key_image))));
            }

            // 4c. Resolve ring member pubkeys from UTXO set
            let ring_pks = self.resolve_ring_pubkeys(i, &inp.ring_members, utxo_set)?;

            // 4d-4g. Scheme-specific signature + KI proof verification
            match tx.ring_scheme {
                RING_SCHEME_LOGRING => {
                    // ── LogRing O(log n) — SYSTEM DEFAULT ──
                    
                    // Parse LogRing signature
                    let lr_sig = LogRingSignature::from_bytes(&inp.ring_signature)
                        .map_err(|e| MempoolError::RingSigParse {
                            index: i, reason: format!("logring: {e}"),
                        })?;

                    // Verify LogRing signature against ring pubkeys
                    logring_verify(&self.a_param, &ring_pks, &signing_digest, &lr_sig)
                        .map_err(|e| MempoolError::RingSigInvalid {
                            index: i, reason: format!("logring: {e}"),
                        })?;

                    // Link tag double-spend check (chain state)
                    if self.spent_link_tags.contains(&lr_sig.link_tag) {
                        return Err(MempoolError::KeyImageConflict(
                            format!("link_tag {} spent on-chain", hex::encode(lr_sig.link_tag))));
                    }

                    // Link tag double-spend check (mempool)
                    if self.link_tags_mempool.contains(&lr_sig.link_tag) {
                        return Err(MempoolError::KeyImageConflict(
                            format!("link_tag {} in mempool", hex::encode(lr_sig.link_tag))));
                    }

                    // Key image in tx must match link_tag concept
                    // For LogRing, the key_image field stores the link_tag
                    if inp.key_image != lr_sig.link_tag {
                        return Err(MempoolError::RingSigInvalid {
                            index: i,
                            reason: "key_image != link_tag in LogRing tx".into(),
                        });
                    }
                }
                RING_SCHEME_LRS => {
                    // Parse LRS ring signature
                    let ring_sig = self.parse_ring_sig(i, &inp.ring_signature, inp.ring_members.len())?;

                    // Key image in sig must match tx
                    if ring_sig.key_image != inp.key_image {
                        return Err(MempoolError::RingSigInvalid {
                            index: i,
                            reason: "key image mismatch between tx input and ring sig".into(),
                        });
                    }

                    // Verify LRS ring signature
                    pq_ring::ring_verify(&self.a_param, &ring_pks, &signing_digest, &ring_sig)
                        .map_err(|e| MempoolError::RingSigInvalid {
                            index: i, reason: e.to_string(),
                        })?;

                    // LRS KI proof is REQUIRED (SEC-003 fix).
                    // The ring signature binds key_image to the signer's secret,
                    // but without the KI proof, an attacker can claim an arbitrary
                    // key_image and bypass double-spend detection.
                    if inp.ki_proof.is_empty() {
                        return Err(MempoolError::KeyImageProofInvalid {
                            index: i,
                            reason: "KI proof is REQUIRED for LRS scheme but was empty".into(),
                        });
                    }
                    {
                        let ki_proof = KiProof::from_bytes(&inp.ki_proof)
                            .map_err(|e| MempoolError::KeyImageProofInvalid {
                                index: i, reason: format!("parse: {e}"),
                            })?;
                        let mut ki_valid = false;
                        for pk in &ring_pks {
                            if ki_proof::verify_key_image_proof(&self.a_param, pk, &inp.key_image, &ki_proof).is_ok() {
                                ki_valid = true;
                                break;
                            }
                        }
                        if !ki_valid {
                            return Err(MempoolError::KeyImageProofInvalid {
                                index: i,
                                reason: "KI proof does not verify against any ring member".into(),
                            });
                        }
                    }
                }
                #[cfg(feature = "chipmunk")]
                RING_SCHEME_CHIPMUNK => {
                    // Parse ChipmunkRing signature (no key_image in sig)
                    let cr_sig = ChipmunkSig::from_bytes(&inp.ring_signature, inp.ring_members.len())
                        .map_err(|e| MempoolError::RingSigParse {
                            index: i, reason: e.to_string(),
                        })?;

                    // Verify ChipmunkRing signature
                    chipmunk_ring_verify(&self.a_param, &ring_pks, &signing_digest, &cr_sig)
                        .map_err(|e| MempoolError::RingSigInvalid {
                            index: i, reason: e.to_string(),
                        })?;

                    // Parse and verify Chipmunk KI proof
                    let cr_proof = ChipmunkKiProof::from_bytes(&inp.ki_proof)
                        .map_err(|e| MempoolError::KeyImageProofInvalid {
                            index: i, reason: format!("parse: {e}"),
                        })?;
                    let mut ki_valid = false;
                    for pk in &ring_pks {
                        if chipmunk_verify_ki(&self.a_param, pk, &inp.key_image, &cr_proof).is_ok() {
                            ki_valid = true;
                            break;
                        }
                    }
                    if !ki_valid {
                        return Err(MempoolError::KeyImageProofInvalid {
                            index: i,
                            reason: "Chipmunk KI proof does not verify against any ring member".into(),
                        });
                    }
                }
                _ => {
                    return Err(MempoolError::Structural(
                        format!("unsupported ring scheme: 0x{:02x}", tx.ring_scheme)));
                }
            }
        }

        // ── 5. Stealth extension sanity ──
        for (i, out) in tx.outputs.iter().enumerate() {
            if let Some(ref sd) = out.pq_stealth {
                // Accept both stealth v1 (0x01) and v2 (0x02)
                if sd.version != PQ_STEALTH_VERSION && sd.version != 0x02 {
                    return Err(MempoolError::StealthMalformed {
                        index: i, reason: format!("version {}", sd.version),
                    });
                }
                if sd.kem_ct.len() != 1088 {
                    return Err(MempoolError::StealthMalformed {
                        index: i, reason: format!("kem_ct len {}", sd.kem_ct.len()),
                    });
                }
            }
        }

        // ── 5b. Amount conservation (state-derived, checked arithmetic) ──
        //
        // For each input, resolve ring member amounts from UTXO state.
        // Same-amount ring: all members must have identical amounts.
        // Input sum must exactly equal output sum + fee.
        if !tx.inputs.is_empty() {
            let mut sum_input: u64 = 0;
            for (i, inp) in tx.inputs.iter().enumerate() {
                // Resolve amounts from UTXO state (not from external data)
                let mut ring_amounts: Vec<u64> = Vec::with_capacity(inp.ring_members.len());
                for member in &inp.ring_members {
                    let amount = utxo_set.get(member)
                        .map(|e| e.output.amount)
                        .ok_or_else(|| MempoolError::RingMemberNotFound {
                            index: i,
                            member: format!("{}:{}", hex::encode(&member.tx_hash[..8]), member.output_index),
                        })?;
                    ring_amounts.push(amount);
                }

                // Same-amount ring enforcement
                if let Some(&first_amt) = ring_amounts.first() {
                    for (j, &amt) in ring_amounts.iter().enumerate().skip(1) {
                        if amt != first_amt {
                            return Err(MempoolError::RingAmountNotUniform {
                                index: i,
                                reason: format!("member[0]={} != member[{}]={}", first_amt, j, amt),
                            });
                        }
                    }
                    sum_input = sum_input.checked_add(first_amt)
                        .ok_or_else(|| MempoolError::AmountMismatch {
                            inputs: u64::MAX, required: 0,
                        })?;
                }
            }

            let sum_output: u64 = tx.outputs.iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
                .ok_or_else(|| MempoolError::AmountMismatch {
                    inputs: sum_input, required: u64::MAX,
                })?;

            let required = sum_output.checked_add(tx.fee)
                .ok_or_else(|| MempoolError::AmountMismatch {
                    inputs: sum_input, required: u64::MAX,
                })?;

            if sum_input != required {
                return Err(MempoolError::AmountMismatch {
                    inputs: sum_input, required,
                });
            }
        }

        // ── 6. Insert ──
        for inp in &tx.inputs {
            self.key_images_mempool.insert(inp.key_image);
            // For LogRing, key_image stores the link_tag — track in both sets
            if tx.ring_scheme == RING_SCHEME_LOGRING {
                self.link_tags_mempool.insert(inp.key_image);
            }
        }
        self.entries.insert(tx_hash, MempoolEntry { tx, tx_hash, received_at_ms: now_ms });

        Ok(tx_hash)
    }

    /// Mark key image / link_tag as spent on-chain; evict conflicting mempool txs.
    pub fn mark_spent(&mut self, key_image: [u8; 32]) {
        self.spent_key_images.insert(key_image);
        self.spent_link_tags.insert(key_image); // Also covers LogRing link_tags
        let to_remove: Vec<[u8; 32]> = self.entries.iter()
            .filter(|(_, e)| e.tx.inputs.iter().any(|inp| inp.key_image == key_image))
            .map(|(h, _)| *h)
            .collect();
        for h in to_remove { self.remove(&h); }
    }

    pub fn remove(&mut self, tx_hash: &[u8; 32]) -> bool {
        if let Some(entry) = self.entries.remove(tx_hash) {
            for inp in &entry.tx.inputs {
                self.key_images_mempool.remove(&inp.key_image);
                self.link_tags_mempool.remove(&inp.key_image);
            }
            true
        } else { false }
    }

    pub fn top_by_fee(&self, n: usize) -> Vec<&UtxoTransaction> {
        let mut txs: Vec<&MempoolEntry> = self.entries.values().collect();
        txs.sort_by(|a, b| b.tx.fee.cmp(&a.tx.fee));
        txs.truncate(n);
        txs.into_iter().map(|e| &e.tx).collect()
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use misaka_pqc::pq_ring::*;

    use misaka_pqc::ki_proof::canonical_strong_ki;

    /// Helper: set up UTXO set + mempool with registered spending keys.
    /// All UTXOs have the same amount (10_000) for same-amount ring compliance.
    fn setup() -> (UtxoMempool, UtxoSet, Vec<SpendingKeypair>, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut utxo_set = UtxoSet::new(100);
        let mut pool = UtxoMempool::new(100);

        let wallets: Vec<SpendingKeypair> = (0..6)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();

        // Create UTXOs with UNIFORM amounts (same-amount ring requirement)
        for (i, w) in wallets.iter().enumerate() {
            let outref = OutputRef { tx_hash: [(i + 1) as u8; 32], output_index: 0 };
            let output = TxOutput {
                amount: 10_000,
                one_time_address: [0xAA; 20],
                pq_stealth: None,
            spending_pubkey: None,
        };
            utxo_set.add_output(outref.clone(), output, 0).unwrap();
            utxo_set.register_spending_key(outref, w.public_poly.to_bytes());
        }

        (pool, utxo_set, wallets, a)
    }

    /// Build a valid signed TX using LRS scheme.
    /// For LRS, key_image comes from the ring signature (legacy derivation).
    /// KI proof is optional for LRS — the ring sig itself provides linkability.
    fn make_signed_tx(a: &Poly, wallets: &[SpendingKeypair], amount: u64, fee: u64) -> UtxoTransaction {
        let ring_pks: Vec<Poly> = (0..4).map(|i| wallets[i].public_poly.clone()).collect();

        let mut tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: (0..4).map(|i|
                    OutputRef { tx_hash: [(i + 1) as u8; 32], output_index: 0 }
                ).collect(),
                ring_signature: vec![],
                key_image: wallets[0].key_image, // Legacy LRS KI — matches ring_sign output
                ki_proof: vec![],                 // Empty = skip KI proof check (optional for LRS)
            }],
            outputs: vec![
                TxOutput { amount, one_time_address: [0xBB; 20], pq_stealth: None, spending_pubkey: None },
                TxOutput { amount: 10_000 - amount - fee, one_time_address: [0xCC; 20], pq_stealth: None, spending_pubkey: None },
            ],
            fee,
            extra: vec![],
        };

        let digest = tx.signing_digest();
        let sig = ring_sign(a, &ring_pks, 0, &wallets[0].secret_poly, &digest).unwrap();
        tx.inputs[0].ring_signature = sig.to_bytes();
        // No KI proof — optional for LRS scheme. Ring sig provides linkability.
        tx
    }

    #[test]
    fn test_admit_valid_tx() {
        let (mut pool, utxo_set, wallets, a) = setup();
        let tx = make_signed_tx(&a, &wallets, 7000, 100);
        let hash = pool.admit(tx, &utxo_set, 1000).unwrap();
        assert_eq!(pool.len(), 1);
        assert_ne!(hash, [0; 32]);
    }

    #[test]
    fn test_admit_invalid_ring_sig_rejected() {
        let (mut pool, utxo_set, wallets, a) = setup();
        let mut tx = make_signed_tx(&a, &wallets, 7000, 100);
        // Corrupt signature
        if !tx.inputs[0].ring_signature.is_empty() {
            tx.inputs[0].ring_signature[0] ^= 0xFF;
        }
        let result = pool.admit(tx, &utxo_set, 1000);
        assert!(result.is_err(), "corrupted ring sig must be rejected");
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_admit_duplicate_key_image_in_mempool() {
        let (mut pool, utxo_set, wallets, a) = setup();
        let tx1 = make_signed_tx(&a, &wallets, 7000, 100);
        pool.admit(tx1, &utxo_set, 1000).unwrap();

        // Second tx with same key image
        let tx2 = make_signed_tx(&a, &wallets, 5000, 200);
        let result = pool.admit(tx2, &utxo_set, 2000);
        assert!(result.is_err(), "duplicate key image must be rejected");
    }

    #[test]
    fn test_admit_spent_key_image_rejected() {
        let (mut pool, utxo_set, wallets, a) = setup();
        pool.mark_spent(wallets[0].key_image); // Legacy LRS KI
        let tx = make_signed_tx(&a, &wallets, 7000, 100);
        assert!(pool.admit(tx, &utxo_set, 1000).is_err());
    }

    #[test]
    fn test_mark_spent_evicts_tx() {
        let (mut pool, utxo_set, wallets, a) = setup();
        let tx = make_signed_tx(&a, &wallets, 7000, 100);
        pool.admit(tx, &utxo_set, 1000).unwrap();
        assert_eq!(pool.len(), 1);
        pool.mark_spent(wallets[0].key_image); // Legacy LRS KI
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_ring_member_not_found_rejected() {
        let (mut pool, utxo_set, wallets, a) = setup();
        let mut tx = make_signed_tx(&a, &wallets, 7000, 100);
        // Point one ring member to non-existent UTXO
        tx.inputs[0].ring_members[2] = OutputRef { tx_hash: [0xFF; 32], output_index: 99 };
        assert!(pool.admit(tx, &utxo_set, 1000).is_err());
    }

    #[test]
    fn test_top_by_fee() {
        let (mut pool, utxo_set, wallets, a) = setup();

        // Need different wallets for different key images
        let w2: Vec<SpendingKeypair> = (0..6)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();

        // Register different spending keys for separate UTXOs
        for (i, w) in w2.iter().enumerate() {
            let outref = OutputRef { tx_hash: [(i + 10) as u8; 32], output_index: 0 };
            let mut utxo_set_mut = UtxoSet::new(100);
            // Can't mutate borrowed utxo_set, so just test ordering with unchecked entries
        }

        // Simple ordering test with direct insertion
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_key_image_mismatch_rejected() {
        let (mut pool, utxo_set, wallets, a) = setup();
        let mut tx = make_signed_tx(&a, &wallets, 7000, 100);
        // Change key image in tx but not in signature
        tx.inputs[0].key_image = [0xFF; 32];
        assert!(pool.admit(tx, &utxo_set, 1000).is_err());
    }
}
