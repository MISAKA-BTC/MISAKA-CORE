//! MuHash3072 — Cryptographically secure incremental multiset hash.
//!
//! Uses multiplication in the group (Z/PZ)* where P = 2^3072 - 1103717
//! (Bitcoin Core / Kaspa safe prime). This replaces the insecure XOR-based
//! accumulator that was a MAINNET-BLOCKER (NM-14).
//!
//! Operations:
//! - add(x): acc = acc * H(x) mod P
//! - remove(x): acc = acc * H(x)^(P-2) mod P  (Fermat inverse)
//! - combine(a, b): a = a * b mod P
//! - finalize(): SHA3-256("MISAKA:muhash3072:finalize:v1:" || acc_bytes)

mod data_to_num3072;
mod num3072;

use data_to_num3072::data_to_num3072;
use num3072::Num3072;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};

/// Domain separator for finalization.
const FINALIZE_DOMAIN: &[u8] = b"MISAKA:muhash3072:finalize:v1:";

/// MuHash3072 accumulator — cryptographically secure multiset hash.
///
/// Uses multiplication in the multiplicative group modulo a 3072-bit safe prime,
/// providing collision resistance equivalent to ~128-bit security.
///
/// The identity element is 1 (empty multiset).
#[derive(Clone, Debug)]
pub struct MuHash {
    state: Num3072,
}

impl MuHash {
    /// Create a new MuHash with the identity element (empty multiset).
    pub fn new() -> Self {
        Self {
            state: Num3072::one(),
        }
    }

    /// Add an element to the multiset: acc = acc * H(data) mod P.
    pub fn add_element(&mut self, data: &[u8]) {
        let elem = data_to_num3072(data);
        self.state.mul_mod(&elem);
    }

    /// Remove an element from the multiset: acc = acc * H(data)^(-1) mod P.
    pub fn remove_element(&mut self, data: &[u8]) {
        let elem = data_to_num3072(data);
        let inv = elem.inverse();
        self.state.mul_mod(&inv);
    }

    /// Combine another MuHash accumulator into this one: self = self * other mod P.
    pub fn combine(&mut self, other: &MuHash) {
        self.state.mul_mod(&other.state);
    }

    /// Finalize the accumulator to a 32-byte hash.
    ///
    /// `SHA3-256("MISAKA:muhash3072:finalize:v1:" || state.to_le_bytes(384))`
    pub fn finalize(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(FINALIZE_DOMAIN);
        hasher.update(&self.state.to_le_bytes());
        hasher.finalize().into()
    }
}

impl Default for MuHash {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for MuHash {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl Eq for MuHash {}

// ═══════════════════════════════════════════════════════════════
//  Serde: serialize state as 384-byte LE blob
// ═══════════════════════════════════════════════════════════════

impl Serialize for MuHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.state.to_le_bytes().to_vec();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MuHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != num3072::BYTE_LEN {
            return Err(serde::de::Error::custom(format!(
                "MuHash state must be {} bytes, got {}",
                num3072::BYTE_LEN,
                bytes.len()
            )));
        }
        let mut arr = [0u8; num3072::BYTE_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            state: Num3072::from_le_bytes(&arr),
        })
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove_inverse() {
        // add(x); add(y); remove(x) == add(y)
        let mut mh = MuHash::new();
        mh.add_element(b"utxo_1");
        mh.add_element(b"utxo_2");
        mh.remove_element(b"utxo_1");

        let mut expected = MuHash::new();
        expected.add_element(b"utxo_2");

        assert_eq!(mh.finalize(), expected.finalize());
    }

    #[test]
    fn test_commutativity() {
        // add(x); add(y) == add(y); add(x)
        let mut mh1 = MuHash::new();
        mh1.add_element(b"a");
        mh1.add_element(b"b");

        let mut mh2 = MuHash::new();
        mh2.add_element(b"b");
        mh2.add_element(b"a");

        assert_eq!(mh1.finalize(), mh2.finalize());
    }

    #[test]
    fn test_add_remove_roundtrip() {
        // add(x); add(y); remove(y); add(y) == add(x); add(y)
        let mut mh = MuHash::new();
        mh.add_element(b"utxo_1");
        mh.add_element(b"utxo_2");
        let state_with_both = mh.finalize();

        mh.remove_element(b"utxo_2");
        mh.add_element(b"utxo_2");
        assert_eq!(mh.finalize(), state_with_both);
    }

    #[test]
    fn test_empty_finalize_deterministic() {
        let mh1 = MuHash::new();
        let mh2 = MuHash::new();
        let f = mh1.finalize();
        assert_eq!(f, mh2.finalize());
        // Regression: empty MuHash always produces the same hash.
        // (Identity element = 1, finalize = SHA3-256(domain || 1_le_384))
        assert_eq!(f, mh1.finalize());
    }

    /// Print known-answer values for manual inspection / pinning.
    /// Once values are pinned below, this test guards against regressions.
    #[test]
    fn test_known_answer_vectors() {
        // KAV-1: empty MuHash finalize (identity = 1)
        let empty_hash = MuHash::new().finalize();
        eprintln!("KAV-1 empty finalize = {}", hex::encode(empty_hash));

        // KAV-2: single element "test"
        let mut mh = MuHash::new();
        mh.add_element(b"test");
        let single_hash = mh.finalize();
        eprintln!(
            "KAV-2 add(\"test\") finalize = {}",
            hex::encode(single_hash)
        );

        // KAV-3: two elements, order-independent
        let mut mh_ab = MuHash::new();
        mh_ab.add_element(b"alpha");
        mh_ab.add_element(b"beta");
        let ab_hash = mh_ab.finalize();
        eprintln!("KAV-3 add(alpha,beta) finalize = {}", hex::encode(ab_hash));

        // KAV-4: Num3072 arithmetic sanity — P is prime: (P-1)! ≡ -1 mod P (Wilson).
        // We verify a simpler property: 2^3072 mod P == 1103717 (the offset c).
        let two_pow_3072 = num3072::Num3072::from_biguint(num_bigint::BigUint::from(1u32) << 3072);
        let expected_c = num3072::Num3072::from_biguint(num_bigint::BigUint::from(1_103_717u32));
        assert_eq!(
            two_pow_3072, expected_c,
            "P = 2^3072 - 1103717 verification"
        );

        // Pinned regression values. These MUST NOT change across releases.
        // Any change means the consensus-critical hash function broke.
        assert_eq!(
            hex::encode(empty_hash),
            "4bd2c7b4a99b5c581a406ca3215d2fac591160bcd52936004e73591eb890c66f",
            "KAV-1: empty MuHash3072 finalize changed — consensus break"
        );
        assert_eq!(
            hex::encode(single_hash),
            "24f2a0fadb64e722c02fa30e9fe2badd5d9e1c061cbe66ca6270f8eed6723dc1",
            "KAV-2: add(\"test\") finalize changed — consensus break"
        );
        assert_eq!(
            hex::encode(ab_hash),
            "82463efb6b1082caae733eadf22daa6271a764ee61107cfbf1961de487da5011",
            "KAV-3: add(alpha,beta) finalize changed — consensus break"
        );
    }

    #[test]
    fn test_combine() {
        let mut mh1 = MuHash::new();
        mh1.add_element(b"a");

        let mut mh2 = MuHash::new();
        mh2.add_element(b"b");

        let mut combined = MuHash::new();
        combined.add_element(b"a");
        combined.add_element(b"b");

        mh1.combine(&mh2);
        assert_eq!(mh1.finalize(), combined.finalize());
    }

    #[test]
    fn test_large_set_add_remove() {
        // Add 100 elements, remove first 50, verify equals adding last 50 directly.
        let mut mh_full = MuHash::new();
        for i in 0u32..100 {
            mh_full.add_element(&i.to_le_bytes());
        }
        for i in 0u32..50 {
            mh_full.remove_element(&i.to_le_bytes());
        }

        let mut mh_half = MuHash::new();
        for i in 50u32..100 {
            mh_half.add_element(&i.to_le_bytes());
        }

        assert_eq!(mh_full.finalize(), mh_half.finalize());
    }

    #[test]
    #[ignore] // Slow: ~5000 modular inversions on 3072-bit numbers
    fn test_10k_elements() {
        // Spec requirement: 10k add, 5k remove, verify against direct 5k add.
        let mut mh_full = MuHash::new();
        for i in 0u32..10_000 {
            mh_full.add_element(&i.to_le_bytes());
        }
        for i in 0u32..5_000 {
            mh_full.remove_element(&i.to_le_bytes());
        }

        let mut mh_half = MuHash::new();
        for i in 5_000u32..10_000 {
            mh_half.add_element(&i.to_le_bytes());
        }

        assert_eq!(mh_full.finalize(), mh_half.finalize());
    }
}
