//! SMT key and value derivation. FROZEN at v0.7.x.
//!
//! Key derivation: H(DST_KEY || tx_hash || output_index_be32).
//! Value derivation: H(DST_VALUE || serialized_output).

use crate::domain::{DST_KEY, DST_VALUE};
use crate::hash::{sha3_with_dst, Hash};

/// Derive an SMT key from a UTXO outref.
///
/// Inputs are fixed-size (tx_hash: 32 bytes, output_index: u32 BE).
/// FROZEN: this derivation is a consensus rule.
#[inline]
pub fn smt_key(tx_hash: &[u8; 32], output_index: u32) -> Hash {
    sha3_with_dst(DST_KEY, &[tx_hash, &output_index.to_be_bytes()])
}

/// Derive a value hash from serialized UTXO output.
///
/// The value MUST be the borsh-encoded TxOutput.
#[inline]
pub fn smt_value(serialized_output: &[u8]) -> Hash {
    sha3_with_dst(DST_VALUE, &[serialized_output])
}

/// MSB-first bit access for SMT path navigation.
///
/// `bit_at(key, 0)` = MSB of `key[0]`
/// `bit_at(key, 255)` = LSB of `key[31]`
#[inline]
pub fn bit_at(key: &Hash, depth: usize) -> bool {
    debug_assert!(depth < 256);
    let byte = key[depth / 8];
    (byte >> (7 - (depth % 8))) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_at_msb() {
        let key = [0x80u8; 32]; // MSB set in every byte
        assert!(bit_at(&key, 0)); // MSB of byte 0
        assert!(!bit_at(&key, 1));
    }

    #[test]
    fn test_bit_at_lsb() {
        let mut key = [0u8; 32];
        key[31] = 0x01; // LSB of last byte
        assert!(bit_at(&key, 255));
        assert!(!bit_at(&key, 254));
    }

    #[test]
    fn test_smt_key_deterministic() {
        let a = smt_key(&[1u8; 32], 0);
        let b = smt_key(&[1u8; 32], 0);
        assert_eq!(a, b);
    }

    #[test]
    fn test_smt_key_differs_by_index() {
        let a = smt_key(&[1u8; 32], 0);
        let b = smt_key(&[1u8; 32], 1);
        assert_ne!(a, b);
    }
}
