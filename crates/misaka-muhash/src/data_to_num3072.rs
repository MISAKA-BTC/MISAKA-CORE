//! Hash arbitrary data to a Num3072 group element.
//!
//! Algorithm: SHA3-256 key derivation + ChaCha20 stream expansion to 384 bytes.
//! Domain: "MISAKA:muhash3072:elem:v1:"
//!
//! This follows the same pattern as Bitcoin Core's `data_to_num3072`:
//! derive a symmetric key from the input, use it to seed a stream cipher,
//! expand to 3072 bits, and reduce mod P.

use crate::num3072::{Num3072, BYTE_LEN};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use num_bigint::BigUint;
use sha3::{Digest, Sha3_256};

/// Domain separator for element hashing.
const ELEM_DOMAIN: &[u8] = b"MISAKA:muhash3072:elem:v1:";

/// Hash `data` into a Num3072 group element.
///
/// 1. key = SHA3-256(domain || data)
/// 2. stream = ChaCha20(key, nonce=0) → 384 bytes
/// 3. result = stream (as LE integer) mod P
pub fn data_to_num3072(data: &[u8]) -> Num3072 {
    // Derive 32-byte ChaCha20 key via SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(ELEM_DOMAIN);
    hasher.update(data);
    let key: [u8; 32] = hasher.finalize().into();

    // Generate 384 bytes of pseudorandom data via ChaCha20 keystream
    let nonce = [0u8; 12];
    let mut buf = [0u8; BYTE_LEN];
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut buf);

    // Interpret as LE integer, reduce mod P
    Num3072::from_biguint(BigUint::from_bytes_le(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let a = data_to_num3072(b"test_data");
        let b = data_to_num3072(b"test_data");
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_inputs_differ() {
        let a = data_to_num3072(b"input_a");
        let b = data_to_num3072(b"input_b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_not_identity() {
        let elem = data_to_num3072(b"anything");
        assert_ne!(elem, Num3072::one());
    }

    #[test]
    fn test_domain_prefix_matters() {
        // Ensure the domain prefix affects the output (not just passthrough of data)
        let a = data_to_num3072(b"");
        let b = data_to_num3072(b"\x00");
        assert_ne!(a, b);
    }
}
