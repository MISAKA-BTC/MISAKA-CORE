//! 3072-bit modular arithmetic for MuHash3072.
//!
//! Prime: P = 2^3072 - 1103717 (Bitcoin Core / Kaspa MuHash3072 safe prime).
//! Operations: multiplication, modular inverse (Fermat), serialization.

use num_bigint::BigUint;
use std::sync::OnceLock;

/// Number of bytes in a 3072-bit number.
pub const BYTE_LEN: usize = 384;

/// Get the safe prime P = 2^3072 - 1103717.
pub(crate) fn prime() -> &'static BigUint {
    static P: OnceLock<BigUint> = OnceLock::new();
    P.get_or_init(|| (BigUint::from(1u32) << 3072) - BigUint::from(1_103_717u32))
}

/// Get P - 2 (for Fermat inversion: a^(P-2) mod P = a^(-1) mod P).
fn p_minus_2() -> &'static BigUint {
    static PM2: OnceLock<BigUint> = OnceLock::new();
    PM2.get_or_init(|| prime() - BigUint::from(2u32))
}

/// A 3072-bit number in the multiplicative group (Z/PZ)*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Num3072 {
    pub(crate) value: BigUint,
}

impl Num3072 {
    /// The multiplicative identity (1).
    pub fn one() -> Self {
        Self {
            value: BigUint::from(1u32),
        }
    }

    /// Create from a `BigUint`, reducing mod P.
    pub fn from_biguint(n: BigUint) -> Self {
        Self { value: n % prime() }
    }

    /// Multiply `self` by `other` in-place: self = (self * other) mod P.
    pub fn mul_mod(&mut self, other: &Num3072) {
        self.value = (&self.value * &other.value) % prime();
    }

    /// Compute the modular inverse via Fermat's little theorem: a^(P-2) mod P.
    ///
    /// Precondition: `self` is not zero (guaranteed by H_to_3072 output range).
    pub fn inverse(&self) -> Self {
        Self {
            value: self.value.modpow(p_minus_2(), prime()),
        }
    }

    /// Serialize to 384 bytes, little-endian, zero-padded.
    pub fn to_le_bytes(&self) -> [u8; BYTE_LEN] {
        let raw = self.value.to_bytes_le();
        let mut out = [0u8; BYTE_LEN];
        let len = raw.len().min(BYTE_LEN);
        out[..len].copy_from_slice(&raw[..len]);
        out
    }

    /// Deserialize from 384 little-endian bytes, reducing mod P.
    pub fn from_le_bytes(bytes: &[u8; BYTE_LEN]) -> Self {
        Self::from_biguint(BigUint::from_bytes_le(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_mul() {
        let one = Num3072::one();
        let mut acc = Num3072::one();
        acc.mul_mod(&one);
        assert_eq!(acc, Num3072::one());
    }

    #[test]
    fn test_p_minus_1_squared_is_one() {
        // (P-1)^2 mod P = (-1)^2 mod P = 1
        let p_minus_1 = Num3072 {
            value: prime() - BigUint::from(1u32),
        };
        let mut result = p_minus_1.clone();
        result.mul_mod(&p_minus_1);
        assert_eq!(result, Num3072::one());
    }

    #[test]
    fn test_inverse_roundtrip() {
        let a = Num3072::from_biguint(BigUint::from(42u32));
        let a_inv = a.inverse();
        let mut product = a.clone();
        product.mul_mod(&a_inv);
        assert_eq!(product, Num3072::one());
    }

    #[test]
    fn test_le_bytes_roundtrip() {
        let a = Num3072::from_biguint(BigUint::from(123_456_789u64));
        let bytes = a.to_le_bytes();
        let b = Num3072::from_le_bytes(&bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn test_reduction_mod_p() {
        // P + 1 should reduce to 1
        let big = prime() + BigUint::from(1u32);
        let reduced = Num3072::from_biguint(big);
        assert_eq!(reduced, Num3072::one());
    }

    #[test]
    fn test_zero_serialization() {
        // 0 mod P = 0 (edge case for serialization)
        let zero = Num3072::from_biguint(BigUint::from(0u32));
        let bytes = zero.to_le_bytes();
        assert_eq!(bytes, [0u8; BYTE_LEN]);
        let restored = Num3072::from_le_bytes(&bytes);
        assert_eq!(zero, restored);
    }
}
