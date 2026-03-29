//! 256-bit unsigned integer for difficulty and work calculations.

use std::fmt;
use std::ops::{Add, Sub, Mul, Div, Rem, Shr, Shl, BitAnd, BitOr, BitXor, Not};

/// 256-bit unsigned integer stored as four 64-bit limbs (little-endian).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uint256(pub [u64; 4]);

impl Uint256 {
    pub const ZERO: Uint256 = Uint256([0, 0, 0, 0]);
    pub const ONE: Uint256 = Uint256([1, 0, 0, 0]);
    pub const MAX: Uint256 = Uint256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    pub fn from_u64(val: u64) -> Self { Uint256([val, 0, 0, 0]) }
    pub fn from_u128(val: u128) -> Self {
        Uint256([val as u64, (val >> 64) as u64, 0, 0])
    }

    pub fn is_zero(&self) -> bool { self.0.iter().all(|&x| x == 0) }

    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return (i as u32) * 64 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    pub fn leading_zeros(&self) -> u32 { 256 - self.bits() }

    pub fn low_u64(&self) -> u64 { self.0[0] }
    pub fn low_u128(&self) -> u128 { (self.0[1] as u128) << 64 | self.0[0] as u128 }

    pub fn from_le_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[i*8..(i+1)*8].try_into().unwrap_or([0u8; 8]));
        }
        Uint256(limbs)
    }

    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i*8..(i+1)*8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        bytes
    }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[3 - i] = u64::from_be_bytes(bytes[i*8..(i+1)*8].try_into().unwrap_or([0u8; 8]));
        }
        Uint256(limbs)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i*8..(i+1)*8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        bytes
    }

    /// Overflowing addition.
    pub fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        (Uint256(result), carry > 0)
    }

    /// Overflowing subtraction.
    pub fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        (Uint256(result), borrow > 0)
    }

    /// Multiply by a u64.
    pub fn mul_u64(self, rhs: u64) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let prod = self.0[i] as u128 * rhs as u128 + carry;
            result[i] = prod as u64;
            carry = prod >> 64;
        }
        Uint256(result)
    }

    /// Divide by a u64, returning (quotient, remainder).
    pub fn div_rem_u64(self, divisor: u64) -> (Self, u64) {
        if divisor == 0 { panic!("division by zero"); }
        let mut result = [0u64; 4];
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            result[i] = (cur / divisor as u128) as u64;
            rem = cur % divisor as u128;
        }
        (Uint256(result), rem as u64)
    }
}

impl Add for Uint256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { self.overflowing_add(rhs).0 }
}

impl Sub for Uint256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { self.overflowing_sub(rhs).0 }
}

impl Shr<u32> for Uint256 {
    type Output = Self;
    fn shr(self, shift: u32) -> Self {
        if shift >= 256 { return Self::ZERO; }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut result = [0u64; 4];
        for i in 0..(4 - word_shift) {
            result[i] = self.0[i + word_shift] >> bit_shift;
            if bit_shift > 0 && i + word_shift + 1 < 4 {
                result[i] |= self.0[i + word_shift + 1] << (64 - bit_shift);
            }
        }
        Uint256(result)
    }
}

impl Shl<u32> for Uint256 {
    type Output = Self;
    fn shl(self, shift: u32) -> Self {
        if shift >= 256 { return Self::ZERO; }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut result = [0u64; 4];
        for i in word_shift..4 {
            result[i] = self.0[i - word_shift] << bit_shift;
            if bit_shift > 0 && i > word_shift {
                result[i] |= self.0[i - word_shift - 1] >> (64 - bit_shift);
            }
        }
        Uint256(result)
    }
}

impl BitAnd for Uint256 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Uint256([self.0[0]&rhs.0[0], self.0[1]&rhs.0[1], self.0[2]&rhs.0[2], self.0[3]&rhs.0[3]]) }
}

impl BitOr for Uint256 {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Uint256([self.0[0]|rhs.0[0], self.0[1]|rhs.0[1], self.0[2]|rhs.0[2], self.0[3]|rhs.0[3]]) }
}

impl Not for Uint256 {
    type Output = Self;
    fn not(self) -> Self { Uint256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]]) }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl fmt::Debug for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_be_bytes()))
    }
}

impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_be_bytes()))
    }
}

impl serde::Serialize for Uint256 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.to_be_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = Uint256::from_u64(100);
        let b = Uint256::from_u64(200);
        assert_eq!((a + b).low_u64(), 300);
    }

    #[test]
    fn test_sub() {
        let a = Uint256::from_u64(300);
        let b = Uint256::from_u64(100);
        assert_eq!((a - b).low_u64(), 200);
    }

    #[test]
    fn test_shift() {
        let a = Uint256::from_u64(1);
        assert_eq!((a << 64).0[1], 1);
        assert_eq!((a << 128).0[2], 1);
    }

    #[test]
    fn test_cmp() {
        assert!(Uint256::from_u64(10) < Uint256::from_u64(20));
        assert!(Uint256::MAX > Uint256::ZERO);
    }

    #[test]
    fn test_round_trip() {
        let a = Uint256([0x1234, 0x5678, 0x9ABC, 0xDEF0]);
        let le = a.to_le_bytes();
        let b = Uint256::from_le_bytes(&le);
        assert_eq!(a, b);
    }

    #[test]
    fn test_mul_u64() {
        let a = Uint256::from_u64(1_000_000);
        let b = a.mul_u64(1_000_000);
        assert_eq!(b.low_u64(), 1_000_000_000_000);
    }
}
