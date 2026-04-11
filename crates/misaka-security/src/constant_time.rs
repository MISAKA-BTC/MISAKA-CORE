//! Constant-time operations to prevent timing side-channel attacks.
//!
//! Used for:
//! - Token/password comparison
//! - Signature verification result handling
//! - Key material operations

use zeroize::Zeroize;

/// Constant-time byte array comparison.
///
/// SEC-FIX R2-C1: Length comparison uses `usize`, not truncated `u8`.
/// The previous `(a.len() ^ b.len()) as u8` cast silently bypassed the
/// check for length differences that are multiples of 256.
///
/// SEC-FIX N-M8: `#[inline(never)]` prevents the compiler from inlining
/// and optimizing away the constant-time loop.
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let lengths_differ = a.len() != b.len();
    let mut diff: u8 = 0;
    let min_len = if a.len() < b.len() { a.len() } else { b.len() };
    for i in 0..min_len {
        diff |= a[i] ^ b[i];
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    diff == 0 && !lengths_differ
}

/// Constant-time selection: returns a if condition is true, b otherwise.
///
/// SEC-FIX N-L9: Uses arithmetic mask instead of if/else branch.
pub fn ct_select(condition: bool, a: u8, b: u8) -> u8 {
    let mask = (-(condition as i8)) as u8;
    (a & mask) | (b & !mask)
}

/// Constant-time conditional copy.
///
/// SEC-FIX N-L9: Uses arithmetic mask instead of if/else branch.
pub fn ct_copy_if(condition: bool, dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len());
    let mask = (-(condition as i8)) as u8;
    for i in 0..dest.len() {
        dest[i] = (src[i] & mask) | (dest[i] & !mask);
    }
}

/// Constant-time zero check.
pub fn ct_is_zero(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &b in data {
        acc |= b;
    }
    acc == 0
}

/// Zeroize a byte slice (compiler-safe, won't be optimized away).
///
/// SEC-FIX R2-M4: Uses `zeroize` crate instead of hand-rolled unsafe
/// `write_volatile`, consistent with all other zeroization sites.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_ct_eq_length_multiple_of_256() {
        assert!(!ct_eq(&[0u8; 256], &[]));
        assert!(!ct_eq(&[0u8; 512], &[0u8; 256]));
        assert!(!ct_eq(&[0u8; 0], &[0u8; 256]));
        assert!(ct_eq(&[0u8; 256], &[0u8; 256]));
    }

    #[test]
    fn test_ct_is_zero() {
        assert!(ct_is_zero(&[0, 0, 0]));
        assert!(!ct_is_zero(&[0, 1, 0]));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = vec![42u8; 32];
        secure_zero(&mut data);
        assert!(ct_is_zero(&data));
    }
}
