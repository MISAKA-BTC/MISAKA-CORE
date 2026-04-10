//! Constant-time operations to prevent timing side-channel attacks.
//!
//! Used for:
//! - Token/password comparison
//! - Signature verification result handling
//! - Key material operations

/// Constant-time byte array comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time selection: returns a if condition is true, b otherwise.
pub fn ct_select(condition: bool, a: u8, b: u8) -> u8 {
    let mask = if condition { 0xFF } else { 0x00 };
    (a & mask) | (b & !mask)
}

/// Constant-time conditional copy.
pub fn ct_copy_if(condition: bool, dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len());
    let mask = if condition { 0xFF } else { 0x00 };
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
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
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
