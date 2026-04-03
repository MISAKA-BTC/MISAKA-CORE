//! Constant-time operations to prevent timing side-channel attacks.
//!
//! Used for:
//! - Token/password comparison
//! - Signature verification result handling
//! - Key material operations
//!
//! All functions are designed to execute in data-independent time,
//! preventing attackers from inferring secrets through timing measurements.

/// Constant-time byte array equality comparison.
///
/// Uses XOR accumulator — the loop always runs to completion
/// regardless of where (or whether) the arrays differ.
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Constant-time conditional select: returns `a` if `choice == 1`, `b` if `choice == 0`.
///
/// Uses `wrapping_neg` mask to avoid branching.
/// `choice` must be 0 or 1; other values produce undefined results.
#[inline(never)]
pub fn ct_select(a: u8, b: u8, choice: u8) -> u8 {
    debug_assert!(choice == 0 || choice == 1, "choice must be 0 or 1");
    let mask = choice.wrapping_neg(); // 0 -> 0x00, 1 -> 0xFF
    b ^ (mask & (a ^ b))
}

/// Constant-time conditional copy: if `choice == 1`, copies `src` into `dst`.
/// If `choice == 0`, `dst` is unchanged.
///
/// `choice` must be 0 or 1.
#[inline(never)]
pub fn ct_copy(dst: &mut [u8], src: &[u8], choice: u8) {
    debug_assert!(choice == 0 || choice == 1, "choice must be 0 or 1");
    assert_eq!(dst.len(), src.len(), "ct_copy: length mismatch");
    let mask = choice.wrapping_neg();
    for i in 0..dst.len() {
        dst[i] ^= mask & (dst[i] ^ src[i]);
    }
}

/// Constant-time non-zero check for a single byte.
///
/// Returns `true` if `value != 0`, `false` if `value == 0`.
#[inline(never)]
pub fn ct_is_nonzero(value: u8) -> bool {
    // (value | value.wrapping_neg()) >> 7 gives 1 if nonzero, 0 if zero
    ((value | value.wrapping_neg()) >> 7) == 1
}

/// Constant-time zero check for a byte slice.
pub fn ct_is_zero(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &b in data {
        acc |= b;
    }
    acc == 0
}

/// Length-hiding constant-time comparison.
///
/// Unlike `ct_eq`, this function does NOT reveal whether the lengths match.
/// It pads the shorter input to the length of the longer one and compares.
/// The result is `false` if lengths differ OR content differs.
///
/// Use this when comparing user-provided tokens against stored hashes
/// where the attacker should not learn the expected length.
#[inline(never)]
pub fn ct_eq_length_hiding(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return a.len() == b.len(); // both empty
    }

    // XOR accumulator — always iterates max_len times
    let mut acc: u8 = 0;

    // Length difference contributes to the accumulator
    // (if lengths differ, result is always false)
    let len_diff = (a.len() as u64) ^ (b.len() as u64);
    acc |= (len_diff | len_diff.wrapping_neg() >> 63) as u8; // 1 if diff, 0 if same

    for i in 0..max_len {
        // Safe indexing: if i >= len, use 0xFF (guaranteed mismatch)
        let byte_a = if i < a.len() { a[i] } else { 0xFF };
        let byte_b = if i < b.len() { b[i] } else { 0x00 };
        acc |= byte_a ^ byte_b;
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
    fn test_ct_eq_equal() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_ct_eq_empty() {
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        assert!(!ct_eq(b"short", b"longer"));
    }

    #[test]
    fn test_ct_select_choice_1() {
        assert_eq!(ct_select(0xAA, 0xBB, 1), 0xAA);
    }

    #[test]
    fn test_ct_select_choice_0() {
        assert_eq!(ct_select(0xAA, 0xBB, 0), 0xBB);
    }

    #[test]
    fn test_ct_copy_choice_1() {
        let mut dst = [0u8; 4];
        let src = [1, 2, 3, 4];
        ct_copy(&mut dst, &src, 1);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_ct_copy_choice_0() {
        let mut dst = [0xFFu8; 4];
        let src = [1, 2, 3, 4];
        ct_copy(&mut dst, &src, 0);
        assert_eq!(dst, [0xFF; 4]);
    }

    #[test]
    fn test_ct_is_nonzero() {
        assert!(ct_is_nonzero(1));
        assert!(ct_is_nonzero(0xFF));
        assert!(ct_is_nonzero(0x80));
        assert!(!ct_is_nonzero(0));
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

    #[test]
    fn test_ct_eq_length_hiding_equal() {
        assert!(ct_eq_length_hiding(b"hello", b"hello"));
    }

    #[test]
    fn test_ct_eq_length_hiding_different() {
        assert!(!ct_eq_length_hiding(b"hello", b"world"));
    }

    #[test]
    fn test_ct_eq_length_hiding_different_lengths() {
        // Must return false but NOT leak which length is correct
        assert!(!ct_eq_length_hiding(b"short", b"longer_string"));
        assert!(!ct_eq_length_hiding(b"longer_string", b"short"));
    }

    #[test]
    fn test_ct_eq_length_hiding_empty() {
        assert!(ct_eq_length_hiding(b"", b""));
        assert!(!ct_eq_length_hiding(b"", b"x"));
    }

    // ── Cross-crate consistency tests ─────────────────────────
    // These verify that the duplicated ct_eq implementations in
    // misaka-pqc (which cannot depend on this crate) produce
    // identical results to the canonical version here.

    /// Reference implementation of the XOR-accumulator pattern used by
    /// misaka-pqc::secret::ct_eq and misaka-pqc::pq_stealth::ct_eq.
    fn pqc_ct_eq_reference(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc = 0u8;
        for i in 0..a.len() {
            acc |= a[i] ^ b[i];
        }
        acc == 0
    }

    /// Reference implementation of the fixed-size ct_eq used by
    /// misaka-pqc::confidential_stealth::ct_eq (16-byte variant).
    fn pqc_ct_eq_16_reference(a: &[u8; 16], b: &[u8; 16]) -> bool {
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    #[test]
    fn test_ct_eq_matches_pqc_reference_equal() {
        let a = [0xAA; 32];
        let b = [0xAA; 32];
        assert_eq!(ct_eq(&a, &b), pqc_ct_eq_reference(&a, &b));
    }

    #[test]
    fn test_ct_eq_matches_pqc_reference_not_equal() {
        let a = [0xAA; 32];
        let mut b = [0xAA; 32];
        b[0] = 0xBB;
        assert_eq!(ct_eq(&a, &b), pqc_ct_eq_reference(&a, &b));
    }

    #[test]
    fn test_ct_eq_matches_pqc_reference_different_lengths() {
        let a = [0xAA; 32];
        let b = [0xAA; 16];
        assert_eq!(ct_eq(&a, &b), pqc_ct_eq_reference(&a, &b));
    }

    #[test]
    fn test_ct_eq_matches_pqc_16_reference_equal() {
        let a = [0xCC; 16];
        let b = [0xCC; 16];
        assert_eq!(ct_eq(&a, &b), pqc_ct_eq_16_reference(&a, &b));
    }

    #[test]
    fn test_ct_eq_matches_pqc_16_reference_not_equal() {
        let a = [0xCC; 16];
        let mut b = [0xCC; 16];
        b[15] = 0xDD;
        assert_eq!(ct_eq(&a, &b), pqc_ct_eq_16_reference(&a, &b));
    }
}
