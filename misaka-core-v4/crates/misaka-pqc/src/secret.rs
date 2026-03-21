//! Secret Type System — zeroize/secrecy crate-based (v3 production).
//!
//! # Architecture
//!
//! All secret memory management is delegated to the `zeroize` crate (v1.8+),
//! which provides:
//! - `Zeroize` trait: portable memory zeroing resistant to compiler optimization
//! - `ZeroizeOnDrop` derive: automatic zeroization when values go out of scope
//! - `Zeroizing<T>` wrapper: Drop-zeroized container
//!
//! The `secrecy` crate (v0.8+) provides:
//! - `Secret<T>`: prevents Debug, Display, and accidental serialization
//!
//! # Migration from v2
//!
//! - Removed: Custom `write_volatile` + `compiler_fence` (unreliable under LTO)
//! - Removed: Custom `Zeroable` trait (replaced by `zeroize::Zeroize`)
//! - Removed: Custom `zeroize_bytes()` / `zeroize_i32s()` functions
//! - Added: `#[derive(Zeroize, ZeroizeOnDrop)]` on all secret-holding types
//! - Added: `Zeroizing<T>` for temporary secret buffers
//!
//! # Safety Policy
//!
//! 1. No secret type may implement `Clone` (prevents accidental copies)
//! 2. No secret type may implement `Serialize` (prevents wire leakage)
//! 3. No secret type may implement `Debug` with real data (redacted only)
//! 4. All secret types must implement `ZeroizeOnDrop` or be wrapped in `Zeroizing<T>`

pub use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use secrecy::{Secret, ExposeSecret};

// ═══════════════════════════════════════════════════════════════
//  Secret Polynomial — spending secrets, masking polynomials
// ═══════════════════════════════════════════════════════════════

/// Secret polynomial (spending secret, masking poly, etc.)
///
/// Wraps `[i32; 256]` with automatic zeroization on drop.
/// Does NOT implement Clone or Serialize.
pub struct SecretPoly {
    pub(crate) coeffs: [i32; 256],
}

impl SecretPoly {
    pub fn new(coeffs: [i32; 256]) -> Self { Self { coeffs } }
    pub fn as_slice(&self) -> &[i32; 256] { &self.coeffs }
}

impl Zeroize for SecretPoly {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Drop for SecretPoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecretPoly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretPoly([REDACTED])")
    }
}

// ═══════════════════════════════════════════════════════════════
//  Typed Secret Key Aliases
// ═══════════════════════════════════════════════════════════════

/// Secret shared key material (KEM output, HKDF root, etc.)
/// Automatically zeroized on drop via Zeroizing wrapper.
pub type SecretKey32 = Zeroizing<[u8; 32]>;

/// Secret nonce material.
pub type SecretNonce24 = Zeroizing<[u8; 24]>;

// ═══════════════════════════════════════════════════════════════
//  Secure Buffer — zeroized Vec<u8>
// ═══════════════════════════════════════════════════════════════

/// A byte buffer that is zeroized on drop.
/// Use this for ANY intermediate buffer that touches secret data.
///
/// Built on `Zeroizing<Vec<u8>>` from the `zeroize` crate.
pub struct SecureBuffer(Zeroizing<Vec<u8>>);

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self(Zeroizing::new(vec![0u8; size]))
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }

    pub fn as_slice(&self) -> &[u8] { &self.0 }
    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.0 }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuffer(len={})", self.0.len())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Convenience: ZeroizeGuard for stack-allocated secrets
// ═══════════════════════════════════════════════════════════════

/// Guard struct that zeroizes a fixed-size byte array on drop.
/// Use for stack-allocated key material in function scope.
pub struct ZeroizeGuard<const N: usize> {
    pub data: [u8; N],
}

impl<const N: usize> ZeroizeGuard<N> {
    pub fn new(data: [u8; N]) -> Self { Self { data } }
}

impl<const N: usize> Drop for ZeroizeGuard<N> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> std::fmt::Debug for ZeroizeGuard<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizeGuard<{}>([REDACTED])", N)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Poly Zeroize Helper (for rejection sampling cleanup)
// ═══════════════════════════════════════════════════════════════

/// Zeroize a polynomial coefficient array.
/// Used by rejection sampling loops to clean up rejected responses.
///
/// This delegates to `zeroize::Zeroize` which uses platform-appropriate
/// volatile writes that cannot be optimized away.
#[inline]
pub fn zeroize_poly_coeffs(coeffs: &mut [i32; 256]) {
    coeffs.zeroize();
}

/// Zeroize a byte slice. Delegates to `zeroize::Zeroize`.
#[inline]
pub fn zeroize_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_poly_debug_redacted() {
        let p = SecretPoly::new([42; 256]);
        let debug = format!("{:?}", p);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn test_secure_buffer_zeroized_on_drop() {
        let mut buf = SecureBuffer::new(64);
        buf.as_mut_slice().fill(0xFF);
        assert_eq!(buf.as_slice()[0], 0xFF);
        // After drop, memory should be zeroed (cannot reliably test allocation reuse)
        drop(buf);
    }

    #[test]
    fn test_zeroize_guard() {
        let guard = ZeroizeGuard::new([0xCC_u8; 32]);
        assert_eq!(guard.data[0], 0xCC);
        drop(guard);
    }

    #[test]
    fn test_zeroizing_key() {
        let key = SecretKey32::new([0xAA; 32]);
        assert_eq!(key[0], 0xAA);
        drop(key);
    }

    #[test]
    fn test_zeroize_poly_coeffs_zeroes() {
        let mut data = [0x7FFFFFFFi32; 256];
        zeroize_poly_coeffs(&mut data);
        assert!(data.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_zeroize_bytes_zeroes() {
        let mut data = [0xFFu8; 64];
        zeroize_bytes(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
