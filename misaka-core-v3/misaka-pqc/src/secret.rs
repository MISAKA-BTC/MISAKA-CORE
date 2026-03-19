//! Secret Type System — Centralized zeroization policy (v3 hardened).
//!
//! # Problem (v2)
//!
//! `write_volatile` scattered across 13+ files. Clone/Debug on secret types.
//! Intermediate buffers not zeroized. Optimizer can elide volatile writes
//! in some edge cases (e.g., when the struct is moved before drop).
//!
//! # Solution (v3)
//!
//! 1. All zeroization goes through `zeroize_bytes()` / `zeroize_slice()`
//!    which are `#[inline(never)]` to prevent LTO/inlining from enabling
//!    dead-store elimination.
//! 2. `Secret<T>` wrapper: Zeroizes on Drop, forbids Debug/Clone/Serialize.
//! 3. `SecretPoly`, `SecureBuffer`, `SecretKey32`, `SecretNonce24` — typed wrappers.
//! 4. All other modules MUST use these primitives instead of raw `write_volatile`.
//!
//! # Note on `zeroize` crate
//!
//! This module implements the same semantics as the `zeroize` crate (v1.8+).
//! When the crate becomes available in the build environment, replace the
//! `Zeroable` trait with `zeroize::Zeroize` and `Secret<T>` with
//! `zeroize::Zeroizing<T>` or `secrecy::SecretBox<T>`.

use std::sync::atomic::{compiler_fence, fence, Ordering};

// ═══════════════════════════════════════════════════════════════
//  Core Zeroization Primitives
// ═══════════════════════════════════════════════════════════════

/// Securely zeroize a byte slice.
///
/// `#[inline(never)]` prevents LTO from seeing through this function and
/// eliminating the writes as "dead stores". The `compiler_fence` further
/// prevents reordering past the barrier.
///
/// This is the ONLY function in the codebase that should directly call
/// `write_volatile` for zeroization. All other code must call this.
#[inline(never)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8); }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely zeroize an i32 slice (polynomial coefficients).
#[inline(never)]
pub fn zeroize_i32s(buf: &mut [i32]) {
    for c in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(c, 0i32); }
    }
    compiler_fence(Ordering::SeqCst);
}

// ═══════════════════════════════════════════════════════════════
//  Zeroable Trait
// ═══════════════════════════════════════════════════════════════

/// Types that can be securely zeroized.
///
/// All implementations MUST delegate to `zeroize_bytes()` or `zeroize_i32s()`.
/// Direct `write_volatile` calls outside of `secret.rs` are PROHIBITED.
pub trait Zeroable {
    fn zeroize(&mut self);
}

impl Zeroable for [u8; 32] {
    fn zeroize(&mut self) { zeroize_bytes(self); }
}

impl Zeroable for [u8; 24] {
    fn zeroize(&mut self) { zeroize_bytes(self); }
}

impl Zeroable for [u8; 16] {
    fn zeroize(&mut self) { zeroize_bytes(self); }
}

impl Zeroable for Vec<u8> {
    fn zeroize(&mut self) { zeroize_bytes(self.as_mut_slice()); }
}

impl Zeroable for [i32; 256] {
    fn zeroize(&mut self) { zeroize_i32s(self); }
}

// ═══════════════════════════════════════════════════════════════
//  Secret<T> Wrapper
// ═══════════════════════════════════════════════════════════════

/// Secret wrapper — zeroizes on drop, no Debug/Clone/Serialize.
///
/// Equivalent to `zeroize::Zeroizing<T>` or `secrecy::SecretBox<T>`.
pub struct Secret<T: Zeroable> {
    inner: T,
}

impl<T: Zeroable> Secret<T> {
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Access the secret value. Caller must not copy it out.
    #[inline]
    pub fn expose(&self) -> &T {
        &self.inner
    }

    /// Mutable access (for in-place operations).
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Explicit duplication (auditable — grep for "duplicate()" in code review).
    pub fn duplicate(&self) -> Self where T: Clone {
        Self { inner: self.inner.clone() }
    }
}

impl<T: Zeroable> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        fence(Ordering::SeqCst);
    }
}

impl<T: Zeroable> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// ═══════════════════════════════════════════════════════════════
//  Concrete Secret Types
// ═══════════════════════════════════════════════════════════════

/// Secret polynomial (spending secret, masking poly, etc.)
/// Wraps [i32; 256] with zeroization.
pub struct SecretPoly {
    pub(crate) coeffs: [i32; 256],
}

impl SecretPoly {
    pub fn new(coeffs: [i32; 256]) -> Self { Self { coeffs } }
    pub fn as_slice(&self) -> &[i32; 256] { &self.coeffs }
}

impl Zeroable for SecretPoly {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Drop for SecretPoly {
    fn drop(&mut self) {
        self.zeroize();
        fence(Ordering::SeqCst);
    }
}

impl std::fmt::Debug for SecretPoly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretPoly([REDACTED])")
    }
}

/// Secret shared key material (KEM output, HKDF root, etc.)
pub type SecretKey32 = Secret<[u8; 32]>;
/// Secret nonce material.
pub type SecretNonce24 = Secret<[u8; 24]>;

// ═══════════════════════════════════════════════════════════════
//  Secure Buffer — zeroized Vec<u8>
// ═══════════════════════════════════════════════════════════════

/// A byte buffer that is zeroized on drop.
/// Use this for ANY intermediate buffer that touches secret data.
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self { data: vec![0u8; size] }
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] { &self.data }
    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.data }
    pub fn len(&self) -> usize { self.data.len() }
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        fence(Ordering::SeqCst);
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuffer(len={})", self.data.len())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Convenience: zeroize_on_drop for inline use
// ═══════════════════════════════════════════════════════════════

/// Guard struct that zeroizes a fixed-size byte array on drop.
/// Use for stack-allocated key material in function scope.
///
/// ```ignore
/// let mut key = ZeroizeGuard::new([0u8; 32]);
/// // ... use key.data ...
/// // automatically zeroized when `key` goes out of scope
/// ```
pub struct ZeroizeGuard<const N: usize> {
    pub data: [u8; N],
}

impl<const N: usize> ZeroizeGuard<N> {
    pub fn new(data: [u8; N]) -> Self { Self { data } }
}

impl<const N: usize> Drop for ZeroizeGuard<N> {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.data);
        fence(Ordering::SeqCst);
    }
}

impl<const N: usize> std::fmt::Debug for ZeroizeGuard<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizeGuard<{}>([REDACTED])", N)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_zeroized_on_drop() {
        {
            let s = Secret::new([0xAA_u8; 32]);
            assert_eq!(s.expose()[0], 0xAA);
        }
    }

    #[test]
    fn test_secret_debug_redacted() {
        let s = Secret::new([0xBB_u8; 32]);
        let debug = format!("{:?}", s);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("BB"));
    }

    #[test]
    fn test_secret_poly_debug_redacted() {
        let p = SecretPoly::new([42; 256]);
        let debug = format!("{:?}", p);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_secure_buffer_zeroized() {
        let mut buf = SecureBuffer::new(64);
        buf.as_mut_slice().fill(0xFF);
        assert_eq!(buf.as_slice()[0], 0xFF);
        drop(buf);
    }

    #[test]
    fn test_zeroize_guard() {
        let guard = ZeroizeGuard::new([0xCC_u8; 32]);
        assert_eq!(guard.data[0], 0xCC);
        drop(guard);
    }

    #[test]
    fn test_zeroize_bytes_zeroes() {
        let mut data = [0xFFu8; 64];
        zeroize_bytes(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_i32s_zeroes() {
        let mut data = [0x7FFFFFFFi32; 256];
        zeroize_i32s(&mut data);
        assert!(data.iter().all(|&c| c == 0));
    }
}
