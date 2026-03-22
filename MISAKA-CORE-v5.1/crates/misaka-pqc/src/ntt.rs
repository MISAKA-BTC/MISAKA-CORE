//! Negacyclic NTT for R_q = Z_12289[X]/(X^256+1).
//!
//! Method: pre-twist + standard radix-2 FFT.
//!   Forward: a[i] *= ψ^i (twist), then standard FFT with ω = ψ²
//!   Inverse: standard IFFT with ω⁻¹, scale by n⁻¹, untwist by ψ^{-i}
//!
//! This converts negacyclic (mod X^n+1) into cyclic (mod X^n-1)
//! where standard FFT applies correctly.

use super::pq_ring::{Poly, N, Q};

#[inline(always)]
fn mod_reduce(a: i32) -> i32 {
    let mut r = a % Q;
    if r < 0 {
        r += Q;
    }
    r
}

#[inline(always)]
fn mod_mul(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) % Q as i64) as i32
}

fn mod_pow(mut base: i64, mut exp: u64, modulus: i64) -> i64 {
    let mut result = 1i64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

fn bitrev8(mut x: usize) -> usize {
    let mut r = 0;
    for _ in 0..8 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Precompute table of n powers of a root.
fn power_table(root: i32, n: usize) -> Vec<i32> {
    let mut t = vec![0i32; n];
    t[0] = 1;
    for i in 1..n {
        t[i] = mod_mul(t[i - 1], root);
    }
    t
}

/// Forward negacyclic NTT.
pub fn forward_ntt(a: &mut [i32; N]) {
    let q = Q as i64;
    let psi = mod_pow(11, 24, q) as i32; // ψ: primitive 512th root
    let omega = mod_mul(psi, psi); // ω = ψ²: primitive 256th root

    let psi_pow = power_table(psi, N);
    let omega_pow = power_table(omega, N);

    // Step 1: twist — a[i] *= ψ^i
    for i in 0..N {
        a[i] = mod_mul(a[i], psi_pow[i]);
    }

    // Step 2: bit-reverse permutation
    for i in 0..N {
        let j = bitrev8(i);
        if i < j {
            a.swap(i, j);
        }
    }

    // Step 3: Cooley-Tukey DIT butterfly
    let mut half = 1;
    while half < N {
        let step = N / (2 * half);
        for k in 0..half {
            let w = omega_pow[k * step];
            let mut i = k;
            while i < N {
                let j = i + half;
                let t = mod_mul(w, a[j]);
                a[j] = mod_reduce(a[i] - t);
                a[i] = mod_reduce(a[i] + t);
                i += 2 * half;
            }
        }
        half <<= 1;
    }
}

/// Inverse negacyclic NTT.
pub fn inverse_ntt(a: &mut [i32; N]) {
    let q = Q as i64;
    let psi = mod_pow(11, 24, q) as i32;
    let psi_inv = mod_pow(psi as i64, (Q - 2) as u64, q) as i32;
    let omega_inv = mod_pow(mod_mul(psi, psi) as i64, (Q - 2) as u64, q) as i32;
    let n_inv = mod_pow(N as i64, (Q - 2) as u64, q) as i32;

    let omega_inv_pow = power_table(omega_inv, N);
    let psi_inv_pow = power_table(psi_inv, N);

    // Step 1: bit-reverse permutation
    for i in 0..N {
        let j = bitrev8(i);
        if i < j {
            a.swap(i, j);
        }
    }

    // Step 2: Cooley-Tukey DIT butterfly with ω⁻¹
    let mut half = 1;
    while half < N {
        let step = N / (2 * half);
        for k in 0..half {
            let w = omega_inv_pow[k * step];
            let mut i = k;
            while i < N {
                let j = i + half;
                let t = mod_mul(w, a[j]);
                a[j] = mod_reduce(a[i] - t);
                a[i] = mod_reduce(a[i] + t);
                i += 2 * half;
            }
        }
        half <<= 1;
    }

    // Step 3: scale by n⁻¹ and untwist by ψ^{-i}
    for i in 0..N {
        a[i] = mod_mul(mod_mul(a[i], n_inv), psi_inv_pow[i]);
    }
}

/// Pointwise mul in NTT domain.
pub fn pointwise_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = mod_mul(a[i], b[i]);
    }
    c
}

/// NTT-based polynomial multiplication in R_q = Z_q[X]/(X^256+1).
pub fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    let mut a_ntt = a.coeffs;
    let mut b_ntt = b.coeffs;
    forward_ntt(&mut a_ntt);
    forward_ntt(&mut b_ntt);
    let mut c_ntt = pointwise_mul(&a_ntt, &b_ntt);
    inverse_ntt(&mut c_ntt);
    let mut result = Poly::zero();
    for i in 0..N {
        result.coeffs[i] = mod_reduce(c_ntt[i]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_ring::{derive_public_param, DEFAULT_A_SEED};

    #[test]
    fn test_ntt_roundtrip() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let original = a.coeffs;
        let mut data = original;
        forward_ntt(&mut data);
        assert_ne!(data, original, "NTT domain must differ");
        inverse_ntt(&mut data);
        for i in 0..N {
            assert_eq!(mod_reduce(data[i]), original[i], "mismatch at {i}");
        }
    }

    #[test]
    fn test_ntt_mul_vs_schoolbook() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut b = Poly::zero();
        b.coeffs[0] = 1;
        b.coeffs[1] = 2;
        b.coeffs[100] = Q - 1;
        let sb = a.mul_schoolbook(&b);
        let nt = ntt_mul(&a, &b);
        assert_eq!(sb.coeffs, nt.coeffs, "NTT must match schoolbook");
    }

    #[test]
    fn test_ntt_mul_identity() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        assert_eq!(ntt_mul(&a, &one).coeffs, a.coeffs);
    }

    #[test]
    fn test_ntt_mul_commutative() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut b = Poly::zero();
        for i in 0..10 {
            b.coeffs[i] = ((i * 137 + 42) % Q as usize) as i32;
        }
        assert_eq!(ntt_mul(&a, &b).coeffs, ntt_mul(&b, &a).coeffs);
    }

    #[test]
    fn test_ntt_zero() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        assert_eq!(ntt_mul(&a, &Poly::zero()).coeffs, [0i32; N]);
    }

    #[test]
    fn test_ntt_mul_random_pair() {
        // Two non-trivial polynomials
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = ((i * 31 + 7) % Q as usize) as i32;
            b.coeffs[i] = ((i * 53 + 13) % Q as usize) as i32;
        }
        let sb = a.mul_schoolbook(&b);
        let nt = ntt_mul(&a, &b);
        assert_eq!(sb.coeffs, nt.coeffs);
    }
}
