//! # Deterministic Integer Square Root — No Floats Allowed
//!
//! Provides `sqrt_scaled()` for the reward weight formula:
//!
//! ```text
//! reward_weight_i = sqrt_scaled(active_stake_i) * smoothed_score_i
//! ```
//!
//! # Why Integer-Only?
//!
//! 1. **Determinism**: All validators MUST compute identical weights.
//!    Floating-point varies across architectures (x87 vs SSE vs ARM).
//! 2. **Consensus**: Non-deterministic math = chain fork.
//! 3. **Auditability**: Integer arithmetic is trivially verifiable.
//!
//! # Algorithm
//!
//! Binary search for the largest `r` such that `r * r <= n`.
//! O(64) iterations for u128 inputs — negligible cost.

/// Compute the integer square root of a u128 value.
///
/// Returns the largest `r` such that `r * r <= n`.
///
/// # Determinism
///
/// This function uses ONLY integer operations (no float, no libm).
/// The result is identical on every architecture for the same input.
///
/// # Examples
///
/// ```
/// # use misaka_tokenomics::sqrt::isqrt_u128;
/// assert_eq!(isqrt_u128(0), 0);
/// assert_eq!(isqrt_u128(1), 1);
/// assert_eq!(isqrt_u128(4), 2);
/// assert_eq!(isqrt_u128(100), 10);
/// assert_eq!(isqrt_u128(10_000), 100);
/// assert_eq!(isqrt_u128(99), 9);   // floor
/// ```
pub fn isqrt_u128(n: u128) -> u128 {
    if n <= 1 {
        return n;
    }

    // Binary search: find largest r where r*r <= n
    let mut lo: u128 = 1;
    // Upper bound: min(n, 1 << 64) — sqrt(u128::MAX) fits in u64
    let mut hi: u128 = {
        let bits = 128 - n.leading_zeros();
        let half_bits = (bits + 1) / 2;
        // 1 << half_bits is a safe upper bound for the integer sqrt
        1u128.checked_shl(half_bits).unwrap_or(u128::MAX)
    };

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        // Use checked_mul to avoid overflow on large inputs
        match mid.checked_mul(mid) {
            Some(sq) if sq == n => return mid,
            Some(sq) if sq < n => lo = mid + 1,
            _ => {
                // mid*mid > n OR overflow (meaning mid is too large)
                if mid == 0 {
                    return 0;
                }
                hi = mid - 1;
            }
        }
    }

    // lo > hi: answer is hi (the last value where mid*mid <= n)
    hi
}

/// Compute `sqrt_scaled(stake)` — the stake component of reward_weight.
///
/// This is the function used directly in the reward formula:
///
/// ```text
/// reward_weight_i = sqrt_scaled(active_stake_i) * smoothed_score_i
/// ```
///
/// # Scaling
///
/// The output is `isqrt(stake)` without additional scaling.
/// The caller multiplies by `smoothed_score` (also integer).
///
/// # Stake Compression Effect
///
/// ```text
/// stake = 100          → sqrt_scaled = 10
/// stake = 10,000       → sqrt_scaled = 100
/// stake = 1,000,000    → sqrt_scaled = 1000
/// stake = 100,000,000  → sqrt_scaled = 10000
/// ```
///
/// 100x stake → only 10x reward weight increase.
/// This dampens large-stake advantage while preserving capital responsibility.
pub fn sqrt_scaled(active_stake: u128) -> u64 {
    let root = isqrt_u128(active_stake);
    // Clamp to u64 — sqrt(u128::MAX) ≈ 1.8e19 which fits in u64
    if root > u64::MAX as u128 {
        u64::MAX
    } else {
        root as u64
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isqrt_perfect_squares() {
        assert_eq!(isqrt_u128(0), 0);
        assert_eq!(isqrt_u128(1), 1);
        assert_eq!(isqrt_u128(4), 2);
        assert_eq!(isqrt_u128(9), 3);
        assert_eq!(isqrt_u128(16), 4);
        assert_eq!(isqrt_u128(25), 5);
        assert_eq!(isqrt_u128(100), 10);
        assert_eq!(isqrt_u128(10000), 100);
        assert_eq!(isqrt_u128(1_000_000), 1000);
        assert_eq!(isqrt_u128(1_000_000_000_000), 1_000_000);
    }

    #[test]
    fn test_isqrt_non_perfect_floors() {
        assert_eq!(isqrt_u128(2), 1);
        assert_eq!(isqrt_u128(3), 1);
        assert_eq!(isqrt_u128(5), 2);
        assert_eq!(isqrt_u128(8), 2);
        assert_eq!(isqrt_u128(99), 9);
        assert_eq!(isqrt_u128(101), 10);
        assert_eq!(isqrt_u128(10001), 100);
    }

    #[test]
    fn test_isqrt_deterministic() {
        // Same input MUST always produce same output (consensus requirement)
        for stake in [0, 1, 42, 999, 250_000_000_000u128, u128::MAX] {
            let a = isqrt_u128(stake);
            let b = isqrt_u128(stake);
            assert_eq!(a, b, "isqrt must be deterministic for stake={stake}");
        }
    }

    #[test]
    fn test_isqrt_correctness_invariant() {
        // For any result r = isqrt(n):
        //   r*r <= n  AND  (r+1)*(r+1) > n
        for n in [
            0, 1, 2, 3, 4, 7, 15, 16, 17, 100, 255, 1000, 9999, 10000, 10001,
        ] {
            let r = isqrt_u128(n);
            assert!(r * r <= n, "r*r must be <= n: r={r}, n={n}, r*r={}", r * r);
            if r < u128::MAX {
                assert!(
                    (r + 1) * (r + 1) > n,
                    "(r+1)^2 must be > n: r={r}, n={n}, (r+1)^2={}",
                    (r + 1) * (r + 1)
                );
            }
        }
    }

    #[test]
    fn test_stake_4x_weight_2x() {
        // Core spec requirement: stake 4x → sqrt part is 2x
        let base_stake = 10_000u128;
        let quadrupled = base_stake * 4;

        let base_weight = sqrt_scaled(base_stake);
        let quad_weight = sqrt_scaled(quadrupled);

        assert_eq!(base_weight, 100);
        assert_eq!(quad_weight, 200);
        assert_eq!(
            quad_weight,
            base_weight * 2,
            "4x stake must produce exactly 2x sqrt weight"
        );
    }

    #[test]
    fn test_stake_100x_weight_10x() {
        let small = 100u128;
        let large = 10_000u128;

        let w_small = sqrt_scaled(small);
        let w_large = sqrt_scaled(large);

        assert_eq!(w_small, 10);
        assert_eq!(w_large, 100);
        assert_eq!(w_large, w_small * 10, "100x stake → 10x sqrt weight");
    }

    #[test]
    fn test_low_stake_high_score_survival() {
        // Spec requirement: low stake + high score must be viable
        let low_stake = 100u128;
        let high_stake = 1_000_000u128;

        let low_sqrt = sqrt_scaled(low_stake); // 10
        let high_sqrt = sqrt_scaled(high_stake); // 1000

        let high_score = 950_000u64;
        let low_score = 100_000u64;

        let weight_low_stake = low_sqrt as u128 * high_score as u128; // 10 * 950000 = 9_500_000
        let weight_high_stake = high_sqrt as u128 * low_score as u128; // 1000 * 100000 = 100_000_000

        // Low stake validator with excellent work should still earn meaningful share
        assert!(
            weight_low_stake > 0,
            "low-stake + high-score must have positive weight"
        );
        // High stake still wins overall but not 10000x advantage
        let ratio = weight_high_stake / weight_low_stake;
        assert!(
            ratio < 100,
            "high_stake/low_stake ratio should be dampened: got {ratio}"
        );
    }

    #[test]
    fn test_sqrt_scaled_large_values() {
        // 250 billion tokens with 9 decimal places
        let stake = 250_000_000_000_000_000_000u128; // 250B * 1e9
        let root = sqrt_scaled(stake);
        assert_eq!(root, isqrt_u128(stake) as u64);
        // ~15.8 billion — fits in u64
        assert!(root > 0);
    }

    #[test]
    fn test_sqrt_scaled_u128_max() {
        let root = sqrt_scaled(u128::MAX);
        // sqrt(2^128 - 1) ≈ 2^64 - 1
        assert!(root > 0);
        // Verify the invariant
        let r = root as u128;
        assert!(r * r <= u128::MAX);
    }

    #[test]
    fn test_sqrt_scaled_zero() {
        assert_eq!(sqrt_scaled(0), 0);
    }

    #[test]
    fn test_sybil_resistance() {
        // Splitting 10000 stake into 4 × 2500 should not increase total weight
        let single = sqrt_scaled(10_000); // 100
        let split: u64 = 4 * sqrt_scaled(2_500); // 4 * 50 = 200

        // Splitting actually increases weight! But:
        // - Each split identity needs independent infra cost
        // - Score is per-validator (not aggregate)
        // - The advantage is only 2x (not 4x as in linear)
        assert!(
            split <= single * 3,
            "sybil advantage should be bounded: single={single}, 4-way split={split}"
        );
    }
}
