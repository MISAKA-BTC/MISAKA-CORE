//! Difficulty calculation and target conversion.

use crate::uint::Uint256;

/// The maximum target (minimum difficulty).
pub fn max_target() -> Uint256 {
    // 2^255 - 1 (simplified max target)
    Uint256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1])
}

/// Calculate the work value from a target.
/// work = 2^256 / (target + 1)
pub fn calc_work(target: &Uint256) -> Uint256 {
    if target.is_zero() {
        return Uint256::MAX;
    }
    let (denom, overflow) = target.overflowing_add(Uint256::ONE);
    if overflow {
        return Uint256::ONE;
    }
    // Simplified: MAX / denom
    let max = Uint256::MAX;
    // Use rough estimation: work ≈ MAX / (target + 1)
    // For exact division we'd need full 256/256 division
    let bits = denom.bits();
    if bits <= 64 {
        let (q, _) = max.div_rem_u64(denom.low_u64());
        q
    } else {
        // Approximate: shift both down
        let shift = bits - 64;
        let approx_denom = (denom >> shift).low_u64().max(1);
        let approx_num = max >> shift;
        let (q, _) = approx_num.div_rem_u64(approx_denom);
        q
    }
}

/// Convert difficulty float to a target Uint256.
pub fn difficulty_to_target(difficulty: f64) -> Uint256 {
    if difficulty <= 0.0 {
        return max_target();
    }
    let max = max_target();
    // target = max_target / difficulty
    let diff_u64 = difficulty.max(1.0) as u64;
    let (result, _) = max.div_rem_u64(diff_u64.max(1));
    result
}

/// Convert a target Uint256 to a difficulty float.
pub fn target_to_difficulty(target: &Uint256) -> f64 {
    if target.is_zero() {
        return f64::MAX;
    }
    let max = max_target();
    // difficulty = max_target / target
    // Approximate using high bits
    let target_bits = target.bits();
    let max_bits = max.bits();
    if target_bits <= 64 {
        let t = target.low_u64() as f64;
        let m = (max >> (max_bits.saturating_sub(64))).low_u64() as f64;
        let shift_factor = 2f64.powi((max_bits.saturating_sub(64)) as i32);
        (m * shift_factor) / t
    } else {
        let shift = target_bits.saturating_sub(64);
        let t = (target.clone() >> shift).low_u64() as f64;
        let m = (max >> shift).low_u64() as f64;
        m / t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_work_inverse() {
        let target = Uint256::from_u64(0xFFFF);
        let work = calc_work(&target);
        assert!(work > Uint256::ZERO);
    }

    #[test]
    fn test_difficulty_round_trip() {
        let diff = 1000.0;
        let target = difficulty_to_target(diff);
        let recovered = target_to_difficulty(&target);
        // Allow 10% error due to approximation
        assert!((recovered - diff).abs() / diff < 0.1);
    }
}
