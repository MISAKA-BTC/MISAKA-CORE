//! Compact target encoding (nBits format).
//!
//! The compact format encodes a 256-bit number as:
//!   bits[31:24] = exponent (number of bytes)
//!   bits[23:0] = mantissa (top 3 bytes of target)
//!   Target = mantissa * 2^(8*(exponent-3))

use crate::uint::Uint256;

/// Convert compact bits to a full 256-bit target.
pub fn compact_to_target(bits: u32) -> Uint256 {
    let exponent = (bits >> 24) as u32;
    let mantissa = bits & 0x007FFFFF;
    let negative = (bits & 0x00800000) != 0;

    if mantissa == 0 || exponent == 0 {
        return Uint256::ZERO;
    }

    let mut target = Uint256::from_u64(mantissa as u64);

    if exponent <= 3 {
        target = target >> (8 * (3 - exponent));
    } else {
        target = target << (8 * (exponent - 3));
    }

    if negative {
        Uint256::ZERO
    } else {
        target
    }
}

/// Convert a 256-bit target to compact bits format.
pub fn target_to_compact(target: &Uint256) -> u32 {
    if target.is_zero() {
        return 0;
    }

    let bits = target.bits();
    let exponent = ((bits + 7) / 8) as u32;

    let mantissa = if exponent <= 3 {
        (target.clone() << (8 * (3 - exponent))).low_u64() as u32
    } else {
        (target.clone() >> (8 * (exponent - 3))).low_u64() as u32
    };

    let mantissa = mantissa & 0x007FFFFF;

    // If the high bit of mantissa is set, shift right and increase exponent
    if mantissa & 0x00800000 != 0 {
        let mantissa = mantissa >> 8;
        ((exponent + 1) << 24) | mantissa
    } else {
        (exponent << 24) | mantissa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let bits = 0x1d00ffff_u32; // Bitcoin genesis target
        let target = compact_to_target(bits);
        let recovered = target_to_compact(&target);
        assert_eq!(bits, recovered);
    }

    #[test]
    fn test_zero() {
        assert_eq!(compact_to_target(0), Uint256::ZERO);
        assert_eq!(target_to_compact(&Uint256::ZERO), 0);
    }
}
