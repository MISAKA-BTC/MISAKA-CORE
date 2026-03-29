//! Integer overflow protection for financial calculations.
//!
//! All monetary calculations MUST use checked arithmetic to prevent:
//! - Supply inflation via overflow
//! - Negative balance exploitation
//! - Fee manipulation attacks

/// Safe addition that returns error on overflow.
pub fn safe_add(a: u64, b: u64) -> Result<u64, OverflowError> {
    a.checked_add(b).ok_or(OverflowError::Addition { a, b })
}

/// Safe subtraction that returns error on underflow.
pub fn safe_sub(a: u64, b: u64) -> Result<u64, OverflowError> {
    a.checked_sub(b).ok_or(OverflowError::Subtraction { a, b })
}

/// Safe multiplication.
pub fn safe_mul(a: u64, b: u64) -> Result<u64, OverflowError> {
    a.checked_mul(b).ok_or(OverflowError::Multiplication { a, b })
}

/// Safe division (returns error on divide-by-zero).
pub fn safe_div(a: u64, b: u64) -> Result<u64, OverflowError> {
    if b == 0 { return Err(OverflowError::DivisionByZero); }
    Ok(a / b)
}

/// Sum a slice of amounts with overflow checking.
pub fn safe_sum(amounts: &[u64]) -> Result<u64, OverflowError> {
    let mut total: u64 = 0;
    for &amount in amounts {
        total = safe_add(total, amount)?;
    }
    Ok(total)
}

/// Check that a value is within an expected range.
pub fn check_range(value: u64, min: u64, max: u64, name: &str) -> Result<(), OverflowError> {
    if value < min || value > max {
        Err(OverflowError::OutOfRange { value, min, max, name: name.to_string() })
    } else {
        Ok(())
    }
}

/// Maximum MISAKA supply (10 billion * 10^9 base units).
/// Per-transaction amount cap (u64 max). True supply (10B×1e9) tracked as u128.
pub const MAX_AMOUNT_PER_TX: u64 = u64::MAX / 2; // ~9.2e18 base units

/// Check that an amount doesn't exceed max supply.
pub fn check_amount(amount: u64) -> Result<u64, OverflowError> {
    if amount > MAX_AMOUNT_PER_TX {
        Err(OverflowError::ExceedsMaxAmount(amount))
    } else {
        Ok(amount)
    }
}

/// Safe fee calculation: fee_rate * mass, capped at reasonable maximum.
pub fn safe_fee_calc(mass: u64, fee_rate_per_unit: u64) -> Result<u64, OverflowError> {
    let fee = safe_mul(mass, fee_rate_per_unit)?;
    if fee > 1_000_000_000_000 { // 1000 MISAKA max fee
        Err(OverflowError::ExcessiveFee(fee))
    } else {
        Ok(fee)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OverflowError {
    #[error("addition overflow: {a} + {b}")]
    Addition { a: u64, b: u64 },
    #[error("subtraction underflow: {a} - {b}")]
    Subtraction { a: u64, b: u64 },
    #[error("multiplication overflow: {a} * {b}")]
    Multiplication { a: u64, b: u64 },
    #[error("division by zero")]
    DivisionByZero,
    #[error("{value} out of range [{min}, {max}] for {name}")]
    OutOfRange { value: u64, min: u64, max: u64, name: String },
    #[error("amount {0} exceeds max per-tx amount")]
    ExceedsMaxAmount(u64),
    #[error("excessive fee: {0}")]
    ExcessiveFee(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_add_overflow() {
        assert!(safe_add(u64::MAX, 1).is_err());
        assert_eq!(safe_add(100, 200).unwrap(), 300);
    }

    #[test]
    fn test_safe_sub_underflow() {
        assert!(safe_sub(100, 200).is_err());
        assert_eq!(safe_sub(200, 100).unwrap(), 100);
    }

    #[test]
    fn test_safe_sum() {
        assert_eq!(safe_sum(&[100, 200, 300]).unwrap(), 600);
        assert!(safe_sum(&[u64::MAX, 1]).is_err());
    }

    #[test]
    fn test_max_supply_check() {
        assert!(check_amount(MAX_AMOUNT_PER_TX).is_ok());
        assert!(check_amount(MAX_AMOUNT_PER_TX + 1).is_err());
    }
}
