//! Inflation model — integer-only (no floating point).
//!
//! All calculations use basis points (BPS) and u128 arithmetic
//! to ensure deterministic, cross-platform consensus.
//!
//! # Schedule
//!
//! - Year 0: 5.00% annual inflation (500 BPS)
//! - Decay: 0.50% per year (50 BPS)
//! - Floor: 1.00% (100 BPS) — reached at year 8

/// Initial annual inflation rate in basis points (5.00%).
pub const INITIAL_ANNUAL_RATE_BPS: u64 = 500;

/// Annual decay of inflation rate in basis points (0.50%).
pub const ANNUAL_DECAY_BPS: u64 = 50;

/// Minimum annual inflation rate in basis points (1.00%).
pub const FLOOR_RATE_BPS: u64 = 100;

/// Basis points denominator.
pub const BPS_DENOMINATOR: u128 = 10_000;

/// Compute the annual inflation rate for a given year (in BPS).
pub fn annual_inflation_rate_bps(year: u64) -> u64 {
    let decay = ANNUAL_DECAY_BPS.saturating_mul(year);
    if decay >= INITIAL_ANNUAL_RATE_BPS - FLOOR_RATE_BPS {
        FLOOR_RATE_BPS
    } else {
        INITIAL_ANNUAL_RATE_BPS - decay
    }
}

/// Compute the per-epoch emission amount (in base units, integer-only).
pub fn epoch_emission(total_supply: u128, year: u64, epochs_per_year: u64) -> u128 {
    if epochs_per_year == 0 {
        return 0;
    }
    let rate_bps = annual_inflation_rate_bps(year) as u128;
    total_supply
        .saturating_mul(rate_bps)
        / BPS_DENOMINATOR
        / epochs_per_year as u128
}

/// Annual emission for a given year (in base units).
pub fn annual_emission(total_supply: u128, year: u64) -> u128 {
    let rate_bps = annual_inflation_rate_bps(year) as u128;
    total_supply.saturating_mul(rate_bps) / BPS_DENOMINATOR
}

/// Display-only: annual inflation rate as percentage. NOT used in consensus.
pub fn annual_inflation_rate_percent(year: u64) -> f64 {
    annual_inflation_rate_bps(year) as f64 / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inflation_decay_bps() {
        assert_eq!(annual_inflation_rate_bps(0), 500);
        assert_eq!(annual_inflation_rate_bps(1), 450);
        assert_eq!(annual_inflation_rate_bps(8), 100); // floor
        assert_eq!(annual_inflation_rate_bps(100), 100);
    }

    #[test]
    fn test_epoch_emission_basic() {
        let supply: u128 = 10_000_000_000;
        let epochs: u64 = 525_600;
        let e = epoch_emission(supply, 0, epochs);
        assert_eq!(e, 951); // 500M / 525600
    }

    #[test]
    fn test_annual_emission() {
        let supply: u128 = 10_000_000_000;
        assert_eq!(annual_emission(supply, 0), 500_000_000);
        assert_eq!(annual_emission(supply, 8), 100_000_000);
    }

    #[test]
    fn test_zero_epochs() {
        assert_eq!(epoch_emission(1_000_000, 0, 0), 0);
    }
}
