//! Inflation model — integer-only (no floating point).
//!
//! All calculations use basis points (BPS) and u128 arithmetic
//! to ensure deterministic, cross-platform consensus.
//!
//! # Schedule
//!
//! - Year 0 (genesis → 1 year): 0% — NO inflation emission
//! - Year 1: 3.00% annual inflation (300 BPS) — emission begins
//! - Decay: 0.50% per year (50 BPS)
//! - Floor: 1.00% (100 BPS) — reached at year 5
//!
//! # Distribution
//!
//! All emitted MISAKA is distributed to 21 SR validator nodes
//! in proportion to their staked amount.

/// Annual inflation rate at emission start (3.00%).
pub const INITIAL_ANNUAL_RATE_BPS: u64 = 300;

/// Annual decay of inflation rate in basis points (0.50%).
pub const ANNUAL_DECAY_BPS: u64 = 50;

/// Minimum annual inflation rate in basis points (1.00%).
pub const FLOOR_RATE_BPS: u64 = 100;

/// Basis points denominator.
pub const BPS_DENOMINATOR: u128 = 10_000;

/// Number of years with zero emission after genesis.
/// Genesis → 1 year: no inflation. Emission starts at year 1.
pub const EMISSION_DELAY_YEARS: u64 = 1;

/// Compute the annual inflation rate for a given year (in BPS).
///
/// Year 0: 0% (no emission during first year after genesis)
/// Year 1: 3.00% (INITIAL_ANNUAL_RATE_BPS)
/// Year 2: 2.50%
/// Year 3: 2.00%
/// Year 4: 1.50%
/// Year 5+: 1.00% (floor)
pub fn annual_inflation_rate_bps(year: u64) -> u64 {
    // No emission during delay period
    if year < EMISSION_DELAY_YEARS {
        return 0;
    }
    // Years since emission started
    let emission_year = year - EMISSION_DELAY_YEARS;
    let decay = ANNUAL_DECAY_BPS.saturating_mul(emission_year);
    if decay >= INITIAL_ANNUAL_RATE_BPS - FLOOR_RATE_BPS {
        FLOOR_RATE_BPS
    } else {
        INITIAL_ANNUAL_RATE_BPS - decay
    }
}

/// Compute the per-epoch emission amount (in base units, integer-only).
///
/// CRIT-3 FIX: Emission is capped so total_supply never exceeds MAX_SUPPLY.
pub fn epoch_emission(total_supply: u128, year: u64, epochs_per_year: u64) -> u128 {
    if epochs_per_year == 0 {
        return 0;
    }
    let max_supply = crate::supply::MAX_SUPPLY;
    if total_supply >= max_supply {
        return 0; // Cap reached — no more emission
    }
    let rate_bps = annual_inflation_rate_bps(year) as u128;
    let emission = total_supply.saturating_mul(rate_bps) / BPS_DENOMINATOR / epochs_per_year as u128;
    // Cap emission to remaining supply
    let remaining = max_supply - total_supply;
    emission.min(remaining)
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
    fn test_inflation_schedule() {
        // Year 0: no emission (delay period)
        assert_eq!(annual_inflation_rate_bps(0), 0);
        // Year 1: 3.00% (emission starts)
        assert_eq!(annual_inflation_rate_bps(1), 300);
        // Year 2: 2.50%
        assert_eq!(annual_inflation_rate_bps(2), 250);
        // Year 3: 2.00%
        assert_eq!(annual_inflation_rate_bps(3), 200);
        // Year 4: 1.50%
        assert_eq!(annual_inflation_rate_bps(4), 150);
        // Year 5+: 1.00% floor
        assert_eq!(annual_inflation_rate_bps(5), 100);
        assert_eq!(annual_inflation_rate_bps(10), 100);
        assert_eq!(annual_inflation_rate_bps(100), 100);
    }

    #[test]
    fn test_epoch_emission_year0_is_zero() {
        let supply: u128 = 10_000_000_000;
        let epochs: u64 = 525_600;
        // Year 0: NO emission
        assert_eq!(epoch_emission(supply, 0, epochs), 0);
    }

    #[test]
    fn test_epoch_emission_year1_starts() {
        let supply: u128 = 10_000_000_000;
        let epochs: u64 = 525_600;
        // Year 1: 3% of 10B = 300M / 525600 = 570 per epoch
        let e = epoch_emission(supply, 1, epochs);
        assert_eq!(e, 570);
    }

    #[test]
    fn test_annual_emission() {
        let supply: u128 = 10_000_000_000;
        assert_eq!(annual_emission(supply, 0), 0);           // year 0: no emission
        assert_eq!(annual_emission(supply, 1), 300_000_000);  // year 1: 3%
        assert_eq!(annual_emission(supply, 5), 100_000_000);  // year 5+: 1% floor
    }

    #[test]
    fn test_zero_epochs() {
        assert_eq!(epoch_emission(1_000_000, 0, 0), 0);
    }
}
