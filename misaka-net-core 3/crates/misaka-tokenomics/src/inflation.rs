//! Inflation model.
pub const INITIAL_ANNUAL_RATE_BPS: u64 = 500; // 5%
pub const ANNUAL_DECAY_BPS: u64 = 50; // 0.5% per year

pub fn annual_inflation_rate(year: u64) -> f64 {
    let rate = INITIAL_ANNUAL_RATE_BPS as f64 - (ANNUAL_DECAY_BPS as f64 * year as f64);
    (rate.max(100.0)) / 10000.0 // floor at 1%
}

pub fn epoch_emission(total_supply: u128, year: u64, epochs_per_year: u64) -> u128 {
    let rate = annual_inflation_rate(year);
    ((total_supply as f64 * rate) / epochs_per_year as f64) as u128
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_inflation_decay() {
        assert!((annual_inflation_rate(0) - 0.05).abs() < 1e-9);
        assert!((annual_inflation_rate(1) - 0.045).abs() < 1e-9);
        assert!((annual_inflation_rate(10) - 0.01).abs() < 1e-9); // floor
    }
}
