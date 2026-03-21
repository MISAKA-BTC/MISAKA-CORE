//! MEV policy enforcement (Spec 17).

#[derive(Debug, Clone)]
pub struct MevScore {
    pub tx_hash: [u8; 32],
    pub sandwich_risk: f64,
    pub frontrun_risk: f64,
}

pub fn compute_mev_score(gas_price: u64, avg_gas_price: u64) -> f64 {
    if avg_gas_price == 0 {
        return 0.0;
    }
    let ratio = gas_price as f64 / avg_gas_price as f64;
    if ratio > 5.0 {
        1.0
    } else if ratio > 2.0 {
        (ratio - 2.0) / 3.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mev_score() {
        assert_eq!(compute_mev_score(100, 100), 0.0);
        assert!(compute_mev_score(1000, 100) > 0.9);
    }
}
