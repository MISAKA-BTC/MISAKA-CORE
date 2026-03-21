//! Fee distribution.
pub const VALIDATOR_SHARE_BPS: u64 = 1500; // 1.5%
pub const ADMIN_SHARE_BPS: u64 = 1000; // 1.0%
pub const ARCHIVE_SHARE_BPS: u64 = 500; // 0.5%

pub struct FeeShares {
    pub validator: u64,
    pub admin: u64,
    pub archive: u64,
}

pub fn compute_fee_shares(total_fee: u64) -> FeeShares {
    FeeShares {
        validator: total_fee * VALIDATOR_SHARE_BPS / 10000,
        admin: total_fee * ADMIN_SHARE_BPS / 10000,
        archive: total_fee * ARCHIVE_SHARE_BPS / 10000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fee_shares() {
        let s = compute_fee_shares(10000);
        assert_eq!(s.validator, 1500);
        assert_eq!(s.admin, 1000);
        assert_eq!(s.archive, 500);
    }
}
