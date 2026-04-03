//! Supply tracking with hard cap enforcement.

/// Maximum total supply (10 billion MISAKA with 9 decimal places).
pub const MAX_SUPPLY: u128 = 10_000_000_000 * 1_000_000_000;

pub struct SupplyTracker {
    pub total_supply: u128,
    pub circulating: u128,
    pub staked: u128,
    pub burned: u128,
}

impl SupplyTracker {
    pub fn new(genesis_supply: u128) -> Self {
        Self {
            total_supply: genesis_supply,
            circulating: genesis_supply,
            staked: 0,
            burned: 0,
        }
    }

    /// CRIT-3 FIX: Mint with hard cap enforcement.
    /// Returns the actually minted amount (may be less than requested if at cap).
    pub fn mint(&mut self, amount: u128) -> u128 {
        let remaining = MAX_SUPPLY.saturating_sub(self.total_supply);
        let actual = amount.min(remaining);
        if actual == 0 {
            return 0;
        }
        self.total_supply += actual;
        self.circulating += actual;
        actual
    }

    /// Check how much can still be minted before hitting MAX_SUPPLY.
    pub fn remaining_mintable(&self) -> u128 {
        MAX_SUPPLY.saturating_sub(self.total_supply)
    }

    /// Whether the supply cap has been reached.
    pub fn is_at_cap(&self) -> bool {
        self.total_supply >= MAX_SUPPLY
    }

    pub fn burn(&mut self, amount: u128) {
        self.burned += amount;
        self.circulating = self.circulating.saturating_sub(amount);
    }
    pub fn stake(&mut self, amount: u128) {
        self.staked += amount;
        self.circulating = self.circulating.saturating_sub(amount);
    }
    pub fn unstake(&mut self, amount: u128) {
        self.staked = self.staked.saturating_sub(amount);
        self.circulating += amount;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_invariant() {
        let mut s = SupplyTracker::new(10_000_000_000);
        s.mint(1000);
        s.stake(5000);
        assert_eq!(s.circulating + s.staked + s.burned, s.total_supply);
    }

    #[test]
    fn test_max_supply_enforced() {
        let mut s = SupplyTracker::new(MAX_SUPPLY - 100);
        // Try to mint 200 but only 100 remaining
        let minted = s.mint(200);
        assert_eq!(minted, 100);
        assert_eq!(s.total_supply, MAX_SUPPLY);
        // No more minting
        assert_eq!(s.mint(1), 0);
        assert!(s.is_at_cap());
    }

    #[test]
    fn test_remaining_mintable() {
        let s = SupplyTracker::new(MAX_SUPPLY / 2);
        assert_eq!(s.remaining_mintable(), MAX_SUPPLY / 2);
    }
}
