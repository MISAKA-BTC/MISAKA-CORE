//! Supply tracking.
pub struct SupplyTracker {
    pub total_supply: u128,
    pub circulating: u128,
    pub staked: u128,
    pub burned: u128,
}

impl SupplyTracker {
    pub fn new(genesis_supply: u128) -> Self {
        Self { total_supply: genesis_supply, circulating: genesis_supply, staked: 0, burned: 0 }
    }
    pub fn mint(&mut self, amount: u128) { self.total_supply += amount; self.circulating += amount; }
    pub fn burn(&mut self, amount: u128) { self.burned += amount; self.circulating -= amount; }
    pub fn stake(&mut self, amount: u128) { self.staked += amount; self.circulating -= amount; }
    pub fn unstake(&mut self, amount: u128) { self.staked -= amount; self.circulating += amount; }
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
}
