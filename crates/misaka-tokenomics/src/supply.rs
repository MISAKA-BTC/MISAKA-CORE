//! Supply tracking with checked arithmetic and cap enforcement.
//!
//! Audit #16/#17: All mutators use checked arithmetic and return Result.
//! `mint` enforces `max_supply` cap. No unchecked `+=`/`-=`.

/// Supply tracking errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SupplyError {
    #[error("supply overflow")]
    Overflow,
    #[error("supply underflow (attempted to subtract {attempted} from {available})")]
    Underflow { available: u128, attempted: u128 },
    #[error("mint would exceed max supply: total {total} + mint {mint} > cap {cap}")]
    ExceedsCap { total: u128, mint: u128, cap: u128 },
}

pub struct SupplyTracker {
    pub total_supply: u128,
    pub circulating: u128,
    pub staked: u128,
    pub burned: u128,
    /// Maximum allowed total supply. Enforced on every mint.
    pub max_supply: u128,
}

impl SupplyTracker {
    pub fn new(genesis_supply: u128, max_supply: u128) -> Self {
        Self {
            total_supply: genesis_supply,
            circulating: genesis_supply,
            staked: 0,
            burned: 0,
            max_supply,
        }
    }

    /// Mint new tokens. Enforces max_supply cap.
    pub fn mint(&mut self, amount: u128) -> Result<(), SupplyError> {
        let new_total = self.total_supply.checked_add(amount)
            .ok_or(SupplyError::Overflow)?;
        if new_total > self.max_supply {
            return Err(SupplyError::ExceedsCap {
                total: self.total_supply,
                mint: amount,
                cap: self.max_supply,
            });
        }
        let new_circ = self.circulating.checked_add(amount)
            .ok_or(SupplyError::Overflow)?;
        self.total_supply = new_total;
        self.circulating = new_circ;
        Ok(())
    }

    /// Burn tokens (reduce circulating supply).
    pub fn burn(&mut self, amount: u128) -> Result<(), SupplyError> {
        if amount > self.circulating {
            return Err(SupplyError::Underflow {
                available: self.circulating,
                attempted: amount,
            });
        }
        self.burned = self.burned.checked_add(amount)
            .ok_or(SupplyError::Overflow)?;
        self.circulating -= amount;
        Ok(())
    }

    /// Stake tokens (move from circulating to staked).
    pub fn stake(&mut self, amount: u128) -> Result<(), SupplyError> {
        if amount > self.circulating {
            return Err(SupplyError::Underflow {
                available: self.circulating,
                attempted: amount,
            });
        }
        self.staked = self.staked.checked_add(amount)
            .ok_or(SupplyError::Overflow)?;
        self.circulating -= amount;
        Ok(())
    }

    /// Unstake tokens (move from staked to circulating).
    pub fn unstake(&mut self, amount: u128) -> Result<(), SupplyError> {
        if amount > self.staked {
            return Err(SupplyError::Underflow {
                available: self.staked,
                attempted: amount,
            });
        }
        let new_circ = self.circulating.checked_add(amount)
            .ok_or(SupplyError::Overflow)?;
        self.staked -= amount;
        self.circulating = new_circ;
        Ok(())
    }

    /// Check the invariant: circulating + staked + burned == total_supply
    pub fn check_invariant(&self) -> bool {
        let sum = self.circulating
            .checked_add(self.staked)
            .and_then(|s| s.checked_add(self.burned));
        sum == Some(self.total_supply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_invariant() {
        let mut s = SupplyTracker::new(10_000_000_000, u128::MAX);
        s.mint(1000).unwrap();
        s.stake(5000).unwrap();
        assert!(s.check_invariant());
    }

    #[test]
    fn test_mint_exceeds_cap() {
        let mut s = SupplyTracker::new(100, 200);
        assert!(s.mint(50).is_ok());
        assert!(s.mint(60).is_err()); // 150 + 60 = 210 > 200
    }

    #[test]
    fn test_burn_underflow() {
        let mut s = SupplyTracker::new(100, u128::MAX);
        assert!(s.burn(101).is_err());
        assert!(s.burn(50).is_ok());
        assert!(s.check_invariant());
    }

    #[test]
    fn test_stake_underflow() {
        let mut s = SupplyTracker::new(100, u128::MAX);
        assert!(s.stake(101).is_err());
        s.stake(50).unwrap();
        assert!(s.unstake(51).is_err());
        s.unstake(50).unwrap();
        assert!(s.check_invariant());
    }
}
