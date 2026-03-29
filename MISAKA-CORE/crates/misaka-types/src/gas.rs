//! Gas metering per Spec 04.

use crate::error::MisakaError;

pub struct GasMeter {
    pub budget: u64,
    pub price: u64,
    pub consumed: u64,
    pub exhausted: bool,
}

impl GasMeter {
    pub fn new(budget: u64, price: u64) -> Self {
        Self {
            budget,
            price,
            consumed: 0,
            exhausted: false,
        }
    }

    pub fn charge(&mut self, amount: u64) -> Result<(), MisakaError> {
        let new = self.consumed.saturating_add(amount);
        if new > self.budget {
            self.exhausted = true;
            self.consumed = self.budget;
            return Err(MisakaError::GasBudgetExceeded {
                charged: new,
                limit: self.budget,
            });
        }
        self.consumed = new;
        Ok(())
    }

    pub fn gas_charged(&self) -> u64 {
        self.consumed
    }

    pub fn fee_charged(&self) -> Result<u64, MisakaError> {
        self.consumed
            .checked_mul(self.price)
            .ok_or(MisakaError::ArithmeticOverflow)
    }

    pub fn fee_refund(&self) -> Result<u64, MisakaError> {
        let remaining = self.budget.saturating_sub(self.consumed);
        remaining
            .checked_mul(self.price)
            .ok_or(MisakaError::ArithmeticOverflow)
    }

    pub fn fee_max(&self) -> Result<u64, MisakaError> {
        self.budget
            .checked_mul(self.price)
            .ok_or(MisakaError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_meter() {
        let mut m = GasMeter::new(1000, 1);
        m.charge(500).unwrap();
        assert_eq!(m.fee_charged().unwrap(), 500);
        assert_eq!(m.fee_refund().unwrap(), 500);
    }

    #[test]
    fn test_exhaustion() {
        let mut m = GasMeter::new(100, 1);
        assert!(m.charge(200).is_err());
        assert!(m.exhausted);
    }
}
