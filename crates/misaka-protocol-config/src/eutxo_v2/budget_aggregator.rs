//! Per-block ExUnits aggregation.
//! Used by both block proposer (misaka-mining) and block validator (misaka-node).

use super::budget::budget_v1;
use misaka_types::eutxo::cost_model::ExUnits;

#[derive(Debug, Clone)]
pub struct BlockBudget {
    pub spent: ExUnits,
    pub limit: ExUnits,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockBudgetError {
    #[error("block ExUnits exceeded: spent={spent:?}, limit={limit:?}")]
    Exceeded { spent: ExUnits, limit: ExUnits },
}

impl BlockBudget {
    pub fn new() -> Self {
        Self {
            spent: ExUnits::ZERO,
            limit: budget_v1().max_block_ex_units,
        }
    }

    pub fn add_tx(&mut self, tx_ex: ExUnits) -> Result<(), BlockBudgetError> {
        let new_spent = self.spent.saturating_add(&tx_ex);
        if !new_spent.fits_within(&self.limit) {
            return Err(BlockBudgetError::Exceeded {
                spent: new_spent,
                limit: self.limit,
            });
        }
        self.spent = new_spent;
        Ok(())
    }

    pub fn has_room_for(&self, tx_ex: ExUnits) -> bool {
        self.spent.saturating_add(&tx_ex).fits_within(&self.limit)
    }
}

impl Default for BlockBudget {
    fn default() -> Self {
        Self::new()
    }
}
