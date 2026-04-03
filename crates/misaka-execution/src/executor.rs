//! DET_EXEC_V1: Deterministic execution (Spec 03 §10).
use misaka_types::gas::GasMeter;
use misaka_types::Digest;

pub struct ExecutionResult {
    pub tx_hash: Digest,
    pub gas_used: u64,
    pub success: bool,
    pub state_mutations: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct DeterministicExecutor {
    pub gas_price: u64,
}

impl DeterministicExecutor {
    pub fn new(gas_price: u64) -> Self {
        Self { gas_price }
    }

    pub fn execute_tx(&self, tx_hash: Digest, gas_budget: u64) -> ExecutionResult {
        let mut meter = GasMeter::new(gas_budget, self.gas_price);
        let _ = meter.charge(1000); // base cost
        ExecutionResult {
            tx_hash,
            gas_used: meter.gas_charged(),
            success: !meter.exhausted,
            state_mutations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_basic() {
        let exec = DeterministicExecutor::new(1);
        let result = exec.execute_tx([0xAA; 32], 5000);
        assert!(result.success);
        assert_eq!(result.gas_used, 1000);
    }
}
