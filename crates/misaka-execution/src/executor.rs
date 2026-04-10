// SPDX-License-Identifier: Apache-2.0
//! DET_EXEC_V2: Deterministic execution stub.
//!
//! # SEC-FIX: This module is a STUB that performs NO state mutations.
//! Gated behind `#[cfg(any(test, feature = "vm-stub"))]` to prevent
//! accidental use in production. If this module is accidentally wired
//! into the execution pipeline, transactions would "succeed" without
//! any state changes — a silent failure mode.
//!
//! Actual UTXO execution is handled by:
//! - `utxo_executor::UtxoExecutor` (Narwhal/DAG production path)
//! - `block_apply::execute_block` → `block_validation::validate_and_apply_block` (legacy)
#![cfg(any(test, feature = "vm-stub"))]

use misaka_types::gas::GasMeter;
use misaka_types::transaction::{Action, Transaction, TxClass};
use misaka_types::Digest;

/// Epoch at which smart contracts activate (TBD before mainnet).
pub const SMART_CONTRACT_ACTIVATION_EPOCH: u64 = u64::MAX; // disabled until hardfork

/// Execution result from processing one transaction.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub tx_hash: Digest,
    pub gas_used: u64,
    pub success: bool,
    pub state_mutations: Vec<(Vec<u8>, Vec<u8>)>,
    /// Events emitted by smart contracts.
    pub events: Vec<(String, Vec<u8>)>,
    /// Error message if failed.
    pub error: Option<String>,
}

impl ExecutionResult {
    pub fn rejected(tx_hash: Digest, reason: &str) -> Self {
        Self {
            tx_hash,
            gas_used: 0,
            success: false,
            state_mutations: vec![],
            events: vec![],
            error: Some(reason.to_string()),
        }
    }
}

/// Deterministic transaction executor.
pub struct DeterministicExecutor {
    pub gas_price: u64,
    /// Whether smart contracts are active.
    smart_contracts_active: bool,
}

impl DeterministicExecutor {
    /// UTXO-only mode (default, mainnet Phase 1).
    pub fn new(gas_price: u64) -> Self {
        Self {
            gas_price,
            smart_contracts_active: false,
        }
    }

    /// Enable smart contract mode (after hardfork epoch).
    pub fn enable_smart_contracts(&mut self) {
        self.smart_contracts_active = true;
        tracing::info!("Smart contracts ENABLED");
    }

    /// Execute a transaction.
    ///
    /// If current_epoch < SMART_CONTRACT_ACTIVATION_EPOCH, non-native
    /// actions are rejected.
    pub fn execute_tx(&self, tx_hash: Digest, gas_budget: u64) -> ExecutionResult {
        let mut meter = GasMeter::new(gas_budget, self.gas_price);
        let _ = meter.charge(1000); // base cost

        ExecutionResult {
            tx_hash,
            gas_used: meter.gas_charged(),
            success: !meter.exhausted,
            state_mutations: Vec::new(),
            events: Vec::new(),
            error: None,
        }
    }

    /// Execute with epoch awareness — reject smart contract TXs before activation.
    pub fn execute_tx_with_epoch(
        &self,
        tx_hash: Digest,
        gas_budget: u64,
        actions: &[Action],
        current_epoch: u64,
    ) -> ExecutionResult {
        // Check if any action targets a smart contract
        let has_contract_call = actions.iter().any(|a| a.module != "native");

        if has_contract_call {
            if current_epoch < SMART_CONTRACT_ACTIVATION_EPOCH {
                return ExecutionResult::rejected(
                    tx_hash,
                    "smart contracts not active until hardfork epoch",
                );
            }
            if !self.smart_contracts_active {
                return ExecutionResult::rejected(
                    tx_hash,
                    "smart contracts feature not enabled on this node",
                );
            }
        }

        // Native execution (UTXO transfers)
        self.execute_tx(tx_hash, gas_budget)
    }

    /// Classify for parallel execution.
    pub fn classify_tx(tx: &Transaction) -> TxClass {
        tx.tx_class()
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

    #[test]
    fn test_smart_contract_rejected_before_activation() {
        let exec = DeterministicExecutor::new(1);
        let contract_action = Action {
            module: "a1b2c3d4".to_string(), // contract hash
            function: "transfer".to_string(),
            args: vec![],
        };
        let result = exec.execute_tx_with_epoch([0xBB; 32], 5000, &[contract_action], 0);
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .map_or(false, |e| e.contains("not active")));
    }

    #[test]
    fn test_native_action_always_works() {
        let exec = DeterministicExecutor::new(1);
        let native_action = Action {
            module: "native".to_string(),
            function: "transfer".to_string(),
            args: vec![],
        };
        let result = exec.execute_tx_with_epoch([0xCC; 32], 5000, &[native_action], 0);
        assert!(result.success);
    }
}
