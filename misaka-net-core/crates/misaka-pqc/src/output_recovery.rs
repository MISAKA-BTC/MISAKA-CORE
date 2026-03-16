//! Wallet Output Recovery (§10 scan efficiency).
//!
//! High-level interface for wallets to scan transaction outputs.

use crate::error::CryptoError;
use crate::pq_kem::MlKemSecretKey;
use crate::pq_stealth::{RecoveredOutput, StealthScanner};
use misaka_types::stealth::PqStealthData;

/// Wallet output recovery engine with statistics.
pub struct OutputRecovery {
    scanner: StealthScanner,
    pub outputs_scanned: u64,
    pub outputs_recovered: u64,
    pub recovered_balance: u128,
}

impl OutputRecovery {
    /// Create with the wallet's view secret key.
    pub fn new(view_sk: MlKemSecretKey) -> Self {
        Self {
            scanner: StealthScanner::new(view_sk),
            outputs_scanned: 0,
            outputs_recovered: 0,
            recovered_balance: 0,
        }
    }

    /// Scan a single output.
    pub fn scan_one(
        &mut self,
        data: &PqStealthData,
        tx_unique_id: &[u8; 32],
        output_index: u32,
    ) -> Result<Option<RecoveredOutput>, CryptoError> {
        self.outputs_scanned += 1;
        match self.scanner.try_recover(data, tx_unique_id, output_index)? {
            Some(r) => {
                self.outputs_recovered += 1;
                self.recovered_balance += r.amount as u128;
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    /// Scan a batch of outputs from a block.
    ///
    /// Each tuple: (stealth_data, tx_unique_id, output_index)
    pub fn scan_block(
        &mut self,
        outputs: &[(PqStealthData, [u8; 32], u32)],
    ) -> Vec<RecoveredOutput> {
        let mut results = Vec::new();
        for (data, tx_id, idx) in outputs {
            if let Ok(Some(r)) = self.scan_one(data, tx_id, *idx) {
                results.push(r);
            }
        }
        results
    }

    /// Get scanning statistics.
    pub fn stats(&self) -> RecoveryStats {
        RecoveryStats {
            outputs_scanned: self.outputs_scanned,
            outputs_recovered: self.outputs_recovered,
            recovered_balance: self.recovered_balance,
            hit_rate: if self.outputs_scanned > 0 {
                self.outputs_recovered as f64 / self.outputs_scanned as f64
            } else { 0.0 },
        }
    }

    pub fn reset_stats(&mut self) {
        self.outputs_scanned = 0;
        self.outputs_recovered = 0;
        self.recovered_balance = 0;
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryStats {
    pub outputs_scanned: u64,
    pub outputs_recovered: u64,
    pub recovered_balance: u128,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_kem::ml_kem_keygen;
    use crate::pq_stealth::create_stealth_output;

    #[test]
    fn test_recovery_block_scan() {
        let recipient = ml_kem_keygen().unwrap();
        let other = ml_kem_keygen().unwrap();
        let tx_id = [0x33; 32];

        let mut outputs = Vec::new();
        for i in 0..3u32 {
            let o = create_stealth_output(&recipient.public_key, (i + 1) as u64 * 100, b"", &tx_id, i).unwrap();
            outputs.push((o.stealth_data, tx_id, i));
        }
        let o = create_stealth_output(&other.public_key, 999, b"", &tx_id, 3).unwrap();
        outputs.push((o.stealth_data, tx_id, 3));

        let mut recovery = OutputRecovery::new(recipient.secret_key);
        let found = recovery.scan_block(&outputs);

        assert_eq!(found.len(), 3);
        let stats = recovery.stats();
        assert_eq!(stats.outputs_scanned, 4);
        assert_eq!(stats.outputs_recovered, 3);
        assert_eq!(stats.recovered_balance, 600);
    }
}
