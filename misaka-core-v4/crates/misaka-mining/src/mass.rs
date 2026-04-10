//! Transaction mass calculation — weight-based fee system.
//!
//! Mass is MISAKA's equivalent of Bitcoin's vSize/weight. It accounts for:
//! - Serialized transaction size
//! - Signature operation cost
//! - UTXO creation/consumption costs
//! - Script complexity

/// Mass calculation parameters.
#[derive(Debug, Clone)]
pub struct MassParams {
    pub mass_per_tx_byte: u64,
    pub mass_per_script_pub_key_byte: u64,
    pub mass_per_sig_op: u64,
    pub mass_per_input: u64,
    pub mass_per_output: u64,
    pub base_mass: u64,
    pub mass_per_pq_sig_op: u64, // PQ sigs are larger
}

impl Default for MassParams {
    fn default() -> Self {
        Self {
            mass_per_tx_byte: 1,
            mass_per_script_pub_key_byte: 10,
            mass_per_sig_op: 1000,
            mass_per_input: 100,
            mass_per_output: 50,
            base_mass: 100,
            mass_per_pq_sig_op: 3000, // PQ sigs are ~3x heavier
        }
    }
}

/// Transaction data needed for mass calculation.
pub struct TxMassData {
    pub serialized_size: usize,
    pub input_count: usize,
    pub output_count: usize,
    pub sig_op_count: usize,
    pub pq_sig_op_count: usize,
    pub total_script_pub_key_bytes: usize,
}

/// Calculate transaction mass.
pub fn calculate_tx_mass(params: &MassParams, data: &TxMassData) -> u64 {
    let mut mass = params.base_mass;
    mass += data.serialized_size as u64 * params.mass_per_tx_byte;
    mass += data.input_count as u64 * params.mass_per_input;
    mass += data.output_count as u64 * params.mass_per_output;
    mass += data.sig_op_count as u64 * params.mass_per_sig_op;
    mass += data.pq_sig_op_count as u64 * params.mass_per_pq_sig_op;
    mass += data.total_script_pub_key_bytes as u64 * params.mass_per_script_pub_key_byte;
    mass
}

/// Estimate fee from mass and fee rate.
pub fn estimate_fee(mass: u64, fee_rate: f64) -> u64 {
    (mass as f64 * fee_rate).ceil() as u64
}

/// Calculate the minimum fee for a transaction to be accepted.
pub fn minimum_fee(mass: u64, minimum_relay_fee_rate: f64) -> u64 {
    estimate_fee(mass, minimum_relay_fee_rate).max(1)
}

/// Estimate mass for a standard P2PKH-PQ transaction.
pub fn estimate_standard_mass(input_count: usize, output_count: usize) -> u64 {
    let params = MassParams::default();
    let data = TxMassData {
        serialized_size: input_count * 200 + output_count * 50 + 10, // Rough estimate
        input_count,
        output_count,
        sig_op_count: 0,
        pq_sig_op_count: input_count,
        total_script_pub_key_bytes: output_count * 37,
    };
    calculate_tx_mass(&params, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mass_calculation() {
        let params = MassParams::default();
        let data = TxMassData {
            serialized_size: 300,
            input_count: 2,
            output_count: 2,
            sig_op_count: 0,
            pq_sig_op_count: 2,
            total_script_pub_key_bytes: 74,
        };
        let mass = calculate_tx_mass(&params, &data);
        assert!(mass > 0);
        assert!(mass > params.base_mass);
    }

    #[test]
    fn test_fee_estimate() {
        let mass = 1000;
        let fee = estimate_fee(mass, 1.0);
        assert_eq!(fee, 1000);
        let fee = estimate_fee(mass, 2.5);
        assert_eq!(fee, 2500);
    }
}
