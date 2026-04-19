//! CostModel V1 builder.
//! Produces the canonical V1 CostModel for v2.0 launch.

use super::budget::budget_v1;
use super::opcodes::cost_model_v1_table;
use misaka_types::eutxo::cost_model::CostModel;

/// Cost model identifier for v2.0 launch.
pub const COST_MODEL_V1_ID: u32 = 1;

/// Build the canonical V1 CostModel.
pub fn cost_model_v1() -> CostModel {
    CostModel {
        model_id: COST_MODEL_V1_ID,
        vm_version: 1, // ScriptVmVersion::V1
        opcode_costs: cost_model_v1_table(),
        params: budget_v1(),
    }
}

/// Stable SHA3-256 hash of the V1 cost model (for protocol param hash).
pub fn cost_model_v1_hash() -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let model = cost_model_v1();
    let bytes = borsh::to_vec(&model).expect("CostModel borsh serialize");
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:eutxo:cost_model:v1:");
    h.update(&bytes);
    h.finalize().into()
}
