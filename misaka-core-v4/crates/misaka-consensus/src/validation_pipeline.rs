//! Validation pipeline metadata and shared stage helpers.
//!
//! This module makes the block/tx validation order explicit.
//! Privacy constraint validation has been removed (deprecated pool removed).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockValidationStage {
    Structural,
    SpendTagConflict,
    RingMemberResolution,
    SameAmountRing,
    RingFamilyProof,
    AmountConservation,
    StateApply,
}

impl BlockValidationStage {
    pub const fn label(self) -> &'static str {
        match self {
            BlockValidationStage::Structural => "structural",
            BlockValidationStage::SpendTagConflict => "spend_tag_conflict",
            BlockValidationStage::RingMemberResolution => "ring_member_resolution",
            BlockValidationStage::SameAmountRing => "same_amount_ring",
            BlockValidationStage::RingFamilyProof => "ring_family_proof",
            BlockValidationStage::AmountConservation => "amount_conservation",
            BlockValidationStage::StateApply => "state_apply",
        }
    }
}

const TRANSPARENT_PIPELINE: &[BlockValidationStage] = &[
    BlockValidationStage::Structural,
    BlockValidationStage::SpendTagConflict,
    BlockValidationStage::RingMemberResolution,
    BlockValidationStage::SameAmountRing,
    BlockValidationStage::RingFamilyProof,
    BlockValidationStage::AmountConservation,
    BlockValidationStage::StateApply,
];

pub const fn block_validation_pipeline() -> &'static [BlockValidationStage] {
    TRANSPARENT_PIPELINE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_starts_structural_ends_state_apply() {
        let stages = block_validation_pipeline();
        assert_eq!(stages.first(), Some(&BlockValidationStage::Structural));
        assert_eq!(stages.last(), Some(&BlockValidationStage::StateApply));
    }
}
