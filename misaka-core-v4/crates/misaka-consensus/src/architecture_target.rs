//! Consensus architecture target summary.
//!
//! SEC-FIX: Comment was backwards. The current production runtime is
//! **Narwhal + Bullshark** (default `dag` feature). GhostDAG is the legacy
//! compatibility path behind `ghostdag-compat` feature flag.
//!
//! Privacy (ZKP/shielded) has been removed in Phase 2c-B — all transfers
//! are transparent (ML-DSA-65 direct signatures).

use misaka_types::constants::{MAX_ACTIVE_VALIDATORS, NUM_SUPER_REPRESENTATIVES};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DisseminationArchitecture {
    GhostdagNativeMempool,
    Narwhal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DisseminationStage {
    NativeMempool,
    NarwhalBatchDissemination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderingArchitecture {
    Ghostdag,
    Bullshark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderingStage {
    GhostdagTotalOrder,
    BullsharkCommitOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderingInputSource {
    GhostdagSelectedParent,
    NarwhalDeliveredBatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FinalityArchitecture {
    CheckpointBft,
    BullsharkCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckpointDecisionSource {
    GhostdagCheckpointBft,
    BullsharkCommit,
}

impl CheckpointDecisionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GhostdagCheckpointBft => "ghostdagCheckpointBft",
            Self::BullsharkCommit => "bullsharkCommit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyCompletionScope {
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CommitteeArchitecture {
    ValidatorBreadth,
    SuperRepresentative21,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CommitteeStage {
    ValidatorBreadthProof,
    Sr21EpochRotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CommitteeSelection {
    ValidatorBreadthRehearsal,
    StakeWeightedTop21Election,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentConsensusArchitecture {
    pub dissemination: DisseminationArchitecture,
    pub dissemination_stage: DisseminationStage,
    pub ordering: OrderingArchitecture,
    pub ordering_stage: OrderingStage,
    pub ordering_input: OrderingInputSource,
    pub finality: FinalityArchitecture,
    pub checkpoint_decision_source: CheckpointDecisionSource,
    pub committee: CommitteeArchitecture,
    pub committee_stage: CommitteeStage,
    pub committee_selection: CommitteeSelection,
    pub committee_size_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionTargetArchitecture {
    pub dissemination: DisseminationArchitecture,
    pub dissemination_stage: DisseminationStage,
    pub ordering: OrderingArchitecture,
    pub ordering_stage: OrderingStage,
    pub ordering_input: OrderingInputSource,
    pub finality: FinalityArchitecture,
    pub checkpoint_decision_source: CheckpointDecisionSource,
    pub committee: CommitteeArchitecture,
    pub committee_stage: CommitteeStage,
    pub committee_selection: CommitteeSelection,
    pub committee_size_cap: u32,
    pub privacy_scope: PrivacyCompletionScope,
    pub cex_friendly_priority: bool,
    pub public_operator_recovery_priority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusArchitectureSummary {
    pub current_runtime: CurrentConsensusArchitecture,
    pub completion_target: CompletionTargetArchitecture,
}

pub fn current_consensus_architecture() -> CurrentConsensusArchitecture {
    CurrentConsensusArchitecture {
        dissemination: DisseminationArchitecture::GhostdagNativeMempool,
        dissemination_stage: current_dissemination_stage(),
        ordering: OrderingArchitecture::Ghostdag,
        ordering_stage: current_ordering_stage(),
        ordering_input: current_ordering_input(),
        finality: FinalityArchitecture::CheckpointBft,
        checkpoint_decision_source: current_checkpoint_decision_source(),
        committee: current_committee_architecture(),
        committee_stage: current_committee_stage(),
        committee_selection: current_committee_selection(),
        committee_size_cap: current_committee_size_cap(),
    }
}

pub fn completion_target_architecture() -> CompletionTargetArchitecture {
    CompletionTargetArchitecture {
        dissemination: DisseminationArchitecture::Narwhal,
        dissemination_stage: completion_target_dissemination_stage(),
        ordering: OrderingArchitecture::Bullshark,
        ordering_stage: completion_target_ordering_stage(),
        ordering_input: completion_target_ordering_input(),
        finality: FinalityArchitecture::BullsharkCommit,
        checkpoint_decision_source: completion_target_checkpoint_decision_source(),
        committee: completion_target_committee_architecture(),
        committee_stage: completion_target_committee_stage(),
        committee_selection: completion_target_committee_selection(),
        committee_size_cap: completion_target_committee_size_cap(),
        privacy_scope: PrivacyCompletionScope::Deferred,
        cex_friendly_priority: true,
        public_operator_recovery_priority: true,
    }
}

pub const fn current_checkpoint_decision_source() -> CheckpointDecisionSource {
    CheckpointDecisionSource::GhostdagCheckpointBft
}

pub const fn completion_target_checkpoint_decision_source() -> CheckpointDecisionSource {
    CheckpointDecisionSource::BullsharkCommit
}

pub const fn current_ordering_stage() -> OrderingStage {
    OrderingStage::GhostdagTotalOrder
}

pub const fn completion_target_ordering_stage() -> OrderingStage {
    OrderingStage::BullsharkCommitOrder
}

pub const fn current_ordering_input() -> OrderingInputSource {
    OrderingInputSource::GhostdagSelectedParent
}

pub const fn completion_target_ordering_input() -> OrderingInputSource {
    OrderingInputSource::NarwhalDeliveredBatch
}

pub const fn current_dissemination_stage() -> DisseminationStage {
    DisseminationStage::NativeMempool
}

pub const fn completion_target_dissemination_stage() -> DisseminationStage {
    DisseminationStage::NarwhalBatchDissemination
}

pub const fn current_committee_architecture() -> CommitteeArchitecture {
    CommitteeArchitecture::ValidatorBreadth
}

pub const fn completion_target_committee_architecture() -> CommitteeArchitecture {
    CommitteeArchitecture::SuperRepresentative21
}

pub const fn current_committee_stage() -> CommitteeStage {
    CommitteeStage::ValidatorBreadthProof
}

pub const fn completion_target_committee_stage() -> CommitteeStage {
    CommitteeStage::Sr21EpochRotation
}

pub const fn current_committee_selection() -> CommitteeSelection {
    CommitteeSelection::ValidatorBreadthRehearsal
}

pub const fn completion_target_committee_selection() -> CommitteeSelection {
    CommitteeSelection::StakeWeightedTop21Election
}

pub const fn current_committee_size_cap() -> u32 {
    MAX_ACTIVE_VALIDATORS as u32
}

pub const fn completion_target_committee_size_cap() -> u32 {
    NUM_SUPER_REPRESENTATIVES as u32
}

pub fn consensus_architecture_summary() -> ConsensusArchitectureSummary {
    ConsensusArchitectureSummary {
        current_runtime: current_consensus_architecture(),
        completion_target: completion_target_architecture(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_exposes_current_and_completion_target() {
        let summary = consensus_architecture_summary();

        assert_eq!(
            summary.current_runtime.dissemination,
            DisseminationArchitecture::GhostdagNativeMempool
        );
        assert_eq!(
            summary.current_runtime.dissemination_stage,
            DisseminationStage::NativeMempool
        );
        assert_eq!(
            summary.current_runtime.ordering,
            OrderingArchitecture::Ghostdag
        );
        assert_eq!(
            summary.current_runtime.ordering_stage,
            OrderingStage::GhostdagTotalOrder
        );
        assert_eq!(
            summary.current_runtime.ordering_input,
            OrderingInputSource::GhostdagSelectedParent
        );
        assert_eq!(
            summary.current_runtime.finality,
            FinalityArchitecture::CheckpointBft
        );
        assert_eq!(
            summary.current_runtime.checkpoint_decision_source,
            CheckpointDecisionSource::GhostdagCheckpointBft
        );
        assert_eq!(
            summary.current_runtime.committee,
            CommitteeArchitecture::ValidatorBreadth
        );
        assert_eq!(
            summary.current_runtime.committee_stage,
            CommitteeStage::ValidatorBreadthProof
        );
        assert_eq!(
            summary.current_runtime.committee_selection,
            CommitteeSelection::ValidatorBreadthRehearsal
        );
        assert_eq!(summary.current_runtime.committee_size_cap, 21);

        assert_eq!(
            summary.completion_target.dissemination,
            DisseminationArchitecture::Narwhal
        );
        assert_eq!(
            summary.completion_target.dissemination_stage,
            DisseminationStage::NarwhalBatchDissemination
        );
        assert_eq!(
            summary.completion_target.ordering,
            OrderingArchitecture::Bullshark
        );
        assert_eq!(
            summary.completion_target.ordering_stage,
            OrderingStage::BullsharkCommitOrder
        );
        assert_eq!(
            summary.completion_target.ordering_input,
            OrderingInputSource::NarwhalDeliveredBatch
        );
        assert_eq!(
            summary.completion_target.finality,
            FinalityArchitecture::BullsharkCommit
        );
        assert_eq!(
            summary.completion_target.checkpoint_decision_source,
            CheckpointDecisionSource::BullsharkCommit
        );
        assert_eq!(
            summary.completion_target.committee,
            CommitteeArchitecture::SuperRepresentative21
        );
        assert_eq!(
            summary.completion_target.committee_stage,
            CommitteeStage::Sr21EpochRotation
        );
        assert_eq!(
            summary.completion_target.committee_selection,
            CommitteeSelection::StakeWeightedTop21Election
        );
        assert_eq!(summary.completion_target.committee_size_cap, 21);
        assert_eq!(
            summary.completion_target.privacy_scope,
            PrivacyCompletionScope::Deferred
        );
        assert!(summary.completion_target.cex_friendly_priority);
        assert!(summary.completion_target.public_operator_recovery_priority);
    }
}
