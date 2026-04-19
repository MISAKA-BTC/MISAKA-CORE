//! Slashing: the glue layer that wires together
//! equivocation detection → persistence → punishment.
//!
//! # Scope
//!
//! Prompt 3 landed this module on top of the extensive existing
//! infrastructure (Pattern C). No existing type is modified:
//!
//! - `SlotEquivocationEvidence` is consumed as-is (DAG layer).
//! - `StakingRegistry::slash()` is called unchanged with
//!   `SlashSeverity::Severe` (20% of stake).
//! - `ValidatorStatus::Jailed { until_epoch, reason }` is set via the
//!   existing field; we only override the `until_epoch` value to a
//!   graduated duration based on the validator's slash count.
//! - `ReputationTracker::on_slash` (Prompt 2D) is the sink for the
//!   `slash_count` metric surfaced by `getvalidator`.
//!
//! # Graduated Jail
//!
//! See [`jail::jail_duration_epochs`]: 1st offence → 10 epochs,
//! 2nd → 50 epochs, 3rd+ → permanent (`u64::MAX`).
//!
//! # Idempotency
//!
//! The processor uses `ValidatorAccount.last_slash_epoch` as the
//! coordinator: evidence whose detection epoch is ≤ the last recorded
//! slash epoch for the same offender is treated as already processed
//! and skipped. This is a strict application of Option C from the
//! design discussion.

pub mod authority_map;
pub mod jail;
pub mod processor;

pub use authority_map::{authority_to_validator_id, AuthorityMapError};
pub use jail::{jail_duration_epochs, JailDuration, JAIL_EPOCHS_FIRST, JAIL_EPOCHS_SECOND};
pub use processor::{ProcessorError, SlashOutcome, SlashingProcessor, SlashingStats};
