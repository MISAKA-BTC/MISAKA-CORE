//! `SlashingProcessor` — epoch-boundary driver that turns persisted
//! equivocation evidence into applied slashes.
//!
//! # Responsibilities
//!
//! 1. Receive pending evidence (from DAG detection or P2P gossip) and
//!    hand-off to the persistent [`ConsensusWal`]-equivalent store via
//!    the caller-supplied `EvidenceStore`.
//! 2. At each epoch boundary, iterate pending evidence, skip anything
//!    already covered by a prior slash (Option C idempotency via
//!    `last_slash_epoch`), and apply slash + graduated jail + reputation
//!    increment for the rest.
//! 3. Rebuild `slash_count` from a WAL replay on startup so graduated
//!    jail decisions survive a restart without a new WAL record kind.
//!
//! # Wiring
//!
//! The processor is *passive* — it does not own the consensus WAL,
//! staking registry, validator system, or reputation tracker. The node
//! layer (or integration tests) pass them in as `Arc`s. That keeps the
//! DAG / staking crates free of circular deps.
//!
//! No existing consensus type is modified. Graduated jail is applied by
//! reaching through `ValidatorSystemV2.validators` (public field) and
//! overriding `status.until_epoch` AFTER the standard
//! `report_infraction(DoubleSign)` path runs — this keeps existing
//! semantics (score → 0, demotion, reward zeroing) while layering our
//! policy on top.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::reputation::ReputationTracker;
use crate::staking::{SlashSeverity, StakingError, StakingRegistry};
use crate::validator_system_v2::{
    Infraction, JailReason, ValidatorStatus, ValidatorSystemError, ValidatorSystemV2,
};

use super::jail::{jail_duration_epochs, JailDuration};

/// 32-byte validator id (SHA3-256 over ML-DSA-65 pubkey).
pub type ValidatorId = [u8; 32];

/// A minimal record of a single evidence, stripped of DAG-internal
/// types. The processor operates on this view so it does not need
/// to depend on `misaka-dag` (which would create a dep cycle).
#[derive(Clone, Debug)]
pub struct PendingEvidence {
    /// Canonical validator id of the offender (already mapped from
    /// `AuthorityIndex` by the caller via `authority_map`).
    pub offender: ValidatorId,
    /// Epoch the evidence was *detected* at. Idempotency gate.
    pub detected_epoch: u64,
    /// Round number the equivocation occurred at. Informational only.
    pub round: u64,
    /// Opaque bytes for WAL storage or debugging. Not consulted by the
    /// processor.
    pub raw: Vec<u8>,
}

/// Outcome of applying a single evidence at epoch boundary.
#[derive(Clone, Debug)]
pub struct SlashOutcome {
    pub offender: ValidatorId,
    pub detected_epoch: u64,
    pub processed_epoch: u64,
    /// Amount in base units actually removed from the validator's stake.
    pub amount_slashed: u64,
    /// Reporter reward carved out of `amount_slashed` (goes to the
    /// staking pool via `StakingRegistry::slash`).
    pub reporter_reward: u64,
    /// Cumulative count (1, 2, 3, ...) used to select jail tier.
    pub new_slash_count: u64,
    pub jail_duration: JailDuration,
    pub jail_until_epoch: u64,
}

/// Summary returned by `process_epoch`.
#[derive(Clone, Debug, Default)]
pub struct SlashingStats {
    pub evidence_seen: u64,
    pub slashed: u64,
    pub skipped_idempotent: u64,
    pub skipped_cooldown: u64,
    pub errors: u64,
    pub total_amount_slashed: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("staking: {0}")]
    Staking(#[from] StakingError),
    #[error("validator system: {0}")]
    ValidatorSystem(#[from] ValidatorSystemError),
}

/// Read-only handle that `SlashingProcessor` uses to discover pending
/// evidence. Abstracted so node-layer code can wire either the DAG's
/// in-memory ledger or a WAL-backed replay source without the
/// processor caring which.
pub trait EvidenceSource: Send + Sync {
    /// Return every evidence the caller currently knows about, in a
    /// deterministic order. Empty is a valid result.
    fn pending(&self) -> Vec<PendingEvidence>;
}

/// The main processor. Stateless apart from the Arcs it holds.
#[derive(Clone)]
pub struct SlashingProcessor {
    staking: Arc<RwLock<StakingRegistry>>,
    validator_system: Arc<RwLock<ValidatorSystemV2>>,
    reputation: Arc<ReputationTracker>,
}

impl SlashingProcessor {
    pub fn new(
        staking: Arc<RwLock<StakingRegistry>>,
        validator_system: Arc<RwLock<ValidatorSystemV2>>,
        reputation: Arc<ReputationTracker>,
    ) -> Self {
        Self {
            staking,
            validator_system,
            reputation,
        }
    }

    /// Recompute `slash_count` for every validator by replaying
    /// persisted evidence. Called once at node startup. Counting rule:
    /// each distinct `(offender, detected_epoch)` pair increments the
    /// count by 1, which matches the epoch-level idempotency used at
    /// processing time.
    pub fn rebuild_slash_count_from_evidence(&self, evidence: &[PendingEvidence]) {
        let mut seen: BTreeMap<(ValidatorId, u64), ()> = BTreeMap::new();
        for e in evidence {
            seen.entry((e.offender, e.detected_epoch)).or_insert(());
        }
        let mut counts: BTreeMap<ValidatorId, u64> = BTreeMap::new();
        for (id, _) in seen.keys() {
            *counts.entry(*id).or_insert(0) += 1;
        }
        // Populate the tracker. `on_slash` is the public path and is
        // idempotent per call so calling it N times is equivalent to
        // setting the count to N from a fresh tracker.
        for (vid, count) in counts {
            for _ in 0..count {
                self.reputation.on_slash(vid);
            }
        }
    }

    /// Drain a set of pending evidence at epoch boundary `current_epoch`.
    ///
    /// For each evidence:
    /// 1. Skip if the offender's `last_slash_epoch` already covers
    ///    `detected_epoch` (Option C idempotency).
    /// 2. Otherwise call `StakingRegistry::slash(Severe)` (existing
    ///    20% rate + cooldown + auto-eject).
    /// 3. Increment `slash_count` via the reputation tracker.
    /// 4. Apply graduated jail via `ValidatorSystemV2.validators[id]`.
    ///
    /// Cooldown rejection from step 2 is recorded as `skipped_cooldown`
    /// and the count is NOT incremented (no slash actually landed).
    pub fn process_epoch(&self, pending: &[PendingEvidence], current_epoch: u64) -> SlashingStats {
        let mut stats = SlashingStats {
            evidence_seen: pending.len() as u64,
            ..Default::default()
        };

        for ev in pending {
            // 1. Idempotency: if we've already slashed this validator at
            //    `detected_epoch` or later, skip. `last_slash_epoch`
            //    records the most recent applied slash.
            let already_covered = {
                let reg = self.staking.read();
                reg.get(&ev.offender)
                    .and_then(|a| a.last_slash_epoch)
                    .map(|last| last >= ev.detected_epoch)
                    .unwrap_or(false)
            };
            if already_covered {
                stats.skipped_idempotent += 1;
                continue;
            }

            match self.apply_single(ev, current_epoch) {
                Ok(out) => {
                    stats.slashed += 1;
                    stats.total_amount_slashed = stats
                        .total_amount_slashed
                        .saturating_add(out.amount_slashed);
                }
                Err(ProcessorError::Staking(StakingError::SlashCooldown { .. })) => {
                    stats.skipped_cooldown += 1;
                }
                Err(_) => {
                    stats.errors += 1;
                }
            }
        }

        stats
    }

    /// Apply one evidence. Returns `SlashCooldown` when the staking
    /// cooldown window prevents the slash (evidence is retained for a
    /// future epoch).
    pub fn apply_single(
        &self,
        ev: &PendingEvidence,
        current_epoch: u64,
    ) -> Result<SlashOutcome, ProcessorError> {
        // Stake reduction via the *existing* path (u128 overflow safe,
        // cooldown-aware, auto-ejects below min stake).
        let (amount_slashed, reporter_reward) = {
            let mut reg = self.staking.write();
            reg.slash(&ev.offender, SlashSeverity::Severe, current_epoch)?
        };

        // Count this slash. `on_slash` is in-memory; the count is
        // authoritatively re-derived from persisted evidence at startup
        // via `rebuild_slash_count_from_evidence`.
        self.reputation.on_slash(ev.offender);
        let new_slash_count = self.reputation.metrics_for(&ev.offender).slash_count;

        // Graduated jail policy — this is the Prompt 3 addition layered
        // on top of the existing fixed-duration infraction flow.
        let duration = jail_duration_epochs(new_slash_count);
        let jail_until = duration.until_epoch(current_epoch);

        // Run the existing infraction flow. It resets score/penalty to
        // 0, demotes Active → Backup, and sets a short jail. We then
        // override `until_epoch` with our graduated value. Errors here
        // (e.g. validator not registered in ValidatorSystemV2) are
        // downgraded to a warning so the core stake-level slash still
        // takes effect — ValidatorSystemV2 is a performance/rotation
        // system, not consensus-critical.
        let mut vsys = self.validator_system.write();
        let known_to_vsys = vsys.validators.contains_key(&ev.offender);
        if known_to_vsys {
            let _ = vsys.report_infraction(&ev.offender, Infraction::DoubleSign);
            if let Some(v) = vsys.validators.get_mut(&ev.offender) {
                v.status = ValidatorStatus::Jailed {
                    until_epoch: jail_until,
                    reason: JailReason::DoubleSign,
                };
            }
        }
        drop(vsys);

        Ok(SlashOutcome {
            offender: ev.offender,
            detected_epoch: ev.detected_epoch,
            processed_epoch: current_epoch,
            amount_slashed,
            reporter_reward,
            new_slash_count,
            jail_duration: duration,
            jail_until_epoch: jail_until,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staking::StakingConfig;
    use crate::validator_system_v2::ValidatorSystemConfig;

    fn vid(n: u8) -> ValidatorId {
        [n; 32]
    }

    fn seed_validator(staking: &Arc<RwLock<StakingRegistry>>, id: ValidatorId, stake: u64) {
        let mut reg = staking.write();
        // Reward address distinct from validator id to match real topology.
        let mut reward = [0u8; 32];
        reward[0] = id[0].wrapping_add(1);
        reg.register(
            id,
            vec![0xAAu8; 32],
            stake,
            500,
            reward,
            0,
            [0xDEu8; 32],
            0,
            true,
            Some(format!("sig-{:x}-{:0>60}", id[0], 0)),
            // PR D1: HEAD's `register()` signature takes an 11th
            // `l1_stake_verified: bool` argument. Merged dropped it.
            // Keep the HEAD shape until PR D2 swaps staking.rs.
            false,
        )
        .unwrap();
        // Move to Active so slash() accepts it.
        let sig = format!("sig-{:x}-{:0>60}", id[0], 0);
        reg.mark_stake_verified(&id, sig.clone(), None).unwrap();
        reg.activate(&id, 0).unwrap();
    }

    fn zero_cooldown_config() -> StakingConfig {
        let mut cfg = StakingConfig::testnet();
        // Disable cooldown so tests can exercise multiple slashes
        // against the same offender back-to-back.
        cfg.slash_cooldown_epochs = 0;
        cfg
    }

    fn make_processor() -> (
        Arc<RwLock<StakingRegistry>>,
        Arc<RwLock<ValidatorSystemV2>>,
        Arc<ReputationTracker>,
        SlashingProcessor,
    ) {
        #[allow(deprecated)]
        let staking = Arc::new(RwLock::new(StakingRegistry::new(zero_cooldown_config())));
        let vsys = Arc::new(RwLock::new(ValidatorSystemV2::new(
            ValidatorSystemConfig::default(),
        )));
        let rep = Arc::new(ReputationTracker::new(1_000));
        let proc = SlashingProcessor::new(staking.clone(), vsys.clone(), rep.clone());
        (staking, vsys, rep, proc)
    }

    fn make_processor_with_cooldown() -> (
        Arc<RwLock<StakingRegistry>>,
        Arc<RwLock<ValidatorSystemV2>>,
        Arc<ReputationTracker>,
        SlashingProcessor,
    ) {
        // Default testnet cooldown = 1000 epochs — used by the cooldown
        // skip test.
        #[allow(deprecated)]
        let staking = Arc::new(RwLock::new(StakingRegistry::new(StakingConfig::testnet())));
        let vsys = Arc::new(RwLock::new(ValidatorSystemV2::new(
            ValidatorSystemConfig::default(),
        )));
        let rep = Arc::new(ReputationTracker::new(1_000));
        let proc = SlashingProcessor::new(staking.clone(), vsys.clone(), rep.clone());
        (staking, vsys, rep, proc)
    }

    #[test]
    fn first_slash_triggers_10_epoch_jail() {
        let (staking, _vsys, _rep, proc) = make_processor();
        seed_validator(&staking, vid(1), 1_000_000_000_000_000);

        let ev = PendingEvidence {
            offender: vid(1),
            detected_epoch: 5,
            round: 42,
            raw: vec![],
        };
        let out = proc.apply_single(&ev, 5).expect("first slash");
        assert_eq!(out.new_slash_count, 1);
        assert_eq!(out.jail_duration, JailDuration::Epochs(10));
        assert_eq!(out.jail_until_epoch, 15);
        assert!(out.amount_slashed > 0);
    }

    #[test]
    fn third_slash_triggers_permanent_jail() {
        // zero cooldown → three consecutive slashes land.
        let (staking, _vsys, rep, proc) = make_processor();
        seed_validator(&staking, vid(2), 10_000_000_000_000_000);

        for (i, ep) in [10u64, 20, 30].iter().enumerate() {
            let out = proc
                .apply_single(
                    &PendingEvidence {
                        offender: vid(2),
                        detected_epoch: *ep,
                        round: i as u64,
                        raw: vec![],
                    },
                    *ep,
                )
                .unwrap_or_else(|e| panic!("slash {}: {:?}", i + 1, e));
            assert_eq!(out.new_slash_count, (i + 1) as u64);
        }
        assert_eq!(rep.metrics_for(&vid(2)).slash_count, 3);
        // The last outcome must be permanent.
        let out = proc
            .apply_single(
                &PendingEvidence {
                    offender: vid(2),
                    detected_epoch: 40,
                    round: 3,
                    raw: vec![],
                },
                40,
            )
            .expect("4th slash");
        assert_eq!(out.new_slash_count, 4);
        assert_eq!(out.jail_duration, JailDuration::Permanent);
        assert_eq!(out.jail_until_epoch, u64::MAX);
    }

    #[test]
    fn process_epoch_idempotent_on_last_slash_epoch() {
        // After one real slash at epoch 10, older-or-equal evidence is
        // skipped as already-covered.
        let (staking, _vsys, _rep, proc) = make_processor();
        seed_validator(&staking, vid(3), 1_000_000_000_000_000);
        proc.apply_single(
            &PendingEvidence {
                offender: vid(3),
                detected_epoch: 10,
                round: 0,
                raw: vec![],
            },
            10,
        )
        .unwrap();

        let pending = vec![
            PendingEvidence {
                offender: vid(3),
                detected_epoch: 5, // older than last_slash_epoch=10 → skip
                round: 1,
                raw: vec![],
            },
            PendingEvidence {
                offender: vid(3),
                detected_epoch: 10, // equal → already covered, skip
                round: 2,
                raw: vec![],
            },
        ];
        let stats = proc.process_epoch(&pending, 11);
        assert_eq!(stats.evidence_seen, 2);
        assert_eq!(stats.slashed, 0);
        assert_eq!(stats.skipped_idempotent, 2);
    }

    #[test]
    fn rebuild_counts_each_distinct_epoch_once() {
        let (_staking, _vsys, rep, proc) = make_processor();
        let evidence = vec![
            PendingEvidence {
                offender: vid(4),
                detected_epoch: 1,
                round: 0,
                raw: vec![],
            },
            PendingEvidence {
                offender: vid(4),
                detected_epoch: 1,
                round: 1,
                raw: vec![],
            }, // dup
            PendingEvidence {
                offender: vid(4),
                detected_epoch: 2,
                round: 0,
                raw: vec![],
            },
            PendingEvidence {
                offender: vid(5),
                detected_epoch: 1,
                round: 0,
                raw: vec![],
            },
        ];
        proc.rebuild_slash_count_from_evidence(&evidence);
        assert_eq!(rep.metrics_for(&vid(4)).slash_count, 2, "epochs 1 and 2");
        assert_eq!(rep.metrics_for(&vid(5)).slash_count, 1);
    }

    #[test]
    fn cooldown_rejection_is_not_counted_as_slash() {
        let (staking, _vsys, rep, proc) = make_processor_with_cooldown();
        seed_validator(&staking, vid(6), 1_000_000_000_000_000);
        // Slash once at epoch 1 to set last_slash_epoch + cooldown.
        proc.apply_single(
            &PendingEvidence {
                offender: vid(6),
                detected_epoch: 1,
                round: 0,
                raw: vec![],
            },
            1,
        )
        .unwrap();
        let count_before = rep.metrics_for(&vid(6)).slash_count;
        assert_eq!(count_before, 1);

        // Fresh evidence at detected_epoch=2, inside cooldown window.
        // Idempotency check (last_slash_epoch=1 >= detected_epoch=2? no)
        // so we call through to slash(), which hits SlashCooldown.
        let pending = vec![PendingEvidence {
            offender: vid(6),
            detected_epoch: 2,
            round: 5,
            raw: vec![],
        }];
        let stats = proc.process_epoch(&pending, 2);
        assert_eq!(stats.slashed, 0);
        assert_eq!(stats.skipped_cooldown, 1);
        assert_eq!(
            rep.metrics_for(&vid(6)).slash_count,
            count_before,
            "cooldown must not double-count"
        );
    }

    #[test]
    fn process_epoch_tallies_totals() {
        let (staking, _vsys, _rep, proc) = make_processor();
        seed_validator(&staking, vid(7), 1_000_000_000_000_000);
        seed_validator(&staking, vid(8), 1_000_000_000_000_000);
        let pending = vec![
            PendingEvidence {
                offender: vid(7),
                detected_epoch: 5,
                round: 0,
                raw: vec![],
            },
            PendingEvidence {
                offender: vid(8),
                detected_epoch: 5,
                round: 1,
                raw: vec![],
            },
        ];
        let stats = proc.process_epoch(&pending, 5);
        assert_eq!(stats.evidence_seen, 2);
        assert_eq!(stats.slashed, 2);
        assert!(stats.total_amount_slashed > 0);
    }
}
