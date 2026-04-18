//! Graduated jail duration based on cumulative slash count.
//!
//! - 1st offence: 10 epochs
//! - 2nd offence: 50 epochs
//! - 3rd or later: permanent (`u64::MAX` sentinel)
//!
//! These values are intentionally more lenient than "double-sign =
//! permanent on first offence" (Cosmos/Tendermint) to give operators
//! recovery room after honest operational mistakes. The 20% stake slash
//! (`SlashSeverity::Severe`) provides strong deterrence regardless of
//! jail length, so graduated time is a UX policy, not a security gate.

/// Jail duration expressed as either a bounded epoch delta or a
/// permanent ban.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JailDuration {
    /// Jailed for `n` epochs starting at the current epoch.
    Epochs(u64),
    /// No re-entry allowed. Represented on `ValidatorStatus::Jailed` as
    /// `until_epoch == u64::MAX`; RPC responses surface this as
    /// `"permanent": true`.
    Permanent,
}

impl JailDuration {
    /// Compute the concrete `until_epoch` value to write onto
    /// `ValidatorStatus::Jailed`. `Permanent` maps to `u64::MAX`.
    pub fn until_epoch(self, current_epoch: u64) -> u64 {
        match self {
            JailDuration::Epochs(n) => current_epoch.saturating_add(n),
            JailDuration::Permanent => u64::MAX,
        }
    }

    /// True iff this duration is the `Permanent` sentinel.
    pub fn is_permanent(self) -> bool {
        matches!(self, JailDuration::Permanent)
    }
}

pub const JAIL_EPOCHS_FIRST: u64 = 10;
pub const JAIL_EPOCHS_SECOND: u64 = 50;

/// Map `slash_count` (cumulative number of equivocation slashes against
/// the same validator) to a jail duration.
///
/// `slash_count == 0` is a defensive default — the caller should have
/// incremented first — and returns `Epochs(0)` so nothing escapes
/// punishment silently.
pub fn jail_duration_epochs(slash_count: u64) -> JailDuration {
    match slash_count {
        0 => JailDuration::Epochs(0),
        1 => JailDuration::Epochs(JAIL_EPOCHS_FIRST),
        2 => JailDuration::Epochs(JAIL_EPOCHS_SECOND),
        _ => JailDuration::Permanent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_offence_is_10_epochs() {
        assert_eq!(jail_duration_epochs(1), JailDuration::Epochs(10));
    }

    #[test]
    fn second_offence_is_50_epochs() {
        assert_eq!(jail_duration_epochs(2), JailDuration::Epochs(50));
    }

    #[test]
    fn third_plus_offence_is_permanent() {
        assert_eq!(jail_duration_epochs(3), JailDuration::Permanent);
        assert_eq!(jail_duration_epochs(10), JailDuration::Permanent);
        assert_eq!(jail_duration_epochs(u64::MAX), JailDuration::Permanent);
    }

    #[test]
    fn zero_count_is_safe_default() {
        assert_eq!(jail_duration_epochs(0), JailDuration::Epochs(0));
    }

    #[test]
    fn until_epoch_accumulates_additively() {
        assert_eq!(JailDuration::Epochs(10).until_epoch(5), 15);
        assert_eq!(JailDuration::Epochs(0).until_epoch(100), 100);
    }

    #[test]
    fn until_epoch_saturates_not_overflows() {
        // current_epoch near u64::MAX must not overflow.
        let near_max = u64::MAX - 3;
        assert_eq!(
            JailDuration::Epochs(10).until_epoch(near_max),
            u64::MAX,
            "saturating add prevents overflow"
        );
    }

    #[test]
    fn permanent_maps_to_u64_max() {
        assert_eq!(JailDuration::Permanent.until_epoch(42), u64::MAX);
        assert!(JailDuration::Permanent.is_permanent());
        assert!(!JailDuration::Epochs(1).is_permanent());
    }
}
