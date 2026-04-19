// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Runtime pruning-mode configuration.
//!
//! # Why
//!
//! Operators choose between two storage profiles:
//!
//! * [`PruneMode::Archival`] — keep every block, commit, and UTXO for
//!   the full chain lifetime. Required for archival / explorer nodes.
//! * [`PruneMode::Pruned`] — drop blocks, commits, and UTXO snapshots
//!   older than `keep_rounds` behind the current tip. Required for
//!   resource-constrained validators.
//!
//! # Scope of this type
//!
//! This module defines only the config surface and its validation.
//! Wiring the mode into the storage / pruning-processor hot path is
//! done elsewhere (Phase 2 Path X R6 — `misaka-node migrate` will stamp
//! schema v2 and a separate prune-loop commit will consume the mode).
//!
//! The mode is intentionally *not* cross-crate-imported by the storage
//! layer; storage APIs accept a plain `Option<u64> keep_rounds` so that
//! `misaka-storage` does not take a new dep on `misaka-config`.
//!
//! # Config shape
//!
//! In TOML:
//!
//! ```toml
//! [consensus]
//! prune_mode = "archival"                  # or "pruned"
//! prune_keep_rounds = 10000                # required iff prune_mode = "pruned"
//! ```
//!
//! In JSON (flat `NodeConfig`):
//!
//! ```json
//! { "prune_mode": "archival" }
//! ```
//!
//! or
//!
//! ```json
//! { "prune_mode": { "pruned": { "keep_rounds": 10000 } } }
//! ```
//!
//! The JSON form uses serde's default externally-tagged enum
//! representation with `rename_all = "snake_case"`. The unit variant
//! `Archival` serialises as the bare string `"archival"`.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Storage retention mode for a running node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PruneMode {
    /// Keep every block, commit, and UTXO for the full chain lifetime.
    /// The default — no history is ever dropped.
    Archival,

    /// Drop blocks, commits, and non-essential UTXO snapshots older
    /// than `keep_rounds` behind the current tip.
    ///
    /// `keep_rounds` MUST be at least `MIN_KEEP_ROUNDS`. Equivocation
    /// evidence is **never** pruned regardless of this setting.
    Pruned {
        /// Rounds of history to retain behind the current tip.
        keep_rounds: u64,
    },
}

/// Lower bound on `keep_rounds` for [`PruneMode::Pruned`]. Below this
/// the node cannot complete finality-gadget rollbacks safely.
///
/// Chosen to comfortably exceed the finality depth (≤ ~1000 rounds as
/// of v0.9.0) plus the safety margin used elsewhere in the codebase.
/// See `crates/misaka-storage/src/utxo_set.rs:104` for the finality
/// depth used by SPC undo.
pub const MIN_KEEP_ROUNDS: u64 = 2_000;

/// Default keep-rounds when `prune_mode = "pruned"` is set in config
/// without an explicit `prune_keep_rounds`. Matches the existing
/// `NodeConfig::dag_retention_rounds` default so that pruned nodes
/// retain at least as much history as the DAG GC already keeps.
pub const DEFAULT_KEEP_ROUNDS: u64 = 10_000;

impl Default for PruneMode {
    fn default() -> Self {
        Self::Archival
    }
}

impl PruneMode {
    /// Reject invalid combinations (e.g. `Pruned { keep_rounds: 0 }`).
    ///
    /// Called during [`crate::NodeConfig::validate`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Archival => Ok(()),
            Self::Pruned { keep_rounds } => {
                if *keep_rounds < MIN_KEEP_ROUNDS {
                    return Err(ConfigError::Custom(format!(
                        "prune_keep_rounds = {} is below the safety floor \
                         MIN_KEEP_ROUNDS = {}. Increase to at least \
                         MIN_KEEP_ROUNDS rounds or switch to prune_mode = \
                         \"archival\".",
                        keep_rounds, MIN_KEEP_ROUNDS,
                    )));
                }
                Ok(())
            }
        }
    }

    /// Convenience: returns `Some(keep_rounds)` for `Pruned`, `None`
    /// for `Archival`. Used by callers that don't need the enum
    /// distinction and just want a retention bound.
    #[must_use]
    pub fn keep_rounds(&self) -> Option<u64> {
        match self {
            Self::Archival => None,
            Self::Pruned { keep_rounds } => Some(*keep_rounds),
        }
    }

    /// `true` iff this mode actively drops history.
    #[must_use]
    pub fn is_pruned(&self) -> bool {
        matches!(self, Self::Pruned { .. })
    }
}

/// Build a [`PruneMode`] from the two-field TOML shape
/// (`prune_mode` string + optional `prune_keep_rounds`).
///
/// * `mode_str = None` ⇒ [`PruneMode::Archival`] (matches the runtime
///   default).
/// * `mode_str = Some("archival")` ⇒ [`PruneMode::Archival`];
///   `keep_rounds` must be absent or is silently dropped with a warning
///   (caller's responsibility to check).
/// * `mode_str = Some("pruned")` ⇒ [`PruneMode::Pruned`] using
///   `keep_rounds.unwrap_or(DEFAULT_KEEP_ROUNDS)`.
/// * Any other string is rejected.
pub fn from_toml_fields(
    mode_str: Option<&str>,
    keep_rounds: Option<u64>,
) -> Result<PruneMode, ConfigError> {
    match mode_str {
        None => Ok(PruneMode::Archival),
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "archival" => Ok(PruneMode::Archival),
            "pruned" => Ok(PruneMode::Pruned {
                keep_rounds: keep_rounds.unwrap_or(DEFAULT_KEEP_ROUNDS),
            }),
            other => Err(ConfigError::Custom(format!(
                "unknown prune_mode \"{other}\" (expected \"archival\" or \"pruned\")",
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Defaults & accessors ──────────────────────────────────────

    #[test]
    fn default_is_archival() {
        assert_eq!(PruneMode::default(), PruneMode::Archival);
    }

    #[test]
    fn keep_rounds_is_none_for_archival() {
        assert_eq!(PruneMode::Archival.keep_rounds(), None);
    }

    #[test]
    fn keep_rounds_returns_value_for_pruned() {
        let m = PruneMode::Pruned {
            keep_rounds: DEFAULT_KEEP_ROUNDS,
        };
        assert_eq!(m.keep_rounds(), Some(DEFAULT_KEEP_ROUNDS));
    }

    #[test]
    fn is_pruned_flag() {
        assert!(!PruneMode::Archival.is_pruned());
        assert!(PruneMode::Pruned { keep_rounds: 5000 }.is_pruned());
    }

    // ── Validation ────────────────────────────────────────────────

    #[test]
    fn validate_archival_is_ok() {
        assert!(PruneMode::Archival.validate().is_ok());
    }

    #[test]
    fn validate_pruned_above_floor_is_ok() {
        let m = PruneMode::Pruned {
            keep_rounds: MIN_KEEP_ROUNDS,
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn validate_pruned_below_floor_errors() {
        let m = PruneMode::Pruned {
            keep_rounds: MIN_KEEP_ROUNDS - 1,
        };
        let err = m.validate().expect_err("must reject below-floor value");
        let msg = format!("{err}");
        assert!(
            msg.contains("MIN_KEEP_ROUNDS"),
            "error should cite floor: {msg}"
        );
    }

    #[test]
    fn validate_pruned_zero_errors() {
        let m = PruneMode::Pruned { keep_rounds: 0 };
        assert!(m.validate().is_err());
    }

    // ── JSON shape ────────────────────────────────────────────────

    #[test]
    fn json_archival_is_plain_string() {
        let j = serde_json::to_string(&PruneMode::Archival).unwrap();
        assert_eq!(j, "\"archival\"");
    }

    #[test]
    fn json_pruned_is_externally_tagged() {
        let m = PruneMode::Pruned { keep_rounds: 5000 };
        let j = serde_json::to_string(&m).unwrap();
        // External tag form, snake_case per the serde attribute on the enum.
        assert_eq!(j, "{\"pruned\":{\"keep_rounds\":5000}}");
    }

    #[test]
    fn json_roundtrip_archival() {
        let a: PruneMode = serde_json::from_str("\"archival\"").unwrap();
        assert_eq!(a, PruneMode::Archival);
    }

    #[test]
    fn json_roundtrip_pruned() {
        let p: PruneMode = serde_json::from_str("{\"pruned\":{\"keep_rounds\":7777}}").unwrap();
        assert_eq!(p, PruneMode::Pruned { keep_rounds: 7777 });
    }

    // ── TOML two-field form ───────────────────────────────────────

    #[test]
    fn toml_absent_defaults_to_archival() {
        let m = from_toml_fields(None, None).unwrap();
        assert_eq!(m, PruneMode::Archival);
    }

    #[test]
    fn toml_archival_string_parses() {
        let m = from_toml_fields(Some("archival"), None).unwrap();
        assert_eq!(m, PruneMode::Archival);
    }

    #[test]
    fn toml_pruned_without_rounds_uses_default() {
        let m = from_toml_fields(Some("pruned"), None).unwrap();
        assert_eq!(
            m,
            PruneMode::Pruned {
                keep_rounds: DEFAULT_KEEP_ROUNDS
            }
        );
    }

    #[test]
    fn toml_pruned_with_explicit_rounds() {
        let m = from_toml_fields(Some("pruned"), Some(12345)).unwrap();
        assert_eq!(m, PruneMode::Pruned { keep_rounds: 12345 });
    }

    #[test]
    fn toml_pruned_is_case_insensitive() {
        assert_eq!(
            from_toml_fields(Some("PrUnEd"), Some(5000)).unwrap(),
            PruneMode::Pruned { keep_rounds: 5000 }
        );
    }

    #[test]
    fn toml_unknown_mode_errors() {
        let err = from_toml_fields(Some("turbo"), None).expect_err("unknown mode");
        let msg = format!("{err}");
        assert!(
            msg.contains("turbo"),
            "error should name the bad value: {msg}"
        );
    }

    // ── Boundary constants ────────────────────────────────────────

    #[test]
    fn min_keep_rounds_is_below_default() {
        assert!(MIN_KEEP_ROUNDS <= DEFAULT_KEEP_ROUNDS);
    }
}
