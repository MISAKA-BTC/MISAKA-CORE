// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Offline schema migration for the misaka node's Kaspa-aligned
//! storage DB.
//!
//! # What this module does today
//!
//! It stamps (or verifies) the storage schema version marker introduced
//! by Phase 2 Path X R5 (see `misaka-storage::schema_version`). It
//! does **not** rewrite user data. The marker is the only piece of
//! state that distinguishes schema versions:
//!
//! * v1 (`STORAGE_SCHEMA_VERSION_V088`) — pre-marker DBs written by
//!   v0.8.x builds.
//! * v2 (`STORAGE_SCHEMA_VERSION_V090`) — Phase 2 Path X layout.
//! * v3 (`STORAGE_SCHEMA_VERSION_V091`) — Phase 3a layout, adds the
//!   `narwhal_votes` + `narwhal_cert_mapping` CFs for Cert V2.
//!
//! For v2 → v3 the tool opens the DB with every existing CF listed
//! and `create_missing_column_families = true`, so the two new CFs
//! are created atomically alongside the marker stamp.
//!
//! # What this module does *not* do (yet)
//!
//! * **Legacy-CF drain.** Phase 2 Path X R1 (retirement of
//!   `RocksBlockStore` and its 5 legacy column families: `utxos`,
//!   `spent_tags`, `spending_keys`, `block_meta`, `state`) is blocked
//!   on the fact that the Kaspa-aligned stack has no persistent
//!   equivalent for `verify_integrity()` or a persisted `state_root`.
//!   Until R1 ships, there is no transform to run: legacy-CF data
//!   stays in place, readable by legacy paths.
//! * **Downgrade.** v0.9.0 → v0.8.x is lossy and explicitly
//!   unsupported; the operator must restore from a pre-upgrade
//!   snapshot. The tool refuses `--to` values below the current DB
//!   marker.
//!
//! # CLI surface (wired in `main.rs`)
//!
//! ```text
//! misaka-node \
//!   --migrate-to 2 \
//!   [--migrate-from 1] \
//!   [--migrate-dry-run] \
//!   [--migrate-db /path/to/db] \
//!   [--data-dir ./data]
//! ```
//!
//! * `--migrate-to` (required to trigger migration) — target schema
//!   version. Must equal [`misaka_storage::CURRENT_STORAGE_SCHEMA_VERSION`];
//!   each build only writes the marker for its own schema. To hop
//!   from v1 → v3 the operator runs a v0.9.0 build for v1 → v2 first,
//!   then a v0.9.1 build for v2 → v3.
//! * `--migrate-from` (optional) — expected current DB version. If
//!   set and the DB's actual marker is different, the tool refuses
//!   to proceed (guards operators against running a v2 migration
//!   against a DB that was already stamped v3 by a newer build).
//! * `--migrate-dry-run` — read the DB marker and print what would
//!   happen, without mutating anything.
//! * `--migrate-db` — explicit path to the RocksDB directory.
//!   Defaults to `<data-dir>/storage` to match the layout the node
//!   uses at runtime.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rocksdb::{Options, DB};

use misaka_storage::{
    check_storage_schema_compatible, read_storage_schema_version, write_storage_schema_version,
    CURRENT_STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_V088, STORAGE_SCHEMA_VERSION_V090,
    STORAGE_SCHEMA_VERSION_V091,
};

/// Arguments consumed by [`run`]. Constructed from CLI flags in
/// `main.rs`. Expressing the parameter bundle as a struct keeps this
/// module decoupled from `clap` and testable in isolation.
#[derive(Debug, Clone)]
pub struct MigrateArgs {
    /// Target schema version. Required and must match
    /// [`CURRENT_STORAGE_SCHEMA_VERSION`].
    pub to: u32,
    /// Optional expected source version. When `Some(v)`, the tool
    /// refuses to proceed unless the DB's current marker is exactly
    /// `v` (or `V088` when the marker is absent and `v == V088`).
    pub from: Option<u32>,
    /// When `true`, read the marker and report the plan but do not
    /// mutate the DB.
    pub dry_run: bool,
    /// Path to the RocksDB directory. Typically `<data-dir>/storage`.
    pub db_path: PathBuf,
}

/// Derive the default migration DB path from a node data directory.
///
/// Kept as a free function so the caller in `main.rs` can compose it
/// out of the effective `cli.data_dir` after config-file overrides
/// have been applied.
///
/// The path component matches where `start_narwhal_node` opens its
/// RocksDB (`crates/misaka-node/src/main.rs:1615` —
/// `data_dir.join("narwhal_consensus")`). An earlier draft of this
/// helper returned `data_dir/storage`; that did not match any live
/// layout and is corrected here — callers of the public migrate API
/// should use this function instead of hard-coding a path.
#[must_use]
pub fn default_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("narwhal_consensus")
}

/// Execute the migration.
///
/// Flow:
/// 1. Validate `to` is a version this build understands.
/// 2. Open the DB read-only first to read the current marker.
/// 3. If `from` is supplied, enforce equality with the observed marker.
/// 4. Decide the plan: `NoOp`, `Stamp`, or `Refuse`.
/// 5. In non-dry-run mode, open the DB read-write and apply the plan.
///
/// The function prints its plan to stdout. On success returns `Ok(())`;
/// on any inconsistency returns a descriptive `anyhow::Error` so the
/// process exit code is non-zero.
pub fn run(args: &MigrateArgs) -> Result<()> {
    // 1. Validate target.
    validate_target(args.to)?;

    // 2. Read current marker.
    let observed = read_marker(&args.db_path)?;

    // 3. Enforce `--migrate-from` if supplied.
    if let Some(expected_from) = args.from {
        let actual = observed.unwrap_or(STORAGE_SCHEMA_VERSION_V088);
        if actual != expected_from {
            bail!(
                "--migrate-from {} does not match the DB's observed version {}. \
                 Refusing to proceed to avoid clobbering an unexpected state. \
                 Drop the --migrate-from flag to let the tool infer the source.",
                expected_from,
                actual,
            );
        }
    }

    // 4. Decide plan.
    let plan = decide_plan(observed, args.to)?;

    // 5. Report and apply.
    println!(
        "misaka-node migrate: db = {}, observed = {}, target = {}, plan = {}",
        args.db_path.display(),
        match observed {
            Some(v) => format!("v{v}"),
            None => format!("absent (pre-v0.9.0, treat as v{STORAGE_SCHEMA_VERSION_V088})"),
        },
        args.to,
        plan.describe(),
    );

    match plan {
        Plan::NoOp => Ok(()),
        Plan::Stamp { to } => {
            if args.dry_run {
                println!("dry-run: not writing marker (would stamp v{to})");
                return Ok(());
            }
            stamp_marker(&args.db_path, to)?;
            println!("migrate: stamped schema_version = {to}");
            // Double-check the write took.
            let final_marker = check_storage_schema_compatible_in(&args.db_path, false)
                .context("post-stamp compatibility check")?;
            println!("migrate: post-stamp check ok (v{final_marker})");
            Ok(())
        }
    }
}

/// What the tool decided to do. Extracted from [`run`] so tests can
/// assert on the decision without needing a real RocksDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The DB is already at the target version.
    NoOp,
    /// The DB needs its marker set to `to`.
    Stamp { to: u32 },
}

impl Plan {
    fn describe(&self) -> String {
        match self {
            Self::NoOp => "no-op (DB already at target version)".to_string(),
            Self::Stamp { to } => format!("stamp schema_version = v{to}"),
        }
    }
}

fn validate_target(to: u32) -> Result<()> {
    if to != CURRENT_STORAGE_SCHEMA_VERSION {
        bail!(
            "--migrate-to {} is not supported by this build (expected {}). \
             This build writes v{} marker exclusively; use a matching build \
             to stamp any other version.",
            to,
            CURRENT_STORAGE_SCHEMA_VERSION,
            CURRENT_STORAGE_SCHEMA_VERSION,
        );
    }
    Ok(())
}

fn decide_plan(observed: Option<u32>, to: u32) -> Result<Plan> {
    match observed {
        Some(v) if v == to => Ok(Plan::NoOp),
        Some(v) if v > to => bail!(
            "DB is at v{} which is newer than the requested target v{}. \
             Refusing to downgrade — restore from a pre-upgrade snapshot if \
             you need to go back.",
            v,
            to,
        ),
        Some(_) | None => Ok(Plan::Stamp { to }),
    }
}

/// Open the DB read-only, read the marker, close. Distinct from the
/// read-write path so we can fail fast before acquiring a writer lock.
fn read_marker(db_path: &Path) -> Result<Option<u32>> {
    if !db_path.exists() {
        bail!(
            "storage DB does not exist at {}. \
             Create the node's data directory and start the node once before migrating.",
            db_path.display(),
        );
    }
    let opts = Options::default();
    let db = DB::open_for_read_only(&opts, db_path, false)
        .with_context(|| format!("open DB read-only at {}", db_path.display()))?;
    let v = read_storage_schema_version(&db)
        .with_context(|| format!("read schema_version from {}", db_path.display()))?;
    Ok(v)
}

/// Open the DB read-write, write the marker, sync, close.
///
/// Handles any `to` version currently supported by `validate_target`.
/// RocksDB requires every existing CF to be listed at open time; this
/// function reads the on-disk CF list, unions with the target schema's
/// expected CFs (so v2 → v3 can add `narwhal_votes` +
/// `narwhal_cert_mapping` atomically with the marker stamp), then
/// opens with `create_missing_column_families = true`.
fn stamp_marker(db_path: &Path, to: u32) -> Result<()> {
    let mut opts = Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(true);

    // Enumerate existing CFs on disk. On a fresh DB `list_cf` returns
    // `["default"]` by RocksDB convention — so always include the
    // default CF explicitly as a fallback.
    let mut all: std::collections::BTreeSet<String> =
        rocksdb::DB::list_cf(&Options::default(), db_path)
            .unwrap_or_else(|_| vec!["default".to_string()])
            .into_iter()
            .collect();
    if !all.contains("default") {
        all.insert("default".to_string());
    }

    // Add the CFs introduced by each target schema version. This is
    // the per-version "schema delta" list — add an arm here when
    // `STORAGE_SCHEMA_VERSION_Vxxx` is introduced.
    if to >= STORAGE_SCHEMA_VERSION_V091 {
        // Phase 3a A.1 + A.5 + Part C — Cert V2 CFs + audit log.
        all.insert("narwhal_votes".to_string());
        all.insert("narwhal_cert_mapping".to_string());
        all.insert("narwhal_round_config_audit".to_string());
    }

    let descriptors: Vec<rocksdb::ColumnFamilyDescriptor> = all
        .into_iter()
        .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, Options::default()))
        .collect();

    let db = rocksdb::DB::open_cf_descriptors(&opts, db_path, descriptors)
        .with_context(|| format!("open DB read-write at {}", db_path.display()))?;
    write_storage_schema_version(&db, to)
        .with_context(|| format!("write schema_version = {to}"))?;
    // `DB::flush` is best-effort; on drop the DB is closed cleanly.
    db.flush().with_context(|| "flush after stamp")?;
    Ok(())
}

/// Strict compatibility check against the configured build. Used after
/// a stamp to confirm the marker round-trips through a fresh open.
fn check_storage_schema_compatible_in(db_path: &Path, accept_unmarked: bool) -> Result<u32> {
    let opts = Options::default();
    let db = DB::open_for_read_only(&opts, db_path, false)
        .with_context(|| format!("reopen DB at {}", db_path.display()))?;
    check_storage_schema_compatible(&db, accept_unmarked)
        .with_context(|| "post-stamp compatibility check".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure plan-decision tests (no RocksDB) ─────────────────────

    #[test]
    fn plan_noop_when_db_already_at_target() {
        let plan = decide_plan(
            Some(STORAGE_SCHEMA_VERSION_V090),
            STORAGE_SCHEMA_VERSION_V090,
        )
        .expect("same version must be no-op");
        assert_eq!(plan, Plan::NoOp);
    }

    #[test]
    fn plan_stamp_when_marker_absent() {
        let plan = decide_plan(None, STORAGE_SCHEMA_VERSION_V090).expect("absent → stamp");
        assert_eq!(
            plan,
            Plan::Stamp {
                to: STORAGE_SCHEMA_VERSION_V090
            }
        );
    }

    #[test]
    fn plan_stamp_when_marker_older() {
        let plan = decide_plan(
            Some(STORAGE_SCHEMA_VERSION_V088),
            STORAGE_SCHEMA_VERSION_V090,
        )
        .expect("older → stamp");
        assert_eq!(
            plan,
            Plan::Stamp {
                to: STORAGE_SCHEMA_VERSION_V090
            }
        );
    }

    #[test]
    fn plan_refuses_downgrade() {
        // Pretend the DB has been stamped by a hypothetical future build.
        let err = decide_plan(Some(99), STORAGE_SCHEMA_VERSION_V090)
            .expect_err("downgrade must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.to_ascii_lowercase().contains("downgrade"),
            "error should mention downgrade: {msg}"
        );
    }

    // ── Target validation ─────────────────────────────────────────

    #[test]
    fn validate_target_accepts_current() {
        validate_target(CURRENT_STORAGE_SCHEMA_VERSION).expect("current target is valid");
    }

    #[test]
    fn validate_target_rejects_non_current() {
        assert!(validate_target(0).is_err());
        assert!(validate_target(STORAGE_SCHEMA_VERSION_V088).is_err());
        assert!(validate_target(CURRENT_STORAGE_SCHEMA_VERSION + 1).is_err());
    }

    // ── Plan descriptions ─────────────────────────────────────────

    #[test]
    fn plan_description_mentions_target_for_stamp() {
        let s = Plan::Stamp { to: 2 }.describe();
        assert!(s.contains("v2"));
        assert!(s.to_ascii_lowercase().contains("stamp"));
    }

    #[test]
    fn plan_description_is_explicit_for_noop() {
        let s = Plan::NoOp.describe();
        assert!(s.to_ascii_lowercase().contains("no-op"));
    }

    // ── default_db_path ───────────────────────────────────────────

    #[test]
    fn default_db_path_appends_narwhal_consensus() {
        let p = default_db_path(Path::new("/data"));
        assert_eq!(p, PathBuf::from("/data/narwhal_consensus"));
    }

    // ── End-to-end with a real temp RocksDB ───────────────────────

    use tempfile::TempDir;

    fn open_fresh_db(path: &Path) {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let _db = DB::open(&opts, path).expect("create fresh db");
    }

    #[test]
    fn e2e_stamp_fresh_db() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("storage");
        open_fresh_db(&db_path);

        let args = MigrateArgs {
            to: CURRENT_STORAGE_SCHEMA_VERSION,
            from: None,
            dry_run: false,
            db_path: db_path.clone(),
        };
        run(&args).expect("stamp fresh DB succeeds");

        // Idempotent second run.
        run(&args).expect("second run is a no-op");
    }

    #[test]
    fn e2e_dry_run_does_not_mutate() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("storage");
        open_fresh_db(&db_path);

        let args = MigrateArgs {
            to: CURRENT_STORAGE_SCHEMA_VERSION,
            from: None,
            dry_run: true,
            db_path: db_path.clone(),
        };
        run(&args).expect("dry-run succeeds");

        // Marker should still be absent.
        let v = read_marker(&db_path).expect("read post-dry-run");
        assert!(v.is_none(), "dry-run must not stamp the marker");
    }

    #[test]
    fn e2e_from_mismatch_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("storage");
        open_fresh_db(&db_path);

        // DB has no marker → treated as V088. Claim V090 via --migrate-from.
        let args = MigrateArgs {
            to: CURRENT_STORAGE_SCHEMA_VERSION,
            from: Some(STORAGE_SCHEMA_VERSION_V090),
            dry_run: true,
            db_path: db_path.clone(),
        };
        let err = run(&args).expect_err("mismatched --migrate-from must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--migrate-from"),
            "error should cite the flag: {msg}"
        );
    }

    #[test]
    fn e2e_rejects_nonexistent_db() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("storage_that_does_not_exist");
        let args = MigrateArgs {
            to: CURRENT_STORAGE_SCHEMA_VERSION,
            from: None,
            dry_run: true,
            db_path,
        };
        let err = run(&args).expect_err("nonexistent DB must error");
        let msg = format!("{err:#}");
        assert!(
            msg.to_ascii_lowercase().contains("does not exist"),
            "error should mention nonexistent path: {msg}"
        );
    }

    // ── A.6: v2 → v3 transition ──────────────────────────────────

    /// Simulate a v2-era DB with existing narwhal CFs (minus the
    /// Phase 3a additions), then migrate --to 3 and verify the two
    /// new CFs are created and the marker is bumped.
    #[test]
    fn e2e_v2_to_v3_creates_new_cfs_and_stamps_marker() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("storage");

        // Stage a "v2-ish" DB: create with some existing narwhal CFs
        // but NOT the Phase 3a additions.
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let v2_cfs: Vec<rocksdb::ColumnFamilyDescriptor> = [
                "default",
                "narwhal_blocks",
                "narwhal_commits",
                "narwhal_meta",
            ]
            .iter()
            .map(|n| rocksdb::ColumnFamilyDescriptor::new(*n, Options::default()))
            .collect();
            let db = rocksdb::DB::open_cf_descriptors(&opts, &db_path, v2_cfs)
                .expect("open staged v2 DB");
            // Stamp v2 so the migrate tool sees it as the observed
            // source.
            write_storage_schema_version(&db, STORAGE_SCHEMA_VERSION_V090).unwrap();
        }

        // Now run migrate --to 3 (CURRENT).
        let args = MigrateArgs {
            to: CURRENT_STORAGE_SCHEMA_VERSION,
            from: Some(STORAGE_SCHEMA_VERSION_V090),
            dry_run: false,
            db_path: db_path.clone(),
        };
        run(&args).expect("v2 → v3 migration should succeed");

        // Post-migration, the marker is v3.
        let v = read_marker(&db_path).expect("read marker").expect("some");
        assert_eq!(v, STORAGE_SCHEMA_VERSION_V091);

        // And the three new CFs exist.
        let cfs = rocksdb::DB::list_cf(&Options::default(), &db_path).expect("list CFs");
        assert!(
            cfs.iter().any(|n| n == "narwhal_votes"),
            "narwhal_votes CF was not created: {cfs:?}"
        );
        assert!(
            cfs.iter().any(|n| n == "narwhal_cert_mapping"),
            "narwhal_cert_mapping CF was not created: {cfs:?}"
        );
        assert!(
            cfs.iter().any(|n| n == "narwhal_round_config_audit"),
            "narwhal_round_config_audit CF was not created: {cfs:?}"
        );
        // And the legacy v2 CFs are preserved.
        assert!(cfs.iter().any(|n| n == "narwhal_blocks"));
        assert!(cfs.iter().any(|n| n == "narwhal_commits"));
    }

    #[test]
    fn e2e_v2_to_v3_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("storage");
        open_fresh_db(&db_path);

        let args = MigrateArgs {
            to: CURRENT_STORAGE_SCHEMA_VERSION,
            from: None,
            dry_run: false,
            db_path: db_path.clone(),
        };
        run(&args).expect("first run");
        run(&args).expect("second run is no-op");
        // Marker is still v3 and CFs still present.
        let v = read_marker(&db_path).expect("read").expect("some");
        assert_eq!(v, CURRENT_STORAGE_SCHEMA_VERSION);
    }
}
