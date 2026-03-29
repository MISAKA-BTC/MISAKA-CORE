#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to run the recovery restart proof" >&2
  exit 1
fi

echo "[recovery] WAL restart proof: reopen survives committed+incomplete state"
cargo test -p misaka-storage wal::tests::test_wal_survives_reopen -- --exact

echo "[recovery] WAL compaction trigger proof: threshold and size guards"
cargo test -p misaka-storage wal::tests::test_wal_compact_trigger_conditions -- --exact

echo "[recovery] DAG recovery status proof: recovery summary is preserved"
cargo test -p misaka-storage dag_recovery::tests::test_recover_wal_status_reports_entries -- --exact

echo "[recovery] cleanup proof: restart artifacts are cleared"
cargo test -p misaka-storage dag_recovery::tests::test_compact_wal_after_recovery_clears_artifacts -- --exact

echo "[recovery] DAG snapshot restart proof: virtual state restores identically"
cargo test -p misaka-dag --test stress_tests test_virtual_state_snapshot_restore_identity -- --exact

echo "[recovery] restart proof passed"
