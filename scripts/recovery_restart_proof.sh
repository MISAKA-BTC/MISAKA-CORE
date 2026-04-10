#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_root="${MISAKA_RECOVERY_RESTART_DIR:-$repo_root/.tmp/recovery-restart-proof}"
logs_dir="$run_root/logs"
summary_file="$run_root/summary.txt"
result_file="$run_root/result.json"
steps_file="$run_root/steps.txt"
current_step="preflight"

mkdir -p "$run_root" "$logs_dir"
: >"$steps_file"
{
  echo "repo_root=$repo_root"
  echo "run_root=$run_root"
  echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} >"$summary_file"

write_summary_line() {
  printf '%s\n' "$1" >>"$summary_file"
}

write_result_json() {
  local status="$1"
  local failure_step="${2:-}"
  local failure_reason="${3:-}"

  python3 - "$steps_file" "$result_file" "$summary_file" "$logs_dir" "$status" "$failure_step" "$failure_reason" <<'PY'
import json
import pathlib
import sys

steps_file, result_file, summary_file, logs_dir, status, failure_step, failure_reason = sys.argv[1:8]
steps = []
steps_path = pathlib.Path(steps_file)
if steps_path.exists():
    for raw in steps_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw:
            steps.append({"slug": raw, "status": "passed", "log": str(pathlib.Path(logs_dir) / f"{raw}.log")})

payload = {
    "status": status,
    "failure": {
        "step": failure_step or None,
        "reason": failure_reason or None,
    },
    "steps": steps,
    "artifacts": {
        "summary": summary_file,
        "logsDir": logs_dir,
    },
}
pathlib.Path(result_file).write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
PY
}

fail() {
  local message="$1"
  trap - ERR
  set +e
  echo "$message" >&2
  write_summary_line "result=failed"
  write_summary_line "failed_step=${current_step}"
  write_summary_line "failure_reason=${message}"
  write_summary_line "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  write_result_json "failed" "$current_step" "$message"
  exit 1
}

trap 'fail "command failed: ${BASH_COMMAND}"' ERR

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required to run the recovery restart proof"
fi

has_native_c_toolchain() {
  command -v clang >/dev/null 2>&1 &&
    printf '#include <stdbool.h>\nint main(void){return 0;}\n' | clang -x c -fsyntax-only - >/dev/null 2>&1
}

run_cargo_step() {
  if has_native_c_toolchain; then
    "$@"
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    fail "native C toolchain or docker is required to run the recovery restart proof"
  fi

  local cargo_home="${CARGO_HOME:-${HOME:-}/.cargo}"
  local docker_args=(
    --rm
    -v "$repo_root:/work"
    -w /work
  )
  if [[ -d "$cargo_home/registry" ]]; then
    docker_args+=(-v "$cargo_home/registry:/usr/local/cargo/registry")
  fi
  if [[ -d "$cargo_home/git" ]]; then
    docker_args+=(-v "$cargo_home/git:/usr/local/cargo/git")
  fi

  local shell_cmd
  shell_cmd="$(printf '%q ' "$@")"
  docker run \
    "${docker_args[@]}" \
    rust:1.89-bookworm \
    bash -lc "set -euo pipefail; \
      export PATH=/usr/local/cargo/bin:\$PATH; \
      apt-get update -qq >/dev/null && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libclang-dev build-essential cmake pkg-config >/dev/null && \
      export CARGO_TARGET_DIR=/work/target && \
      export BINDGEN_EXTRA_CLANG_ARGS=\"-isystem \$(gcc -print-file-name=include)\" && \
      ${shell_cmd}"
}

run_step() {
  local label="$1"
  local slug="$2"
  shift 2
  local log_file="$logs_dir/${slug}.log"
  current_step="$slug"
  echo "[recovery] ${label}"
  {
    echo "== ${label} =="
    echo "cmd: $*"
    echo
    "$@"
  } | tee "$log_file"
  printf '%s\n' "$slug" >>"$steps_file"
  write_summary_line "step=${slug}:passed"
}

run_step "WAL restart proof: reopen survives committed+incomplete state" \
  "wal_reopen" \
  run_cargo_step cargo test -p misaka-storage wal::tests::test_wal_survives_reopen -- --exact

run_step "WAL compaction trigger proof: threshold and size guards" \
  "wal_compact_trigger" \
  run_cargo_step cargo test -p misaka-storage wal::tests::test_wal_compact_trigger_conditions -- --exact

run_step "DAG recovery status proof: recovery summary is preserved" \
  "dag_recovery_status" \
  run_cargo_step cargo test -p misaka-storage dag_recovery::tests::test_recover_wal_status_reports_entries -- --exact

run_step "cleanup proof: restart artifacts are cleared" \
  "cleanup_after_recovery" \
  run_cargo_step cargo test -p misaka-storage dag_recovery::tests::test_compact_wal_after_recovery_clears_artifacts -- --exact

run_step "DAG snapshot restart proof: virtual state restores identically" \
  "dag_snapshot_restore_identity" \
  run_cargo_step cargo test -p misaka-dag --test stress_tests test_virtual_state_snapshot_restore_identity -- --exact

write_summary_line "result=passed"
write_summary_line "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
write_result_json "passed"
echo "[recovery] restart proof passed"
echo "[recovery] artifacts: $result_file"
