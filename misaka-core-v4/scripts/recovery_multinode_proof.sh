#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_root="${MISAKA_RECOVERY_HARNESS_DIR:-$repo_root/.tmp/recovery-multinode-proof}"
mkdir -p "$run_root"

summary_file="$run_root/summary.txt"
result_file="$run_root/result.json"
steps_file="$run_root/steps.txt"
current_step="preflight"
: >"$steps_file"

write_summary_line() {
  printf '%s\n' "$1" >>"$summary_file"
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

{
  echo "repo_root=$repo_root"
  echo "run_root=$run_root"
  echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} >"$summary_file"

write_result_json() {
  local status="$1"
  local failure_step="${2:-}"
  local failure_reason="${3:-}"

  python3 - "$steps_file" "$result_file" "$summary_file" "$run_root" "$status" "$failure_step" "$failure_reason" <<'PY'
import json
import pathlib
import sys

steps_file, result_file, summary_file, run_root, status, failure_step, failure_reason = sys.argv[1:8]
steps = []
steps_path = pathlib.Path(steps_file)
if steps_path.exists():
    for raw in steps_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw:
            steps.append({
                "slug": raw,
                "status": "passed",
                "log": str(pathlib.Path(run_root) / f"{raw}.log"),
            })

payload = {
    "status": status,
    "failure": {
        "step": failure_step or None,
        "reason": failure_reason or None,
    },
    "steps": steps,
    "artifacts": {
        "summary": summary_file,
        "runRoot": run_root,
    },
}
pathlib.Path(result_file).write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
PY
}

trap 'fail "command failed: ${BASH_COMMAND}"' ERR

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required to run the multi-node recovery proof"
fi

has_native_c_toolchain() {
  command -v clang >/dev/null 2>&1 &&
    printf '%s\n' '#include <stdbool.h>' 'int main(void) { return 0; }' | clang -x c -fsyntax-only - >/dev/null 2>&1
}

run_cargo_step() {
  if has_native_c_toolchain; then
    "$@"
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    fail "native C toolchain or docker is required to run the multi-node recovery proof"
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

{
  echo "cargo_version=$(cargo --version)"
  if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "git_head=$(git -C "$repo_root" rev-parse --short HEAD)"
  fi
} >>"$summary_file"

run_step() {
  local label="$1"
  shift
  local slug="$1"
  shift
  local log_file="$run_root/${slug}.log"
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

run_step "single-node restart proof prerequisite" "restart_proof" \
  bash ./scripts/recovery_restart_proof.sh

run_step "multi-node convergence proof: same-order delivery stays deterministic" \
  "same_order_convergence" \
  run_cargo_step cargo test -p misaka-dag --test multi_node_chaos tests::test_same_order_convergence -- --exact

run_step "multi-node convergence proof: random-order delivery converges" \
  "random_order_convergence" \
  run_cargo_step cargo test -p misaka-dag --test multi_node_chaos tests::test_random_order_convergence -- --exact

run_step "multi-node crash recovery proof: mid-sync restart catches back up" \
  "crash_and_catchup" \
  run_cargo_step cargo test -p misaka-dag --test multi_node_chaos tests::test_crash_and_catchup -- --exact

run_step "multi-node wide-DAG proof: concurrent proposers converge after restart" \
  "wide_dag_convergence" \
  run_cargo_step cargo test -p misaka-dag --test multi_node_chaos tests::test_wide_dag_convergence -- --exact

{
  echo "result=passed"
  echo "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} >>"$summary_file"
write_result_json "passed"

echo "[recovery] multi-node recovery proof passed"
echo "[recovery] artifacts: $result_file"
