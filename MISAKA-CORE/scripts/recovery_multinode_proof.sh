#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_root="${MISAKA_RECOVERY_HARNESS_DIR:-$repo_root/.tmp/recovery-multinode-proof}"
mkdir -p "$run_root"

summary_file="$run_root/summary.txt"
current_step="preflight"

write_summary_line() {
  printf '%s\n' "$1" >>"$summary_file"
}

fail() {
  local message="$1"
  echo "$message" >&2
  write_summary_line "result=failed"
  write_summary_line "failed_step=${current_step}"
  write_summary_line "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  exit 1
}

{
  echo "repo_root=$repo_root"
  echo "run_root=$run_root"
  echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} >"$summary_file"

trap 'status=$?; write_summary_line "result=failed"; write_summary_line "failed_step=${current_step}"; write_summary_line "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; exit $status' ERR

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required to run the multi-node recovery proof"
fi

if ! command -v clang >/dev/null 2>&1; then
  fail "clang is required to run the multi-node recovery proof"
fi

if ! printf '%s\n' '#include <stdbool.h>' 'int main(void) { return 0; }' | clang -x c -fsyntax-only - >/dev/null 2>&1; then
  fail "native C headers for librocksdb-sys are required before running the multi-node recovery proof. hint: install clang, libclang-dev, build-essential, cmake, and pkg-config in the execution environment"
fi

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
  write_summary_line "step=${slug}:passed"
}

run_step "single-node restart proof prerequisite" "restart_proof" \
  ./scripts/recovery_restart_proof.sh

run_step "multi-node convergence proof: same-order delivery stays deterministic" \
  "same_order_convergence" \
  cargo test -p misaka-dag --test multi_node_chaos test_same_order_convergence -- --exact

run_step "multi-node convergence proof: random-order delivery converges" \
  "random_order_convergence" \
  cargo test -p misaka-dag --test multi_node_chaos test_random_order_convergence -- --exact

run_step "multi-node crash recovery proof: mid-sync restart catches back up" \
  "crash_and_catchup" \
  cargo test -p misaka-dag --test multi_node_chaos test_crash_and_catchup -- --exact

run_step "multi-node wide-DAG proof: concurrent proposers converge after restart" \
  "wide_dag_convergence" \
  cargo test -p misaka-dag --test multi_node_chaos test_wide_dag_convergence -- --exact

{
  echo "result=passed"
  echo "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} >>"$summary_file"

echo "[recovery] multi-node recovery proof passed"
