#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to run the release gate" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to validate the node compose surface" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin is required to validate the node compose surface" >&2
  exit 1
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

  local docker_env_args=()
  local forward_var
  for forward_var in \
    MISAKA_HARNESS_DIR \
    MISAKA_CARGO_TARGET_DIR \
    MISAKA_INITIAL_WAIT_ATTEMPTS \
    MISAKA_RESTART_WAIT_ATTEMPTS \
    MISAKA_POLL_INTERVAL_SECS \
    MISAKA_DAG_CHECKPOINT_INTERVAL \
    MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL \
    MISAKA_NODE_A_RPC_PORT \
    MISAKA_NODE_B_RPC_PORT \
    MISAKA_NODE_C_RPC_PORT \
    MISAKA_NODE_A_P2P_PORT \
    MISAKA_NODE_B_P2P_PORT \
    MISAKA_NODE_C_P2P_PORT
  do
    if [[ -n "${!forward_var:-}" ]]; then
      docker_env_args+=(-e "${forward_var}=${!forward_var}")
    fi
  done

  local shell_cmd
  shell_cmd="$(printf '%q ' "$@")"
  docker run --rm \
    -v "$repo_root:/work" \
    -w /work \
    "${docker_env_args[@]}" \
    rust:1.89-bookworm \
    bash -lc "set -euo pipefail; \
      export PATH=/usr/local/cargo/bin:\$PATH; \
      apt-get update -qq >/dev/null && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libclang-dev build-essential cmake pkg-config >/dev/null && \
      export CARGO_TARGET_DIR=/work/target && \
      export BINDGEN_EXTRA_CLANG_ARGS=\"-isystem \$(gcc -print-file-name=include)\" && \
      ${shell_cmd}"
}

run_harness_step() {
  "$@"
}

tmp_env="$(mktemp "${TMPDIR:-/tmp}/misaka-node-env.XXXXXX")"
trap 'rm -f "$tmp_env"' EXIT
cp scripts/node.env.example "$tmp_env"

echo "[gate] validating operator shell surfaces"
bash -n scripts/node-bootstrap.sh
bash -n scripts/recovery_restart_proof.sh
bash -n scripts/recovery_multinode_proof.sh
bash -n scripts/dag_natural_restart_harness.sh
bash -n scripts/dag_three_validator_recovery_harness.sh
bash -n scripts/dag_release_gate_extended.sh
sh -n docker/node-entrypoint.sh

echo "[gate] rehearsing node bootstrap config"
MISAKA_NODE_ENV_FILE="$tmp_env" scripts/node-bootstrap.sh config >/dev/null

echo "[gate] running restart proof"
run_cargo_step bash scripts/recovery_restart_proof.sh

echo "[gate] running multi-node recovery proof"
run_cargo_step bash scripts/recovery_multinode_proof.sh

echo "[gate] building release node binary for natural restart harness"
run_cargo_step cargo build -p misaka-node --release --locked

if [ "${MISAKA_SKIP_NATURAL_DURABLE_RESTART:-0}" = "1" ]; then
  echo "[gate] skipping natural durable restart harness (explicit extended rehearsal path)"
else
  echo "[gate] running natural durable restart harness"
  run_harness_step env \
    MISAKA_SKIP_BUILD=1 \
    MISAKA_BIN=target/release/misaka-node \
    MISAKA_DAG_CHECKPOINT_INTERVAL="${MISAKA_DAG_CHECKPOINT_INTERVAL:-6}" \
    MISAKA_INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-90}" \
    MISAKA_RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-90}" \
    bash scripts/dag_natural_restart_harness.sh
fi

if [ "${MISAKA_RUN_THREE_VALIDATOR_RESTART:-0}" = "1" ]; then
  echo "[gate] running 3-validator durable restart harness"
  run_harness_step env \
    MISAKA_SKIP_BUILD=1 \
    MISAKA_BIN=target/release/misaka-node \
    MISAKA_DAG_CHECKPOINT_INTERVAL="${MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL:-12}" \
    MISAKA_INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-140}" \
    MISAKA_RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-140}" \
    bash scripts/dag_three_validator_recovery_harness.sh
fi

echo "[gate] validating node docker compose config"
docker compose --env-file scripts/node.env.example -f docker/node-compose.yml config >/dev/null

echo "[gate] building release binaries"
run_cargo_step cargo build --manifest-path relayer/Cargo.toml --release --locked

echo "[gate] release gate passed"
