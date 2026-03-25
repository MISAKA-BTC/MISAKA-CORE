#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

default_extended_harness_dir() {
  mktemp -d "${repo_root}/.tmp/dag-release-gate-extended.XXXXXX"
}

default_extended_target_dir() {
  mktemp -d "${repo_root}/.tmp/dag-release-gate-extended-target.XXXXXX"
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
MISAKA DAG extended release rehearsal

Usage:
  ./scripts/dag_release_gate_extended.sh

Purpose:
  Run the standard release gate with the optional 3-validator durable restart
  stage enabled explicitly.

This wrapper keeps the default release gate unchanged while making the extended
rehearsal path intentional.

The extended path skips the known-fragile 2-validator natural restart prelude
and then runs the optional 3-validator stage with a stable operator profile.
It also relaxes the durable-restart harness wait windows so the rehearsal can
absorb slower local convergence without changing consensus semantics.

Operator profile defaults for the extended rehearsal:
  - unique harness dir under ./.tmp/dag-release-gate-extended.XXXXXX
  - unique cargo target dir under ./.tmp/dag-release-gate-extended-target.XXXXXX
  - checkpoint interval defaults to 12 unless overridden
  - wait attempts default to 360 unless overridden
  - polling defaults to 3s unless overridden
  - dedicated RPC ports 5711 / 5712 / 5713
  - dedicated P2P ports 9212 / 9213 / 9214
EOF
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: ./scripts/dag_release_gate_extended.sh" >&2
  exit 1
fi

echo "[gate] running extended release rehearsal (explicit 3-validator stage)"
extended_harness_dir="${MISAKA_EXTENDED_HARNESS_DIR:-$(default_extended_harness_dir)}"
extended_target_dir="${MISAKA_EXTENDED_CARGO_TARGET_DIR:-$(default_extended_target_dir)}"
exec env \
  MISAKA_RUN_THREE_VALIDATOR_RESTART=1 \
  MISAKA_SKIP_NATURAL_DURABLE_RESTART=1 \
  MISAKA_DAG_CHECKPOINT_INTERVAL="${MISAKA_EXTENDED_DAG_CHECKPOINT_INTERVAL:-12}" \
  MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL="${MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL:-12}" \
  MISAKA_INITIAL_WAIT_ATTEMPTS="${MISAKA_EXTENDED_INITIAL_WAIT_ATTEMPTS:-360}" \
  MISAKA_RESTART_WAIT_ATTEMPTS="${MISAKA_EXTENDED_RESTART_WAIT_ATTEMPTS:-360}" \
  MISAKA_POLL_INTERVAL_SECS="${MISAKA_EXTENDED_POLL_INTERVAL_SECS:-3}" \
  MISAKA_HARNESS_DIR="${extended_harness_dir}" \
  MISAKA_CARGO_TARGET_DIR="${extended_target_dir}" \
  MISAKA_NODE_A_RPC_PORT="${MISAKA_EXTENDED_NODE_A_RPC_PORT:-5711}" \
  MISAKA_NODE_B_RPC_PORT="${MISAKA_EXTENDED_NODE_B_RPC_PORT:-5712}" \
  MISAKA_NODE_C_RPC_PORT="${MISAKA_EXTENDED_NODE_C_RPC_PORT:-5713}" \
  MISAKA_NODE_A_P2P_PORT="${MISAKA_EXTENDED_NODE_A_P2P_PORT:-9212}" \
  MISAKA_NODE_B_P2P_PORT="${MISAKA_EXTENDED_NODE_B_P2P_PORT:-9213}" \
  MISAKA_NODE_C_P2P_PORT="${MISAKA_EXTENDED_NODE_C_P2P_PORT:-9214}" \
  bash scripts/dag_release_gate.sh
