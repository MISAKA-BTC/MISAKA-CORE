#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SOAK_PROFILE="${MISAKA_SOAK_PROFILE:-default}"
if [[ "${1:-}" == "extended" ]]; then
  SOAK_PROFILE="extended"
  shift
fi

STATE_DIR="${MISAKA_HARNESS_DIR:-${ROOT_DIR}/.tmp/dag-soak-harness}"
RESULT_FILE="${STATE_DIR}/result.json"
DEFAULT_ITERATIONS=2
DEFAULT_RUN_THREE_VALIDATOR=1
DEFAULT_RUN_ROLLING_RESTART=0
DEFAULT_ROLLING_RESTART_CYCLES=1

case "$SOAK_PROFILE" in
  default)
    ;;
  extended)
    DEFAULT_ITERATIONS=3
    DEFAULT_RUN_THREE_VALIDATOR=1
    DEFAULT_RUN_ROLLING_RESTART=1
    DEFAULT_ROLLING_RESTART_CYCLES=2
    ;;
  *)
    echo "unknown soak profile: $SOAK_PROFILE (expected default or extended)" >&2
    exit 1
    ;;
esac

ITERATIONS="${MISAKA_SOAK_ITERATIONS:-$DEFAULT_ITERATIONS}"
RUN_THREE_VALIDATOR="${MISAKA_SOAK_RUN_THREE_VALIDATOR:-$DEFAULT_RUN_THREE_VALIDATOR}"
RUN_ROLLING_RESTART="${MISAKA_SOAK_RUN_ROLLING_RESTART:-$DEFAULT_RUN_ROLLING_RESTART}"
BASE_RPC_PORT="${MISAKA_SOAK_BASE_RPC_PORT:-5011}"
BASE_P2P_PORT="${MISAKA_SOAK_BASE_P2P_PORT:-8512}"
THREE_VALIDATOR_CHECKPOINT_INTERVAL="${MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL:-12}"
ROLLING_RESTART_CYCLES="${MISAKA_ROLLING_RESTART_CYCLES:-$DEFAULT_ROLLING_RESTART_CYCLES}"

mkdir -p "$STATE_DIR"

usage() {
  cat <<'EOF'
MISAKA DAG soak harness

Usage:
  ./scripts/dag_soak_harness.sh
  ./scripts/dag_soak_harness.sh extended
  ./scripts/dag_soak_harness.sh status
  ./scripts/dag_soak_harness.sh --help

Purpose:
  Re-run the existing durable restart harnesses multiple times and capture a
  compact operator-facing soak summary. The default path stays at the current
  smoke-sized baseline; `extended` enables the longer rolling-restart profile.

Optional env:
  MISAKA_BIN=/path/to/misaka-node
  MISAKA_SKIP_BUILD=1
  MISAKA_HARNESS_DIR=/custom/writable/path
  MISAKA_SOAK_PROFILE=default|extended
  MISAKA_SOAK_ITERATIONS=2
  MISAKA_SOAK_RUN_THREE_VALIDATOR=1
  MISAKA_SOAK_RUN_ROLLING_RESTART=0
  MISAKA_SOAK_BASE_RPC_PORT=5011
  MISAKA_SOAK_BASE_P2P_PORT=8512
  MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL=12
  MISAKA_ROLLING_RESTART_CYCLES=${MISAKA_ROLLING_RESTART_CYCLES:-1}
EOF
}

show_status() {
  if [[ -f "$RESULT_FILE" ]]; then
    cat "$RESULT_FILE"
    echo
    return 0
  fi
  echo "result file not found: $RESULT_FILE" >&2
  exit 1
}

if [[ "${1:-}" == "status" ]]; then
  show_status
  exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command missing: $cmd" >&2
    exit 1
  fi
}

require_cmd python3

BIN="${MISAKA_BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x "${ROOT_DIR}/.tmp/user-target/debug/misaka-node" ]]; then
    BIN="${ROOT_DIR}/.tmp/user-target/debug/misaka-node"
  elif [[ -x "${ROOT_DIR}/target/debug/misaka-node" ]]; then
    BIN="${ROOT_DIR}/target/debug/misaka-node"
  elif [[ -x "${ROOT_DIR}/target/release/misaka-node" ]]; then
    BIN="${ROOT_DIR}/target/release/misaka-node"
  else
    echo "misaka-node binary not found. Set MISAKA_BIN or build first." >&2
    exit 1
  fi
fi

tmp_results="${STATE_DIR}/iterations.jsonl"
rm -f "$tmp_results"

for i in $(seq 1 "$ITERATIONS"); do
  two_rpc_a=$((BASE_RPC_PORT + ((i - 1) * 10)))
  two_rpc_b=$((two_rpc_a + 1))
  two_p2p_a=$((BASE_P2P_PORT + ((i - 1) * 10)))
  two_p2p_b=$((two_p2p_a + 1))
  two_dir="${STATE_DIR}/iter-${i}-two"

  MISAKA_BIN="$BIN" \
  MISAKA_SKIP_BUILD=1 \
  MISAKA_HARNESS_DIR="$two_dir" \
  MISAKA_NODE_A_RPC_PORT="$two_rpc_a" \
  MISAKA_NODE_B_RPC_PORT="$two_rpc_b" \
  MISAKA_NODE_A_P2P_PORT="$two_p2p_a" \
  MISAKA_NODE_B_P2P_PORT="$two_p2p_b" \
    bash "${ROOT_DIR}/scripts/dag_natural_restart_harness.sh" >/dev/null

  python3 - "$two_dir/result.json" "$i" <<'PY' >>"$tmp_results"
import json
import sys

path = sys.argv[1]
iteration = int(sys.argv[2])
with open(path, "r", encoding="utf-8") as f:
    d = json.load(f)
print(json.dumps({
    "iteration": iteration,
    "scenario": "two-validator-durable-restart",
    "preRestartConverged": d["durableRestart"]["preRestartConverged"],
    "postRestartConverged": d["durableRestart"]["postRestartConverged"],
    "restartReady": d["durableRestart"]["nodeARestartReady"],
    "lifecycleSummary": d["durableRestart"]["nodeALifecycleSummary"],
    "resultFile": path,
}))
PY

  MISAKA_HARNESS_DIR="$two_dir" bash "${ROOT_DIR}/scripts/dag_natural_restart_harness.sh" stop >/dev/null || true

  if [[ "$RUN_THREE_VALIDATOR" == "1" ]]; then
    three_rpc_a=$((BASE_RPC_PORT + 100 + ((i - 1) * 20)))
    three_rpc_b=$((three_rpc_a + 1))
    three_rpc_c=$((three_rpc_a + 2))
    three_p2p_a=$((BASE_P2P_PORT + 100 + ((i - 1) * 20)))
    three_p2p_b=$((three_p2p_a + 1))
    three_p2p_c=$((three_p2p_a + 2))
    three_dir="${STATE_DIR}/iter-${i}-three"

    MISAKA_BIN="$BIN" \
    MISAKA_SKIP_BUILD=1 \
    MISAKA_HARNESS_DIR="$three_dir" \
    MISAKA_DAG_CHECKPOINT_INTERVAL="$THREE_VALIDATOR_CHECKPOINT_INTERVAL" \
    MISAKA_NODE_A_RPC_PORT="$three_rpc_a" \
    MISAKA_NODE_B_RPC_PORT="$three_rpc_b" \
    MISAKA_NODE_C_RPC_PORT="$three_rpc_c" \
    MISAKA_NODE_A_P2P_PORT="$three_p2p_a" \
    MISAKA_NODE_B_P2P_PORT="$three_p2p_b" \
    MISAKA_NODE_C_P2P_PORT="$three_p2p_c" \
      bash "${ROOT_DIR}/scripts/dag_three_validator_recovery_harness.sh" >/dev/null

    python3 - "$three_dir/result.json" "$i" <<'PY' >>"$tmp_results"
import json
import sys

path = sys.argv[1]
iteration = int(sys.argv[2])
with open(path, "r", encoding="utf-8") as f:
    d = json.load(f)
print(json.dumps({
    "iteration": iteration,
    "scenario": "three-validator-durable-restart",
    "preRestartConverged": d["durableRestart"]["preRestartConverged"],
    "postRestartConverged": d["durableRestart"]["postRestartConverged"],
    "allRestartReady": d["durableRestart"]["allRestartReady"],
    "resultFile": path,
}))
PY

    MISAKA_HARNESS_DIR="$three_dir" bash "${ROOT_DIR}/scripts/dag_three_validator_recovery_harness.sh" stop >/dev/null || true
  fi

  if [[ "$RUN_ROLLING_RESTART" == "1" ]]; then
    rolling_rpc_a=$((BASE_RPC_PORT + 200 + ((i - 1) * 20)))
    rolling_rpc_b=$((rolling_rpc_a + 1))
    rolling_rpc_c=$((rolling_rpc_a + 2))
    rolling_p2p_a=$((BASE_P2P_PORT + 200 + ((i - 1) * 20)))
    rolling_p2p_b=$((rolling_p2p_a + 1))
    rolling_p2p_c=$((rolling_p2p_a + 2))
    rolling_dir="${STATE_DIR}/iter-${i}-rolling"

    MISAKA_BIN="$BIN" \
    MISAKA_SKIP_BUILD=1 \
    MISAKA_HARNESS_DIR="$rolling_dir" \
    MISAKA_DAG_CHECKPOINT_INTERVAL="$THREE_VALIDATOR_CHECKPOINT_INTERVAL" \
    MISAKA_NODE_A_RPC_PORT="$rolling_rpc_a" \
    MISAKA_NODE_B_RPC_PORT="$rolling_rpc_b" \
    MISAKA_NODE_C_RPC_PORT="$rolling_rpc_c" \
    MISAKA_NODE_A_P2P_PORT="$rolling_p2p_a" \
    MISAKA_NODE_B_P2P_PORT="$rolling_p2p_b" \
    MISAKA_NODE_C_P2P_PORT="$rolling_p2p_c" \
    MISAKA_ROLLING_RESTART_CYCLES="$ROLLING_RESTART_CYCLES" \
      bash "${ROOT_DIR}/scripts/dag_rolling_restart_soak_harness.sh" >/dev/null

    python3 - "$rolling_dir/result.json" "$i" <<'PY' >>"$tmp_results"
import json
import sys

path = sys.argv[1]
iteration = int(sys.argv[2])
with open(path, "r", encoding="utf-8") as f:
    d = json.load(f)
final_entry = d["cycleEntries"][-1] if d.get("cycleEntries") else {}
print(json.dumps({
    "iteration": iteration,
    "scenario": "three-validator-rolling-restart",
    "rollingRestartCycles": d.get("rollingRestartCycles", 0),
    "allCyclesPassed": d.get("allCyclesPassed", False),
    "finalSameValidatorTarget": final_entry.get("sameValidatorTarget", False),
    "resultFile": path,
}))
PY

    MISAKA_HARNESS_DIR="$rolling_dir" bash "${ROOT_DIR}/scripts/dag_rolling_restart_soak_harness.sh" stop >/dev/null || true
  fi
done

python3 - "$tmp_results" "$RESULT_FILE" "$ITERATIONS" "$RUN_THREE_VALIDATOR" "$RUN_ROLLING_RESTART" "$SOAK_PROFILE" <<'PY'
import json
import sys
from datetime import datetime, timezone

source_path, result_path, iterations, run_three, run_rolling, profile = sys.argv[1:7]
entries = []
with open(source_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            entries.append(json.loads(line))

summary = {
    "capturedAt": datetime.now(timezone.utc).isoformat(),
    "soakProfile": profile,
    "iterations": int(iterations),
    "runThreeValidator": run_three == "1",
    "runRollingRestart": run_rolling == "1",
    "entries": entries,
}

def ok(entry):
    if entry["scenario"] == "two-validator-durable-restart":
        return (
            entry["preRestartConverged"]
            and entry["postRestartConverged"]
            and entry["restartReady"]
            and entry["lifecycleSummary"] == "ready"
        )
    if entry["scenario"] == "three-validator-rolling-restart":
        return (
            entry["rollingRestartCycles"] >= 1
            and entry["allCyclesPassed"]
            and entry["finalSameValidatorTarget"]
        )
    if entry["scenario"] == "three-validator-durable-restart":
        return (
            entry["preRestartConverged"]
            and entry["postRestartConverged"]
            and entry["allRestartReady"]
        )
    return False

summary["allPassed"] = all(ok(entry) for entry in entries)
summary["passedEntries"] = sum(1 for entry in entries if ok(entry))
summary["entryCount"] = len(entries)

with open(result_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")
PY

cat "$RESULT_FILE"
