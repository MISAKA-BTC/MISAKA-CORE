#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STATE_DIR="${MISAKA_HARNESS_DIR:-${ROOT_DIR}/.tmp/dag-rolling-restart-soak-harness}"
NODE_A_DIR="${STATE_DIR}/node-a"
NODE_B_DIR="${STATE_DIR}/node-b"
NODE_C_DIR="${STATE_DIR}/node-c"
LOG_DIR="${STATE_DIR}/logs"
PID_FILE="${STATE_DIR}/pids"
RESULT_FILE="${STATE_DIR}/result.json"
TARGET_DIR="${MISAKA_CARGO_TARGET_DIR:-${ROOT_DIR}/.tmp/dag-rolling-restart-target}"

NODE_A_RPC="${MISAKA_NODE_A_RPC_PORT:-5211}"
NODE_B_RPC="${MISAKA_NODE_B_RPC_PORT:-5212}"
NODE_C_RPC="${MISAKA_NODE_C_RPC_PORT:-5213}"
NODE_A_P2P="${MISAKA_NODE_A_P2P_PORT:-8712}"
NODE_B_P2P="${MISAKA_NODE_B_P2P_PORT:-8713}"
NODE_C_P2P="${MISAKA_NODE_C_P2P_PORT:-8714}"
BLOCK_TIME_SECS="${MISAKA_BLOCK_TIME_SECS:-5}"
CHECKPOINT_INTERVAL="${MISAKA_DAG_CHECKPOINT_INTERVAL:-12}"
INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-140}"
RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-120}"
POLL_INTERVAL_SECS="${MISAKA_POLL_INTERVAL_SECS:-2}"
ROLLING_RESTART_CYCLES="${MISAKA_ROLLING_RESTART_CYCLES:-1}"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$TARGET_DIR"

usage() {
  cat <<'EOF'
MISAKA DAG rolling restart soak harness

Usage:
  ./scripts/dag_rolling_restart_soak_harness.sh
  ./scripts/dag_rolling_restart_soak_harness.sh status
  ./scripts/dag_rolling_restart_soak_harness.sh stop
  ./scripts/dag_rolling_restart_soak_harness.sh --help

Purpose:
  Start a natural 3-validator DAG network, wait for convergence, then restart
  validators one by one and verify that quorum/finality re-form after each
  rolling restart step.

Optional env:
  MISAKA_BIN=/path/to/misaka-node
  MISAKA_SKIP_BUILD=1
  MISAKA_HARNESS_DIR=/custom/writable/path
  MISAKA_CARGO_TARGET_DIR=/custom/target/dir
  MISAKA_NODE_A_RPC_PORT=5211
  MISAKA_NODE_B_RPC_PORT=5212
  MISAKA_NODE_C_RPC_PORT=5213
  MISAKA_NODE_A_P2P_PORT=8712
  MISAKA_NODE_B_P2P_PORT=8713
  MISAKA_NODE_C_P2P_PORT=8714
  MISAKA_BLOCK_TIME_SECS=5
  MISAKA_DAG_CHECKPOINT_INTERVAL=12
  MISAKA_INITIAL_WAIT_ATTEMPTS=140
  MISAKA_RESTART_WAIT_ATTEMPTS=120
  MISAKA_POLL_INTERVAL_SECS=2
  MISAKA_ROLLING_RESTART_CYCLES=1
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command missing: $cmd" >&2
    exit 1
  fi
}

has_native_c_toolchain() {
  command -v cargo >/dev/null 2>&1 &&
    command -v clang >/dev/null 2>&1 &&
    printf '#include <stdbool.h>\nint main(void){return 0;}\n' | clang -x c -fsyntax-only - >/dev/null 2>&1
}

docker_build_node() {
  require_cmd docker
  docker run --rm \
    -v "$ROOT_DIR:/work" \
    -w /work \
    rust:1.89-bookworm \
    bash -lc "set -euo pipefail; \
      export PATH=/usr/local/cargo/bin:\$PATH; \
      apt-get update -qq >/dev/null && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libclang-dev build-essential cmake pkg-config >/dev/null && \
      export CARGO_TARGET_DIR='${TARGET_DIR}'; \
      export BINDGEN_EXTRA_CLANG_ARGS=\"-isystem \$(gcc -print-file-name=include)\"; \
      cargo build -p misaka-node --features qdag_ct --quiet"
}

resolve_binary() {
  if [[ -n "${MISAKA_BIN:-}" ]]; then
    echo "${MISAKA_BIN}"
    return 0
  fi

  if [[ "${MISAKA_SKIP_BUILD:-0}" != "1" ]]; then
    if has_native_c_toolchain; then
      CARGO_TARGET_DIR="$TARGET_DIR" cargo build -p misaka-node --features qdag_ct --quiet
    else
      docker_build_node
    fi
  fi

  if [[ -x "${TARGET_DIR}/debug/misaka-node" ]]; then
    echo "${TARGET_DIR}/debug/misaka-node"
    return 0
  fi
  if [[ -x "${ROOT_DIR}/.tmp/user-target/debug/misaka-node" ]]; then
    echo "${ROOT_DIR}/.tmp/user-target/debug/misaka-node"
    return 0
  fi
  if [[ -x "${ROOT_DIR}/target/debug/misaka-node" ]]; then
    echo "${ROOT_DIR}/target/debug/misaka-node"
    return 0
  fi
  if [[ -x "${ROOT_DIR}/target/release/misaka-node" ]]; then
    echo "${ROOT_DIR}/target/release/misaka-node"
    return 0
  fi

  echo "misaka-node binary not found. Set MISAKA_BIN or build first." >&2
  exit 1
}

stop_harness() {
  if [[ -f "$PID_FILE" ]]; then
    tac "$PID_FILE" 2>/dev/null | while read -r pid; do
      [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    rm -f "$PID_FILE"
    echo "DAG rolling restart soak harness stopped."
  else
    echo "No DAG rolling restart soak harness is running."
  fi
}

wait_for_chain_info() {
  local port="$1"
  local attempts="${2:-30}"
  local i
  for i in $(seq 1 "$attempts"); do
    if curl -fsS -X POST "http://127.0.0.1:${port}/api/get_chain_info" \
      -H 'content-type: application/json' \
      -d '{}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

fetch_chain_info_file() {
  local port="$1"
  local out_file="$2"
  curl -fsS -X POST "http://127.0.0.1:${port}/api/get_chain_info" \
    -H 'content-type: application/json' \
    -d '{}' >"$out_file"
}

check_cluster_convergence_snapshot() {
  local node_a_json="$1"
  local node_b_json="$2"
  local node_c_json="$3"
  local require_all_restored="${4:-0}"

  python3 - "$node_a_json" "$node_b_json" "$node_c_json" "$require_all_restored" <<'PY'
import json
import sys

paths = sys.argv[1:4]
require_all_restored = int(sys.argv[4])
nodes = []
for path in paths:
    with open(path, "r", encoding="utf-8") as f:
        nodes.append(json.load(f))

def checkpoint_target(body):
    cp = body.get("latestCheckpoint")
    if not cp:
        return None
    return cp.get("validatorTarget") or {
        "blockHash": cp.get("blockHash"),
        "blueScore": cp.get("blueScore"),
        "totalAppliedTxs": cp.get("totalAppliedTxs"),
        "totalKeyImages": cp.get("totalKeyImages"),
        "utxoRoot": cp.get("utxoRoot"),
    }

def votes(body):
    return body.get("validatorAttestation", {}).get("currentCheckpointVotes")

def vote_quorum_met(body):
    v = votes(body)
    if not v:
        return False
    try:
        return int(v.get("voteCount", 0)) >= int(v.get("quorumThreshold", 0)) > 0
    except (TypeError, ValueError):
        return False

def finalized(body):
    return bool(
        body.get("validatorAttestation", {})
        .get("currentCheckpointStatus", {})
        .get("currentCheckpointFinalized", False)
    )

targets = [checkpoint_target(body) for body in nodes]
same_target = all(t is not None for t in targets) and len({json.dumps(t, sort_keys=True) for t in targets}) == 1
all_quorum = all(vote_quorum_met(body) for body in nodes)
all_finalized = all(finalized(body) for body in nodes)

if not (same_target and all_quorum and all_finalized):
    raise SystemExit(1)

if require_all_restored:
    for body in nodes:
        recovery = body.get("runtimeRecovery", {})
        lifecycle = body.get("validatorLifecycleRecovery", {})
        if not recovery.get("startupSnapshotRestored", False):
            raise SystemExit(1)
        if not recovery.get("operatorRestartReady", False):
            raise SystemExit(1)
        if lifecycle.get("summary") != "ready":
            raise SystemExit(1)

raise SystemExit(0)
PY
}

wait_for_cluster_convergence() {
  local phase="$1"
  local attempts="$2"
  local require_all_restored="${3:-0}"
  local node_a_json="${STATE_DIR}/node-a-${phase}.json"
  local node_b_json="${STATE_DIR}/node-b-${phase}.json"
  local node_c_json="${STATE_DIR}/node-c-${phase}.json"
  local i

  for i in $(seq 1 "$attempts"); do
    if ! fetch_chain_info_file "$NODE_A_RPC" "$node_a_json" 2>/dev/null; then
      sleep "$POLL_INTERVAL_SECS"
      continue
    fi
    if ! fetch_chain_info_file "$NODE_B_RPC" "$node_b_json" 2>/dev/null; then
      sleep "$POLL_INTERVAL_SECS"
      continue
    fi
    if ! fetch_chain_info_file "$NODE_C_RPC" "$node_c_json" 2>/dev/null; then
      sleep "$POLL_INTERVAL_SECS"
      continue
    fi
    if check_cluster_convergence_snapshot "$node_a_json" "$node_b_json" "$node_c_json" "$require_all_restored"; then
      return 0
    fi
    sleep "$POLL_INTERVAL_SECS"
  done
  return 1
}

start_detached_node() {
  local log_file="$1"
  shift
  if command -v setsid >/dev/null 2>&1; then
    env MISAKA_VALIDATOR_PASSPHRASE="${MISAKA_VALIDATOR_PASSPHRASE:-}" \
      setsid "$@" >"$log_file" 2>&1 < /dev/null &
  else
    env MISAKA_VALIDATOR_PASSPHRASE="${MISAKA_VALIDATOR_PASSPHRASE:-}" \
      nohup "$@" >"$log_file" 2>&1 < /dev/null &
  fi
  echo $!
}

start_node_a() {
  local log_file="$1"
  start_detached_node "$log_file" "$BIN" \
    --name "dag-roll-a" \
    --validator \
    --validator-index 0 \
    --validators 3 \
    --block-time "$BLOCK_TIME_SECS" \
    --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_B_RPC},http://127.0.0.1:${NODE_C_RPC}" \
    --rpc-port "$NODE_A_RPC" \
    --p2p-port "$NODE_A_P2P" \
    --data-dir "$NODE_A_DIR"
}

start_node_b() {
  local log_file="$1"
  start_detached_node "$log_file" "$BIN" \
    --name "dag-roll-b" \
    --validator \
    --validator-index 1 \
    --validators 3 \
    --block-time "$BLOCK_TIME_SECS" \
    --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_A_RPC},http://127.0.0.1:${NODE_C_RPC}" \
    --rpc-port "$NODE_B_RPC" \
    --p2p-port "$NODE_B_P2P" \
    --seeds "127.0.0.1:${NODE_A_P2P}" \
    --data-dir "$NODE_B_DIR"
}

start_node_c() {
  local log_file="$1"
  start_detached_node "$log_file" "$BIN" \
    --name "dag-roll-c" \
    --validator \
    --validator-index 2 \
    --validators 3 \
    --block-time "$BLOCK_TIME_SECS" \
    --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_A_RPC},http://127.0.0.1:${NODE_B_RPC}" \
    --rpc-port "$NODE_C_RPC" \
    --p2p-port "$NODE_C_P2P" \
    --seeds "127.0.0.1:${NODE_A_P2P}" \
    --data-dir "$NODE_C_DIR"
}

start_all_nodes() {
  NODE_A_PID="$(start_node_a "${LOG_DIR}/node-a.log")"
  printf '%s\n' "$NODE_A_PID" >"$PID_FILE"
  wait_for_chain_info "$NODE_A_RPC" 60 || { echo "node-a did not start in time" >&2; exit 1; }

  NODE_B_PID="$(start_node_b "${LOG_DIR}/node-b.log")"
  printf '%s\n%s\n' "$NODE_A_PID" "$NODE_B_PID" >"$PID_FILE"
  wait_for_chain_info "$NODE_B_RPC" 60 || { echo "node-b did not start in time" >&2; exit 1; }

  NODE_C_PID="$(start_node_c "${LOG_DIR}/node-c.log")"
  printf '%s\n%s\n%s\n' "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" >"$PID_FILE"
  wait_for_chain_info "$NODE_C_RPC" 60 || { echo "node-c did not start in time" >&2; exit 1; }
}

replace_pid_file() {
  printf '%s\n%s\n%s\n' "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" >"$PID_FILE"
}

rolling_restart_one() {
  local node="$1"
  case "$node" in
    nodeA)
      kill "$NODE_A_PID" 2>/dev/null || true
      sleep 3
      NODE_A_PID="$(start_node_a "${LOG_DIR}/node-a.log")"
      wait_for_chain_info "$NODE_A_RPC" 60 || { echo "node-a did not restart in time" >&2; exit 1; }
      ;;
    nodeB)
      kill "$NODE_B_PID" 2>/dev/null || true
      sleep 3
      NODE_B_PID="$(start_node_b "${LOG_DIR}/node-b.log")"
      wait_for_chain_info "$NODE_B_RPC" 60 || { echo "node-b did not restart in time" >&2; exit 1; }
      ;;
    nodeC)
      kill "$NODE_C_PID" 2>/dev/null || true
      sleep 3
      NODE_C_PID="$(start_node_c "${LOG_DIR}/node-c.log")"
      wait_for_chain_info "$NODE_C_RPC" 60 || { echo "node-c did not restart in time" >&2; exit 1; }
      ;;
    *)
      echo "unknown node: $node" >&2
      exit 1
      ;;
  esac
  replace_pid_file
}

append_cycle_summary() {
  local cycle="$1"
  local node="$2"
  local snapshot_prefix="${STATE_DIR}/cycle-${cycle}-${node}"
  fetch_chain_info_file "$NODE_A_RPC" "${snapshot_prefix}-a.json"
  fetch_chain_info_file "$NODE_B_RPC" "${snapshot_prefix}-b.json"
  fetch_chain_info_file "$NODE_C_RPC" "${snapshot_prefix}-c.json"
  python3 - "$cycle" "$node" "${snapshot_prefix}-a.json" "${snapshot_prefix}-b.json" "${snapshot_prefix}-c.json" >>"${STATE_DIR}/cycles.jsonl" <<'PY'
import json
import sys

cycle_raw = sys.argv[1]
node = sys.argv[2]
paths = sys.argv[3:6]
names = ("nodeA", "nodeB", "nodeC")
nodes = {}
for name, path in zip(names, paths):
    with open(path, "r", encoding="utf-8") as f:
        nodes[name] = json.load(f)

def checkpoint_target(body):
    cp = body.get("latestCheckpoint")
    if not cp:
        return None
    return cp.get("validatorTarget") or {
        "blockHash": cp.get("blockHash"),
        "blueScore": cp.get("blueScore"),
        "utxoRoot": cp.get("utxoRoot"),
        "totalAppliedTxs": cp.get("totalAppliedTxs"),
        "totalKeyImages": cp.get("totalKeyImages"),
    }

def votes(body):
    return body.get("validatorAttestation", {}).get("currentCheckpointVotes")

def status(body):
    return body.get("validatorAttestation", {}).get("currentCheckpointStatus")

def recovery(body):
    return body.get("runtimeRecovery", {})

def lifecycle(body):
    return body.get("validatorLifecycleRecovery", {})

targets = {name: checkpoint_target(body) for name, body in nodes.items()}
print(json.dumps({
    "cycle": cycle_raw,
    "restartedNode": node,
    "sameValidatorTarget": all(v is not None for v in targets.values()) and len({json.dumps(v, sort_keys=True) for v in targets.values()}) == 1,
    "validatorTargets": targets,
    "voteCounts": {name: votes(body) for name, body in nodes.items()},
    "statuses": {name: status(body) for name, body in nodes.items()},
    "recovery": {
        name: {
            "startupSnapshotRestored": recovery(body).get("startupSnapshotRestored"),
            "operatorRestartReady": recovery(body).get("operatorRestartReady"),
            "lifecycleSummary": lifecycle(body).get("summary"),
        }
        for name, body in nodes.items()
    },
}))
PY
}

write_result_snapshot() {
  local baseline_prefix="${STATE_DIR}/baseline"
  fetch_chain_info_file "$NODE_A_RPC" "${baseline_prefix}-a.json"
  fetch_chain_info_file "$NODE_B_RPC" "${baseline_prefix}-b.json"
  fetch_chain_info_file "$NODE_C_RPC" "${baseline_prefix}-c.json"

  python3 - "${STATE_DIR}/cycles.jsonl" "$RESULT_FILE" "$ROLLING_RESTART_CYCLES" "$CHECKPOINT_INTERVAL" "$LOG_DIR" <<'PY'
import json
import sys
from datetime import datetime, timezone

cycles_path, result_path, cycles_count, checkpoint_interval, log_dir = sys.argv[1:6]
entries = []
with open(cycles_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            entries.append(json.loads(line))

summary = {
    "scenario": "dag-rolling-restart-soak-harness",
    "capturedAt": datetime.now(timezone.utc).isoformat(),
    "rollingRestartCycles": int(cycles_count),
    "checkpointInterval": int(checkpoint_interval),
    "cycleEntries": entries,
    "allCyclesPassed": all(
        entry["sameValidatorTarget"]
        and all((v or {}).get("quorumReached", False) for v in entry["voteCounts"].values())
        and all((v or {}).get("currentCheckpointFinalized", False) for v in entry["statuses"].values())
        for entry in entries
    ),
    "logs": {
        "nodeA": f"{log_dir}/node-a.log",
        "nodeB": f"{log_dir}/node-b.log",
        "nodeC": f"{log_dir}/node-c.log",
    },
}

with open(result_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")
PY
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

if [[ "${1:-}" == "stop" ]]; then
  stop_harness
  exit 0
fi

if [[ "${1:-}" == "status" ]]; then
  show_status
  exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_cmd curl
require_cmd python3

stop_harness
rm -rf "$NODE_A_DIR" "$NODE_B_DIR" "$NODE_C_DIR"
mkdir -p "$NODE_A_DIR" "$NODE_B_DIR" "$NODE_C_DIR" "$LOG_DIR"
rm -f "$RESULT_FILE" "$PID_FILE" "${STATE_DIR}/cycles.jsonl"

BIN="$(resolve_binary)"

echo "Step 1/4: start 3-validator cluster"
start_all_nodes

echo "Step 2/4: wait for initial convergence"
wait_for_cluster_convergence "initial" "$INITIAL_WAIT_ATTEMPTS" 0 || {
  echo "initial rolling-restart baseline did not converge in time" >&2
  exit 1
}

echo "Step 3/4: perform rolling restarts"
for cycle in $(seq 1 "$ROLLING_RESTART_CYCLES"); do
  for node in nodeA nodeB nodeC; do
    echo "  cycle ${cycle}: restarting ${node}"
    rolling_restart_one "$node"
    wait_for_cluster_convergence "cycle-${cycle}-${node}" "$RESTART_WAIT_ATTEMPTS" 0 || {
      echo "cluster did not reconverge after ${node} in cycle ${cycle}" >&2
      exit 1
    }
    append_cycle_summary "$cycle" "$node"
  done
done

echo "Step 4/4: verify final all-restored convergence"
wait_for_cluster_convergence "final" "$RESTART_WAIT_ATTEMPTS" 1 || {
  echo "final all-restored convergence did not complete in time" >&2
  exit 1
}
append_cycle_summary "final" "all"
write_result_snapshot

echo
echo "DAG rolling restart soak harness completed."
echo
cat "$RESULT_FILE"
echo
echo "Status:"
echo "  ./scripts/dag_rolling_restart_soak_harness.sh status"
echo "Stop:"
echo "  ./scripts/dag_rolling_restart_soak_harness.sh stop"
