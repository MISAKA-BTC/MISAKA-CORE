#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STATE_DIR="${MISAKA_HARNESS_DIR:-${ROOT_DIR}/.tmp/dag-natural-restart-harness}"
NODE_A_DIR="${STATE_DIR}/node-a"
NODE_B_DIR="${STATE_DIR}/node-b"
LOG_DIR="${STATE_DIR}/logs"
PID_FILE="${STATE_DIR}/pids"
RESULT_FILE="${STATE_DIR}/result.json"
TARGET_DIR="${MISAKA_CARGO_TARGET_DIR:-${ROOT_DIR}/.tmp/dag-natural-restart-target}"

NODE_A_RPC="${MISAKA_NODE_A_RPC_PORT:-4511}"
NODE_B_RPC="${MISAKA_NODE_B_RPC_PORT:-4512}"
NODE_A_P2P="${MISAKA_NODE_A_P2P_PORT:-8012}"
NODE_B_P2P="${MISAKA_NODE_B_P2P_PORT:-8013}"
BLOCK_TIME_SECS="${MISAKA_BLOCK_TIME_SECS:-5}"
CHECKPOINT_INTERVAL="${MISAKA_DAG_CHECKPOINT_INTERVAL:-6}"
INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-90}"
RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-90}"
POLL_INTERVAL_SECS="${MISAKA_POLL_INTERVAL_SECS:-2}"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$TARGET_DIR"

usage() {
  cat <<'EOF'
MISAKA DAG natural durable restart harness

Usage:
  ./scripts/dag_natural_restart_harness.sh
  ./scripts/dag_natural_restart_harness.sh status
  ./scripts/dag_natural_restart_harness.sh stop
  ./scripts/dag_natural_restart_harness.sh --help

Purpose:
  Start a natural 2-validator DAG network, wait for checkpoint/finality
  convergence, restart one validator with the same data directory, and verify
  that checkpoint, finality, and runtime recovery surfaces converge again.

Optional env:
  MISAKA_BIN=/path/to/misaka-node
  MISAKA_SKIP_BUILD=1
  MISAKA_HARNESS_DIR=/custom/writable/path
  MISAKA_CARGO_TARGET_DIR=/custom/target/dir
  MISAKA_NODE_A_RPC_PORT=4511
  MISAKA_NODE_B_RPC_PORT=4512
  MISAKA_NODE_A_P2P_PORT=8012
  MISAKA_NODE_B_P2P_PORT=8013
  MISAKA_BLOCK_TIME_SECS=5
  MISAKA_DAG_CHECKPOINT_INTERVAL=6
  MISAKA_INITIAL_WAIT_ATTEMPTS=90
  MISAKA_RESTART_WAIT_ATTEMPTS=90
  MISAKA_POLL_INTERVAL_SECS=2
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
    echo "DAG natural durable restart harness stopped."
  else
    echo "No DAG natural durable restart harness is running."
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

check_convergence_snapshot() {
  local node_a_json="$1"
  local node_b_json="$2"
  local require_restart_ready="${3:-0}"

  python3 - "$node_a_json" "$node_b_json" "$require_restart_ready" <<'PY'
import json
import sys

node_a_path, node_b_path, require_restart_ready = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(node_a_path, "r", encoding="utf-8") as f:
    node_a = json.load(f)
with open(node_b_path, "r", encoding="utf-8") as f:
    node_b = json.load(f)

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

def current_votes(body):
    return body.get("validatorAttestation", {}).get("currentCheckpointVotes")

def finalized(body):
    return bool(
        body.get("validatorAttestation", {})
        .get("currentCheckpointStatus", {})
        .get("currentCheckpointFinalized", False)
    )

def vote_quorum_met(body):
    votes = current_votes(body)
    if not votes:
        return False
    try:
        vote_count = int(votes.get("voteCount", 0))
        quorum_threshold = int(votes.get("quorumThreshold", 0))
    except (TypeError, ValueError):
        return False
    return vote_count >= quorum_threshold and quorum_threshold > 0

a_target = checkpoint_target(node_a)
b_target = checkpoint_target(node_b)
same_target = a_target is not None and b_target is not None and a_target == b_target
both_finalized = finalized(node_a) and finalized(node_b)
both_vote_quorum = vote_quorum_met(node_a) and vote_quorum_met(node_b)

if not (same_target and both_finalized and both_vote_quorum):
    raise SystemExit(1)

if require_restart_ready:
    recovery = node_a.get("runtimeRecovery", {})
    lifecycle = node_a.get("validatorLifecycleRecovery", {})
    if not recovery.get("operatorRestartReady", False):
        raise SystemExit(1)
    if not recovery.get("startupSnapshotRestored", False):
        raise SystemExit(1)
    if lifecycle.get("summary") != "ready":
        raise SystemExit(1)

raise SystemExit(0)
PY
}

wait_for_convergence() {
  local phase="$1"
  local attempts="$2"
  local require_restart_ready="${3:-0}"
  local node_a_json="${STATE_DIR}/node-a-${phase}.json"
  local node_b_json="${STATE_DIR}/node-b-${phase}.json"
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

    if check_convergence_snapshot "$node_a_json" "$node_b_json" "$require_restart_ready"; then
      sleep "$POLL_INTERVAL_SECS"
      if ! fetch_chain_info_file "$NODE_A_RPC" "$node_a_json" 2>/dev/null; then
        sleep "$POLL_INTERVAL_SECS"
        continue
      fi
      if ! fetch_chain_info_file "$NODE_B_RPC" "$node_b_json" 2>/dev/null; then
        sleep "$POLL_INTERVAL_SECS"
        continue
      fi
      if check_convergence_snapshot "$node_a_json" "$node_b_json" "$require_restart_ready"; then
        return 0
      fi
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

write_result_snapshot() {
  local before_a="${STATE_DIR}/node-a-before.json"
  local before_b="${STATE_DIR}/node-b-before.json"
  local after_a="${STATE_DIR}/node-a-after.json"
  local after_b="${STATE_DIR}/node-b-after.json"

  python3 - "$before_a" "$before_b" "$after_a" "$after_b" "$RESULT_FILE" "$LOG_DIR" <<'PY'
import json
import sys
from datetime import datetime, timezone

before_a_path, before_b_path, after_a_path, after_b_path, result_file, log_dir = sys.argv[1:7]

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

before_a = load(before_a_path)
before_b = load(before_b_path)
after_a = load(after_a_path)
after_b = load(after_b_path)

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

def finalized(body):
    return bool(
        body.get("validatorAttestation", {})
        .get("currentCheckpointStatus", {})
        .get("currentCheckpointFinalized", False)
    )

def current_votes(body):
    return body.get("validatorAttestation", {}).get("currentCheckpointVotes")

def vote_quorum_met(body):
    votes = current_votes(body)
    if not votes:
        return False
    try:
        vote_count = int(votes.get("voteCount", 0))
        quorum_threshold = int(votes.get("quorumThreshold", 0))
    except (TypeError, ValueError):
        return False
    return vote_count >= quorum_threshold and quorum_threshold > 0

def compact(body):
    return {
        "latestBlockHeight": body.get("latestBlockHeight"),
        "dagBlockCount": body.get("dagBlockCount"),
        "dagTipCount": body.get("dagTipCount"),
        "latestCheckpoint": body.get("latestCheckpoint"),
        "validatorAttestation": body.get("validatorAttestation"),
        "runtimeRecovery": body.get("runtimeRecovery"),
        "validatorLifecycleRecovery": body.get("validatorLifecycleRecovery"),
        "consumerSurfaces": body.get("consumerSurfaces"),
        "privacyBackend": body.get("privacyBackend"),
        "dagP2pObservation": body.get("dagP2pObservation"),
    }

def phase_summary(node_a, node_b):
    a_target = checkpoint_target(node_a)
    b_target = checkpoint_target(node_b)
    return {
        "sameValidatorTarget": a_target is not None and b_target is not None and a_target == b_target,
        "nodeAValidatorTarget": a_target,
        "nodeBValidatorTarget": b_target,
        "nodeACurrentCheckpointVotes": current_votes(node_a),
        "nodeBCurrentCheckpointVotes": current_votes(node_b),
        "nodeAVoteQuorumMet": vote_quorum_met(node_a),
        "nodeBVoteQuorumMet": vote_quorum_met(node_b),
        "nodeAFinalized": finalized(node_a),
        "nodeBFinalized": finalized(node_b),
        "bothFinalized": finalized(node_a) and finalized(node_b),
        "bothVoteQuorumMet": vote_quorum_met(node_a) and vote_quorum_met(node_b),
    }

before_summary = phase_summary(before_a, before_b)
after_summary = phase_summary(after_a, after_b)
node_a_recovery = after_a.get("runtimeRecovery", {})
node_a_lifecycle = after_a.get("validatorLifecycleRecovery", {})

result = {
    "scenario": "dag-natural-durable-restart-harness",
    "capturedAt": datetime.now(timezone.utc).isoformat(),
    "beforeRestart": {
        "comparison": before_summary,
        "nodeA": compact(before_a),
        "nodeB": compact(before_b),
    },
    "afterRestart": {
        "comparison": after_summary,
        "nodeA": compact(after_a),
        "nodeB": compact(after_b),
    },
    "durableRestart": {
        "preRestartConverged": before_summary["sameValidatorTarget"]
        and before_summary["bothFinalized"]
        and before_summary["bothVoteQuorumMet"],
        "postRestartConverged": after_summary["sameValidatorTarget"]
        and after_summary["bothFinalized"]
        and after_summary["bothVoteQuorumMet"],
        "nodeARestoredSnapshot": node_a_recovery.get("startupSnapshotRestored"),
        "nodeARestartReady": node_a_recovery.get("operatorRestartReady"),
        "nodeALifecycleSummary": node_a_lifecycle.get("summary"),
        "nodeALifecycleRestartReady": node_a_lifecycle.get("restartReady"),
        "nodeALifecycleCheckpointFinalized": node_a_lifecycle.get("checkpointFinalized"),
    },
    "logs": {
        "nodeA": f"{log_dir}/node-a.log",
        "nodeB": f"{log_dir}/node-b.log",
    },
}

with open(result_file, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
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
rm -rf "$NODE_A_DIR" "$NODE_B_DIR"
mkdir -p "$NODE_A_DIR" "$NODE_B_DIR" "$LOG_DIR"
rm -f "$RESULT_FILE" "$PID_FILE"

BIN="$(resolve_binary)"

echo "Step 1/7: start node-a"
NODE_A_PID="$(start_detached_node "${LOG_DIR}/node-a.log" "$BIN" \
  --name "dag-restart-a" \
  --validator \
  --validator-index 0 \
  --validators 2 \
  --block-time "$BLOCK_TIME_SECS" \
  --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
  --dag-rpc-peers "http://127.0.0.1:${NODE_B_RPC}" \
  --rpc-port "$NODE_A_RPC" \
  --p2p-port "$NODE_A_P2P" \
  --data-dir "$NODE_A_DIR")"
echo "$NODE_A_PID" >>"$PID_FILE"
wait_for_chain_info "$NODE_A_RPC" 60 || {
  echo "node-a did not start in time" >&2
  exit 1
}

echo "Step 2/7: start node-b"
NODE_B_PID="$(start_detached_node "${LOG_DIR}/node-b.log" "$BIN" \
  --name "dag-restart-b" \
  --validator \
  --validator-index 1 \
  --validators 2 \
  --block-time "$BLOCK_TIME_SECS" \
  --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
  --dag-rpc-peers "http://127.0.0.1:${NODE_A_RPC}" \
  --rpc-port "$NODE_B_RPC" \
  --p2p-port "$NODE_B_P2P" \
  --seeds "127.0.0.1:${NODE_A_P2P}" \
  --data-dir "$NODE_B_DIR")"
echo "$NODE_B_PID" >>"$PID_FILE"
wait_for_chain_info "$NODE_B_RPC" 60 || {
  echo "node-b did not start in time" >&2
  exit 1
}

echo "Step 3/7: wait for natural checkpoint/finality convergence"
wait_for_convergence "before" "$INITIAL_WAIT_ATTEMPTS" 0 || {
  echo "initial natural convergence did not complete in time" >&2
  exit 1
}

echo "Step 4/7: capture pre-restart state"
fetch_chain_info_file "$NODE_A_RPC" "${STATE_DIR}/node-a-before.json"
fetch_chain_info_file "$NODE_B_RPC" "${STATE_DIR}/node-b-before.json"

echo "Step 5/7: restart node-a with the same data directory"
kill "$NODE_A_PID" 2>/dev/null || true
sleep 3
NODE_A_PID="$(start_detached_node "${LOG_DIR}/node-a.log" "$BIN" \
  --name "dag-restart-a" \
  --validator \
  --validator-index 0 \
  --validators 2 \
  --block-time "$BLOCK_TIME_SECS" \
  --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
  --dag-rpc-peers "http://127.0.0.1:${NODE_B_RPC}" \
  --rpc-port "$NODE_A_RPC" \
  --p2p-port "$NODE_A_P2P" \
  --data-dir "$NODE_A_DIR")"
printf '%s\n%s\n' "$NODE_A_PID" "$NODE_B_PID" >"$PID_FILE"
wait_for_chain_info "$NODE_A_RPC" 60 || {
  echo "node-a did not restart in time" >&2
  exit 1
}

echo "Step 6/7: wait for post-restart convergence and recovery readiness"
wait_for_convergence "after" "$RESTART_WAIT_ATTEMPTS" 1 || {
  echo "post-restart convergence did not complete in time" >&2
  exit 1
}

echo "Step 7/7: capture post-restart state"
fetch_chain_info_file "$NODE_A_RPC" "${STATE_DIR}/node-a-after.json"
fetch_chain_info_file "$NODE_B_RPC" "${STATE_DIR}/node-b-after.json"
write_result_snapshot

echo
echo "DAG natural durable restart harness completed."
echo
cat "$RESULT_FILE"
echo
echo "Logs:"
echo "  node-a: ${LOG_DIR}/node-a.log"
echo "  node-b: ${LOG_DIR}/node-b.log"
echo "Result:"
echo "  ${RESULT_FILE}"
echo
echo "Status:"
echo "  ./scripts/dag_natural_restart_harness.sh status"
echo "Stop:"
echo "  ./scripts/dag_natural_restart_harness.sh stop"
