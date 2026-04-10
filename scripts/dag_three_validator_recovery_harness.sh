#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STATE_DIR="${MISAKA_HARNESS_DIR:-${ROOT_DIR}/.tmp/dag-three-validator-recovery-harness}"
NODE_A_DIR="${STATE_DIR}/node-a"
NODE_B_DIR="${STATE_DIR}/node-b"
NODE_C_DIR="${STATE_DIR}/node-c"
LOG_DIR="${STATE_DIR}/logs"
PID_FILE="${STATE_DIR}/pids"
RESULT_FILE="${STATE_DIR}/result.json"
TARGET_DIR="${MISAKA_CARGO_TARGET_DIR:-${ROOT_DIR}/.tmp/dag-three-validator-target}"

NODE_A_RPC="${MISAKA_NODE_A_RPC_PORT:-4711}"
NODE_B_RPC="${MISAKA_NODE_B_RPC_PORT:-4712}"
NODE_C_RPC="${MISAKA_NODE_C_RPC_PORT:-4713}"
NODE_A_P2P="${MISAKA_NODE_A_P2P_PORT:-8212}"
NODE_B_P2P="${MISAKA_NODE_B_P2P_PORT:-8213}"
NODE_C_P2P="${MISAKA_NODE_C_P2P_PORT:-8214}"
BLOCK_TIME_SECS="${MISAKA_BLOCK_TIME_SECS:-5}"
HARNESS_PROFILE="${MISAKA_THREE_VALIDATOR_PROFILE:-operator-safe}"

case "$HARNESS_PROFILE" in
  operator-safe)
    CHECKPOINT_INTERVAL="${MISAKA_DAG_CHECKPOINT_INTERVAL:-12}"
    INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-180}"
    RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-180}"
    POLL_INTERVAL_SECS="${MISAKA_POLL_INTERVAL_SECS:-3}"
    CONVERGENCE_STABILIZATION_POLLS="${MISAKA_CONVERGENCE_STABILIZATION_POLLS:-3}"
    NETWORK_WARMUP_SECS="${MISAKA_NETWORK_WARMUP_SECS:-10}"
    ;;
  legacy)
    CHECKPOINT_INTERVAL="${MISAKA_DAG_CHECKPOINT_INTERVAL:-6}"
    INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-140}"
    RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-140}"
    POLL_INTERVAL_SECS="${MISAKA_POLL_INTERVAL_SECS:-2}"
    CONVERGENCE_STABILIZATION_POLLS="${MISAKA_CONVERGENCE_STABILIZATION_POLLS:-2}"
    NETWORK_WARMUP_SECS="${MISAKA_NETWORK_WARMUP_SECS:-5}"
    ;;
  *)
    echo "unknown MISAKA_THREE_VALIDATOR_PROFILE: $HARNESS_PROFILE (expected operator-safe or legacy)" >&2
    exit 1
    ;;
esac

if [[ "$HARNESS_PROFILE" == "operator-safe" ]]; then
  if (( CHECKPOINT_INTERVAL < 12 )); then
    CHECKPOINT_INTERVAL=12
  fi
  if (( INITIAL_WAIT_ATTEMPTS < 480 )); then
    INITIAL_WAIT_ATTEMPTS=480
  fi
  if (( RESTART_WAIT_ATTEMPTS < 480 )); then
    RESTART_WAIT_ATTEMPTS=480
  fi
  if (( POLL_INTERVAL_SECS > 2 )); then
    POLL_INTERVAL_SECS=2
  fi
  if (( CONVERGENCE_STABILIZATION_POLLS > 2 )); then
    CONVERGENCE_STABILIZATION_POLLS=2
  fi
fi

mkdir -p "$STATE_DIR" "$LOG_DIR" "$TARGET_DIR"

usage() {
  cat <<'EOF'
MISAKA DAG natural 3-validator durable restart harness

Usage:
  ./scripts/dag_three_validator_recovery_harness.sh
  ./scripts/dag_three_validator_recovery_harness.sh status
  ./scripts/dag_three_validator_recovery_harness.sh stop
  ./scripts/dag_three_validator_recovery_harness.sh --help

Purpose:
  Start a natural 3-validator DAG network, wait for checkpoint / quorum /
  finality convergence, restart all validators with the same data directories,
  and verify that checkpoint / finality / recovery surfaces converge again.

Optional env:
  MISAKA_BIN=/path/to/misaka-node
  MISAKA_SKIP_BUILD=1
  MISAKA_HARNESS_DIR=/custom/writable/path
  MISAKA_CARGO_TARGET_DIR=/custom/target/dir
  MISAKA_NODE_A_RPC_PORT=4711
  MISAKA_NODE_B_RPC_PORT=4712
  MISAKA_NODE_C_RPC_PORT=4713
  MISAKA_NODE_A_P2P_PORT=8212
  MISAKA_NODE_B_P2P_PORT=8213
  MISAKA_NODE_C_P2P_PORT=8214
  MISAKA_BLOCK_TIME_SECS=5
  MISAKA_THREE_VALIDATOR_PROFILE=operator-safe
  MISAKA_DAG_CHECKPOINT_INTERVAL=12
  MISAKA_INITIAL_WAIT_ATTEMPTS=180
  MISAKA_RESTART_WAIT_ATTEMPTS=180
  MISAKA_POLL_INTERVAL_SECS=3
  MISAKA_CONVERGENCE_STABILIZATION_POLLS=3
  MISAKA_NETWORK_WARMUP_SECS=10
  # legacy profile remains available for comparison:
  # MISAKA_THREE_VALIDATOR_PROFILE=legacy
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
    echo "DAG 3-validator durable restart harness stopped."
  else
    echo "No DAG 3-validator durable restart harness is running."
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
  local node_c_json="$3"
  local require_restart_ready="${4:-0}"

  python3 - "$node_a_json" "$node_b_json" "$node_c_json" "$require_restart_ready" <<'PY'
import json
import sys

node_paths = sys.argv[1:4]
require_restart_ready = int(sys.argv[4])
nodes = {}
for idx, path in enumerate(node_paths):
    with open(path, "r", encoding="utf-8") as f:
        nodes[f"node{chr(ord('A') + idx)}"] = json.load(f)

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

def finalized(body):
    return bool(
        body.get("validatorAttestation", {})
        .get("currentCheckpointStatus", {})
        .get("currentCheckpointFinalized", False)
    )

targets = {name: checkpoint_target(body) for name, body in nodes.items()}
same_target = all(v is not None for v in targets.values()) and len(
    {json.dumps(v, sort_keys=True) for v in targets.values()}
) == 1
all_finalized = all(finalized(body) for body in nodes.values())
all_quorum = all(vote_quorum_met(body) for body in nodes.values())

if not (same_target and all_finalized and all_quorum):
    raise SystemExit(1)

if require_restart_ready:
    for body in nodes.values():
        recovery = body.get("runtimeRecovery", {})
        lifecycle = body.get("validatorLifecycleRecovery", {})
        if not recovery.get("operatorRestartReady", False):
            raise SystemExit(1)
        if not recovery.get("startupSnapshotRestored", False):
            raise SystemExit(1)
        if lifecycle.get("summary") != "ready":
            raise SystemExit(1)

raise SystemExit(0)
PY
}

check_vote_acceptance_snapshot() {
  local node_a_json="$1"
  local node_b_json="$2"
  local node_c_json="$3"

  python3 - "$node_a_json" "$node_b_json" "$node_c_json" <<'PY'
import json
import sys

node_paths = sys.argv[1:4]
nodes = {}
for idx, path in enumerate(node_paths):
    with open(path, "r", encoding="utf-8") as f:
        nodes[f"node{chr(ord('A') + idx)}"] = json.load(f)

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

targets = {name: checkpoint_target(body) for name, body in nodes.items()}
same_target = all(v is not None for v in targets.values()) and len(
    {json.dumps(v, sort_keys=True) for v in targets.values()}
) == 1
all_quorum = all(vote_quorum_met(body) for body in nodes.values())

raise SystemExit(0 if same_target and all_quorum else 1)
PY
}

check_finality_snapshot() {
  local node_a_json="$1"
  local node_b_json="$2"
  local node_c_json="$3"
  local require_restart_ready="${4:-0}"

  python3 - "$node_a_json" "$node_b_json" "$node_c_json" "$require_restart_ready" <<'PY'
import json
import sys

node_paths = sys.argv[1:4]
require_restart_ready = int(sys.argv[4])
nodes = {}
for idx, path in enumerate(node_paths):
    with open(path, "r", encoding="utf-8") as f:
        nodes[f"node{chr(ord('A') + idx)}"] = json.load(f)

def finalized(body):
    return bool(
        body.get("validatorAttestation", {})
        .get("currentCheckpointStatus", {})
        .get("currentCheckpointFinalized", False)
    )

if not all(finalized(body) for body in nodes.values()):
    raise SystemExit(1)

if require_restart_ready:
    for body in nodes.values():
        recovery = body.get("runtimeRecovery", {})
        lifecycle = body.get("validatorLifecycleRecovery", {})
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
  local node_c_json="${STATE_DIR}/node-c-${phase}.json"
  local i
  local stable_vote_hits=0
  local stable_finality_hits=0

  for i in $(seq 1 "$attempts"); do
    if ! fetch_chain_info_file "$NODE_A_RPC" "$node_a_json" 2>/dev/null; then
      sleep "$POLL_INTERVAL_SECS"
      stable_vote_hits=0
      stable_finality_hits=0
      continue
    fi
    if ! fetch_chain_info_file "$NODE_B_RPC" "$node_b_json" 2>/dev/null; then
      sleep "$POLL_INTERVAL_SECS"
      stable_vote_hits=0
      stable_finality_hits=0
      continue
    fi
    if ! fetch_chain_info_file "$NODE_C_RPC" "$node_c_json" 2>/dev/null; then
      sleep "$POLL_INTERVAL_SECS"
      stable_vote_hits=0
      stable_finality_hits=0
      continue
    fi

    if check_vote_acceptance_snapshot "$node_a_json" "$node_b_json" "$node_c_json"; then
      stable_vote_hits=$((stable_vote_hits + 1))
      if [[ "$stable_vote_hits" -lt "$CONVERGENCE_STABILIZATION_POLLS" ]]; then
        sleep "$POLL_INTERVAL_SECS"
        continue
      fi
    else
      stable_vote_hits=0
      stable_finality_hits=0
      sleep "$POLL_INTERVAL_SECS"
      continue
    fi

    if check_finality_snapshot "$node_a_json" "$node_b_json" "$node_c_json" "$require_restart_ready"; then
      stable_finality_hits=$((stable_finality_hits + 1))
      if [[ "$stable_finality_hits" -ge "$CONVERGENCE_STABILIZATION_POLLS" ]]; then
        return 0
      fi
    else
      stable_finality_hits=0
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
    --name "dag-three-a" \
    --validator \
    --validator-index 0 \
    --validators 3 \
    --block-time "$BLOCK_TIME_SECS" \
    --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_B_RPC},http://127.0.0.1:${NODE_C_RPC}" \
    --rpc-port "$NODE_A_RPC" \
    --p2p-port "$NODE_A_P2P" \
    --seeds "127.0.0.1:${NODE_B_P2P},127.0.0.1:${NODE_C_P2P}" \
    --data-dir "$NODE_A_DIR"
}

start_node_b() {
  local log_file="$1"
  start_detached_node "$log_file" "$BIN" \
    --name "dag-three-b" \
    --validator \
    --validator-index 1 \
    --validators 3 \
    --block-time "$BLOCK_TIME_SECS" \
    --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_A_RPC},http://127.0.0.1:${NODE_C_RPC}" \
    --rpc-port "$NODE_B_RPC" \
    --p2p-port "$NODE_B_P2P" \
    --seeds "127.0.0.1:${NODE_C_P2P}" \
    --data-dir "$NODE_B_DIR"
}

start_node_c() {
  local log_file="$1"
  start_detached_node "$log_file" "$BIN" \
    --name "dag-three-c" \
    --validator \
    --validator-index 2 \
    --validators 3 \
    --block-time "$BLOCK_TIME_SECS" \
    --dag-checkpoint-interval "$CHECKPOINT_INTERVAL" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_A_RPC},http://127.0.0.1:${NODE_B_RPC}" \
    --rpc-port "$NODE_C_RPC" \
    --p2p-port "$NODE_C_P2P" \
    --data-dir "$NODE_C_DIR"
}

write_result_snapshot() {
  local status="${1:-passed}"
  local failure_phase="${2:-}"
  local failure_reason="${3:-}"
  local before_a="${STATE_DIR}/node-a-before.json"
  local before_b="${STATE_DIR}/node-b-before.json"
  local before_c="${STATE_DIR}/node-c-before.json"
  local after_a="${STATE_DIR}/node-a-after.json"
  local after_b="${STATE_DIR}/node-b-after.json"
  local after_c="${STATE_DIR}/node-c-after.json"

  python3 - "$before_a" "$before_b" "$before_c" "$after_a" "$after_b" "$after_c" "$RESULT_FILE" "$LOG_DIR" "$status" "$failure_phase" "$failure_reason" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

before_paths = sys.argv[1:4]
after_paths = sys.argv[4:7]
result_file = sys.argv[7]
log_dir = sys.argv[8]
status = sys.argv[9]
failure_phase = sys.argv[10]
failure_reason = sys.argv[11]

def load_optional(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def checkpoint_target(body):
    if not body:
        return None
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
    if not body:
        return None
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

def finalized(body):
    if not body:
        return False
    return bool(
        body.get("validatorAttestation", {})
        .get("currentCheckpointStatus", {})
        .get("currentCheckpointFinalized", False)
    )

def compact(body):
    if not body:
        return None
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
        "relaySurfaces": body.get("relaySurfaces"),
        "relayActivity": body.get("relayActivity"),
        "checkpointSelection": body.get("checkpointSelection"),
    }

def phase_summary(nodes):
    targets = {name: checkpoint_target(body) for name, body in nodes.items()}
    return {
        "sameValidatorTarget": all(v is not None for v in targets.values()) and len(
            {json.dumps(v, sort_keys=True) for v in targets.values()}
        ) == 1,
        "validatorTargets": targets,
        "voteCounts": {
            name: current_votes(body)
            for name, body in nodes.items()
        },
        "quorumPerNode": {
            name: vote_quorum_met(body)
            for name, body in nodes.items()
        },
        "finalizedPerNode": {
            name: finalized(body)
            for name, body in nodes.items()
        },
        "allFinalized": all(finalized(body) for body in nodes.values()),
        "allVoteQuorumMet": all(vote_quorum_met(body) for body in nodes.values()),
    }

before_nodes = {
    "nodeA": load_optional(before_paths[0]),
    "nodeB": load_optional(before_paths[1]),
    "nodeC": load_optional(before_paths[2]),
}
after_nodes = {
    "nodeA": load_optional(after_paths[0]),
    "nodeB": load_optional(after_paths[1]),
    "nodeC": load_optional(after_paths[2]),
}

before_summary = phase_summary(before_nodes)
after_summary = phase_summary(after_nodes)
recovery_ready = {}
for name, body in after_nodes.items():
    recovery = (body or {}).get("runtimeRecovery", {})
    lifecycle = (body or {}).get("validatorLifecycleRecovery", {})
    recovery_ready[name] = {
        "startupSnapshotRestored": recovery.get("startupSnapshotRestored"),
        "operatorRestartReady": recovery.get("operatorRestartReady"),
        "lifecycleSummary": lifecycle.get("summary"),
        "lifecycleRestartReady": lifecycle.get("restartReady"),
        "lifecycleCheckpointFinalized": lifecycle.get("checkpointFinalized"),
    }

result = {
    "scenario": "dag-three-validator-durable-restart-harness",
    "capturedAt": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "failure": {
        "phase": failure_phase or None,
        "reason": failure_reason or None,
    },
    "beforeRestart": {
        "comparison": before_summary,
        "nodeA": compact(before_nodes["nodeA"]),
        "nodeB": compact(before_nodes["nodeB"]),
        "nodeC": compact(before_nodes["nodeC"]),
    },
    "afterRestart": {
        "comparison": after_summary,
        "nodeA": compact(after_nodes["nodeA"]),
        "nodeB": compact(after_nodes["nodeB"]),
        "nodeC": compact(after_nodes["nodeC"]),
    },
    "durableRestart": {
        "preRestartConverged": before_summary["sameValidatorTarget"]
        and before_summary["allFinalized"]
        and before_summary["allVoteQuorumMet"],
        "postRestartConverged": after_summary["sameValidatorTarget"]
        and after_summary["allFinalized"]
        and after_summary["allVoteQuorumMet"],
        "recoveryReadinessPerNode": recovery_ready,
        "allRestartReady": all(
            ready["startupSnapshotRestored"]
            and ready["operatorRestartReady"]
            and ready["lifecycleSummary"] == "ready"
            for ready in recovery_ready.values()
        ),
    },
    "logs": {
        "nodeA": f"{log_dir}/node-a.log",
        "nodeB": f"{log_dir}/node-b.log",
        "nodeC": f"{log_dir}/node-c.log",
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
rm -rf "$NODE_A_DIR" "$NODE_B_DIR" "$NODE_C_DIR"
mkdir -p "$NODE_A_DIR" "$NODE_B_DIR" "$NODE_C_DIR" "$LOG_DIR"
rm -f "$RESULT_FILE" "$PID_FILE"

BIN="$(resolve_binary)"

echo "Step 1/8: start node-a / node-b / node-c"
NODE_A_PID="$(start_node_a "${LOG_DIR}/node-a.log")"
NODE_B_PID="$(start_node_b "${LOG_DIR}/node-b.log")"
NODE_C_PID="$(start_node_c "${LOG_DIR}/node-c.log")"
printf '%s\n%s\n%s\n' "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" >"$PID_FILE"

echo "Step 2/8: wait for RPC health on all validators"
wait_for_chain_info "$NODE_A_RPC" 60 || {
  echo "node-a did not start in time" >&2
  exit 1
}
wait_for_chain_info "$NODE_B_RPC" 60 || {
  echo "node-b did not start in time" >&2
  exit 1
}
wait_for_chain_info "$NODE_C_RPC" 60 || {
  echo "node-c did not start in time" >&2
  exit 1
}

if (( NETWORK_WARMUP_SECS > 0 )); then
  echo "Warmup: allow peer mesh to settle for ${NETWORK_WARMUP_SECS}s"
  sleep "$NETWORK_WARMUP_SECS"
fi

echo "Step 3/8: wait for natural checkpoint/finality convergence"
wait_for_convergence "before" "$INITIAL_WAIT_ATTEMPTS" 0 || {
  write_result_snapshot "failed" "before" "initial 3-validator natural convergence did not complete in time"
  echo "initial 3-validator natural convergence did not complete in time" >&2
  exit 1
}

echo "Step 4/8: capture pre-restart state"
fetch_chain_info_file "$NODE_A_RPC" "${STATE_DIR}/node-a-before.json"
fetch_chain_info_file "$NODE_B_RPC" "${STATE_DIR}/node-b-before.json"
fetch_chain_info_file "$NODE_C_RPC" "${STATE_DIR}/node-c-before.json"

echo "Step 5/8: restart all validators with the same data directories"
stop_harness
NODE_A_PID="$(start_node_a "${LOG_DIR}/node-a.log")"
NODE_B_PID="$(start_node_b "${LOG_DIR}/node-b.log")"
NODE_C_PID="$(start_node_c "${LOG_DIR}/node-c.log")"
printf '%s\n%s\n%s\n' "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" >"$PID_FILE"
wait_for_chain_info "$NODE_A_RPC" 60 || {
  echo "node-a did not restart in time" >&2
  exit 1
}
wait_for_chain_info "$NODE_B_RPC" 60 || {
  echo "node-b did not restart in time" >&2
  exit 1
}
wait_for_chain_info "$NODE_C_RPC" 60 || {
  echo "node-c did not restart in time" >&2
  exit 1
}

if (( NETWORK_WARMUP_SECS > 0 )); then
  echo "Warmup: allow restarted peers to settle for ${NETWORK_WARMUP_SECS}s"
  sleep "$NETWORK_WARMUP_SECS"
fi

echo "Step 6/8: wait for post-restart convergence and recovery readiness"
wait_for_convergence "after" "$RESTART_WAIT_ATTEMPTS" 1 || {
  write_result_snapshot "failed" "after" "post-restart 3-validator convergence did not complete in time"
  echo "post-restart 3-validator convergence did not complete in time" >&2
  exit 1
}

echo "Step 7/8: capture post-restart state"
fetch_chain_info_file "$NODE_A_RPC" "${STATE_DIR}/node-a-after.json"
fetch_chain_info_file "$NODE_B_RPC" "${STATE_DIR}/node-b-after.json"
fetch_chain_info_file "$NODE_C_RPC" "${STATE_DIR}/node-c-after.json"
write_result_snapshot "passed"

echo
echo "Step 8/8: DAG 3-validator durable restart harness completed."
echo
cat "$RESULT_FILE"
echo
echo "Logs:"
echo "  node-a: ${LOG_DIR}/node-a.log"
echo "  node-b: ${LOG_DIR}/node-b.log"
echo "  node-c: ${LOG_DIR}/node-c.log"
echo "Result:"
echo "  ${RESULT_FILE}"
echo
echo "Status:"
echo "  ./scripts/dag_three_validator_recovery_harness.sh status"
echo "Stop:"
echo "  ./scripts/dag_three_validator_recovery_harness.sh stop"
