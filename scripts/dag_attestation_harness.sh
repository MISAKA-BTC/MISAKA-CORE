#!/bin/bash
# Controlled local harness for DAG checkpoint vote gossip + remote quorum.
#
# This does not provide natural multi-node DAG sync.
# It reuses the same checkpoint snapshot across two validators so that
# checkpoint vote gossip and quorum formation can be observed locally.
#
# Usage:
#   ./scripts/dag_attestation_harness.sh
#   ./scripts/dag_attestation_harness.sh stop
#
# Optional env:
#   MISAKA_BIN=/path/to/misaka-node
#   MISAKA_SKIP_BUILD=1
#   MISAKA_HARNESS_DIR=/custom/writable/path

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STATE_DIR="${MISAKA_HARNESS_DIR:-${ROOT_DIR}/.tmp/dag-attestation-harness}"
BOOTSTRAP_DIR="${STATE_DIR}/bootstrap"
NODE_A_DIR="${STATE_DIR}/node-a"
NODE_B_DIR="${STATE_DIR}/node-b"
LOG_DIR="${STATE_DIR}/logs"
PID_FILE="${STATE_DIR}/pids"

BOOTSTRAP_RPC=4111
NODE_A_RPC=4112
NODE_B_RPC=4113
BOOTSTRAP_P2P=7711
NODE_A_P2P=7712
NODE_B_P2P=7713

mkdir -p "$STATE_DIR" "$LOG_DIR"

stop_harness() {
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do
            [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
        done < "$PID_FILE"
        rm -f "$PID_FILE"
        echo "DAG attestation harness stopped."
    else
        echo "No DAG attestation harness is running."
    fi
}

if [ "${1:-}" = "stop" ]; then
    stop_harness
    exit 0
fi

stop_harness
rm -rf "$BOOTSTRAP_DIR" "$NODE_A_DIR" "$NODE_B_DIR"
mkdir -p "$BOOTSTRAP_DIR" "$NODE_A_DIR" "$NODE_B_DIR" "$LOG_DIR"

BIN="${MISAKA_BIN:-}"
if [ -z "$BIN" ]; then
    if [ "${MISAKA_SKIP_BUILD:-0}" != "1" ]; then
        echo "Building misaka-node (experimental_dag, stark-stub)..."
        cargo build -p misaka-node --features experimental_dag,stark-stub >/dev/null
    fi

    if [ -x "${ROOT_DIR}/target/debug/misaka-node" ]; then
        BIN="${ROOT_DIR}/target/debug/misaka-node"
    elif [ -x "${ROOT_DIR}/target/release/misaka-node" ]; then
        BIN="${ROOT_DIR}/target/release/misaka-node"
    else
        echo "misaka-node binary not found. Set MISAKA_BIN or build the workspace first." >&2
        exit 1
    fi
fi

wait_for_chain_info() {
    local port="$1"
    local attempts="${2:-60}"
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

wait_for_finalized_checkpoint() {
    local port="$1"
    local attempts="${2:-90}"
    local i
    for i in $(seq 1 "$attempts"); do
        local body
        body="$(curl -fsS -X POST "http://127.0.0.1:${port}/api/get_chain_info" \
            -H 'content-type: application/json' \
            -d '{}' 2>/dev/null || true)"
        if [ -n "$body" ] && printf '%s' "$body" | grep -q '"currentCheckpointFinalized":true'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

echo "Step 1/5: bootstrap a finalized checkpoint"
export MISAKA_DAG_EXPERIMENTAL=1
"$BIN" \
    --name "dag-bootstrap" \
    --validator \
    --validator-index 0 \
    --validators 1 \
    --block-time 5 \
    --dag-checkpoint-interval 1 \
    --rpc-port "$BOOTSTRAP_RPC" \
    --p2p-port "$BOOTSTRAP_P2P" \
    --data-dir "$BOOTSTRAP_DIR" \
    > "${LOG_DIR}/bootstrap.log" 2>&1 &
BOOTSTRAP_PID=$!
echo "$BOOTSTRAP_PID" >> "$PID_FILE"

wait_for_chain_info "$BOOTSTRAP_RPC" 60 || {
    echo "bootstrap node did not start in time" >&2
    exit 1
}

wait_for_finalized_checkpoint "$BOOTSTRAP_RPC" 90 || {
    echo "bootstrap node did not finalize a checkpoint in time" >&2
    exit 1
}

kill "$BOOTSTRAP_PID" 2>/dev/null || true
wait "$BOOTSTRAP_PID" 2>/dev/null || true
rm -f "$PID_FILE"

SNAPSHOT_FILE="${BOOTSTRAP_DIR}/dag_runtime_snapshot.json"
if [ ! -f "$SNAPSHOT_FILE" ]; then
    echo "bootstrap snapshot not found: ${SNAPSHOT_FILE}" >&2
    exit 1
fi

echo "Step 2/5: sanitize snapshot so validator A/B can re-attest cleanly"
python3 - "$SNAPSHOT_FILE" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["known_validators"] = []
data["latest_checkpoint_vote"] = None
data["latest_checkpoint_finality"] = None
data["checkpoint_vote_pool"] = []
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

cp "$SNAPSHOT_FILE" "${NODE_A_DIR}/dag_runtime_snapshot.json"
cp "$SNAPSHOT_FILE" "${NODE_B_DIR}/dag_runtime_snapshot.json"

echo "Step 3/5: start node-b with the shared checkpoint"
"$BIN" \
    --name "dag-node-b" \
    --validator \
    --validator-index 1 \
    --validators 2 \
    --block-time 600 \
    --dag-checkpoint-interval 50 \
    --rpc-port "$NODE_B_RPC" \
    --p2p-port "$NODE_B_P2P" \
    --data-dir "$NODE_B_DIR" \
    > "${LOG_DIR}/node-b.log" 2>&1 &
NODE_B_PID=$!
echo "$NODE_B_PID" >> "$PID_FILE"
wait_for_chain_info "$NODE_B_RPC" 60 || {
    echo "node-b did not start in time" >&2
    exit 1
}

echo "Step 4/5: start node-a and gossip its vote to node-b"
"$BIN" \
    --name "dag-node-a" \
    --validator \
    --validator-index 0 \
    --validators 2 \
    --block-time 600 \
    --dag-checkpoint-interval 50 \
    --rpc-port "$NODE_A_RPC" \
    --p2p-port "$NODE_A_P2P" \
    --dag-rpc-peers "http://127.0.0.1:${NODE_B_RPC}" \
    --data-dir "$NODE_A_DIR" \
    > "${LOG_DIR}/node-a.log" 2>&1 &
NODE_A_PID=$!
echo "$NODE_A_PID" >> "$PID_FILE"
wait_for_chain_info "$NODE_A_RPC" 60 || {
    echo "node-a did not start in time" >&2
    exit 1
}

echo "Step 5/5: wait for remote quorum on node-b"
wait_for_finalized_checkpoint "$NODE_B_RPC" 20 || {
    echo "node-b did not reach finalized checkpoint after remote gossip" >&2
    exit 1
}

echo
echo "DAG attestation harness is running."
echo
echo "Node B attestation view:"
curl -s -X POST "http://127.0.0.1:${NODE_B_RPC}/api/get_chain_info" \
    -H 'content-type: application/json' \
    -d '{}'
echo
echo
echo "Logs:"
echo "  bootstrap: ${LOG_DIR}/bootstrap.log"
echo "  node-a:    ${LOG_DIR}/node-a.log"
echo "  node-b:    ${LOG_DIR}/node-b.log"
echo
echo "Stop:"
echo "  ./scripts/dag_attestation_harness.sh stop"
