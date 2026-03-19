#!/bin/bash
# MISAKA Testnet Launcher
#
# Usage:
#   ./scripts/testnet.sh              # 4 public validators, 10s blocks
#   ./scripts/testnet.sh 2 60         # 2 validators, 60s blocks
#   ./scripts/testnet.sh stop         # stop all nodes
#   ./scripts/testnet.sh hidden 4 10  # hidden-mode validators + 1 seed node

set -e

MODE=${1:-public}
if [ "$MODE" = "stop" ]; then
    [ -f ./testnet.pids ] && while read pid; do kill "$pid" 2>/dev/null || true; done < ./testnet.pids && rm -f ./testnet.pids && echo "Testnet stopped." || echo "No testnet running."
    exit 0
fi

# If first arg is a number, it's validator count (public mode)
if [[ "$MODE" =~ ^[0-9]+$ ]]; then
    VALIDATORS=$MODE; MODE="public"; BLOCK_TIME=${2:-10}
elif [ "$MODE" = "hidden" ] || [ "$MODE" = "seed" ] || [ "$MODE" = "public" ]; then
    VALIDATORS=${2:-4}; BLOCK_TIME=${3:-10}
else
    VALIDATORS=${1:-4}; BLOCK_TIME=${2:-10}; MODE="public"
fi

BASE_RPC=3001; BASE_P2P=6690; LOG_DIR=./testnet-logs; PID_FILE=./testnet.pids
G='\033[0;32m'; B='\033[0;34m'; Y='\033[1;33m'; N='\033[0m'

# Stop existing
[ -f "$PID_FILE" ] && while read pid; do kill "$pid" 2>/dev/null || true; done < "$PID_FILE" && rm -f "$PID_FILE" 2>/dev/null

# Build
echo -e "${B}Building...${N}"
cargo build --release -p misaka-node 2>&1 | tail -3
BIN=./target/release/misaka-node
[ -f "$BIN" ] || { cargo build -p misaka-node 2>&1 | tail -3; BIN=./target/debug/misaka-node; }

mkdir -p "$LOG_DIR"; rm -f "$PID_FILE"

echo ""
echo -e "${G}╔════════════════════════════════════════════════════════════╗${N}"
echo -e "${G}║  MISAKA Testnet  |  mode=$MODE  |  validators=$VALIDATORS  |  block=${BLOCK_TIME}s  ║${N}"
echo -e "${G}╚════════════════════════════════════════════════════════════╝${N}"
echo ""

# If hidden mode, start a seed node first
SEED_PORT=""
if [ "$MODE" = "hidden" ]; then
    SEED_RPC=$((BASE_RPC + VALIDATORS))
    SEED_P2P=$((BASE_P2P + VALIDATORS))
    SEED_PORT=$SEED_P2P
    echo -e "${Y}Starting seed node${N} | RPC=:${SEED_RPC} | P2P=:${SEED_P2P}"
    $BIN --name "seed-0" --mode seed --rpc-port "$SEED_RPC" --p2p-port "$SEED_P2P" \
         --validators "$VALIDATORS" --block-time "$BLOCK_TIME" --log-level info \
         > "${LOG_DIR}/seed-0.log" 2>&1 &
    echo $! >> "$PID_FILE"
    sleep 1
fi

for i in $(seq 0 $((VALIDATORS - 1))); do
    RPC=$((BASE_RPC + i)); P2P=$((BASE_P2P + i))
    # Build peer list
    PEERS=""
    for j in $(seq 0 $((VALIDATORS - 1))); do
        [ "$j" != "$i" ] && { [ -n "$PEERS" ] && PEERS="${PEERS},"; PEERS="${PEERS}127.0.0.1:$((BASE_P2P + j))"; }
    done
    # Add seed node to peers if hidden mode
    [ -n "$SEED_PORT" ] && { [ -n "$PEERS" ] && PEERS="${PEERS},"; PEERS="${PEERS}127.0.0.1:${SEED_PORT}"; }

    NODE_MODE=$MODE
    EXTRA_FLAGS=""
    [ "$MODE" = "hidden" ] && EXTRA_FLAGS="--hide-my-ip"

    echo -e "${B}Starting node-${i} (${NODE_MODE})${N} | RPC=:${RPC} | P2P=:${P2P}"
    $BIN --name "node-${i}" --mode "$NODE_MODE" --validator-index "$i" --validators "$VALIDATORS" \
         --rpc-port "$RPC" --p2p-port "$P2P" --block-time "$BLOCK_TIME" --peers "$PEERS" \
         --log-level info $EXTRA_FLAGS \
         > "${LOG_DIR}/node-${i}.log" 2>&1 &
    echo $! >> "$PID_FILE"
done

echo ""
echo -e "${G}Testnet running with $VALIDATORS validators (mode=$MODE).${N}"
echo ""
echo "Monitor:  tail -f ${LOG_DIR}/node-0.log"
echo "Status:   curl -s -X POST http://127.0.0.1:3001/api/get_chain_info -H 'Content-Type: application/json' -d '{}' | python3 -m json.tool"
echo "Explorer: cd misaka-explorer && NEXT_PUBLIC_USE_MOCK=false npm run dev"
echo "Stop:     ./scripts/testnet.sh stop"
echo ""
echo "Examples:"
echo "  ./scripts/testnet.sh              # 4 public nodes"
echo "  ./scripts/testnet.sh hidden 4 10  # 4 hidden validators + seed"
