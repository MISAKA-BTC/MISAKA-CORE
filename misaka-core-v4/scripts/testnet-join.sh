#!/usr/bin/env bash
set -euo pipefail

CHAIN_ID=2
NODE_NAME=""
DATA_DIR="/opt/misaka/data"
RPC_PORT=3001
P2P_PORT=6690
SEEDS=""
VALIDATOR_INDEX=""
VALIDATORS=3
RPC_PEERS=""
LOG_LEVEL="info"

while [[ $# -gt 0 ]]; do
    case $1 in
        --seeds) SEEDS="$2"; shift 2 ;;
        --index) VALIDATOR_INDEX="$2"; shift 2 ;;
        --validators) VALIDATORS="$2"; shift 2 ;;
        --name) NODE_NAME="$2"; shift 2 ;;
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        --rpc-port) RPC_PORT="$2"; shift 2 ;;
        --p2p-port) P2P_PORT="$2"; shift 2 ;;
        --rpc-peers) RPC_PEERS="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

if [ -z "$SEEDS" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SEEDS_FILE="$SCRIPT_DIR/../configs/testnet-seeds.txt"
    if [ -f "$SEEDS_FILE" ]; then
        SEEDS=$(grep -v '^#' "$SEEDS_FILE" | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
        echo "Seeds from $SEEDS_FILE: $SEEDS"
    else
        echo "ERROR: No --seeds and no configs/testnet-seeds.txt"
        exit 1
    fi
fi

if [ -z "$VALIDATOR_INDEX" ]; then
    echo "ERROR: --index required (your validator index, e.g. 1, 2, ...)"
    exit 1
fi

[ -z "$NODE_NAME" ] && NODE_NAME="misaka-testnet-sr${VALIDATOR_INDEX}"

PUBLIC_IP=$(curl -s -4 ifconfig.me 2>/dev/null || echo "")
if [ -z "$PUBLIC_IP" ]; then
    echo "ERROR: Could not detect public IP"
    exit 1
fi

if [ -z "$RPC_PEERS" ]; then
    RPC_PEERS=$(echo "$SEEDS" | tr ',' '\n' | sed "s/:${P2P_PORT}/:${RPC_PORT}/g; s/^/http:\/\//" | tr '\n' ',' | sed 's/,$//')
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet - Joining as Validator                   ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Node:     $NODE_NAME"
echo "║  Index:    $VALIDATOR_INDEX / $VALIDATORS"
echo "║  Seeds:    $SEEDS"
echo "║  Public:   $PUBLIC_IP:$P2P_PORT"
echo "╚═══════════════════════════════════════════════════════════╝"

sudo mkdir -p "$DATA_DIR"
sudo chown "$(whoami)" "$DATA_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/target/release/misaka-node"

if [ ! -f "$BINARY" ]; then
    echo "Building misaka-node..."
    cd "$PROJECT_ROOT"
    cargo build -p misaka-node --release --features testnet 2>&1 | tail -3
fi

KEYSTORE="$DATA_DIR/dag_validator_0.enc.json"
if [ ! -f "$KEYSTORE" ]; then
    if [ -z "${MISAKA_VALIDATOR_PASSPHRASE:-}" ]; then
        echo "Enter validator passphrase:"
        read -rs MISAKA_VALIDATOR_PASSPHRASE
        export MISAKA_VALIDATOR_PASSPHRASE
    fi
    "$BINARY" --keygen-only --name "$NODE_NAME" --chain-id $CHAIN_ID \
        --data-dir "$DATA_DIR" --validator --validator-index "$VALIDATOR_INDEX" \
        --validators "$VALIDATORS"
    echo "Keystore created: $KEYSTORE"
fi

echo ""
echo "Starting node..."
"$BINARY" \
    --validator \
    --name "$NODE_NAME" \
    --chain-id $CHAIN_ID \
    --validator-index "$VALIDATOR_INDEX" \
    --validators "$VALIDATORS" \
    --data-dir "$DATA_DIR" \
    --rpc-port "$RPC_PORT" \
    --p2p-port "$P2P_PORT" \
    --seeds "$SEEDS" \
    --dag-rpc-peers "$RPC_PEERS" \
    --advertise-addr "$PUBLIC_IP:$P2P_PORT" \
    --log-level "$LOG_LEVEL"
