#!/usr/bin/env bash
set -euo pipefail

CHAIN_ID=2
NODE_NAME=""
DATA_DIR="/opt/misaka/data"
RPC_PORT=3001
# v0.5.9: Narwhal relay listens on 16110 by convention.
P2P_PORT=16110
SEEDS=""
SEED_PUBKEYS=""
VALIDATOR_INDEX=""
VALIDATORS=3
RPC_PEERS=""
LOG_LEVEL="info"

while [[ $# -gt 0 ]]; do
    case $1 in
        --seeds) SEEDS="$2"; shift 2 ;;
        --seed-pubkeys) SEED_PUBKEYS="$2"; shift 2 ;;
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

# v0.5.9: read both seeds and seed pubkeys from disk when not passed
# explicitly. Narwhal relay hardcodes PK-pinning and refuses to dial
# --seeds without a matching --seed-pubkeys, so both are required.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEEDS_FILE="$SCRIPT_DIR/../configs/testnet-seeds.txt"
PUBKEYS_FILE="$SCRIPT_DIR/../configs/testnet-seed-pubkeys.txt"

read_csv() {
    local file="$1" out=""
    if [ -f "$file" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line=$(echo "$line" | sed 's/#.*//' | xargs)
            [ -z "$line" ] && continue
            if [ -z "$out" ]; then out="$line"; else out="$out,$line"; fi
        done < "$file"
    fi
    printf '%s' "$out"
}

count_csv() {
    local s="$1"
    if [ -z "$s" ]; then printf '0'; else echo "$s" | tr ',' '\n' | grep -c '.'; fi
}

if [ -z "$SEEDS" ]; then
    if [ -f "$SEEDS_FILE" ]; then
        SEEDS=$(read_csv "$SEEDS_FILE")
        echo "Seeds from $SEEDS_FILE: $SEEDS"
    else
        echo "ERROR: No --seeds and no configs/testnet-seeds.txt"
        exit 1
    fi
fi
if [ -z "$SEED_PUBKEYS" ]; then
    if [ -f "$PUBKEYS_FILE" ]; then
        SEED_PUBKEYS=$(read_csv "$PUBKEYS_FILE")
        echo "Seed pubkeys from $PUBKEYS_FILE: $(count_csv "$SEED_PUBKEYS") entries"
    else
        echo "ERROR: No --seed-pubkeys and no configs/testnet-seed-pubkeys.txt"
        echo "       Narwhal relay requires ML-DSA-65 PK-pinning for every seed."
        exit 1
    fi
fi

SEEDS_COUNT=$(count_csv "$SEEDS")
PUBKEYS_COUNT=$(count_csv "$SEED_PUBKEYS")
if [ "$SEEDS_COUNT" -ne "$PUBKEYS_COUNT" ]; then
    echo "ERROR: seeds ($SEEDS_COUNT) and seed-pubkeys ($PUBKEYS_COUNT) count mismatch"
    echo "       Each seed entry must have a matching pubkey on the same line."
    exit 1
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
# v0.5.9: export MISAKA_RPC_AUTH_MODE=open so this dev/validator node
# doesn't fail-closed on write routes. Remove this and provision a
# proper MISAKA_RPC_API_KEY before running on mainnet.
export MISAKA_RPC_AUTH_MODE=open
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
    --seed-pubkeys "$SEED_PUBKEYS" \
    --dag-rpc-peers "$RPC_PEERS" \
    --advertise-addr "$PUBLIC_IP:$P2P_PORT" \
    --log-level "$LOG_LEVEL"
