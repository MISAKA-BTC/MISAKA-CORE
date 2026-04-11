#!/usr/bin/env bash
# Self-host validator join helper for the official/public testnet.
# Public observer package users should use distribution/public-node/start-public-node.*.
# This script expects operator-provided genesis + seed metadata and then delegates to
# scripts/start-node.sh as a lower-level source-build launcher.
set -euo pipefail

CHAIN_ID=2
NODE_NAME=""
DATA_DIR="/opt/misaka/data"
RPC_PORT=3001
P2P_PORT=16110
SEEDS=""
SEED_PUBKEYS=""
VALIDATOR_INDEX=""
VALIDATORS="${MISAKA_TESTNET_VALIDATORS:-3}"
RPC_PEERS=""
LOG_LEVEL="info"
GENESIS_PATH="${MISAKA_GENESIS_PATH:-}"
ADVERTISE_ADDR="${MISAKA_ADVERTISE_ADDR:-}"

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
        --genesis-path) GENESIS_PATH="$2"; shift 2 ;;
        --advertise-addr) ADVERTISE_ADDR="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/native_toolchain.sh"
SEEDS_FILE="$SCRIPT_DIR/../configs/testnet-seeds.txt"
PUBKEYS_FILE="$SCRIPT_DIR/../configs/testnet-seed-pubkeys.txt"

read_csv() {
    local file="$1" out=""
    if [ -f "$file" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line="$(echo "$line" | sed 's/#.*//' | xargs)"
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

validate_public_advertise_addr() {
    local addr="$1"
    if ! command -v python3 >/dev/null 2>&1; then
        echo "WARNING: python3 not found; skipping preflight public-routable validation for $addr"
        return 0
    fi
    python3 - "$addr" <<'PY'
import ipaddress
import socket
import sys

addr = sys.argv[1]
host, port = addr.rsplit(":", 1)
try:
    ip = ipaddress.ip_address(host)
except ValueError:
    raise SystemExit(f"not an IP literal: {addr}")
try:
    port_i = int(port)
except ValueError:
    raise SystemExit(f"port is not numeric: {addr}")
if port_i <= 0 or port_i > 65535:
    raise SystemExit(f"port out of range: {addr}")
doc_nets = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("100.64.0.0/10"),
]
if (
    ip.is_unspecified
    or ip.is_loopback
    or ip.is_private
    or ip.is_link_local
    or ip.is_multicast
    or ip.is_reserved
    or any(ip in net for net in doc_nets)
):
    raise SystemExit(f"not public-routable: {addr}")
PY
}

if [ -z "$SEEDS" ] && [ -f "$SEEDS_FILE" ]; then
    SEEDS="$(read_csv "$SEEDS_FILE")"
fi
if [ -z "$SEED_PUBKEYS" ] && [ -f "$PUBKEYS_FILE" ]; then
    SEED_PUBKEYS="$(read_csv "$PUBKEYS_FILE")"
fi

SEEDS_COUNT="$(count_csv "$SEEDS")"
PUBKEYS_COUNT="$(count_csv "$SEED_PUBKEYS")"
if [ "$SEEDS_COUNT" -eq 0 ]; then
    echo "ERROR: no seeds configured"
    echo "       testnet-join.sh is for joining an existing official/public seed."
    echo "       Populate configs/testnet-seeds.txt or pass --seeds explicitly."
    exit 1
fi
if [ "$SEEDS_COUNT" -ne "$PUBKEYS_COUNT" ]; then
    echo "ERROR: seeds ($SEEDS_COUNT) and seed-pubkeys ($PUBKEYS_COUNT) count mismatch"
    echo "       Each seed entry must have a matching ML-DSA-65 pubkey."
    exit 1
fi

if [ -z "$VALIDATOR_INDEX" ]; then
    echo "ERROR: --index required (your validator index, e.g. 1, 2, ...)"
    exit 1
fi
if [ -z "$GENESIS_PATH" ]; then
    echo "ERROR: --genesis-path required for validator/self-host join"
    echo "       Copy the operator's genesis_committee.toml first."
    echo "       Public observer join should use distribution/public-node."
    exit 1
fi
if [ ! -f "$GENESIS_PATH" ]; then
    echo "ERROR: genesis file not found: $GENESIS_PATH"
    exit 1
fi

[ -z "$NODE_NAME" ] && NODE_NAME="misaka-testnet-sr${VALIDATOR_INDEX}"

if [ -z "$ADVERTISE_ADDR" ]; then
    PUBLIC_IP="$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "")"
    if [ -z "$PUBLIC_IP" ]; then
        echo "ERROR: Could not detect public IP; pass --advertise-addr YOUR_IP:$P2P_PORT"
        exit 1
    fi
    ADVERTISE_ADDR="$PUBLIC_IP:$P2P_PORT"
fi
if ! validate_public_advertise_addr "$ADVERTISE_ADDR"; then
    echo "ERROR: advertise address is not public-routable: $ADVERTISE_ADDR"
    echo "       Pass --advertise-addr PUBLIC_IP:$P2P_PORT with a real public IPv4 address."
    exit 1
fi

if [ -z "$RPC_PEERS" ] && [ -n "$SEEDS" ]; then
    RPC_PEERS=$(
        echo "$SEEDS" \
            | tr ',' '\n' \
            | sed -E "s/:[0-9]+$/:${RPC_PORT}/; s#^#http://#" \
            | tr '\n' ',' \
            | sed 's/,$//'
    )
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet - Self-host Validator Join               ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Node:     $NODE_NAME"
echo "║  Index:    $VALIDATOR_INDEX / $VALIDATORS"
echo "║  Seeds:    ${SEEDS:-"(none)"}"
echo "║  Genesis:  $GENESIS_PATH"
echo "║  Public:   $ADVERTISE_ADDR"
echo "╚═══════════════════════════════════════════════════════════╝"

sudo mkdir -p "$DATA_DIR"
sudo chown "$(whoami)" "$DATA_DIR"

export MISAKA_CHAIN_ID="$CHAIN_ID"
export MISAKA_NODE_NAME="$NODE_NAME"
export MISAKA_DATA_DIR="$DATA_DIR"
export MISAKA_RPC_PORT="$RPC_PORT"
export MISAKA_P2P_PORT="$P2P_PORT"
export MISAKA_VALIDATORS="$VALIDATORS"
export MISAKA_VALIDATOR_INDEX="$VALIDATOR_INDEX"
export MISAKA_GENESIS_PATH="$GENESIS_PATH"
export MISAKA_MODE="public"
export MISAKA_NODE_ROLE="validator"
export MISAKA_SEEDS="$SEEDS"
export MISAKA_SEED_PUBKEYS="$SEED_PUBKEYS"
export MISAKA_RPC_PEERS="$RPC_PEERS"
export MISAKA_ADVERTISE_ADDR="$ADVERTISE_ADDR"
export MISAKA_LOG_LEVEL="$LOG_LEVEL"
export MISAKA_RPC_AUTH_MODE="${MISAKA_RPC_AUTH_MODE:-open}"
export MISAKA_BUILD_FEATURES="${MISAKA_BUILD_FEATURES:-dag,testnet}"

exec "$SCRIPT_DIR/start-node.sh"
