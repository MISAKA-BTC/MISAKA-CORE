#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA Testnet — Public Node 起動 (Linux / macOS)
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/misaka-node"
CONFIG="$SCRIPT_DIR/config/public-node.toml"
SEEDS_FILE="$SCRIPT_DIR/config/seeds.txt"
GENESIS="$SCRIPT_DIR/config/genesis_committee.toml"
DATA_DIR="$SCRIPT_DIR/misaka-data"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: misaka-node binary not found at $BINARY"
    echo "Release archive が正しく展開されているか確認してください。"
    exit 1
fi

chmod +x "$BINARY" 2>/dev/null || true

mkdir -p "$DATA_DIR"
# First run: copy bundled validator key so genesis_committee.toml matches (authority 0)
if [ ! -f "$DATA_DIR/validator.key" ] && [ -f "$SCRIPT_DIR/config/bundled-validator.key" ]; then
    cp "$SCRIPT_DIR/config/bundled-validator.key" "$DATA_DIR/validator.key"
    chmod 600 "$DATA_DIR/validator.key" 2>/dev/null || true
fi

if [ ! -f "$GENESIS" ]; then
    echo "ERROR: $GENESIS not found"
    exit 1
fi

# seeds.txt から接続先を読む
SEEDS=""
if [ -f "$SEEDS_FILE" ]; then
    while IFS= read -r line; do
        line="$(echo "$line" | sed 's/#.*//' | xargs)"
        [ -z "$line" ] && continue
        [ -n "$SEEDS" ] && SEEDS="$SEEDS,"
        SEEDS="$SEEDS$line"
    done < "$SEEDS_FILE"
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet — Public Node                            ║"
echo "║  PQ Signature: ML-DSA-65 (FIPS 204)                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Config : $CONFIG"
echo "Seeds  : $SEEDS"
echo "RPC    : http://localhost:3001"
echo "P2P    : 6691"
echo "Data   : $DATA_DIR"
echo "Genesis: $GENESIS"
echo ""
echo "停止するには Ctrl+C を押してください"
echo "─────────────────────────────────────────────────────────────"
echo ""

export MISAKA_RPC_AUTH_MODE=open

exec "$BINARY" \
    --config "$CONFIG" \
    --data-dir "$DATA_DIR" \
    --genesis-path "$GENESIS" \
    --seeds "$SEEDS" \
    --chain-id 2
