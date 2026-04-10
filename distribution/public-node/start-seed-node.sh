#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA Testnet — Seed Node 起動
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/misaka-node"
CONFIG="$SCRIPT_DIR/config/seed-node.toml"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: misaka-node binary not found at $BINARY"
    exit 1
fi

chmod +x "$BINARY" 2>/dev/null || true

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet — Seed Node                              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Config : $CONFIG"
echo "P2P    : 6690 (seed)"
echo "RPC    : http://localhost:3001"
echo ""
echo "停止するには Ctrl+C を押してください"
echo "─────────────────────────────────────────────────────────────"
echo ""

export MISAKA_RPC_AUTH_MODE=open

exec "$BINARY" \
    --config "$CONFIG" \
    --data-dir "$SCRIPT_DIR/misaka-data" \
    --mode seed \
    --chain-id 2
