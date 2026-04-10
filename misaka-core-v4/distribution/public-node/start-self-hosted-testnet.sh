#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA — セルフホスト テストネット
#  seed が落ちている時にローカルで 3 validator を起動して動作確認
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/misaka-node"
CHAIN_ID=2
GENESIS="/tmp/misaka-self-genesis.toml"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: misaka-node not found at $BINARY"
    exit 1
fi

chmod +x "$BINARY" 2>/dev/null || true

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Self-Hosted Testnet (3 Validators, localhost)    ║"
echo "╚═══════════════════════════════════════════════════════════╝"

# 既存のノードを停止
pkill -f "misaka-node" 2>/dev/null || true
sleep 1

# データディレクトリ
mkdir -p /tmp/misaka-v0 /tmp/misaka-v1 /tmp/misaka-v2

echo ""
echo "▶ Phase 1: Generating validator keys..."

PK0=$("$BINARY" --emit-validator-pubkey --data-dir /tmp/misaka-v0 --chain-id $CHAIN_ID 2>/dev/null | grep "^0x")
PK1=$("$BINARY" --emit-validator-pubkey --data-dir /tmp/misaka-v1 --chain-id $CHAIN_ID 2>/dev/null | grep "^0x")
PK2=$("$BINARY" --emit-validator-pubkey --data-dir /tmp/misaka-v2 --chain-id $CHAIN_ID 2>/dev/null | grep "^0x")

echo "  V0: ${PK0:0:20}..."
echo "  V1: ${PK1:0:20}..."
echo "  V2: ${PK2:0:20}..."

echo ""
echo "▶ Phase 2: Creating genesis committee..."

cat > "$GENESIS" <<EOF
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "$PK0"
stake = 10000
network_address = "127.0.0.1:16110"

[[committee.validators]]
authority_index = 1
public_key = "$PK1"
stake = 10000
network_address = "127.0.0.1:16111"

[[committee.validators]]
authority_index = 2
public_key = "$PK2"
stake = 10000
network_address = "127.0.0.1:16112"
EOF

echo ""
echo "▶ Phase 3: Starting 3 validators..."

export MISAKA_RPC_AUTH_MODE=open

"$BINARY" --data-dir /tmp/misaka-v0 --genesis-path "$GENESIS" --rpc-port 3010 --p2p-port 16110 --validators 3 --validator-index 0 --chain-id $CHAIN_ID --log-level info > /tmp/misaka-v0/node.log 2>&1 &
PID0=$!

"$BINARY" --data-dir /tmp/misaka-v1 --genesis-path "$GENESIS" --rpc-port 3011 --p2p-port 16111 --validators 3 --validator-index 1 --chain-id $CHAIN_ID --log-level info > /tmp/misaka-v1/node.log 2>&1 &
PID1=$!

"$BINARY" --data-dir /tmp/misaka-v2 --genesis-path "$GENESIS" --rpc-port 3012 --p2p-port 16112 --validators 3 --validator-index 2 --chain-id $CHAIN_ID --log-level info > /tmp/misaka-v2/node.log 2>&1 &
PID2=$!

sleep 5

echo ""
echo "Validators started:"
echo "  V0: PID=$PID0  RPC=http://localhost:3010  P2P=16110"
echo "  V1: PID=$PID1  RPC=http://localhost:3011  P2P=16111"
echo "  V2: PID=$PID2  RPC=http://localhost:3012  P2P=16112"
echo ""

for port in 3010 3011 3012; do
    HEALTH=$(curl -s "http://localhost:$port/api/health" 2>/dev/null || echo '{"status":"starting..."}')
    echo "  V$((port-3010)) health: $HEALTH"
done

echo ""
echo "停止: pkill -f misaka-node"
echo "ログ: tail -f /tmp/misaka-v{0,1,2}/node.log"
echo ""

wait
