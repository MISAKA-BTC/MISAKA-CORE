#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA Network — テストネット起動 (3バリデータ)
#
#  Phase 1: validator.key 生成 + 公開鍵取得
#  Phase 2: genesis_committee.toml 自動生成
#  Phase 3: 3ノード起動 + ヘルスチェック
# ═══════════════════════════════════════════════════════════
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$PROJECT_DIR/target/release/misaka-node"
CHAIN_ID=2
GENESIS="/tmp/misaka-genesis.toml"

if [ ! -f "$BINARY" ]; then
    echo "Building..."
    cd "$PROJECT_DIR"
    cargo build --release -p misaka-node --features dag,testnet 2>&1 | tail -3
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet — 3 Validator Nodes (localhost)          ║"
echo "╚═══════════════════════════════════════════════════════════╝"

# Kill any existing nodes
pkill -f "misaka-node" 2>/dev/null || true
sleep 1

# ── Phase 1: Generate validator keys ──
echo ""
echo "▶ Phase 1: Generating validator keys..."

mkdir -p /tmp/misaka-v0 /tmp/misaka-v1 /tmp/misaka-v2

PK0=$($BINARY --emit-validator-pubkey --data-dir /tmp/misaka-v0 --chain-id $CHAIN_ID 2>/dev/null)
PK1=$($BINARY --emit-validator-pubkey --data-dir /tmp/misaka-v1 --chain-id $CHAIN_ID 2>/dev/null)
PK2=$($BINARY --emit-validator-pubkey --data-dir /tmp/misaka-v2 --chain-id $CHAIN_ID 2>/dev/null)

echo "  V0 pubkey: ${PK0:0:16}...${PK0: -8}"
echo "  V1 pubkey: ${PK1:0:16}...${PK1: -8}"
echo "  V2 pubkey: ${PK2:0:16}...${PK2: -8}"

# ── Phase 2: Generate genesis committee manifest ──
echo ""
echo "▶ Phase 2: Creating genesis_committee.toml..."

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

echo "  Genesis: $GENESIS"

# ── Phase 3: Start nodes ──
echo ""
echo "▶ Phase 3: Starting validators..."

# RPC auth is required by default; use "open" for local dev testnet
export MISAKA_RPC_AUTH_MODE=open

$BINARY \
    --data-dir /tmp/misaka-v0 \
    --genesis-path "$GENESIS" \
    --rpc-port 3000 \
    --p2p-port 16110 \
    --validators 3 \
    --validator-index 0 \
    --chain-id $CHAIN_ID \
    > /tmp/misaka-v0/node.log 2>&1 &
PID0=$!

$BINARY \
    --data-dir /tmp/misaka-v1 \
    --genesis-path "$GENESIS" \
    --rpc-port 3001 \
    --p2p-port 16111 \
    --validators 3 \
    --validator-index 1 \
    --chain-id $CHAIN_ID \
    > /tmp/misaka-v1/node.log 2>&1 &
PID1=$!

$BINARY \
    --data-dir /tmp/misaka-v2 \
    --genesis-path "$GENESIS" \
    --rpc-port 3002 \
    --p2p-port 16112 \
    --validators 3 \
    --validator-index 2 \
    --chain-id $CHAIN_ID \
    > /tmp/misaka-v2/node.log 2>&1 &
PID2=$!

sleep 3

echo ""
echo "Validators started:"
echo "  V0: PID=$PID0, RPC=http://localhost:3000, P2P=16110"
echo "  V1: PID=$PID1, RPC=http://localhost:3001, P2P=16111"
echo "  V2: PID=$PID2, RPC=http://localhost:3002, P2P=16112"
echo ""

# Health check
for port in 3000 3001 3002; do
    HEALTH=$(curl -s http://localhost:$port/api/health 2>/dev/null || echo "FAIL")
    echo "  V$((port-3000)) health: $HEALTH"
done

echo ""
echo "=== E2E Test: Submit TX to V0 ==="
TX_RESULT=$(curl -s -X POST http://localhost:3000/api/submit_tx \
    -H "Content-Type: application/json" \
    -d '{"version":1,"tx_type":6,"inputs":[],"outputs":[{"amount":1000}],"fee":10}')
echo "  Result: $TX_RESULT"

echo ""
echo "=== Status of all validators ==="
for port in 3000 3001 3002; do
    STATUS=$(curl -s http://localhost:$port/api/status 2>/dev/null || echo "FAIL")
    echo "  V$((port-3000)): $STATUS"
done

echo ""
echo "=== Chain Info ==="
curl -s http://localhost:3000/api/get_chain_info 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "chain info unavailable"

echo ""
echo "Genesis: $GENESIS"
echo "To stop: pkill -f misaka-node"
echo "Logs: tail -f /tmp/misaka-v{0,1,2}/node.log"
