#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA Network — ワンクリック ノード起動スクリプト
#  Narwhal/Bullshark Consensus (GhostDAG-free)
#
#  Auto-generates validator.key + genesis_committee.toml
#  if they do not already exist.
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="${MISAKA_DATA_DIR:-$PROJECT_DIR/misaka-data}"
RPC_PORT="${MISAKA_RPC_PORT:-3000}"
P2P_PORT="${MISAKA_P2P_PORT:-6690}"
VALIDATORS="${MISAKA_VALIDATORS:-1}"
VALIDATOR_INDEX="${MISAKA_VALIDATOR_INDEX:-0}"
CHAIN_ID="${MISAKA_CHAIN_ID:-2}"
GENESIS_PATH="${MISAKA_GENESIS_PATH:-$DATA_DIR/genesis_committee.toml}"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Network — Narwhal/Bullshark Node                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  Data dir:        $DATA_DIR"
echo "  RPC port:        $RPC_PORT"
echo "  P2P port:        $P2P_PORT"
echo "  Validators:      $VALIDATORS"
echo "  Validator index: $VALIDATOR_INDEX"
echo "  Chain ID:        $CHAIN_ID"
echo "  Genesis:         $GENESIS_PATH"
echo ""

# ── 1. 依存チェック ──
echo "▶ Checking dependencies..."
if ! command -v cargo &>/dev/null; then
    echo "  Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# ── 2. システム依存 (Ubuntu/Debian) ──
if command -v apt &>/dev/null; then
    echo "  Installing system dependencies..."
    sudo apt update -qq
    sudo apt install -y -qq pkg-config libssl-dev build-essential clang cmake 2>/dev/null || true
fi

# ── 3. ビルド ──
echo "▶ Building MISAKA node (Narwhal mode)..."
cd "$PROJECT_DIR"
cargo build --release -p misaka-node --features dag,testnet 2>&1 | tail -5

BINARY="$PROJECT_DIR/target/release/misaka-node"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed — binary not found at $BINARY"
    exit 1
fi
echo "  Binary: $BINARY"

# ── 4. データディレクトリ ──
mkdir -p "$DATA_DIR"

# ── 5. Genesis 自動生成 (未作成の場合) ──
if [ ! -f "$GENESIS_PATH" ]; then
    echo "▶ Generating genesis committee manifest..."

    PK=$($BINARY --emit-validator-pubkey --data-dir "$DATA_DIR" --chain-id "$CHAIN_ID" 2>/dev/null)
    echo "  Validator pubkey: ${PK:0:16}...${PK: -8}"

    cat > "$GENESIS_PATH" <<EOF
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "$PK"
stake = 10000
network_address = "127.0.0.1:$P2P_PORT"
EOF

    echo "  Genesis: $GENESIS_PATH"
else
    echo "▶ Using existing genesis: $GENESIS_PATH"
fi

# ── 6. 起動 ──
echo "▶ Starting MISAKA node..."
echo ""

# RPC auth is required by default; use "open" for local development
export MISAKA_RPC_AUTH_MODE="${MISAKA_RPC_AUTH_MODE:-open}"

exec "$BINARY" \
    --data-dir "$DATA_DIR" \
    --genesis-path "$GENESIS_PATH" \
    --rpc-port "$RPC_PORT" \
    --p2p-port "$P2P_PORT" \
    --validators "$VALIDATORS" \
    --validator-index "$VALIDATOR_INDEX" \
    --chain-id "$CHAIN_ID"
