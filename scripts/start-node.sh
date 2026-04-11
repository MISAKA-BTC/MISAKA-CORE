#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA Network — 汎用 source-build ノード起動スクリプト
#  Narwhal/Bullshark Consensus (GhostDAG-free)
#
#  Public observer package の front door ではありません。
#  Public observer は distribution/public-node/start-public-node.* を使い、
#  official/public seed への self-host validator join は scripts/testnet-join.sh を使います。
#  この script は source checkout 上で validator/full-node を直接起動したい場合の
#  lower-level launcher です。
#  validator.key + genesis_committee.toml は未存在時のみ自動生成します。
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/native_toolchain.sh"
BINARY="${MISAKA_BINARY:-$PROJECT_DIR/target/release/misaka-node}"
DATA_DIR="${MISAKA_DATA_DIR:-$PROJECT_DIR/misaka-data}"
RPC_PORT="${MISAKA_RPC_PORT:-3000}"
P2P_PORT="${MISAKA_P2P_PORT:-16110}"
VALIDATORS="${MISAKA_VALIDATORS:-1}"
VALIDATOR_INDEX="${MISAKA_VALIDATOR_INDEX:-0}"
CHAIN_ID="${MISAKA_CHAIN_ID:-2}"
GENESIS_PATH="${MISAKA_GENESIS_PATH:-$DATA_DIR/genesis_committee.toml}"
NODE_MODE="${MISAKA_MODE:-public}"
NODE_ROLE="${MISAKA_NODE_ROLE:-validator}"
PEERS="${MISAKA_PEERS:-}"
SEEDS="${MISAKA_SEEDS:-}"
SEED_PUBKEYS="${MISAKA_SEED_PUBKEYS:-}"
ADVERTISE_ADDR="${MISAKA_ADVERTISE_ADDR:-${NODE_ADVERTISE_ADDR:-}}"
ACCEPT_OBSERVERS="${MISAKA_ACCEPT_OBSERVERS:-0}"
BUILD_FEATURES="${MISAKA_BUILD_FEATURES:-dag,testnet}"
NODE_NAME="${MISAKA_NODE_NAME:-}"
NODE_LOG_LEVEL="${MISAKA_LOG_LEVEL:-info}"
RPC_PEERS="${MISAKA_RPC_PEERS:-}"
RUNTIME_TRACK="${MISAKA_RUNTIME_TRACK:-stock}"
PHASE_C_REHEARSAL="${MISAKA_PHASE_C_REHEARSAL:-0}"

count_csv() {
    local s="$1"
    if [ -z "$s" ]; then
        printf '0'
    else
        echo "$s" | tr ',' '\n' | grep -c '.'
    fi
}

SEEDS_COUNT="$(count_csv "$SEEDS")"
SEED_PUBKEYS_COUNT="$(count_csv "$SEED_PUBKEYS")"

has_feature() {
    case ",$1," in
    *,"$2",*) return 0 ;;
    *) return 1 ;;
    esac
}

if [ "$PHASE_C_REHEARSAL" = "1" ] && [ "${MISAKA_RUNTIME_TRACK:-}" = "stock" ]; then
    RUNTIME_TRACK="ghostdag-compat"
fi

case "$RUNTIME_TRACK" in
stock | ghostdag-compat) ;;
*)
    echo "ERROR: MISAKA_RUNTIME_TRACK must be either 'stock' or 'ghostdag-compat'"
    exit 1
    ;;
esac

if [ "$RUNTIME_TRACK" = "ghostdag-compat" ]; then
    if [ "$PHASE_C_REHEARSAL" != "1" ]; then
        echo "ERROR: ghostdag-compat runtime is reserved for isolated Phase C rehearsal"
        echo "       Set MISAKA_PHASE_C_REHEARSAL=1 to opt in explicitly."
        exit 1
    fi
    if ! has_feature "$BUILD_FEATURES" "ghostdag-compat"; then
        echo "ERROR: Phase C committee rehearsal requires ghostdag-compat in MISAKA_BUILD_FEATURES"
        echo "       Example: MISAKA_BUILD_FEATURES=dag,testnet,ghostdag-compat"
        exit 1
    fi
    if [ "$CHAIN_ID" -eq 1 ]; then
        echo "ERROR: ghostdag-compat rehearsal is not allowed on mainnet"
        exit 1
    fi
    if [ "$NODE_MODE" = "seed" ]; then
        echo "ERROR: seed mode is not supported for the isolated Phase C rehearsal lane"
        exit 1
    fi
    RUNTIME_TRACK_LABEL="committee rehearsal / ghostdag-compat"
else
    if has_feature "$BUILD_FEATURES" "ghostdag-compat"; then
        echo "ERROR: ghostdag-compat feature requires MISAKA_RUNTIME_TRACK=ghostdag-compat"
        echo "       and MISAKA_PHASE_C_REHEARSAL=1."
        exit 1
    fi
    RUNTIME_TRACK_LABEL="validatorBreadth / stock Narwhal"
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Network — Narwhal/Bullshark Node                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
if [ -n "$NODE_NAME" ]; then
    echo "  Node name:       $NODE_NAME"
fi
echo "  Data dir:        $DATA_DIR"
echo "  RPC port:        $RPC_PORT"
echo "  P2P port:        $P2P_PORT"
echo "  Validators:      $VALIDATORS"
echo "  Validator index: $VALIDATOR_INDEX"
echo "  Chain ID:        $CHAIN_ID"
echo "  Genesis:         $GENESIS_PATH"
echo "  Mode:            $NODE_MODE"
echo "  Role:            $NODE_ROLE"
echo "  Runtime track:   $RUNTIME_TRACK_LABEL"
echo "  Accept observers:$ACCEPT_OBSERVERS"
echo "  Log level:       $NODE_LOG_LEVEL"
if [ "$SEEDS_COUNT" -gt 0 ]; then
    echo "  Seeds:           $SEEDS"
    echo "  Seed pubkeys:    $SEED_PUBKEYS_COUNT entries"
fi
echo ""

if [ "$NODE_MODE" = "seed" ] && [ "$NODE_ROLE" = "validator" ]; then
    echo "ERROR: seed mode cannot run with validator role"
    echo "       Seeds are dialable bootstrap/full-node endpoints, not block producers."
    exit 1
fi

if [ "$RUNTIME_TRACK" = "ghostdag-compat" ]; then
    echo ""
    echo "  NOTE: this is an isolated Phase C committee rehearsal lane."
    echo "        It is not the stock public testnet runtime."
fi

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
    misaka_prepare_native_toolchain || true
fi

# ── 3. ビルド ──
echo "▶ Building MISAKA node (Narwhal mode)..."
cd "$PROJECT_DIR"
misaka_export_bindgen_env
if [ ! -x "$BINARY" ]; then
    cargo build --release -p misaka-node --features "$BUILD_FEATURES" 2>&1 | tail -5
fi

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed — binary not found at $BINARY"
    exit 1
fi
echo "  Binary: $BINARY"

# ── 4. データディレクトリ ──
mkdir -p "$DATA_DIR"

if [ "$SEEDS_COUNT" -ne "$SEED_PUBKEYS_COUNT" ]; then
    echo "ERROR: seed count ($SEEDS_COUNT) and seed-pubkeys count ($SEED_PUBKEYS_COUNT) mismatch"
    echo "       Narwhal relay requires 1:1 ML-DSA-65 PK-pinning for every seed."
    exit 1
fi
if [ -z "$ADVERTISE_ADDR" ] && [ "$NODE_MODE" != "hidden" ]; then
    if [ "$NODE_MODE" = "seed" ] || [ "$ACCEPT_OBSERVERS" = "1" ] || { [ "$SEEDS_COUNT" -gt 0 ] && [ "$NODE_ROLE" = "validator" ]; }; then
        echo "ERROR: MISAKA_ADVERTISE_ADDR is required for dialable profiles"
        echo "       mode=$NODE_MODE role=$NODE_ROLE seeds=$SEEDS_COUNT accept_observers=$ACCEPT_OBSERVERS"
        echo "       Pass MISAKA_ADVERTISE_ADDR=PUBLIC_IP:$P2P_PORT or NODE_ADVERTISE_ADDR=..."
        exit 1
    elif [ "$NODE_ROLE" = "validator" ]; then
        echo "WARNING: validator/public self-host start without MISAKA_ADVERTISE_ADDR"
        echo "         runtime will warn, and peers may not be able to dial back."
    fi
fi

# ── 5. Genesis 自動生成 (未作成の場合) ──
if [ ! -f "$GENESIS_PATH" ]; then
    if [ "$NODE_ROLE" != "validator" ]; then
        echo "ERROR: $GENESIS_PATH is missing for non-validator launch"
        echo "       start-node.sh may auto-generate genesis only for validator/source-build flows."
        echo "       Public observer users should use distribution/public-node/start-public-node.*"
        echo "       Self-host validator join should use scripts/testnet-join.sh with operator genesis."
        exit 1
    fi
    if [ "$VALIDATORS" -gt 1 ]; then
        echo "ERROR: $GENESIS_PATH is missing"
        echo "       For multi-validator startup, generate a shared genesis first."
        echo "       Example: MISAKA_TESTNET_VALIDATORS=$VALIDATORS scripts/start-testnet.sh"
        exit 1
    fi

    echo "▶ Generating genesis committee manifest..."

    PK=$("$BINARY" --emit-validator-pubkey --data-dir "$DATA_DIR" --chain-id "$CHAIN_ID" 2>&1 \
        | awk '/^0x/ { key=$0 } END { if (key == "") exit 1; print key }')
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
ARGS=(
    --mode "$NODE_MODE"
    --data-dir "$DATA_DIR"
    --genesis-path "$GENESIS_PATH"
    --rpc-port "$RPC_PORT"
    --p2p-port "$P2P_PORT"
    --validators "$VALIDATORS"
    --validator-index "$VALIDATOR_INDEX"
    --chain-id "$CHAIN_ID"
    --log-level "$NODE_LOG_LEVEL"
)

if [ -n "$NODE_NAME" ]; then
    ARGS+=(--name "$NODE_NAME")
fi
if [ "$NODE_ROLE" = "validator" ]; then
    ARGS+=(--validator)
fi
if [ -n "$PEERS" ]; then
    ARGS+=(--peers "$PEERS")
fi
if [ -n "$SEEDS" ]; then
    ARGS+=(--seeds "$SEEDS")
fi
if [ -n "$SEED_PUBKEYS" ]; then
    ARGS+=(--seed-pubkeys "$SEED_PUBKEYS")
fi
if [ -n "$RPC_PEERS" ]; then
    ARGS+=(--dag-rpc-peers "$RPC_PEERS")
fi
if [ -n "$ADVERTISE_ADDR" ]; then
    ARGS+=(--advertise-addr "$ADVERTISE_ADDR")
fi

exec "$BINARY" "${ARGS[@]}"
