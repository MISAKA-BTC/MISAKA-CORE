#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA Network — ローカル testnet 起動
#
#  - validator.key 生成
#  - genesis_committee.toml 自動生成
#  - N validators 起動
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/native_toolchain.sh"
DEFAULT_BINARY="$PROJECT_DIR/target/release/misaka-node"
BINARY="${MISAKA_BINARY:-$DEFAULT_BINARY}"
CHAIN_ID="${MISAKA_CHAIN_ID:-2}"
VALIDATORS="${MISAKA_TESTNET_VALIDATORS:-15}"
BASE_RPC_PORT="${MISAKA_BASE_RPC_PORT:-3000}"
BASE_P2P_PORT="${MISAKA_BASE_P2P_PORT:-16110}"
BASE_DIR="${MISAKA_BASE_DIR:-/tmp/misaka-local-testnet}"
GENESIS="${MISAKA_GENESIS_PATH:-$BASE_DIR/genesis_committee.toml}"
GENESIS_STAKE="${MISAKA_GENESIS_STAKE:-10000}"
STARTUP_WAIT="${MISAKA_STARTUP_WAIT:-6}"
BUILD_FEATURES="${MISAKA_BUILD_FEATURES:-dag,testnet}"
RESET_BASE_DIR="${MISAKA_RESET_BASE_DIR:-0}"
RUNTIME_TRACK="${MISAKA_RUNTIME_TRACK:-stock}"
PHASE_C_REHEARSAL="${MISAKA_PHASE_C_REHEARSAL:-0}"

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
    RUNTIME_TRACK_LABEL="committee rehearsal / ghostdag-compat"
else
    if has_feature "$BUILD_FEATURES" "ghostdag-compat"; then
        echo "ERROR: ghostdag-compat feature requires MISAKA_RUNTIME_TRACK=ghostdag-compat"
        echo "       and MISAKA_PHASE_C_REHEARSAL=1."
        exit 1
    fi
    RUNTIME_TRACK_LABEL="validatorBreadth / stock Narwhal"
fi

if ! [[ "$VALIDATORS" =~ ^[0-9]+$ ]] || [ "$VALIDATORS" -lt 1 ]; then
    echo "ERROR: MISAKA_TESTNET_VALIDATORS must be a positive integer"
    exit 1
fi

if [ "$RESET_BASE_DIR" = "1" ] && [ -d "$BASE_DIR" ]; then
    rm -rf "$BASE_DIR"
fi
mkdir -p "$BASE_DIR"

if [ ! -x "$BINARY" ]; then
    echo "Building misaka-node..."
    cd "$PROJECT_DIR"
    misaka_prepare_native_toolchain || true
    misaka_export_bindgen_env
    cargo build --release -p misaka-node --features "$BUILD_FEATURES" 2>&1 | tail -5
fi

if [ ! -x "$BINARY" ]; then
    echo "ERROR: misaka-node binary not found at $BINARY"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet — Local Validator Cluster                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  Binary:           $BINARY"
echo "  Validators:       $VALIDATORS"
echo "  Chain ID:         $CHAIN_ID"
echo "  Base RPC port:    $BASE_RPC_PORT"
echo "  Base P2P port:    $BASE_P2P_PORT"
echo "  Base dir:         $BASE_DIR"
echo "  Genesis:          $GENESIS"
echo "  Runtime track:    $RUNTIME_TRACK_LABEL"
echo ""

if [ "$RUNTIME_TRACK" = "ghostdag-compat" ]; then
    echo "  NOTE: this is an isolated Phase C committee rehearsal lane."
    echo "        It is not the stock public testnet runtime."
    echo ""
fi

pkill -f -- "$BASE_DIR/" 2>/dev/null || true
sleep 1

declare -a DATA_DIRS
declare -a PUBKEYS
declare -a RPC_PORTS
declare -a P2P_PORTS
declare -a PIDS

short_hex() {
    local value="$1"
    local prefix="${value:0:18}"
    local suffix="${value: -8}"
    printf "%s...%s" "$prefix" "$suffix"
}

emit_validator_pubkey() {
    "$BINARY" --emit-validator-pubkey --data-dir "$1" --chain-id "$CHAIN_ID" 2>&1 \
        | awk '/^0x/ { key=$0 } END { if (key == "") exit 1; print key }'
}

echo "▶ Phase 1: Generating validator keys..."
for idx in $(seq 0 $((VALIDATORS - 1))); do
    DATA_DIRS[$idx]="$BASE_DIR/v$idx"
    RPC_PORTS[$idx]=$((BASE_RPC_PORT + idx))
    P2P_PORTS[$idx]=$((BASE_P2P_PORT + idx))
    mkdir -p "${DATA_DIRS[$idx]}"
    PUBKEYS[$idx]="$(emit_validator_pubkey "${DATA_DIRS[$idx]}")"
    echo "  V$idx pubkey: $(short_hex "${PUBKEYS[$idx]}")"
done

echo ""
echo "▶ Phase 2: Creating genesis committee manifest..."
mkdir -p "$(dirname "$GENESIS")"
{
    echo "[committee]"
    echo "epoch = 0"
    echo ""
    for idx in $(seq 0 $((VALIDATORS - 1))); do
        echo "[[committee.validators]]"
        echo "authority_index = $idx"
        echo "public_key = \"${PUBKEYS[$idx]}\""
        echo "stake = $GENESIS_STAKE"
        echo "network_address = \"127.0.0.1:${P2P_PORTS[$idx]}\""
        echo ""
    done
} > "$GENESIS"
echo "  Genesis: $GENESIS"

echo ""
echo "▶ Phase 3: Starting validators..."
export MISAKA_RPC_AUTH_MODE="${MISAKA_RPC_AUTH_MODE:-open}"

for idx in $(seq 0 $((VALIDATORS - 1))); do
    nohup "$BINARY" \
        --name "misaka-local-v$idx" \
        --validator \
        --data-dir "${DATA_DIRS[$idx]}" \
        --genesis-path "$GENESIS" \
        --rpc-port "${RPC_PORTS[$idx]}" \
        --p2p-port "${P2P_PORTS[$idx]}" \
        --validators "$VALIDATORS" \
        --validator-index "$idx" \
        --chain-id "$CHAIN_ID" \
        > "${DATA_DIRS[$idx]}/node.log" 2>&1 < /dev/null &
    PIDS[$idx]=$!
done

sleep "$STARTUP_WAIT"

echo ""
echo "Validators started:"
for idx in $(seq 0 $((VALIDATORS - 1))); do
    echo "  V$idx: PID=${PIDS[$idx]}, RPC=http://127.0.0.1:${RPC_PORTS[$idx]}, P2P=${P2P_PORTS[$idx]}"
done

echo ""
echo "Health:"
for idx in $(seq 0 $((VALIDATORS - 1))); do
    HEALTH="$(curl -s "http://127.0.0.1:${RPC_PORTS[$idx]}/api/health" 2>/dev/null || echo "FAIL")"
    echo "  V$idx: $HEALTH"
done

echo ""
echo "Chain info (V0):"
curl -s "http://127.0.0.1:${RPC_PORTS[0]}/api/get_chain_info" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "chain info unavailable"

echo ""
echo "Peers (V0):"
curl -s "http://127.0.0.1:${RPC_PORTS[0]}/api/get_peers" 2>/dev/null || echo "peer info unavailable"
echo ""
echo "Genesis: $GENESIS"
echo "Logs: tail -f $BASE_DIR/v0/node.log"
echo "Stop: pkill -f '$BASE_DIR/'"
