#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#   MISAKA Testnet — Public Node (Linux / macOS)
# ═══════════════════════════════════════════════════════════════
# Usage:
#   ./start-public-node.sh           # Terminal から直接起動
#   File manager からダブルクリック  # 実行権限が必要
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

if [ -t 1 ]; then
    BOLD='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'
    YELLOW='\033[33m'; CYAN='\033[36m'; RESET='\033[0m'
else
    BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; CYAN=''; RESET=''
fi

print_header() {
    printf "${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${CYAN}║${RESET}  ${BOLD}MISAKA Testnet — Public Node${RESET}                             ${CYAN}║${RESET}\n"
    printf "${CYAN}║${RESET}  ${DIM}PQ Signature:${RESET} ML-DSA-65 (FIPS 204)                      ${CYAN}║${RESET}\n"
    printf "${CYAN}║${RESET}  ${DIM}Consensus:${RESET}    Mysticeti-equivalent DAG (Bullshark)     ${CYAN}║${RESET}\n"
    printf "${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}\n"
    printf "\n"
}

pause_on_exit() {
    printf "\n${DIM}─── 終了しました ───${RESET}\n"
    if [ -t 0 ]; then
        printf "このウインドウを閉じるには ${BOLD}Enter${RESET} を押してください: "
        read -r _ || true
    fi
}
trap pause_on_exit EXIT

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

print_header

# Detect platform for binary name
case "$(uname -s)" in
    Darwin*) BIN_NAME="misaka-node" ;;
    Linux*)  BIN_NAME="misaka-node" ;;
    *)       BIN_NAME="misaka-node" ;;
esac

BINARY="$SCRIPT_DIR/$BIN_NAME"
CONFIG="$SCRIPT_DIR/config/public-node.toml"
GENESIS="$SCRIPT_DIR/config/genesis_committee.toml"
SEEDS_FILE="$SCRIPT_DIR/config/seeds.txt"
BUNDLED_KEY="$SCRIPT_DIR/config/bundled-validator.key"
DATA_DIR="$SCRIPT_DIR/misaka-data"

# --- Pre-flight checks -------------------------------------------
if [ ! -f "$BINARY" ]; then
    printf "${RED}✗ misaka-node バイナリが見つかりません:${RESET}\n  $BINARY\n"
    printf "  リリースアーカイブを正しく展開してから再度実行してください。\n"
    exit 1
fi
if [ ! -f "$CONFIG" ]; then
    printf "${RED}✗ 設定ファイルが見つかりません: config/public-node.toml${RESET}\n"
    exit 1
fi
if [ ! -f "$GENESIS" ]; then
    printf "${RED}✗ genesis_committee.toml が見つかりません${RESET}\n"
    exit 1
fi

# --- macOS: strip Gatekeeper quarantine --------------------------
if [ "$(uname -s)" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
    if xattr "$BINARY" 2>/dev/null | grep -q "com.apple.quarantine"; then
        printf "${YELLOW}⚠ quarantine 属性を解除中...${RESET}\n"
        xattr -d com.apple.quarantine "$BINARY" 2>/dev/null || true
    fi
fi

chmod +x "$BINARY" 2>/dev/null || true

# --- First-run: copy bundled validator key -----------------------
mkdir -p "$DATA_DIR"
if [ ! -f "$DATA_DIR/validator.key" ] && [ -f "$BUNDLED_KEY" ]; then
    printf "${DIM}初回起動: bundled validator key をコピー中...${RESET}\n"
    cp "$BUNDLED_KEY" "$DATA_DIR/validator.key"
    chmod 600 "$DATA_DIR/validator.key" 2>/dev/null || true
fi

# --- Read seeds --------------------------------------------------
SEEDS=""
if [ -f "$SEEDS_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(echo "$line" | sed 's/#.*//' | xargs)"
        [ -z "$line" ] && continue
        if [ -z "$SEEDS" ]; then
            SEEDS="$line"
        else
            SEEDS="$SEEDS,$line"
        fi
    done < "$SEEDS_FILE"
fi

printf "${BOLD}起動パラメータ${RESET}\n"
printf "  ${DIM}Config :${RESET} $CONFIG\n"
printf "  ${DIM}Genesis:${RESET} $GENESIS\n"
printf "  ${DIM}Seeds  :${RESET} ${SEEDS:-${YELLOW}(none — self-host mode)${RESET}}\n"
printf "  ${DIM}Data   :${RESET} $DATA_DIR\n"
printf "  ${DIM}RPC    :${RESET} http://localhost:3001\n"
printf "  ${DIM}P2P    :${RESET} 6691\n"
printf "\n"
printf "${GREEN}▶ ノードを起動します...${RESET}\n"
printf "${DIM}（停止するには Ctrl+C を押してください）${RESET}\n"
printf "\n"

export MISAKA_RPC_AUTH_MODE=open

SEEDS_ARG=()
if [ -n "$SEEDS" ]; then
    SEEDS_ARG=(--seeds "$SEEDS")
fi

"$BINARY" \
    --config "$CONFIG" \
    --data-dir "$DATA_DIR" \
    --genesis-path "$GENESIS" \
    "${SEEDS_ARG[@]}" \
    --chain-id 2
