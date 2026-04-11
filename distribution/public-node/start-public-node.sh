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
SEED_PUBKEYS_FILE="$SCRIPT_DIR/config/seed-pubkeys.txt"
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
VALIDATOR_SLOTS="$(grep -c '^\[\[committee\.validators\]\]' "$GENESIS" 2>/dev/null || printf '0')"
if [ "$VALIDATOR_SLOTS" -eq 0 ]; then
    printf "${RED}✗ genesis_committee.toml にバリデータが定義されていません${RESET}\n"
    exit 1
fi
GENESIS_VALIDATOR_PK="$(awk -F'"' '/^[[:space:]]*public_key[[:space:]]*=/{print $2; exit}' "$GENESIS" 2>/dev/null || echo "")"
if [ -z "$GENESIS_VALIDATOR_PK" ]; then
    printf "${RED}✗ genesis_committee.toml から validator public_key を取得できません${RESET}\n"
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

# --- First-run: data dir only ------------------------------------
# v0.5.7: bundled-validator.key has been REMOVED. Each download now
# generates a fresh ML-DSA-65 ephemeral validator.key on first run, which
# means clients automatically run in OBSERVER mode (their key is not in
# the genesis committee). The node detects this and skips the propose
# loop — it will receive blocks from the operator but will not sign any.
mkdir -p "$DATA_DIR"
if [ ! -f "$DATA_DIR/validator.key" ]; then
    printf "${DIM}初回起動: ephemeral observer key を生成します (validator.key)${RESET}\n"
fi
LOCAL_VALIDATOR_PK="$("$BINARY" --emit-validator-pubkey --data-dir "$DATA_DIR" --chain-id 2 2>/dev/null | awk '/^0x/ { key=$0 } END { print key }')"
if [ -z "$LOCAL_VALIDATOR_PK" ]; then
    printf "${RED}✗ validator.key の公開鍵を取得できませんでした${RESET}\n"
    printf "${DIM}  misaka-data/validator.key を確認し、必要なら削除して再生成してください。${RESET}\n"
    exit 1
fi
if [ "$LOCAL_VALIDATOR_PK" = "$GENESIS_VALIDATOR_PK" ]; then
    printf "${RED}✗ misaka-data/validator.key が genesis validator と一致しています${RESET}\n"
    printf "${RED}  public observer package は observer-only です。operator/shared validator key は使えません。${RESET}\n"
    printf "${DIM}  $DATA_DIR/validator.key を削除して再起動し、ephemeral observer key を再生成してください。${RESET}\n"
    exit 1
fi

# --- Read seeds + pubkeys (both required or both skipped) --------
#
# Narwhal relay のハンドシェイクは ML-DSA-65 PK-pinning 必須です (TOFU なし)。
# node は `--seeds` だけ渡されて `--seed-pubkeys` が空だと FATAL で落ちます。
# stock public-node package では `seeds.txt` と `seed-pubkeys.txt` は
# 必ず 1:1 で揃っている前提です。 mismatch を warning で握りつぶすと
# 利用者が joined のつもりで solo 起動してしまうため、fail-closed にします。
read_csv() {
    local file="$1" out=""
    if [ -f "$file" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line="$(echo "$line" | sed 's/#.*//' | xargs)"
            [ -z "$line" ] && continue
            if [ -z "$out" ]; then
                out="$line"
            else
                out="$out,$line"
            fi
        done < "$file"
    fi
    printf '%s' "$out"
}

SEEDS="$(read_csv "$SEEDS_FILE")"
SEED_PUBKEYS="$(read_csv "$SEED_PUBKEYS_FILE")"

# Count comma-separated entries. `printf '%s'` does not append a newline,
# so wc -l returned 0 for non-empty single-entry strings — use grep -c
# on echo output instead.
count_csv() {
    local s="$1"
    if [ -z "$s" ]; then
        printf '0'
    else
        echo "$s" | tr ',' '\n' | grep -c '.'
    fi
}
SEEDS_COUNT="$(count_csv "$SEEDS")"
PUBKEYS_COUNT="$(count_csv "$SEED_PUBKEYS")"

SEEDS_ARG=()
SEED_STATUS_TEXT=""
if [ "$SEEDS_COUNT" -eq "$PUBKEYS_COUNT" ] && [ "$SEEDS_COUNT" -gt 0 ]; then
    SEEDS_ARG=(--seeds "$SEEDS" --seed-pubkeys "$SEED_PUBKEYS")
    SEED_STATUS_TEXT="$SEEDS  ${DIM}(with $PUBKEYS_COUNT pinned pubkey$([ "$PUBKEYS_COUNT" -gt 1 ] && echo s))${RESET}"
elif [ "$SEEDS_COUNT" -eq 0 ] && [ "$PUBKEYS_COUNT" -eq 0 ]; then
    printf "${RED}ERROR: seeds.txt と seed-pubkeys.txt が空です。${RESET}\n"
    printf "${RED}  public observer package は official/public seed への join 専用です。solo self-host mode には入りません。${RESET}\n"
    printf "${DIM}  stock package の config を復元して再試行してください。${RESET}\n"
    exit 1
else
    printf "${RED}ERROR: seeds.txt (%s entries) と seed-pubkeys.txt (%s entries) が揃いません。${RESET}\n" \
        "$SEEDS_COUNT" "$PUBKEYS_COUNT"
    printf "${RED}  stock package の current truth が壊れています。solo fallback せず停止します。${RESET}\n"
    printf "${DIM}  config/seeds.txt と config/seed-pubkeys.txt を同じ件数に揃えて再試行してください。${RESET}\n"
    exit 1
fi

# v0.5.11 audit Mid #9: extract the real Narwhal relay port from
# the genesis manifest instead of hardcoding 6691 (the legacy
# GhostDAG port, which never matched the actual relay listener).
RELAY_ADDR="$(awk -F'"' '/^[[:space:]]*network_address[[:space:]]*=/{print $2; exit}' "$GENESIS" 2>/dev/null || echo "")"
if [ -n "$RELAY_ADDR" ]; then
    RELAY_DISPLAY="$RELAY_ADDR  ${DIM}(from genesis)${RESET}"
else
    RELAY_DISPLAY="${YELLOW}(could not parse genesis network_address)${RESET}"
fi

printf "${BOLD}起動パラメータ${RESET}\n"
printf "  ${DIM}Config :${RESET} $CONFIG\n"
printf "  ${DIM}Genesis:${RESET} $GENESIS\n"
printf "  ${DIM}Seeds  :${RESET} $SEED_STATUS_TEXT\n"
printf "  ${DIM}Data   :${RESET} $DATA_DIR\n"
printf "  ${DIM}RPC    :${RESET} http://localhost:3001\n"
printf "  ${DIM}Relay  :${RESET} $RELAY_DISPLAY\n"
printf "\n"
printf "${GREEN}▶ ノードを起動します...${RESET}\n"
printf "${DIM}（停止するには Ctrl+C を押してください）${RESET}\n"
printf "\n"

export MISAKA_RPC_AUTH_MODE=open

# `${SEEDS_ARG[@]+...}` expands ONLY when SEEDS_ARG is set, which is
# safe under `set -u` even when the array is empty.
"$BINARY" \
    --config "$CONFIG" \
    --data-dir "$DATA_DIR" \
    --genesis-path "$GENESIS" \
    ${SEEDS_ARG[@]+"${SEEDS_ARG[@]}"} \
    --chain-id 2
