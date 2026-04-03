#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  MISAKA Network — One-Click Node Installer
#
#  Usage:
#    curl -sSL https://install.misaka.network | bash
#    OR
#    ./installer/install.sh [--role observer|candidate|archive|relay|sr] [--network testnet|mainnet]
#
#  Supports: Linux (x86_64, aarch64), macOS (x86_64, arm64)
#  License: Apache-2.0
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

VERSION="0.1.0"
REPO="https://github.com/user/MISAKA-CORE.git"
INSTALL_DIR="$HOME/.misaka"
BIN_DIR="$INSTALL_DIR/bin"
DATA_DIR="$INSTALL_DIR/data"
CONFIG_FILE="$INSTALL_DIR/config.toml"
LOG_FILE="$INSTALL_DIR/misaka-node.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
ROLE="observer"
NETWORK="testnet"
RPC_PORT=3001
P2P_PORT=6690

# ── Parse arguments ────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --role) ROLE="$2"; shift 2 ;;
        --network) NETWORK="$2"; shift 2 ;;
        --rpc-port) RPC_PORT="$2"; shift 2 ;;
        --p2p-port) P2P_PORT="$2"; shift 2 ;;
        --help|-h)
            echo "MISAKA One-Click Installer"
            echo "  --role      observer|candidate|archive|relay|sr (default: observer)"
            echo "  --network   testnet|mainnet (default: testnet)"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Banner ─────────────────────────────────────────────────────
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              MISAKA Network — Node Installer              ║"
echo "║          Post-Quantum Native L1 BlockDAG                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Role:    ${GREEN}${ROLE}${NC}"
echo -e "  Network: ${GREEN}${NETWORK}${NC}"
echo ""

# ── SR mainnet guard ───────────────────────────────────────────
if [ "$ROLE" = "sr" ] && [ "$NETWORK" = "mainnet" ]; then
    echo -e "${RED}ERROR: SR mode is not available for mainnet in one-click installer.${NC}"
    echo "Mainnet SR validators require manual setup for security."
    echo "See: docs/SR_COMMITTEE_DESIGN.md"
    exit 1
fi

if [ "$ROLE" = "sr" ]; then
    echo -e "${YELLOW}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  WARNING: SR MODE — TESTNET ONLY              ║${NC}"
    echo -e "${YELLOW}║                                               ║${NC}"
    echo -e "${YELLOW}║  This mode uses more CPU, RAM, and bandwidth. ║${NC}"
    echo -e "${YELLOW}║  Public IP / stable connectivity recommended. ║${NC}"
    echo -e "${YELLOW}║  Do NOT use for mainnet operations.           ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════╝${NC}"
    echo ""
    read -p "Continue with SR testnet mode? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

# ── System checks ──────────────────────────────────────────────
echo ">>> Checking system requirements..."

OS=$(uname -s)
ARCH=$(uname -m)
echo "  OS: $OS ($ARCH)"

# RAM check
check_ram() {
    local required_mb=$1
    local total_mb=0
    if [ "$OS" = "Darwin" ]; then
        total_mb=$(( $(sysctl -n hw.memsize) / 1024 / 1024 ))
    else
        total_mb=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 ))
    fi
    echo "  RAM: ${total_mb} MB (required: ${required_mb} MB)"
    if [ "$total_mb" -lt "$required_mb" ]; then
        echo -e "${RED}  ERROR: Insufficient RAM for role '${ROLE}'${NC}"
        return 1
    fi
    return 0
}

# Disk check
check_disk() {
    local required_gb=$1
    local available_gb=0
    if [ "$OS" = "Darwin" ]; then
        available_gb=$(df -g "$HOME" | tail -1 | awk '{print $4}')
    else
        available_gb=$(df -BG "$HOME" | tail -1 | awk '{print $4}' | tr -d 'G')
    fi
    echo "  Disk: ${available_gb} GB free (required: ${required_gb} GB)"
    if [ "$available_gb" -lt "$required_gb" ]; then
        echo -e "${RED}  ERROR: Insufficient disk space for role '${ROLE}'${NC}"
        return 1
    fi
    return 0
}

case $ROLE in
    observer)   check_ram 2048; check_disk 10 ;;
    candidate)  check_ram 4096; check_disk 50 ;;
    archive)    check_ram 8192; check_disk 200 ;;
    relay)      check_ram 4096; check_disk 50 ;;
    sr)         check_ram 8192; check_disk 100 ;;
    *)          echo "Unknown role: $ROLE"; exit 1 ;;
esac
echo -e "  ${GREEN}System check passed${NC}"

# ── Install dependencies ───────────────────────────────────────
echo ""
echo ">>> Checking dependencies..."

# Rust
if ! command -v cargo &>/dev/null; then
    echo "  Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    source "$HOME/.cargo/env"
fi
echo "  Rust: $(rustc --version 2>/dev/null || echo 'installing...')"

# Git
if ! command -v git &>/dev/null; then
    echo -e "${RED}  ERROR: git is required. Install it first.${NC}"
    exit 1
fi

# ── Clone / update source ─────────────────────────────────────
echo ""
echo ">>> Downloading MISAKA source..."

mkdir -p "$INSTALL_DIR"

if [ -d "$INSTALL_DIR/source/.git" ]; then
    echo "  Updating existing source..."
    cd "$INSTALL_DIR/source"
    git pull --ff-only 2>/dev/null || git fetch
else
    echo "  Cloning from GitHub..."
    git clone --depth 1 "$REPO" "$INSTALL_DIR/source" 2>&1 | tail -3
fi

cd "$INSTALL_DIR/source"

# ── Build ──────────────────────────────────────────────────────
echo ""
echo ">>> Building misaka-node (this may take a few minutes)..."

BUILD_FEATURES="testnet"
if [ "$NETWORK" = "mainnet" ]; then
    BUILD_FEATURES=""
fi

if [ -n "$BUILD_FEATURES" ]; then
    cargo build -p misaka-node --release --features "$BUILD_FEATURES" 2>&1 | tail -5
else
    cargo build -p misaka-node --release 2>&1 | tail -5
fi

mkdir -p "$BIN_DIR"
cp target/release/misaka-node "$BIN_DIR/"
echo -e "  ${GREEN}Build complete: $BIN_DIR/misaka-node${NC}"

# ── Generate config ────────────────────────────────────────────
echo ""
echo ">>> Generating configuration for role '${ROLE}'..."

mkdir -p "$DATA_DIR"

CHAIN_ID=2
VALIDATORS=1
VALIDATOR_INDEX=0
VALIDATOR_FLAG=""
FAUCET_FLAG=""
MODE="public"

case $NETWORK in
    testnet) CHAIN_ID=2; FAUCET_FLAG="--faucet-amount 1000000000 --faucet-cooldown-ms 300000" ;;
    mainnet) CHAIN_ID=1 ;;
esac

case $ROLE in
    observer)
        MODE="hidden"
        ;;
    candidate)
        MODE="hidden"
        ;;
    archive)
        MODE="public"
        ;;
    relay)
        MODE="public"
        ;;
    sr)
        MODE="public"
        VALIDATOR_FLAG="--validator"
        ;;
esac

# Seed nodes
SEEDS="163.43.225.27:6690"

# Write launch script
cat > "$INSTALL_DIR/start.sh" << STARTEOF
#!/usr/bin/env bash
exec "$BIN_DIR/misaka-node" \\
  $VALIDATOR_FLAG \\
  --name "misaka-${ROLE}-$(hostname -s)" \\
  --chain-id $CHAIN_ID \\
  --validator-index $VALIDATOR_INDEX \\
  --validators $VALIDATORS \\
  --data-dir "$DATA_DIR" \\
  --rpc-port $RPC_PORT \\
  --p2p-port $P2P_PORT \\
  --seeds "$SEEDS" \\
  --mode $MODE \\
  --log-level info \\
  $FAUCET_FLAG \\
  "\$@"
STARTEOF
chmod +x "$INSTALL_DIR/start.sh"

echo "  Config written to: $INSTALL_DIR/start.sh"

# ── Start node ─────────────────────────────────────────────────
echo ""
echo ">>> Starting MISAKA node..."

"$INSTALL_DIR/start.sh" 2>&1 | tee "$LOG_FILE" &
NODE_PID=$!
echo "$NODE_PID" > "$INSTALL_DIR/node.pid"

echo "  PID: $NODE_PID"
echo "  Waiting for node to start..."

for i in $(seq 1 30); do
    if curl -s "http://127.0.0.1:$RPC_PORT/health" 2>/dev/null | grep -q '"status"'; then
        echo -e "  ${GREEN}Node is UP!${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "  ${YELLOW}Node did not respond in 30s. Check: tail -f $LOG_FILE${NC}"
    fi
    sleep 1
done

# ── Summary ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              MISAKA Node — Running!                       ║${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Role:      ${CYAN}${ROLE}${NC}"
echo -e "${GREEN}║${NC}  Network:   ${CYAN}${NETWORK}${NC}"
echo -e "${GREEN}║${NC}  RPC:       ${CYAN}http://127.0.0.1:${RPC_PORT}${NC}"
echo -e "${GREEN}║${NC}  Health:    ${CYAN}http://127.0.0.1:${RPC_PORT}/health${NC}"
echo -e "${GREEN}║${NC}  Logs:      ${CYAN}tail -f ${LOG_FILE}${NC}"
echo -e "${GREEN}║${NC}  Stop:      ${CYAN}kill \$(cat ${INSTALL_DIR}/node.pid)${NC}"
echo -e "${GREEN}║${NC}  Restart:   ${CYAN}${INSTALL_DIR}/start.sh${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Chain info:"
curl -s -X POST "http://127.0.0.1:$RPC_PORT/api/get_chain_info" -d '{}' 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(waiting for first block...)"
