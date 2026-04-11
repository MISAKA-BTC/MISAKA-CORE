#!/usr/bin/env bash
set -euo pipefail

CHAIN_ID=2
NODE_NAME="misaka-testnet-sr0"
DATA_DIR="/opt/misaka/data"
RPC_PORT=3001
# v0.5.9: Narwhal relay listens on 16110 by convention, NOT the legacy
# 6690 port. Operators running a genesis node should advertise this.
P2P_PORT=16110
FAUCET_AMOUNT=1000000000
FAUCET_COOLDOWN_MS=300000
CHECKPOINT_INTERVAL=50
MAX_TXS=256
MEMPOOL_SIZE=10000
VALIDATORS=1
VALIDATOR_INDEX=0
LOG_LEVEL="info"
GENESIS_PATH="${MISAKA_GENESIS_PATH:-$DATA_DIR/genesis_committee.toml}"
RPC_AUTH_MODE="${MISAKA_RPC_AUTH_MODE:-open}"
ACCEPT_OBSERVERS="${MISAKA_ACCEPT_OBSERVERS:-1}"
EXPOSE_RPC="${MISAKA_EXPOSE_RPC:-0}"

PUBLIC_IP=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip) PUBLIC_IP="$2"; shift 2 ;;
        --name) NODE_NAME="$2"; shift 2 ;;
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "")
    if [ -z "$PUBLIC_IP" ]; then
        echo "ERROR: Could not detect public IP. Use --ip YOUR_IP"
        exit 1
    fi
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet Genesis Node Deployment                  ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Chain ID:    $CHAIN_ID (testnet)                            ║"
echo "║  Node:        $NODE_NAME"
echo "║  Public IP:   $PUBLIC_IP"
echo "║  RPC:         $RPC_PORT"
echo "║  P2P:         $P2P_PORT"
echo "║  Data:        $DATA_DIR"
echo "║  Genesis:     $GENESIS_PATH"
echo "║  RPC auth:    $RPC_AUTH_MODE"
echo "║  Observers:   $ACCEPT_OBSERVERS"
echo "║  Expose RPC:  $EXPOSE_RPC"
echo "╚═══════════════════════════════════════════════════════════╝"

echo ""
echo ">>> Phase 1: System preparation"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/lib/native_toolchain.sh"

if ! command -v cargo &>/dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
echo "  Rust: $(rustc --version)"

if command -v apt-get &>/dev/null; then
    misaka_prepare_native_toolchain || true
    sudo apt-get install -y -qq curl ufw >/dev/null
fi

sudo mkdir -p "$DATA_DIR"
sudo chown "$(whoami)" "$DATA_DIR"

echo ""
echo ">>> Phase 2: Building misaka-node (release)"

cd "$PROJECT_ROOT"

misaka_export_bindgen_env
cargo build -p misaka-node --release --features dag,testnet 2>&1 | tail -5

BINARY="$PROJECT_ROOT/target/release/misaka-node"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed - binary not found"
    exit 1
fi
echo "  Binary: $BINARY ($(du -h "$BINARY" | cut -f1))"

echo ""
echo ">>> Phase 3: Generating validator transport identity"

VALIDATOR_KEY="$DATA_DIR/validator.key"
PUBKEY="$("$BINARY" --emit-validator-pubkey --data-dir "$DATA_DIR" --chain-id "$CHAIN_ID" 2>&1 \
    | awk '/^0x/ { key=$0 } END { if (key == "") exit 1; print key }')"
if [ ! -f "$VALIDATOR_KEY" ]; then
    echo "ERROR: validator.key was not created under $DATA_DIR"
    exit 1
fi
echo "  Validator key: $VALIDATOR_KEY"
echo "  Validator pubkey: ${PUBKEY:0:18}...${PUBKEY: -8}"

if [ ! -f "$GENESIS_PATH" ]; then
    cat > "$GENESIS_PATH" <<EOF
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "$PUBKEY"
stake = 10000
network_address = "$PUBLIC_IP:$P2P_PORT"
EOF
    echo "  Genesis created: $GENESIS_PATH"
else
    echo "  Using existing genesis: $GENESIS_PATH"
fi

echo ""
echo ">>> Phase 4: Creating systemd service"

SERVICE_FILE="/etc/systemd/system/misaka-node.service"
PASSPHRASE_FILE="/opt/misaka/.passphrase"

if [ -n "${MISAKA_VALIDATOR_PASSPHRASE:-}" ]; then
    echo "$MISAKA_VALIDATOR_PASSPHRASE" | sudo tee "$PASSPHRASE_FILE" > /dev/null
    sudo chmod 600 "$PASSPHRASE_FILE"
    sudo chown root:root "$PASSPHRASE_FILE"
fi

sudo tee "$SERVICE_FILE" > /dev/null << SERVICEEOF
[Unit]
Description=MISAKA Testnet Node ($NODE_NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$PROJECT_ROOT
Environment=RUST_LOG=$LOG_LEVEL
Environment=MISAKA_VALIDATOR_PASSPHRASE_FILE=$PASSPHRASE_FILE
Environment=MISAKA_RPC_AUTH_MODE=$RPC_AUTH_MODE
Environment=MISAKA_ACCEPT_OBSERVERS=$ACCEPT_OBSERVERS
ExecStart=$BINARY \\
    --validator \\
    --name $NODE_NAME \\
    --chain-id $CHAIN_ID \\
    --validator-index $VALIDATOR_INDEX \\
    --validators $VALIDATORS \\
    --data-dir $DATA_DIR \\
    --genesis-path $GENESIS_PATH \\
    --rpc-port $RPC_PORT \\
    --p2p-port $P2P_PORT \\
    --advertise-addr $PUBLIC_IP:$P2P_PORT \\
    --dag-checkpoint-interval $CHECKPOINT_INTERVAL \\
    --dag-max-txs $MAX_TXS \\
    --dag-mempool-size $MEMPOOL_SIZE \\
    --faucet-amount $FAUCET_AMOUNT \\
    --faucet-cooldown-ms $FAUCET_COOLDOWN_MS \\
    --log-level $LOG_LEVEL
Restart=on-failure
RestartSec=10
LimitNOFILE=65535
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
SERVICEEOF

sudo systemctl daemon-reload
echo "  Service created: $SERVICE_FILE"

echo ""
echo ">>> Phase 5: Configuring firewall"

if command -v ufw &>/dev/null; then
    sudo ufw allow "$P2P_PORT"/tcp comment "MISAKA P2P"
    sudo ufw allow 22/tcp comment "SSH"
    if [ "$EXPOSE_RPC" = "1" ]; then
        sudo ufw allow "$RPC_PORT"/tcp comment "MISAKA RPC"
        echo "  Firewall: ports $RPC_PORT, $P2P_PORT, 22 open"
    else
        echo "  Firewall: ports $P2P_PORT, 22 open (RPC stays local-only)"
    fi
    sudo ufw --force enable 2>/dev/null || true
else
    echo "  WARNING: ufw not found - configure firewall manually"
fi

echo ""
echo ">>> Phase 6: Starting node"

sudo systemctl enable misaka-node
sudo systemctl start misaka-node

echo "  Waiting for node to start..."
for i in $(seq 1 30); do
    if curl -s "http://127.0.0.1:$RPC_PORT/api/health" | grep -q '"status"' 2>/dev/null; then
        echo "  Node is UP!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  WARNING: Node did not respond within 30s"
        echo "  Check logs: sudo journalctl -u misaka-node -f"
        exit 1
    fi
    sleep 1
done

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Testnet Genesis Node - RUNNING                   ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Health:   curl http://127.0.0.1:$RPC_PORT/api/health"
echo "║  Chain:    curl http://127.0.0.1:$RPC_PORT/api/get_chain_info"
echo "║  Faucet:   curl -X POST http://127.0.0.1:$RPC_PORT/api/faucet -d '{\"address\":\"misaka1...\"}'"
echo "║  Logs:     sudo journalctl -u misaka-node -f"
echo "║  Seed:     $PUBLIC_IP:$P2P_PORT"
echo "║  Genesis:  $GENESIS_PATH"
echo "║  Profile:  observers=$ACCEPT_OBSERVERS rpc_auth=$RPC_AUTH_MODE expose_rpc=$EXPOSE_RPC"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "To join this testnet from another node:"
echo "  - Public observer: use distribution/public-node with seeds=$PUBLIC_IP:$P2P_PORT"
echo "  - Self-host/local node: copy $GENESIS_PATH and the operator pubkey, then use scripts/start-node.sh"
