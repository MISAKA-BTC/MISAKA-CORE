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
echo "╚═══════════════════════════════════════════════════════════╝"

echo ""
echo ">>> Phase 1: System preparation"

if ! command -v cargo &>/dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
echo "  Rust: $(rustc --version)"

if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl ufw
fi

sudo mkdir -p "$DATA_DIR"
sudo chown "$(whoami)" "$DATA_DIR"

echo ""
echo ">>> Phase 2: Building misaka-node (release)"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

cargo build -p misaka-node --release --features testnet 2>&1 | tail -5

BINARY="$PROJECT_ROOT/target/release/misaka-node"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed - binary not found"
    exit 1
fi
echo "  Binary: $BINARY ($(du -h "$BINARY" | cut -f1))"

echo ""
echo ">>> Phase 3: Generating ML-DSA-65 validator keypair"

KEYSTORE="$DATA_DIR/dag_validator_0.enc.json"
if [ -f "$KEYSTORE" ]; then
    echo "  Keystore already exists: $KEYSTORE (skipping keygen)"
else
    if [ -z "${MISAKA_VALIDATOR_PASSPHRASE:-}" ]; then
        echo "  Enter validator passphrase (min 8 chars):"
        read -rs MISAKA_VALIDATOR_PASSPHRASE
        export MISAKA_VALIDATOR_PASSPHRASE
    fi

    "$BINARY" \
        --keygen-only \
        --name "$NODE_NAME" \
        --chain-id "$CHAIN_ID" \
        --data-dir "$DATA_DIR" \
        --validator \
        --validator-index "$VALIDATOR_INDEX" \
        --validators "$VALIDATORS"

    echo "  Keystore created: $KEYSTORE"
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
# v0.5.9: testnet default is fail-closed RPC auth. Operators running
# a public testnet node without external API-key provisioning must
# explicitly set open mode here OR provision an API key via
# MISAKA_RPC_API_KEY. Keep this line for the public testnet; remove
# it and set MISAKA_RPC_API_KEY before running on mainnet.
Environment=MISAKA_RPC_AUTH_MODE=open
# v0.5.9: accept observer clients so stock public-node downloads can
# sync from this genesis node. Omit this if you are running a private
# validator that should only accept peers in the genesis committee.
Environment=MISAKA_ACCEPT_OBSERVERS=1
ExecStart=$BINARY \\
    --validator \\
    --name $NODE_NAME \\
    --chain-id $CHAIN_ID \\
    --validator-index $VALIDATOR_INDEX \\
    --validators $VALIDATORS \\
    --data-dir $DATA_DIR \\
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
    sudo ufw allow "$RPC_PORT"/tcp comment "MISAKA RPC"
    sudo ufw allow "$P2P_PORT"/tcp comment "MISAKA P2P"
    sudo ufw allow 22/tcp comment "SSH"
    sudo ufw --force enable 2>/dev/null || true
    echo "  Firewall: ports $RPC_PORT, $P2P_PORT, 22 open"
else
    echo "  WARNING: ufw not found - configure firewall manually"
fi

echo ""
echo ">>> Phase 6: Starting node"

sudo systemctl enable misaka-node
sudo systemctl start misaka-node

echo "  Waiting for node to start..."
for i in $(seq 1 30); do
    if curl -s "http://127.0.0.1:$RPC_PORT/health" | grep -q '"status"' 2>/dev/null; then
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
echo "║  Health:   http://$PUBLIC_IP:$RPC_PORT/health"
echo "║  Chain:    http://$PUBLIC_IP:$RPC_PORT/api/get_chain_info"
echo "║  Faucet:   curl -X POST http://$PUBLIC_IP:$RPC_PORT/api/faucet -d '{\"address\":\"misaka1...\"}'"
echo "║  Logs:     sudo journalctl -u misaka-node -f"
echo "║  Seed:     $PUBLIC_IP:$P2P_PORT"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "To join this testnet from another node:"
echo "  ./scripts/testnet-join.sh --seeds $PUBLIC_IP:$P2P_PORT"
