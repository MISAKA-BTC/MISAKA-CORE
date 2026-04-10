#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  MISAKA Network — Testnet v3 Protocol Upgrade Script
# ═══════════════════════════════════════════════════════════════
#
# This script performs a SIMULTANEOUS upgrade of all testnet nodes
# from P2P protocol v2 to v3. Because v2 and v3 are incompatible
# (different DSTs, handshake wire format, nonce fields), all nodes
# MUST be stopped and restarted within the same window.
#
# ┌──────────────────────────────────────────────────────────────┐
# │  WARNING: v2 and v3 nodes CANNOT communicate.               │
# │  All nodes must be upgraded in a single maintenance window.  │
# │  Expected downtime: ~2-3 minutes per node.                  │
# └──────────────────────────────────────────────────────────────┘
#
# Usage:
#   ./testnet_v3_upgrade.sh [phase]
#
#   Phases:
#     preflight  — Validate SSH access, binary, config on all nodes
#     stop       — Stop all nodes simultaneously (parallel SSH)
#     deploy     — Upload binary + config to all nodes
#     start      — Start all nodes simultaneously
#     verify     — Check handshake success + peer counts
#     rollback   — Emergency: restore v2 binary + config and restart
#     all        — Run preflight → stop → deploy → start → verify
#
# Prerequisites:
#   - SSH key access to all testnet nodes
#   - Built misaka-node binary at ./target/release/misaka-node
#   - Updated testnet.toml at ./configs/testnet.toml

set -euo pipefail

# ═══════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════

# Testnet node addresses (SSH user@host)
NODES=(
    "misaka@49.212.136.189"
    "misaka@49.212.166.172"
)

# Remote paths
REMOTE_BIN="/opt/misaka/bin/misaka-node"
REMOTE_CONFIG="/opt/misaka/configs/testnet.toml"
REMOTE_BACKUP_DIR="/opt/misaka/backup/v2"
PM2_PROCESS_NAME="misaka-node"

# Local paths
LOCAL_BIN="./target/release/misaka-node"
LOCAL_CONFIG="./configs/testnet.toml"

# SSH options
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# Run a command on a remote node
remote() {
    local node="$1"
    shift
    ssh $SSH_OPTS "$node" "$@"
}

# Run a command on ALL nodes in parallel, wait for all to finish
parallel_all() {
    local cmd="$1"
    local pids=()

    for node in "${NODES[@]}"; do
        remote "$node" "$cmd" &
        pids+=($!)
    done

    local failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            ((failed++))
        fi
    done

    return $failed
}

# ═══════════════════════════════════════════════════════════════
#  Phase: Preflight
# ═══════════════════════════════════════════════════════════════

preflight() {
    log "═══ Preflight Check ═══"

    # Check local binary exists
    if [[ ! -f "$LOCAL_BIN" ]]; then
        fail "Binary not found: $LOCAL_BIN (run: cargo build --release)"
    fi
    ok "Local binary: $LOCAL_BIN ($(stat -c%s "$LOCAL_BIN" 2>/dev/null || stat -f%z "$LOCAL_BIN") bytes)"

    # Check local config
    if [[ ! -f "$LOCAL_CONFIG" ]]; then
        fail "Config not found: $LOCAL_CONFIG"
    fi
    if ! grep -q "min_protocol_version = 3" "$LOCAL_CONFIG"; then
        fail "Config missing min_protocol_version = 3"
    fi
    ok "Local config: $LOCAL_CONFIG (v3 protocol confirmed)"

    # Check SSH access to all nodes
    for node in "${NODES[@]}"; do
        if remote "$node" "echo ok" >/dev/null 2>&1; then
            ok "SSH access: $node"
        else
            fail "Cannot SSH to $node"
        fi
    done

    # Check PM2 on all nodes
    for node in "${NODES[@]}"; do
        if remote "$node" "command -v pm2 >/dev/null 2>&1"; then
            ok "PM2 available: $node"
        else
            warn "PM2 not found on $node — will use systemctl"
        fi
    done

    # Check current running version
    for node in "${NODES[@]}"; do
        local ver
        ver=$(remote "$node" "$REMOTE_BIN --version 2>/dev/null || echo 'unknown'")
        log "  $node running: $ver"
    done

    ok "Preflight complete — ${#NODES[@]} nodes ready"
}

# ═══════════════════════════════════════════════════════════════
#  Phase: Stop
# ═══════════════════════════════════════════════════════════════

stop() {
    log "═══ Stopping All Nodes (simultaneous) ═══"
    log "Stopping ${#NODES[@]} nodes in parallel..."

    if parallel_all "pm2 stop $PM2_PROCESS_NAME 2>/dev/null || sudo systemctl stop misaka-node 2>/dev/null || true"; then
        ok "All nodes stopped"
    else
        warn "Some nodes may not have stopped cleanly"
    fi

    # Verify all stopped
    sleep 2
    for node in "${NODES[@]}"; do
        local running
        running=$(remote "$node" "pm2 pid $PM2_PROCESS_NAME 2>/dev/null || echo 0")
        if [[ "$running" == "0" ]] || [[ -z "$running" ]]; then
            ok "Confirmed stopped: $node"
        else
            warn "Still running on $node (pid=$running) — force killing"
            remote "$node" "pm2 kill $PM2_PROCESS_NAME 2>/dev/null || kill -9 $running 2>/dev/null || true"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════
#  Phase: Deploy
# ═══════════════════════════════════════════════════════════════

deploy() {
    log "═══ Deploying v3 Binary + Config ═══"

    for node in "${NODES[@]}"; do
        log "Deploying to $node..."

        # Create backup directory
        remote "$node" "mkdir -p $REMOTE_BACKUP_DIR"

        # Backup current binary and config
        remote "$node" "cp $REMOTE_BIN $REMOTE_BACKUP_DIR/misaka-node.v2.bak 2>/dev/null || true"
        remote "$node" "cp $REMOTE_CONFIG $REMOTE_BACKUP_DIR/testnet.toml.v2.bak 2>/dev/null || true"
        ok "  Backed up v2 to $REMOTE_BACKUP_DIR"

        # Upload new binary
        scp $SSH_OPTS "$LOCAL_BIN" "$node:$REMOTE_BIN.new"
        remote "$node" "chmod +x $REMOTE_BIN.new && mv $REMOTE_BIN.new $REMOTE_BIN"
        ok "  Binary uploaded"

        # Upload new config
        scp $SSH_OPTS "$LOCAL_CONFIG" "$node:$REMOTE_CONFIG.new"
        remote "$node" "mv $REMOTE_CONFIG.new $REMOTE_CONFIG"
        ok "  Config uploaded"

        ok "Deploy complete: $node"
    done
}

# ═══════════════════════════════════════════════════════════════
#  Phase: Start
# ═══════════════════════════════════════════════════════════════

start() {
    log "═══ Starting All Nodes (simultaneous) ═══"
    log "Starting ${#NODES[@]} nodes in parallel..."

    if parallel_all "pm2 start $PM2_PROCESS_NAME 2>/dev/null || sudo systemctl start misaka-node 2>/dev/null"; then
        ok "All nodes started"
    else
        warn "Some nodes may have failed to start — check logs"
    fi

    sleep 3
    for node in "${NODES[@]}"; do
        local running
        running=$(remote "$node" "pm2 pid $PM2_PROCESS_NAME 2>/dev/null || echo 0")
        if [[ "$running" != "0" ]] && [[ -n "$running" ]]; then
            ok "Confirmed running: $node (pid=$running)"
        else
            fail "Node failed to start: $node — run: ssh $node 'pm2 logs $PM2_PROCESS_NAME'"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════
#  Phase: Verify
# ═══════════════════════════════════════════════════════════════

verify() {
    log "═══ Verifying v3 Handshake ═══"
    log "Waiting 15s for peers to connect..."
    sleep 15

    local all_ok=true

    for node in "${NODES[@]}"; do
        log "Checking $node..."

        # Check peer count via RPC
        local rpc_port=3001
        local peer_info
        peer_info=$(remote "$node" "curl -s http://127.0.0.1:$rpc_port/peers 2>/dev/null || echo '{}'")

        # Check logs for v3 handshake success
        local v3_handshakes
        v3_handshakes=$(remote "$node" "pm2 logs $PM2_PROCESS_NAME --nostream --lines 100 2>/dev/null | grep -c 'Peer.*auth' || echo 0")

        # Check for handshake failures
        local failures
        failures=$(remote "$node" "pm2 logs $PM2_PROCESS_NAME --nostream --lines 100 2>/dev/null | grep -c 'Handshake fail' || echo 0")

        # Check for SEC-P2P-GUARD rejections (expected for non-upgraded nodes)
        local guard_rejects
        guard_rejects=$(remote "$node" "pm2 logs $PM2_PROCESS_NAME --nostream --lines 100 2>/dev/null | grep -c 'SEC-P2P-GUARD' || echo 0")

        log "  Successful handshakes: $v3_handshakes"
        log "  Failed handshakes: $failures"
        log "  Guard rejections: $guard_rejects"

        if [[ "$v3_handshakes" -gt 0 ]]; then
            ok "v3 handshakes confirmed on $node"
        else
            warn "No v3 handshakes yet on $node — may need more time"
            all_ok=false
        fi
    done

    if $all_ok; then
        ok "═══ v3 Protocol Upgrade VERIFIED ═══"
    else
        warn "═══ Some nodes pending verification — monitor with: pm2 logs ═══"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  Phase: Rollback (Emergency)
# ═══════════════════════════════════════════════════════════════

rollback() {
    log "═══ EMERGENCY ROLLBACK to v2 ═══"
    warn "This will restore v2 binary and config on ALL nodes"

    read -p "Are you sure? Type 'ROLLBACK' to confirm: " confirm
    if [[ "$confirm" != "ROLLBACK" ]]; then
        fail "Rollback cancelled"
    fi

    # Stop all nodes
    stop

    # Restore v2 binary and config
    for node in "${NODES[@]}"; do
        log "Rolling back $node..."
        remote "$node" "cp $REMOTE_BACKUP_DIR/misaka-node.v2.bak $REMOTE_BIN 2>/dev/null && chmod +x $REMOTE_BIN"
        remote "$node" "cp $REMOTE_BACKUP_DIR/testnet.toml.v2.bak $REMOTE_CONFIG 2>/dev/null"
        ok "  Restored v2: $node"
    done

    # Restart all
    start

    warn "═══ ROLLBACK COMPLETE — running v2 ═══"
}

# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

main() {
    local phase="${1:-all}"

    echo ""
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║  MISAKA Testnet v3 Protocol Upgrade         ║"
    echo "  ║  Nodes: ${#NODES[@]}                                    ║"
    echo "  ║  Change: v2 → v3 (BREAKING — simultaneous)  ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo ""

    case "$phase" in
        preflight) preflight ;;
        stop)      stop ;;
        deploy)    deploy ;;
        start)     start ;;
        verify)    verify ;;
        rollback)  rollback ;;
        all)
            preflight
            echo ""
            read -p "Proceed with upgrade? [y/N] " yn
            if [[ "$yn" != "y" && "$yn" != "Y" ]]; then
                fail "Upgrade cancelled"
            fi
            echo ""
            stop
            deploy
            start
            verify
            ;;
        *)
            echo "Usage: $0 [preflight|stop|deploy|start|verify|rollback|all]"
            exit 1
            ;;
    esac
}

main "$@"
