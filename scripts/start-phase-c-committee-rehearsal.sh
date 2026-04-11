#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export MISAKA_PHASE_C_REHEARSAL="${MISAKA_PHASE_C_REHEARSAL:-1}"
export MISAKA_RUNTIME_TRACK="${MISAKA_RUNTIME_TRACK:-ghostdag-compat}"
export MISAKA_BUILD_FEATURES="${MISAKA_BUILD_FEATURES:-dag,testnet,ghostdag-compat}"

exec "$SCRIPT_DIR/start-testnet.sh" "$@"
