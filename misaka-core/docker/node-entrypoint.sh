#!/usr/bin/env sh
set -eu

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

data_dir="${NODE_DATA_DIR:-/var/lib/misaka}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$data_dir"
  chown -R misaka:misaka "$data_dir"
fi

set -- misaka-node
set -- "$@" --name "${NODE_NAME:-misaka-node-0}"
set -- "$@" --mode "${NODE_MODE:-public}"
set -- "$@" --rpc-port "${NODE_RPC_PORT:-3001}"
set -- "$@" --p2p-port "${NODE_P2P_PORT:-6690}"
set -- "$@" --block-time "${NODE_BLOCK_TIME_SECS:-60}"
set -- "$@" --validator-index "${NODE_VALIDATOR_INDEX:-0}"
set -- "$@" --validators "${NODE_VALIDATORS:-1}"
set -- "$@" --data-dir "$data_dir"
set -- "$@" --log-level "${NODE_LOG_LEVEL:-info}"
set -- "$@" --chain-id "${NODE_CHAIN_ID:-2}"
set -- "$@" --faucet-amount "${NODE_FAUCET_AMOUNT:-1000000}"
set -- "$@" --faucet-cooldown-ms "${NODE_FAUCET_COOLDOWN_MS:-300000}"
set -- "$@" --dag-k "${NODE_DAG_K:-18}"
set -- "$@" --dag-checkpoint-interval "${NODE_DAG_CHECKPOINT_INTERVAL:-50}"
set -- "$@" --dag-max-txs "${NODE_DAG_MAX_TXS:-256}"
set -- "$@" --dag-mempool-size "${NODE_DAG_MEMPOOL_SIZE:-10000}"

if [ -n "${NODE_ADVERTISE_ADDR:-}" ]; then
  set -- "$@" --advertise-addr "$NODE_ADVERTISE_ADDR"
fi

if is_true "${NODE_OUTBOUND_ONLY:-false}"; then
  set -- "$@" --outbound-only
fi

if is_true "${NODE_HIDE_MY_IP:-false}"; then
  set -- "$@" --hide-my-ip
fi

if is_true "${NODE_VALIDATOR:-false}"; then
  set -- "$@" --validator
fi

if [ -n "${NODE_PEERS:-}" ]; then
  set -- "$@" --peers "$NODE_PEERS"
fi

if [ -n "${NODE_SEEDS:-}" ]; then
  set -- "$@" --seeds "$NODE_SEEDS"
fi

if [ -n "${NODE_MAX_INBOUND_PEERS:-}" ]; then
  set -- "$@" --max-inbound-peers "$NODE_MAX_INBOUND_PEERS"
fi

if [ -n "${NODE_MAX_OUTBOUND_PEERS:-}" ]; then
  set -- "$@" --max-outbound-peers "$NODE_MAX_OUTBOUND_PEERS"
fi

if [ -n "${NODE_PROXY:-}" ]; then
  set -- "$@" --proxy "$NODE_PROXY"
fi

if [ -n "${NODE_DAG_RPC_PEERS:-}" ]; then
  set -- "$@" --dag-rpc-peers "$NODE_DAG_RPC_PEERS"
fi

if is_true "${NODE_EXPERIMENTAL_ZK_PATH:-false}"; then
  set -- "$@" --experimental-zk-path
fi

if [ "$(id -u)" = "0" ]; then
  exec gosu misaka "$@"
fi

exec "$@"
