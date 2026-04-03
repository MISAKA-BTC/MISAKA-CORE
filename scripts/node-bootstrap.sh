#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_example="$repo_root/scripts/node.env.example"
env_file="${MISAKA_NODE_ENV_FILE:-$repo_root/scripts/node.env}"
compose_file="$repo_root/docker/node-compose.yml"
compose_cmd=(docker compose)
declare -A env_values=()

fail() {
  echo "$1" >&2
  exit 1
}

warn() {
  echo "warning: $1" >&2
}

usage() {
  cat <<EOF
usage: $(basename "$0") [init|check|config|up|down|logs]

  init    create $env_file from the example and exit
  check   validate the bootstrap env and render the Compose config
  config  validate and render the Compose config using $env_file
  up      validate the Compose config, then build and start the node
  down    stop the node stack
  logs    follow the node logs

If no command is given, 'up' is used.
EOF
}

require_docker_compose() {
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker is required to manage the node stack"
  fi
  if ! "${compose_cmd[@]}" version >/dev/null 2>&1; then
    fail "docker compose plugin is required to manage the node stack"
  fi
}

ensure_env_file() {
  if [[ -f "$env_file" ]]; then
    return 0
  fi

  mkdir -p "$(dirname "$env_file")"
  cp "$env_example" "$env_file"
  cat <<EOF
created $env_file from the example
edit NODE_MODE, NODE_CHAIN_ID, NODE_ADVERTISE_ADDR, NODE_VALIDATOR, and
MISAKA_VALIDATOR_PASSPHRASE as needed before starting a validator
EOF
}

load_env_file() {
  local path="$1"
  local line key value

  env_values=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    case "$line" in
      ""|\#*) continue ;;
      export\ *) line="${line#export }" ;;
    esac

    if [[ ! "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
      fail "invalid env line in $path: $line"
    fi

    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"

    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi

    env_values["$key"]="$value"
  done <"$path"
}

env_value() {
  local key="$1"
  printf '%s' "${env_values[$key]-}"
}

env_value_or_default() {
  local key="$1"
  local default_value="$2"
  if [[ ${env_values[$key]+x} ]]; then
    printf '%s' "${env_values[$key]}"
  else
    printf '%s' "$default_value"
  fi
}

is_uint() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

validate_uint() {
  local name="$1"
  local value="$2"
  local allow_zero="${3:-false}"

  if ! is_uint "$value"; then
    fail "$name must be a non-negative integer, got '$value'"
  fi

  if [[ "$allow_zero" != true && "$value" == "0" ]]; then
    fail "$name must be greater than zero"
  fi
}

validate_port() {
  local name="$1"
  local value="$2"

  validate_uint "$name" "$value" true
  if (( value < 1 || value > 65535 )); then
    fail "$name must be between 1 and 65535, got '$value'"
  fi
}

validate_node_env() {
  local source_path="$1"
  load_env_file "$source_path"

  local node_mode node_validator node_chain_id node_name node_validators
  local node_validator_index node_rpc_port node_p2p_port node_block_time_secs
  local node_dag_k node_dag_checkpoint_interval node_dag_max_txs
  local node_dag_mempool_size node_max_inbound_peers node_max_outbound_peers
  local node_faucet_amount node_faucet_cooldown_ms node_advertise_addr
  local validator_passphrase

  node_mode="$(env_value_or_default NODE_MODE public)"
  node_validator="$(env_value_or_default NODE_VALIDATOR false)"
  node_chain_id="$(env_value_or_default NODE_CHAIN_ID 2)"
  node_name="$(env_value_or_default NODE_NAME misaka-node-0)"
  node_validators="$(env_value_or_default NODE_VALIDATORS 1)"
  node_validator_index="$(env_value_or_default NODE_VALIDATOR_INDEX 0)"
  node_rpc_port="$(env_value_or_default NODE_RPC_PORT 3001)"
  node_p2p_port="$(env_value_or_default NODE_P2P_PORT 6690)"
  node_block_time_secs="$(env_value_or_default NODE_BLOCK_TIME_SECS 60)"
  node_dag_k="$(env_value_or_default NODE_DAG_K 18)"
  node_dag_checkpoint_interval="$(env_value_or_default NODE_DAG_CHECKPOINT_INTERVAL 50)"
  node_dag_max_txs="$(env_value_or_default NODE_DAG_MAX_TXS 256)"
  node_dag_mempool_size="$(env_value_or_default NODE_DAG_MEMPOOL_SIZE 10000)"
  node_max_inbound_peers="$(env_value_or_default NODE_MAX_INBOUND_PEERS 32)"
  node_max_outbound_peers="$(env_value_or_default NODE_MAX_OUTBOUND_PEERS 8)"
  node_faucet_amount="$(env_value_or_default NODE_FAUCET_AMOUNT 1000000)"
  node_faucet_cooldown_ms="$(env_value_or_default NODE_FAUCET_COOLDOWN_MS 300000)"
  node_advertise_addr="$(env_value_or_default NODE_ADVERTISE_ADDR "")"
  validator_passphrase="$(env_value_or_default MISAKA_VALIDATOR_PASSPHRASE "")"

  case "$node_mode" in
    public|hidden|seed|validator) ;;
    *)
      fail "NODE_MODE must be one of public, hidden, seed, or validator; got '$node_mode'"
      ;;
  esac

  if [[ -z "${env_values[NODE_MODE]+x}" ]]; then
    warn "NODE_MODE is not set in $source_path; the Compose default will be used"
  fi

  validate_uint NODE_CHAIN_ID "$node_chain_id"
  validate_uint NODE_VALIDATORS "$node_validators"
  validate_uint NODE_VALIDATOR_INDEX "$node_validator_index" true
  validate_port NODE_RPC_PORT "$node_rpc_port"
  validate_port NODE_P2P_PORT "$node_p2p_port"
  validate_uint NODE_BLOCK_TIME_SECS "$node_block_time_secs"
  validate_uint NODE_DAG_K "$node_dag_k"
  validate_uint NODE_DAG_CHECKPOINT_INTERVAL "$node_dag_checkpoint_interval"
  validate_uint NODE_DAG_MAX_TXS "$node_dag_max_txs"
  validate_uint NODE_DAG_MEMPOOL_SIZE "$node_dag_mempool_size"
  validate_uint NODE_MAX_INBOUND_PEERS "$node_max_inbound_peers"
  validate_uint NODE_MAX_OUTBOUND_PEERS "$node_max_outbound_peers"
  validate_uint NODE_FAUCET_AMOUNT "$node_faucet_amount"
  validate_uint NODE_FAUCET_COOLDOWN_MS "$node_faucet_cooldown_ms"

  if (( node_validator_index >= node_validators )); then
    fail "NODE_VALIDATOR_INDEX must be smaller than NODE_VALIDATORS"
  fi

  if [[ "$node_mode" == "seed" && "$(printf '%s' "$node_validator" | tr '[:upper:]' '[:lower:]')" != "false" ]]; then
    fail "NODE_MODE=seed cannot be combined with NODE_VALIDATOR=true"
  fi

  if [[ "$node_mode" == "validator" || "$(printf '%s' "$node_validator" | tr '[:upper:]' '[:lower:]')" == "true" ]]; then
    if [[ -z "$validator_passphrase" ]]; then
      fail "validator mode requires MISAKA_VALIDATOR_PASSPHRASE to be set"
    fi
  fi

  if [[ "$node_mode" == "public" || "$node_mode" == "validator" ]] && [[ -z "$node_advertise_addr" ]]; then
    warn "NODE_ADVERTISE_ADDR is empty for a public/validator node; inbound peers may not be able to dial it"
  fi
}

validate_compose_config() {
  "${compose_cmd[@]}" --env-file "$env_file" -f "$compose_file" config >/dev/null
}

rehearse_bootstrap_config() {
  local tmp_env
  tmp_env="$(mktemp "${TMPDIR:-/tmp}/misaka-node-env.XXXXXX")"
  cp "$env_example" "$tmp_env"
  trap 'rm -f "$tmp_env"' RETURN
  env_file="$tmp_env"
  validate_node_env "$env_file"
  validate_compose_config
}

cmd="${1:-up}"
if [[ $# -gt 0 ]]; then
  shift
fi

if [[ $# -gt 0 ]]; then
  usage >&2
  exit 1
fi

case "$cmd" in
  init)
    ensure_env_file
    exit 0
    ;;
  check)
    require_docker_compose
    if [[ -f "$env_file" ]]; then
      validate_node_env "$env_file"
      validate_compose_config
    else
      rehearse_bootstrap_config
    fi
    ;;
  config)
    require_docker_compose
    if [[ ! -f "$env_file" ]]; then
      echo "env file not found: $env_file" >&2
      echo "run $(basename "$0") init first" >&2
      exit 1
    fi
    validate_node_env "$env_file"
    validate_compose_config
    "${compose_cmd[@]}" --env-file "$env_file" -f "$compose_file" config
    ;;
  up)
    require_docker_compose
    ensure_env_file
    validate_node_env "$env_file"
    validate_compose_config
    "${compose_cmd[@]}" --env-file "$env_file" -f "$compose_file" up -d --build
    ;;
  down)
    require_docker_compose
    if [[ ! -f "$env_file" ]]; then
      echo "env file not found: $env_file" >&2
      exit 1
    fi
    "${compose_cmd[@]}" --env-file "$env_file" -f "$compose_file" down
    ;;
  logs)
    require_docker_compose
    if [[ ! -f "$env_file" ]]; then
      echo "env file not found: $env_file" >&2
      exit 1
    fi
    "${compose_cmd[@]}" --env-file "$env_file" -f "$compose_file" logs -f
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
