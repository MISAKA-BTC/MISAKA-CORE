#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_example="$repo_root/scripts/relayer.env.example"
env_file="$repo_root/scripts/relayer.env"
compose_file="$repo_root/relayer/docker-compose.yml"

if [[ ! -f "$env_file" ]]; then
  mkdir -p "$(dirname "$env_file")"
  cp "$env_example" "$env_file"
  cat <<EOF
created $env_file from the example
edit it to point at your RPC endpoints, bridge program id, and relayer keypair
EOF
  exit 0
fi

if [[ ! -f "$compose_file" ]]; then
  echo "compose file not found: $compose_file" >&2
  exit 1
fi

docker compose -f "$compose_file" up -d --build
