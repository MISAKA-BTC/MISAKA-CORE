# MISAKA Public Testnet — Deployment Guide

## Prerequisites

- **Rust** 1.75+ (with `cargo`)
- **Docker** 24+ and `docker compose` v2+
- **Ports**: 3001 (RPC), 6690 (P2P), 16110 (Narwhal DAG), 17110 (wRPC)
- **Disk**: ≥ 20 GB SSD recommended
- **RAM**: ≥ 4 GB

## 1. Genesis Generation

Generate the genesis configuration and initial validator key:

```bash
# Build the CLI
cargo build --release -p misaka-cli

# Generate genesis for a new testnet (chain_id = 2)
./target/release/misaka-cli genesis \
  --chain-id 2 \
  --validators 4 \
  --output-dir ./genesis-output
```

This creates:
- `genesis.json` — genesis block definition
- `validator-keys/` — encrypted keystores per validator

## 2. Node Setup (Docker)

### 2.1. Prepare secrets

```bash
mkdir -p docker/secrets
echo "your-validator-passphrase" > docker/secrets/validator_passphrase.txt
chmod 600 docker/secrets/validator_passphrase.txt
```

### 2.2. Configure `.env`

```bash
cp .env.example .env
# Edit .env:
#   NODE_NAME=misaka-node-0
#   NODE_CHAIN_ID=2
#   NODE_VALIDATOR=true
#   NODE_SEEDS=seed1.example.com:6690,seed2.example.com:6690
#   MISAKA_RPC_AUTH_MODE=required
#   MISAKA_RPC_API_KEY=<generate-a-strong-key>
```

### 2.3. Start the node

```bash
cd docker
docker compose -f node-compose.yml up -d
```

### 2.4. Verify health

```bash
curl -s http://localhost:3001/api/health | jq .
```

Expected: `{"status":"ok","blockHeight":...,"peerCount":...}`

## 3. Node Setup (Direct / Bare Metal)

```bash
# Build
cargo build --release -p misaka-node --features "dag,testnet"

# Run
MISAKA_VALIDATOR_PASSPHRASE_FILE=/opt/misaka/.passphrase \
MISAKA_RPC_AUTH_MODE=required \
MISAKA_RPC_API_KEY=<key> \
./target/release/misaka-node \
  --chain-id 2 \
  --data-dir /var/lib/misaka \
  --rpc-port 3001 \
  --p2p-port 6690 \
  --seeds seed1.example.com:6690 \
  --validator true
```

## 4. Seed Node Configuration

Seed nodes run with `--validator false` and `--node-mode public`:

```bash
NODE_VALIDATOR=false NODE_MODE=public docker compose -f node-compose.yml up -d
```

## 5. Faucet

Request testnet tokens:

```bash
curl -X POST http://localhost:3001/api/v1/faucet/request \
  -H 'Content-Type: application/json' \
  -d '{"address": "<your-misaka-address>"}'
```

Default cooldown: 300 seconds (configurable via `MISAKA_FAUCET_COOLDOWN_SECS`).

## 6. Explorer

The public API server (`misaka-api`) provides:

- REST API: `http://<api-host>:8080/api/v1/...`
- WebSocket: `ws://<api-host>:8080/ws` (real-time block events)
- Swagger: `http://<api-host>:8080/docs`

## 7. Monitoring

### Prometheus

Update `configs/prometheus.yml` with your node targets. Scrape path: `/api/metrics`.

```bash
prometheus --config.file=configs/prometheus.yml
```

### Grafana

Import dashboards from `dashboards/grafana/`:
- `misaka-overview.json` — node health overview
- `misaka-consensus-deep.json` — DAG consensus metrics

## 8. Troubleshooting

| Symptom | Check |
|---------|-------|
| Node stuck at round 0 | Verify seeds are reachable: `curl http://seed:3001/api/health` |
| `FATAL: MISAKA_VALIDATOR_PASSPHRASE` | Set passphrase via Docker secret or env var |
| `401 Unauthorized` on RPC | Set `MISAKA_RPC_API_KEY` and pass via `Authorization: Bearer <key>` |
| Disk full | Check with `df -h`; node logs disk usage warnings at 90% |
| Peer count = 0 | Ensure P2P port (6690) is reachable; check firewall rules |
