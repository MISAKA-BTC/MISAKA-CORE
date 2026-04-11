# MISAKA Validator Guide

## Overview

Validators participate in the Narwhal-based DAG consensus, proposing and voting
on blocks. Each validator holds an ML-DSA-65 keypair stored in an encrypted
keystore.

## 1. Initial Setup

### Generate Validator Key

```bash
cargo build --release -p misaka-node --features "dag,testnet"

MISAKA_VALIDATOR_PASSPHRASE="<strong-passphrase>" \
./target/release/misaka-node \
  --chain-id 2 \
  --data-dir /var/lib/misaka \
  keygen
```

This creates:
- `/var/lib/misaka/l1-secret-key.json` — encrypted keystore
- `/var/lib/misaka/l1-public-key.json` — public key (share with genesis coordinator)

### Keystore Management

The keystore uses Argon2id KDF + ChaCha20-Poly1305 AEAD encryption.

**Security requirements:**
- Passphrase length ≥ 16 characters recommended
- Keystore file permissions: `chmod 600`
- Data directory permissions: `chmod 700`

## 2. Docker Secrets (Production)

Never store passphrases in environment variables for production.
Use Docker secrets:

```bash
mkdir -p docker/secrets
echo "<passphrase>" > docker/secrets/validator_passphrase.txt
chmod 600 docker/secrets/validator_passphrase.txt
```

The node reads secrets from `/run/secrets/validator_passphrase` automatically.

## 3. Running the Validator

### Docker

```bash
cd docker
cp ../.env.example .env
# Edit .env:
#   NODE_VALIDATOR=true
#   NODE_CHAIN_ID=2
#   NODE_SEEDS=<seed-addresses>
#   MISAKA_RPC_AUTH_MODE=required
#   MISAKA_RPC_API_KEY=<api-key>

docker compose -f node-compose.yml up -d
```

### Bare Metal

```bash
MISAKA_VALIDATOR_PASSPHRASE_FILE=/opt/misaka/.passphrase \
./target/release/misaka-node \
  --chain-id 2 \
  --data-dir /var/lib/misaka \
  --validator true \
  --seeds seed1:6690,seed2:6690
```

## 4. Monitoring

### Health Check

```bash
curl -s http://localhost:3001/api/health | jq .
```

### Prometheus Metrics

Metrics are exposed at `/api/metrics` (requires API key when `MISAKA_RPC_AUTH_MODE=required`):

```bash
curl -H "Authorization: Bearer <api-key>" http://localhost:3001/api/metrics
```

### Grafana Dashboards

Import from `dashboards/grafana/`:

| Dashboard | Purpose |
|-----------|---------|
| `misaka-overview.json` | Node health, peer count, block height |
| `misaka-consensus-deep.json` | DAG rounds, commit lag, finalization |

Key alerts to configure:
- Block height stalled > 5 minutes
- Peer count < 2
- Disk usage > 85%
- Commit lag > 100 rounds

## 5. Upgrading

### Rolling Upgrade

1. Pull the latest code / image
2. Stop the node gracefully (sends SIGTERM, 2-minute grace period)
3. Back up the data directory
4. Start with the new binary / image
5. Verify health and peer connectivity

```bash
# Docker
docker compose -f node-compose.yml pull
docker compose -f node-compose.yml up -d

# Bare metal
systemctl stop misaka-node
cp -r /var/lib/misaka /var/lib/misaka.bak
systemctl start misaka-node
```

### State Recovery

If the node crashes, it recovers automatically from the persisted DAG store
on startup. The `CommitFinalizer` restores its `last_finalized_index` from
the highest commit in the store.

## 6. Staking (Testnet)

Current testnet staking parameters (configurable in `testnet.toml`):

| Parameter | Value |
|-----------|-------|
| Minimum stake | 100,000,000,000 (100 MISAKA) |
| Unbonding period | 43,200 blocks |
| Max validators | 50 |

## 7. Security Checklist

- [ ] Keystore passphrase is strong and stored via Docker secrets or file
- [ ] Data directory permissions are 0700
- [ ] RPC auth mode is `required` with a strong API key
- [ ] P2P port (6690) is open; RPC port (3001) is firewalled to trusted IPs
- [ ] Prometheus metrics endpoint is behind auth
- [ ] Node binary is built from a verified source commit
- [ ] Automatic disk space monitoring is enabled
