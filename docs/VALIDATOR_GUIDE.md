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

## 7. Registration Trust Model (0.9.0 β-3)

`/api/register_validator` is protected by two independent signature checks
and one operator-controlled bypass. Understanding which signature proves
what prevents misconfiguration at onboarding time.

### Signatures involved

| Field | Type | What it proves | What it does NOT prove |
|-------|------|----------------|------------------------|
| `public_key` | ML-DSA-65 pubkey hex (1952 bytes) | The pubkey is well-formed. | That the caller owns the corresponding private key. |
| `intent_signature` | ML-DSA-65 sig over `"MISAKA:rest_register:v1:" \|\| public_key \|\| network_address` | The caller controls the L1 private key AND committed to this exact `(pubkey, network_address)` tuple — replay to other endpoints is impossible. | That any stake exists on-chain. |
| `solana_stake_signature` | Solana TX signature | A finalized Solana TX staked ≥ `min_validator_stake` for this L1 key via the MISAKA staking program. | That the caller controls the L1 private key (only that they know *a* valid staking TX). |

Only the combination `intent_signature + solana_stake_signature` is a full
proof of both identity and economic commitment. Either alone is
insufficient for mainnet.

### Lifecycle after POST

1. Request body is parsed; `intent_signature` (if supplied) is verified
   synchronously against the domain-tagged digest. Invalid signatures
   reject with HTTP 200 + `ok: false`.
2. Validator inserted into `StakingRegistry` as `LOCKED`,
   `solana_stake_verified = false`, `solana_stake_signature = Some(sig)`.
3. Committee is hot-reloaded (the new validator is **not** yet an
   authority — `LOCKED` is filtered out).
4. A tokio task is spawned that calls `verify_solana_stake(...)` against
   the configured Solana RPC. The request handler returns immediately
   with `stake_verification: "pending"`.
5. On RPC success the task takes the registry write lock, calls
   `mark_stake_verified` + `activate(LOCKED → ACTIVE)`, then hot-reloads
   the committee a second time — the validator enters the authority set.
6. On RPC failure the validator remains `LOCKED` and is never promoted.
   No automatic retry — the operator must re-register after fixing the
   staking TX.

### `stake_verification` response field

| Value | Meaning |
|-------|---------|
| `"pending"` | Background verifier was spawned; poll `/api/get_committee` to see when the validator enters the authority set. |
| `"skipped"` | No `solana_stake_signature` supplied. Validator stays `LOCKED` indefinitely. |
| `"bypassed"` | Node was started with `--allow-unverified-validators`. Validator was activated **without** on-chain verification. See the warning below. |

### `--allow-unverified-validators` (testnet only)

CLI flag (or env `MISAKA_ALLOW_UNVERIFIED_VALIDATORS=1`) that short-circuits
the entire Solana verification path: new registrations are inserted with
`solana_stake_verified = true` and immediately promoted to `ACTIVE`. The
node logs a prominent `tracing::warn!` at startup and on every use.

**This flag must never be enabled on mainnet**: it removes the economic
security of the validator set. Anyone with network access to
`/api/register_validator` can join consensus. Testnet and CI are the
only legitimate use cases.

### Required Solana environment

When `--allow-unverified-validators` is **not** set, the background
verifier needs:

| Variable | Purpose | Default |
|----------|---------|---------|
| `MISAKA_SOLANA_RPC_URL` | Solana JSON-RPC endpoint | `https://api.mainnet-beta.solana.com` |
| `MISAKA_STAKING_PROGRAM_ID` | Deployed MISAKA staking program | `27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG` |
| `MISAKA_STAKING_POOL_ID` | Pool PDA seed | `papaYBfvZcmfmSNHM86zc5NAH5B7Kso1PXYGQsKFYnE` |

If the RPC URL or program ID is unset the verifier logs a warning and the
validator stays `LOCKED` — the same outcome as an RPC failure.

## 8. Security Checklist

- [ ] Keystore passphrase is strong and stored via Docker secrets or file
- [ ] Data directory permissions are 0700
- [ ] RPC auth mode is `required` with a strong API key
- [ ] P2P port (6690) is open; RPC port (3001) is firewalled to trusted IPs
- [ ] Prometheus metrics endpoint is behind auth
- [ ] Node binary is built from a verified source commit
- [ ] Automatic disk space monitoring is enabled
