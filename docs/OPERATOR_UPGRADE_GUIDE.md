# Operator Upgrade Guide: Testnet to Mainnet

Step-by-step guide for migrating a MISAKA node from testnet to mainnet.

## Prerequisites

- Running testnet node (v0.5.x or later)
- Access to validator keypair
- Mainnet genesis file
- Sufficient disk space for mainnet chain data

## Step 1: Back Up Testnet Data

```bash
# Stop the testnet node
misaka-cli node stop

# Back up the entire data directory
cp -r ~/.misaka/testnet ~/.misaka/testnet-backup-$(date +%Y%m%d)

# Back up validator keys separately
cp -r ~/.misaka/keystore ~/.misaka/keystore-backup-$(date +%Y%m%d)
```

## Step 2: Update Configuration

Edit `~/.misaka/config.toml`:

```toml
[network]
chain_id = 1              # mainnet chain ID
network = "mainnet"

[rpc]
admin_bind = "127.0.0.1:3002"  # localhost only on mainnet

[bridge]
verifier = "committee"    # never "mock" on mainnet
```

Remove any testnet-specific settings:
- `faucet_enabled = true`
- `dev_mode = true`
- `allow_tofu = true`

## Step 3: Verify Genesis Hash

```bash
# Download official mainnet genesis
curl -LO https://releases.misaka.network/mainnet/genesis.json

# Verify hash matches published value
sha256sum genesis.json
# Compare with the hash published on the official website
```

Place genesis file in the data directory:
```bash
cp genesis.json ~/.misaka/mainnet/genesis.json
```

## Step 4: Set Validator Passphrase

```bash
# Set passphrase (minimum 12 characters)
export MISAKA_VALIDATOR_PASSPHRASE="your-secure-passphrase-here"

# Alternatively, use a secrets file (chmod 600)
echo 'MISAKA_VALIDATOR_PASSPHRASE=your-secure-passphrase' > ~/.misaka/.env
chmod 600 ~/.misaka/.env
```

Never store the passphrase in shell history. Use `set +o history` temporarily if entering interactively.

## Step 5: Migrate Keystore

```bash
# If using file-based keystore, move keys to mainnet directory
mkdir -p ~/.misaka/mainnet/keystore
cp ~/.misaka/keystore/validator.enc ~/.misaka/mainnet/keystore/

# Verify key loads correctly
misaka-cli key-verify --keystore ~/.misaka/mainnet/keystore
```

If upgrading keystore format, use the migration tool:
```bash
misaka-cli keystore-migrate --from ~/.misaka/keystore --to ~/.misaka/mainnet/keystore
```

## Step 6: Run Startup Checks

```bash
# Dry-run startup checks without starting the node
misaka-node --data-dir ~/.misaka/mainnet --startup-check --mainnet

# Expected output:
# startup check 'data_dir_writable': PASS
# startup check 'validator_passphrase': PASS
# startup check 'release_manifest': PASS
```

All checks must pass before proceeding.

## Step 7: Verify Bridge State

If running a bridge validator:

```bash
# Check bridge persistence files
ls -la ~/.misaka/mainnet/bridge/

# Verify nullifier file integrity (size must be multiple of 32)
wc -c ~/.misaka/mainnet/bridge/bridge_nullifiers.dat

# Check circuit breaker is configured
grep -A5 'circuit_breaker' ~/.misaka/config.toml
```

## Step 8: Start Mainnet Node

```bash
# Start with explicit mainnet flag
misaka-node --data-dir ~/.misaka/mainnet --network mainnet

# Monitor logs for startup check results
tail -f ~/.misaka/mainnet/logs/misaka.log | grep -i "startup\|error\|warning"
```

## Post-Launch Verification

- [ ] Node is syncing blocks from mainnet peers
- [ ] Admin RPC is only accessible on localhost
- [ ] Bridge verifier reports `committee` (not `mock`)
- [ ] Prometheus metrics are being exported
- [ ] Monitoring alerts are configured and tested

## Rollback Procedure

If issues are encountered, revert to testnet:

```bash
misaka-cli node stop
# Restore testnet config
cp ~/.misaka/testnet-backup-*/config.toml ~/.misaka/config.toml
misaka-node --data-dir ~/.misaka/testnet --network testnet
```
