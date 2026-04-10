# MISAKA Network — Public Testnet Quickstart

## Requirements

- Ubuntu 22.04+ / macOS 13+
- 2 GB RAM, 20 GB disk
- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- OpenSSL dev: `sudo apt install pkg-config libssl-dev build-essential`

## 1. Quick Start (Single Node)

```bash
git clone https://github.com/nicetomeetyou-42/MISAKA-CORE.git
cd MISAKA-CORE
bash scripts/start-node.sh
```

The script automatically generates a validator key and genesis manifest
on first run. Node will start on `http://localhost:3000`.

## 2. Local Testnet (3 Validators)

```bash
bash scripts/start-testnet.sh
```

This generates 3 validator keys, creates a genesis committee manifest,
and starts 3 nodes on localhost (RPC: 3000-3002, P2P: 16110-16112).

## 3. Verify Node is Running

```bash
curl http://localhost:3000/api/health
# -> ok

curl http://localhost:3000/api/status
# -> {"current_round":0,"num_blocks":0,...}

curl http://localhost:3000/api/get_chain_info
# -> {"chain":"MISAKA Network","consensus":"Narwhal/Bullshark",...}
```

## 4. Get Testnet Tokens (Faucet)

```bash
curl -X POST http://localhost:3000/api/faucet \
  -H "Content-Type: application/json" \
  -d '{"address":"YOUR_ADDRESS","amount":100000}'
```

## 5. Send a Transaction

```bash
curl -X POST http://localhost:3000/api/submit_tx \
  -H "Content-Type: application/json" \
  -d '{"version":1,"tx_type":6,"inputs":[],"outputs":[{"amount":1000}],"fee":10}'
```

## 6. Check Metrics

```bash
curl http://localhost:3000/api/metrics | head -20
```

## Testnet Info

| Item | Value |
|------|-------|
| Chain ID | 2 (testnet) |
| Network | `misaka-testnet-1` |
| Consensus | Narwhal/Bullshark (BFT) |
| PQ Signature | ML-DSA-65 (FIPS 204) |
| Address Prefix | `misakatest1` |

## Configuration

Environment variables:
```
MISAKA_RPC_PORT=3000
MISAKA_P2P_PORT=6690
MISAKA_DATA_DIR=./misaka-data
MISAKA_VALIDATORS=1
MISAKA_VALIDATOR_INDEX=0
MISAKA_CHAIN_ID=2
MISAKA_GENESIS_PATH=./misaka-data/genesis_committee.toml
```

## Troubleshooting

- **Port already in use**: `sudo lsof -i :3000` then `kill -9 <PID>`
- **Build fails**: `sudo apt install pkg-config libssl-dev build-essential clang cmake`
- **Node stops on SSH disconnect**: Use `nohup` or `tmux`
- **Genesis error**: Delete `misaka-data/` and re-run — the script regenerates keys and genesis
