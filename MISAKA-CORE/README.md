# MISAKA Network

**Post-Quantum Native Layer 1 Blockchain**

A high-performance BlockDAG with dual-lane block production, ML-DSA-65 lattice-based cryptography, and optional shielded transactions.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              21 Super Representatives            │
│         Round-Robin Block Production             │
├────────────────────┬────────────────────────────┤
│   ⚡ Fast Lane     │    🛡️ ZKP Batch Lane       │
│   2s / block       │    30s / block             │
│   Transparent TX   │    Shielded TX             │
├────────────────────┴────────────────────────────┤
│              GhostDAG Consensus (K=18)           │
├─────────────────────────────────────────────────┤
│   ML-DSA-65 (FIPS 204)  │  ML-KEM-768 (P2P)    │
│   SHA3-256 / Blake3      │  Post-Quantum Safe    │
├─────────────────────────────────────────────────┤
│              UTXO Model + Shielded Pool          │
└─────────────────────────────────────────────────┘
```

## Key Features

| Feature | Specification |
|---------|--------------|
| Consensus | 21 SR DPoS + GhostDAG |
| Cryptography | ML-DSA-65 (NIST FIPS 204) — 128-bit quantum security |
| Block Time | 2s (transparent) / 30s (shielded) |
| Finality | ~1 minute (30 Fast blocks) |
| Max Supply | 10,000,000,000 MISAKA |
| Decimals | 9 |
| Min Stake | 10,000,000 MISAKA |
| P2P Encryption | ML-KEM-768 + ChaCha20-Poly1305 |
| Shielded Pool | SHA3 Merkle commitment tree + nullifier set |
| Bridge | Solana SPL ↔ MISAKA (Anchor program) |

## Project Structure

```
MISAKA-CORE/
├── crates/
│   ├── misaka-types/        # Core types, constants, address encoding
│   ├── misaka-crypto/       # ML-DSA-65, Blake3, key derivation
│   ├── misaka-pqc/          # Post-quantum ring signatures, key management
│   ├── misaka-dag/          # GhostDAG consensus, block production, virtual state
│   ├── misaka-node/         # Full node: P2P, RPC, block producer, validator
│   ├── misaka-cli/          # Command-line wallet and tools
│   ├── misaka-shielded/     # Shielded pool: commitment tree, nullifier set, proofs
│   ├── misaka-storage/      # UTXO set, persistent storage
│   ├── misaka-mempool/      # Transaction mempool with nullifier tracking
│   ├── misaka-mining/       # Block template construction
│   ├── misaka-consensus/    # Staking registry, validator lifecycle
│   ├── misaka-rpc/          # RPC types and handlers
│   ├── misaka-txscript/     # Script engine (Kaspa-compatible + PQ opcodes)
│   ├── misaka-security/     # Overflow protection, constant-time ops, fuzzing
│   ├── misaka-tokenomics/   # Inflation schedule, block rewards, fee distribution
│   └── misaka-notify/       # Event notification system
├── configs/
│   ├── mainnet.toml
│   └── testnet.toml
├── solana-bridge/
│   └── programs/
│       ├── misaka-bridge/   # Anchor: lock/unlock SPL tokens
│       └── misaka-staking/  # Anchor: validator staking (deployed)
├── relayer/                 # Solana ↔ MISAKA bridge relayer
└── wallet/                  # Wallet core library
```

## Quick Start

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- Linux (Ubuntu 22.04+) or macOS

### Build

```bash
cargo build --release
# For testnet P2P (TOFU handshake):
cargo build --release --features allow-tofu
```

### Generate Wallet

```bash
./target/release/misaka-cli keygen --name my-wallet
```

### Run Validator Node

```bash
# 1. Setup validator (interactive guide)
./target/release/misaka-cli setup-validator --data-dir ./data --chain-id 2

# 2. Generate validator key
export MISAKA_VALIDATOR_PASSPHRASE="your-secure-passphrase"
./target/release/misaka-node --keygen-only --name validator-0 --data-dir ./data

# 3. Start node
./target/release/misaka-node \
  --validator \
  --validator-index 0 \
  --validators 21 \
  --data-dir ./data \
  --chain-id 2 \
  --advertise-addr YOUR_IP:6690
```

### Connect Peer Node

```bash
./target/release/misaka-node \
  --validator \
  --validator-index 1 \
  --validators 21 \
  --data-dir ./data \
  --seeds SEED_IP:6690 \
  --advertise-addr YOUR_IP:6690
```

## CLI Commands

### Wallet & Transfers

```bash
# Check balance
misaka-cli balance <ADDRESS> --rpc http://127.0.0.1:3001

# Transparent send (ML-DSA-65 signed)
misaka-cli send <TO_ADDRESS> <AMOUNT> --rpc http://127.0.0.1:3001

# Faucet (testnet only)
curl -s http://127.0.0.1:3001/api/faucet -X POST \
  -H "Content-Type: application/json" \
  -d '{"address":"<ADDR>","spendingPubkey":"<PK_HEX>"}'
```

### Shielded Transactions

```bash
# Deposit to shielded pool
misaka-cli shield-deposit --amount 200000000 --wallet wallet.key.json --rpc http://127.0.0.1:3001

# Withdraw from shielded pool
misaka-cli shield-withdraw --to <ADDRESS> --amount 100000000 --wallet wallet.key.json --rpc http://127.0.0.1:3001

# Check shielded pool status
misaka-cli shielded-status --rpc http://127.0.0.1:3001
```

### Validator Setup

```bash
# Interactive SR21 setup guide
misaka-cli setup-validator --data-dir ./data --chain-id 2

# Check stake on Solana
misaka-cli check-stake --key-file data/l1-public-key.json
```

## RPC API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Node health check |
| `/api/get_chain_info` | POST | Chain info (height, tips, etc.) |
| `/api/get_virtual_state` | POST | Virtual state (UTXO count, nullifiers) |
| `/api/get_utxos_by_address` | POST | UTXOs for an address |
| `/api/submit_tx` | POST | Submit transparent transaction |
| `/api/faucet` | POST | Testnet faucet |
| `/api/shielded/module_status` | GET | Shielded pool status |
| `/api/shielded/submit_deposit` | POST | Shield deposit |
| `/api/shielded/submit_withdraw` | POST | Shield withdraw |
| `/api/shielded/submit_transfer` | POST | Shielded transfer |

## Tokenomics

| Parameter | Value |
|-----------|-------|
| Total Supply | 10,000,000,000 MISAKA |
| Decimals | 9 |
| Initial Block Reward | 50 MISAKA |
| Min Validator Stake | 10,000,000 MISAKA |
| Staking Program | `27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG` |

## Dual-Lane Block Timing

All retention policies use wall-clock time, converted per lane:

| Wall-Clock | Fast Lane (2s) | ZKP Lane (30s) |
|------------|----------------|----------------|
| 1 minute | 30 blocks | 2 blocks |
| 1 hour | 1,800 blocks | 120 blocks |
| 6 hours | 10,800 blocks | 720 blocks |
| 24 hours | 43,200 blocks | 2,880 blocks |
| 7 days | 302,400 blocks | 20,160 blocks |

## Solana Bridge

Lock-and-mint bridge between Solana SPL tokens and MISAKA:

```
Solana → MISAKA: lock_tokens() → Relayer → MISAKA mint
MISAKA → Solana: MISAKA burn → Relayer → unlock_tokens() (M-of-N committee)
```

Bridge program: `solana-bridge/programs/misaka-bridge/`
Staking program: `solana-bridge/programs/misaka-staking/`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MISAKA_VALIDATOR_PASSPHRASE` | Validator key encryption | (required) |
| `MISAKA_SOLANA_RPC_URL` | Solana RPC for stake verification | (optional) |
| `MISAKA_STAKING_PROGRAM_ID` | Staking program address | `27WjgCA...` |
| `MISAKA_RPC_API_KEY` | RPC write endpoint auth | (optional) |
| `MISAKA_FAUCET_AMOUNT` | Faucet drip amount (base units) | `1000000000` |

## Security

- **Post-Quantum**: ML-DSA-65 (NIST FIPS 204) for all signatures
- **P2P Encryption**: ML-KEM-768 key exchange + ChaCha20-Poly1305
- **Shielded Pool**: SHA3-256 Merkle proofs (quantum-resistant)
- **Bridge**: M-of-N Ed25519 committee signatures with replay protection
- **Signature Verification**: All transparent TX inputs verified at admission

## License

MIT
