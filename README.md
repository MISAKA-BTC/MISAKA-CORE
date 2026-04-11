# MISAKA Network

**Post-Quantum Native Layer 1 Blockchain**

A high-performance BlockDAG with Narwhal/Bullshark consensus, ML-DSA-65 (FIPS 204) post-quantum signatures, and ML-KEM-768 (FIPS 203) P2P key exchange.

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Narwhal/Bullshark DAG Consensus         │
│         21 Super Representatives (DPoS)          │
├─────────────────────────────────────────────────┤
│   ML-DSA-65 (FIPS 204)  │  ML-KEM-768 (P2P)    │
│   SHA3-256 / BLAKE3      │  Post-Quantum Safe    │
├─────────────────────────────────────────────────┤
│          Transparent UTXO Model                  │
└─────────────────────────────────────────────────┘
```

## Key Features

| Feature | Specification |
|---------|--------------|
| Consensus | Narwhal/Bullshark DAG (Sui-aligned) |
| Cryptography | ML-DSA-65 (NIST FIPS 204) -- 128-bit quantum security |
| Block Time | ~2s |
| Finality | BFT checkpoint voting |
| Max Supply | 10,000,000,000 MISAKA |
| Decimals | 9 |
| Min Stake | 10,000,000 MISAKA |
| P2P Encryption | ML-KEM-768 + ChaCha20-Poly1305 |
| Transaction Model | Transparent UTXO (sender, receiver, amount visible on-chain) |
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
│   ├── misaka-storage/      # UTXO set, persistent storage
│   ├── misaka-mempool/      # Transaction mempool with fee-rate priority
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
├── wallet/core/             # Wallet core library
└── docs/                    # Testnet deploy, validator guide
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

### Privacy Model

MISAKA v1.0 is a transparent blockchain. All transactions reveal sender,
receiver, and amount on-chain. Confidential transaction features were removed
before mainnet because the available ZK proof systems (Groth16, PLONK over
BLS12-381) rely on pairing-based cryptography broken by Shor's algorithm.
See [docs/whitepaper_errata.md](docs/whitepaper_errata.md) for details.

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
<!-- Shielded endpoints removed in v1.0. See CHANGELOG.md. -->

## Tokenomics

| Parameter | Value |
|-----------|-------|
| Total Supply | 10,000,000,000 MISAKA |
| Decimals | 9 |
| Initial Block Reward | 50 MISAKA |
| Min Validator Stake | 10,000,000 MISAKA |
| Staking Program | `27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG` |

## Block Timing

| Wall-Clock | Blocks (~2s each) |
|------------|-------------------|
| 1 minute | ~30 |
| 1 hour | ~1,800 |
| 24 hours | ~43,200 |
| 7 days | ~302,400 |

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
- **Bridge**: M-of-N Ed25519 committee signatures with replay protection
- **Signature Verification**: All transparent TX inputs verified at admission
- **Supply Cap**: Hard-enforced MAX_TOTAL_SUPPLY at consensus execution layer

## Testnet Deployment

See [docs/TESTNET_DEPLOY_GUIDE.md](docs/TESTNET_DEPLOY_GUIDE.md) for full testnet setup and operation instructions, and [docs/VALIDATOR_GUIDE.md](docs/VALIDATOR_GUIDE.md) for validator participation.

## License

Apache-2.0
