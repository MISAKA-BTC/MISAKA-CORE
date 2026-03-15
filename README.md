
---

# MISAKA Network — CLI Setup Guide (v0.4.1)

Post-Quantum Privacy Layer-1 Blockchain

---

# 配布物

| File                     | Description                                |
| ------------------------ | ------------------------------------------ |
| `misaka-net-core.tar.gz` | MISAKA L1 Blockchain Core (Rust workspace) |
| `misaka-explorer.tar.gz` | Block Explorer (Next.js 14)                |

---

# 1. misaka-net-core (Rust Node)

## Requirements

```
Rust 1.75+
cargo
OpenSSL dev headers
pkg-config
cmake
clang
```

Ubuntu

```bash
sudo apt update

sudo apt install \
build-essential \
pkg-config \
libssl-dev \
cmake \
clang
```

Install Rust

```bash
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
```

---

# Build

```bash
tar xzf misaka-net-core.tar.gz
cd misaka-net-core

cargo build --release
```

---

# Test

Run all tests

```bash
cargo test --workspace
```

Test specific modules

```bash
cargo test -p misaka-pqc
cargo test -p misaka-mempool
cargo test -p misaka-consensus
```

---

# Workspace Structure

```
crates/
```

| crate               | role                             |
| ------------------- | -------------------------------- |
| misaka-types        | UTXO / stealth / block types     |
| misaka-pqc          | post-quantum cryptography        |
| misaka-crypto       | crypto primitives                |
| misaka-execution    | tx execution                     |
| misaka-storage      | UTXO set storage                 |
| misaka-mempool      | mempool + key image verification |
| misaka-consensus    | BFT consensus                    |
| misaka-p2p          | P2P networking                   |
| misaka-tokenomics   | token economics                  |
| misaka-governance   | governance                       |
| misaka-bridge       | cross-chain bridge               |
| misaka-mev          | MEV protection                   |
| misaka-rpc          | JSON-RPC server                  |
| misaka-node         | node binary                      |
| misaka-test-vectors | test vectors                     |

---

# Start Node

Example: seed node

```
./target/release/misaka-node \
--name seed-tokyo-1 \
--mode seed \
--rpc-port 3001 \
--p2p-port 6690 \
--chain-id 2 \
--data-dir ./data \
--log-level info
```

Seed node role

```
peer discovery
network bootstrap
no block production
```

---

# RPC Endpoint

Default

```
http://localhost:3001
```

Example

```bash
curl -X POST http://127.0.0.1:3001/api/get_chain_info \
-H "Content-Type: application/json" \
-d '{}'
```

Example response

```
{
 "networkName":"MISAKA Testnet",
 "latestBlockHeight":0,
 "activeValidators":1
}
```

---

# Validator Info

```bash
curl -X POST http://127.0.0.1:3001/api/get_validator_set \
-H "Content-Type: application/json" \
-d '{}'
```

Example

```
{
 "publicKey":"msk1val0000..."
}
```

---

# 2. misaka-explorer

Explorer UI for MISAKA blockchain.

Requirements

```
Node.js 18+
npm 9+
```

Install

```bash
tar xzf misaka-explorer.tar.gz
cd misaka-explorer

npm install
```

---

# Environment

Create config

```
cp .env.example .env.local
```

Example

```
NEXT_PUBLIC_USE_MOCK=false
NEXT_PUBLIC_MISAKA_RPC_URL=http://localhost:3001
```

---

# Development Mode

```
npm run dev
```

Open

```
http://localhost:3000
```

---

# Production Build

```
npm run build
npm start
```

---

# Explorer Pages

| Route           | Description        |
| --------------- | ------------------ |
| /               | dashboard          |
| /blocks         | block list         |
| /blocks/:id     | block detail       |
| /txs            | transactions       |
| /txs/:hash      | transaction detail |
| /address/:addr  | address view       |
| /validators     | validator list     |
| /validators/:id | validator detail   |

---

# Explorer Features

* auto refresh
* hash copy button
* raw JSON viewer
* skeleton loading
* error retry system
* privacy-preserving metadata
* responsive dark UI

---

# Technology Stack

## Blockchain Core

| Technology             | Purpose                   |
| ---------------------- | ------------------------- |
| Falcon-512 / ML-DSA-65 | post-quantum signatures   |
| ML-KEM-768             | key encapsulation         |
| LaRRS                  | lattice ring signature    |
| NTT                    | polynomial multiplication |
| SHA3-256/512           | hashing                   |
| XChaCha20-Poly1305     | stealth encryption        |

---

# Explorer

| Tech         | Role        |
| ------------ | ----------- |
| Next.js 14   | framework   |
| TypeScript   | type safety |
| Tailwind CSS | UI          |
| Recharts     | charts      |

---

# Troubleshooting

## Rust build errors

Install dependencies

```bash
sudo apt install libssl-dev pkg-config
```

For pqcrypto

```
sudo apt install cmake clang
```

---

# Explorer install errors

Check Node version

```
node --version
```

Must be

```
18+
```

Clear cache

```
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

---

# Privacy Policy

MISAKA is a privacy-focused blockchain.

Features

* ring signatures hide sender
* stealth addresses hide receiver
* explorer displays only verifiable metadata

Explorer **never reveals**

```
ring members
stealth recipients
private transfer amounts
```

---

# MISAKA Network

Post-Quantum Native Privacy Blockchain

---

