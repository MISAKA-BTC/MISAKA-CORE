# MISAKA Bridge Relayer -- Burn & Mint Model

> ## ⚠ STATUS: DEFERRED — NOT PART OF v0.8.0 MAINNET
>
> The bridge is **explicitly out of scope for the v0.8.0 mainnet launch**.
>
> What this means concretely:
>
> - The crate is listed in **`[workspace.exclude]`** of the top-level
>   `Cargo.toml`, so `cargo build --workspace`, `cargo test --workspace`,
>   `cargo clippy --workspace`, and the CI `--all-features` gate **do
>   not compile it**. The relayer binary exists as a dedicated
>   sub-project that you can build by `cd relayer && cargo build`.
>
> - The mint endpoint on the MISAKA node
>   (`POST /api/bridge/submit_mint` in `misaka-node/src/main.rs`) is a
>   defensive stub — it **always rejects** with
>   `"bridge mint not yet implemented — do not burn tokens"` and
>   `accepted: false`. It does NOT silently accept burns.
>
> - The relayer binary itself (`relayer/src/main.rs`) has a `FATAL`
>   startup guard that `std::process::exit(1)`s when
>   `NetworkMode::Mainnet` + `MintExecutorKind::MisakaRpc` is
>   combined, so an operator cannot accidentally run the unimplemented
>   bridge on mainnet.
>
> **Do not burn real tokens on Solana against this bridge.** The
> burn-and-mint roundtrip is not live and cannot be live until a
> future release implements:
> 1. `POST /api/bridge/submit_mint` with N-of-M attestation
>    verification against a configured relayer-pubkey set,
> 2. `UtxoExecutor::check_burn_replay` integration (already wired into
>    the persisted `processed_burns` set, see BLOCKER A),
> 3. End-to-end tests of the Solana burn → MISAKA mint path.
>
> The rest of this file describes the **design** that the crate
> implements, not the operational status.

## Overview

The MISAKA Bridge Relayer watches for SPL Token Burn transactions on Solana and submits corresponding mint requests to the MISAKA chain. This replaces the previous lock/mint model with a true Burn & Mint architecture.

## Burn & Mint Flow

1. **User registers** their MISAKA receive address via `POST /api/burn/register-address`
2. **User burns** MISAKA SPL tokens on Solana using a standard SPL Token Burn instruction
3. **Relayer detects** the burn by polling `getSignaturesForAddress` for the MISAKA mint
4. **Relayer verifies** the burn on-chain:
   - Transaction succeeded (not failed)
   - Transaction is finalized (commitment = "finalized")
   - The burned token mint matches the expected MISAKA mint
   - The instruction is a real SPL Token Program Burn (discriminator byte 8)
   - Slot is at least 32 slots below current finalized slot (defense-in-depth)
5. **Relayer submits mint** request to MISAKA chain RPC
6. **Status tracked** in SQLite with full audit logging and retry logic (max 10 attempts)

## Why SPL Burn, Not Transfer to a Dead Address

Detecting real SPL Token Program Burn instructions (program data byte 8) rather than transfers to a dead/null address provides several guarantees:

- **Provably irreversible**: Burned tokens are permanently destroyed at the protocol level. A transfer to a "dead" address could theoretically be recovered if the dead address key is known.
- **Unambiguous intent**: The SPL Burn instruction explicitly signals the user's intent to destroy tokens. Transfers to arbitrary addresses are ambiguous.
- **No address confusion**: Dead address patterns (e.g., `1111...1111`) vary by convention. A real burn needs no convention -- the SPL Token Program enforces it.
- **On-chain verification**: The `getParsedTransaction` RPC returns structured `{ "type": "burn" }` data that can be verified without error-prone log parsing.

## Setup

### Prerequisites

- Rust 1.70+
- Solana devnet/testnet/mainnet RPC access
- MISAKA chain RPC access
- Relayer keypair JSON file

### Configuration

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
# Edit .env with your configuration
```

### Build & Run

```bash
cargo build --release
source .env
./target/release/misaka-relayer
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RELAYER_NETWORK` | Yes | -- | Network mode: devnet, testnet, mainnet |
| `SOLANA_RPC_URL` | Yes | -- | Solana JSON-RPC endpoint |
| `MISAKA_RPC_URL` | Yes | -- | MISAKA chain RPC endpoint |
| `BRIDGE_PROGRAM_ID` | Yes | -- | Bridge program ID on Solana |
| `SOLANA_MISAKA_MINT` | Yes | -- | SPL token mint for MISAKA tokens |
| `RELAYER_KEYPAIR` | Yes | -- | Path to relayer keypair JSON |
| `ADMIN_SECRET` | Yes | -- | Admin secret for API (min 16 chars) |
| `MISAKA_CHAIN_ID` | No | 2 | Chain ID (1=mainnet, 2=devnet) |
| `API_PORT` | No | 8080 | HTTP API port |
| `POLL_INTERVAL` | No | 15 | Poll interval in seconds |
| `PROCESSED_STORE` | No | ./relayer-processed.json | SQLite DB path |

## HTTP API

### POST /api/burn/register-address

Register a MISAKA receive address for a Solana wallet.

```json
{
  "wallet_address": "SoLaNaWaLLeTaDdReSs...",
  "misaka_receive_address": "msk1..."
}
```

### POST /api/burn/submit-tx

Submit a Solana burn transaction signature for manual processing.

```json
{
  "solana_tx_signature": "5abc123..."
}
```

### GET /api/burn/status/:signature

Query the processing status of a burn by its Solana tx signature.

### GET /api/admin/claims

List all burn claims (requires `Authorization: Bearer <ADMIN_SECRET>` header).

## Database Schema

- **burn_requests**: Tracks each burn through the pipeline (detected -> verified -> mint_requested -> mint_completed/mint_failed/failed_permanent)
- **address_registrations**: Maps Solana wallets to MISAKA receive addresses
- **audit_log**: Immutable log of all relayer actions
- **cursors**: Pagination state for Solana polling

## Circuit Breaker

After 5 consecutive Solana RPC failures, the bridge pauses automatically. To resume:

```bash
export MISAKA_BRIDGE_RESUME=1
```

The relayer will detect this on the next poll iteration and resume operation.
