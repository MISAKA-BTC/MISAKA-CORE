# MISAKA Explorer

Block explorer for the **MISAKA Network** — post-quantum, privacy-by-default Layer 1 blockchain.

## Architecture

```
Browser → Next.js API Routes → MISAKA Node RPC
         (proxy / normalize)    (localhost:3001)
```

- The browser **never** contacts the MISAKA node directly
- All requests go through `/api/explorer/*` API routes
- Server-side normalizers handle response validation
- CORS issues are eliminated by design

## Quick Start

### Development (with mock data)

```bash
cp .env.example .env.local
# Edit .env.local:
#   NEXT_PUBLIC_USE_MOCK=true
npm install
npm run dev
```

### Development (with real node)

```bash
# Start MISAKA node first:
# ./target/release/misaka-node --rpc-port 3001 ...

cp .env.example .env.local
# Edit .env.local:
#   NEXT_PUBLIC_USE_MOCK=false
#   MISAKA_RPC_URL=http://localhost:3001
npm install
npm run dev
```

### Production

```bash
# .env.production:
#   MISAKA_RPC_URL=http://localhost:3001
#   NEXT_PUBLIC_USE_MOCK=false  (or omit — mock is disabled in production)
npm run build
npm run start
# Or: PORT=3000 npm run start
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISAKA_RPC_URL` | Yes (prod) | `http://localhost:3001` | MISAKA node RPC URL. **Server-side only.** |
| `NEXT_PUBLIC_USE_MOCK` | No | `false` | Set to `true` **only in development** to use mock data. Ignored in production. |

### `.env.example`

```
# Server-side RPC URL (never exposed to browser)
MISAKA_RPC_URL=http://localhost:3001

# Mock mode (development only — ignored in production)
# NEXT_PUBLIC_USE_MOCK=true
```

## API Routes (Internal Proxy)

All API routes are POST endpoints:

| Route | Proxies to |
|-------|-----------|
| `/api/explorer/chain-info` | `get_chain_info` |
| `/api/explorer/blocks/latest` | `get_latest_blocks` |
| `/api/explorer/block/{id}` | `get_block_by_height` / `get_block_by_hash` |
| `/api/explorer/txs/latest` | `get_latest_txs` |
| `/api/explorer/tx/{hash}` | `get_tx_by_hash` |
| `/api/explorer/address/{addr}` | `get_address_outputs` |
| `/api/explorer/validators` | `get_validator_set` |
| `/api/explorer/validator/{id}` | `get_validator_by_id` |
| `/api/explorer/search` | `search` |
| `/api/explorer/peers` | `get_peers` |
| `/api/explorer/block-production` | `get_block_production` |
| `/api/faucet` | `faucet` |

## Pages

| Path | Description |
|------|-------------|
| `/` | Dashboard — hero, stats, recent blocks/txs |
| `/blocks` | Block list with pagination |
| `/blocks/{id}` | Block detail |
| `/txs` | Transaction list |
| `/txs/{hash}` | Transaction detail |
| `/address/{addr}` | Address detail |
| `/validators` | Validator list |
| `/validators/{id}` | Validator detail |
| `/peers` | Connected peers (mode, direction, advertise addr) |
| `/faucet` | Testnet faucet |
| `/search?q=` | Search results (not_found fallback) |

## Mock Data

- Mock is **only** available when `NODE_ENV === 'development'` AND `NEXT_PUBLIC_USE_MOCK === 'true'`
- In production builds, mock is **always disabled** regardless of env
- A console warning is shown when mock is active

## Faucet Notes

- Address must start with `msk1` and be at least 10 characters
- Rate limited to 1 request per address per 60 seconds (server-side)
- All faucet requests go through `/api/faucet` (proxied to node)

## Pre-deployment Checklist

- [ ] `MISAKA_RPC_URL` is set to the correct node address
- [ ] `NEXT_PUBLIC_USE_MOCK` is **not** set to `true`
- [ ] MISAKA node is running and `/health` responds
- [ ] `npm run build` succeeds without errors
- [ ] Test `/api/explorer/chain-info` returns valid data
- [ ] Test `/api/explorer/peers` returns peer list
- [ ] Faucet works end-to-end

## Design

- White & black only — no color accents
- Bittensor-inspired minimal aesthetic
- JetBrains Mono for code/hashes, Helvetica Neue for display
- No rounded corners, no shadows, no gradients
- Information density with visual breathing room
