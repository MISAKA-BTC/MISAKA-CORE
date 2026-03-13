# MISAKA Explorer

Official block explorer for the **MISAKA Network** — a post-quantum, privacy-by-default Layer 1 blockchain.

## Quick Start

```bash
# Install dependencies
npm install

# Copy environment config
cp .env.example .env.local

# Run in development mode (uses mock data by default)
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_MISAKA_RPC_URL` | `http://localhost:3001` | MISAKA node RPC endpoint |
| `NEXT_PUBLIC_USE_MOCK` | `true` | Set to `false` to use real RPC |

### Switching from Mock to Real RPC

1. Edit `.env.local`:
   ```
   NEXT_PUBLIC_USE_MOCK=false
   NEXT_PUBLIC_MISAKA_RPC_URL=https://your-misaka-node:3001
   ```
2. Restart the dev server.

The explorer expects the RPC node to expose REST endpoints under `/api/`:
- `POST /api/get_chain_info`
- `POST /api/get_latest_blocks` — `{ page, pageSize }`
- `POST /api/get_block_by_hash` — `{ hash }`
- `POST /api/get_block_by_height` — `{ height }`
- `POST /api/get_latest_txs` — `{ page, pageSize }`
- `POST /api/get_tx_by_hash` — `{ hash }`
- `POST /api/get_address_outputs` — `{ address }`
- `POST /api/get_validator_set` — `{ page, pageSize }`
- `POST /api/get_validator_by_id` — `{ id }`
- `POST /api/search` — `{ query }`
- `POST /api/get_block_production` — `{ count }`

If an endpoint is not yet available, the mock adapter will be used as a fallback.

## Architecture

```
app/                       Next.js 14 App Router pages
  page.tsx                 Home dashboard
  blocks/page.tsx          Blocks list
  blocks/[id]/page.tsx     Block detail
  txs/page.tsx             Transactions list
  txs/[hash]/page.tsx      Transaction detail
  address/[address]/       Address page
  validators/page.tsx      Validators list
  validators/[id]/         Validator detail

components/
  explorer/                Domain components (SearchBar, Tables, Chart, Header)
  ui/                      Generic UI (StatCard, Badge, HashDisplay, CopyButton, etc.)

lib/
  api/client.ts            API abstraction (ExplorerAPI interface)
  api/mock.ts              Mock data for development
  format/index.ts          Formatting utilities (hash, time, amount, bytes)
  utils/cn.ts              Tailwind class merge helper

types/
  explorer.ts              Core TypeScript types
```

### Data Layer

`lib/api/client.ts` defines the `ExplorerAPI` interface. Two implementations exist:
- **`rpcClient`** — calls the real MISAKA node RPC
- **`mockClient`** — returns deterministic mock data for development

The active client is selected by `NEXT_PUBLIC_USE_MOCK`. Adding an indexer-backed implementation is straightforward: implement the `ExplorerAPI` interface and register it in `client.ts`.

## Privacy-Aware Design

MISAKA uses ring signatures and stealth addresses. The explorer follows strict rules:
- **No deanonymization** of ring members or stealth recipients
- **No fabricated** hidden payload contents
- Only publicly verifiable metadata is displayed
- Privacy notices are shown in context

## Tech Stack

- Next.js 14 (App Router, Server Components)
- TypeScript
- Tailwind CSS
- Recharts
- DM Sans + JetBrains Mono + Outfit fonts

## Production Build

```bash
npm run build
npm start
```

## License

MIT
