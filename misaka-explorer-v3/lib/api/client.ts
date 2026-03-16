// lib/api/client.ts — Explorer API client
// All calls go through Next.js API Routes (server-side proxy).
// Browser NEVER contacts the MISAKA node directly.

import type {
  NetworkStats, BlockSummary, BlockDetail,
  TransactionSummary, TransactionDetail,
  AddressSummary, ValidatorSummary, ValidatorDetail,
  SearchResult, PaginatedResponse, BlockProductionPoint,
  PeersResponse,
} from '@/types/explorer';
import { useMock } from '@/lib/config';

export interface ExplorerAPI {
  getNetworkStats(): Promise<NetworkStats>;
  getLatestBlocks(page?: number, pageSize?: number): Promise<PaginatedResponse<BlockSummary>>;
  getBlockByHash(hash: string): Promise<BlockDetail | null>;
  getBlockByHeight(height: number): Promise<BlockDetail | null>;
  getLatestTransactions(page?: number, pageSize?: number): Promise<PaginatedResponse<TransactionSummary>>;
  getTransactionByHash(hash: string): Promise<TransactionDetail | null>;
  getAddressSummary(address: string): Promise<AddressSummary | null>;
  getValidatorList(page?: number, pageSize?: number): Promise<PaginatedResponse<ValidatorSummary>>;
  getValidatorById(id: string): Promise<ValidatorDetail | null>;
  searchExplorer(query: string): Promise<SearchResult>;
  getBlockProduction(count?: number): Promise<BlockProductionPoint[]>;
  getPeers(): Promise<PeersResponse>;
}

export interface FaucetResult {
  success: boolean; txHash?: string; amount?: number; error?: string;
}

// ─── Internal API client (calls our Next.js API routes) ─────
const BASE = '/api/explorer';

async function apiCall<T>(path: string, body: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    next: { revalidate: 5 },
  });
  if (!res.ok) {
    if (res.status === 404) return null as T;
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

export const rpcClient: ExplorerAPI = {
  getNetworkStats:       ()           => apiCall(`${BASE}/chain-info`),
  getLatestBlocks:       (p=1, s=20)  => apiCall(`${BASE}/blocks/latest`, { page: p, pageSize: s }),
  getBlockByHash:        (hash)       => apiCall(`${BASE}/block/${hash}`),
  getBlockByHeight:      (height)     => apiCall(`${BASE}/block/${height}`),
  getLatestTransactions: (p=1, s=20)  => apiCall(`${BASE}/txs/latest`, { page: p, pageSize: s }),
  getTransactionByHash:  (hash)       => apiCall(`${BASE}/tx/${hash}`),
  getAddressSummary:     (address)    => apiCall(`${BASE}/address/${address}`),
  getValidatorList:      (p=1, s=20)  => apiCall(`${BASE}/validators`, { page: p, pageSize: s }),
  getValidatorById:      (id)         => apiCall(`${BASE}/validator/${id}`),
  searchExplorer:        (query)      => apiCall(`${BASE}/search`, { query }),
  getBlockProduction:    (n=30)       => apiCall(`${BASE}/block-production`, { count: n }),
  getPeers:              ()           => apiCall(`${BASE}/peers`),
};

export async function requestFaucet(address: string): Promise<FaucetResult> {
  const res = await fetch('/api/faucet', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address }),
  });
  return res.json();
}

// ─── Mock (development only) ────────────────────────────────
import { mockClient } from './mock';

export const api: ExplorerAPI = useMock ? mockClient : rpcClient;

if (useMock && typeof console !== 'undefined') {
  console.warn('[MISAKA Explorer] Running with MOCK data. Set NEXT_PUBLIC_USE_MOCK=false for production.');
}
