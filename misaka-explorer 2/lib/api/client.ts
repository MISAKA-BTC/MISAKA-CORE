// lib/api/client.ts — Explorer data client (switch between mock and real RPC)

import type {
  NetworkStats, BlockSummary, BlockDetail,
  TransactionSummary, TransactionDetail,
  AddressSummary, ValidatorSummary, ValidatorDetail,
  SearchResult, PaginatedResponse, BlockProductionPoint,
} from '@/types/explorer';

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
}

export interface FaucetResult {
  success: boolean;
  txHash?: string;
  amount?: number;
  error?: string;
}

// --- RPC client (for real MISAKA node) ---

const RPC_URL = process.env.NEXT_PUBLIC_MISAKA_RPC_URL || 'http://localhost:3001';

async function rpcCall<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch(`${RPC_URL}/api/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
    next: { revalidate: 5 },
  });
  if (!res.ok) {
    // Return null-ish for 404s instead of throwing
    if (res.status === 404) return null as T;
    throw new Error(`RPC error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const rpcClient: ExplorerAPI = {
  getNetworkStats:        ()            => rpcCall('get_chain_info'),
  getLatestBlocks:        (p=1, s=20)   => rpcCall('get_latest_blocks', { page: p, pageSize: s }),
  getBlockByHash:         (hash)        => rpcCall('get_block_by_hash', { hash }),
  getBlockByHeight:       (height)      => rpcCall('get_block_by_height', { height }),
  getLatestTransactions:  (p=1, s=20)   => rpcCall('get_latest_txs', { page: p, pageSize: s }),
  getTransactionByHash:   (hash)        => rpcCall('get_tx_by_hash', { hash }),
  getAddressSummary:      (address)     => rpcCall('get_address_outputs', { address }),
  getValidatorList:       (p=1, s=20)   => rpcCall('get_validator_set', { page: p, pageSize: s }),
  getValidatorById:       (id)          => rpcCall('get_validator_by_id', { id }),
  searchExplorer:         (query)       => rpcCall('search', { query }),
  getBlockProduction:     (n=30)        => rpcCall('get_block_production', { count: n }),
};

/** Request tokens from the faucet. */
export async function requestFaucet(address: string): Promise<FaucetResult> {
  const res = await fetch(`${RPC_URL}/api/faucet`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address }),
  });
  return res.json();
}

/** Submit a raw transaction. */
export async function submitTransaction(body: Record<string, unknown>): Promise<{ txHash: string; accepted: boolean; error?: string }> {
  const res = await fetch(`${RPC_URL}/api/submit_tx`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

// --- Select active client ---

import { mockClient } from './mock';

const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK !== 'false';

export const api: ExplorerAPI = USE_MOCK ? mockClient : rpcClient;
