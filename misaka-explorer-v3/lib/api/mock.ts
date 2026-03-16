// lib/api/mock.ts — Mock data for development (isolated from production code)

import type { ExplorerAPI } from './client';
import type {
  NetworkStats, BlockSummary, BlockDetail,
  TransactionSummary, TransactionDetail,
  AddressSummary, ValidatorSummary, ValidatorDetail,
  SearchResult, PaginatedResponse, BlockProductionPoint,
} from '@/types/explorer';

// --- Helpers ---
function randomHash(): string {
  const chars = '0123456789abcdef';
  let h = '';
  for (let i = 0; i < 64; i++) h += chars[Math.floor(Math.random() * 16)];
  return h;
}

function ago(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

const VALIDATORS = [
  { id: 'validator-01', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Alpha' },
  { id: 'validator-02', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Beta' },
  { id: 'validator-03', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Gamma' },
  { id: 'validator-04', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Delta' },
  { id: 'validator-05', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Epsilon' },
  { id: 'validator-06', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Zeta' },
  { id: 'validator-07', publicKey: 'msk1val' + randomHash().slice(0, 56), name: 'MISAKA-Node-Eta' },
];

const LATEST_HEIGHT = 184729;

function mockBlock(height: number): BlockSummary {
  const minAgo = (LATEST_HEIGHT - height) * 1;
  return {
    height,
    hash: randomHash(),
    proposer: VALIDATORS[height % VALIDATORS.length].id,
    txCount: Math.floor(Math.random() * 25) + 1,
    timestamp: ago(minAgo),
    size: Math.floor(Math.random() * 48000) + 2000,
    finality: height < LATEST_HEIGHT - 2 ? 'finalized' : 'pending',
  };
}

function mockTx(blockHeight: number): TransactionSummary {
  return {
    hash: randomHash(),
    blockHeight,
    timestamp: ago((LATEST_HEIGHT - blockHeight) * 1 + Math.random()),
    fee: Math.floor(Math.random() * 500) + 10,
    inputCount: Math.floor(Math.random() * 4) + 1,
    outputCount: Math.floor(Math.random() * 3) + 1,
    status: 'confirmed',
  };
}

function paginate<T>(items: T[], page: number, pageSize: number): PaginatedResponse<T> {
  const start = (page - 1) * pageSize;
  const data = items.slice(start, start + pageSize);
  return { data, total: items.length, page, pageSize, hasMore: start + pageSize < items.length };
}

// --- Pre-generate data ---
const BLOCKS: BlockSummary[] = [];
for (let i = 0; i < 200; i++) BLOCKS.push(mockBlock(LATEST_HEIGHT - i));

const TXS: TransactionSummary[] = [];
for (const b of BLOCKS.slice(0, 80)) {
  for (let t = 0; t < b.txCount && TXS.length < 500; t++) TXS.push(mockTx(b.height));
}

// --- Mock Client ---
export const mockClient: ExplorerAPI = {
  async getNetworkStats(): Promise<NetworkStats> {
    return {
      networkName: 'MISAKA Network',
      networkVersion: 'v0.4.1-testnet',
      latestBlockHeight: LATEST_HEIGHT,
      totalTransactions: 1_847_293,
      activeValidators: VALIDATORS.length,
      avgBlockTime: 60.2,
      tpsEstimate: 8.4,
      finalityStatus: 'finalized',
      chainHealth: 'healthy',
      genesisTimestamp: '2025-12-01T00:00:00Z',
    };
  },

  async getLatestBlocks(page = 1, pageSize = 20): Promise<PaginatedResponse<BlockSummary>> {
    return paginate(BLOCKS, page, pageSize);
  },

  async getBlockByHash(hash: string): Promise<BlockDetail | null> {
    const b = BLOCKS.find(b => b.hash === hash);
    if (!b) return { ...mockBlockDetail(LATEST_HEIGHT), hash };
    return mockBlockDetail(b.height, b.hash);
  },

  async getBlockByHeight(height: number): Promise<BlockDetail | null> {
    return mockBlockDetail(height);
  },

  async getLatestTransactions(page = 1, pageSize = 20): Promise<PaginatedResponse<TransactionSummary>> {
    return paginate(TXS, page, pageSize);
  },

  async getTransactionByHash(hash: string): Promise<TransactionDetail | null> {
    const tx = TXS.find(t => t.hash === hash);
    const base = tx || mockTx(LATEST_HEIGHT - 5);
    return {
      ...base,
      hash: tx?.hash || hash,
      blockHash: randomHash(),
      size: Math.floor(Math.random() * 4000) + 800,
      ringInputCount: base.inputCount,
      keyImages: Array.from({ length: base.inputCount }, () => randomHash()),
      stealthOutputCount: base.outputCount,
      hasPayload: Math.random() > 0.7,
      confirmations: Math.floor(Math.random() * 100) + 6,
      version: 1,
    };
  },

  async getAddressSummary(address: string): Promise<AddressSummary | null> {
    return {
      address,
      balance: null,
      totalReceived: null,
      totalSent: null,
      txCount: Math.floor(Math.random() * 50) + 1,
      outputs: Array.from({ length: 5 }, () => ({
        txHash: randomHash(),
        outputIndex: Math.floor(Math.random() * 3),
        amount: null,
        timestamp: ago(Math.random() * 10000),
        spent: null,
      })),
      privacyNote: 'Balance and amounts are privacy-protected via stealth addresses and ring signatures. Only publicly verifiable metadata is shown.',
    };
  },

  async getValidatorList(page = 1, pageSize = 20): Promise<PaginatedResponse<ValidatorSummary>> {
    const vals: ValidatorSummary[] = VALIDATORS.map((v, i) => ({
      id: v.id,
      publicKey: v.publicKey,
      stakeWeight: 1_000_000 - i * 80_000 + Math.floor(Math.random() * 10_000),
      status: i < 6 ? 'active' : 'inactive',
      latestProposedBlock: LATEST_HEIGHT - Math.floor(Math.random() * 50),
      participationRate: 95 + Math.random() * 5,
      uptime: 98 + Math.random() * 2,
    }));
    return paginate(vals, page, pageSize);
  },

  async getValidatorById(id: string): Promise<ValidatorDetail | null> {
    const v = VALIDATORS.find(v => v.id === id) || VALIDATORS[0];
    return {
      id: v.id,
      publicKey: v.publicKey,
      stakeWeight: 920_000 + Math.floor(Math.random() * 80_000),
      status: 'active',
      latestProposedBlock: LATEST_HEIGHT - 3,
      participationRate: 97.8,
      uptime: 99.4,
      recentProposals: Array.from({ length: 10 }, (_, i) => LATEST_HEIGHT - i * 7 - Math.floor(Math.random() * 3)),
      recentVotes: Array.from({ length: 20 }, (_, i) => LATEST_HEIGHT - i),
      slashingStatus: 'clean',
      latestActivity: ago(2),
      totalBlocksProposed: 26_418,
      joinedAt: '2025-12-01T00:00:00Z',
    };
  },

  async searchExplorer(query: string): Promise<SearchResult> {
    const q = query.trim();
    if (/^\d+$/.test(q)) return { type: 'block', value: q, label: `Block #${q}` };
    if (q.length === 64 && /^[0-9a-f]+$/i.test(q)) {
      const isTx = Math.random() > 0.5;
      return { type: isTx ? 'transaction' : 'block', value: q };
    }
    if (q.startsWith('msk1')) return { type: 'address', value: q };
    if (q.startsWith('validator')) return { type: 'validator', value: q };
    return { type: 'not_found', value: q };
  },

  async getBlockProduction(count = 30): Promise<BlockProductionPoint[]> {
    return Array.from({ length: count }, (_, i) => ({
      height: LATEST_HEIGHT - (count - 1 - i),
      txCount: Math.floor(Math.random() * 25) + 1,
      timestamp: ago((count - 1 - i) * 1),
      blockTime: 55 + Math.random() * 15,
    }));
  },
};

function mockBlockDetail(height: number, hash?: string): BlockDetail {
  const b = mockBlock(height);
  const txs: TransactionSummary[] = Array.from({ length: b.txCount }, () => mockTx(height));
  return {
    ...b,
    hash: hash || b.hash,
    parentHash: randomHash(),
    validatorSignatures: 5 + Math.floor(Math.random() * 3),
    totalFees: txs.reduce((s, t) => s + t.fee, 0),
    status: 'confirmed',
    transactions: txs,
  };
}

// Added: getPeers mock
(mockClient as any).getPeers = async function(): Promise<import('@/types/explorer').PeersResponse> {
  const LATEST_HEIGHT = 184729;
  function ago(m: number) { return new Date(Date.now() - m * 60000).toISOString(); }
  return {
    peers: [
      { node_name: 'seed-tokyo-1', remote_addr: '49.212.136.189:6690', advertise_addr: '49.212.136.189:6690', mode: 'seed', direction: 'outbound', height: LATEST_HEIGHT, connected_at: ago(120), last_seen: ago(0) },
      { node_name: 'node-osaka-1', remote_addr: '133.167.126.51:6690', advertise_addr: '133.167.126.51:6690', mode: 'public', direction: 'inbound', height: LATEST_HEIGHT - 1, connected_at: ago(90), last_seen: ago(1) },
      { node_name: 'validator-01', remote_addr: '192.168.1.100:6690', advertise_addr: null, mode: 'hidden', direction: 'outbound', height: LATEST_HEIGHT, connected_at: ago(200), last_seen: ago(0) },
    ],
    total: 3, inbound: 1, outbound: 2,
  };
};
