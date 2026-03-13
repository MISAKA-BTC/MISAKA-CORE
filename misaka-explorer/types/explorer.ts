// types/explorer.ts — Core domain types for MISAKA Explorer

export interface NetworkStats {
  networkName: string;
  networkVersion: string;
  latestBlockHeight: number;
  totalTransactions: number;
  activeValidators: number;
  avgBlockTime: number; // seconds
  tpsEstimate: number;
  finalityStatus: 'finalized' | 'pending' | 'degraded';
  chainHealth: 'healthy' | 'degraded' | 'down';
  genesisTimestamp: string;
}

export interface BlockSummary {
  height: number;
  hash: string;
  proposer: string;
  txCount: number;
  timestamp: string;
  size: number; // bytes
  finality: 'finalized' | 'pending' | 'orphaned';
}

export interface BlockDetail extends BlockSummary {
  parentHash: string;
  validatorSignatures: number;
  totalFees: number;
  status: 'confirmed' | 'pending' | 'orphaned';
  transactions: TransactionSummary[];
}

export interface TransactionSummary {
  hash: string;
  blockHeight: number;
  timestamp: string;
  fee: number;
  inputCount: number;
  outputCount: number;
  status: 'confirmed' | 'pending' | 'failed';
}

export interface TransactionDetail extends TransactionSummary {
  blockHash: string;
  size: number; // bytes
  ringInputCount: number;
  keyImages: string[];
  stealthOutputCount: number;
  hasPayload: boolean;
  confirmations: number;
  version: number;
}

export interface AddressSummary {
  address: string;
  balance: number | null;       // null if stealth-hidden
  totalReceived: number | null;
  totalSent: number | null;
  txCount: number;
  outputs: OutputEntry[];
  privacyNote: string;
}

export interface OutputEntry {
  txHash: string;
  outputIndex: number;
  amount: number | null;
  timestamp: string;
  spent: boolean | null;
}

export interface ValidatorSummary {
  id: string;
  publicKey: string;
  stakeWeight: number;
  status: 'active' | 'inactive' | 'jailed';
  latestProposedBlock: number | null;
  participationRate: number; // 0-100
  uptime: number | null;     // 0-100
}

export interface ValidatorDetail extends ValidatorSummary {
  recentProposals: number[];
  recentVotes: number[];
  slashingStatus: 'clean' | 'slashed' | 'under_review';
  latestActivity: string;
  totalBlocksProposed: number;
  joinedAt: string;
}

export interface SearchResult {
  type: 'block' | 'transaction' | 'address' | 'validator' | 'not_found';
  value: string;
  label?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface BlockProductionPoint {
  height: number;
  txCount: number;
  timestamp: string;
  blockTime: number; // seconds since previous block
}
