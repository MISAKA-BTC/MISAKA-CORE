// lib/normalizers.ts — Normalize raw RPC responses to UI-safe types

import type {
  NetworkStats, BlockSummary, BlockDetail,
  TransactionSummary, TransactionDetail,
  AddressSummary, ValidatorSummary, ValidatorDetail,
  SearchResult, PaginatedResponse, BlockProductionPoint,
  PeerInfo, PeersResponse,
} from '@/types/explorer';

function str(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}
function num(v: unknown, fallback = 0): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function arr<T>(v: unknown): T[] {
  return Array.isArray(v) ? v : [];
}

// ─── Network Stats ──────────────────────────────────────
export function normalizeNetworkStats(raw: Record<string, unknown>): NetworkStats {
  return {
    networkName: str(raw.networkName, 'MISAKA Network'),
    networkVersion: str(raw.networkVersion, 'unknown'),
    latestBlockHeight: num(raw.latestBlockHeight),
    totalTransactions: num(raw.totalTransactions),
    activeValidators: num(raw.activeValidators),
    avgBlockTime: num(raw.avgBlockTime, 60),
    tpsEstimate: num(raw.tpsEstimate),
    finalityStatus: (['finalized', 'pending', 'degraded'].includes(str(raw.finalityStatus))
      ? str(raw.finalityStatus) : 'pending') as NetworkStats['finalityStatus'],
    chainHealth: (['healthy', 'degraded', 'down'].includes(str(raw.chainHealth))
      ? str(raw.chainHealth) : 'degraded') as NetworkStats['chainHealth'],
    genesisTimestamp: str(raw.genesisTimestamp),
  };
}

// ─── Block ──────────────────────────────────────────────
export function normalizeBlock(raw: Record<string, unknown>): BlockSummary {
  return {
    height: num(raw.height),
    hash: str(raw.hash),
    proposer: str(raw.proposer, 'unknown'),
    txCount: num(raw.txCount ?? raw.tx_count),
    timestamp: str(raw.timestamp),
    size: num(raw.size),
    finality: (['finalized', 'pending', 'orphaned'].includes(str(raw.finality))
      ? str(raw.finality) : 'pending') as BlockSummary['finality'],
  };
}

export function normalizeBlockDetail(raw: Record<string, unknown>): BlockDetail {
  const base = normalizeBlock(raw);
  return {
    ...base,
    parentHash: str(raw.parentHash ?? raw.parent_hash),
    validatorSignatures: num(raw.validatorSignatures ?? raw.validator_signatures),
    totalFees: num(raw.totalFees ?? raw.total_fees),
    status: (['confirmed', 'pending', 'orphaned'].includes(str(raw.status))
      ? str(raw.status) : 'pending') as BlockDetail['status'],
    transactions: arr<Record<string, unknown>>(raw.transactions).map(normalizeTx),
  };
}

// ─── Transaction ────────────────────────────────────────
export function normalizeTx(raw: Record<string, unknown>): TransactionSummary {
  return {
    hash: str(raw.hash),
    blockHeight: num(raw.blockHeight ?? raw.block_height),
    timestamp: str(raw.timestamp),
    fee: num(raw.fee),
    inputCount: num(raw.inputCount ?? raw.input_count),
    outputCount: num(raw.outputCount ?? raw.output_count),
    status: (['confirmed', 'pending', 'failed'].includes(str(raw.status))
      ? str(raw.status) : 'pending') as TransactionSummary['status'],
  };
}

export function normalizeTxDetail(raw: Record<string, unknown>): TransactionDetail {
  const base = normalizeTx(raw);
  return {
    ...base,
    blockHash: str(raw.blockHash ?? raw.block_hash),
    size: num(raw.size),
    ringInputCount: num(raw.ringInputCount ?? raw.ring_input_count),
    keyImages: arr<string>(raw.keyImages ?? raw.key_images),
    stealthOutputCount: num(raw.stealthOutputCount ?? raw.stealth_output_count),
    hasPayload: Boolean(raw.hasPayload ?? raw.has_payload),
    confirmations: num(raw.confirmations),
    version: num(raw.version, 1),
  };
}

// ─── Address ────────────────────────────────────────────
export function normalizeAddress(raw: Record<string, unknown>): AddressSummary {
  return {
    address: str(raw.address),
    balance: raw.balance != null ? num(raw.balance) : null,
    totalReceived: raw.totalReceived != null ? num(raw.totalReceived) : null,
    totalSent: raw.totalSent != null ? num(raw.totalSent) : null,
    txCount: num(raw.txCount ?? raw.tx_count),
    outputs: arr(raw.outputs),
    privacyNote: str(raw.privacyNote ?? raw.privacy_note,
      'Balance and amounts are privacy-protected via stealth addresses and ring signatures.'),
  };
}

// ─── Validator ──────────────────────────────────────────
export function normalizeValidator(raw: Record<string, unknown>): ValidatorSummary {
  return {
    id: str(raw.id),
    publicKey: str(raw.publicKey ?? raw.public_key),
    stakeWeight: num(raw.stakeWeight ?? raw.stake_weight),
    status: (['active', 'inactive', 'jailed'].includes(str(raw.status))
      ? str(raw.status) : 'inactive') as ValidatorSummary['status'],
    latestProposedBlock: raw.latestProposedBlock != null ? num(raw.latestProposedBlock) : null,
    participationRate: num(raw.participationRate ?? raw.participation_rate),
    uptime: raw.uptime != null ? num(raw.uptime) : null,
  };
}

export function normalizeValidatorDetail(raw: Record<string, unknown>): ValidatorDetail {
  const base = normalizeValidator(raw);
  return {
    ...base,
    recentProposals: arr<number>(raw.recentProposals ?? raw.recent_proposals),
    recentVotes: arr<number>(raw.recentVotes ?? raw.recent_votes),
    slashingStatus: (['clean', 'slashed', 'under_review'].includes(str(raw.slashingStatus))
      ? str(raw.slashingStatus) : 'clean') as ValidatorDetail['slashingStatus'],
    latestActivity: str(raw.latestActivity ?? raw.latest_activity),
    totalBlocksProposed: num(raw.totalBlocksProposed ?? raw.total_blocks_proposed),
    joinedAt: str(raw.joinedAt ?? raw.joined_at),
  };
}

// ─── Search ─────────────────────────────────────────────
export function normalizeSearch(raw: Record<string, unknown>): SearchResult {
  const type = str(raw.type, 'not_found');
  return {
    type: (['block', 'transaction', 'address', 'validator', 'not_found'].includes(type)
      ? type : 'not_found') as SearchResult['type'],
    value: str(raw.value),
    label: raw.label ? str(raw.label) : undefined,
  };
}

// ─── Paginated ──────────────────────────────────────────
export function normalizePaginated<T>(
  raw: Record<string, unknown>,
  normalizeItem: (item: Record<string, unknown>) => T,
): PaginatedResponse<T> {
  return {
    data: arr<Record<string, unknown>>(raw.data).map(normalizeItem),
    total: num(raw.total),
    page: num(raw.page, 1),
    pageSize: num(raw.pageSize ?? raw.page_size, 20),
    hasMore: Boolean(raw.hasMore ?? raw.has_more),
  };
}

// ─── Block Production ───────────────────────────────────
export function normalizeBlockProduction(raw: Record<string, unknown>): BlockProductionPoint {
  return {
    height: num(raw.height),
    txCount: num(raw.txCount ?? raw.tx_count),
    timestamp: str(raw.timestamp),
    blockTime: num(raw.blockTime ?? raw.block_time, 60),
  };
}

// ─── Peers ──────────────────────────────────────────────
export function normalizePeer(raw: Record<string, unknown>): PeerInfo {
  return {
    node_name: str(raw.node_name, 'unknown'),
    remote_addr: str(raw.remote_addr),
    advertise_addr: raw.advertise_addr ? str(raw.advertise_addr) : null,
    mode: str(raw.mode, 'unknown'),
    direction: str(raw.direction, 'unknown'),
    height: num(raw.height),
    connected_at: str(raw.connected_at),
    last_seen: str(raw.last_seen),
  };
}

export function normalizePeers(raw: Record<string, unknown>): PeersResponse {
  return {
    peers: arr<Record<string, unknown>>(raw.peers).map(normalizePeer),
    total: num(raw.total),
    inbound: num(raw.inbound),
    outbound: num(raw.outbound),
  };
}
