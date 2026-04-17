import { API_BASE } from './constants';

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(`${API_BASE}${url}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      if (err.error) throw new Error(err.error);
      return null;
    }
    return await res.json();
  } catch {
    return null;
  }
}

export async function getChainInfo() {
  return fetchJSON<any>('/v1/chain/info');
}

export async function getRecentBlocks(limit: number = 15) {
  return fetchJSON<any>(`/api/v1/explorer/blocks?limit=${limit}`);
}

export async function getTxStatus(txHash: string) {
  return fetchJSON<any>(`/api/v1/tx/${encodeURIComponent(txHash)}/status`);
}

export async function getWallet(address: string) {
  return fetchJSON<any>(`/v1/wallet/${encodeURIComponent(address)}`);
}

export async function getAddressHistory(address: string, page: number = 1, pageSize: number = 50) {
  return fetchJSON<any>(`/v1/wallet/${encodeURIComponent(address)}/history?page=${page}&pageSize=${pageSize}`);
}

export async function getBlockByHeight(height: number) {
  return fetchJSON<any>(`/api/v1/explorer/block/${height}`);
}

export async function requestFaucet(address: string) {
  return fetchJSON<any>('/api/v1/faucet/request', {
    method: 'POST',
    body: JSON.stringify({ address }),
  });
}
