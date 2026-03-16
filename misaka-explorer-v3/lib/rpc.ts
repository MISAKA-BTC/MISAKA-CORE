// lib/rpc.ts — Server-side RPC client (NEVER imported from client components)

import { rpcBaseUrl } from './config';

/**
 * Call the MISAKA node RPC from the server side.
 * Used exclusively by Next.js API Route Handlers.
 */
export async function rpcCall<T = Record<string, unknown>>(
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const url = `${rpcBaseUrl}/api/${method}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
    next: { revalidate: 5 },
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new RpcNotFoundError(method);
    }
    throw new RpcError(method, res.status, await res.text().catch(() => ''));
  }

  return res.json();
}

export class RpcError extends Error {
  constructor(
    public method: string,
    public status: number,
    public body: string,
  ) {
    super(`RPC ${method} failed: ${status}`);
    this.name = 'RpcError';
  }
}

export class RpcNotFoundError extends RpcError {
  constructor(method: string) {
    super(method, 404, 'not found');
    this.name = 'RpcNotFoundError';
  }
}
