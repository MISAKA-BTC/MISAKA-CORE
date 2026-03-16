import { NextResponse } from 'next/server';
import { rpcCall, RpcError } from '@/lib/rpc';
import { normalizePeers } from '@/lib/normalizers';
export async function POST() {
  try {
    const raw = await rpcCall('get_peers');
    return NextResponse.json(normalizePeers(raw as Record<string, unknown>));
  } catch (e) {
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch peers' }, { status });
  }
}
