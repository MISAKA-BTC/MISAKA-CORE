import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcError } from '@/lib/rpc';
import { normalizeSearch } from '@/lib/normalizers';
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const query = typeof body.query === 'string' ? body.query.trim() : '';
    if (!query) return NextResponse.json({ type: 'not_found', value: '' });
    const raw = await rpcCall('search', { query });
    return NextResponse.json(normalizeSearch(raw as Record<string, unknown>));
  } catch (e) {
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Search failed' }, { status });
  }
}
