import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcError } from '@/lib/rpc';
import { normalizeBlockProduction } from '@/lib/normalizers';
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const raw = await rpcCall('get_block_production', body);
    const items = Array.isArray(raw) ? raw : [];
    return NextResponse.json(items.map((r: Record<string, unknown>) => normalizeBlockProduction(r)));
  } catch (e) {
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch block production' }, { status });
  }
}
