import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcError } from '@/lib/rpc';
import { normalizePaginated, normalizeValidator } from '@/lib/normalizers';
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const raw = await rpcCall('get_validator_set', body);
    return NextResponse.json(normalizePaginated(raw as Record<string, unknown>, normalizeValidator));
  } catch (e) {
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch validators' }, { status });
  }
}
