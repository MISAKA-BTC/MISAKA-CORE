import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcNotFoundError, RpcError } from '@/lib/rpc';
import { normalizeBlockDetail } from '@/lib/normalizers';

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const id = params.id;
    const method = /^\d+$/.test(id) ? 'get_block_by_height' : 'get_block_by_hash';
    const payload = /^\d+$/.test(id) ? { height: parseInt(id) } : { hash: id };
    const raw = await rpcCall(method, payload);
    if (!raw) return NextResponse.json({ error: 'Block not found' }, { status: 404 });
    return NextResponse.json(normalizeBlockDetail(raw as Record<string, unknown>));
  } catch (e) {
    if (e instanceof RpcNotFoundError) return NextResponse.json({ error: 'Block not found' }, { status: 404 });
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch block' }, { status });
  }
}
