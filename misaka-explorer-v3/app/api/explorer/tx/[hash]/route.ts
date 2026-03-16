import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcNotFoundError, RpcError } from '@/lib/rpc';
import { normalizeTxDetail } from '@/lib/normalizers';

export async function POST(req: NextRequest, { params }: { params: { hash: string } }) {
  try {
    const raw = await rpcCall('get_tx_by_hash', { hash: params.hash });
    if (!raw) return NextResponse.json({ error: 'Transaction not found' }, { status: 404 });
    return NextResponse.json(normalizeTxDetail(raw as Record<string, unknown>));
  } catch (e) {
    if (e instanceof RpcNotFoundError) return NextResponse.json({ error: 'Tx not found' }, { status: 404 });
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch transaction' }, { status });
  }
}
