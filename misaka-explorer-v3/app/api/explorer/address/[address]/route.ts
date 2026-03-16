import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcError } from '@/lib/rpc';
import { normalizeAddress } from '@/lib/normalizers';

export async function POST(req: NextRequest, { params }: { params: { address: string } }) {
  try {
    const raw = await rpcCall('get_address_outputs', { address: params.address });
    return NextResponse.json(normalizeAddress(raw as Record<string, unknown>));
  } catch (e) {
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch address' }, { status });
  }
}
