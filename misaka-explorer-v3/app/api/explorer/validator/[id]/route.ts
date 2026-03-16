import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcNotFoundError, RpcError } from '@/lib/rpc';
import { normalizeValidatorDetail } from '@/lib/normalizers';

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const raw = await rpcCall('get_validator_by_id', { id: params.id });
    if (!raw) return NextResponse.json({ error: 'Validator not found' }, { status: 404 });
    return NextResponse.json(normalizeValidatorDetail(raw as Record<string, unknown>));
  } catch (e) {
    if (e instanceof RpcNotFoundError) return NextResponse.json({ error: 'Validator not found' }, { status: 404 });
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ error: 'Failed to fetch validator' }, { status });
  }
}
