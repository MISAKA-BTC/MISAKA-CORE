import { NextResponse, NextRequest } from 'next/server';
import { rpcCall, RpcError } from '@/lib/rpc';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const address = typeof body.address === 'string' ? body.address.trim() : '';

    if (!address) {
      return NextResponse.json({ success: false, error: 'Address is required' }, { status: 400 });
    }
    if (!address.startsWith('msk1') || address.length < 10) {
      return NextResponse.json({ success: false, error: 'Invalid MISAKA address format' }, { status: 400 });
    }

    const raw = await rpcCall('faucet', { address });
    return NextResponse.json(raw);
  } catch (e) {
    const status = e instanceof RpcError ? e.status : 502;
    return NextResponse.json({ success: false, error: 'Faucet request failed' }, { status });
  }
}
