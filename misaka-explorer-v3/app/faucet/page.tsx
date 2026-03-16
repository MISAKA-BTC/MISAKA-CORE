'use client';

import { useState } from 'react';

export default function FaucetPage() {
  const [address, setAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; txHash?: string; amount?: number; error?: string } | null>(null);

  const isValidFormat = address.trim().startsWith('msk1') && address.trim().length >= 10;

  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    const addr = address.trim();
    if (!addr) return;

    if (!isValidFormat) {
      setResult({ success: false, error: 'Invalid address format. Must start with msk1.' });
      return;
    }

    setLoading(true);
    setResult(null);
    try {
      const res = await fetch('/api/faucet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address: addr }),
      });
      const data = await res.json();
      setResult(data);
    } catch {
      setResult({ success: false, error: 'Failed to connect. Is the node running?' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-enter max-w-xl mx-auto">
      <section className="pt-12 pb-8 text-center">
        <h1 className="text-[36px] font-extralight text-fg tracking-tight mb-2">Testnet Faucet</h1>
        <p className="text-[13px] text-muted tracking-wide">
          Request free MISAKA testnet tokens
        </p>
      </section>

      <form onSubmit={handleRequest} className="space-y-4 mb-8">
        <div>
          <label className="block text-[10px] font-medium uppercase tracking-[0.2em] text-dim mb-2">
            MISAKA Address
          </label>
          <input
            type="text"
            value={address}
            onChange={(e) => { setAddress(e.target.value); setResult(null); }}
            placeholder="msk1..."
            className="w-full bg-transparent border border-line px-4 py-3 text-[13px] text-fg placeholder-dim outline-none focus:border-subtle transition-colors font-mono"
          />
          {address.trim() && !isValidFormat && (
            <p className="text-[11px] text-muted mt-1.5">Address must start with msk1</p>
          )}
        </div>

        <button
          type="submit"
          disabled={loading || !address.trim()}
          className="w-full py-3 text-[13px] font-medium uppercase tracking-[0.15em] bg-fg text-bg hover:bg-subtle disabled:opacity-30 disabled:cursor-not-allowed transition-colors duration-150"
        >
          {loading ? (
            <span className="inline-flex items-center gap-2">
              <span className="w-3.5 h-3.5 border border-bg/30 border-t-bg rounded-full animate-spin" />
              Requesting...
            </span>
          ) : (
            'Request Tokens'
          )}
        </button>
      </form>

      {result && (
        <div className={`border p-5 mb-8 ${result.success ? 'border-fg/20' : 'border-line'}`}>
          {result.success ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-fg" />
                <span className="text-[13px] font-medium text-fg">Tokens sent</span>
              </div>
              {result.amount && (
                <p className="text-[12px] text-muted">
                  <span className="text-dim">Amount:</span> {result.amount.toLocaleString()} MISAKA
                </p>
              )}
              {result.txHash && (
                <p className="text-[12px]">
                  <span className="text-dim">TX:</span>{' '}
                  <span className="font-mono text-[11px] text-subtle break-all">{result.txHash}</span>
                </p>
              )}
              <p className="text-[11px] text-dim mt-2">Included in the next block.</p>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-dim" />
              <span className="text-[13px] text-muted">{result.error}</span>
            </div>
          )}
        </div>
      )}

      <div className="border-t border-line pt-6">
        <p className="text-[11px] text-dim leading-relaxed">
          Testnet tokens have no real value. Rate limited to 1 request per address per 60 seconds.
        </p>
      </div>
    </div>
  );
}
