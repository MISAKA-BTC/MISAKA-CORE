'use client';

import { useState } from 'react';
import { requestFaucet } from '@/lib/api/client';

export default function FaucetPage() {
  const [address, setAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; txHash?: string; amount?: number; error?: string } | null>(null);

  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!address.trim()) return;

    setLoading(true);
    setResult(null);
    try {
      const res = await requestFaucet(address.trim());
      setResult(res);
    } catch (err) {
      setResult({ success: false, error: 'Failed to connect to node. Is the MISAKA node running?' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-enter max-w-xl mx-auto space-y-8">
      <div className="text-center pt-6">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-misaka-500/20 to-accent-cyan/20 border border-misaka-500/20 flex items-center justify-center mx-auto mb-4">
          <span className="text-3xl">🚰</span>
        </div>
        <h1 className="font-display text-3xl font-bold text-white tracking-tight mb-2">
          Testnet Faucet
        </h1>
        <p className="text-sm text-slate-500 max-w-md mx-auto">
          Request free MISAKA testnet tokens to try out transactions, ring signatures, and stealth addresses.
        </p>
      </div>

      <form onSubmit={handleRequest} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
            MISAKA Address
          </label>
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="msk1..."
            className="w-full bg-surface-200 border border-surface-400/50 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 outline-none focus:border-misaka-500/40 transition-all font-mono"
          />
        </div>

        <button
          type="submit"
          disabled={loading || !address.trim()}
          className="w-full py-3 rounded-xl text-sm font-semibold bg-gradient-to-r from-misaka-500 to-misaka-600 text-white hover:from-misaka-400 hover:to-misaka-500 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-lg shadow-misaka-500/20"
        >
          {loading ? (
            <span className="inline-flex items-center gap-2">
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Requesting...
            </span>
          ) : (
            'Request Testnet Tokens'
          )}
        </button>
      </form>

      {result && (
        <div className={`rounded-xl border p-5 ${
          result.success
            ? 'bg-accent-green/5 border-accent-green/20'
            : 'bg-accent-red/5 border-accent-red/20'
        }`}>
          {result.success ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-accent-green text-lg">✅</span>
                <span className="text-sm font-semibold text-accent-green">Tokens sent!</span>
              </div>
              <div className="text-sm text-slate-300">
                <span className="text-slate-500">Amount:</span> {result.amount?.toLocaleString()} MISAKA
              </div>
              <div className="text-sm">
                <span className="text-slate-500">TX Hash:</span>{' '}
                <span className="font-mono text-xs text-misaka-400 break-all">{result.txHash}</span>
              </div>
              <p className="text-xs text-slate-500 mt-2">
                The transaction will be included in the next block.
              </p>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-accent-red text-lg">❌</span>
              <span className="text-sm text-accent-red">{result.error}</span>
            </div>
          )}
        </div>
      )}

      <div className="rounded-lg bg-surface-200 border border-surface-300/50 px-4 py-3">
        <p className="text-xs text-slate-500 leading-relaxed">
          <span className="text-slate-400 font-semibold">Note:</span>{' '}
          Testnet tokens have no real value. Faucet is rate-limited to 1 request per address per 60 seconds.
          Use <code className="text-misaka-400 text-[10px]">misaka-cli faucet {'<address>'}</code> for CLI access.
        </p>
      </div>
    </div>
  );
}
