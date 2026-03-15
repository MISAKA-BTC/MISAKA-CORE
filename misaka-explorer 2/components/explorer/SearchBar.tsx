'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';

export function SearchBar({ compact = false }: { compact?: boolean }) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSearch = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;

    setLoading(true);
    try {
      // Auto-detect query type
      if (/^\d+$/.test(q)) {
        router.push(`/blocks/${q}`);
      } else if (q.length === 64 && /^[0-9a-fA-F]+$/.test(q)) {
        // Could be block hash or tx hash — try tx first
        router.push(`/txs/${q}`);
      } else if (q.startsWith('msk1')) {
        router.push(`/address/${q}`);
      } else if (q.startsWith('validator')) {
        router.push(`/validators/${q}`);
      } else {
        router.push(`/txs/${q}`);
      }
    } finally {
      setLoading(false);
    }
  }, [query, router]);

  return (
    <form onSubmit={handleSearch} className={compact ? 'w-full max-w-md' : 'w-full max-w-2xl mx-auto'}>
      <div className="relative group">
        <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-misaka-500/20 via-misaka-400/10 to-misaka-500/20 blur-sm opacity-0 group-focus-within:opacity-100 transition-opacity" />
        <div className="relative flex items-center bg-surface-200 border border-surface-400/50 rounded-xl focus-within:border-misaka-500/40 transition-all">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="ml-4 text-slate-500 shrink-0">
            <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by block height, hash, tx hash, or address..."
            className={`w-full bg-transparent text-sm text-white placeholder-slate-500 outline-none ${compact ? 'px-3 py-2.5' : 'px-4 py-3.5'}`}
          />
          {loading && (
            <div className="mr-4">
              <div className="w-4 h-4 border-2 border-misaka-400/30 border-t-misaka-400 rounded-full animate-spin" />
            </div>
          )}
          {!loading && query && (
            <button
              type="submit"
              className="mr-2 px-3 py-1.5 text-xs font-semibold bg-misaka-500/20 text-misaka-400 rounded-lg hover:bg-misaka-500/30 transition-colors"
            >
              Search
            </button>
          )}
        </div>
      </div>
    </form>
  );
}
