'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export function SearchBar({ compact = false }: { compact?: boolean }) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;

    setLoading(true);
    try {
      const res = await fetch('/api/explorer/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      });
      const result = await res.json();

      switch (result.type) {
        case 'block':
          router.push(`/blocks/${result.value}`);
          break;
        case 'transaction':
          router.push(`/txs/${result.value}`);
          break;
        case 'address':
          router.push(`/address/${result.value}`);
          break;
        case 'validator':
          router.push(`/validators/${result.value}`);
          break;
        default:
          router.push(`/search?q=${encodeURIComponent(q)}`);
      }
    } catch {
      router.push(`/search?q=${encodeURIComponent(q)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSearch} className="relative">
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search by block, tx, address..."
        disabled={loading}
        className={`w-full bg-transparent border border-line px-4 text-[13px] text-fg placeholder-dim outline-none focus:border-subtle transition-colors duration-150 font-mono disabled:opacity-50 ${
          compact ? 'py-2' : 'py-3.5'
        }`}
      />
      {loading && (
        <div className="absolute right-3 top-1/2 -translate-y-1/2">
          <div className="w-4 h-4 border border-muted border-t-fg rounded-full animate-spin" />
        </div>
      )}
    </form>
  );
}
