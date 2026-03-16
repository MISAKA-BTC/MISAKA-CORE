'use client';

import { useSearchParams } from 'next/navigation';
import { SearchBar } from '@/components/explorer/SearchBar';

export default function SearchPage() {
  const params = useSearchParams();
  const q = params.get('q') || '';

  return (
    <div className="page-enter max-w-2xl mx-auto">
      <section className="pt-16 pb-12 text-center">
        <span className="text-[48px] text-dim block mb-6">∅</span>
        <h1 className="text-[28px] font-extralight text-fg tracking-tight mb-3">
          No Results Found
        </h1>
        {q && (
          <p className="text-[13px] text-muted mb-8">
            Nothing matched <span className="font-mono text-subtle">{q}</span>
          </p>
        )}
        <div className="max-w-lg mx-auto mb-8">
          <SearchBar />
        </div>
        <div className="text-[12px] text-dim space-y-1">
          <p>Try searching by:</p>
          <p className="text-muted">Block height · Block hash · Transaction hash · Address (msk1...) · Validator ID</p>
        </div>
      </section>
    </div>
  );
}
