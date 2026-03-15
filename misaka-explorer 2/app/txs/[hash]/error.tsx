'use client';

import Link from 'next/link';

export default function RouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center page-enter">
      <div className="w-16 h-16 rounded-xl bg-accent-red/10 border border-accent-red/20 flex items-center justify-center mb-5">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-accent-red">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      </div>
      <h2 className="font-display text-xl font-bold text-white mb-2">Failed to load data</h2>
      <p className="text-sm text-slate-500 mb-1 max-w-md">
        The requested resource could not be fetched. The node may be temporarily unavailable.
      </p>
      {error.message && (
        <p className="text-[11px] text-slate-600 font-mono bg-surface-200 px-3 py-1 rounded-lg mb-5 max-w-md break-all">
          {error.message}
        </p>
      )}
      <div className="flex gap-3">
        <button
          onClick={reset}
          className="px-4 py-2 rounded-lg text-sm font-medium bg-misaka-500/20 text-misaka-400 hover:bg-misaka-500/30 transition-colors"
        >
          Retry
        </button>
        <Link href="/" className="px-4 py-2 rounded-lg text-sm font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white transition-all">
          Dashboard
        </Link>
      </div>
    </div>
  );
}
