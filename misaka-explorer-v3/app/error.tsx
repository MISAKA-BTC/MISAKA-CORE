'use client';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-32 text-center page-enter">
      <div className="w-20 h-20 rounded-2xl bg-accent-red/10 border border-accent-red/20 flex items-center justify-center mb-6">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-accent-red">
          <circle cx="12" cy="12" r="10" />
          <line x1="15" y1="9" x2="9" y2="15" />
          <line x1="9" y1="9" x2="15" y2="15" />
        </svg>
      </div>
      <h1 className="text-2xl font-bold text-fg mb-2">Something went wrong</h1>
      <p className="text-sm text-muted500 mb-2 max-w-md">
        An error occurred while loading this page. This could be due to a network issue or the MISAKA node being temporarily unavailable.
      </p>
      {error.message && (
        <p className="text-xs text-muted600 font-mono bg-hover200 px-3 py-1.5 rounded-lg mb-6 max-w-lg break-all">
          {error.message}
        </p>
      )}
      <button
        onClick={reset}
        className="px-5 py-2.5 rounded-lg text-sm font-medium bg-misaka-500/20 text-subtle400 hover:bg-misaka-500/30 transition-colors"
      >
        Try again
      </button>
    </div>
  );
}
