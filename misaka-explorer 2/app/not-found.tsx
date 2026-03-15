import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-32 text-center page-enter">
      <div className="w-20 h-20 rounded-2xl bg-surface-200 border border-surface-300/50 flex items-center justify-center mb-6">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-slate-500">
          <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /><line x1="8" y1="11" x2="14" y2="11" />
        </svg>
      </div>
      <h1 className="font-display text-3xl font-bold text-white mb-2">Not Found</h1>
      <p className="text-sm text-slate-500 mb-8 max-w-sm">
        The block, transaction, address, or validator you&apos;re looking for doesn&apos;t exist or hasn&apos;t been indexed yet.
      </p>
      <div className="flex gap-3">
        <Link href="/" className="px-4 py-2 rounded-lg text-sm font-medium bg-misaka-500/20 text-misaka-400 hover:bg-misaka-500/30 transition-colors">
          Go to Dashboard
        </Link>
        <Link href="/blocks" className="px-4 py-2 rounded-lg text-sm font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white transition-all">
          Browse Blocks
        </Link>
      </div>
    </div>
  );
}
