import { api } from '@/lib/api/client';
import { TransactionsTable } from '@/components/explorer/TransactionsTable';
import Link from 'next/link';

export const revalidate = 15;

export default async function TransactionsPage({
  searchParams,
}: {
  searchParams: { page?: string };
}) {
  const page = Math.max(1, parseInt(searchParams.page || '1', 10));
  const res = await api.getLatestTransactions(page, 20);
  const totalPages = Math.ceil(res.total / res.pageSize);

  return (
    <div className="page-enter space-y-6">
      <div>
        <h1 className="font-display text-2xl font-bold text-white tracking-tight">Transactions</h1>
        <p className="text-sm text-slate-500 mt-1">Browse all transactions on the MISAKA network</p>
      </div>

      {/* Privacy notice */}
      <div className="rounded-lg bg-misaka-500/5 border border-misaka-500/10 px-4 py-3">
        <p className="text-xs text-slate-400 leading-relaxed">
          <span className="text-misaka-400 font-semibold">Privacy Notice:</span>{' '}
          This explorer shows only publicly verifiable transaction metadata. Ring-member identities and stealth-address recipients are not deanonymized.
        </p>
      </div>

      <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
        <TransactionsTable transactions={res.data} />
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          {page > 1 && (
            <Link href={`/txs?page=${page - 1}`} className="px-3 py-1.5 rounded-lg text-sm font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white transition-all">
              ← Prev
            </Link>
          )}
          <span className="px-3 py-1.5 text-sm text-slate-500">Page {page} of {totalPages}</span>
          {page < totalPages && (
            <Link href={`/txs?page=${page + 1}`} className="px-3 py-1.5 rounded-lg text-sm font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white transition-all">
              Next →
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
