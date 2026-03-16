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
        <h1 className="text-2xl font-bold text-fg tracking-tight">Transactions</h1>
        <p className="text-sm text-muted mt-1">Browse all transactions on the MISAKA network</p>
      </div>

      {/* Privacy notice */}
      <div className="rounded-none bg-fg/3 border border-line px-4 py-3">
        <p className="text-xs text-subtle leading-relaxed">
          <span className="text-subtle font-semibold">Privacy Notice:</span>{' '}
          This explorer shows only publicly verifiable transaction metadata. Ring-member identities and stealth-address recipients are not deanonymized.
        </p>
      </div>

      <div className="rounded-none border border-line bg-surface overflow-hidden">
        <TransactionsTable transactions={res.data} />
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          {page > 1 && (
            <Link href={`/txs?page=${page - 1}`} className="px-3 py-1.5 rounded-none text-sm font-medium bg-hover text-subtle hover:bg-dim hover:text-fg transition-all">
              ← Prev
            </Link>
          )}
          <span className="px-3 py-1.5 text-sm text-muted">Page {page} of {totalPages}</span>
          {page < totalPages && (
            <Link href={`/txs?page=${page + 1}`} className="px-3 py-1.5 rounded-none text-sm font-medium bg-hover text-subtle hover:bg-dim hover:text-fg transition-all">
              Next →
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
