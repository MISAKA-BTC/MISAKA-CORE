import { api } from '@/lib/api/client';
import { BlocksTable } from '@/components/explorer/BlocksTable';
import Link from 'next/link';

export const revalidate = 15;

export default async function BlocksPage({
  searchParams,
}: {
  searchParams: { page?: string };
}) {
  const page = Math.max(1, parseInt(searchParams.page || '1', 10));
  const res = await api.getLatestBlocks(page, 20);
  const totalPages = Math.ceil(res.total / res.pageSize);

  return (
    <div className="page-enter space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-fg tracking-tight">Blocks</h1>
          <p className="text-sm text-muted mt-1">Browse all blocks on the MISAKA network</p>
        </div>
      </div>

      <div className="rounded-none border border-line bg-surface overflow-hidden">
        <BlocksTable blocks={res.data} />
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          {page > 1 && (
            <Link
              href={`/blocks?page=${page - 1}`}
              className="px-3 py-1.5 rounded-none text-sm font-medium bg-hover text-subtle hover:bg-dim hover:text-fg transition-all"
            >
              ← Prev
            </Link>
          )}
          <span className="px-3 py-1.5 text-sm text-muted">
            Page {page} of {totalPages}
          </span>
          {page < totalPages && (
            <Link
              href={`/blocks?page=${page + 1}`}
              className="px-3 py-1.5 rounded-none text-sm font-medium bg-hover text-subtle hover:bg-dim hover:text-fg transition-all"
            >
              Next →
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
