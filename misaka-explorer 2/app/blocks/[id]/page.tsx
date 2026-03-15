import { api } from '@/lib/api/client';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { FinalityBadge, StatusBadge } from '@/components/ui/Badge';
import { TransactionsTable } from '@/components/explorer/TransactionsTable';
import { TimestampDisplay } from '@/components/ui/Shared';
import { AutoRefresh } from '@/components/ui/AutoRefresh';
import { RawJsonViewer } from '@/components/ui/RawJsonViewer';
import { formatBytes, formatFee, formatNumber, formatTimestamp } from '@/lib/format';
import Link from 'next/link';
import { notFound } from 'next/navigation';

export const revalidate = 15;

export default async function BlockDetailPage({ params }: { params: { id: string } }) {
  const id = params.id;
  const block = /^\d+$/.test(id)
    ? await api.getBlockByHeight(parseInt(id, 10))
    : await api.getBlockByHash(id);

  if (!block) return notFound();

  const rows: [string, React.ReactNode][] = [
    ['Block Height', <span key="h" className="font-mono text-white font-semibold">#{formatNumber(block.height)}</span>],
    ['Block Hash', <HashDisplay key="bh" hash={block.hash} full copyable />],
    ['Parent Hash', <HashDisplay key="ph" hash={block.parentHash} href={`/blocks/${block.height - 1}`} copyable />],
    ['Status', <StatusBadge key="s" status={block.status} />],
    ['Finality', <FinalityBadge key="f" status={block.finality} />],
    ['Timestamp', <span key="t" className="text-slate-300">{formatTimestamp(block.timestamp)} (<TimestampDisplay iso={block.timestamp} />)</span>],
    ['Proposer', (
      <Link key="p" href={`/validators/${block.proposer}`} className="font-mono text-misaka-400 hover:text-misaka-300 text-sm transition-colors link-underline">
        {block.proposer}
      </Link>
    )],
    ['Validator Signatures', <span key="vs" className="text-slate-300 font-mono">{block.validatorSignatures}</span>],
    ['Transaction Count', <span key="tc" className="text-slate-300 font-mono">{block.txCount}</span>],
    ['Total Fees', <span key="tf" className="text-slate-300 font-mono">{formatFee(block.totalFees)}</span>],
    ['Block Size', <span key="bs" className="text-slate-300">{formatBytes(block.size)}</span>],
  ];

  return (
    <div className="page-enter space-y-8">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link href="/blocks" className="text-slate-500 hover:text-misaka-400 transition-colors">Blocks</Link>
        <span className="text-slate-600">/</span>
        <span className="text-slate-300">#{formatNumber(block.height)}</span>
      </div>

      <div className="flex items-center justify-between">
        <h1 className="font-display text-2xl font-bold text-white tracking-tight">
          Block #{formatNumber(block.height)}
        </h1>
        <AutoRefresh />
      </div>

      {/* Detail card */}
      <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
        <div className="divide-y divide-surface-300/30">
          {rows.map(([label, value]) => (
            <div key={label} className="flex flex-col sm:flex-row sm:items-center px-5 py-3.5 gap-1 sm:gap-0">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 sm:w-48 shrink-0">{label}</span>
              <div className="text-sm min-w-0 break-all">{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Navigation */}
      <div className="flex items-center gap-3">
        {block.height > 0 && (
          <Link href={`/blocks/${block.height - 1}`} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white transition-all">
            ← Block #{formatNumber(block.height - 1)}
          </Link>
        )}
        <Link href={`/blocks/${block.height + 1}`} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white transition-all">
          Block #{formatNumber(block.height + 1)} →
        </Link>
      </div>

      {/* Transactions in block */}
      <section>
        <h2 className="font-display font-semibold text-white text-lg mb-4">
          Transactions ({block.transactions.length})
        </h2>
        <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
          <TransactionsTable transactions={block.transactions} />
        </div>
      </section>

      {/* Raw JSON */}
      <RawJsonViewer data={block} title="View Raw Block Data" />
    </div>
  );
}
