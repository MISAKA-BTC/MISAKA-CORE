import { api } from '@/lib/api/client';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { StatusBadge, Badge } from '@/components/ui/Badge';
import { TimestampDisplay } from '@/components/ui/Shared';
import { AutoRefresh } from '@/components/ui/AutoRefresh';
import { RawJsonViewer } from '@/components/ui/RawJsonViewer';
import { formatBytes, formatFee, formatNumber, formatTimestamp } from '@/lib/format';
import Link from 'next/link';
import { notFound } from 'next/navigation';

export const revalidate = 15;

export default async function TxDetailPage({ params }: { params: { hash: string } }) {
  const tx = await api.getTransactionByHash(params.hash);
  if (!tx) return notFound();

  const rows: [string, React.ReactNode][] = [
    ['Transaction Hash', <HashDisplay key="th" hash={tx.hash} full copyable />],
    ['Status', <StatusBadge key="s" status={tx.status} />],
    ['Block', (
      <Link key="b" href={`/blocks/${tx.blockHeight}`} className="font-mono text-misaka-400 hover:text-misaka-300 text-sm transition-colors">
        #{formatNumber(tx.blockHeight)}
      </Link>
    )],
    ['Block Hash', <HashDisplay key="bh" hash={tx.blockHash} href={`/blocks/${tx.blockHeight}`} copyable />],
    ['Timestamp', <span key="t" className="text-slate-300">{formatTimestamp(tx.timestamp)} (<TimestampDisplay iso={tx.timestamp} />)</span>],
    ['Confirmations', <span key="c" className="text-slate-300 font-mono">{formatNumber(tx.confirmations)}</span>],
    ['Fee', <span key="f" className="text-slate-300 font-mono">{formatFee(tx.fee)}</span>],
    ['Size', <span key="sz" className="text-slate-300">{formatBytes(tx.size)}</span>],
    ['Version', <span key="v" className="text-slate-400 font-mono">{tx.version}</span>],
    ['Ring Inputs', <span key="ri" className="text-slate-300 font-mono">{tx.ringInputCount}</span>],
    ['Stealth Outputs', <span key="so" className="text-slate-300 font-mono">{tx.stealthOutputCount}</span>],
    ['Payload', tx.hasPayload
      ? <Badge key="pl" variant="info">Present</Badge>
      : <span key="pl" className="text-slate-500">None</span>
    ],
  ];

  return (
    <div className="page-enter space-y-8">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link href="/txs" className="text-slate-500 hover:text-misaka-400 transition-colors">Transactions</Link>
        <span className="text-slate-600">/</span>
        <span className="text-slate-300 font-mono text-xs">{tx.hash.slice(0, 12)}…</span>
      </div>

      <div className="flex items-center justify-between">
        <h1 className="font-display text-2xl font-bold text-white tracking-tight">Transaction Details</h1>
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

      {/* Key Images */}
      <section>
        <h2 className="font-display font-semibold text-white text-lg mb-3">
          Key Images ({tx.keyImages.length})
        </h2>
        <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 space-y-2">
          {tx.keyImages.map((ki, i) => (
            <div key={i} className="flex items-center gap-3">
              <span className="text-xs text-slate-500 font-mono w-6 text-right">{i}</span>
              <HashDisplay hash={ki} full={false} copyable />
            </div>
          ))}
        </div>
      </section>

      {/* Privacy notice */}
      <div className="rounded-lg bg-surface-200 border border-surface-300/50 px-4 py-3">
        <p className="text-xs text-slate-500 leading-relaxed">
          <span className="text-slate-400 font-semibold">Privacy-Aware Display:</span>{' '}
          Ring signature inputs protect sender anonymity among {tx.ringInputCount} possible signers.
          Stealth outputs obscure recipient addresses. This explorer does not attempt to deanonymize
          ring members or stealth recipients.
        </p>
      </div>

      {/* Raw JSON */}
      <RawJsonViewer data={tx} title="View Raw Transaction Data" />
    </div>
  );
}
