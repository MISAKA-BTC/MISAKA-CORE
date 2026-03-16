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
      <Link key="b" href={`/blocks/${tx.blockHeight}`} className="font-mono text-subtle hover:text-fg text-sm transition-colors">
        #{formatNumber(tx.blockHeight)}
      </Link>
    )],
    ['Block Hash', <HashDisplay key="bh" hash={tx.blockHash} href={`/blocks/${tx.blockHeight}`} copyable />],
    ['Timestamp', <span key="t" className="text-subtle">{formatTimestamp(tx.timestamp)} (<TimestampDisplay iso={tx.timestamp} />)</span>],
    ['Confirmations', <span key="c" className="text-subtle font-mono">{formatNumber(tx.confirmations)}</span>],
    ['Fee', <span key="f" className="text-subtle font-mono">{formatFee(tx.fee)}</span>],
    ['Size', <span key="sz" className="text-subtle">{formatBytes(tx.size)}</span>],
    ['Version', <span key="v" className="text-subtle font-mono">{tx.version}</span>],
    ['Ring Inputs', <span key="ri" className="text-subtle font-mono">{tx.ringInputCount}</span>],
    ['Stealth Outputs', <span key="so" className="text-subtle font-mono">{tx.stealthOutputCount}</span>],
    ['Payload', tx.hasPayload
      ? <Badge key="pl" variant="info">Present</Badge>
      : <span key="pl" className="text-muted">None</span>
    ],
  ];

  return (
    <div className="page-enter space-y-8">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link href="/txs" className="text-muted hover:text-subtle transition-colors">Transactions</Link>
        <span className="text-dim">/</span>
        <span className="text-subtle font-mono text-xs">{tx.hash.slice(0, 12)}…</span>
      </div>

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-fg tracking-tight">Transaction Details</h1>
        <AutoRefresh />
      </div>

      {/* Detail card */}
      <div className="rounded-none border border-line bg-surface overflow-hidden">
        <div className="divide-y divide-surface-300/30">
          {rows.map(([label, value]) => (
            <div key={label} className="flex flex-col sm:flex-row sm:items-center px-5 py-3.5 gap-1 sm:gap-0">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted sm:w-48 shrink-0">{label}</span>
              <div className="text-sm min-w-0 break-all">{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Key Images */}
      <section>
        <h2 className="font-semibold text-fg text-lg mb-3">
          Key Images ({tx.keyImages.length})
        </h2>
        <div className="rounded-none border border-line bg-surface p-5 space-y-2">
          {tx.keyImages.map((ki, i) => (
            <div key={i} className="flex items-center gap-3">
              <span className="text-xs text-muted font-mono w-6 text-right">{i}</span>
              <HashDisplay hash={ki} full={false} copyable />
            </div>
          ))}
        </div>
      </section>

      {/* Privacy notice */}
      <div className="rounded-none bg-hover border border-line px-4 py-3">
        <p className="text-xs text-muted leading-relaxed">
          <span className="text-subtle font-semibold">Privacy-Aware Display:</span>{' '}
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
