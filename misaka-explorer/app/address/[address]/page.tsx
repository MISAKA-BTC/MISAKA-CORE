import { api } from '@/lib/api/client';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { TimestampDisplay } from '@/components/ui/Shared';
import { Badge } from '@/components/ui/Badge';
import { formatNumber } from '@/lib/format';
import Link from 'next/link';
import { notFound } from 'next/navigation';

export const revalidate = 30;

export default async function AddressPage({ params }: { params: { address: string } }) {
  const summary = await api.getAddressSummary(params.address);
  if (!summary) return notFound();

  return (
    <div className="page-enter space-y-8">
      {/* Header */}
      <div>
        <h1 className="font-display text-2xl font-bold text-white tracking-tight mb-2">Address</h1>
        <div className="hash-text text-sm text-slate-300 break-all bg-surface-200 px-4 py-2.5 rounded-lg border border-surface-300/50">
          {summary.address}
        </div>
      </div>

      {/* Privacy notice */}
      {summary.privacyNote && (
        <div className="rounded-lg bg-misaka-500/5 border border-misaka-500/10 px-4 py-3">
          <p className="text-xs text-slate-400 leading-relaxed">
            <span className="text-misaka-400 font-semibold">Privacy Note:</span>{' '}
            {summary.privacyNote}
          </p>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <InfoCard label="Balance" value={summary.balance != null ? `${formatNumber(summary.balance)} MSK` : null} />
        <InfoCard label="Total Received" value={summary.totalReceived != null ? `${formatNumber(summary.totalReceived)} MSK` : null} />
        <InfoCard label="Total Sent" value={summary.totalSent != null ? `${formatNumber(summary.totalSent)} MSK` : null} />
        <InfoCard label="Transactions" value={formatNumber(summary.txCount)} />
      </div>

      {/* Outputs */}
      <section>
        <h2 className="font-display font-semibold text-white text-lg mb-4">
          Outputs ({summary.outputs.length})
        </h2>
        <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-300/50">
                <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Tx Hash</th>
                <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Index</th>
                <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Amount</th>
                <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Time</th>
                <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Spent</th>
              </tr>
            </thead>
            <tbody>
              {summary.outputs.map((o, i) => (
                <tr key={i} className="border-b border-surface-300/20 table-row-hover">
                  <td className="py-3 px-4">
                    <HashDisplay hash={o.txHash} href={`/txs/${o.txHash}`} startLen={6} endLen={4} />
                  </td>
                  <td className="py-3 px-4 text-right text-slate-400 font-mono text-xs">{o.outputIndex}</td>
                  <td className="py-3 px-4 text-right text-slate-400 font-mono text-xs">
                    {o.amount != null ? `${o.amount} MSK` : <PrivacyShield />}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <TimestampDisplay iso={o.timestamp} className="text-xs" />
                  </td>
                  <td className="py-3 px-4 text-right">
                    {o.spent === true && <Badge variant="neutral">Spent</Badge>}
                    {o.spent === false && <Badge variant="success">Unspent</Badge>}
                    {o.spent === null && <PrivacyShield />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function InfoCard({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-4">
      <span className="text-xs font-medium uppercase tracking-widest text-slate-500 block mb-1.5">{label}</span>
      {value != null ? (
        <span className="text-lg font-semibold font-display text-white">{value}</span>
      ) : (
        <span className="inline-flex items-center gap-1.5 text-sm text-slate-500">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          Privacy-protected
        </span>
      )}
    </div>
  );
}

function PrivacyShield() {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-slate-600" title="Hidden for privacy">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
        <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
      Hidden
    </span>
  );
}
