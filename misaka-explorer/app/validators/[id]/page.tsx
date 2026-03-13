import { api } from '@/lib/api/client';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { StatusBadge } from '@/components/ui/Badge';
import { StatCard } from '@/components/ui/StatCard';
import { TimestampDisplay } from '@/components/ui/Shared';
import { formatNumber, formatPercent, formatTimestamp } from '@/lib/format';
import Link from 'next/link';
import { notFound } from 'next/navigation';

export const revalidate = 30;

export default async function ValidatorDetailPage({ params }: { params: { id: string } }) {
  const v = await api.getValidatorById(params.id);
  if (!v) return notFound();

  return (
    <div className="page-enter space-y-8">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link href="/validators" className="text-slate-500 hover:text-misaka-400 transition-colors">Validators</Link>
        <span className="text-slate-600">/</span>
        <span className="text-slate-300 font-mono text-xs">{v.id}</span>
      </div>

      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-misaka-500/20 to-misaka-700/20 border border-misaka-500/20 flex items-center justify-center">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-misaka-400">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div>
          <h1 className="font-display text-2xl font-bold text-white tracking-tight">{v.id}</h1>
          <div className="flex items-center gap-2 mt-1">
            <StatusBadge status={v.status} />
            <StatusBadge status={v.slashingStatus} />
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Stake Weight" value={`${formatNumber(v.stakeWeight)} MSK`} />
        <StatCard label="Participation" value={formatPercent(v.participationRate)} trend={v.participationRate > 95 ? 'up' : 'down'} />
        <StatCard label="Uptime" value={v.uptime != null ? formatPercent(v.uptime) : '—'} />
        <StatCard label="Total Proposed" value={formatNumber(v.totalBlocksProposed)} />
      </div>

      {/* Detail card */}
      <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
        <div className="divide-y divide-surface-300/30">
          <DetailRow label="Public Key">
            <HashDisplay hash={v.publicKey} full copyable />
          </DetailRow>
          <DetailRow label="Joined">
            <span className="text-slate-300">{formatTimestamp(v.joinedAt)}</span>
          </DetailRow>
          <DetailRow label="Latest Activity">
            <span className="text-slate-300">{formatTimestamp(v.latestActivity)} (<TimestampDisplay iso={v.latestActivity} />)</span>
          </DetailRow>
          <DetailRow label="Latest Proposed Block">
            {v.latestProposedBlock ? (
              <Link href={`/blocks/${v.latestProposedBlock}`} className="font-mono text-misaka-400 hover:text-misaka-300 text-sm transition-colors">
                #{formatNumber(v.latestProposedBlock)}
              </Link>
            ) : <span className="text-slate-500">—</span>}
          </DetailRow>
        </div>
      </div>

      {/* Recent Proposals */}
      <section>
        <h2 className="font-display font-semibold text-white text-lg mb-3">Recent Proposals</h2>
        <div className="flex flex-wrap gap-2">
          {v.recentProposals.map((h) => (
            <Link
              key={h}
              href={`/blocks/${h}`}
              className="px-3 py-1.5 rounded-lg bg-surface-200 border border-surface-300/50 text-xs font-mono text-misaka-400 hover:bg-surface-300 hover:text-misaka-300 transition-all"
            >
              #{formatNumber(h)}
            </Link>
          ))}
        </div>
      </section>

      {/* Recent Votes */}
      <section>
        <h2 className="font-display font-semibold text-white text-lg mb-3">Recent Votes</h2>
        <div className="flex flex-wrap gap-2">
          {v.recentVotes.slice(0, 20).map((h) => (
            <Link
              key={h}
              href={`/blocks/${h}`}
              className="px-2.5 py-1 rounded-md bg-surface-200 border border-surface-300/30 text-[10px] font-mono text-slate-400 hover:bg-surface-300 hover:text-white transition-all"
            >
              #{h}
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center px-5 py-3.5 gap-1 sm:gap-0">
      <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 sm:w-48 shrink-0">{label}</span>
      <div className="text-sm min-w-0 break-all">{children}</div>
    </div>
  );
}
