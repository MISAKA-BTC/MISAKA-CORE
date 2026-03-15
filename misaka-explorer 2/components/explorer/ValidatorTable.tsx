import Link from 'next/link';
import type { ValidatorSummary } from '@/types/explorer';
import { StatusBadge } from '@/components/ui/Badge';
import { formatPercent, formatNumber } from '@/lib/format';

interface ValidatorTableProps {
  validators: ValidatorSummary[];
}

export function ValidatorTable({ validators }: ValidatorTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-300/50">
            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">#</th>
            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Validator</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Stake</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Participation</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Uptime</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Latest Block</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Status</th>
          </tr>
        </thead>
        <tbody>
          {validators.map((v, i) => (
            <tr key={v.id} className="border-b border-surface-300/20 table-row-hover">
              <td className="py-3 px-4 text-slate-500 font-mono text-xs">{i + 1}</td>
              <td className="py-3 px-4">
                <Link href={`/validators/${v.id}`} className="text-misaka-400 hover:text-misaka-300 font-mono text-xs transition-colors link-underline">
                  {v.id}
                </Link>
              </td>
              <td className="py-3 px-4 text-right text-slate-300 font-mono text-xs">
                {formatNumber(v.stakeWeight)} MSK
              </td>
              <td className="py-3 px-4 text-right">
                <ParticipationBar value={v.participationRate} />
              </td>
              <td className="py-3 px-4 text-right text-slate-400 text-xs">
                {v.uptime != null ? formatPercent(v.uptime) : '—'}
              </td>
              <td className="py-3 px-4 text-right">
                {v.latestProposedBlock ? (
                  <Link href={`/blocks/${v.latestProposedBlock}`} className="font-mono text-misaka-400 hover:text-misaka-300 text-xs transition-colors">
                    #{formatNumber(v.latestProposedBlock)}
                  </Link>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </td>
              <td className="py-3 px-4 text-right">
                <StatusBadge status={v.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ParticipationBar({ value }: { value: number }) {
  const pct = Math.min(100, Math.max(0, value));
  const color = pct >= 95 ? 'bg-accent-green' : pct >= 80 ? 'bg-accent-yellow' : 'bg-accent-red';
  return (
    <div className="flex items-center gap-2 justify-end">
      <span className="text-xs text-slate-400 font-mono">{formatPercent(pct)}</span>
      <div className="w-16 h-1.5 bg-surface-300 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
