import Link from 'next/link';
import type { ValidatorSummary } from '@/types/explorer';
import { StatusBadge } from '@/components/ui/Badge';
import { formatPercent, formatNumber } from '@/lib/format';

interface ValidatorTableProps { validators: ValidatorSummary[]; }

export function ValidatorTable({ validators }: ValidatorTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-line">
            <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">#</th>
            <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Validator</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Stake</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Participation</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Uptime</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Latest Block</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Status</th>
          </tr>
        </thead>
        <tbody>
          {validators.map((v, i) => (
            <tr key={v.id} className="border-b border-line/50 table-row-hover">
              <td className="py-3 px-5 text-dim font-mono text-[12px]">{i + 1}</td>
              <td className="py-3 px-5">
                <Link href={`/validators/${v.id}`} className="text-fg hover:text-subtle font-mono text-[12px] transition-colors link-underline">
                  {v.id}
                </Link>
              </td>
              <td className="py-3 px-5 text-right text-subtle font-mono text-[12px]">{formatNumber(v.stakeWeight)}</td>
              <td className="py-3 px-5 text-right">
                <div className="flex items-center gap-2 justify-end">
                  <span className="text-[12px] text-muted font-mono">{formatPercent(v.participationRate)}</span>
                  <div className="w-12 h-1 bg-line overflow-hidden">
                    <div className="h-full bg-fg/30 transition-all" style={{ width: `${Math.min(100, v.participationRate)}%` }} />
                  </div>
                </div>
              </td>
              <td className="py-3 px-5 text-right text-muted text-[12px]">{v.uptime != null ? formatPercent(v.uptime) : '—'}</td>
              <td className="py-3 px-5 text-right">
                {v.latestProposedBlock ? (
                  <Link href={`/blocks/${v.latestProposedBlock}`} className="font-mono text-subtle hover:text-fg text-[12px] transition-colors">
                    #{formatNumber(v.latestProposedBlock)}
                  </Link>
                ) : <span className="text-dim">—</span>}
              </td>
              <td className="py-3 px-5 text-right"><StatusBadge status={v.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
