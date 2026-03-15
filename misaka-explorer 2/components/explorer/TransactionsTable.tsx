import Link from 'next/link';
import type { TransactionSummary } from '@/types/explorer';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { StatusBadge } from '@/components/ui/Badge';
import { TimestampDisplay } from '@/components/ui/Shared';
import { formatFee, formatNumber } from '@/lib/format';

interface TransactionsTableProps {
  transactions: TransactionSummary[];
  compact?: boolean;
}

export function TransactionsTable({ transactions, compact = false }: TransactionsTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-300/50">
            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Tx Hash</th>
            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Block</th>
            {!compact && <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Fee</th>}
            {!compact && <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">In/Out</th>}
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Time</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Status</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map((tx) => (
            <tr key={tx.hash} className="border-b border-surface-300/20 table-row-hover">
              <td className="py-3 px-4">
                <HashDisplay hash={tx.hash} href={`/txs/${tx.hash}`} startLen={compact ? 6 : 8} endLen={compact ? 4 : 6} copyable={!compact} />
              </td>
              <td className="py-3 px-4">
                <Link href={`/blocks/${tx.blockHeight}`} className="font-mono text-misaka-400 hover:text-misaka-300 text-xs transition-colors">
                  #{formatNumber(tx.blockHeight)}
                </Link>
              </td>
              {!compact && (
                <td className="py-3 px-4 text-right text-slate-400 font-mono text-xs">{formatFee(tx.fee)}</td>
              )}
              {!compact && (
                <td className="py-3 px-4 text-right text-slate-500 text-xs font-mono">
                  {tx.inputCount} → {tx.outputCount}
                </td>
              )}
              <td className="py-3 px-4 text-right">
                <TimestampDisplay iso={tx.timestamp} className="text-xs" />
              </td>
              <td className="py-3 px-4 text-right">
                <StatusBadge status={tx.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
