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
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-line">
            <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Tx Hash</th>
            <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Block</th>
            {!compact && <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Fee</th>}
            {!compact && <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">In/Out</th>}
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Time</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Status</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map((tx) => (
            <tr key={tx.hash} className="border-b border-line/50 table-row-hover">
              <td className="py-3 px-5">
                <HashDisplay hash={tx.hash} href={`/txs/${tx.hash}`} startLen={compact ? 6 : 8} endLen={compact ? 4 : 6} copyable={!compact} />
              </td>
              <td className="py-3 px-5">
                <Link href={`/blocks/${tx.blockHeight}`} className="font-mono text-subtle hover:text-fg text-[12px] transition-colors">
                  #{formatNumber(tx.blockHeight)}
                </Link>
              </td>
              {!compact && <td className="py-3 px-5 text-right text-muted font-mono text-[12px]">{formatFee(tx.fee)}</td>}
              {!compact && <td className="py-3 px-5 text-right text-dim text-[12px] font-mono">{tx.inputCount} → {tx.outputCount}</td>}
              <td className="py-3 px-5 text-right">
                <TimestampDisplay iso={tx.timestamp} />
              </td>
              <td className="py-3 px-5 text-right">
                <StatusBadge status={tx.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
