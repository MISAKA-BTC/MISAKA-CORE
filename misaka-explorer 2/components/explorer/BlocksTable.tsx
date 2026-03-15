import Link from 'next/link';
import type { BlockSummary } from '@/types/explorer';
import { HashDisplay } from '@/components/ui/HashDisplay';
import { FinalityBadge } from '@/components/ui/Badge';
import { TimestampDisplay } from '@/components/ui/Shared';
import { formatBytes, formatNumber } from '@/lib/format';

interface BlocksTableProps {
  blocks: BlockSummary[];
  compact?: boolean;
}

export function BlocksTable({ blocks, compact = false }: BlocksTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-300/50">
            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Height</th>
            <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Hash</th>
            {!compact && <th className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Proposer</th>}
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Txs</th>
            {!compact && <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Size</th>}
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Time</th>
            <th className="text-right py-3 px-4 text-xs font-semibold uppercase tracking-wider text-slate-500">Status</th>
          </tr>
        </thead>
        <tbody>
          {blocks.map((block) => (
            <tr key={block.height} className="border-b border-surface-300/20 table-row-hover">
              <td className="py-3 px-4">
                <Link href={`/blocks/${block.height}`} className="font-mono text-misaka-400 hover:text-misaka-300 font-semibold transition-colors">
                  #{formatNumber(block.height)}
                </Link>
              </td>
              <td className="py-3 px-4">
                <HashDisplay hash={block.hash} href={`/blocks/${block.height}`} startLen={6} endLen={4} copyable={!compact} />
              </td>
              {!compact && (
                <td className="py-3 px-4">
                  <Link href={`/validators/${block.proposer}`} className="text-slate-400 hover:text-misaka-400 text-xs font-mono transition-colors">
                    {block.proposer}
                  </Link>
                </td>
              )}
              <td className="py-3 px-4 text-right text-slate-300 font-mono">{block.txCount}</td>
              {!compact && <td className="py-3 px-4 text-right text-slate-500 text-xs">{formatBytes(block.size)}</td>}
              <td className="py-3 px-4 text-right">
                <TimestampDisplay iso={block.timestamp} className="text-xs" />
              </td>
              <td className="py-3 px-4 text-right">
                <FinalityBadge status={block.finality} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
