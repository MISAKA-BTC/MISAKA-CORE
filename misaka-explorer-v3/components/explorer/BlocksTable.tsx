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
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-line">
            <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Height</th>
            <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Hash</th>
            {!compact && <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Proposer</th>}
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Txs</th>
            {!compact && <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Size</th>}
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Time</th>
            <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Status</th>
          </tr>
        </thead>
        <tbody>
          {blocks.map((block) => (
            <tr key={block.height} className="border-b border-line/50 table-row-hover">
              <td className="py-3 px-5">
                <Link href={`/blocks/${block.height}`} className="font-mono text-fg hover:text-subtle transition-colors">
                  #{formatNumber(block.height)}
                </Link>
              </td>
              <td className="py-3 px-5">
                <HashDisplay hash={block.hash} href={`/blocks/${block.height}`} startLen={6} endLen={4} copyable={!compact} />
              </td>
              {!compact && (
                <td className="py-3 px-5">
                  <Link href={`/validators/${block.proposer}`} className="text-muted hover:text-fg text-[12px] font-mono transition-colors">
                    {block.proposer}
                  </Link>
                </td>
              )}
              <td className="py-3 px-5 text-right text-subtle font-mono">{block.txCount}</td>
              {!compact && <td className="py-3 px-5 text-right text-dim text-[12px]">{formatBytes(block.size)}</td>}
              <td className="py-3 px-5 text-right">
                <TimestampDisplay iso={block.timestamp} />
              </td>
              <td className="py-3 px-5 text-right">
                <FinalityBadge status={block.finality} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
