import Link from "next/link";
import { shortHash, timeAgo } from "../lib/format";

export default function BlocksTable({ blocks }: { blocks: any[] }) {
  if (!blocks || blocks.length === 0) {
    return (
      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden">
        <div className="p-8 text-center text-misaka-text3">Waiting for blocks...</div>
      </div>
    );
  }

  return (
    <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-x-auto shadow-sm">
      <table className="w-full text-left border-collapse">
        <thead className="bg-misaka-bg3/50 text-[11px] uppercase tracking-wider text-misaka-text2">
          <tr>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Block</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Age</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">TXs</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Proposer</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Hash</th>
          </tr>
        </thead>
        <tbody className="text-sm divide-y divide-misaka-border">
          {blocks.map((b: any, i: number) => {
            const height = b.height ?? b.round ?? "—";
            const hash = b.hash ?? b.block_hash ?? "";
            const txs = b.txCount ?? b.tx_count ?? b.transactions?.length ?? 0;
            const time = b.timestamp ? timeAgo(b.timestamp) : "—";
            const proposer = b.proposer ?? (b.author != null ? `Validator ${b.author}` : "—");

            return (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-5 py-4">
                  <Link href={`/block/${height}`} className="text-blue-500 hover:text-blue-400 font-medium">
                    #{height}
                  </Link>
                </td>
                <td className="px-5 py-4 text-misaka-text3">{time}</td>
                <td className="px-5 py-4 text-misaka-text2">{txs}</td>
                <td className="px-5 py-4 text-misaka-text2">
                  <span className="bg-white/5 px-2 py-1 rounded text-xs">{proposer}</span>
                </td>
                <td className="px-5 py-4 font-mono text-misaka-text3">
                  {shortHash(hash, 8)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
