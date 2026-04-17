import Link from "next/link";
import { shortHash } from "../lib/format";
import TypeBadge from "./TypeBadge";
import StatusBadge from "./StatusBadge";

export default function TxsTable({ txs }: { txs: any[] }) {
  if (!txs || txs.length === 0) {
    return (
      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden">
        <div className="p-8 text-center text-misaka-text3">No transactions yet</div>
      </div>
    );
  }

  return (
    <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-x-auto shadow-sm">
      <table className="w-full text-left border-collapse">
        <thead className="bg-misaka-bg3/50 text-[11px] uppercase tracking-wider text-misaka-text2">
          <tr>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Transaction Hash</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Block</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Type</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border">Fee (MSK)</th>
            <th className="px-5 py-4 font-semibold border-b border-misaka-border text-right">Result</th>
          </tr>
        </thead>
        <tbody className="text-sm divide-y divide-misaka-border">
          {txs.map((t: any, i: number) => {
            const hash = t.hash ?? t.txHash ?? "";
            const height = t.blockHeight ?? "—";
            
            // Format fee safely
            let feeDisplay = "0";
            if (t.fee != null) {
              feeDisplay = (Number(t.fee) / 1e9).toFixed(9).replace(/\.?0+$/, "");
              if (feeDisplay === "") feeDisplay = "0";
            }

            return (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-5 py-4 font-mono">
                  <Link href={`/tx/${hash}`} className="text-blue-500 hover:text-blue-400">
                    {shortHash(hash, 10)}
                  </Link>
                </td>
                <td className="px-5 py-4">
                  {height !== "—" ? (
                    <Link href={`/block/${height}`} className="text-blue-500 hover:text-blue-400">
                      {height}
                    </Link>
                  ) : (
                    <span className="text-misaka-text3">—</span>
                  )}
                </td>
                <td className="px-5 py-4">
                  <TypeBadge type={t.txType || t.type} />
                </td>
                <td className="px-5 py-4 text-misaka-text2 font-mono text-[13px]">
                  {feeDisplay}
                </td>
                <td className="px-5 py-4 text-right">
                  <StatusBadge status={t.status || "confirmed"} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
