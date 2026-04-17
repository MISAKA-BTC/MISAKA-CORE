import Link from "next/link";
import { formatAmount, shortAddress } from "../lib/format";
import CopyButton from "./CopyButton";
import { ArrowRight } from "lucide-react";

export default function TxActionItem({ output, index }: { output: any; index: number }) {
  return (
    <div className="p-4 border-b border-misaka-border last:border-none flex items-center justify-between gap-4">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="w-6 h-6 rounded-md bg-white/5 flex items-center justify-center text-xs font-mono text-misaka-text3 shrink-0">
          #{index + 1}
        </span>
        <div className="flex items-center gap-2 text-sm flex-wrap">
          <span className="text-misaka-text2 whitespace-nowrap">Transfer to</span>
          <Link href={`/address/${output.address}`} className="text-blue-500 hover:text-blue-400 font-mono truncate max-w-[150px] sm:max-w-xs">
            {shortAddress(output.address, 10)}
          </Link>
          <CopyButton text={output.address} />
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <ArrowRight className="w-4 h-4 text-misaka-text3 hidden sm:block" />
        <span className="font-semibold text-white whitespace-nowrap">
          {formatAmount(output.amount)}
        </span>
      </div>
    </div>
  );
}
