"use client";

import { useEffect, useState } from "react";
import { getBlockByHeight } from "../../../lib/api";
import { formatDate, formatNumber } from "../../../lib/format";
import CopyButton from "../../../components/CopyButton";
import TxsTable from "../../../components/TxsTable";
import { Box, RefreshCcw } from "lucide-react";
import Link from "next/link";

export default function BlockClient({ id }: { id: string }) {
  const height = Number(id);
  
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      if (isNaN(height)) {
        setError("Invalid block height.");
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const res = await getBlockByHeight(height);
        if (res && !res.error) {
          setData(res);
        } else {
          setError(res?.error || "Block not found.");
        }
      } catch (err: any) {
        setError(err.message || "Failed to load block details.");
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [height]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-misaka-text3">
        <RefreshCcw className="w-8 h-8 animate-spin-slow mb-4" />
        <p>Loading block...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="bg-red-500/10 border border-red-500/20 text-red-500 px-6 py-4 rounded-xl mb-6 text-center">
          <p className="font-semibold text-lg mb-1">Block Not Found</p>
          <p className="text-sm">{error}</p>
        </div>
        <Link href="/" className="text-blue-500 hover:underline text-sm">
          &larr; Back to Dashboard
        </Link>
      </div>
    );
  }

  const txs = data.transactions || [];
  
  const formattedTxs = txs.map((t: any) => ({
    ...t,
    blockHeight: height
  }));

  return (
    <>
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-500 flex items-center justify-center shrink-0">
          <Box className="w-5 h-5" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Block Details</h1>
      </div>

      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm mb-8">
        <div className="px-6 py-4 border-b border-misaka-border bg-misaka-bg3/50 font-semibold text-white">
          Overview
        </div>
        <div className="divide-y divide-misaka-border text-sm">
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Block Height</div>
            <div className="font-semibold text-white">#{formatNumber(height)}</div>
          </div>
          
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Block Hash</div>
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-white truncate">{data.hash || "—"}</span>
              {data.hash && <CopyButton text={data.hash} />}
            </div>
          </div>

          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Timestamp</div>
            <div className="text-white flex items-center gap-2">
              {formatDate(data.timestamp)}
              <span className="text-misaka-text3 text-xs ml-2">({data.timestamp ? new Date(Number(data.timestamp)).toUTCString() : ""})</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Transactions</div>
            <div className="text-white">{formatNumber(data.txCount || txs.length)}</div>
          </div>

          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Proposer</div>
            <div className="text-white">
              {data.proposer ?? (data.author != null ? `Validator ${data.author}` : "—")}
            </div>
          </div>
          
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Total Fees</div>
            <div className="text-white font-mono">
              {data.totalFees != null ? `${(Number(data.totalFees) / 1e9).toFixed(9).replace(/\.?0+$/, "")} MSK` : "—"}
            </div>
          </div>
        </div>
      </div>

      <h2 className="text-lg font-bold text-white tracking-wide mb-4">
        Transactions <span className="text-misaka-text3 font-normal text-sm ml-2">({formattedTxs.length})</span>
      </h2>
      <TxsTable txs={formattedTxs} />
    </>
  );
}
