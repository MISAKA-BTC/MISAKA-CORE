"use client";

import { useEffect, useState } from "react";
import { getChainInfo, getRecentBlocks } from "../lib/api";
import StatsGrid from "../components/StatsGrid";
import BlocksTable from "../components/BlocksTable";
import TxsTable from "../components/TxsTable";
import FaucetForm from "../components/FaucetForm";
import { RefreshCcw } from "lucide-react";

export default function Dashboard() {
  const [stats, setStats] = useState<any>({});
  const [blocks, setBlocks] = useState<any[]>([]);
  const [txs, setTxs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [info, recentData] = await Promise.all([
        getChainInfo(),
        getRecentBlocks(10)
      ]);

      if (info) setStats(info);
      
      if (recentData && recentData.blocks) {
        setBlocks(recentData.blocks);
        
        // Extract recent txs from recent blocks
        let recentTxs: any[] = [];
        for (const b of recentData.blocks) {
          if (b.transactions && Array.isArray(b.transactions)) {
            for (const t of b.transactions) {
              recentTxs.push({
                ...t,
                blockHeight: b.height ?? b.round
              });
            }
          }
        }
        setTxs(recentTxs.slice(0, 15));
      }
    } catch {
      // silently ignore API errors
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-white">Network Dashboard</h1>
        {loading && <RefreshCcw className="w-4 h-4 text-misaka-text3 animate-spin-slow" />}
      </div>
      
      <StatsGrid stats={stats} />
      
      <FaucetForm />
      
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 mb-8">
        <section>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold text-white tracking-wide">Latest Blocks</h2>
            <span className="bg-green-500/10 text-green-500 text-[10px] uppercase tracking-widest font-bold px-2 py-0.5 rounded-full flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> Live
            </span>
          </div>
          <BlocksTable blocks={blocks} />
        </section>

        <section>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold text-white tracking-wide">Recent Transactions</h2>
            <span className="bg-green-500/10 text-green-500 text-[10px] uppercase tracking-widest font-bold px-2 py-0.5 rounded-full flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> Live
            </span>
          </div>
          <TxsTable txs={txs} />
        </section>
      </div>
    </>
  );
}
