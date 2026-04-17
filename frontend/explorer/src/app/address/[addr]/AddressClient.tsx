"use client";

import { useEffect, useState } from "react";
import { getWallet, getAddressHistory } from "../../../lib/api";
import { formatDate, formatAmount, shortHash } from "../../../lib/format";
import CopyButton from "../../../components/CopyButton";
import BalanceHero from "../../../components/BalanceHero";
import { RefreshCcw, Wallet, ArrowDown, ArrowUp } from "lucide-react";
import Link from "next/link";

export default function AddressClient({ addr }: { addr: string }) {
  const address = decodeURIComponent(addr);
  
  const [data, setData] = useState<any>(null);
  const [history, setHistory] = useState<any>({ transactions: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"txs" | "utxos">("txs");

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [walletRes, histRes] = await Promise.all([
          getWallet(address),
          getAddressHistory(address, 1, 50).catch(() => ({ transactions: [], total: 0 }))
        ]);
        
        if (walletRes && !walletRes.error) {
          setData(walletRes);
        } else {
          setError(walletRes?.error || "Failed to load address details.");
        }
        if (histRes) {
          setHistory(histRes);
        }
      } catch (err: any) {
        setError(err.message || "Failed to load address details.");
      } finally {
        setLoading(false);
      }
    };
    if (address) fetchData();
  }, [address]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-misaka-text3">
        <RefreshCcw className="w-8 h-8 animate-spin-slow mb-4" />
        <p>Loading address...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="bg-red-500/10 border border-red-500/20 text-red-500 px-6 py-4 rounded-xl mb-6 text-center">
          <p className="font-semibold text-lg mb-1">Address Not Found</p>
          <p className="text-sm">{error}</p>
        </div>
        <Link href="/" className="text-blue-500 hover:underline text-sm">
          &larr; Back to Dashboard
        </Link>
      </div>
    );
  }

  const txs = history.transactions || [];
  const utxos = data.utxos || [];

  return (
    <>
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-500 flex items-center justify-center shrink-0">
          <Wallet className="w-5 h-5" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Account Details</h1>
      </div>

      <BalanceHero balance={data.balance} />

      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm mb-6">
        <div className="px-6 py-4 border-b border-misaka-border bg-misaka-bg3/50 font-semibold text-white">
          Overview
        </div>
        <div className="divide-y divide-misaka-border text-sm">
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Address</div>
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-white truncate">{address}</span>
              <CopyButton text={address} />
            </div>
          </div>
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">UTXO Count</div>
            <div className="text-white">{data.utxoCount || utxos.length}</div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-4 mb-4 border-b border-misaka-border">
        <button 
          onClick={() => setActiveTab("txs")}
          className={`pb-3 px-2 text-sm font-semibold transition-colors ${
            activeTab === "txs" ? "border-b-2 border-blue-500 text-white" : "text-misaka-text3 hover:text-white"
          }`}
        >
          Transactions
        </button>
        <button 
          onClick={() => setActiveTab("utxos")}
          className={`pb-3 px-2 text-sm font-semibold transition-colors ${
            activeTab === "utxos" ? "border-b-2 border-blue-500 text-white" : "text-misaka-text3 hover:text-white"
          }`}
        >
          UTXOs
        </button>
      </div>

      {activeTab === "txs" && (
        <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm">
          {txs.length === 0 ? (
            <div className="p-12 text-center text-misaka-text3">No transaction history found.</div>
          ) : (
            <div className="divide-y divide-misaka-border">
              {txs.map((tx: any, i: number) => {
                const isReceive = tx.direction === "receive";
                const typeLabel = tx.txType === "TransparentTransfer" ? "Transfer" : 
                                  tx.txType === "SystemEmission" ? "Block Reward" : 
                                  (tx.txType || "Transfer");

                return (
                  <Link href={`/tx/${tx.txHash}`} key={i} className="flex items-center justify-between p-4 sm:p-5 hover:bg-white/[0.02] transition-colors gap-4">
                    <div className="flex items-center gap-4">
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${
                        isReceive ? "bg-green-500/10 text-green-500" : "bg-white/10 text-white"
                      }`}>
                        {isReceive ? <ArrowDown className="w-5 h-5" /> : <ArrowUp className="w-5 h-5" />}
                      </div>
                      <div>
                        <div className="font-semibold text-white mb-0.5 text-sm">{typeLabel}</div>
                        <div className="text-xs font-mono text-misaka-text3">{shortHash(tx.txHash, 14)}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`font-bold text-sm mb-0.5 ${isReceive ? "text-green-500" : "text-white"}`}>
                        {isReceive ? "+" : "-"}{formatAmount(tx.amount)}
                      </div>
                      <div className="text-xs text-misaka-text3">{formatDate(tx.timestampMs)}</div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      )}

      {activeTab === "utxos" && (
        <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-x-auto shadow-sm">
          {utxos.length === 0 ? (
            <div className="p-12 text-center text-misaka-text3">No UTXOs found.</div>
          ) : (
            <table className="w-full text-left border-collapse text-sm">
              <thead className="bg-misaka-bg3/50 text-[11px] uppercase tracking-wider text-misaka-text2">
                <tr>
                  <th className="px-6 py-4 font-semibold border-b border-misaka-border">Transaction Hash</th>
                  <th className="px-6 py-4 font-semibold border-b border-misaka-border">Index</th>
                  <th className="px-6 py-4 font-semibold border-b border-misaka-border">Block</th>
                  <th className="px-6 py-4 font-semibold border-b border-misaka-border text-right">Amount (MSK)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-misaka-border">
                {utxos.map((u: any, i: number) => (
                  <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-6 py-4 font-mono text-blue-500 hover:underline">
                      <Link href={`/tx/${u.txHash}`}>{shortHash(u.txHash, 12)}</Link>
                    </td>
                    <td className="px-6 py-4 font-mono text-misaka-text2">{u.outputIndex}</td>
                    <td className="px-6 py-4 text-misaka-text2">{u.createdAt ? u.createdAt.toLocaleString() : "—"}</td>
                    <td className="px-6 py-4 font-mono text-right text-white">
                      {(Number(u.amount) / 1e9).toFixed(9).replace(/\.?0+$/, "")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </>
  );
}
