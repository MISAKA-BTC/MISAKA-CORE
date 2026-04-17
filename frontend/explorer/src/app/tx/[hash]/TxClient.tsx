"use client";

import { useEffect, useState } from "react";
import { getTxStatus } from "../../../lib/api";
import { formatDate, formatAmount, formatNumber, shortHash, shortAddress } from "../../../lib/format";
import CopyButton from "../../../components/CopyButton";
import StatusBadge from "../../../components/StatusBadge";
import TypeBadge from "../../../components/TypeBadge";
import TxActionItem from "../../../components/TxActionItem";
import { FileText, RefreshCcw, ChevronRight, ChevronDown } from "lucide-react";
import Link from "next/link";

export default function TxClient({ hash }: { hash: string }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [rawOpen, setRawOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await getTxStatus(hash);
        if (res && res.status !== "unknown") {
          setData(res);
        } else {
          setError("Transaction not found or still pending in network.");
        }
      } catch (err: any) {
        setError(err.message || "Failed to load transaction details.");
      } finally {
        setLoading(false);
      }
    };
    if (hash) fetchData();
  }, [hash]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-misaka-text3">
        <RefreshCcw className="w-8 h-8 animate-spin-slow mb-4" />
        <p>Loading transaction...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="bg-red-500/10 border border-red-500/20 text-red-500 px-6 py-4 rounded-xl mb-6 text-center">
          <p className="font-semibold text-lg mb-1">Transaction Not Found</p>
          <p className="text-sm">{error}</p>
        </div>
        <Link href="/" className="text-blue-500 hover:underline text-sm">
          &larr; Back to Dashboard
        </Link>
      </div>
    );
  }

  let summary = "Transaction processed successfully";
  if (data.txType === "Faucet") {
    const to = data.outputs?.[0]?.address;
    const amount = data.outputs?.[0]?.amount;
    summary = `Faucet distribution to ${shortAddress(to)} for ${formatAmount(amount)}`;
  } else if (data.txType === "TransparentTransfer" || !data.txType) {
    const count = data.outputs?.length || 0;
    const total = data.outputs?.reduce((a: number, c: any) => a + (c.amount || 0), 0) || 0;
    summary = `Transfer to ${count} account${count > 1 ? 's' : ''} for ${formatAmount(total)}`;
  } else if (data.txType === "SystemEmission") {
    summary = `Block reward emission generated`;
  }

  return (
    <>
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-500 flex items-center justify-center shrink-0">
          <FileText className="w-5 h-5" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Transaction Details</h1>
      </div>

      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-4 sm:p-6 mb-6 shadow-sm">
        <div className="text-sm text-misaka-text2 flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-white">Summary:</span>
          {summary}
        </div>
      </div>

      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm mb-6">
        <div className="px-6 py-4 border-b border-misaka-border bg-misaka-bg3/50 font-semibold text-white">
          Overview
        </div>
        <div className="divide-y divide-misaka-border text-sm">
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Signature</div>
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-white truncate">{data.txHash || hash}</span>
              <CopyButton text={data.txHash || hash} />
            </div>
          </div>
          
          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Result</div>
            <div><StatusBadge status={data.status} /></div>
          </div>

          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Block & Timestamp</div>
            <div className="text-white flex items-center gap-2 flex-wrap">
              {data.blockHeight ? (
                <Link href={`/block/${data.blockHeight}`} className="text-blue-500 hover:underline">
                  Block #{formatNumber(data.blockHeight)}
                </Link>
              ) : (
                <span className="text-misaka-text3">—</span>
              )}
              <span className="text-misaka-text3 px-2">|</span>
              <span>{formatDate(data.timestampMs)}</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Type</div>
            <div><TypeBadge type={data.txType} /></div>
          </div>

          <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
            <div className="sm:w-48 text-misaka-text3 shrink-0">Fee</div>
            <div className="text-white font-mono">{formatAmount(data.fee)}</div>
          </div>

          {data.memo && (
            <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
              <div className="sm:w-48 text-misaka-text3 shrink-0">Memo</div>
              <div className="text-white font-mono bg-white/5 px-3 py-1.5 rounded-lg whitespace-pre-wrap break-all">
                {data.memo}
              </div>
            </div>
          )}
        </div>
      </div>

      {data.outputs && data.outputs.length > 0 && (
        <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm mb-6">
          <div className="px-6 py-4 border-b border-misaka-border bg-misaka-bg3/50 font-semibold text-white flex items-center justify-between">
            <span>Transaction Actions</span>
            <span className="text-xs font-normal text-misaka-text3 bg-white/5 px-2 py-1 rounded">
              {data.outputs.length} Instruction{data.outputs.length > 1 ? 's' : ''}
            </span>
          </div>
          <div className="flex flex-col">
            {data.outputs.map((out: any, i: number) => (
              <TxActionItem key={i} output={out} index={i} />
            ))}
          </div>
        </div>
      )}

      {data.inputs && data.inputs.length > 0 && (
        <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm mb-6">
          <div className="px-6 py-4 border-b border-misaka-border bg-misaka-bg3/50 font-semibold text-white">
            Inputs <span className="text-misaka-text3 font-normal text-sm ml-2">({data.inputs.length})</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead className="bg-white/[0.02] text-[11px] uppercase tracking-wider text-misaka-text3">
                <tr>
                  <th className="px-6 py-3 font-semibold">#</th>
                  <th className="px-6 py-3 font-semibold">UTXO Reference</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-misaka-border">
                {data.inputs.map((inp: any, i: number) => (
                  <tr key={i} className="hover:bg-white/[0.01]">
                    <td className="px-6 py-3 text-misaka-text3 font-mono">{i + 1}</td>
                    <td className="px-6 py-3 font-mono text-white">
                      {(inp.utxo_refs || inp.utxoRefs || []).map((ref: string, j: number) => {
                        const parts = ref.split(':');
                        if (parts.length === 2) {
                          return (
                            <div key={j} className="flex items-center gap-2">
                              <Link href={`/tx/${parts[0]}`} className="text-blue-500 hover:underline truncate max-w-[200px] sm:max-w-xs">
                                {shortHash(parts[0], 12)}
                              </Link>
                              <span className="text-misaka-text3">:{parts[1]}</span>
                            </div>
                          );
                        }
                        return <div key={j}>{ref}</div>;
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(data.leaderAuthority != null || (data.participatingValidators && data.participatingValidators.length > 0)) && (
        <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm mb-6">
          <div className="px-6 py-4 border-b border-misaka-border bg-misaka-bg3/50 font-semibold text-white">
            Consensus
          </div>
          <div className="divide-y divide-misaka-border text-sm">
            {data.leaderAuthority != null && (
              <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
                <div className="sm:w-48 text-misaka-text3 shrink-0">Leader</div>
                <div>
                  <span className="inline-flex items-center gap-1.5 bg-green-500/10 border border-green-500/20 text-green-500 px-3 py-1 rounded-lg font-mono text-xs">
                    ★ Validator #{data.leaderAuthority}
                  </span>
                </div>
              </div>
            )}
            {data.participatingValidators && data.participatingValidators.length > 0 && (
              <div className="flex flex-col sm:flex-row px-6 py-4 gap-2 sm:gap-6">
                <div className="sm:w-48 text-misaka-text3 shrink-0">Participants</div>
                <div className="flex flex-wrap gap-2">
                  {data.participatingValidators.map((v: number) => {
                    const isLeader = v === data.leaderAuthority;
                    return (
                      <span key={v} className={`inline-flex items-center gap-1.5 border px-3 py-1 rounded-lg font-mono text-xs ${
                        isLeader 
                          ? "bg-green-500/10 border-green-500/20 text-green-500" 
                          : "bg-white/5 border-white/10 text-misaka-text2"
                      }`}>
                        {isLeader ? "★ " : ""}Validator #{v}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl overflow-hidden shadow-sm">
        <button 
          onClick={() => setRawOpen(!rawOpen)}
          className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-white/[0.02] transition-colors"
        >
          <span className="font-semibold text-white">Raw Data</span>
          {rawOpen ? <ChevronDown className="w-4 h-4 text-misaka-text3" /> : <ChevronRight className="w-4 h-4 text-misaka-text3" />}
        </button>
        {rawOpen && (
          <div className="p-6 border-t border-misaka-border bg-[#0d0d0f] overflow-x-auto">
            <pre className="text-xs font-mono text-misaka-text2 whitespace-pre-wrap break-all">
              {JSON.stringify(data, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </>
  );
}