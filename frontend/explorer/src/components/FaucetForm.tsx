"use client";

import { useState } from "react";
import { requestFaucet } from "../lib/api";
import { Droplets } from "lucide-react";

export default function FaucetForm() {
  const [address, setAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ text: string; isError: boolean } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!address.trim()) return;
    
    setLoading(true);
    setMessage(null);
    try {
      const res = await requestFaucet(address.trim());
      if (res && (res.tx_hash || res.txid)) {
        setMessage({ text: `Success! TX: ${res.tx_hash || res.txid}`, isError: false });
      } else if (res && res.error) {
        setMessage({ text: res.error, isError: true });
      } else {
        setMessage({ text: "Request accepted", isError: false });
      }
    } catch (err: any) {
      setMessage({ text: err.message || "Network error", isError: true });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-6 shadow-sm mb-8">
      <div className="flex items-center gap-2 mb-4">
        <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-500 flex items-center justify-center">
          <Droplets className="w-4 h-4" />
        </div>
        <h2 className="text-lg font-semibold text-white">Testnet Faucet</h2>
      </div>
      
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder="Enter address (misaka1...)"
          className="flex-1 bg-misaka-bg3 border border-misaka-border2 rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-misaka-text3 focus:outline-none focus:border-white/20 font-mono transition-colors"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={loading || !address.trim()}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm px-6 py-2.5 rounded-lg transition-colors whitespace-nowrap"
        >
          {loading ? "Requesting..." : "Request MSK"}
        </button>
      </form>
      
      {message && (
        <div className={`mt-4 px-4 py-3 rounded-lg text-sm border ${message.isError ? "bg-red-500/10 border-red-500/20 text-red-500" : "bg-green-500/10 border-green-500/20 text-green-500"}`}>
          {message.text}
        </div>
      )}
    </div>
  );
}
