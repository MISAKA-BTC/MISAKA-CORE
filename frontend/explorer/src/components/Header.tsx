"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import SearchBar from "./SearchBar";
import { getChainInfo } from "../lib/api";
import { formatNumber } from "../lib/format";

export default function Header() {
  const [stats, setStats] = useState<{ height?: number; validators?: number }>({});

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await getChainInfo();
        if (data) {
          setStats({
            height: data.blockHeight,
            validators: data.validatorCount,
          });
        }
      } catch (err) {
        // ignore
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="border-b border-misaka-border bg-misaka-bg2 sticky top-0 z-50">
      <div className="mx-auto max-w-6xl w-full px-4 sm:px-6 h-16 flex items-center justify-between gap-4 sm:gap-8">
        {/* Logo */}
        <div className="flex items-center gap-3 shrink-0">
          <Link href="/" className="flex items-center gap-1.5 hover:opacity-80 transition-opacity">
            <span className="font-bold text-lg tracking-wide text-white">MISAKA</span>
            <span className="font-normal text-[13px] text-misaka-text3 hidden sm:inline">Explorer</span>
          </Link>
          <span className="text-[10px] font-semibold text-yellow-500 bg-yellow-500/10 px-2 py-0.5 rounded-md uppercase tracking-wider">
            Testnet
          </span>
        </div>

        {/* Search */}
        <div className="flex-1 hidden md:flex">
          <SearchBar />
        </div>

        {/* Stats */}
        <div className="flex items-center gap-6 shrink-0">
          <div className="text-right hidden sm:block">
            <div className="text-[10px] text-misaka-text3 uppercase tracking-widest">Block Height</div>
            <div className="text-sm font-semibold text-white">{formatNumber(stats.height)}</div>
          </div>
          <div className="text-right hidden sm:block">
            <div className="text-[10px] text-misaka-text3 uppercase tracking-widest">Validators</div>
            <div className="text-sm font-semibold text-white">{formatNumber(stats.validators)}</div>
          </div>
        </div>
      </div>
      
      {/* Mobile search bar (shows on small screens below header) */}
      <div className="md:hidden px-4 pb-4 bg-misaka-bg2">
        <SearchBar />
      </div>
    </header>
  );
}
